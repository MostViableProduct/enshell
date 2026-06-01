//! Local structured logging and tamper-evident audit log for enShell.
//!
//! # Responsibility boundary
//!
//! This crate **stores already-redacted records**. Secret detection, secret
//! redaction, and the population of `redaction_count` are the orchestration
//! layer's responsibility (e.g. `enshell-core`). Once a record arrives here,
//! every field is written verbatim to disk. Do not pass un-redacted secret
//! values in any [`AuditRecord`] field.
//!
//! # Hash-chain scheme
//!
//! Each stored entry carries:
//! - `prev_hash` — the hex-encoded SHA-256 hash of the previous entry (or the
//!   genesis hash `"0000…0000"` (64 zeros) for the first entry).
//! - `hash` — `SHA-256(prev_hash_bytes || canonical_json_bytes)` where
//!   `prev_hash_bytes` is the UTF-8 encoding of the 64-character hex string and
//!   `canonical_json_bytes` is the UTF-8 output of `serde_json::to_string(record)`.
//!   The result is hex-encoded (lowercase, 64 characters).
//!
//! This scheme is **tamper-evident** — it detects in-place edits, deletions,
//! truncation, and reordering of existing entries. It is **not tamper-proof**
//! against an attacker who rewrites the entire chain from scratch. Cryptographic
//! signing or external anchoring is a future enhancement.
//!
//! Each line in the JSONL file is a JSON object:
//! ```json
//! {"record":{...},"prev_hash":"<64 hex chars>","hash":"<64 hex chars>"}
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write as IoWrite};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ─── Genesis hash ─────────────────────────────────────────────────────────────

/// The fixed "genesis" `prev_hash` used for the very first entry in a new log.
/// 64 zero characters, matching the 64-hex-char output of SHA-256.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ─── AuditRecord ──────────────────────────────────────────────────────────────

/// A single audit event. All fields are caller-supplied; **all secret-sensitive
/// fields must be redacted by the caller before constructing this record**.
///
/// `timestamp` is a caller-supplied string so that this crate remains
/// clock-free and fully testable without time mocking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    /// Ties request → intent → policy decision → execution → outcome.
    pub correlation_id: String,
    /// The original natural-language request that produced this action.
    /// (Assumed already secret-redacted by the caller, like `params`.)
    pub user_request: String,
    /// When the event occurred; RFC 3339 or Unix-millis string.
    /// The caller is responsible for supplying this; the crate does not read
    /// the system clock.
    pub timestamp: String,
    /// Version of the policy ruleset that classified this action.
    pub policy_version: u32,
    /// Version of the intent catalog used.
    pub intent_schema_version: u32,
    /// Which model produced the intent (e.g. `"gemma-4-e4b-q4"`, `"stub"`).
    pub model_id: String,
    /// Quantization label (e.g. `"Q4"`), or `None` for a stub/no-model path.
    pub model_quant: Option<String>,
    /// Version of the prompt template used.
    pub prompt_template_version: String,
    /// The validated intent name (snake_case).
    pub intent: String,
    /// Intent parameters. **Must already be redacted by the caller.**
    pub params: serde_json::Value,
    /// The policy-assigned risk tier (authoritative).
    pub risk_tier: String,
    /// The rendered display command (display-only; not used for execution).
    pub command_plan: String,
    /// How confirmation was obtained: `"yes"` | `"interactive"` | `"typed"`.
    pub confirmation_mode: String,
    /// Process exit code, if the command ran.
    pub exit_code: Option<i32>,
    /// High-level outcome: `"ok"` | `"denied"` | `"aborted"` | `"error"`.
    pub outcome: String,
    /// Number of secret matches redacted from this record before storage.
    pub redaction_count: u32,
}

// ─── StoredEntry ──────────────────────────────────────────────────────────────

/// A record as stored on disk, with the chain hashes attached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEntry {
    /// The audit record (already redacted).
    pub record: AuditRecord,
    /// Hash of the previous entry (or the genesis hash for entry 0).
    pub prev_hash: String,
    /// SHA-256 of `prev_hash_bytes || canonical_json(record)`, hex-encoded.
    pub hash: String,
}

// ─── AuditError ───────────────────────────────────────────────────────────────

/// Errors produced by [`AuditLog`] operations.
#[derive(Debug)]
pub enum AuditError {
    /// I/O failure (file read, write, directory creation, …).
    Io(io::Error),
    /// JSON serialization or deserialization failure.
    Serde(serde_json::Error),
    /// The hash chain is broken: the message names the first bad position.
    Corrupt(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Io(e) => write!(f, "audit log I/O error: {e}"),
            AuditError::Serde(e) => write!(f, "audit log serialization error: {e}"),
            AuditError::Corrupt(msg) => write!(f, "audit log integrity violation: {msg}"),
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuditError::Io(e) => Some(e),
            AuditError::Serde(e) => Some(e),
            AuditError::Corrupt(_) => None,
        }
    }
}

impl From<io::Error> for AuditError {
    fn from(e: io::Error) -> Self {
        AuditError::Io(e)
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(e: serde_json::Error) -> Self {
        AuditError::Serde(e)
    }
}

// ─── AuditLog ─────────────────────────────────────────────────────────────────

/// An append-only, hash-chained JSONL audit log stored at a local path.
///
/// Each line is a JSON object: `{"record":{...},"prev_hash":"<hex>","hash":"<hex>"}`.
///
/// The log is designed for local use at human-terminal scale (thousands of
/// entries, not millions). All reads load the entire file; no indexing is
/// performed.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Open (creating parent directories and the file if needed) the audit log
    /// at `path`.
    ///
    /// If the file already exists its contents are not validated here; call
    /// [`verify`](AuditLog::verify) to check integrity.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        // Touch the file so it exists (append mode creates if absent).
        OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(AuditLog { path })
    }

    /// Append `record` to the log.
    ///
    /// Reads the last line to obtain the previous hash (or uses the genesis
    /// hash for an empty log). Computes the new hash as
    /// `SHA-256(prev_hash_utf8 || canonical_json(record))`, then writes one
    /// JSON line.
    ///
    /// Returns the hex-encoded hash of the new entry.
    pub fn append(&self, record: &AuditRecord) -> Result<String, AuditError> {
        let prev_hash = self.last_hash()?;
        let hash = compute_hash(&prev_hash, record)?;

        let entry = StoredEntry {
            record: record.clone(),
            prev_hash,
            hash: hash.clone(),
        };
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        Ok(hash)
    }

    /// Read all stored entries in insertion order.
    pub fn entries(&self) -> Result<Vec<StoredEntry>, AuditError> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let entry: StoredEntry = serde_json::from_str(trimmed).map_err(|e| {
                AuditError::Corrupt(format!(
                    "line {} cannot be parsed as StoredEntry: {e}",
                    line_num + 1
                ))
            })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Verify the integrity of the hash chain.
    ///
    /// Checks:
    /// 1. Each entry's `hash` equals the freshly recomputed
    ///    `SHA-256(prev_hash_utf8 || canonical_json(record))`.
    /// 2. Each entry's `prev_hash` equals the previous entry's `hash` (or the
    ///    genesis hash for the first entry).
    ///
    /// Returns `Ok(())` if the chain is intact, or `Err(AuditError::Corrupt(_))`
    /// naming the first bad line number.
    pub fn verify(&self) -> Result<(), AuditError> {
        let entries = self.entries()?;
        let mut expected_prev = GENESIS_HASH.to_string();

        for (idx, entry) in entries.iter().enumerate() {
            let line_num = idx + 1;

            // Check that prev_hash matches the chain.
            if entry.prev_hash != expected_prev {
                return Err(AuditError::Corrupt(format!(
                    "line {line_num}: prev_hash mismatch \
                     (expected {expected_prev}, found {})",
                    entry.prev_hash
                )));
            }

            // Recompute the hash and compare.
            let recomputed = compute_hash(&entry.prev_hash, &entry.record)?;
            if recomputed != entry.hash {
                return Err(AuditError::Corrupt(format!(
                    "line {line_num}: hash mismatch \
                     (stored {}, recomputed {recomputed})",
                    entry.hash
                )));
            }

            expected_prev = entry.hash.clone();
        }
        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Read the `hash` field of the last non-empty line, or return the genesis
    /// hash if the file is empty.
    fn last_hash(&self) -> Result<String, AuditError> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut last: Option<String> = None;
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                last = Some(trimmed.to_string());
            }
        }
        match last {
            None => Ok(GENESIS_HASH.to_string()),
            Some(json) => {
                // We only need the `hash` field; parse just enough.
                let v: serde_json::Value = serde_json::from_str(&json)?;
                let hash = v
                    .get("hash")
                    .and_then(|h| h.as_str())
                    .ok_or_else(|| {
                        AuditError::Corrupt("last line is missing the `hash` field".to_string())
                    })?
                    .to_string();
                Ok(hash)
            }
        }
    }
}

// ─── Hash computation ─────────────────────────────────────────────────────────

/// Compute `SHA-256(prev_hash_utf8 || canonical_json(record))` and return
/// the result as a 64-character lowercase hex string.
///
/// "Canonical JSON" here means `serde_json::to_string(record)`. Because
/// [`AuditRecord`] is a plain Rust struct (not a `serde_json::Map`) the field
/// order in the serialized output is the declaration order in the struct —
/// deterministic across runs and platforms.
fn compute_hash(prev_hash: &str, record: &AuditRecord) -> Result<String, AuditError> {
    let canonical = serde_json::to_string(record)?;
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    let bytes = hasher.finalize();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(hex)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn temp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("enshell_audit_test_{suffix}.jsonl"));
        p
    }

    fn make_record(n: u32) -> AuditRecord {
        AuditRecord {
            correlation_id: format!("corr-{n}"),
            user_request: format!("request number {n}"),
            timestamp: format!("2024-01-01T00:00:{n:02}Z"),
            policy_version: 1,
            intent_schema_version: 1,
            model_id: "stub".to_string(),
            model_quant: None,
            prompt_template_version: "v1".to_string(),
            intent: "check_system_health".to_string(),
            params: serde_json::json!({}),
            risk_tier: "read_only".to_string(),
            command_plan: format!("echo {n}"),
            confirmation_mode: "yes".to_string(),
            exit_code: Some(0),
            outcome: "ok".to_string(),
            redaction_count: 0,
        }
    }

    // ── test: three records round-trip and verify ─────────────────────────────

    #[test]
    fn append_three_and_verify() {
        let path = temp_path("three");
        let _ = std::fs::remove_file(&path); // clean slate

        let log = AuditLog::open(&path).unwrap();
        log.append(&make_record(1)).unwrap();
        log.append(&make_record(2)).unwrap();
        log.append(&make_record(3)).unwrap();

        let entries = log.entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].record.correlation_id, "corr-1");
        assert_eq!(entries[1].record.correlation_id, "corr-2");
        assert_eq!(entries[2].record.correlation_id, "corr-3");

        log.verify().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    // ── test: genesis hash and chain links ───────────────────────────────────

    #[test]
    fn chain_links_are_correct() {
        let path = temp_path("chain");
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::open(&path).unwrap();
        let h1 = log.append(&make_record(1)).unwrap();
        let h2 = log.append(&make_record(2)).unwrap();
        let h3 = log.append(&make_record(3)).unwrap();

        let entries = log.entries().unwrap();

        // First entry chains from genesis.
        assert_eq!(entries[0].prev_hash, GENESIS_HASH);
        assert_eq!(entries[0].hash, h1);

        // Each subsequent entry chains from the previous hash.
        assert_eq!(entries[1].prev_hash, h1);
        assert_eq!(entries[1].hash, h2);

        assert_eq!(entries[2].prev_hash, h2);
        assert_eq!(entries[2].hash, h3);

        let _ = std::fs::remove_file(&path);
    }

    // ── test: tamper detection — mutate a record field ───────────────────────

    #[test]
    fn tamper_detection_mutated_field() {
        let path = temp_path("tamper_field");
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::open(&path).unwrap();
        log.append(&make_record(1)).unwrap();
        log.append(&make_record(2)).unwrap();
        log.append(&make_record(3)).unwrap();

        // Read the file, replace a field in line 2 without fixing the hash.
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);

        // Parse line 2, change `outcome` to "tampered", re-serialize.
        let mut entry2: StoredEntry = serde_json::from_str(lines[1]).unwrap();
        entry2.record.outcome = "tampered".to_string();
        let tampered_line = serde_json::to_string(&entry2).unwrap();

        let new_content = format!("{}\n{}\n{}\n", lines[0], tampered_line, lines[2]);
        std::fs::write(&path, new_content).unwrap();

        // verify() must detect the corruption.
        let log2 = AuditLog::open(&path).unwrap();
        let result = log2.verify();
        assert!(
            matches!(result, Err(AuditError::Corrupt(_))),
            "expected Corrupt error, got: {result:?}"
        );
        if let Err(AuditError::Corrupt(msg)) = result {
            // The message should mention line 2.
            assert!(
                msg.contains("line 2"),
                "corrupt message should name line 2, got: {msg}"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    // ── test: deletion/truncation detection — remove middle line ─────────────

    #[test]
    fn tamper_detection_deleted_line() {
        let path = temp_path("tamper_delete");
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::open(&path).unwrap();
        log.append(&make_record(1)).unwrap();
        log.append(&make_record(2)).unwrap();
        log.append(&make_record(3)).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        // Drop line 2 (the middle entry).
        let new_content = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, new_content).unwrap();

        let log2 = AuditLog::open(&path).unwrap();
        let result = log2.verify();
        assert!(
            matches!(result, Err(AuditError::Corrupt(_))),
            "expected Corrupt error after line deletion, got: {result:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── test: reopen continuity ───────────────────────────────────────────────

    #[test]
    fn reopen_continuity() {
        let path = temp_path("reopen");
        let _ = std::fs::remove_file(&path);

        // First session: append 2 records.
        {
            let log = AuditLog::open(&path).unwrap();
            log.append(&make_record(1)).unwrap();
            log.append(&make_record(2)).unwrap();
        }

        // Second session: reopen and append 2 more.
        {
            let log = AuditLog::open(&path).unwrap();
            log.append(&make_record(3)).unwrap();
            log.append(&make_record(4)).unwrap();
        }

        // The whole chain should verify.
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(log.entries().unwrap().len(), 4);
        log.verify().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    // ── test: serde round-trip ────────────────────────────────────────────────

    #[test]
    fn record_serde_round_trip() {
        let record = AuditRecord {
            correlation_id: "abc-123".to_string(),
            user_request: "show me what is using port 3000".to_string(),
            timestamp: "2024-06-01T12:00:00Z".to_string(),
            policy_version: 3,
            intent_schema_version: 2,
            model_id: "gemma-4-e4b-q4".to_string(),
            model_quant: Some("Q4".to_string()),
            prompt_template_version: "v2".to_string(),
            intent: "find_large_files".to_string(),
            params: serde_json::json!({"path": "/home/user", "min_size": "500MB"}),
            risk_tier: "read_only".to_string(),
            command_plan: "du -ah /home/user | sort -rh | head -10".to_string(),
            confirmation_mode: "yes".to_string(),
            exit_code: Some(0),
            outcome: "ok".to_string(),
            redaction_count: 0,
        };

        let json = serde_json::to_string(&record).unwrap();
        let decoded: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, decoded);
    }

    // ── test: model_quant = None round-trips ─────────────────────────────────

    #[test]
    fn record_no_model_quant_round_trip() {
        let record = make_record(42);
        assert!(record.model_quant.is_none());
        let json = serde_json::to_string(&record).unwrap();
        let decoded: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, decoded);
    }

    // ── test: empty log returns genesis hash for prev_hash ───────────────────

    #[test]
    fn empty_log_uses_genesis_hash() {
        let path = temp_path("genesis");
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::open(&path).unwrap();
        log.append(&make_record(1)).unwrap();

        let entries = log.entries().unwrap();
        assert_eq!(entries[0].prev_hash, GENESIS_HASH);

        let _ = std::fs::remove_file(&path);
    }

    // ── test: open creates parent dirs ────────────────────────────────────────

    #[test]
    fn open_creates_parent_dirs() {
        let mut path = std::env::temp_dir();
        path.push("enshell_audit_subdir_test");
        path.push("nested");
        path.push("audit.jsonl");

        let _ = std::fs::remove_dir_all(
            path.parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("enshell_audit_subdir_test"),
        );

        let log = AuditLog::open(&path).unwrap();
        log.append(&make_record(1)).unwrap();
        log.verify().unwrap();

        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("enshell_audit_subdir_test"));
    }

    // ── test: hash is deterministic for same input ────────────────────────────

    #[test]
    fn hash_is_deterministic() {
        let record = make_record(7);
        let h1 = compute_hash(GENESIS_HASH, &record).unwrap();
        let h2 = compute_hash(GENESIS_HASH, &record).unwrap();
        assert_eq!(h1, h2);
        // Must be a 64-char hex string.
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
