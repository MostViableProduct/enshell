//! Local, SQLite-backed memory for enShell.
//!
//! # Scope
//!
//! Today this stores **preferences** only — a simple key/value table the user
//! manages with `enshell memory ...`. The schema is versioned (via SQLite's
//! `PRAGMA user_version`) so future tables (trust decisions, richer memory) are
//! additive migrations, not a rewrite.
//!
//! # Privacy
//!
//! Preferences are **local-only** and never transmitted; the store is just a file
//! under the user's config dir. Prefs are intended for **non-secret configuration**
//! (e.g. a default timeout) — secret material does not belong here. The store is
//! created lazily, only when the user first writes a preference.
//!
//! # Storage
//!
//! Uses `rusqlite` with **bundled SQLite**, so a build/install needs no system
//! `libsqlite3` — keeping `cargo install` self-contained across platforms.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

/// The current on-disk schema version. Bump this and add a migration step in
/// `Store`'s internal `migrate` routine when the schema changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Errors from the memory store.
#[derive(Debug)]
pub enum MemoryError {
    /// Opening or creating the database failed.
    Open(rusqlite::Error),
    /// Applying schema migrations failed.
    Migrate(rusqlite::Error),
    /// A query (read or write) failed.
    Query(rusqlite::Error),
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryError::Open(e) => write!(f, "could not open memory store: {e}"),
            MemoryError::Migrate(e) => write!(f, "could not migrate memory store: {e}"),
            MemoryError::Query(e) => write!(f, "memory query failed: {e}"),
        }
    }
}

impl std::error::Error for MemoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MemoryError::Open(e) | MemoryError::Migrate(e) | MemoryError::Query(e) => Some(e),
        }
    }
}

/// The local memory store: a SQLite connection with the current schema applied.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) and migrate the store at `path`.
    ///
    /// Parent directories are created as needed.
    pub fn open(path: &Path) -> Result<Store, MemoryError> {
        if let Some(parent) = path.parent() {
            // Best-effort: if this fails, Connection::open will surface the error.
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path).map_err(MemoryError::Open)?;
        let store = Store { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Open an ephemeral in-memory store (for tests).
    pub fn open_in_memory() -> Result<Store, MemoryError> {
        let conn = Connection::open_in_memory().map_err(MemoryError::Open)?;
        let store = Store { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Apply schema migrations forward from the database's current
    /// `user_version` to [`SCHEMA_VERSION`]. Idempotent: re-opening an
    /// up-to-date store is a no-op.
    fn migrate(&self) -> Result<(), MemoryError> {
        let current: u32 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(MemoryError::Migrate)?;

        if current < 1 {
            self.conn
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS prefs (
                         key        TEXT PRIMARY KEY,
                         value      TEXT NOT NULL,
                         updated_at INTEGER NOT NULL
                     );
                     PRAGMA user_version = 1;",
                )
                .map_err(MemoryError::Migrate)?;
        }
        // Future migrations: `if current < 2 { ...; PRAGMA user_version = 2; }`
        Ok(())
    }

    /// The schema version recorded in the database.
    pub fn schema_version(&self) -> Result<u32, MemoryError> {
        self.conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(MemoryError::Query)
    }

    /// Set (insert or overwrite) a preference.
    pub fn set_pref(&self, key: &str, value: &str) -> Result<(), MemoryError> {
        let now = now_millis();
        self.conn
            .execute(
                "INSERT INTO prefs (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![key, value, now],
            )
            .map_err(MemoryError::Query)?;
        Ok(())
    }

    /// Get a preference, or `None` if it is not set.
    pub fn get_pref(&self, key: &str) -> Result<Option<String>, MemoryError> {
        self.conn
            .query_row(
                "SELECT value FROM prefs WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(MemoryError::Query)
    }

    /// All preferences as `(key, value)` pairs, ordered by key.
    pub fn all_prefs(&self) -> Result<Vec<(String, String)>, MemoryError> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM prefs ORDER BY key")
            .map_err(MemoryError::Query)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(MemoryError::Query)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(MemoryError::Query)?);
        }
        Ok(out)
    }

    /// Delete a single preference. Returns `true` if a row was removed.
    pub fn delete_pref(&self, key: &str) -> Result<bool, MemoryError> {
        let n = self
            .conn
            .execute("DELETE FROM prefs WHERE key = ?1", params![key])
            .map_err(MemoryError::Query)?;
        Ok(n > 0)
    }

    /// Remove all stored data, keeping the (now-empty) schema in place.
    pub fn reset(&self) -> Result<(), MemoryError> {
        self.conn
            .execute_batch("DELETE FROM prefs;")
            .map_err(MemoryError::Query)
    }
}

/// Delete the store's database file entirely. Returns `true` if a file was
/// removed, `false` if there was nothing to delete.
///
/// This is a coarser operation than [`Store::reset`]: it removes the whole file
/// rather than clearing rows.
pub fn delete_store_file(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_store_is_at_current_schema_version() {
        let store = Store::open_in_memory().expect("open");
        assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
    }

    #[test]
    fn set_then_get_round_trips() {
        let store = Store::open_in_memory().expect("open");
        store.set_pref("editor", "nvim").expect("set");
        assert_eq!(
            store.get_pref("editor").expect("get"),
            Some("nvim".to_owned())
        );
    }

    #[test]
    fn set_overwrites_existing_value() {
        let store = Store::open_in_memory().expect("open");
        store.set_pref("mode", "beginner").expect("set");
        store.set_pref("mode", "expert").expect("set");
        assert_eq!(
            store.get_pref("mode").expect("get"),
            Some("expert".to_owned())
        );
    }

    #[test]
    fn missing_pref_is_none() {
        let store = Store::open_in_memory().expect("open");
        assert_eq!(store.get_pref("nope").expect("get"), None);
    }

    #[test]
    fn all_prefs_is_ordered_by_key() {
        let store = Store::open_in_memory().expect("open");
        store.set_pref("zeta", "1").expect("set");
        store.set_pref("alpha", "2").expect("set");
        let all = store.all_prefs().expect("all");
        assert_eq!(
            all,
            vec![
                ("alpha".to_owned(), "2".to_owned()),
                ("zeta".to_owned(), "1".to_owned())
            ]
        );
    }

    #[test]
    fn delete_pref_reports_whether_it_removed_a_row() {
        let store = Store::open_in_memory().expect("open");
        store.set_pref("k", "v").expect("set");
        assert!(store.delete_pref("k").expect("delete"));
        assert!(!store.delete_pref("k").expect("delete again"));
        assert_eq!(store.get_pref("k").expect("get"), None);
    }

    #[test]
    fn reset_clears_all_prefs_but_keeps_schema() {
        let store = Store::open_in_memory().expect("open");
        store.set_pref("a", "1").expect("set");
        store.set_pref("b", "2").expect("set");
        store.reset().expect("reset");
        assert!(store.all_prefs().expect("all").is_empty());
        // Schema is intact after reset.
        assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
    }

    #[test]
    fn migration_is_idempotent_across_reopens() {
        // Use a unique temp path; clean up before and after.
        let path = std::env::temp_dir().join("enshell-mem-migrate-idempotent.db");
        let _ = std::fs::remove_file(&path);

        {
            let store = Store::open(&path).expect("open 1");
            store.set_pref("persisted", "yes").expect("set");
            assert_eq!(store.schema_version().expect("v1"), SCHEMA_VERSION);
        }
        {
            // Reopen: migration must not error or wipe data.
            let store = Store::open(&path).expect("open 2");
            assert_eq!(store.schema_version().expect("v2"), SCHEMA_VERSION);
            assert_eq!(
                store.get_pref("persisted").expect("get"),
                Some("yes".to_owned())
            );
        }

        assert!(delete_store_file(&path).expect("delete"));
        assert!(!delete_store_file(&path).expect("delete again"));
    }

    #[test]
    fn delete_store_file_on_missing_path_is_false() {
        let path = std::env::temp_dir().join("enshell-mem-does-not-exist-xyz.db");
        let _ = std::fs::remove_file(&path);
        assert!(!delete_store_file(&path).expect("delete missing"));
    }
}
