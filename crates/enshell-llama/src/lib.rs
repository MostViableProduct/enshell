//! llama.cpp integration and Gemma 4 model loading.
//!
//! # Overview
//!
//! This crate provides `LlamaProvider` (under the `llama` feature), a real
//! [`enshell_model::ModelProvider`]
//! backed by [`llama.cpp`](https://github.com/ggerganov/llama.cpp) via the
//! [`llama-cpp-2`](https://crates.io/crates/llama-cpp-2) bindings. It loads a GGUF
//! model (e.g. Gemma 4) and runs local inference on CPU or, where available, the
//! platform's GPU backend (Metal on macOS).
//!
//! # Feature gate
//!
//! Everything that touches llama.cpp lives behind the `llama` feature. The default
//! build compiles **none** of the C++ — `cargo build -p enshell-llama` does not pull
//! in `llama-cpp-2`, does not require `cmake`, and does not build any GGML/llama.cpp
//! sources. Enable the real provider with:
//!
//! ```text
//! cargo build -p enshell-llama --features llama
//! ```
//!
//! which requires a C++ toolchain and `cmake`, and (at runtime) a GGUF model file.
//!
//! # Boundary contract
//!
//! [`enshell_model::ModelProvider::infer`] returns the model's **raw, untrusted**
//! output string. `LlamaProvider::infer` returns the decoded model output verbatim;
//! callers MUST validate it via [`enshell_intents::parse_model_output`] before acting
//! on it. The provider never returns a typed intent — the trust boundary is intentional.

// ---------------------------------------------------------------------------
// Feature OFF: the crate still compiles cleanly with no llama.cpp code.
// ---------------------------------------------------------------------------

/// Marker note for builds without the `llama` feature.
///
/// When the `llama` feature is disabled (the default), no llama.cpp bindings are
/// compiled and `LlamaProvider` is unavailable. Build with `--features llama` to
/// get the real provider. This constant exists so the default build has a small,
/// inspectable surface and documents how to enable the real backend.
#[cfg(not(feature = "llama"))]
pub const LLAMA_FEATURE_DISABLED_NOTE: &str =
    "enshell-llama built without the `llama` feature; build with --features llama for the real provider";

// ---------------------------------------------------------------------------
// Feature ON: the real llama.cpp-backed provider.
// ---------------------------------------------------------------------------

#[cfg(feature = "llama")]
mod provider {
    use std::fmt;
    use std::num::NonZeroU32;
    use std::path::Path;

    use enshell_model::{build_prompt, ModelError, ModelProvider, ModelRequest};

    use llama_cpp_2::context::params::LlamaContextParams;
    use llama_cpp_2::context::LlamaContext;
    use llama_cpp_2::llama_backend::LlamaBackend;
    use llama_cpp_2::llama_batch::LlamaBatch;
    use llama_cpp_2::model::params::LlamaModelParams;
    use llama_cpp_2::model::{AddBos, LlamaModel};
    use llama_cpp_2::sampling::LlamaSampler;

    /// Default context window size (tokens). Modest, fits the structured prompt plus
    /// the short JSON response the model is asked to produce.
    const DEFAULT_N_CTX: u32 = 4096;

    /// Hard cap on the number of tokens generated per `infer` call. The provider is
    /// asked to emit a single small JSON object, so this is generous but bounded.
    const MAX_GENERATED_TOKENS: usize = 1024;

    /// Headroom reserved in the context window for the model's response. A prompt
    /// is rejected unless at least this many tokens remain for generation, so a
    /// long prompt cannot leave the model with no room to emit a complete intent.
    const MIN_RESPONSE_TOKENS: usize = 256;

    /// Errors specific to the llama.cpp-backed provider.
    ///
    /// Each variant maps cleanly to [`ModelError::InferenceFailed`] via the
    /// [`From`] impl below, so call sites can use `?` and surface a single error
    /// type at the [`ModelProvider`] boundary.
    #[derive(Debug)]
    pub enum LlamaError {
        /// The llama backend failed to initialize.
        BackendInit(String),
        /// The GGUF model failed to load from disk.
        ModelLoad(String),
        /// A context could not be created from the model.
        ContextInit(String),
        /// Prompt tokenization failed.
        Tokenize(String),
        /// Building or filling the decode batch failed.
        Batch(String),
        /// A decode (forward pass) step failed.
        Decode(String),
        /// Decoding generated tokens back into a UTF-8 string failed.
        Detokenize(String),
        /// A configuration value was invalid (e.g. a zero context size).
        Config(String),
    }

    impl fmt::Display for LlamaError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                LlamaError::BackendInit(m) => write!(f, "llama backend init failed: {m}"),
                LlamaError::ModelLoad(m) => write!(f, "model load failed: {m}"),
                LlamaError::ContextInit(m) => write!(f, "context init failed: {m}"),
                LlamaError::Tokenize(m) => write!(f, "tokenization failed: {m}"),
                LlamaError::Batch(m) => write!(f, "batch error: {m}"),
                LlamaError::Decode(m) => write!(f, "decode failed: {m}"),
                LlamaError::Detokenize(m) => write!(f, "detokenization failed: {m}"),
                LlamaError::Config(m) => write!(f, "invalid configuration: {m}"),
            }
        }
    }

    impl std::error::Error for LlamaError {}

    impl From<LlamaError> for ModelError {
        fn from(err: LlamaError) -> Self {
            ModelError::InferenceFailed(err.to_string())
        }
    }

    /// A local [`ModelProvider`] backed by llama.cpp and a GGUF model.
    ///
    /// Construct one with [`LlamaProvider::new`], passing the path to a GGUF model
    /// file. The backend, model, and context are created once at construction and
    /// reused for every [`ModelProvider::infer`] call.
    ///
    /// # Threading
    ///
    /// Inference mutates the underlying llama.cpp context, so [`ModelProvider::infer`]
    /// takes `&self` per the trait but guards the mutable context behind a [`Mutex`].
    /// This keeps the provider `Send + Sync` and serializes concurrent `infer` calls.
    ///
    /// [`Mutex`]: std::sync::Mutex
    pub struct LlamaProvider {
        // ----------------------------------------------------------------
        // Field declaration order is load-bearing: Rust drops struct fields
        // in declaration order (top to bottom). The context borrows the
        // model, so the context (`inner`) MUST be declared — and therefore
        // dropped — before `model`, and the model before `_backend`. Do not
        // reorder these three fields.
        // ----------------------------------------------------------------
        /// The inference context, behind a `Mutex` for `&self` inference.
        ///
        /// The context borrows from `model`. We erase the borrow lifetime to
        /// `'static` via a raw pointer in [`LlamaProvider::new`]; the
        /// [`Box<LlamaModel>`] guarantees the referent's address is stable, and
        /// this field is declared first so it is dropped before `model`.
        inner: std::sync::Mutex<Inner>,
        /// The loaded GGUF model. Boxed so the context can safely hold a
        /// pointer into a stable heap address that survives moves of `self`.
        model: Box<LlamaModel>,
        /// The llama backend handle. Held for the lifetime of the provider so the
        /// backend stays initialized while the model and context are alive.
        _backend: LlamaBackend,
        /// Human-readable provider name.
        name: String,
    }

    /// The borrow-erased inference state. See [`LlamaProvider`] for the safety rationale.
    struct Inner {
        context: LlamaContext<'static>,
    }

    // SAFETY: `LlamaModel` is `Send + Sync` (the crate asserts this) and the context is
    // only ever accessed under the `Mutex`, which serializes all mutation. The raw
    // pointer used to extend the borrow lifetime points into the boxed model, whose
    // address is stable for the provider's lifetime.
    unsafe impl Send for LlamaProvider {}
    unsafe impl Sync for LlamaProvider {}

    impl LlamaProvider {
        /// Load a GGUF model from `model_path` and prepare it for inference.
        ///
        /// Initializes the llama backend (idempotent across the process), loads the
        /// model with default parameters (which use the platform GPU backend — e.g.
        /// Metal on macOS — when the bindings were built with that support, otherwise
        /// CPU), and creates a context with a modest default-sized token window.
        ///
        /// # Errors
        ///
        /// Returns [`LlamaError`] if the backend, model, or context fail to initialize.
        /// The returned error converts into [`ModelError::InferenceFailed`] via `?`.
        pub fn new(model_path: impl AsRef<Path>) -> Result<Self, LlamaError> {
            let backend =
                LlamaBackend::init().map_err(|e| LlamaError::BackendInit(e.to_string()))?;

            // Default model params: GPU offload as built (Metal on macOS), mmap on.
            let model_params = LlamaModelParams::default();

            let model = LlamaModel::load_from_file(&backend, model_path.as_ref(), &model_params)
                .map_err(|e| LlamaError::ModelLoad(e.to_string()))?;
            let model = Box::new(model);

            let n_ctx = NonZeroU32::new(DEFAULT_N_CTX)
                .ok_or_else(|| LlamaError::Config("context size must be non-zero".to_string()))?;
            let ctx_params = LlamaContextParams::default().with_n_ctx(Some(n_ctx));

            // SAFETY: We extend the lifetime of the `&model` borrow to `'static`. This is
            // sound because:
            //   * `model` is a `Box<LlamaModel>`, so its referent has a stable address
            //     that does not move when `self` moves.
            //   * `inner` (which holds the borrow) and `model` are dropped together as
            //     fields of the same struct; Rust drops fields top-to-bottom, and we
            //     declare `inner` before `model` so the context is dropped first.
            //   * The context is only accessed under the `Mutex`.
            let model_ref: &'static LlamaModel = unsafe { &*(model.as_ref() as *const LlamaModel) };

            let context = model_ref
                .new_context(&backend, ctx_params)
                .map_err(|e| LlamaError::ContextInit(e.to_string()))?;

            Ok(LlamaProvider {
                inner: std::sync::Mutex::new(Inner { context }),
                model,
                _backend: backend,
                name: "gemma-4 (llama.cpp)".to_string(),
            })
        }
    }

    impl ModelProvider for LlamaProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn infer(&self, request: &ModelRequest) -> Result<String, ModelError> {
            let prompt = build_prompt(request).text;
            let output = self.generate(&prompt)?;
            Ok(output)
        }
    }

    impl LlamaProvider {
        /// Run the tokenize -> decode -> sample loop for `prompt` and return the
        /// decoded model output.
        ///
        /// Uses greedy sampling for deterministic, low-variance JSON output (the model
        /// is asked to emit a single structured object). Stops at the model's
        /// end-of-generation token or after [`MAX_GENERATED_TOKENS`] tokens.
        fn generate(&self, prompt: &str) -> Result<String, LlamaError> {
            let mut guard = self
                .inner
                .lock()
                .map_err(|e| LlamaError::Decode(format!("inference lock poisoned: {e}")))?;
            let inner = &mut *guard;
            let ctx = &mut inner.context;

            // The context is reused across calls, so reset the KV cache before each
            // inference — otherwise request N+1 would inherit request N's sequence
            // state, hurting correctness and determinism.
            ctx.clear_kv_cache();

            // Tokenize the prompt, adding a BOS token at the start.
            let tokens = self
                .model
                .str_to_token(prompt, AddBos::Always)
                .map_err(|e| LlamaError::Tokenize(e.to_string()))?;

            if tokens.is_empty() {
                return Err(LlamaError::Tokenize(
                    "prompt produced no tokens".to_string(),
                ));
            }

            // Reject prompts that leave no room for a response: require at least
            // MIN_RESPONSE_TOKENS of generation headroom within the context window.
            let n_ctx = ctx.n_ctx() as usize;
            if tokens.len() + MIN_RESPONSE_TOKENS >= n_ctx {
                return Err(LlamaError::Config(format!(
                    "prompt is {} tokens; with {MIN_RESPONSE_TOKENS} reserved for the \
                     response that exceeds the {n_ctx}-token context window",
                    tokens.len()
                )));
            }

            // Allocate a batch large enough for the prompt (we re-use it one token at a
            // time during generation, so its capacity only needs to cover the prompt).
            let mut batch = LlamaBatch::new(tokens.len().max(1), 1);

            // Add the prompt tokens to sequence 0; request logits only for the last one.
            let last_index = tokens.len() - 1;
            for (i, token) in tokens.iter().enumerate() {
                let is_last = i == last_index;
                batch
                    .add(*token, i as i32, &[0], is_last)
                    .map_err(|e| LlamaError::Batch(e.to_string()))?;
            }

            ctx.decode(&mut batch)
                .map_err(|e| LlamaError::Decode(e.to_string()))?;

            // Greedy sampler chain: deterministic argmax selection.
            let mut sampler = LlamaSampler::chain_simple([LlamaSampler::greedy()]);

            // Accumulate the raw decoded bytes. We decode the full buffer to a
            // String once at the end via `from_utf8_lossy`, which correctly
            // handles multi-byte UTF-8 sequences split across token boundaries
            // (decoding each token in isolation could split a code point).
            let mut output_bytes: Vec<u8> = Vec::new();
            // Position of the next token to be decoded (continues after the prompt).
            let mut n_cur = tokens.len() as i32;

            for _ in 0..MAX_GENERATED_TOKENS {
                // Sample from the logits of the last token in the current batch.
                let token = sampler.sample(ctx, batch.n_tokens() - 1);

                // Stop at any end-of-generation token.
                if self.model.is_eog_token(token) {
                    break;
                }

                // Decode this token to raw bytes and append them. `special = false`
                // so control/special tokens are not rendered into the output.
                let piece = self.token_bytes(token)?;
                output_bytes.extend_from_slice(&piece);

                // Feed the sampled token back in for the next step.
                batch.clear();
                batch
                    .add(token, n_cur, &[0], true)
                    .map_err(|e| LlamaError::Batch(e.to_string()))?;
                n_cur += 1;

                // Guard against overrunning the context window.
                if n_cur as usize >= n_ctx {
                    break;
                }

                ctx.decode(&mut batch)
                    .map_err(|e| LlamaError::Decode(e.to_string()))?;
            }

            // Lossy decode of the full byte buffer: any invalid sequence becomes
            // U+FFFD rather than failing. The caller validates the JSON anyway.
            Ok(String::from_utf8_lossy(&output_bytes).into_owned())
        }

        /// Decode a single token to its raw UTF-8 bytes.
        ///
        /// Starts with a small buffer and retries once with the exact required
        /// size if llama.cpp reports the buffer was too small (it returns the
        /// needed size as a negative number, surfaced as
        /// `InsufficientBufferSpace`).
        fn token_bytes(
            &self,
            token: llama_cpp_2::token::LlamaToken,
        ) -> Result<Vec<u8>, LlamaError> {
            use llama_cpp_2::TokenToStringError;

            const INITIAL_BUFFER: usize = 32;
            match self
                .model
                .token_to_piece_bytes(token, INITIAL_BUFFER, false, None)
            {
                Ok(bytes) => Ok(bytes),
                Err(TokenToStringError::InsufficientBufferSpace(needed)) => {
                    let size = usize::try_from(-needed).map_err(|_| {
                        LlamaError::Detokenize("negative buffer size out of range".to_string())
                    })?;
                    self.model
                        .token_to_piece_bytes(token, size, false, None)
                        .map_err(|e| LlamaError::Detokenize(e.to_string()))
                }
                Err(e) => Err(LlamaError::Detokenize(e.to_string())),
            }
        }
    }
}

#[cfg(feature = "llama")]
pub use provider::{LlamaError, LlamaProvider};

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(2 + 2, 4);
    }

    #[cfg(not(feature = "llama"))]
    #[test]
    fn disabled_note_mentions_feature() {
        assert!(super::LLAMA_FEATURE_DISABLED_NOTE.contains("llama"));
    }
}
