//! Pure-Rust facade over mls-rs used by the `mls_py` Python binding.
//!
//! This crate owns every protocol-facing decision the binding makes: the MLS
//! profile, client/group lifecycle, input limits, error codes and event
//! conversion. It contains no PyO3 types and is tested with `cargo test`.
//!
//! Observed upstream behaviours that these semantics depend on are pinned in
//! `tests/upstream_probe.rs` and documented in `docs/DESIGN.md`.

mod client;
mod error;
mod group;

pub use client::Client;
pub use error::{Error, ErrorCode, Result};
pub use group::{Event, EventKind, Group};

/// Cipher suites this build accepts (RFC 9420 IANA values). Classical only in
/// v0.1; see the PQC section of docs/DESIGN.md.
pub const SUPPORTED_CIPHER_SUITES: &[u16] = &[
    1, // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (mandatory to implement)
    2, // MLS_128_DHKEMP256_AES128GCM_SHA256_P256
];

/// Default cipher suite.
pub const DEFAULT_CIPHER_SUITE: u16 = 1;

/// Default bound on any single inbound serialized input.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Bounds on caller-supplied values.
pub mod limits {
    pub const MAX_IDENTITY_LEN: usize = 256;
    pub const MAX_EXPORT_LABEL_LEN: usize = 255;
    pub const MAX_EXPORT_CONTEXT_LEN: usize = 64 * 1024;
    pub const MAX_EXPORT_LEN: usize = 1024;
}
