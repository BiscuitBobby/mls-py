#![no_main]
//! Upstream wire parsing: must never panic, and when a parsed message
//! re-encodes, the encoding must be stable.
//!
//! Note: upstream's decoder accepts some inputs its encoder refuses (a
//! reserved proposal type 0..=7 decoded as "custom"); such messages fail
//! closed when processed (signature verification re-encodes). See
//! docs/DESIGN.md §4 and `decoder_accepts_what_encoder_refuses` in
//! crates/mls-facade/tests/upstream_probe.rs.
use libfuzzer_sys::fuzz_target;
use mls_rs::MlsMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = MlsMessage::from_bytes(data) {
        if let Ok(enc) = m.to_bytes() {
            let m2 = MlsMessage::from_bytes(&enc).expect("re-parse of own encoding");
            assert_eq!(m2.to_bytes().expect("re-encode of own encoding"), enc);
        }
    }
});
