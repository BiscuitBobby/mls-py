#![no_main]
//! `Client::join` with arbitrary bytes, against a client holding an unused
//! key package: never panic.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use mls_facade::{Client, DEFAULT_MAX_MESSAGE_SIZE};

fn client() -> &'static Client {
    static C: OnceLock<Client> = OnceLock::new();
    C.get_or_init(|| {
        let c = Client::new(b"bob", 1, DEFAULT_MAX_MESSAGE_SIZE).unwrap();
        let _ = c.key_package().unwrap();
        c
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = client().join(data);
});
