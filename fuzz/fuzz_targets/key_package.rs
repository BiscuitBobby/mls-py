#![no_main]
//! Key-package parsing/validation via `Group::add`: never panic; a rejected
//! key package leaves no pending commit.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use mls_facade::{Client, Group, DEFAULT_MAX_MESSAGE_SIZE};

fn group() -> &'static Group {
    static G: OnceLock<Group> = OnceLock::new();
    G.get_or_init(|| {
        Client::new(b"alice", 1, DEFAULT_MAX_MESSAGE_SIZE)
            .unwrap()
            .create_group()
            .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let g = group();
    match g.add(data) {
        Ok(_) => g.discard_pending().unwrap(),
        Err(_) => assert!(!g.has_pending_commit().unwrap()),
    }
});
