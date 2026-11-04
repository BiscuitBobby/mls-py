#![no_main]
//! `Group::process` on a seeded two-member group: never panic, and a
//! rejected input must leave the group fully usable.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use mls_facade::{Client, Group, DEFAULT_MAX_MESSAGE_SIZE};

struct Seed {
    alice: Group,
    bob: Group,
}

fn seed() -> &'static Seed {
    static S: OnceLock<Seed> = OnceLock::new();
    S.get_or_init(|| {
        let a = Client::new(b"alice", 1, DEFAULT_MAX_MESSAGE_SIZE).unwrap();
        let b = Client::new(b"bob", 1, DEFAULT_MAX_MESSAGE_SIZE).unwrap();
        let alice = a.create_group().unwrap();
        let (_c, w) = alice.add(&b.key_package().unwrap()).unwrap();
        alice.apply_pending().unwrap();
        let bob = b.join(&w).unwrap();
        Seed { alice, bob }
    })
}

fuzz_target!(|data: &[u8]| {
    let s = seed();
    if s.bob.process(data).is_err() {
        let ct = s.alice.encrypt(b"probe", b"").unwrap();
        assert_eq!(s.bob.process(&ct).unwrap().data.unwrap(), b"probe");
    }
});
