//! Facade behaviour tests. Every scenario runs once per allowlisted suite.

use std::sync::Arc;
use std::thread;

use mls_facade::{
    Client, ErrorCode, EventKind, Group, DEFAULT_MAX_MESSAGE_SIZE, SUPPORTED_CIPHER_SUITES,
};

fn client(name: &str, cs: u16) -> Client {
    Client::new(name.as_bytes(), cs, DEFAULT_MAX_MESSAGE_SIZE).unwrap()
}

fn code<T: std::fmt::Debug>(r: mls_facade::Result<T>) -> ErrorCode {
    r.unwrap_err().code
}

/// Alice creates a group and adds Bob.
fn pair(cs: u16) -> (Client, Group, Client, Group) {
    let alice = client("alice", cs);
    let bob = client("bob", cs);
    let ag = alice.create_group().unwrap();
    let (_commit, welcome) = ag.add(&bob.key_package().unwrap()).unwrap();
    ag.apply_pending().unwrap();
    let bg = bob.join(&welcome).unwrap();
    (alice, ag, bob, bg)
}

fn for_each_suite(f: impl Fn(u16)) {
    for &cs in SUPPORTED_CIPHER_SUITES {
        f(cs);
    }
}

#[test]
fn create_join_roundtrip_aad_export() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        assert_eq!(ag.group_id(), bg.group_id());
        assert_eq!(ag.epoch().unwrap(), 1);
        assert_eq!(bg.epoch().unwrap(), 1);
        assert_eq!(bg.cipher_suite().unwrap(), cs);

        let ct = ag.encrypt(b"hello", b"header").unwrap();
        let ev = bg.process(&ct).unwrap();
        assert_eq!(ev.kind, EventKind::Application);
        assert_eq!(ev.data.as_deref(), Some(&b"hello"[..]));
        assert_eq!(ev.aad, b"header");
        assert_eq!(ev.sender_index, Some(0));
        assert!(!ev.removed);

        for label in [&b""[..], b"app/key"] {
            assert_eq!(
                ag.export_secret(label, b"ctx", 32).unwrap(),
                bg.export_secret(label, b"ctx", 32).unwrap()
            );
        }
        assert_ne!(
            ag.export_secret(b"a", b"", 32).unwrap(),
            ag.export_secret(b"b", b"", 32).unwrap()
        );
        let members = ag.members().unwrap();
        assert_eq!(members, vec![(0, b"alice".to_vec()), (1, b"bob".to_vec())]);
        assert_eq!(bg.leaf_index().unwrap(), 1);
    });
}

#[test]
fn three_member_sync() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let carol = client("carol", cs);
        let (commit, welcome) = bg.add(&carol.key_package().unwrap()).unwrap();
        bg.apply_pending().unwrap();
        let cg = carol.join(&welcome).unwrap();
        let ev = ag.process(&commit).unwrap();
        assert_eq!(ev.kind, EventKind::Commit);
        assert_eq!(ev.sender_index, Some(1));
        assert_eq!(ev.epoch, 2);
        for (sender, others) in [(&ag, [&bg, &cg]), (&bg, [&ag, &cg]), (&cg, [&ag, &bg])] {
            let ct = sender.encrypt(b"x", b"").unwrap();
            for o in others {
                assert_eq!(o.process(&ct).unwrap().data.unwrap(), b"x");
            }
        }
        assert_eq!(cg.leaf_index().unwrap(), 2);
    });
}

#[test]
fn removal_is_terminal_and_not_revivable() {
    for_each_suite(|cs| {
        let (_a, ag, bob, bg) = pair(cs);
        let carol = client("carol", cs);
        let (c, w) = ag.add(&carol.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        bg.process(&c).unwrap();
        let cg = carol.join(&w).unwrap();

        let rm = ag.remove(1).unwrap();
        ag.apply_pending().unwrap();
        cg.process(&rm).unwrap();
        let ev = bg.process(&rm).unwrap();
        assert!(ev.removed);
        assert_eq!(ev.kind, EventKind::Commit);
        assert_eq!(ev.epoch, 3);
        assert!(!bg.is_active().unwrap());

        // Alice and Carol continue; Bob can neither read nor act.
        let ct = ag.encrypt(b"after", b"").unwrap();
        assert_eq!(cg.process(&ct).unwrap().data.unwrap(), b"after");
        assert_eq!(code(bg.process(&ct)), ErrorCode::InvalidGroupState);
        assert_eq!(code(bg.encrypt(b"z", b"")), ErrorCode::InvalidGroupState);
        assert_eq!(code(bg.epoch()), ErrorCode::InvalidGroupState);
        assert_eq!(
            code(bg.export_secret(b"", b"", 16)),
            ErrorCode::InvalidGroupState
        );
        assert_eq!(code(bg.commit()), ErrorCode::InvalidGroupState);

        // Stored state was deleted: no revival through load_group.
        let gid = bg.group_id().to_vec();
        drop(bg);
        assert_eq!(code(bob.load_group(&gid)), ErrorCode::GroupNotFound);
        assert_eq!(ag.members().unwrap().len(), 2);
    });
}

#[test]
fn rejoin_after_removal_while_old_handle_alive() {
    for_each_suite(|cs| {
        let (_a, ag, bob, bg) = pair(cs);
        let rm = ag.remove(1).unwrap();
        ag.apply_pending().unwrap();
        assert!(bg.process(&rm).unwrap().removed);
        let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        let bg2 = bob.join(&w).unwrap();
        let ct = ag.encrypt(b"welcome back", b"").unwrap();
        assert_eq!(bg2.process(&ct).unwrap().data.unwrap(), b"welcome back");
        assert!(!bg.is_active().unwrap());
    });
}

#[test]
fn pending_commit_lifecycle() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let carol = client("carol", cs);
        assert_eq!(code(ag.apply_pending()), ErrorCode::NoPendingCommit);
        assert_eq!(code(ag.discard_pending()), ErrorCode::NoPendingCommit);

        let (_c, _w) = ag.add(&carol.key_package().unwrap()).unwrap();
        assert!(ag.has_pending_commit().unwrap());
        assert_eq!(ag.epoch().unwrap(), 1);
        assert_eq!(code(ag.encrypt(b"x", b"")), ErrorCode::PendingCommit);
        assert_eq!(
            code(ag.add(&carol.key_package().unwrap())),
            ErrorCode::PendingCommit
        );
        assert_eq!(code(ag.remove(1)), ErrorCode::PendingCommit);
        assert_eq!(code(ag.commit()), ErrorCode::PendingCommit);

        ag.discard_pending().unwrap();
        assert!(!ag.has_pending_commit().unwrap());
        assert_eq!(ag.epoch().unwrap(), 1);

        let commit = ag.commit().unwrap();
        ag.apply_pending().unwrap();
        assert_eq!(ag.epoch().unwrap(), 2);
        assert_eq!(code(ag.apply_pending()), ErrorCode::NoPendingCommit);
        assert_eq!(bg.process(&commit).unwrap().epoch, 2);
        let ct = bg.encrypt(b"ok", b"").unwrap();
        assert_eq!(ag.process(&ct).unwrap().data.unwrap(), b"ok");
    });
}

#[test]
fn own_commit_echo_applies_pending() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let commit = ag.commit().unwrap();
        let ev = ag.process(&commit).unwrap();
        assert_eq!(ev.kind, EventKind::Commit);
        assert!(!ag.has_pending_commit().unwrap());
        assert_eq!(ag.epoch().unwrap(), 2);
        bg.process(&commit).unwrap();
        assert_eq!(
            ag.export_secret(b"", b"", 16).unwrap(),
            bg.export_secret(b"", b"", 16).unwrap()
        );
    });
}

#[test]
fn competing_commit_clears_pending_and_old_bytes_are_stale() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let alice_commit = ag.commit().unwrap();
        let bob_commit = bg.commit().unwrap();
        bg.apply_pending().unwrap();
        let ev = ag.process(&bob_commit).unwrap();
        assert_eq!(ev.epoch, 2);
        assert!(!ag.has_pending_commit().unwrap());
        assert_eq!(ag.epoch().unwrap(), 2);
        assert_eq!(code(ag.apply_pending()), ErrorCode::NoPendingCommit);
        // Alice's old commit is for epoch 1: stale for Bob.
        assert_eq!(code(bg.process(&alice_commit)), ErrorCode::InvalidEpoch);
        assert_eq!(
            ag.export_secret(b"", b"", 16).unwrap(),
            bg.export_secret(b"", b"", 16).unwrap()
        );
    });
}

#[test]
fn tampered_message_and_aad_rejected_state_intact() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let ct = ag.encrypt(b"secret", b"aad-value").unwrap();
        // Flip the last byte (ciphertext/tag).
        let mut t = ct.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(bg.process(&t).is_err());
        // Flip a byte inside the cleartext authenticated data.
        let pos = ct.windows(9).position(|w| w == b"aad-value").unwrap();
        let mut t2 = ct.clone();
        t2[pos] ^= 1;
        assert!(bg.process(&t2).is_err());
        // The untampered message still decrypts afterwards.
        assert_eq!(bg.process(&ct).unwrap().data.unwrap(), b"secret");
    });
}

#[test]
fn duplicates() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let ct = ag.encrypt(b"once", b"").unwrap();
        bg.process(&ct).unwrap();
        assert_eq!(code(bg.process(&ct)), ErrorCode::InvalidMessage);

        let commit = ag.commit().unwrap();
        ag.apply_pending().unwrap();
        bg.process(&commit).unwrap();
        assert_eq!(code(bg.process(&commit)), ErrorCode::InvalidEpoch);
        assert_eq!(bg.epoch().unwrap(), 2);
        let ct = ag.encrypt(b"still fine", b"").unwrap();
        assert_eq!(bg.process(&ct).unwrap().data.unwrap(), b"still fine");
    });
}

#[test]
fn prior_epoch_retention_is_bounded() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let mut olds = Vec::new();
        for _ in 0..5 {
            olds.push(ag.encrypt(b"old", b"").unwrap());
            let c = ag.commit().unwrap();
            ag.apply_pending().unwrap();
            bg.process(&c).unwrap();
        }
        let res: Vec<_> = olds
            .iter()
            .map(|m| bg.process(m).map(|_| ()).map_err(|e| e.code))
            .collect();
        assert_eq!(
            res,
            vec![
                Err(ErrorCode::InvalidEpoch),
                Err(ErrorCode::InvalidEpoch),
                Ok(()),
                Ok(()),
                Ok(())
            ]
        );
    });
}

#[test]
fn sender_index_after_membership_change() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let carol = client("carol", cs);
        let (c, w) = ag.add(&carol.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        bg.process(&c).unwrap();
        let cg = carol.join(&w).unwrap();
        let rm = ag.remove(1).unwrap();
        ag.apply_pending().unwrap();
        cg.process(&rm).unwrap();
        bg.process(&rm).unwrap();
        // Bob's leaf (1) is now blank; Carol stays at leaf 2.
        let ct = cg.encrypt(b"c", b"").unwrap();
        assert_eq!(ag.process(&ct).unwrap().sender_index, Some(2));
        assert_eq!(
            ag.members().unwrap(),
            vec![(0, b"alice".to_vec()), (2, b"carol".to_vec())]
        );
        // A new member reuses the blank leaf 1.
        let dave = client("dave", cs);
        let (c, w) = ag.add(&dave.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        cg.process(&c).unwrap();
        let dg = dave.join(&w).unwrap();
        assert_eq!(dg.leaf_index().unwrap(), 1);
    });
}

#[test]
fn save_load_and_registry() {
    for_each_suite(|cs| {
        let (alice, ag, _b, bg) = pair(cs);
        let gid = ag.group_id().to_vec();
        assert_eq!(code(alice.load_group(&gid)), ErrorCode::GroupAlreadyLoaded);
        let ct = ag.encrypt(b"before", b"").unwrap();
        bg.process(&ct).unwrap();
        drop(ag);
        let ag = alice.load_group(&gid).unwrap();
        assert_eq!(ag.epoch().unwrap(), 1);
        // State is the latest: sending continues without generation reuse.
        let ct2 = ag.encrypt(b"after", b"").unwrap();
        assert_eq!(bg.process(&ct2).unwrap().data.unwrap(), b"after");
        assert_eq!(code(alice.load_group(b"nope")), ErrorCode::GroupNotFound);
        assert_eq!(code(alice.load_group(b"")), ErrorCode::InvalidArgument);
    });
}

#[test]
fn pending_commit_survives_reload() {
    let (alice, ag, _b, bg) = pair(1);
    let gid = ag.group_id().to_vec();
    let commit = ag.commit().unwrap();
    drop(ag);
    let ag = alice.load_group(&gid).unwrap();
    assert!(ag.has_pending_commit().unwrap());
    ag.apply_pending().unwrap();
    bg.process(&commit).unwrap();
    assert_eq!(
        ag.export_secret(b"", b"", 8).unwrap(),
        bg.export_secret(b"", b"", 8).unwrap()
    );
}

#[test]
fn join_twice_while_active_refused() {
    let alice = client("alice", 1);
    let bob = client("bob", 1);
    let ag = alice.create_group().unwrap();
    let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
    ag.apply_pending().unwrap();
    let _bg = bob.join(&w).unwrap();
    // Same Welcome again: the key package was consumed.
    assert_eq!(code(bob.join(&w)), ErrorCode::InvalidWelcome);
}

#[test]
fn key_package_reuse_across_groups_rejected() {
    let alice = client("alice", 1);
    let bob = client("bob", 1);
    let kp = bob.key_package().unwrap();
    let g1 = alice.create_group().unwrap();
    let g2 = alice.create_group().unwrap();
    let (_c1, w1) = g1.add(&kp).unwrap();
    let (_c2, w2) = g2.add(&kp).unwrap();
    bob.join(&w1).unwrap();
    assert_eq!(code(bob.join(&w2)), ErrorCode::InvalidWelcome);
}

#[test]
fn invalid_inputs() {
    let (_a, ag, bob, bg) = pair(1);
    assert_eq!(code(bob.join(b"garbage")), ErrorCode::InvalidWelcome);
    assert_eq!(
        code(bob.join(&bob.key_package().unwrap())),
        ErrorCode::InvalidWelcome
    );
    assert_eq!(code(ag.add(b"garbage")), ErrorCode::InvalidKeyPackage);
    let ct = ag.encrypt(b"x", b"").unwrap();
    assert_eq!(code(ag.add(&ct)), ErrorCode::InvalidKeyPackage);
    assert_eq!(code(bg.process(b"")), ErrorCode::InvalidMessage);
    assert_eq!(
        code(bg.process(b"\x00\x01garbage")),
        ErrorCode::InvalidMessage
    );
    assert_eq!(
        code(bg.process(&bob.key_package().unwrap())),
        ErrorCode::InvalidMessage
    );
    // Trailing bytes after a valid message are rejected.
    let mut t = ct.clone();
    t.push(0);
    assert_eq!(code(bg.process(&t)), ErrorCode::InvalidMessage);
    // Truncation.
    assert_eq!(
        code(bg.process(&ct[..ct.len() / 2])),
        ErrorCode::InvalidMessage
    );
    // Own message.
    assert_eq!(code(ag.process(&ct)), ErrorCode::InvalidMessage);
    assert_eq!(code(ag.remove(0)), ErrorCode::InvalidArgument);
    assert_eq!(code(ag.remove(7)), ErrorCode::InvalidArgument);
    assert_eq!(code(ag.remove(u32::MAX)), ErrorCode::InvalidArgument);
    // A fresh key package from a current member reuses its signature key,
    // which RFC 9420 forbids within one group.
    let kp = bob.key_package().unwrap();
    assert_eq!(code(ag.add(&kp)), ErrorCode::InvalidKeyPackage);
    assert!(!ag.has_pending_commit().unwrap());
    // After all these rejections the group still works both ways.
    let ct = ag.encrypt(b"ok", b"").unwrap();
    assert_eq!(bg.process(&ct).unwrap().data.unwrap(), b"ok");
}

#[test]
fn repeated_rejections_keep_state_intact() {
    for_each_suite(|cs| {
        let (_a, ag, _b, bg) = pair(cs);
        let first = ag.encrypt(b"first", b"").unwrap();
        let second = ag.encrypt(b"second", b"").unwrap();
        for genuine in [&second, &first] {
            for _ in 0..3 {
                let mut t = genuine.clone();
                *t.last_mut().unwrap() ^= 0x80;
                assert_eq!(code(bg.process(&t)), ErrorCode::InvalidMessage);
            }
        }
        assert_eq!(bg.process(&second).unwrap().data.unwrap(), b"second");
        assert_eq!(bg.process(&first).unwrap().data.unwrap(), b"first");
    });
}

#[test]
fn wrong_group_message() {
    let (alice, ag, _b, _bg) = pair(1);
    let other = alice.create_group().unwrap();
    let ct = other.encrypt(b"x", b"").unwrap();
    assert_eq!(code(ag.process(&ct)), ErrorCode::InvalidMessage);
}

#[test]
fn argument_bounds() {
    assert_eq!(code(Client::new(b"", 1, 1024)), ErrorCode::InvalidArgument);
    Client::new(&[7u8; 256], 1, 1024).unwrap();
    assert_eq!(
        code(Client::new(&[7u8; 257], 1, 1024)),
        ErrorCode::InvalidArgument
    );
    assert_eq!(code(Client::new(b"a", 1, 0)), ErrorCode::InvalidArgument);
    for bad in [0u16, 3, 5, 7, 0xFFFF, 65002, 65100] {
        assert_eq!(
            code(Client::new(b"a", bad, 1024)),
            ErrorCode::UnsupportedCipherSuite
        );
    }
    let (_a, ag, _b, _bg) = pair(1);
    ag.export_secret(&[1u8; 255], &[2u8; 65536], 1024).unwrap();
    assert_eq!(
        code(ag.export_secret(&[1u8; 256], b"", 16)),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(ag.export_secret(b"", &[2u8; 65537], 16)),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(ag.export_secret(b"", b"", 0)),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(ag.export_secret(b"", b"", 1025)),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn input_size_limit() {
    let alice = Client::new(b"alice", 1, DEFAULT_MAX_MESSAGE_SIZE).unwrap();
    let bob = Client::new(b"bob", 1, 1000).unwrap();
    let ag = alice.create_group().unwrap();
    let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
    ag.apply_pending().unwrap();
    let bg = bob.join(&w).unwrap();
    let big = ag.encrypt(&[0u8; 2000], b"").unwrap();
    assert_eq!(code(bg.process(&big)), ErrorCode::InputTooLarge);
    assert_eq!(
        code(bg.encrypt(&[0u8; 1001], b"")),
        ErrorCode::InputTooLarge
    );
    assert_eq!(code(bg.add(&[0u8; 1001])), ErrorCode::InputTooLarge);
    assert_eq!(code(bob.join(&[0u8; 1001])), ErrorCode::InputTooLarge);
    // Empty and moderately large application messages round trip.
    let e = ag.encrypt(b"", b"").unwrap();
    assert_eq!(bg.process(&e).unwrap().data.unwrap(), b"");
}

#[test]
fn cross_suite_inputs_rejected() {
    let a1 = client("a1", 1);
    let b2 = client("b2", 2);
    let g1 = a1.create_group().unwrap();
    assert_eq!(
        code(g1.add(&b2.key_package().unwrap())),
        ErrorCode::UnsupportedCipherSuite
    );
    let a2 = client("a2", 2);
    let g2 = a2.create_group().unwrap();
    let b1 = client("b1", 1);
    let b2b = client("b2b", 2);
    let (_c, w) = g2.add(&b2b.key_package().unwrap()).unwrap();
    assert_eq!(code(b1.join(&w)), ErrorCode::UnsupportedCipherSuite);
}

#[test]
fn group_outlives_client_and_multiple_groups() {
    let (alice, ag, bob, bg) = pair(1);
    let ag2 = alice.create_group().unwrap();
    let (_c, w) = ag2.add(&bob.key_package().unwrap()).unwrap();
    ag2.apply_pending().unwrap();
    let bg2 = bob.join(&w).unwrap();
    drop(alice);
    drop(bob);
    let m1 = ag.encrypt(b"g1", b"").unwrap();
    let m2 = ag2.encrypt(b"g2", b"").unwrap();
    assert_eq!(bg.process(&m1).unwrap().data.unwrap(), b"g1");
    assert_eq!(bg2.process(&m2).unwrap().data.unwrap(), b"g2");
    assert_eq!(code(bg.process(&m2)), ErrorCode::InvalidMessage);
}

#[test]
fn concurrent_use() {
    let (alice, ag, _bob, bg) = pair(1);
    let ag = Arc::new(ag);
    let bg = Arc::new(bg);
    let msgs: Vec<Vec<u8>> = thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|i| {
                let ag = ag.clone();
                s.spawn(move || {
                    (0..20)
                        .map(|j| ag.encrypt(format!("{i}-{j}").as_bytes(), b"").unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    let ok = thread::scope(|s| {
        let chunks: Vec<_> = msgs.chunks(40).collect();
        let hs: Vec<_> = chunks
            .into_iter()
            .map(|c| {
                let bg = bg.clone();
                let ag = ag.clone();
                s.spawn(move || {
                    let _ = ag.export_secret(b"", b"", 16).unwrap();
                    c.iter().filter(|m| bg.process(m).is_ok()).count()
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).sum::<usize>()
    });
    assert_eq!(ok, 160);
    drop(alice); // client dropped while groups still in use
    let m = ag.encrypt(b"end", b"").unwrap();
    assert_eq!(bg.process(&m).unwrap().data.unwrap(), b"end");
}

#[test]
fn concurrent_calls_after_removal() {
    let (_a, ag, _b, bg) = pair(1);
    let rm = ag.remove(1).unwrap();
    ag.apply_pending().unwrap();
    let bg = Arc::new(bg);
    thread::scope(|s| {
        let b1 = bg.clone();
        let rm2 = rm.clone();
        let h = s.spawn(move || b1.process(&rm2).map(|e| e.removed));
        let b2 = bg.clone();
        let h2 = s.spawn(move || (0..50).filter(|_| b2.encrypt(b"x", b"").is_ok()).count());
        let r = h.join().unwrap();
        let _ = h2.join().unwrap();
        assert!(r.unwrap());
    });
    assert_eq!(code(bg.encrypt(b"x", b"")), ErrorCode::InvalidGroupState);
}

#[test]
fn medium_group_within_default_limit() {
    let n = 200;
    let alice = client("alice", 1);
    let ag = alice.create_group().unwrap();
    let joiners: Vec<_> = (1..n).map(|i| client(&format!("m{i}"), 1)).collect();
    let mut last_welcome = Vec::new();
    for c in joiners.chunks(50) {
        // add() commits one member at a time; drive many quickly.
        for j in c {
            let (_commit, w) = ag.add(&j.key_package().unwrap()).unwrap();
            ag.apply_pending().unwrap();
            last_welcome = w;
        }
    }
    assert!(last_welcome.len() < DEFAULT_MAX_MESSAGE_SIZE);
    let g = joiners.last().unwrap().join(&last_welcome).unwrap();
    assert_eq!(g.members().unwrap().len(), n);
    let ct = ag.encrypt(b"all", b"").unwrap();
    assert_eq!(g.process(&ct).unwrap().data.unwrap(), b"all");
}

/// ~1000 members, one add per commit (persist after every operation).
/// Run with: cargo test --release --test facade -- --ignored --nocapture
#[test]
#[ignore = "slow; run explicitly in release mode"]
fn large_group_1000_members() {
    let n = 1000;
    let start = std::time::Instant::now();
    let alice = client("alice", 1);
    let ag = alice.create_group().unwrap();
    let joiners: Vec<_> = (1..n).map(|i| client(&format!("m{i}"), 1)).collect();
    let mut welcome = Vec::new();
    let mut max_commit = 0;
    for j in &joiners {
        let (c, w) = ag.add(&j.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        max_commit = max_commit.max(c.len());
        welcome = w;
    }
    let built = start.elapsed();
    assert!(welcome.len() < DEFAULT_MAX_MESSAGE_SIZE);
    let g = joiners.last().unwrap().join(&welcome).unwrap();
    assert_eq!(g.members().unwrap().len(), n);
    let t = std::time::Instant::now();
    for _ in 0..100 {
        let ct = ag.encrypt(b"msg", b"").unwrap();
        g.process(&ct).unwrap();
    }
    let per_msg = t.elapsed() / 100;
    let c = g.commit().unwrap();
    g.apply_pending().unwrap();
    ag.process(&c).unwrap();
    println!(
        "n={n}: build {built:?}, welcome {} B, max add-commit {max_commit} B, \
         self-update commit {} B, encrypt+process per message {per_msg:?}",
        welcome.len(),
        c.len()
    );
}
