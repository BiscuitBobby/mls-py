//! Milestone-1 gate probes: pin *observed* mls-rs behaviour that the facade's
//! semantics depend on. If an upstream bump changes any of these, the test
//! fails and docs/DESIGN.md must be revisited before the bump lands.

use mls_rs::{
    client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider},
    error::MlsError,
    group::{CommitEffect, ReceivedMessage},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Group, MlsMessage,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

const CS: CipherSuite = CipherSuite::CURVE25519_AES128;

type Cfg = WithCryptoProvider<
    AwsLcCryptoProvider,
    WithIdentityProvider<BasicIdentityProvider, BaseConfig>,
>;

fn client(name: &str) -> Client<Cfg> {
    let provider = AwsLcCryptoProvider::default();
    let csp = provider.cipher_suite_provider(CS).unwrap();
    let (secret, public) = csp.signature_key_generate().unwrap();
    let cred = BasicCredential::new(name.as_bytes().to_vec());
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(provider)
        .signing_identity(
            SigningIdentity::new(cred.into_credential(), public),
            secret,
            CS,
        )
        .build()
}

fn kp(c: &Client<Cfg>) -> MlsMessage {
    c.generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap()
}

fn rt(m: &MlsMessage) -> MlsMessage {
    MlsMessage::from_bytes(&m.to_bytes().unwrap()).unwrap()
}

fn pair() -> (Client<Cfg>, Group<Cfg>, Client<Cfg>, Group<Cfg>) {
    let alice = client("alice");
    let bob = client("bob");
    let mut ag = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let out = ag
        .commit_builder()
        .add_member(kp(&bob))
        .unwrap()
        .build()
        .unwrap();
    ag.apply_pending_commit().unwrap();
    let (bg, _) = bob
        .join_group(None, &rt(&out.welcome_messages[0]), None)
        .unwrap();
    (alice, ag, bob, bg)
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn provider_supports_expected_classical_suites() {
    let suites = AwsLcCryptoProvider::default().supported_cipher_suites();
    assert!(suites.contains(&CipherSuite::CURVE25519_AES128));
    assert!(suites.contains(&CipherSuite::P256_AES128));
    println!("awslc suites: {suites:?}");
}

#[test]
fn client_and_group_are_send_sync() {
    assert_send_sync::<Client<Cfg>>();
    assert_send_sync::<Group<Cfg>>();
    assert_send_sync::<AwsLcCryptoProvider>();
}

#[test]
fn application_round_trip_and_aad() {
    let (_, mut ag, _, mut bg) = pair();
    let m = ag
        .encrypt_application_message(b"hi", b"aad".to_vec())
        .unwrap();
    match bg.process_incoming_message(rt(&m)).unwrap() {
        ReceivedMessage::ApplicationMessage(d) => {
            assert_eq!(d.data(), b"hi");
            assert_eq!(d.authenticated_data, b"aad");
            assert_eq!(d.sender_index, 0);
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// Observed: processing an incoming *competing* commit does NOT clear our
/// pending commit is cleared by upstream (group/mod.rs, end of the commit
/// processing path); applying afterwards fails with PendingCommitNotFound and
/// the epoch stays where the competing commit put it.
#[test]
fn competing_commit_clears_pending_upstream() {
    let (_, mut ag, _, mut bg) = pair();
    let carol = client("carol");
    // Alice prepares a commit (pending) ...
    let _alice_commit = ag
        .commit_builder()
        .add_member(kp(&carol))
        .unwrap()
        .build()
        .unwrap();
    assert!(ag.has_pending_commit());
    // ... but Bob's commit wins at the delivery service.
    let bob_commit = bg.commit(vec![]).unwrap();
    bg.apply_pending_commit().unwrap();
    let r = ag
        .process_incoming_message(rt(&bob_commit.commit_message))
        .unwrap();
    assert!(matches!(r, ReceivedMessage::Commit(_)));
    assert_eq!(ag.current_epoch(), 2);
    assert!(
        !ag.has_pending_commit(),
        "upstream behaviour changed: re-check facade logic"
    );
    let res = ag.apply_pending_commit();
    assert!(matches!(res, Err(MlsError::PendingCommitNotFound)));
    assert_eq!(ag.current_epoch(), 2);
    // Alice and Bob agree on the new epoch.
    assert_eq!(
        ag.export_secret(b"l", b"c", 16).unwrap().as_bytes(),
        bg.export_secret(b"l", b"c", 16).unwrap().as_bytes()
    );
}

/// Observed: delivering our own commit back to `process_incoming_message`
/// applies the pending commit (echo == apply).
#[test]
fn own_commit_echo_applies_pending() {
    let (_, mut ag, _, mut bg) = pair();
    let out = ag.commit(vec![]).unwrap();
    let r = ag
        .process_incoming_message(rt(&out.commit_message))
        .unwrap();
    assert!(matches!(r, ReceivedMessage::Commit(_)));
    assert!(!ag.has_pending_commit());
    assert_eq!(ag.current_epoch(), 2);
    bg.process_incoming_message(rt(&out.commit_message))
        .unwrap();
    assert_eq!(bg.current_epoch(), 2);
}

#[test]
fn duplicate_application_message() {
    let (_, mut ag, _, mut bg) = pair();
    let m = ag.encrypt_application_message(b"x", vec![]).unwrap();
    bg.process_incoming_message(rt(&m)).unwrap();
    let e = bg.process_incoming_message(rt(&m)).unwrap_err();
    println!("duplicate app message: {e:?}");
    // group still usable
    let m2 = ag.encrypt_application_message(b"y", vec![]).unwrap();
    bg.process_incoming_message(rt(&m2)).unwrap();
}

#[test]
fn duplicate_commit() {
    let (_, mut ag, _, mut bg) = pair();
    let out = ag.commit(vec![]).unwrap();
    ag.apply_pending_commit().unwrap();
    bg.process_incoming_message(rt(&out.commit_message))
        .unwrap();
    let e = bg
        .process_incoming_message(rt(&out.commit_message))
        .unwrap_err();
    println!("duplicate commit: {e:?}");
    assert_eq!(bg.current_epoch(), 2);
}

#[test]
fn prior_epoch_application_message() {
    let (_, mut ag, _, mut bg) = pair();
    let old = ag.encrypt_application_message(b"old", vec![]).unwrap();
    let out = ag.commit(vec![]).unwrap();
    ag.apply_pending_commit().unwrap();
    bg.process_incoming_message(rt(&out.commit_message))
        .unwrap();
    let r = bg.process_incoming_message(rt(&old));
    println!(
        "prior-epoch app message accepted: {:?}",
        r.as_ref().map(|_| ())
    );
    // walk 5 more epochs; retention is limited
    let old2 = ag.encrypt_application_message(b"old2", vec![]).unwrap();
    for _ in 0..5 {
        let out = ag.commit(vec![]).unwrap();
        ag.apply_pending_commit().unwrap();
        bg.process_incoming_message(rt(&out.commit_message))
            .unwrap();
    }
    let r2 = bg.process_incoming_message(rt(&old2));
    println!(
        "6-epoch-old app message: {:?}",
        r2.as_ref().map(|_| ()).map_err(|e| format!("{e:?}"))
    );
}

#[test]
fn removal_effect_and_after() {
    let (_, mut ag, _, mut bg) = pair();
    let out = ag
        .commit_builder()
        .remove_member(1)
        .unwrap()
        .build()
        .unwrap();
    ag.apply_pending_commit().unwrap();
    match bg
        .process_incoming_message(rt(&out.commit_message))
        .unwrap()
    {
        ReceivedMessage::Commit(d) => {
            assert!(matches!(d.effect, CommitEffect::Removed { .. }));
        }
        other => panic!("unexpected {other:?}"),
    }
    let after_encrypt = bg.encrypt_application_message(b"z", vec![]);
    println!("removed member encrypt: ok={}", after_encrypt.is_ok());
    let new_msg = ag.encrypt_application_message(b"secret", vec![]).unwrap();
    let r = bg.process_incoming_message(rt(&new_msg));
    assert!(
        r.is_err(),
        "removed member must not read new-epoch messages"
    );
    println!("removed member epoch: {}", bg.current_epoch());
}

#[test]
fn incoming_by_ref_proposal_blocks_encrypt() {
    let (_, mut ag, _, mut bg) = pair();
    let p = bg.propose_update(vec![]).unwrap();
    let r = ag.process_incoming_message(rt(&p)).unwrap();
    assert!(matches!(r, ReceivedMessage::Proposal(_)));
    let e = ag.encrypt_application_message(b"x", vec![]).unwrap_err();
    assert!(matches!(e, MlsError::CommitRequired));
    // An ordinary commit sweeps up the cached by-ref proposal.
    let out = ag.commit(vec![]).unwrap();
    ag.apply_pending_commit().unwrap();
    bg.process_incoming_message(rt(&out.commit_message))
        .unwrap();
    ag.encrypt_application_message(b"x", vec![]).unwrap();
}

#[test]
fn key_package_consumed_only_after_write_to_storage() {
    let alice = client("alice");
    let bob = client("bob");
    let bob_kp = kp(&bob);
    let mut g1 = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let mut g2 = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let w1 = g1
        .commit_builder()
        .add_member(bob_kp.clone())
        .unwrap()
        .build()
        .unwrap();
    let w2 = g2
        .commit_builder()
        .add_member(bob_kp)
        .unwrap()
        .build()
        .unwrap();
    let (mut bg1, _) = bob
        .join_group(None, &rt(&w1.welcome_messages[0]), None)
        .unwrap();
    let before = bob.key_package_store().key_packages().len();
    bg1.write_to_storage().unwrap();
    let after = bob.key_package_store().key_packages().len();
    println!("bob key packages before/after write_to_storage: {before}/{after}");
    let second = bob.join_group(None, &rt(&w2.welcome_messages[0]), None);
    println!(
        "second join with consumed key package: ok={}",
        second.is_ok()
    );
    assert!(second.is_err());
}

#[test]
fn welcome_contains_ratchet_tree() {
    // join_group(None, ..) succeeding in pair() already proves it; keep explicit.
    let (_, ag, _, bg) = pair();
    assert_eq!(ag.group_id(), bg.group_id());
    assert_eq!(bg.roster().members().len(), 2);
}

#[test]
fn export_secret_matches_and_empty_label() {
    let (_, ag, _, bg) = pair();
    let a = ag.export_secret(b"", b"ctx", 32).unwrap();
    let b = bg.export_secret(b"", b"ctx", 32).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
}

#[test]
fn save_while_pending_persists_pending_snapshot() {
    let (alice, mut ag, _, _) = pair();
    let _ = ag.commit(vec![]).unwrap();
    ag.write_to_storage().unwrap();
    let loaded = alice.load_group(ag.group_id()).unwrap();
    println!(
        "loaded group has pending commit: {}",
        loaded.has_pending_commit()
    );
}

/// Observed: prior epochs accumulate in memory until `write_to_storage`, which
/// trims them to the in-memory store's retention limit (3). The facade
/// persists after every state change, so retention is bounded.
#[test]
fn prior_epoch_retention_bounded_by_storage_writes() {
    let (_, mut ag, _, mut bg) = pair();
    let mut olds = Vec::new();
    for _ in 0..5 {
        olds.push(ag.encrypt_application_message(b"old", vec![]).unwrap());
        let out = ag.commit(vec![]).unwrap();
        ag.apply_pending_commit().unwrap();
        bg.process_incoming_message(rt(&out.commit_message))
            .unwrap();
        bg.write_to_storage().unwrap();
    }
    // olds[i] was sent in epoch i+1; bob is now in epoch 6.
    let accepted: Vec<bool> = olds
        .iter()
        .map(|m| bg.process_incoming_message(rt(m)).is_ok())
        .collect();
    println!("epochs 1..=5 old messages accepted: {accepted:?}");
    assert_eq!(accepted, vec![false, false, true, true, true]);
}

/// Observed: `AwsLcCryptoProvider::with_enabled_cipher_suites` only changes
/// what `supported_cipher_suites()` reports; `cipher_suite_provider()` still
/// builds every suite it implements. Upstream's own test
/// `joining_group_fails_if_cipher_suite_is_not_supported` fails under AWS-LC
/// for this reason. The facade must enforce its allowlist itself.
#[test]
fn awslc_enabled_suites_is_advisory_only() {
    let p = AwsLcCryptoProvider::with_enabled_cipher_suites(vec![CipherSuite::CURVE25519_AES128]);
    assert_eq!(
        p.supported_cipher_suites(),
        vec![CipherSuite::CURVE25519_AES128]
    );
    assert!(
        p.cipher_suite_provider(CipherSuite::P384_AES256).is_some(),
        "upstream now enforces enabled suites; facade comment can be relaxed"
    );
}

/// Observed (found by fuzzing `parse_message`): the decoder accepts a
/// proposal whose type is a reserved value 0..=7 that is not compiled in,
/// decoding it as a custom proposal that the encoder then refuses
/// (`SerializationError(Custom(2))`). It fails closed (processing re-encodes
/// content for signature verification); the facade never panics on it.
#[test]
fn decoder_accepts_what_encoder_refuses() {
    let crash: &[u8] = &[
        0x00, 0x01, 0x00, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x05, 0xef, 0x3d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];
    let m = MlsMessage::from_bytes(crash).expect("upstream decoder accepts this input");
    assert!(
        m.to_bytes().is_err(),
        "upstream fixed the asymmetry; relax this probe"
    );
    let (_, _ag, _, mut bg) = pair();
    assert!(bg.process_incoming_message(m).is_err());
}
