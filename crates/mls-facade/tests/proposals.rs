//! By-reference proposals from another (raw mls-rs) member: the facade
//! surfaces them as `proposal` events, blocks `encrypt` with
//! `commit_required`, and `commit()` sweeps them up.

use mls_facade::{Client, ErrorCode, EventKind, DEFAULT_MAX_MESSAGE_SIZE};
use mls_rs::{
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, CryptoProvider, MlsMessage,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

#[test]
fn proposal_flow_with_raw_mls_rs_member() {
    let cs = CipherSuite::CURVE25519_AES128;
    let provider = AwsLcCryptoProvider::default();
    let (sk, pk) = provider
        .cipher_suite_provider(cs)
        .unwrap()
        .signature_key_generate()
        .unwrap();
    let raw = mls_rs::Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(provider)
        .signing_identity(
            SigningIdentity::new(BasicCredential::new(b"raw".to_vec()).into_credential(), pk),
            sk,
            cs,
        )
        .build();

    let alice = Client::new(b"alice", 1, DEFAULT_MAX_MESSAGE_SIZE).unwrap();
    let ag = alice.create_group().unwrap();
    let kp = raw
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let (_commit, welcome) = ag.add(&kp.to_bytes().unwrap()).unwrap();
    ag.apply_pending().unwrap();
    let (mut rg, _) = raw
        .join_group(None, &MlsMessage::from_bytes(&welcome).unwrap(), None)
        .unwrap();

    // Raw member proposes an update by reference.
    let proposal = rg.propose_update(b"p-aad".to_vec()).unwrap();
    let ev = ag.process(&proposal.to_bytes().unwrap()).unwrap();
    assert_eq!(ev.kind, EventKind::Proposal);
    assert_eq!(ev.sender_index, Some(1));
    assert_eq!(ev.aad, b"p-aad");
    assert_eq!(ev.epoch, 1);

    assert_eq!(
        ag.encrypt(b"x", b"").unwrap_err().code,
        ErrorCode::CommitRequired
    );

    let commit = ag.commit().unwrap();
    ag.apply_pending().unwrap();
    rg.process_incoming_message(MlsMessage::from_bytes(&commit).unwrap())
        .unwrap();
    let ct = ag.encrypt(b"after commit", b"").unwrap();
    match rg
        .process_incoming_message(MlsMessage::from_bytes(&ct).unwrap())
        .unwrap()
    {
        mls_rs::group::ReceivedMessage::ApplicationMessage(d) => {
            assert_eq!(d.data(), b"after commit")
        }
        other => panic!("unexpected {other:?}"),
    }

    // Raw member's commit is processed by the facade too.
    let rc = rg.commit(vec![]).unwrap();
    rg.apply_pending_commit().unwrap();
    let ev = ag.process(&rc.commit_message.to_bytes().unwrap()).unwrap();
    assert_eq!(ev.kind, EventKind::Commit);
    assert_eq!(ev.epoch, 3);
}
