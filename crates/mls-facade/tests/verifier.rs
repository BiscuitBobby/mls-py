//! Application verifier (`ClientOptions::verifier`): consulted for every
//! credential a group accepts; a rejection fails the operation and leaves
//! state unchanged. Every scenario runs once per allowlisted suite.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use mls_facade::{Client, ClientOptions, ErrorCode, MemberVerifier, SUPPORTED_CIPHER_SUITES};

/// Records every call; rejects the identities in `deny`.
#[derive(Default)]
struct Policy {
    deny: Vec<&'static [u8]>,
    seen: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl MemberVerifier for Policy {
    fn verify(&self, identity: &[u8], signature_key: &[u8]) -> bool {
        self.seen
            .lock()
            .unwrap()
            .push((identity.to_vec(), signature_key.to_vec()));
        !self.deny.contains(&identity)
    }
}

impl Policy {
    fn deny(ids: &[&'static [u8]]) -> Arc<Self> {
        Arc::new(Self {
            deny: ids.to_vec(),
            ..Default::default()
        })
    }
    fn identities(&self) -> HashSet<Vec<u8>> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(i, _)| i.clone())
            .collect()
    }
    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

fn client(name: &str, cs: u16, policy: Option<Arc<Policy>>) -> Client {
    Client::with_options(
        name.as_bytes(),
        ClientOptions {
            cipher_suite: cs,
            verifier: policy.map(|p| p as Arc<dyn MemberVerifier>),
            ..Default::default()
        },
    )
    .unwrap()
}

fn code<T: std::fmt::Debug>(r: mls_facade::Result<T>) -> ErrorCode {
    r.unwrap_err().code
}

fn for_each_suite(f: impl Fn(u16)) {
    for &cs in SUPPORTED_CIPHER_SUITES {
        f(cs);
    }
}

#[test]
fn verifier_sees_every_member_with_a_stable_key() {
    for_each_suite(|cs| {
        let (pa, pb) = (Policy::deny(&[]), Policy::deny(&[]));
        let alice = client("alice", cs, Some(pa.clone()));
        let bob = client("bob", cs, Some(pb.clone()));
        let ag = alice.create_group().unwrap();
        let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        assert!(
            pa.identities().contains(b"bob".as_slice()),
            "adder checks the joiner"
        );

        let bg = bob.join(&w).unwrap();
        let seen = pb.identities();
        assert!(
            seen.contains(b"alice".as_slice()),
            "joiner checks existing members"
        );

        // One identity, one key: the same bytes in every call.
        let keys = |p: &Policy, id: &[u8]| -> HashSet<Vec<u8>> {
            p.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(i, _)| i == id)
                .map(|(_, k)| k.clone())
                .collect()
        };
        assert_eq!(keys(&pb, b"alice").len(), 1);
        assert_eq!(keys(&pa, b"bob").len(), 1);
        assert_ne!(keys(&pb, b"alice"), keys(&pa, b"bob"));

        // A commit's new leaf node is checked by the receiver.
        let before = pb.calls();
        let c = ag.commit().unwrap();
        ag.apply_pending().unwrap();
        bg.process(&c).unwrap();
        assert!(pb.calls() > before);
    });
}

#[test]
fn adder_rejects_key_package() {
    for_each_suite(|cs| {
        let alice = client("alice", cs, Some(Policy::deny(&[b"mallory"])));
        let ag = alice.create_group().unwrap();
        let kp = client("mallory", cs, None).key_package().unwrap();
        assert_eq!(code(ag.add(&kp)), ErrorCode::IdentityRejected);
        assert!(!ag.has_pending_commit().unwrap());
        assert_eq!(ag.epoch().unwrap(), 0);
        let ok = client("bob", cs, None).key_package().unwrap();
        ag.add(&ok).unwrap();
    });
}

#[test]
fn joiner_rejects_welcome_with_unacceptable_member() {
    for_each_suite(|cs| {
        let mallory = client("mallory", cs, None);
        let bob = client("bob", cs, Some(Policy::deny(&[b"mallory"])));
        let mg = mallory.create_group().unwrap();
        let (_c, w) = mg.add(&bob.key_package().unwrap()).unwrap();
        mg.apply_pending().unwrap();
        assert_eq!(code(bob.join(&w)), ErrorCode::IdentityRejected);
    });
}

#[test]
fn receiver_rejects_commit_adding_unacceptable_member() {
    for_each_suite(|cs| {
        let alice = client("alice", cs, None);
        let bob = client("bob", cs, Some(Policy::deny(&[b"mallory"])));
        let ag = alice.create_group().unwrap();
        let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        let bg = bob.join(&w).unwrap();

        let kp = client("mallory", cs, None).key_package().unwrap();
        let (commit, _w) = ag.add(&kp).unwrap();
        ag.apply_pending().unwrap();
        assert_eq!(code(bg.process(&commit)), ErrorCode::IdentityRejected);
        // Bob's state is untouched: still at the old epoch, still active.
        assert_eq!(bg.epoch().unwrap(), 1);
        assert!(bg.is_active().unwrap());
        assert_eq!(bg.members().unwrap().len(), 2);
    });
}

#[test]
fn own_identity_is_checked_too() {
    for_each_suite(|cs| {
        let alice = client("alice", cs, Some(Policy::deny(&[b"alice"])));
        assert_eq!(code(alice.create_group()), ErrorCode::IdentityRejected);
    });
}
