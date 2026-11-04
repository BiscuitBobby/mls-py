//! Cross-implementation interop: mls_py's facade (mls-rs + AWS-LC) against
//! OpenMLS (RustCrypto provider). Same-implementation round trips can share a
//! bug; these exchange real wire bytes between independent implementations.

use mls_facade::{Client, EventKind, Group, DEFAULT_MAX_MESSAGE_SIZE};
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

const SUITES: &[(u16, Ciphersuite)] = &[
    (1, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
    (2, Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
];

struct Om {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    cred: CredentialWithKey,
    cs: Ciphersuite,
}

impl Om {
    fn new(name: &str, cs: Ciphersuite) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(cs.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let cred = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Self { provider, signer, cred, cs }
    }

    fn key_package(&self) -> Vec<u8> {
        let bundle = KeyPackage::builder()
            .build(self.cs, &self.provider, &self.signer, self.cred.clone())
            .unwrap();
        MlsMessageOut::from(bundle.key_package().clone()).to_bytes().unwrap()
    }

    fn join(&self, welcome: &[u8]) -> MlsGroup {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).unwrap();
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => panic!("not a welcome"),
        };
        let cfg = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build();
        StagedWelcome::new_from_welcome(&self.provider, &cfg, welcome, None)
            .unwrap()
            .into_group(&self.provider)
            .unwrap()
    }

    fn create_group(&self) -> MlsGroup {
        MlsGroup::builder()
            .ciphersuite(self.cs)
            .use_ratchet_tree_extension(true)
            .build(&self.provider, &self.signer, self.cred.clone())
            .unwrap()
    }

    fn parse_kp(&self, bytes: &[u8]) -> KeyPackage {
        match MlsMessageIn::tls_deserialize_exact(bytes).unwrap().extract() {
            MlsMessageBodyIn::KeyPackage(kp) => {
                kp.validate(self.provider.crypto(), ProtocolVersion::Mls10).unwrap()
            }
            _ => panic!("not a key package"),
        }
    }

    /// Process `bytes`; merge commits. Returns application data if any.
    fn process(&self, g: &mut MlsGroup, bytes: &[u8]) -> Option<Vec<u8>> {
        let pm = MlsMessageIn::tls_deserialize_exact(bytes)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        match g.process_message(&self.provider, pm).unwrap().into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => Some(a.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(sc) => {
                g.merge_staged_commit(&self.provider, *sc).unwrap();
                None
            }
            _ => None,
        }
    }

    fn send(&self, g: &mut MlsGroup, data: &[u8]) -> Vec<u8> {
        g.create_message(&self.provider, &self.signer, data)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    fn export(&self, g: &MlsGroup) -> Vec<u8> {
        g.export_secret(self.provider.crypto(), "interop", b"ctx", 32).unwrap()
    }
}

fn export(g: &Group) -> Vec<u8> {
    g.export_secret(b"interop", b"ctx", 32).unwrap()
}

/// mls_py creates the group and adds an OpenMLS member.
#[test]
fn mls_py_hosts_openmls_member() {
    for &(id, cs) in SUITES {
        let alice = Client::new(b"alice", id, DEFAULT_MAX_MESSAGE_SIZE).unwrap();
        let oscar = Om::new("oscar", cs);
        let ag = alice.create_group().unwrap();
        let (_commit, welcome) = ag.add(&oscar.key_package()).unwrap();
        ag.apply_pending().unwrap();
        let mut og = oscar.join(&welcome);
        assert_eq!(og.epoch().as_u64(), ag.epoch().unwrap());
        assert_eq!(export(&ag), oscar.export(&og), "suite {id}: exporter mismatch after join");

        // Application data both ways.
        let ct = ag.encrypt(b"hi oscar", b"").unwrap();
        assert_eq!(oscar.process(&mut og, &ct).unwrap(), b"hi oscar");
        let ct = oscar.send(&mut og, b"hi alice");
        let ev = ag.process(&ct).unwrap();
        assert_eq!(ev.kind, EventKind::Application);
        assert_eq!(ev.data.unwrap(), b"hi alice");
        assert_eq!(ev.sender_index, Some(1));

        // mls_py self-update commit -> OpenMLS.
        let c = ag.commit().unwrap();
        ag.apply_pending().unwrap();
        assert!(oscar.process(&mut og, &c).is_none());
        assert_eq!(export(&ag), oscar.export(&og), "suite {id}: exporter mismatch after mls_py commit");

        // OpenMLS self-update commit -> mls_py.
        let (out, _w, _gi) = og
            .self_update(&oscar.provider, &oscar.signer, LeafNodeParameters::default())
            .unwrap()
            .into_contents();
        og.merge_pending_commit(&oscar.provider).unwrap();
        let ev = ag.process(&out.to_bytes().unwrap()).unwrap();
        assert_eq!(ev.kind, EventKind::Commit);
        assert_eq!(ev.epoch, og.epoch().as_u64());
        assert_eq!(export(&ag), oscar.export(&og), "suite {id}: exporter mismatch after OpenMLS commit");

        // A third member (mls_py) added by mls_py; OpenMLS follows.
        let carol = Client::new(b"carol", id, DEFAULT_MAX_MESSAGE_SIZE).unwrap();
        let (c, w) = ag.add(&carol.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        oscar.process(&mut og, &c);
        let cg = carol.join(&w).unwrap();
        let ct = oscar.send(&mut og, b"to both");
        assert_eq!(ag.process(&ct).unwrap().data.unwrap(), b"to both");
        assert_eq!(cg.process(&ct).unwrap().data.unwrap(), b"to both");

        // mls_py removes the OpenMLS member; OpenMLS observes its removal.
        let rm = ag.remove(1).unwrap();
        ag.apply_pending().unwrap();
        cg.process(&rm).unwrap();
        oscar.process(&mut og, &rm);
        assert!(!og.is_active(), "suite {id}: OpenMLS should see itself removed");
        assert_eq!(export(&ag), export(&cg));
    }
}

/// OpenMLS creates the group and adds an mls_py member.
#[test]
fn openmls_hosts_mls_py_member() {
    for &(id, cs) in SUITES {
        let oscar = Om::new("oscar", cs);
        let bob = Client::new(b"bob", id, DEFAULT_MAX_MESSAGE_SIZE).unwrap();
        let mut og = oscar.create_group();
        let kp = oscar.parse_kp(&bob.key_package().unwrap());
        let (_commit, welcome, _gi) = og
            .add_members(&oscar.provider, &oscar.signer, core::slice::from_ref(&kp))
            .unwrap();
        og.merge_pending_commit(&oscar.provider).unwrap();
        let bg = bob.join(&welcome.to_bytes().unwrap()).unwrap();
        assert_eq!(bg.epoch().unwrap(), og.epoch().as_u64());
        assert_eq!(export(&bg), oscar.export(&og), "suite {id}: exporter mismatch after join");
        assert_eq!(bg.members().unwrap(), vec![(0, b"oscar".to_vec()), (1, b"bob".to_vec())]);

        let ct = oscar.send(&mut og, b"hello bob");
        assert_eq!(bg.process(&ct).unwrap().data.unwrap(), b"hello bob");
        let ct = bg.encrypt(b"hello oscar", b"").unwrap();
        assert_eq!(oscar.process(&mut og, &ct).unwrap(), b"hello oscar");

        // Commits both ways.
        let c = bg.commit().unwrap();
        bg.apply_pending().unwrap();
        oscar.process(&mut og, &c);
        let (out, _w, _gi) = og
            .self_update(&oscar.provider, &oscar.signer, LeafNodeParameters::default())
            .unwrap()
            .into_contents();
        og.merge_pending_commit(&oscar.provider).unwrap();
        bg.process(&out.to_bytes().unwrap()).unwrap();
        assert_eq!(export(&bg), oscar.export(&og), "suite {id}: exporter mismatch after commits");

        // OpenMLS removes the mls_py member.
        let (rm, _w, _gi) = og
            .remove_members(&oscar.provider, &oscar.signer, &[LeafNodeIndex::new(1)])
            .unwrap();
        og.merge_pending_commit(&oscar.provider).unwrap();
        let ev = bg.process(&rm.to_bytes().unwrap()).unwrap();
        assert!(ev.removed, "suite {id}: mls_py should see itself removed");
        assert!(!bg.is_active().unwrap());
    }
}
