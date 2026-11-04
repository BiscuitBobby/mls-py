//! A Welcome for a group id that already has stored state is refused, so a
//! replayed Welcome or a different group reusing the id cannot silently
//! replace a stored group. `Client::delete_group` is the explicit way out.

use mls_facade::{Client, ErrorCode, Group, DEFAULT_MAX_MESSAGE_SIZE, SUPPORTED_CIPHER_SUITES};
use mls_rs::{
    client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, CryptoProvider, MlsMessage,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

type Raw = mls_rs::Client<
    WithCryptoProvider<
        AwsLcCryptoProvider,
        WithIdentityProvider<BasicIdentityProvider, BaseConfig>,
    >,
>;

/// A plain mls-rs client: anyone who knows a group id can create a group
/// with that id.
fn raw_client(name: &str, cs: u16) -> Raw {
    let cs = CipherSuite::new(cs);
    let provider = AwsLcCryptoProvider::default();
    let (secret, public) = provider
        .cipher_suite_provider(cs)
        .unwrap()
        .signature_key_generate()
        .unwrap();
    let cred = BasicCredential::new(name.as_bytes().to_vec()).into_credential();
    mls_rs::Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(provider)
        .signing_identity(SigningIdentity::new(cred, public), secret, cs)
        .build()
}

fn client(name: &str, cs: u16) -> Client {
    Client::new(name.as_bytes(), cs, DEFAULT_MAX_MESSAGE_SIZE).unwrap()
}

fn code<T: std::fmt::Debug>(r: mls_facade::Result<T>) -> ErrorCode {
    r.unwrap_err().code
}

fn pair(cs: u16) -> (Client, Group, Client, Group) {
    let (alice, bob) = (client("alice", cs), client("bob", cs));
    let ag = alice.create_group().unwrap();
    let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
    ag.apply_pending().unwrap();
    let bg = bob.join(&w).unwrap();
    (alice, ag, bob, bg)
}

#[test]
fn welcome_reusing_a_stored_group_id_is_refused() {
    for &cs in SUPPORTED_CIPHER_SUITES {
        let (_alice, ag, bob, bg) = pair(cs);
        let gid = bg.group_id().to_vec();
        drop(bg); // no live handle; the group stays stored

        let mallory = raw_client("mallory", cs);
        let mut mg = mallory
            .create_group_with_id(gid.clone(), Default::default(), Default::default(), None)
            .unwrap();
        let kp = MlsMessage::from_bytes(&bob.key_package().unwrap()).unwrap();
        let out = mg.commit_builder().add_member(kp).unwrap().build().unwrap();
        let welcome = out.welcome_messages[0].to_bytes().unwrap();

        assert_eq!(code(bob.join(&welcome)), ErrorCode::InvalidWelcome);

        // The real group is untouched.
        let bg = bob.load_group(&gid).unwrap();
        let ct = ag.encrypt(b"still here", b"").unwrap();
        assert_eq!(
            bg.process(&ct).unwrap().data.as_deref(),
            Some(&b"still here"[..])
        );

        // Only an explicit delete lets that Welcome in; the refused join did
        // not consume the key package.
        drop(bg);
        bob.delete_group(&gid).unwrap();
        assert_eq!(code(bob.load_group(&gid)), ErrorCode::GroupNotFound);
        let joined = bob.join(&welcome).unwrap();
        assert_eq!(joined.members().unwrap()[0].1, b"mallory");
    }
}

#[test]
fn delete_group_rules() {
    for &cs in SUPPORTED_CIPHER_SUITES {
        let (_alice, _ag, bob, bg) = pair(cs);
        let gid = bg.group_id().to_vec();
        assert_eq!(code(bob.delete_group(&gid)), ErrorCode::GroupAlreadyLoaded);
        assert_eq!(code(bob.delete_group(b"unknown")), ErrorCode::GroupNotFound);
        drop(bg);
        bob.delete_group(&gid).unwrap();
        assert_eq!(code(bob.load_group(&gid)), ErrorCode::GroupNotFound);
        assert_eq!(code(bob.delete_group(&gid)), ErrorCode::GroupNotFound);
    }
}
