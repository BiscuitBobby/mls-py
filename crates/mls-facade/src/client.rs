use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use mls_rs::{
    client_builder::{
        BaseConfig, PaddingMode, WithCryptoProvider, WithIdentityProvider, WithMlsRules,
    },
    identity::{basic::BasicCredential, SigningIdentity},
    mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions},
    storage_provider::in_memory::InMemoryGroupStateStorage,
    CipherSuite, CipherSuiteProvider, CryptoProvider, MlsMessage, WireFormat,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

use crate::error::{map_upstream, Ctx, Error, ErrorCode, Result};
use crate::group::{Group, GroupShared, Lifecycle};
use crate::identity::{FacadeIdentityProvider, MemberVerifier};
use crate::{limits, DEFAULT_CIPHER_SUITE, DEFAULT_MAX_MESSAGE_SIZE, SUPPORTED_CIPHER_SUITES};

pub(crate) type Config = WithMlsRules<
    DefaultMlsRules,
    WithCryptoProvider<
        AwsLcCryptoProvider,
        WithIdentityProvider<FacadeIdentityProvider, BaseConfig>,
    >,
>;

pub(crate) type MlsClient = mls_rs::Client<Config>;

pub(crate) struct ClientInner {
    pub(crate) mls: MlsClient,
    pub(crate) cipher_suite: u16,
    pub(crate) max_message_size: usize,
    pub(crate) storage: InMemoryGroupStateStorage,
    /// One live handle per group id. Lock order: registry, then a group's
    /// state lock. Never take the registry lock while holding a group lock.
    registry: Mutex<HashMap<Vec<u8>, Weak<GroupShared>>>,
}

impl ClientInner {
    fn registry(&self) -> Result<MutexGuard<'_, HashMap<Vec<u8>, Weak<GroupShared>>>> {
        self.registry
            .lock()
            .map_err(|_| Error::new(ErrorCode::Other, "internal lock poisoned"))
    }

    pub(crate) fn check_size(&self, input: &[u8]) -> Result<()> {
        if input.len() > self.max_message_size {
            return Err(Error::new(
                ErrorCode::InputTooLarge,
                "input exceeds max_message_size",
            ));
        }
        Ok(())
    }
}

/// Optional settings for [`Client::with_options`].
#[derive(Clone)]
pub struct ClientOptions {
    pub cipher_suite: u16,
    /// Bound on every inbound serialized input.
    pub max_message_size: usize,
    /// Application policy for every credential the client's groups accept.
    /// `None` accepts any well-formed BasicCredential (unverified labels).
    pub verifier: Option<Arc<dyn MemberVerifier>>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            cipher_suite: DEFAULT_CIPHER_SUITE,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            verifier: None,
        }
    }
}

/// An MLS client: one identity, one signing key, one cipher suite, and a
/// process-local in-memory store for key packages and group state.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new(identity: &[u8], cipher_suite: u16, max_message_size: usize) -> Result<Self> {
        Self::with_options(
            identity,
            ClientOptions {
                cipher_suite,
                max_message_size,
                ..Default::default()
            },
        )
    }

    pub fn with_options(identity: &[u8], options: ClientOptions) -> Result<Self> {
        let ClientOptions {
            cipher_suite,
            max_message_size,
            verifier,
        } = options;
        if identity.is_empty() || identity.len() > limits::MAX_IDENTITY_LEN {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "identity must be 1..=256 bytes",
            ));
        }
        if max_message_size == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "max_message_size must be positive",
            ));
        }
        if !SUPPORTED_CIPHER_SUITES.contains(&cipher_suite) {
            return Err(Error::new(
                ErrorCode::UnsupportedCipherSuite,
                "cipher suite not in SUPPORTED_CIPHER_SUITES",
            ));
        }
        let cs = CipherSuite::new(cipher_suite);
        // Advertise only the allowlist (it feeds leaf-node capabilities).
        // This does NOT enforce anything: the AWS-LC provider builds any suite
        // it implements regardless of this list (pinned in
        // tests/upstream_probe.rs). The facade checks suites itself in
        // `join` (Welcome) and `Group::add` (KeyPackage).
        let provider = AwsLcCryptoProvider::with_enabled_cipher_suites(
            SUPPORTED_CIPHER_SUITES
                .iter()
                .map(|s| CipherSuite::new(*s))
                .collect(),
        );
        let csp = provider.cipher_suite_provider(cs).ok_or(Error::new(
            ErrorCode::UnsupportedCipherSuite,
            "cipher suite not available from the crypto provider",
        ))?;
        let (secret, public) = csp
            .signature_key_generate()
            .map_err(|_| Error::new(ErrorCode::Other, "signature key generation failed"))?;
        let credential = BasicCredential::new(identity.to_vec()).into_credential();

        // Every commit carries an UpdatePath, so the committer always refreshes
        // its own leaf key (post-compromise security). Welcomes embed the
        // ratchet tree so joiners need nothing out of band. Commits and
        // proposals are sent as PrivateMessage: the delivery service sees
        // group id, epoch and content type, but not membership changes; this
        // also matches OpenMLS's default (it rejects plaintext handshakes).
        let rules = DefaultMlsRules::new()
            .with_commit_options(
                CommitOptions::new()
                    .with_path_required(true)
                    .with_ratchet_tree_extension(true)
                    .with_single_welcome_message(true)
                    .with_allow_external_commit(false),
            )
            .with_encryption_options(EncryptionOptions::new(true, PaddingMode::StepFunction));

        let mls = mls_rs::Client::builder()
            .identity_provider(FacadeIdentityProvider::new(verifier))
            .crypto_provider(provider)
            .mls_rules(rules)
            .signing_identity(SigningIdentity::new(credential, public), secret, cs)
            .build();
        let storage = mls.group_state_storage();

        Ok(Self {
            inner: Arc::new(ClientInner {
                mls,
                cipher_suite,
                max_message_size,
                storage,
                registry: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn cipher_suite(&self) -> u16 {
        self.inner.cipher_suite
    }

    pub fn max_message_size(&self) -> usize {
        self.inner.max_message_size
    }

    /// A fresh, single-use key package. Its private keys stay in this
    /// client's store until a Welcome consumes them.
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let msg = self
            .inner
            .mls
            .generate_key_package_message(Default::default(), Default::default(), None)
            .map_err(|e| map_upstream(Ctx::Local, &e))?;
        msg.to_bytes().map_err(|e| map_upstream(Ctx::Local, &e))
    }

    pub fn create_group(&self) -> Result<Group> {
        let group = self
            .inner
            .mls
            .create_group(Default::default(), Default::default(), None)
            .map_err(|e| map_upstream(Ctx::Local, &e))?;
        self.install(group)
    }

    pub fn join(&self, welcome: &[u8]) -> Result<Group> {
        self.inner.check_size(welcome)?;
        let msg = MlsMessage::from_bytes(welcome).map_err(|e| map_upstream(Ctx::Welcome, &e))?;
        if msg.wire_format() != WireFormat::Welcome {
            return Err(Error::new(
                ErrorCode::InvalidWelcome,
                "input is not a welcome message",
            ));
        }
        if msg.cipher_suite().map(u16::from) != Some(self.inner.cipher_suite) {
            return Err(Error::new(
                ErrorCode::UnsupportedCipherSuite,
                "welcome uses a different cipher suite than this client",
            ));
        }
        let (group, _info) = self
            .inner
            .mls
            .join_group(None, &msg, None)
            .map_err(|e| map_upstream(Ctx::Welcome, &e))?;
        self.install(group)
    }

    pub fn load_group(&self, group_id: &[u8]) -> Result<Group> {
        if group_id.is_empty() || group_id.len() > self.inner.max_message_size {
            return Err(Error::new(ErrorCode::InvalidArgument, "invalid group id"));
        }
        let mut registry = self.inner.registry()?;
        if let Some(existing) = registry.get(group_id).and_then(Weak::upgrade) {
            // A live terminal handle (e.g. removed) owns no stored state; fall
            // through so the caller gets `group_not_found`.
            if existing.lifecycle()? == Lifecycle::Active {
                return Err(Error::new(
                    ErrorCode::GroupAlreadyLoaded,
                    "a live handle for this group already exists",
                ));
            }
        }
        let group = self.inner.mls.load_group(group_id).map_err(|e| match e {
            mls_rs::error::MlsError::GroupNotFound => {
                Error::new(ErrorCode::GroupNotFound, "group not found")
            }
            mls_rs::error::MlsError::SerializationError(_) => {
                Error::new(ErrorCode::Storage, "stored group state is corrupt")
            }
            other => map_upstream(Ctx::Local, &other),
        })?;
        let shared = GroupShared::new(self.inner.clone(), group);
        registry.insert(group_id.to_vec(), Arc::downgrade(&shared));
        Ok(Group::from_shared(shared))
    }

    /// Persist and register a freshly created/joined group. A Welcome for a group that
    /// still has a live *active* handle is refused; a live handle in a
    /// terminal state (e.g. removed) is superseded, which is how rejoining
    /// after removal works.
    ///
    /// The registry is checked *before* anything is written, so a refused
    /// Welcome neither overwrites the live group's stored state nor consumes
    /// the key package.
    fn install(&self, mut group: crate::group::MlsGroup) -> Result<Group> {
        let group_id = group.group_id().to_vec();
        let mut registry = self.inner.registry()?;
        registry.retain(|_, w| w.strong_count() > 0);
        if let Some(existing) = registry.get(&group_id).and_then(Weak::upgrade) {
            if existing.lifecycle()? == Lifecycle::Active {
                return Err(Error::new(
                    ErrorCode::GroupAlreadyLoaded,
                    "a live, active handle for this group already exists",
                ));
            }
        }
        // For a join, writing state is what deletes the consumed key
        // package's private keys from the key-package store (observed
        // upstream behaviour, pinned in tests/upstream_probe.rs).
        group
            .write_to_storage()
            .map_err(|e| map_upstream(Ctx::Local, &e))?;
        let shared = GroupShared::new(self.inner.clone(), group);
        registry.insert(group_id, Arc::downgrade(&shared));
        Ok(Group::from_shared(shared))
    }
}

/// Never prints keys or stored state.
impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("cipher_suite", &self.inner.cipher_suite)
            .finish_non_exhaustive()
    }
}
