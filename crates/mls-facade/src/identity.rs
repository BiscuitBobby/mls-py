//! Identity provider: upstream `BasicIdentityProvider` semantics, plus an
//! optional application verifier consulted for every credential the group
//! accepts (members, joiners, key-package owners, external senders).

use std::sync::Arc;

use mls_rs::{
    error::IntoAnyError,
    identity::{basic::BasicIdentityProvider, CredentialType, SigningIdentity},
    time::MlsTime,
    ExtensionList, IdentityProvider,
};
use mls_rs_core::identity::MemberValidationContext;

/// Application policy binding a BasicCredential identity to a signature key.
///
/// Called while a group operation is in progress (adding a member, joining,
/// processing a commit or update). It must be fast, must not block on other
/// work using the same client, and must not call back into the facade.
pub trait MemberVerifier: Send + Sync {
    /// Return `true` to accept `identity` bound to `signature_key` (the raw
    /// public key bytes from the leaf node). Anything else rejects.
    fn verify(&self, identity: &[u8], signature_key: &[u8]) -> bool;
}

#[derive(Debug)]
pub(crate) enum IdentityError {
    /// The upstream basic provider rejected the credential (e.g. not Basic).
    Basic,
    /// The application verifier returned something other than accept.
    Rejected,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            IdentityError::Basic => "unsupported credential",
            IdentityError::Rejected => "credential rejected by verifier",
        })
    }
}

impl std::error::Error for IdentityError {}

impl IntoAnyError for IdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

#[derive(Clone, Default)]
pub(crate) struct FacadeIdentityProvider {
    verifier: Option<Arc<dyn MemberVerifier>>,
}

impl FacadeIdentityProvider {
    pub(crate) fn new(verifier: Option<Arc<dyn MemberVerifier>>) -> Self {
        Self { verifier }
    }

    fn check(&self, id: &SigningIdentity) -> Result<(), IdentityError> {
        let basic = id.credential.as_basic().ok_or(IdentityError::Basic)?;
        match &self.verifier {
            None => Ok(()),
            Some(v) if v.verify(&basic.identifier, id.signature_key.as_bytes()) => Ok(()),
            Some(_) => Err(IdentityError::Rejected),
        }
    }
}

impl IdentityProvider for FacadeIdentityProvider {
    type Error = IdentityError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        BasicIdentityProvider
            .validate_member(signing_identity, timestamp, context)
            .map_err(|_| IdentityError::Basic)?;
        self.check(signing_identity)
    }

    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        BasicIdentityProvider
            .validate_external_sender(signing_identity, timestamp, extensions)
            .map_err(|_| IdentityError::Basic)?;
        self.check(signing_identity)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        BasicIdentityProvider
            .identity(signing_identity, extensions)
            .map_err(|_| IdentityError::Basic)
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        BasicIdentityProvider
            .valid_successor(predecessor, successor, extensions)
            .map_err(|_| IdentityError::Basic)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        BasicIdentityProvider.supported_types()
    }
}

/// True if an upstream `IdentityProviderError` came from our verifier.
pub(crate) fn is_rejection(e: &mls_rs::error::AnyError) -> bool {
    matches!(
        e.inner_dyn_error().downcast_ref::<IdentityError>(),
        Some(IdentityError::Rejected)
    )
}
