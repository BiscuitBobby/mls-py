//! Stable error codes. Messages are fixed strings chosen per upstream error
//! *variant*; they never contain plaintext, keys, or upstream `Debug` output.

use core::fmt;

use mls_rs::error::MlsError as Upstream;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    InvalidMessage,
    InvalidSignature,
    InvalidEpoch,
    InvalidGroupState,
    GroupAlreadyLoaded,
    GroupNotFound,
    PendingCommit,
    NoPendingCommit,
    CommitRequired,
    LeavePending,
    InvalidKeyPackage,
    InvalidWelcome,
    InvalidArgument,
    InputTooLarge,
    Storage,
    UnsupportedCipherSuite,
    Other,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidMessage => "invalid_message",
            ErrorCode::InvalidSignature => "invalid_signature",
            ErrorCode::InvalidEpoch => "invalid_epoch",
            ErrorCode::InvalidGroupState => "invalid_group_state",
            ErrorCode::GroupAlreadyLoaded => "group_already_loaded",
            ErrorCode::GroupNotFound => "group_not_found",
            ErrorCode::PendingCommit => "pending_commit",
            ErrorCode::NoPendingCommit => "no_pending_commit",
            ErrorCode::CommitRequired => "commit_required",
            ErrorCode::LeavePending => "leave_pending",
            ErrorCode::InvalidKeyPackage => "invalid_key_package",
            ErrorCode::InvalidWelcome => "invalid_welcome",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::InputTooLarge => "input_too_large",
            ErrorCode::Storage => "storage",
            ErrorCode::UnsupportedCipherSuite => "unsupported_cipher_suite",
            ErrorCode::Other => "other",
        }
    }

    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::InvalidMessage,
        ErrorCode::InvalidSignature,
        ErrorCode::InvalidEpoch,
        ErrorCode::InvalidGroupState,
        ErrorCode::GroupAlreadyLoaded,
        ErrorCode::GroupNotFound,
        ErrorCode::PendingCommit,
        ErrorCode::NoPendingCommit,
        ErrorCode::CommitRequired,
        ErrorCode::LeavePending,
        ErrorCode::InvalidKeyPackage,
        ErrorCode::InvalidWelcome,
        ErrorCode::InvalidArgument,
        ErrorCode::InputTooLarge,
        ErrorCode::Storage,
        ErrorCode::UnsupportedCipherSuite,
        ErrorCode::Other,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: ErrorCode,
    pub message: &'static str,
}

impl Error {
    pub(crate) const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

/// Which operation an upstream error came from; decides the code for errors
/// whose meaning depends on the input being processed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ctx {
    KeyPackage,
    Welcome,
    Message,
    Local,
}

pub(crate) fn map_upstream(ctx: Ctx, e: &Upstream) -> Error {
    use ErrorCode as C;
    let (code, message) = match e {
        Upstream::InvalidSignature => match ctx {
            Ctx::KeyPackage => (C::InvalidKeyPackage, "key package signature is invalid"),
            Ctx::Welcome => (C::InvalidWelcome, "welcome signature is invalid"),
            _ => (C::InvalidSignature, "invalid signature"),
        },
        Upstream::InvalidEpoch | Upstream::EpochNotFound => (
            C::InvalidEpoch,
            "message is for an epoch that is not available",
        ),
        Upstream::InvalidConfirmationTag => (C::InvalidMessage, "invalid confirmation tag"),
        Upstream::InvalidMembershipTag => (C::InvalidMessage, "invalid membership tag"),
        Upstream::KeyMissing(_) => (
            C::InvalidMessage,
            "message key unavailable (duplicate or already-consumed generation)",
        ),
        Upstream::InvalidFutureGeneration(_) => (
            C::InvalidMessage,
            "message generation too far in the future",
        ),
        Upstream::CantProcessMessageFromSelf => {
            (C::InvalidMessage, "message was sent by this member")
        }
        Upstream::GroupIdMismatch => (C::InvalidMessage, "message is for a different group"),
        Upstream::CipherSuiteMismatch | Upstream::UnsupportedCipherSuite(_) => (
            C::UnsupportedCipherSuite,
            "cipher suite not supported by this client",
        ),
        Upstream::UnsupportedProtocolVersion(_) | Upstream::ProtocolVersionMismatch => {
            (C::InvalidMessage, "unsupported protocol version")
        }
        Upstream::UnexpectedMessageType => match ctx {
            Ctx::KeyPackage => (C::InvalidKeyPackage, "input is not a key package"),
            Ctx::Welcome => (C::InvalidWelcome, "input is not a welcome message"),
            _ => (C::InvalidMessage, "unexpected message type"),
        },
        Upstream::SerializationError(_) => match ctx {
            Ctx::KeyPackage => (C::InvalidKeyPackage, "malformed key package"),
            Ctx::Welcome => (C::InvalidWelcome, "malformed welcome message"),
            _ => (C::InvalidMessage, "malformed message"),
        },
        Upstream::WelcomeKeyPackageNotFound => (
            C::InvalidWelcome,
            "welcome is not for any unused key package of this client",
        ),
        Upstream::InvalidWelcomeMessage | Upstream::InvalidGroupInfo => {
            (C::InvalidWelcome, "invalid welcome message")
        }
        Upstream::RatchetTreeNotFound => {
            (C::InvalidWelcome, "welcome does not carry a ratchet tree")
        }
        Upstream::DuplicateLeafData(_) => match ctx {
            Ctx::KeyPackage => (
                C::InvalidKeyPackage,
                "key package duplicates an existing member's keys",
            ),
            _ => (C::InvalidMessage, "duplicate leaf data"),
        },
        Upstream::InvalidInitKey | Upstream::InitLeafKeyEquality => {
            (C::InvalidKeyPackage, "invalid key package init key")
        }
        Upstream::TimeOverflow => (C::InvalidKeyPackage, "invalid key package lifetime"),
        Upstream::IdentityProviderError(_) => match ctx {
            Ctx::KeyPackage => (C::InvalidKeyPackage, "credential rejected"),
            Ctx::Welcome => (C::InvalidWelcome, "credential rejected"),
            _ => (C::InvalidMessage, "credential rejected"),
        },
        Upstream::ExistingPendingCommit => (C::PendingCommit, "a commit is already pending"),
        Upstream::PendingCommitNotFound => (C::NoPendingCommit, "no pending commit"),
        Upstream::CommitRequired => (
            C::CommitRequired,
            "proposals were received; call commit() before encrypting",
        ),
        Upstream::CommitterSelfRemoval => (
            C::InvalidArgument,
            "a member cannot remove itself with a commit",
        ),
        Upstream::RemovingNonExistingMember | Upstream::LeafNotFound(_) => {
            (C::InvalidArgument, "no member at that leaf index")
        }
        Upstream::InvalidTreeIndex | Upstream::InvalidNodeIndex(_) => match ctx {
            Ctx::Local => (C::InvalidArgument, "leaf index out of range"),
            _ => (C::InvalidMessage, "tree index out of range"),
        },
        Upstream::GroupNotFound => (C::GroupNotFound, "group not found"),
        Upstream::GroupStorageError(_) | Upstream::KeyPackageRepoError(_) => {
            (C::Storage, "storage operation failed")
        }
        Upstream::GroupUsedAfterReInit => (C::InvalidGroupState, "group was re-initialized"),
        Upstream::ExporterDeleted => (C::InvalidGroupState, "exporter secret was deleted"),
        Upstream::MissingRequiredPsk | Upstream::UnexpectedPskId => (
            C::InvalidMessage,
            "commit requires a pre-shared key this client does not have",
        ),
        Upstream::CryptoProviderError(_) => match ctx {
            Ctx::Local => (C::Other, "cryptographic operation failed"),
            Ctx::KeyPackage => (C::InvalidKeyPackage, "cryptographic validation failed"),
            Ctx::Welcome => (C::InvalidWelcome, "cryptographic validation failed"),
            Ctx::Message => (C::InvalidMessage, "cryptographic validation failed"),
        },
        _ => match ctx {
            Ctx::KeyPackage => (C::InvalidKeyPackage, "key package rejected"),
            Ctx::Welcome => (C::InvalidWelcome, "welcome rejected"),
            Ctx::Message => (C::InvalidMessage, "message rejected"),
            Ctx::Local => (C::Other, "operation failed"),
        },
    };
    Error::new(code, message)
}
