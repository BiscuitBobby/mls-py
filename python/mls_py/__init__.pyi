import os
from typing import Callable, Final, Literal, Optional, Tuple, List, Union, final

__version__: str

SUPPORTED_CIPHER_SUITES: Final[Tuple[int, ...]]
"""RFC 9420 cipher-suite IDs accepted by this build (classical only in v0.1)."""
DEFAULT_CIPHER_SUITE: Final[int]
DEFAULT_MAX_MESSAGE_SIZE: Final[int]
ERROR_CODES: Final[Tuple[str, ...]]

ErrorCode = Literal[
    "invalid_message",
    "invalid_signature",
    "invalid_epoch",
    "invalid_group_state",
    "group_already_loaded",
    "group_not_found",
    "pending_commit",
    "no_pending_commit",
    "commit_required",
    "leave_pending",
    "invalid_key_package",
    "invalid_welcome",
    "identity_rejected",
    "invalid_argument",
    "input_too_large",
    "storage",
    "unsupported_cipher_suite",
    "other",
]

class MlsError(Exception):
    """An MLS operation failed. Messages never contain plaintext or keys."""

    code: ErrorCode
    message: str

@final
class Event:
    """Immutable result of :meth:`Group.process`. ``repr`` omits contents."""

    @property
    def kind(self) -> Literal["application", "commit", "proposal", "other"]: ...
    @property
    def data(self) -> Optional[bytes]:
        """Decrypted application data (``application`` events only)."""
    @property
    def aad(self) -> bytes:
        """Authenticated but *not encrypted* data sent with the message."""
    @property
    def sender_index(self) -> Optional[int]:
        """Sender's MLS leaf index; ``None`` for non-member senders.

        Stable while that member stays in the group, but a leaf freed by a
        removal can be reused by a later member: it is not an identity.
        """
    @property
    def epoch(self) -> int:
        """Epoch after processing."""
    @property
    def removed(self) -> bool:
        """True if this commit removed us; the group is now terminal."""
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Client:
    """One identity, one signing key, one cipher suite, one store."""

    def __init__(
        self,
        identity: bytes,
        *,
        cipher_suite: int = 1,
        max_message_size: int = 16 * 2**20,
        verifier: Optional[Callable[[bytes, bytes], bool]] = None,
        storage: Optional[Union[str, os.PathLike[str]]] = None,
    ) -> None:
        """``identity`` is a BasicCredential label (1..=256 bytes).

        ``max_message_size`` bounds every inbound serialized input (messages,
        commits, proposals, welcomes, key packages).

        ``verifier(identity, signature_key)`` is called for every credential
        this client's groups accept, including its own; only ``True``
        accepts. Anything else, or an exception (reported to
        ``sys.unraisablehook``), fails the operation with
        ``identity_rejected`` and leaves state unchanged. It must not call
        mls_py (``RuntimeError``) and should not reference this client.
        Without a verifier, identities are unverified labels.

        ``storage`` is a SQLite file holding this client's signing key, key
        packages and group state (owner-only permissions, unencrypted:
        protect it like a private key). It is bound to ``identity`` and
        ``cipher_suite`` and locked while the client or any of its groups is
        alive. ``None`` keeps everything in process memory.
        """
    @property
    def cipher_suite(self) -> int: ...
    @property
    def max_message_size(self) -> int: ...
    def key_package(self) -> bytes:
        """A fresh, single-use key package."""
    def create_group(self) -> Group: ...
    def join(self, welcome: bytes) -> Group:
        """Join from a Welcome; consumes the matching key package.

        Raises ``invalid_welcome`` if this client already has stored state
        for that group id (a replay, or a different group reusing the id);
        see :meth:`delete_group`.
        """
    def group_ids(self) -> List[bytes]:
        """Ids of the groups in this client's store, sorted."""
    def delete_group(self, group_id: bytes) -> None:
        """Delete a stored group that has no live handle (``group_not_found``
        if there is none, ``group_already_loaded`` while a handle is alive)."""
    def load_group(self, group_id: bytes) -> Group:
        """Re-open a group whose previous handle was released.

        Raises ``group_already_loaded`` while another handle is alive and
        ``group_not_found`` for unknown or removed groups.
        """

@final
class Group:
    """Handle to one MLS group. State is saved in the client's store after
    every successful operation; a failed operation leaves the state
    unchanged."""

    @property
    def group_id(self) -> bytes: ...
    @property
    def is_active(self) -> bool:
        """False once removed (or after an unrecoverable error)."""
    @property
    def epoch(self) -> int: ...
    @property
    def leaf_index(self) -> int:
        """Our current leaf index."""
    @property
    def cipher_suite(self) -> int: ...
    @property
    def has_pending_commit(self) -> bool: ...
    @property
    def leave_pending(self) -> bool:
        """True between :meth:`leave` and the next commit in this group."""
    @property
    def members(self) -> List[Tuple[int, bytes]]:
        """``(leaf_index, identity)`` for each current member."""
    def add(self, key_package: bytes) -> Tuple[bytes, bytes]:
        """Create a commit adding a member: ``(commit, welcome)``.

        The commit is pending; the epoch does not change until
        :meth:`apply_pending`. Keep the exact returned bytes.
        """
    def remove(self, leaf_index: int) -> bytes:
        """Create a commit removing the member at ``leaf_index`` (pending)."""
    def leave(self) -> bytes:
        """Ask to leave: a Remove proposal for our own leaf, to send to the group.

        Another member must commit it; that commit yields
        ``Event(removed=True)``. Until then ``add``/``remove``/``commit``/
        ``encrypt`` raise ``leave_pending`` (committing ourselves would drop the
        removal). A commit that does not remove us voids the proposal; call
        ``leave()`` again.
        """
    def commit(self) -> bytes:
        """Create a commit that refreshes our own leaf key (post-compromise
        security) and includes any proposals received by reference (pending)."""
    def apply_pending(self) -> None:
        """Apply the stored pending commit. A local state transition, not a
        delivery confirmation."""
    def discard_pending(self) -> None: ...
    def process(self, message: bytes) -> Event:
        """Process an inbound commit, proposal or application message."""
    def encrypt(self, data: bytes, aad: Optional[bytes] = None) -> bytes:
        """Encrypt an application message. ``aad`` is authenticated, not
        encrypted."""
    def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
        """MLS exporter: ``label`` <= 255 B, ``context`` <= 64 KiB,
        ``0 < length <= 1024``."""
