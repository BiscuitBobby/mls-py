# mls_py

`mls_py` is a minimal Python binding for the [mls-rs](https://github.com/awslabs/mls-rs)
implementation of Messaging Layer Security (MLS, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)):
a synchronous, byte-oriented API for creating groups, managing membership,
processing messages and exporting group secrets. It prioritizes a small API
surface, explicit state transitions, and Rust-managed cryptographic state.

The Python API is small; the security model is not trimmed to match. Read the
[security section](#security) before building on it.

## Install

```sh
pip install mls_py
```

CI builds abi3 wheels (CPython 3.9+) for Linux x86_64/aarch64 (manylinux_2_28, glibc
2.28+), macOS x86_64 and arm64 (separate wheels), Windows x64. Building from
source needs a Rust toolchain (1.89+), cmake, a C compiler (for AWS-LC) and
network access to github.com: mls-rs is pinned to an upstream git commit
(see `docs/DESIGN.md` §1).

## Example

```python
import mls_py

alice = mls_py.Client(b"alice")
bob = mls_py.Client(b"bob")

group = alice.create_group()
commit, welcome = group.add(bob.key_package())   # pending; epoch unchanged
group.apply_pending()                            # after your server accepts `commit`
bob_group = bob.join(welcome)

ct = group.encrypt(b"hello", b"header")          # aad is authenticated, NOT encrypted
ev = bob_group.process(ct)
assert (ev.kind, ev.data, ev.aad, ev.sender_index) == ("application", b"hello", b"header", 0)

# Same secret on both sides, e.g. to key an app-level channel:
assert group.export_secret(b"my-app/v1", b"", 32) == bob_group.export_secret(b"my-app/v1", b"", 32)
```

## API

```python
SUPPORTED_CIPHER_SUITES: tuple[int, ...]     # (1, 2) in v0.1; classical only
Client(identity: bytes, *, cipher_suite: int = 1, max_message_size: int = 16 * 2**20,
       verifier: Callable[[bytes, bytes], bool] | None = None,
       storage: str | os.PathLike | None = None)  # None: process memory
client.cipher_suite, client.max_message_size
client.group_ids() -> [group_id, ...]        # groups in this client's store
client.key_package() -> bytes                # fresh, single-use
client.create_group() -> Group
client.join(welcome: bytes) -> Group
client.load_group(group_id: bytes) -> Group
client.delete_group(group_id: bytes)         # discard stored state you know is stale

group.add(key_package) -> (commit, welcome)  # pending
group.remove(leaf_index) -> commit           # pending
group.commit() -> commit                     # pending; self-update + received proposals
group.leave() -> proposal                    # ask another member to remove us
group.apply_pending() / group.discard_pending()
group.process(message) -> Event
group.encrypt(data, aad=b"") -> bytes
group.export_secret(label, context, length) -> bytes
group.group_id, .epoch, .leaf_index, .cipher_suite, .has_pending_commit,
      .leave_pending, .is_active
group.members -> [(leaf_index, identity), ...]

Event: kind ("application" | "commit" | "proposal" | "other"), data, aad,
       sender_index, epoch, removed        # immutable; repr omits contents
MlsError: .code (stable string, see mls_py.ERROR_CODES), .message
```

Inputs accept `bytes` or `bytearray`. Integer arguments reject `bool`/non-int
with `TypeError`; out-of-range values raise `MlsError(code="invalid_argument")`.

### Error codes

`invalid_message`, `invalid_signature`, `invalid_epoch`, `invalid_group_state`,
`group_already_loaded`, `group_not_found`, `pending_commit`,
`no_pending_commit`, `commit_required`, `leave_pending`, `invalid_key_package`,
`invalid_welcome`, `identity_rejected`, `invalid_argument`, `input_too_large`, `storage`,
`unsupported_cipher_suite`, `other`. Messages never contain plaintext, keys or
internal state.

## State semantics

**Local commits.** `add`, `remove` and `commit` create a *pending* commit; the
epoch does not change until `apply_pending()`, which applies exactly the stored
commit. While pending, `add`/`remove`/`commit`/`encrypt` raise `pending_commit`.
`apply_pending()`/`discard_pending()` with nothing pending raise
`no_pending_commit`.

- Keep the exact returned bytes and send them. `apply_pending()` is a **local
  state transition, not delivery confirmation**: call it once your delivery
  service has accepted the commit. Processing your own commit when the server
  echoes it back (`group.process(commit)`) applies it too.
- If the app crashes after applying but before distributing, your epoch is
  ahead of everyone else's.
- **Competing commits.** If another member's commit is accepted first,
  `process()` applies it and *clears* your pending commit. Your old commit bytes
  are then **stale: do not retransmit them** (peers reject them with
  `invalid_epoch`). Rebuild your change on the new epoch.

**Incoming messages.** `process()` applies valid commits immediately. A
rejected message leaves group state exactly as it was. Duplicate application
messages raise `invalid_message`, duplicate/stale commits `invalid_epoch`.
Application messages from the last 3 epochs still decrypt; older ones raise
`invalid_epoch`.

**Proposals.** Other members (or other implementations) may send proposals by
reference; they arrive as `kind == "proposal"`. Until someone commits them,
`encrypt` raises `commit_required`; call `group.commit()` (or receive a commit).

**Removal.** A commit that removes you yields `Event(removed=True)`. The group
becomes terminal: `is_active` is false, every other call raises
`invalid_group_state`, its stored state is deleted, and `load_group` raises
`group_not_found`. A member cannot remove itself with a commit; another member
must remove it (see *Leaving*). A removed client can be re-added with a new
key package.

**Leaving.** `leave()` returns an RFC 9420 Remove proposal for your own leaf;
send it to the group. Another member commits it (`commit()` picks it up), and
processing that commit gives you `Event(removed=True)`. Until then
`leave_pending` is true and `add`/`remove`/`commit`/`encrypt`/`leave` raise
`leave_pending`: a commit you made yourself would silently drop your removal.
The proposal lives only in the current epoch: if a commit arrives that does
not remove you, `leave_pending` becomes false and you can call `leave()` again.
Processing your own proposal when the server echoes it back is harmless.

**Verifying identities.** Without a verifier, a `BasicCredential` identity
is a label anyone can claim. Pass `verifier(identity, signature_key) -> bool`
to bind identities to keys you trust, for example keys from your directory or
key-transparency service. It is called for every credential your groups
accept: each member in a Welcome you join (including yourself), the owner of a
key package you add, new members and updated leaves in commits you process,
and your own credential when you create a group. Only `True` accepts. Any
other value, or an exception (reported to `sys.unraisablehook`), fails the
operation with `identity_rejected`, and group state is unchanged.

- It runs in the middle of an MLS operation, possibly on another thread. Keep
  it fast and free of side effects.
- It must not call `mls_py` (that raises `RuntimeError`) or wait on threads
  that do.
- Do not reference the `Client` or its groups from the verifier. Rust holds
  that reference where Python's cycle collector can't see it, so the client
  would never be freed.
- All members should apply the same policy. A member that rejects a commit
  others accepted cannot follow the group from that epoch on.

**Sender index.** `sender_index` is an MLS *leaf index*, not an identity. It is
stable while that member stays in the group, but a leaf freed by a removal can
be reused by a later member. It is `None` for non-member senders.

**Joining a group you already have.** `join()` refuses a Welcome for a
group id this client already has stored state for, with `invalid_welcome`. Such
a Welcome is either a replay or a different group reusing the id, and anyone
who knows a group id can create such a group. Accepting it would silently
replace your group. If you know the stored group is stale (for example, you
were removed while offline and have been re-invited), call
`client.delete_group(group_id)` with no live handle, then join.

**Persistence.** Group state is written to the client's store after every
successful operation, before the operation returns its output.
`load_group()` re-opens a group once its previous handle has been released.
Only one live handle per group is allowed, otherwise `group_already_loaded`.

- **Default (`storage=None`):** process memory, lost when the process exits.
- **Durable (`storage="alice.db"`):** a SQLite file holding the client's
  signing key, unused key packages and group state.
  - Reopening `Client(b"alice", storage="alice.db")` after a restart restores
    the same signing key. `client.group_ids()` lists the stored groups, and
    `load_group()` continues where you left off.
  - The file is bound to one identity and cipher suite. Opening it with
    others raises `invalid_argument`.
  - It is locked (`<file>.lock`) while the client or any of its groups is
    alive, so a second client on the same file, in this process or another,
    raises `storage`.
  - Writes are synchronous (`synchronous=FULL`), so a crash cannot roll state
    back to before a message you already sent. The cost is one disk sync per
    state-changing call, including every `encrypt`.

The store does not persist your application's queues and does not coordinate
with your transport. In particular, **pending commit bytes are not stored**.
After a crash with a commit pending, `has_pending_commit` is true after
reload; call `discard_pending()` unless you still have the bytes.

**Protect the storage file like a private key.**
- It is **not encrypted**. It holds the signing key and the group secrets of
  the current and last 3 epochs.
- It is created owner-only (`0600`) on Unix. On Windows it inherits the
  directory's ACL.
- Deleted rows are overwritten in the file (`secure_delete`). Copies can
  still survive in deleted journal files, in filesystem free space and in
  backups, so keep it on an encrypted volume and out of synced or backed-up
  folders.

**Exported secrets.** Use a distinct label per purpose, feed the output into a
defined derivation scheme rather than using it directly as a general-purpose
key, and never log it.

**Threads.** Methods release the interpreter for the whole MLS operation;
calls on one group are serialized internally. Groups outlive their `Client`.

**asyncio.** The API is synchronous. Because every call releases the
interpreter, `await asyncio.to_thread(group.process, message)` keeps the event
loop responsive. Calls on one group are serialized, but tasks don't run them
in a guaranteed order, so drive each group from one task (or await its calls
in sequence) when order matters, as it does for commits.

## Security

- `mls_py` **uses mls-rs; it does not implement MLS**. Crypto is AWS-LC
  (`mls-rs-crypto-awslc`, non-FIPS build). Cipher suites: 1
  (X25519/AES-128-GCM/Ed25519) and 2 (P-256/AES-128-GCM/P-256).
- **No independent third-party audit** of mls-rs or of this binding is
  claimed.
- **Not post-quantum secure.** v0.1 uses classical X25519/Ed25519 or P-256:
  recorded traffic is exposed to a future quantum adversary. mls-rs's
  ML-KEM support is experimental and uses non-standard suite IDs; it is not
  exposed. The API takes `cipher_suite` so PQ suites can be added later without
  an API break.
- **Identities are unverified unless you pass a `verifier`.** `BasicCredential`
  bytes are labels anyone can claim. Without a verifier, successful MLS
  processing does **not** mean the sender is who they say. With one, it means
  only that your verifier accepted the (identity, key) pair. Authorization and
  membership policy remain your application's job.
- **Metadata.** Commits, proposals and application messages are all sent as
  encrypted MLS PrivateMessages; the delivery service sees the group id, epoch,
  content type, message sizes (padded) and `aad`, which is authenticated but
  **not encrypted**. Key packages and Welcomes reveal what they must (identity,
  public keys).
- **Durable storage is opt-in and unencrypted at rest** (see *Persistence*).
  There is no raw state export. Your app owns delivery, ordering, retries,
  and persistence of its own data.
- Signing keys never reach Python. Secrets inside mls-rs/AWS-LC are zeroized
  where upstream supports it; plaintext and exported secrets returned to Python
  are ordinary `bytes` and are **not** securely erased.
- Interoperability is claimed only for what has been tested: OpenMLS 0.9.1 on
  suites 1 and 2 (join, messages, commits, removal and leave in both
  directions);
  see `docs/DESIGN.md`.
- A working round trip is not a production-ready secure messenger.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest hypothesis
maturin develop --release && pytest
cargo test --locked
scripts/verify_deps.sh
```

Design decisions and the upstream behaviour they rely on: `docs/DESIGN.md`.

## License

Apache-2.0.
