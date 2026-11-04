# mls-py

`mls-py` (imported as `mls_py`) is a minimal Python binding for the [mls-rs](https://github.com/awslabs/mls-rs)
implementation of Messaging Layer Security (MLS, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)):
a synchronous, byte-oriented API for creating groups, managing membership,
processing messages and exporting group secrets. It prioritizes a small API
surface, explicit state transitions, and Rust-managed cryptographic state.

The Python API is small; the security model is not trimmed to match. Read the
[security section](#security) before building on it.

## Install

```sh
pip install mls-py
```

CI builds abi3 wheels (CPython 3.9+) for Linux x86_64/aarch64 (manylinux_2_28, glibc
2.28+), macOS x86_64 and arm64 (separate wheels), Windows x64. Building from
source needs a Rust toolchain (1.85+), cmake, a C compiler (for AWS-LC) and
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
Client(identity: bytes, *, cipher_suite: int = 1, max_message_size: int = 16 * 2**20)
client.cipher_suite, client.max_message_size
client.key_package() -> bytes                # fresh, single-use
client.create_group() -> Group
client.join(welcome: bytes) -> Group
client.load_group(group_id: bytes) -> Group
client.delete_group(group_id: bytes)         # discard stored state you know is stale

group.add(key_package) -> (commit, welcome)  # pending
group.remove(leaf_index) -> commit           # pending
group.commit() -> commit                     # pending; self-update + received proposals
group.apply_pending() / group.discard_pending()
group.process(message) -> Event
group.encrypt(data, aad=b"") -> bytes
group.export_secret(label, context, length) -> bytes
group.group_id, .epoch, .leaf_index, .cipher_suite, .has_pending_commit, .is_active
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
`no_pending_commit`, `commit_required`, `invalid_key_package`,
`invalid_welcome`, `invalid_argument`, `input_too_large`, `storage`,
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
must remove it. A removed client can be re-added with a new key package.

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

**Persistence.** Group state is written to the client's in-memory store after
every successful operation; `load_group()` re-opens a group once its previous
handle has been released (only one live handle per group, otherwise
`group_already_loaded`). Storage is **process-local and not durable**: it
does not persist application queues, does not coordinate with your transport,
and is lost when the process exits.

**Exported secrets.** Use a distinct label per purpose, feed the output into a
defined derivation scheme rather than using it directly as a general-purpose
key, and never log it.

**Threads.** Methods release the interpreter for the whole MLS operation;
calls on one group are serialized internally. Groups outlive their `Client`.

## Security

- `mls-py` **uses mls-rs; it does not implement MLS**. Crypto is AWS-LC
  (`mls-rs-crypto-awslc`, non-FIPS build). Cipher suites: 1
  (X25519/AES-128-GCM/Ed25519) and 2 (P-256/AES-128-GCM/P-256).
- **No independent third-party audit** of mls-rs or of this binding is
  claimed.
- **Not post-quantum secure.** v0.1 uses classical X25519/Ed25519 or P-256:
  recorded traffic is exposed to a future quantum adversary. mls-rs's
  ML-KEM support is experimental and uses non-standard suite IDs; it is not
  exposed. The API takes `cipher_suite` so PQ suites can be added later without
  an API break.
- **Identities are unverified.** `BasicCredential` bytes are labels anyone can
  claim. Successful MLS processing does **not** mean the sender is who they
  say or is authorized by your application. Your app owns authentication,
  authorization and membership policy.
- **Metadata.** Commits, proposals and application messages are all sent as
  encrypted MLS PrivateMessages; the delivery service sees the group id, epoch,
  content type, message sizes (padded) and `aad`, which is authenticated but
  **not encrypted**. Key packages and Welcomes reveal what they must (identity,
  public keys).
- **No durable storage**, no raw state export. Your app owns delivery,
  ordering, retries and persistence.
- Signing keys never reach Python. Secrets inside mls-rs/AWS-LC are zeroized
  where upstream supports it; plaintext and exported secrets returned to Python
  are ordinary `bytes` and are **not** securely erased.
- Interoperability is claimed only for what has been tested: OpenMLS 0.9.1 on
  suites 1 and 2 (join, messages, commits and removal in both directions);
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

Apache-2.0. The wheels also contain statically linked third-party code
(AWS-LC and the Rust crates in `Cargo.lock`); their licenses and
notices are in `THIRD_PARTY_NOTICES.txt`, installed with the package under
`mls_py-<version>.dist-info/licenses/`.
