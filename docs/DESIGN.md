# mls-py design record

This file records the decisions the binding makes and the *observed* upstream
behaviour those decisions rest on. Every observation is pinned by a test in
`crates/mls-facade/tests/upstream_probe.rs`; if a dependency bump changes one,
that test fails and this file must be revisited before the bump lands.

Priority order: protocol correctness and cryptographic implementation quality
first; binary size and build convenience last.

## 1. Dependency set

**mls-rs is pinned to git commit `6c819eface1e8b00a3241412d1b7e21c162df515`**
(awslabs/mls-rs `main`, 2026-11-02), not the crates.io release. Relative to the
`0.57.0` tag it adds only a required `insert` method on the
`PreSharedKeyStorage` trait (plus an example); no protocol or crypto code
changed, and the facade does not implement that trait. Consequences:

- Every mls-rs crate must come from this one commit: git `main` reuses the
  crates.io version numbers (`mls-rs-core 0.27.0`) with a different API, and a
  mix would not show up as a duplicate. `scripts/verify_deps.sh` fails unless
  every `mls-rs*` entry in `Cargo.lock`, `fuzz/Cargo.lock` and
  `interop/Cargo.lock` has this exact git source.
- **cargo-audit cannot see the mls-rs crates**: RustSec matches advisories to
  packages from the advisory's source (crates.io), so git-sourced packages are
  skipped (verified in rustsec 0.33 `Query::matches`). `scripts/audit_git_pins.sh`
  (run in CI after `cargo audit`) fails if the advisory database has any
  advisory for any `mls-rs*` crate name, for manual review. None exist today.
- Lockfile integrity is the git commit hash rather than crates.io SHA-256
  checksums; source builds (sdist) need network access to github.com.
- Return to a crates.io release once one contains this commit; that restores
  cargo-audit coverage.

| Crate | Version | Released | Notes |
|---|---|---|---|
| mls-rs | 0.57.0 @ `6c819ef` (git) | 2026-11-02 | upstream defaults (`std`, `rayon`, `rfc_compliant`, `tree_index`, `fast_serialize`) |
| mls-rs-core | 0.27.0 @ `6c819ef` (git) | | single copy in the graph |
| mls-rs-crypto-awslc | 0.27.0 @ `6c819ef` (git) | | default `non-fips`; post-quantum feature off (out of scope) |
| aws-lc-rs | 1.18.1 | | **pinned exactly by the provider** (`=1.18.1`, upstream issue #408); 1.18.2 and 1.19.0 exist but cannot be taken without a provider release |
| mls-rs-crypto-traits | 0.22.0 | | single copy |
| pyo3 | =0.30.1 | 2026-10-14 | `abi3-py39` |
| maturin | 1.15.0 (CI pin), `>=1.9,<2` (build-system) | 2026-08-24 | 1.16.0 skipped: under two weeks old at the gate |

`scripts/verify_deps.sh` re-runs the coherence checks: `cargo tree -d` (only
`syn` 2/3 is duplicated, a proc-macro dependency), `cargo tree -i mls-rs-core`,
`cargo tree -i mls-rs-crypto-traits`, `cargo tree -e features -i mls-rs`, then
`cargo test --locked` and `cargo build --release --locked`. The mls-rs crates
are bumped together, never one alone.

### Resolved mls-rs feature graph

`by_ref_proposal custom_proposal default fast_serialize hex out_of_order
prior_epoch private_message psk rayon rfc_compliant std tree_index x509`;
mls-rs-core: `default fast_serialize rfc_compliant std`. `rfc_compliant` is a
bundle whose composition can change between releases; re-check on every bump.

## 2. Crypto provider

**AWS-LC (`mls-rs-crypto-awslc`, non-FIPS).** Chosen for assurance: AWS-LC is
widely deployed and heavily reviewed, and its C build is acceptable CI cost. It
builds here with cmake + a C compiler (no Go needed for non-FIPS).
OpenSSL (vendored) was the fallback and RustCrypto (experimental upstream) the
last resort; neither was needed.

**Upstream conformance under AWS-LC.** mls-rs's own test suite runs against
OpenSSL upstream. We re-ran it at tag `0.57.0` with the test provider swapped to
AWS-LC (scratch clone; includes the IETF interop vectors in `test_data/`):
**435 passed, 1 failed**. The failure is
`joining_group_fails_if_cipher_suite_is_not_supported`: AWS-LC's
`with_enabled_cipher_suites` is advisory only (next section).

Supported by the provider: suites 1, 2, 3, 5, 7. The binding allowlists **1**
(X25519/AES-128-GCM/Ed25519, RFC 9420 mandatory-to-implement, default) and
**2** (P-256/AES-128-GCM/P-256).

## 3. MLS profile

| Item | Choice | Why |
|---|---|---|
| Credentials | `BasicCredential` + `BasicIdentityProvider` | v0.1 scope. Identities are unverified labels (upstream itself calls Basic "for demonstration"; X.509 is recommended for production) |
| `path_required` | **true** (upstream default false) | every commit carries an UpdatePath, so the committer always refreshes its leaf key (post-compromise security). Cost: larger add-only commits |
| Ratchet tree in Welcome | yes | joiners need nothing out of band |
| Single Welcome per commit | yes | |
| External commits | disabled, GroupInfo never published | out of scope |
| Handshake encryption | **commits and proposals are PrivateMessage** (`encrypt_control_messages = true`; upstream default is PublicMessage) | the delivery service sees group id, epoch and content type (enough to sequence commits) but not membership changes; also required to interoperate with OpenMLS's default policy, which rejects plaintext handshakes from members |
| Padding | upstream default `StepFunction` | |
| Prior-epoch retention | 3 epochs (in-memory store default) | late messages from the last 3 epochs decrypt; older secrets are dropped |
| Key package lifetime | upstream default (365 days) | |

## 4. Observed upstream behaviour → facade decision

| Observation (probe test) | Facade decision |
|---|---|
| A competing incoming commit **clears** our pending commit (`competing_commit_clears_pending_upstream`; done at the end of upstream's commit-processing path) | Nothing extra; `apply_pending()` afterwards raises `no_pending_commit`. The old commit bytes are stale (peers reject them with `invalid_epoch`) |
| Processing our own commit applies the pending commit (`own_commit_echo_applies_pending`) | Documented: echo-from-server == `apply_pending()` |
| Duplicate application message → `KeyMissing`; duplicate commit → `InvalidEpoch`; group stays usable | Mapped to `invalid_message` / `invalid_epoch` |
| Prior epochs accumulate in memory **until `write_to_storage`**, then trim to 3 (`prior_epoch_*`) | **Persist after every successful operation** (bounded retention; old epoch secrets dropped) |
| A consumed key package's private keys are deleted **only on `write_to_storage`** after join | `join()` persists immediately |
| A removed member can still call `encrypt_application_message` (upstream does not stop it) | Facade lifecycle: `Removed` is terminal, upstream group dropped, stored state deleted; all calls raise `invalid_group_state`; `load_group` → `group_not_found` |
| AWS-LC `with_enabled_cipher_suites` only changes what is advertised; `cipher_suite_provider` still builds every suite (`awslc_enabled_suites_is_advisory_only`) | The facade enforces its allowlist itself: `Client` construction, `join` (Welcome suite), `add` (KeyPackage suite) |
| Incoming by-reference proposals make `encrypt` fail with `CommitRequired` until a commit (`incoming_by_ref_proposal_blocks_encrypt`) | Added `Group.commit()` (self-update + sweeps cached proposals) and error code `commit_required` |
| A group snapshot includes the pending commit (`save_while_pending_persists_pending_snapshot`) | Consistent with persist-always: reloading restores the pending commit |
| `Client`/`Group` are `Send + Sync` with this config (`client_and_group_are_send_sync`) | `#[pyclass(frozen)]`, facade-internal `Mutex`, runtime detached for each whole operation |
| Leaf index of a member is stable while it remains a member; a blanked leaf is reused by later adds | Docs say exactly that (the plan's "not stable across membership changes" was imprecise) |
| Adding a key package whose signature key matches an existing member is rejected (RFC 9420 uniqueness) | `invalid_key_package` |
| **Found by fuzzing:** the decoder accepts a proposal with a reserved type 0..=7 that is not compiled in (decoded as "custom"), which the encoder refuses (`decoder_accepts_what_encoder_refuses`) | Fails closed (signature verification re-encodes); facade never panics. Fuzz invariant relaxed to "stable when re-encodable". Worth reporting upstream |
| `join_group` accepts a Welcome for a group id the client already stores, and writing it replaces the stored group. Anyone who knows a group id can create a different group with that id (`welcome_reusing_a_stored_group_id_is_refused`). Upstream also writes the joined group *before* deleting the consumed key package, so a crash in between allows a replay | `join()` refuses a Welcome when stored state exists for its group id (`invalid_welcome`), checked before anything is written; `Client.delete_group()` lets the app discard state it knows is stale. Previously only a live handle was checked |

### Persistence invariant

Whenever a group's lock is released, the in-memory store holds exactly the
in-memory group state: persist on success, restore on failure, delete on
terminal transitions. Consequences:

- `load_group()` never returns a stale snapshot, so a reloaded group cannot
  re-use sender-ratchet generations.
- The plan's explicit `save()` became redundant and was removed.
- If persisting ever fails, the group becomes `Invalid` (terminal) and its
  stored state is deleted rather than left stale.

Cost: one snapshot serialization per successful operation. Measured
(release, x86_64, suite 1, `large_group_1000_members`): with 1000 members an
application message costs about 5 ms for encrypt + process combined (both
sides persist the full state); Welcome 174 KB, largest add-commit 98 KB,
self-update commit 41 KB; building the group one add per commit took 31 s.
If this becomes a bottleneck, the safe optimization is to persist
application-message ratchet changes lazily (on handle release) while still
persisting every epoch change; not done in v0.1 because the simple invariant
is easier to reason about.

## 5. Deviations from the approved plan (all gate-driven)

| Plan | Now | Reason |
|---|---|---|
| `group.save()` | removed; persistence is automatic | §4 persistence invariant |
| no commit-without-proposals API | `group.commit()` | needed to answer received proposals; also the key-rotation (PCS) primitive |
| `Event(kind, data, sender_index, epoch, removed)` | adds `aad` | receivers must see the authenticated data |
| error codes | adds `group_not_found`, `commit_required`; `unsupported_cipher_suite` always raised by the facade | |
| — | `group.is_active` | lets apps check terminal state without catching |
| local self-removal ends in `Removed` | not possible in v0.1: MLS forbids a committer removing itself; another member must remove it (self-remove proposals are out of scope) | RFC 9420 |
| `Event` as a `@dataclass(frozen=True)` | Rust `#[pyclass(frozen, eq, hash)]` with a repr that omits contents | immutability without plaintext in logs |

## 6. Post-quantum spike (recorded, not shipped)

`mls-rs-crypto-awslc` with `post-quantum` builds (enables `aws-lc-rs/unstable`;
same `=1.18.1` pin). Create/join/self-update/application round trip passed for
all four PQ suites. Sizes (bytes, one committer adding everyone in one commit,
then the first joiner self-updating — worst case over a tree with no path
secrets):

| Suite | n | KeyPackage | Welcome | update commit |
|---|---|---|---|---|
| 1 (X25519, classical) | 1000 | 292 | 305,033 | 82,661 |
| 65100 (ML-KEM-768+X25519, X-Wing-01) | 1000 | 2,662 | 2,577,944 | 1,183,615 |
| 65002 (ML-KEM-768) | 1000 | 2,598 | 2,513,976 | 1,151,295 |
| 65003 (ML-KEM-1024, P-384 sig) | 1000 | 3,511 | 3,515,562 | 1,652,232 |

All fit the 16 MiB default. Upstream PR #359 ("fix ml-kem768 provider", 665
additions) was closed unmerged on 2026-06-10 with **no description and no
comments**, so why it was closed cannot be determined from the public record.
Treat this as unresolved before relying on the PQ suites. Decision unchanged:
v0.1 classical only, PQ-ready API (see README and the plan's roadmap).

## 7. Concurrency and FFI rules

- Python inputs are pinned as `PyBackedBytes` (immutable `bytes` are borrowed,
  `bytearray` is copied) before detaching; no Python object is touched while
  detached or while a facade lock is held.
- Lock order: client registry, then a group lock; never the registry while a
  group lock is held. Poisoned locks surface as `MlsError`, never a panic.
- Integers are extracted strictly: `bool` and non-`int` raise `TypeError`;
  out-of-range values raise `MlsError(invalid_argument)`.
- Error messages are fixed strings chosen per upstream variant; upstream
  `Debug` text is never exposed. `Event.__repr__` omits data and aad contents.
- `Client`/`Group` are not picklable and expose no raw state export.

## 8. Verification record

### Local CI run (2026-11-04), mls-rs pinned to `6c819ef`

The Linux jobs of `.github/workflows/{wheels,audit}.yml` were run locally
(`scripts/ci_local.sh`, Docker; aarch64 natively under qemu-user emulation).
No GitHub remote exists yet, so the GitHub-hosted jobs have not run.

| Job | Result |
|---|---|
| `actionlint` (v1.7.11) on both workflows | clean after replacing the retired `macos-13` runner label with `macos-15-intel` |
| Actions pinned to commit SHAs | all 7 (`checkout`, `upload/download-artifact`, `setup-python`, `maturin-action`, `setup-nasm`, `gh-action-pypi-publish`) |
| rust-tests: `scripts/verify_deps.sh` | pass (single mls-rs source = pinned commit; features unchanged; 17 upstream probes hold) |
| rust-tests: OpenMLS interop | pass (2 scenarios x 2 suites) |
| supply-chain: `cargo audit --deny warnings` | 0 advisories (83 crates; mls-rs not covered, see §1) |
| supply-chain: `scripts/audit_git_pins.sh` | no advisories for the 8 mls-rs crates |
| supply-chain: `cargo deny check` | advisories, bans, licenses, sources ok |
| fuzz-smoke (300 s each) | no crashes: `parse_message` 12.3M runs, `join` 12.9M, `key_package` 4.8M, `process` 412K |
| linux x86_64 wheel | `mls_py-0.1.0-cp39-abi3-manylinux_2_28_x86_64.whl` (1.7 MB); auditwheel: manylinux_2_28, only glibc <= 2.28 + libgcc_s |
| test x86_64, Python 3.9-3.14 (clean `python:X-slim` containers) | 70/70 on every version (3.13 rerun once after a transient PyPI fetch failure in the container) |
| linux aarch64 wheel | `mls_py-0.1.0-cp39-abi3-manylinux_2_28_aarch64.whl` (1.5 MB); auditwheel: manylinux_2_28 |
| test aarch64, Python 3.9-3.14 (clean `python:X-slim` arm64 containers, qemu-user) | 70/70 on every version |
| sdist + build-from-sdist (clean `python:3.12`, + cmake, stable Rust) | pass, 70/70; fetches mls-rs from the pinned commit |
| Upstream mls-rs suite under AWS-LC at `6c819ef` | unit tests 435/436 (same known failure as at 0.57.0, §2); integration `client_tests` (needs `--features test_util`, previously not run) 18/18 |

**Not run (need GitHub-hosted runners):** macOS x86_64 (`macos-15-intel`) and
arm64 (`macos-14`) builds and tests, Windows x64 build and tests, and the
tag-only `publish` job.

### Earlier checks at the 0.57.0 crates.io release

- Upstream mls-rs 0.57.0 suite under AWS-LC: 435/436 (failure explained in §2).
- Rust: facade (25 + 1 ignored 1000-member test, run separately in release),
  proposals (1), upstream probes (17): all pass.
- Python `pytest` (70, both suites): editable install, clean-venv wheel
  install, and build from sdist.

Interoperability is claimed only for the OpenMLS scenarios above.
