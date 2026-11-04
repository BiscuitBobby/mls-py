# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in public issues:
use the repository's private vulnerability reporting ("Report a
vulnerability" under the Security tab) once the project is hosted. Include the
version, platform, a description, and a reproducer if you have one.

If the issue is in mls-rs or AWS-LC rather than in this binding, it will be
forwarded upstream (mls-rs and AWS-LC follow the AWS vulnerability reporting
process: https://aws.amazon.com/security/vulnerability-reporting/).

## Scope

In scope: the PyO3 layer and the `mls-facade` crate (state handling, input
limits, error mapping, lifecycle), build and release artifacts.

Known, documented limitations (see README "Security") are not vulnerabilities:
unverified BasicCredential identities, in-memory non-durable storage,
unencrypted handshake metadata, classical (non-post-quantum) cipher suites.

## Supported versions

Only the latest release receives fixes during 0.x.

## Supply chain

- `Cargo.lock` is committed; builds and tests run with `--locked`.
- mls-rs crates are pinned to exact versions and bumped together.
- `cargo audit` and `cargo deny` run in CI (`.github/workflows/audit.yml`).
- Wheels are built in CI from tags; publishing uses PyPI trusted publishing.
