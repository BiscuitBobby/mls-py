# Releasing

Publishing uses PyPI trusted publishing from `.github/workflows/wheels.yml`;
no API token is stored anywhere.

## One-time setup

1. On GitHub, create two environments under *Settings → Environments*:
   `pypi` and `testpypi`. Give both a required reviewer and restrict them to
   protected branches/tags, so no upload runs without approval.
2. On <https://pypi.org/manage/account/publishing/>, add a *pending publisher*
   for project `mls-py`: your owner/repo, workflow `wheels.yml`, environment
   `pypi`. Repeat on <https://test.pypi.org/manage/account/publishing/> with
   environment `testpypi`.

## Each release

1. Run `scripts/verify_deps.sh` and the interop tests; check that
   `cargo audit`, `scripts/audit_git_pins.sh` and `cargo deny check` are clean.
2. Set the version in `pyproject.toml`, `Cargo.toml` (`workspace.package`)
   and `python/mls_py/__init__.py`.
3. Dry run: *Actions → wheels → Run workflow* with `testpypi` checked, then
   `pip install -i https://test.pypi.org/simple/ mls-py==<version>` in a clean
   venv and run the test suite against it. TestPyPI never accepts the same
   version twice, so use a pre-release (e.g. `0.1.0rc1`) for repeat runs.
4. Tag and push: `git tag -a v<version> -m v<version> && git push origin v<version>`. The
   `publish` job waits for approval on the `pypi` environment.
