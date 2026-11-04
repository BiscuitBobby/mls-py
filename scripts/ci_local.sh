#!/usr/bin/env bash
# Run the Linux jobs of .github/workflows/wheels.yml locally with Docker:
# build abi3 wheels inside the manylinux_2_28 containers (aarch64 natively
# under qemu-user emulation, like the native arm runner in CI), then install
# each wheel in a clean environment and run the test suite on every
# supported Python. macOS and Windows jobs need GitHub-hosted runners.
#
#   scripts/ci_local.sh build x86_64|aarch64
#   scripts/ci_local.sh test  x86_64|aarch64
#   scripts/ci_local.sh sdist
#   scripts/ci_local.sh sdist-test
#
# Output: $CI_OUT (default ./dist-ci). Cargo/rustup caches: $CI_CACHE.
# Extra `docker run` arguments: $CI_DOCKER_ARGS (e.g. to force IPv4 with
# "--sysctl net.ipv6.conf.all.disable_ipv6=1" on hosts with broken IPv6).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=${CI_OUT:-$ROOT/dist-ci}
CACHE=${CI_CACHE:-$ROOT/target/ci-cache}
MATURIN_VERSION=1.15.0            # keep in sync with wheels.yml
RUST_TOOLCHAIN=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
PYTHONS=(3.9 3.10 3.11 3.12 3.13 3.14)
mkdir -p "$OUT" "$CACHE"
read -r -a DOCKER_ARGS <<< "${CI_DOCKER_ARGS:-}"

platform_for() { case "$1" in x86_64) echo linux/amd64 ;; aarch64) echo linux/arm64 ;; *) echo "unknown arch $1" >&2; exit 2 ;; esac; }

build() {
  local arch=$1 plat; plat=$(platform_for "$arch")
  mkdir -p "$CACHE/$arch/home" "$OUT/$arch"
  docker run --rm "${DOCKER_ARGS[@]}" --platform "$plat" --user "$(id -u):$(id -g)" \
    -e HOME=/home/ci -e CARGO_TARGET_DIR=/home/ci/target \
    -v "$CACHE/$arch/home":/home/ci -v "$ROOT":/io:ro -v "$OUT/$arch":/out -w /io \
    "quay.io/pypa/manylinux_2_28_$arch" bash -euc "
      if [ ! -x \$HOME/.cargo/bin/rustup ]; then
        curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
      fi
      . \$HOME/.cargo/env
      rustup toolchain install $RUST_TOOLCHAIN --profile minimal >/dev/null
      PY=/opt/python/cp312-cp312/bin/python
      \$PY -m pip install --user -q --disable-pip-version-check maturin==$MATURIN_VERSION
      rm -f /out/*.whl
      \$HOME/.local/bin/maturin build --release --locked --manylinux 2_28 --out /out
      \$PY -m pip install --user -q --disable-pip-version-check auditwheel
      \$HOME/.local/bin/auditwheel show /out/*.whl"
  ls -l "$OUT/$arch"
}

test_wheels() {
  local arch=$1 plat; plat=$(platform_for "$arch")
  local wheel; wheel=$(ls "$OUT/$arch"/*.whl)
  local failed=()
  for py in ${PY_VERSIONS:-${PYTHONS[@]}}; do
    echo "== $arch / Python $py"
    # Official python images: a clean interpreter per version; the repo's
    # tests are mounted read-only, the wheel is installed from file only.
    # Like the CI matrix (fail-fast: false), keep going and report at the end.
    docker run --rm "${DOCKER_ARGS[@]}" --platform "$plat" \
      -v "$ROOT/tests":/tests:ro -v "$OUT/$arch":/wheels:ro \
      "python:$py-slim" sh -euc "
        python -m venv /venv
        /venv/bin/pip install -q --disable-pip-version-check --no-index --find-links /wheels mls-py
        /venv/bin/pip install -q --disable-pip-version-check 'pytest>=8' 'hypothesis>=6'
        cd /tmp && cp -r /tests t && cd t
        /venv/bin/python -c 'import mls_py, sys; print(sys.version.split()[0], mls_py.__version__, mls_py.SUPPORTED_CIPHER_SUITES)'
        /venv/bin/python -m pytest -q -p no:cacheprovider ." > "$OUT/$arch/test-py$py.log" 2>&1 \
      || failed+=("$py")
    tail -3 "$OUT/$arch/test-py$py.log"
  done
  if [ ${#failed[@]} -ne 0 ]; then
    echo "FAILED on $arch: Python ${failed[*]} (logs in $OUT/$arch)" >&2
    return 1
  fi
  echo "tested $(basename "$wheel") on Python ${PY_VERSIONS:-${PYTHONS[*]}}"
}

sdist() {
  mkdir -p "$OUT/sdist" && rm -f "$OUT/sdist"/*.tar.gz
  "${MATURIN:-maturin}" sdist --out "$OUT/sdist"
}

sdist_test() {
  # Build from the sdist in a clean Python 3.12 container with only a Rust
  # toolchain and a C toolchain/cmake added (what a source install needs).
  docker run --rm "${DOCKER_ARGS[@]}" -v "$ROOT/tests":/tests:ro -v "$OUT/sdist":/sdist:ro \
    python:3.12 bash -euc "
      apt-get update -qq && apt-get install -y -qq cmake >/dev/null
      curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
      . \$HOME/.cargo/env
      python -m venv /venv
      /venv/bin/pip install -q --disable-pip-version-check /sdist/*.tar.gz 'pytest>=8' 'hypothesis>=6'
      cp -r /tests /tmp/t && cd /tmp/t && /venv/bin/python -m pytest -q -p no:cacheprovider ." \
    > "$OUT/sdist-test.log" 2>&1 || { tail -40 "$OUT/sdist-test.log"; return 1; }
  tail -3 "$OUT/sdist-test.log"
}

case "${1:-}" in
  build) build "${2:?arch}" ;;
  test) test_wheels "${2:?arch}" ;;
  sdist) sdist ;;
  sdist-test) sdist_test ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
