#!/usr/bin/env bash
# Milestone-1 gate, re-run on every dependency change. Fails if the mls-rs
# crate set is incoherent, the resolved feature set drifted from what
# docs/DESIGN.md records, or tests/builds fail with the committed lockfile.
set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

say "locked versions"
for c in mls-rs mls-rs-core mls-rs-crypto-awslc mls-rs-crypto-traits mls-rs-crypto-hpke aws-lc-rs aws-lc-sys pyo3; do
  v=$(cargo tree --locked -e normal --prefix none -i "$c" 2>/dev/null | head -1 || true)
  echo "${v:-$c: not in graph}"
done

say "duplicate crates (only syn 2/3 is expected)"
dups=$(cargo tree --locked -d -e normal --depth 0 --prefix none | grep -E '^[a-z]' | awk '{print $1" "$2}' | sort -u)
echo "$dups"
if echo "$dups" | grep -qE '^(mls-rs|aws-lc)'; then
  fail "more than one version of an mls-rs/aws-lc crate"
fi

say "mls-rs crates all from the pinned commit"
# git main reuses crates.io version numbers with a different API, so a mix
# of sources must never resolve (it would not be caught as a duplicate).
PIN=6c819eface1e8b00a3241412d1b7e21c162df515
for lock in Cargo.lock fuzz/Cargo.lock interop/Cargo.lock; do
  [ -f "$lock" ] || continue
  srcs=$(grep -A2 '^name = "mls-rs' "$lock" | grep '^source' | sort -u)
  echo "$lock: $srcs"
  [ "$(printf '%s\n' "$srcs" | wc -l)" -eq 1 ] && printf '%s' "$srcs" | grep -q "rev=$PIN#$PIN" \
    || fail "$lock: mls-rs crates not all from git rev $PIN"
done

say "single mls-rs-core / crypto-traits"
cargo tree --locked -i mls-rs-core >/dev/null
cargo tree --locked -i mls-rs-crypto-traits >/dev/null

say "resolved mls-rs features"
expected="by_ref_proposal custom_proposal default fast_serialize hex out_of_order prior_epoch private_message psk rayon rfc_compliant std tree_index x509"
actual=$(cargo tree --locked -e features -i mls-rs --prefix none \
  | grep -o 'mls-rs feature "[a-z0-9_]*"' | sed 's/.*"\(.*\)"/\1/' | sort -u | tr '\n' ' ' | sed 's/ $//')
echo "$actual"
[ "$actual" = "$expected" ] || fail "feature set changed; update docs/DESIGN.md §1 and re-review"

say "tests"
cargo test --locked --workspace

say "release build"
cargo build --release --locked --workspace

say "gate passed"
