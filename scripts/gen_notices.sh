#!/usr/bin/env bash
# Regenerate THIRD_PARTY_NOTICES.txt (shipped in every wheel and the sdist)
# from Cargo.lock, using cargo-about with about.toml.
#
#   scripts/gen_notices.sh           # rewrite the file
#   scripts/gen_notices.sh --check   # fail if it is out of date (CI)
#
# Run after any dependency change. A changed AWS-LC license file makes
# cargo-about fail on the checksums in about.toml: review the new file,
# then update the checksums.
set -euo pipefail
cd "$(dirname "$0")/.."
CARGO_ABOUT_VERSION=0.9.2   # keep in sync with .github/workflows/audit.yml

have=$(cargo about --version 2>/dev/null | awk '{print $2}' || true)
if [ "$have" != "$CARGO_ABOUT_VERSION" ]; then
  echo "need cargo-about $CARGO_ABOUT_VERSION (found: ${have:-none}):" >&2
  echo "  cargo install --locked --features cli cargo-about@$CARGO_ABOUT_VERSION" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cargo about generate --locked --workspace --fail --format json -o "$tmp/about.json"
python3 scripts/render_notices.py "$tmp/about.json" > "$tmp/notices.txt"

if [ "${1:-}" = "--check" ]; then
  diff -u THIRD_PARTY_NOTICES.txt "$tmp/notices.txt" \
    || { echo "THIRD_PARTY_NOTICES.txt is stale: run scripts/gen_notices.sh" >&2; exit 1; }
else
  mv "$tmp/notices.txt" THIRD_PARTY_NOTICES.txt
fi
