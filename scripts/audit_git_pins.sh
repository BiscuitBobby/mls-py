#!/usr/bin/env bash
# cargo-audit only matches advisories to packages from the advisory's source
# (crates.io), so the git-pinned mls-rs crates are invisible to it. This
# fails if the RustSec database has *any* advisory for an mls-rs crate, so a
# human checks whether it affects the pinned commit. Run after `cargo audit`
# (which fetches the database to ~/.cargo/advisory-db).
set -euo pipefail
DB="${CARGO_HOME:-$HOME/.cargo}/advisory-db/crates"
[ -d "$DB" ] || { echo "advisory database not found at $DB; run cargo audit first" >&2; exit 2; }
cd "$(dirname "$0")/.."
crates=$(grep -A2 '^name = "mls-rs' Cargo.lock | grep '^name' | sed 's/name = "\(.*\)"/\1/' | sort -u)
found=0
for c in $crates; do
  if [ -d "$DB/$c" ]; then
    echo "ADVISORY for git-pinned crate $c:"; ls "$DB/$c"; found=1
  fi
done
if [ "$found" -ne 0 ]; then
  echo "Review the advisories above against the pinned mls-rs commit (Cargo.toml)." >&2
  exit 1
fi
echo "no RustSec advisories for: $(echo $crates)"
