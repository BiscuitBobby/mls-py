#!/usr/bin/env python3
"""Render THIRD_PARTY_NOTICES.txt from `cargo about generate --format json`.

Identical license texts are printed once, listing every license and crate
they cover (AWS-LC's single license file covers several licenses).
Usage: render_notices.py about.json > THIRD_PARTY_NOTICES.txt
"""
import json
import sys
import textwrap

HEADER = """\
Third-party notices for mls-py
==============================

mls-py is licensed under Apache-2.0 (see LICENSE). Its wheels also contain
compiled code from the Rust crates listed below, which bundle these C
libraries:

- AWS-LC, through aws-lc-sys. AWS-LC's own license file, which covers the
  code it derives from BoringSSL and OpenSSL and its third-party components,
  is reproduced in full below.
{sqlite}
Generated from Cargo.lock by scripts/gen_notices.sh (cargo-about); do not
edit by hand.
"""
SQLITE = """\
- SQLite, through libsqlite3-sys (bundled build). SQLite is in the public
  domain.
"""
RULE = "=" * 80


def label(pkg):
    src = pkg.get("source") or ""
    if src.startswith("git+"):
        return f"{pkg['name']} {pkg['version']} (git {src.rsplit('#', 1)[-1][:7]})"
    return f"{pkg['name']} {pkg['version']}"


def main(path):
    data = json.load(open(path, encoding="utf-8"))
    names = {c["package"]["name"] for c in data["crates"]}
    sqlite = SQLITE if "libsqlite3-sys" in names else ""
    out = [HEADER.format(sqlite=sqlite), "Crates", "------", ""]
    crates = sorted(data["crates"], key=lambda c: (c["package"]["name"], c["package"]["version"]))
    width = max(len(label(c["package"])) for c in crates)
    for c in crates:
        out.append(f"  {label(c['package']).ljust(width)}  {c['license']}")

    blocks = {}  # normalised text -> (license names, crate labels)
    for lic in data["licenses"]:
        text = lic["text"].replace("\r\n", "\n").strip("\n")
        names, users = blocks.setdefault(text, (set(), set()))
        names.add(lic["name"])
        users.update(label(u["crate"]) for u in lic["used_by"])

    out += ["", "", "License texts", "-------------"]
    for text, (names, users) in sorted(
            blocks.items(), key=lambda kv: (sorted(kv[1][0]), sorted(kv[1][1]))):
        out += ["", RULE, ", ".join(sorted(names))]
        out += textwrap.wrap("Used by: " + ", ".join(sorted(users)), 80,
                             subsequent_indent="  ", break_on_hyphens=False)
        out += [RULE, "", "\n".join(l.rstrip() for l in text.split("\n"))]
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
