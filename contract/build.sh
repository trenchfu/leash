#!/usr/bin/env bash
# Reproducible build for the Leash NEAR contract. Produces BYTE-IDENTICAL output on any machine.
#
# WHY THIS SCRIPT EXISTS, 2026-11-11. A plain `cargo build --locked --target wasm32-unknown-unknown
# --release` is NOT byte-reproducible across machines. The artifact carries 19 absolute dependency
# source paths in its data section -- panic-location strings of the form
#   /home/<user>/.cargo/registry/src/index.crates.io-<hash>/<crate>/src/<file>.rs
# so the BUILDING USER'S HOME DIRECTORY ends up inside the wasm. Measured on one commit, same rustc
# 1.95.0, same LLVM 22.1.2, same Cargo.lock under --locked: /home/<user-a> (10 chars) gave 458,456 bytes
# and a peer's /home/<user-b> (11 chars) gave 458,472. Nineteen paths one byte longer each, minus
# string dedup and LEB128 length encoding, is that 16-byte delta.
#
# It was found ONLY because the re-derivation was done blind on a second host. A reproducibility
# check run on the build machine cannot see this class of defect at all.
#
# `[profile.release] trim-paths` would be the clean fix but is NOT stabilised in the pinned cargo
# 1.95.0 (it needs nightly), and unpinning the toolchain changes codegen -- the pin is load-bearing.
# So the registry prefix is remapped explicitly instead: each machine maps ITS OWN cargo registry
# onto the same token, and the OUTPUT becomes machine-independent.
#
# TWO TRAPS THIS SCRIPT EXISTS TO NOT FALL INTO:
#   1. An env RUSTFLAGS OVERRIDES .cargo/config.toml's rustflags entirely -- it does not merge. So
#      `--cfg near` must be repeated here or near-sdk compiles its HOST branch and every panic
#      becomes an unreachable trap, losing every refusal reason. That is a silent, severe failure.
#   2. The artifact is CHECKED for absolute paths afterwards. Reproducibility that is hoped for is
#      not reproducibility; if any remain the build FAILS rather than shipping.
set -euo pipefail
cd "$(dirname "$0")"

CH="${CARGO_HOME:-$HOME/.cargo}"
SYSROOT="$(rustc --print sysroot)"
RUSTC_HASH="$(rustc -vV | awk '/^commit-hash/{print $2}')"
# THE STANDARD LIBRARY'S PATHS ARE A SECOND, SNEAKIER INPUT -- found 2026-11-11 by diffing the
# DEPLOYED artifact against a faithful rebuild of its own commit. All 608 differing bytes were std
# source paths, and rustc spells them TWO ways depending on an OPTIONAL component:
#   rust-src INSTALLED  -> /home/<user>/.rustup/toolchains/<ch>/lib/rustlib/src/rust/library/...
#   rust-src ABSENT     -> /rustc/<40-hex-commit>/library/...
# The SECOND form is baked into the shipped std rlib by upstream's own remap, so --remap-path-prefix
# cannot rewrite it -- and it does not need to: it carries no user path and is already machine
# independent. It is the CANONICAL form and the one this build requires. The first form is the
# hazard, and the sysroot remap below converts it if some machine has rust-src installed.
# rust-src is therefore a BUILD INPUT: rust-toolchain.toml pins `profile = "minimal"`, which
# excludes it. The deployed 2026-11-05 artifact was built with it present, under the `stable` alias
# and before that pin existed, which is why the deployed bytes are not reachable under this recipe.
# So two machines, both correctly pinned to the same rustc, still produce different bytes depending
# on whether someone ran `rustup component add rust-src`. The deployed build had it installed; this
# machine does not, which is the only reason the first version of this script looked correct here.
# CORRECTED 2026-11-11, second pass, after a POSITIVE CONTROL that the first pass never ran.
# The first version mapped the rust-src tree to the invented token /rust-std. That is NOT the
# canonical spelling, so it did not make the two machine states agree -- it merely gave the
# rust-src machine a THIRD spelling, and the artifacts differed by machine state. The script
# reported success in BOTH cases, because the guard accepted either form with an OR and so could
# not tell the two apart. The flag fired zero times on the two machines that had agreed on the
# bytes, which is exactly why their agreement could not detect this.
#
# NO EXPECTED FIGURES LIVE IN THIS FILE, DELIBERATELY. It briefly carried the measured byte counts
# and hashes of both legs, which is the same defect the coordinator caught in build-reproducible.sh on
# 2026-11-07: a build input that documents its own expected output cannot be used for a BLIND
# re-derivation, because whoever diffs the script to understand the recipe is anchored by it. The
# numbers live in VERSIONS.md; verify.sh does the asserting; this script reports only what it just
# measured. Three jobs, three places.
# THE FIX: map the rust-src tree onto the CANONICAL token the shipped std rlib already carries,
# /rustc/<40-hex-commit>, which `rustc -vV` reports and which is identical on any machine running
# the same pinned rustc. Then both machine states emit the same strings and the bytes agree.
if ! printf '%s' "$RUSTC_HASH" | grep -qE '^[0-9a-f]{40}$'; then
  echo "build.sh: REFUSED -- rustc -vV gave no 40-hex commit-hash (got '${RUSTC_HASH}')." >&2
  echo "build.sh: that hash IS the canonical std path token, so it cannot be constructed." >&2
  exit 1
fi
export RUSTFLAGS="--cfg near \
 --remap-path-prefix=${CH}/registry=/cargo-registry \
 --remap-path-prefix=${CH}/git=/cargo-git \
 --remap-path-prefix=${SYSROOT}/lib/rustlib/src/rust=/rustc/${RUSTC_HASH} \
"
echo "build.sh: CARGO_HOME=${CH}"
echo "build.sh: RUSTFLAGS=${RUSTFLAGS}"
rustc --version --verbose | sed -n '1p;/LLVM/p' | sed 's/^/build.sh: /'
cargo --version | sed 's/^/build.sh: /'

cargo build --locked --target wasm32-unknown-unknown --release
W="${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/leash.wasm"

LEAK=$(strings -a "$W" | grep -c '/home/\|/Users/\|/root/\|\.rustup' || true)
if [ "$LEAK" != "0" ]; then
  echo "build.sh: REFUSED -- $LEAK absolute path(s) still embedded in the artifact:" >&2
  strings -a "$W" | grep -o '/home/[^ ]*\|/Users/[^ ]*\|/root/[^ ]*' | sort -u | head -5 >&2
  echo "build.sh: the output would not be reproducible on another machine." >&2
  exit 1
fi
# Positive control: the remap must have ACTUALLY fired, not silently matched nothing.
MAPPED=$(strings -a "$W" | grep -c '/cargo-registry' || true)
# The std paths must be in the CANONICAL form. This used to accept '/rust-std' OR '/rustc/',
# which is why it passed on a rust-src machine whose bytes differed: a guard that accepts both
# spellings cannot detect the disagreement BETWEEN them. Only /rustc/<hash> counts now, and any
# surviving /rust-std is a hard refusal.
MAPSTD=$(strings -a "$W" | grep -c "/rustc/${RUSTC_HASH}/" || true)
STRAY=$(strings -a "$W" | grep -c '/rust-std' || true)
if [ "$STRAY" != "0" ]; then
  echo "build.sh: REFUSED -- $STRAY path(s) still spelled /rust-std. The sysroot remap pointed at" >&2
  echo "build.sh: the wrong token, so this artifact will not match one built without rust-src." >&2
  exit 1
fi
if [ "$MAPPED" = "0" ]; then
  echo "build.sh: REFUSED -- no remapped path found. Zero absolute paths AND zero remapped paths" >&2
  echo "build.sh: means the check proved nothing: the scan may simply have matched nothing." >&2
  exit 1
fi

SZ=$(stat -c%s "$W")
SHA=$(sha256sum "$W" | cut -d' ' -f1)
B58=$(/usr/bin/python3 -c "
import sys,hashlib
A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
h=bytes.fromhex('$SHA'); n=int.from_bytes(h,'big'); s=''
while n: n,r=divmod(n,58); s=A[r]+s
print('1'*sum(1 for c in h if c==0)+s)")
echo "build.sh: artifact  $W"
echo "build.sh: bytes     $SZ"
echo "build.sh: sha256    $SHA"
echo "build.sh: code_hash $B58"
if [ "$MAPSTD" = "0" ]; then
  echo "build.sh: REFUSED -- no /rustc/${RUSTC_HASH}/ path found. The std paths are unaccounted" >&2
  echo "build.sh: for, so the clean scan above proves nothing." >&2
  exit 1
fi
echo "build.sh: embedded absolute paths 0, remapped registry $MAPPED, canonical std paths $MAPSTD"
echo "build.sh: rust-src $([ -d "${SYSROOT}/lib/rustlib/src/rust/library" ] && echo PRESENT || echo absent) -> reproducible either way (controlled 2026-11-11)"
