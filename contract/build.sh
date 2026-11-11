#!/usr/bin/env bash
# Reproducible build for the Leash NEAR contract. Produces BYTE-IDENTICAL output on any machine.
#
# WHY THIS SCRIPT EXISTS, 2026-11-11. A plain `cargo build --locked --target wasm32-unknown-unknown
# --release` is NOT byte-reproducible across machines. The artifact carries 19 absolute dependency
# source paths in its data section -- panic-location strings of the form
#   /home/<user>/.cargo/registry/src/index.crates.io-<hash>/<crate>/src/<file>.rs
# so the BUILDING USER'S HOME DIRECTORY ends up inside the wasm. Measured on one commit, same rustc
# 1.95.0, same LLVM 22.1.2, same Cargo.lock under --locked: <home> (10 chars) gave 458,456 bytes
# and a peer's <home> (11 chars) gave 458,472. Nineteen paths one byte longer each, minus
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
export RUSTFLAGS="--cfg near --remap-path-prefix=${CH}/registry=/cargo-registry --remap-path-prefix=${CH}/git=/cargo-git"
echo "build.sh: CARGO_HOME=${CH}"
echo "build.sh: RUSTFLAGS=${RUSTFLAGS}"
rustc --version --verbose | sed -n '1p;/LLVM/p' | sed 's/^/build.sh: /'
cargo --version | sed 's/^/build.sh: /'

cargo build --locked --target wasm32-unknown-unknown --release
W="${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/leash.wasm"

LEAK=$(strings -a "$W" | grep -c '/home/\|/Users/\|/root/' || true)
if [ "$LEAK" != "0" ]; then
  echo "build.sh: REFUSED -- $LEAK absolute path(s) still embedded in the artifact:" >&2
  strings -a "$W" | grep -o '/home/[^ ]*\|/Users/[^ ]*\|/root/[^ ]*' | sort -u | head -5 >&2
  echo "build.sh: the output would not be reproducible on another machine." >&2
  exit 1
fi
# Positive control: the remap must have ACTUALLY fired, not silently matched nothing.
MAPPED=$(strings -a "$W" | grep -c '/cargo-registry' || true)
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
echo "build.sh: embedded absolute paths 0, remapped paths $MAPPED -> reproducible"
