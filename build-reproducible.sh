#!/usr/bin/env bash
# Build the Leash contract so that the bytes do not depend on WHERE this machine keeps things.
#
# WHY THIS SCRIPT EXISTS, measured 2026-11-07 and not guessed: a plain `cargo build --release`
# under the pinned toolchain embeds 19 absolute dependency-source paths from $CARGO_HOME. Move
# CARGO_HOME and the artifact changes -- 458,442 B at one path, 459,714 B at another. The earlier
# "portable" claim in VERSIONS.md was tested by moving the SOURCE tree, which left $CARGO_HOME
# fixed, so it could not see this. The two --remap-path-prefix flags below are the fix, and they
# have to be computed HERE rather than written into .cargo/config.toml, because the prefixes they
# erase are different on every machine.
set -euo pipefail
cd "$(dirname "$0")/contract"
CARGO_HOME_ABS="${CARGO_HOME:-$HOME/.cargo}"
SRC_ABS="$(pwd)"
export RUSTFLAGS="--cfg near --remap-path-prefix=${CARGO_HOME_ABS}=/cargo --remap-path-prefix=${SRC_ABS}=/src"
# --cfg near is repeated deliberately: RUSTFLAGS in the environment REPLACES the rustflags in
# .cargo/config.toml, it does not append. Dropping it swaps the host sha256 for a software one,
# which is a gas change, not a size change.
OUT="${1:-$(pwd)/target}"
rm -rf "$OUT"
CARGO_TARGET_DIR="$OUT" cargo build --release --target wasm32-unknown-unknown
W="$OUT/wasm32-unknown-unknown/release/leash.wasm"
echo
echo "artifact : $W"
echo "bytes    : $(stat -c %s "$W")"
echo "sha256   : $(sha256sum "$W" | cut -d' ' -f1)"
# NO "expected" LINE HERE, DELIBERATELY. It used to print the hash this repo documents, right
# under the one just computed. the coordinator re-derived these bytes blind on a second machine on
# 2026-11-07 and reported that the echo disclosed my number to her at the end of her own run --
# harmless for a deterministic build she had already finished, and fatal for the NEXT independent
# re-derivation, which is the only instrument that can falsify a reproducibility claim. An
# instrument states what it MEASURED; the claim lives in VERSIONS.md and the assertion lives in
# verify.sh, which exits non-zero on drift. Keep those three jobs in three places.
echo "host paths left in the artifact (must be 0):"
strings -a "$W" | grep -cE "^(/home|/Users|/root)/" || true
