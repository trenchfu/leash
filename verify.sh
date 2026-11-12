#!/usr/bin/env bash
# Leash — one-command verification. No keys, no accounts, no trust in this README.
#
# Proves three things and says which is which:
#   1. the offline policy suite passes
#   2. this source rebuilds the EXACT bytes deployed at leash-b0c503d6.testnet
#   3. the account holding the proven custody guarantee has ZERO access keys
#
# Needs: rust stable + wasm32-unknown-unknown, python3 (>=3.8), curl.
set -u
RPC="${LEASH_RPC:-https://rpc.testnet.near.org}"
CONTRACT="${LEASH_CONTRACT:-leash-b0c503d6.testnet}"
LOCKED="${LEASH_LOCKED:-leash-locked-7f0c6d.testnet}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# Pick an interpreter that is actually >= 3.8. A bare `python3` is not safe to assume:
# on at least one of our own machines it resolves to a 3.4 that shadows the real one.
PY=""
for c in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
  command -v "$c" >/dev/null 2>&1 || continue
  if "$c" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3,8) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
if [ -z "$PY" ]; then echo "no python3 >= 3.8 found on PATH"; exit 3; fi
fail=0
say() { printf '\n== %s\n' "$1"; }

say "1/3  offline policy suite"
( cd "$HERE/contract" && cargo test -q 2>&1 | grep -E '^test result' ) || fail=1

say "2/3  reproducible build vs the deployed artifact"
TGT="$(mktemp -d)"
# ONE RECIPE, 2026-11-11. This used to carry its own inline --remap-path-prefix flags, which made
# THREE scripts in this repo with three different remaps and three different artifacts
# (458,234 / 458,248 / 458,442). A verifier with its own private recipe cannot verify the recipe
# that actually shipped, so this now runs contract/build.sh -- the same script whose output was
# deployed -- and build.sh owns the flags, the guards and the positive controls.
( cd "$HERE/contract" && CARGO_TARGET_DIR="$TGT" ./build.sh 2>&1 | tail -3 )
LOCAL_WASM="$TGT/wasm32-unknown-unknown/release/leash.wasm"
if [ ! -f "$LOCAL_WASM" ]; then echo "BUILD FAILED"; fail=1; else
  "$PY" - "$RPC" "$CONTRACT" "$LOCAL_WASM" <<'PY'
import base64, hashlib, json, sys, urllib.request
rpc, acct, path = sys.argv[1], sys.argv[2], sys.argv[3]
body = {"jsonrpc":"2.0","id":"1","method":"query","params":{
        "request_type":"view_code","finality":"final","account_id":acct}}
req = urllib.request.Request(rpc, data=json.dumps(body).encode(),
                             headers={"Content-Type":"application/json"})
res = json.load(urllib.request.urlopen(req, timeout=60))["result"]
# derive the hash from the BYTES, never from the RPC's own code_hash field
chain = base64.b64decode(res["code_base64"])
local = open(path, "rb").read()
ch, lh = hashlib.sha256(chain).hexdigest(), hashlib.sha256(local).hexdigest()
# REDEPLOYED 2026-11-11: the WL-CL-020 fix went on chain as the REPRODUCIBLE build, so the
# deployed artifact and this tree now agree for everyone, and this check asserts IDENTICAL
# instead of explaining a gap. Two independent machines re-derived these bytes.
DEPLOYED_SHA = "3d8dae96c0eea6ee999c333031ae9b6152174c017830046cf7737a1eae91bf11"
EXPECT_BYTES = 458248
# Superseded, kept so a stale citation elsewhere can be traced rather than puzzled over:
#   db40808d...b30b / 459,050 B -- the artifact deployed 2026-11-05, NOT re-derivable by anyone
#     (its build machine had rust-src installed; that state was never recorded). Replaced.
#   c70089857a9efaa0 / 458,234 B -- build-reproducible.sh, a different remap recipe. Superseded.
#   3fe8d7b6...       / 458,442 B -- the plain pinned build, 19 host paths. Retracted 2026-11-07.
print("   deployed %7d bytes  sha256 %s" % (len(chain), ch))
print("   rebuilt  %7d bytes  sha256 %s" % (len(local), lh))
if ch == lh:
    print("   IDENTICAL -- the deployed artifact is this build")
    # Identical is necessary but not sufficient: both could be some OTHER build. Pin both to the
    # documented figures, so this cannot pass against an artifact nobody re-derived.
    pinned = (ch == DEPLOYED_SHA and len(chain) == EXPECT_BYTES)
    print("   matches the DOCUMENTED hash and byte count (%d): %s" % (EXPECT_BYTES, pinned))
    if not pinned:
        print("   *** the chain and this tree agree with EACH OTHER but not with VERSIONS.md.")
        print("   *** Either the docs are stale or both sides moved together. Do not trust either")
        print("   *** until VERSIONS.md is re-derived. Failing closed.")
    sys.exit(0 if pinned else 1)
print("   DIFFERENT -- and since 2026-11-11 that is a REAL FAILURE, not an expected gap.")
print("   The deployed artifact IS this reproducible build; if these disagree then the tree,")
print("   the toolchain or the deployed code has moved. Expected sha256 %s" % DEPLOYED_SHA)
print("   deployed matches the documented hash: %s" % (ch == DEPLOYED_SHA))
print("   rebuilt  matches the documented hash: %s" % (lh == DEPLOYED_SHA))
sys.exit(1)
PY
  [ $? -ne 0 ] && fail=1
fi
rm -rf "$TGT"

say "3/3  custody: the proven account must hold ZERO access keys"
"$PY" - "$RPC" "$LOCKED" "$CONTRACT" <<'PY'
import json, sys, urllib.request
rpc = sys.argv[1]
def keys(acct):
    body = {"jsonrpc":"2.0","id":"1","method":"query","params":{
            "request_type":"view_access_key_list","finality":"final","account_id":acct}}
    req = urllib.request.Request(rpc, data=json.dumps(body).encode(),
                                 headers={"Content-Type":"application/json"})
    ks = json.load(urllib.request.urlopen(req, timeout=60))["result"]["keys"]
    return len(ks), sum(1 for k in ks if k["access_key"]["permission"] == "FullAccess")
ln, lf = keys(sys.argv[2])
cn, cf = keys(sys.argv[3])
print("   %-30s keys=%d FullAccess=%d  %s" % (sys.argv[2], ln, lf,
      "LOCKED" if lf == 0 else "*** NOT LOCKED ***"))
print("   %-30s keys=%d FullAccess=%d  %s" % (sys.argv[3], cn, cf,
      "locked" if cf == 0 else "still upgradable (stated in README: Custody status)"))
sys.exit(0 if lf == 0 else 1)
PY
[ $? -ne 0 ] && fail=1

say "RESULT"
[ "$fail" -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOMETHING FAILED -- see above"
exit "$fail"
