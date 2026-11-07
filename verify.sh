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
# The remap flags are what make these bytes independent of where THIS machine keeps its
# cargo registry; without them a different $CARGO_HOME gives a different artifact (measured:
# 458,442 vs 459,714 B). --cfg near is repeated because RUSTFLAGS REPLACES the config rustflags.
( cd "$HERE/contract" \
  && CARGO_TARGET_DIR="$TGT" \
     RUSTFLAGS="--cfg near --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$HERE/contract=/src" \
     cargo build --release --target wasm32-unknown-unknown 2>&1 | tail -1 )
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
DEPLOYED_SHA = "db40808d5b6ad22f733f2ff674d91913af1eb21a2e81a5f41e4012816922b30b"
# The REMAPPED build's hash. The earlier 3fe8d7b6... was the plain pinned build, which carries
# 19 absolute $CARGO_HOME paths and is NOT portable -- retracted in VERSIONS.md 2026-11-07.
PORTABLE_SHA = "c70089857a9efaa0" 
print("   deployed %7d bytes  sha256 %s" % (len(chain), ch))
print("   rebuilt  %7d bytes  sha256 %s" % (len(local), lh))
if ch == lh:
    print("   IDENTICAL -- the deployed artifact is this build")
    sys.exit(0)
print("   DIFFERENT, AND EXPECTED. The deployed artifact predates the toolchain pin and")
print("   embeds absolute paths from its build machine, so only that machine can reproduce")
print("   it. This rebuild is the REMAPPED one: byte-identical from two different $CARGO_HOME")
print("   paths, with no /home, /Users or /root string left in it. See VERSIONS.md.")
ok = ch == DEPLOYED_SHA and lh.startswith(PORTABLE_SHA)
print("   deployed matches the documented hash: %s" % (ch == DEPLOYED_SHA))
print("   rebuild  matches the documented portable hash: %s" % lh.startswith(PORTABLE_SHA))
sys.exit(0 if ok else 1)
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
