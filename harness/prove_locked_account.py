#!/usr/bin/env python3.10
"""Prove the one caveat Leash carries: a derived key follows the ACCOUNT, not the code.

Leash's custody claim is that an agent cannot move funds it has no key for. That claim has a hole
I documented against my own design from the start: NEAR Chain-Signatures derives the foreign key
from (account, path), so whoever holds a FULL-ACCESS key on the contract's account can replace the
policy with anything -- keeping the same Solana address -- and the guarantee evaporates.

Stating that is not proving it. This script RUNS the attack, then closes it:

  ARM A  derive the address for a fresh account                      (baseline)
  ARM B  deploy Leash, confirm the address is unchanged              (key is account-bound)
  ARM C  ATTACK: while unlocked, replace Leash with a no-policy      (the hole, demonstrated)
         contract -- and show the Solana address is STILL identical
  ARM D  restore Leash, then LOCK the account (delete every
         full-access key) and verify zero remain on chain            (the fix)
  ARM E  DEFENCE: attempt the same attack with the deleted key and
         have the CHAIN reject it                                    (the fix, proven)

Arm C is the one that matters. Without it, arm E proves only that a thing I never showed was
dangerous is now prevented.
"""
import json, os, re, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
rd = lambda n: open(os.path.join(ROOT, n)).read().strip()
# ONE ACCOUNT PER CLAIM. The first attempt reused a single account for both halves: the rogue's
# seize() had written state, Leash's new() is #[init] and refuses existing state, so the "restore"
# silently failed and the account was locked with the ROGUE on it. The harness caught that, but
# the right fix is structural -- an account that has been attacked cannot also be the account that
# demonstrates the defence.
ATTACK = rd(".attack-account")      # stays unlocked; shows the hole is real
LOCKED = rd(".locked-account")      # fresh; shows locking closes it
ACC = ATTACK
OWNER = rd(".owner-account")
NEAR = os.path.expanduser("~/.local/bin/near")
RPC = "https://rpc.testnet.near.org"
LEASH_WASM = os.path.join(ROOT, "contract/target/wasm32-unknown-unknown/release/leash.wasm")
ROGUE_WASM = os.path.join(ROOT, "rogue/target/wasm32-unknown-unknown/release/rogue.wasm")
PATHSTR = "solana-1"

def rpc(method, params):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def view(account, method, args):
    import base64
    a = base64.b64encode(json.dumps(args).encode()).decode()
    r = rpc("query", {"request_type":"call_function","finality":"final",
                      "account_id":account,"method_name":method,"args_base64":a})
    if "error" in r or "error" in r.get("result", {}):
        return None
    return bytes(r["result"]["result"]).decode()

def derived_address():
    out = view("v1.signer-prod.testnet", "derived_public_key",
               {"path": PATHSTR, "predecessor": ACC, "domain_id": 1})
    return json.loads(out).split(":", 1)[1] if out else None

def access_keys():
    r = rpc("query", {"request_type":"view_access_key_list","finality":"final","account_id":ACC})
    return r.get("result", {}).get("keys", [])

def full_access_keys():
    return [k for k in access_keys() if k["access_key"]["permission"] == "FullAccess"]

def sh(args, timeout=180):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))

def deploy(wasm, init_method=None, init_args=None):
    cmd = [NEAR, "contract", "deploy", ACC, "use-file", wasm]
    if init_method:
        cmd += ["with-init-call", init_method, "json-args", json.dumps(init_args),
                "prepaid-gas", "100.0 Tgas", "attached-deposit", "0 NEAR"]
    else:
        cmd += ["without-init-call"]
    cmd += ["network-config", "testnet", "sign-with-legacy-keychain", "send"]
    return sh(cmd)

results = []
def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"   {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))

def main():
    global ACC
    print("=" * 78)
    print("PROVE THE LOCKED ACCOUNT -- running the attack on Leash, then closing it")
    print("account:", ACC)
    print("=" * 78)

    print("\n[A] baseline: derive the Solana address for this account")
    addr0 = derived_address()
    print("    ", addr0)
    record("address derives before any code is deployed", addr0 is not None)

    print("\n[B] deploy Leash and confirm the address did not move")
    out = deploy(LEASH_WASM, "new", {"owner": OWNER, "mpc_contract": "v1.signer-prod.testnet",
                                     "derivation_path": PATHSTR, "solana_address": addr0})
    deployed = "successfully deployed" in out
    addr1 = derived_address()
    sol = view(ACC, "get_solana_address", {})
    record("Leash deployed", deployed)
    record("derived address unchanged by deploying code", addr1 == addr0, addr1)
    record("Leash is live and reports its address", sol is not None and addr0 in (sol or ""))

    print("\n[C] ATTACK -- account is UNLOCKED. Replace Leash with a no-policy contract.")
    fa = full_access_keys()
    print(f"     full-access keys present: {len(fa)}  <- this is what makes the attack possible")
    out = deploy(ROGUE_WASM, "seize", {})
    seized = "successfully deployed" in out
    record("rogue contract REPLACED Leash", seized,
           "the attack works while unlocked" if seized else "")
    addr2 = derived_address()
    record("SAME Solana address after the swap", addr2 == addr0, addr2)
    pc = view(ACC, "policy_count", {})
    record("new code has NO policy", pc is not None and pc.strip() == "0",
           f"policy_count={pc.strip() if pc else 'n/a'}")
    drain = view(ACC, "drain", {"recipient": "anywhere", "lamports": "999999999"})
    if drain:
        print("     rogue says:", drain.strip('"')[:90])
    gone = view(ACC, "get_agent_policy", {"agent": OWNER})
    record("Leash's policy surface is gone", gone is None)

    print("\n[D] FRESH account: deploy Leash, then LOCK it")
    ACC = LOCKED
    print("     account:", ACC)
    laddr = derived_address()
    out = deploy(LEASH_WASM, "new", {"owner": OWNER, "mpc_contract": "v1.signer-prod.testnet",
                                     "derivation_path": PATHSTR, "solana_address": laddr})
    record("Leash deployed to the fresh account", "successfully deployed" in out)
    record("Leash answers before locking",
           view(ACC, "get_solana_address", {}) is not None)
    before = full_access_keys()
    print(f"     deleting {len(before)} full-access key(s)")
    for k in before:
        out = sh([NEAR, "account", "delete-keys", ACC, "public-keys", k["public_key"],
                  "network-config", "testnet", "sign-with-legacy-keychain", "send"])
        if "successful" not in out.lower() and "error" in out.lower():
            print("     delete failed:", re.sub(r"\s+", " ", out)[-160:])
        time.sleep(3)
    after = full_access_keys()
    record("zero full-access keys remain on chain", len(after) == 0,
           f"{len(before)} -> {len(after)}")
    record("derived address survives locking", derived_address() == laddr, laddr)

    print("\n[E] DEFENCE -- attempt the SAME attack with the now-deleted key")
    out = deploy(ROGUE_WASM, "seize", {})
    refused = "successfully deployed" not in out
    reason = ""
    for pat in (r"AccessKeyDoesNotExist", r"access key .* does not exist", r"InvalidAccessKeyError",
                r"NotEnoughBalance", r"Error:.*"):
        m = re.search(pat, out, re.I)
        if m: reason = m.group(0)[:110]; break
    record("rogue redeploy REFUSED on a locked account", refused, reason)
    rogue_marker = view(ACC, "policy_count", {})
    leash_marker = view(ACC, "get_solana_address", {})
    record("the rogue did NOT land", rogue_marker is None, "policy_count absent")
    record("Leash is STILL the deployed code", leash_marker is not None,
           "get_solana_address still answers")

    print("\n" + "=" * 78)
    p = sum(1 for _, ok, _ in results if ok)
    print(f"{p}/{len(results)} -- " + ("PROVEN" if p == len(results) else "NOT PROVEN"))
    attack_worked = next((ok for n, ok, _ in results if "rogue contract REPLACED" in n), False)
    lock_held = next((ok for n, ok, _ in results if "REFUSED on a locked account" in n), False)
    print("attack on an UNLOCKED account succeeded : %s" % attack_worked)
    print("same attack on a LOCKED account refused : %s" % lock_held)
    if attack_worked and lock_held:
        print("Both halves hold: the hole is real, and locking closes it.")
    else:
        print("INCOMPLETE -- do not quote this as a proof.")
    print("=" * 78)
    return 0 if p == len(results) else 1

if __name__ == "__main__":
    sys.exit(main())
