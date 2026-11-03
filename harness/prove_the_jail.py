#!/usr/bin/env python3.10
"""Prove the jail: every refusal Leash claims must be REACHABLE against the LIVE contract.

A verifier that cannot fail is not a verifier. Unit tests prove the pure decision function
refuses; they cannot prove the deployed contract does, because the deployed contract is a
different artifact. This harness drives the real contract on NEAR testnet and asserts on the
exact refusal string each arm must produce.

It also runs a POSITIVE CONTROL: a compliant request that must NOT be refused. Without it, a
contract that refused absolutely everything would score a perfect 7/7 and look like a triumph.
"""
import json, os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
def rd(n): return open(os.path.join(ROOT, n)).read().strip()

CONTRACT = rd(".contract-account")
OWNER    = rd(".owner-account")
AGENT    = rd(".agent-account")
ALLOW    = rd(".allowed-recipient")
DENY     = rd(".denied-recipient")
NEAR     = os.path.expanduser("~/.local/bin/near")
# A valid 32-byte base58 value, reused as a stand-in blockhash for refusal arms. Arms that are
# refused never reach message construction, so the blockhash is irrelevant to them.
BH_STUB  = "11111111111111111111111111111111"


def call(signer, method, args, deposit="1 yoctoNEAR", gas="300.0 Tgas"):
    cmd = [NEAR, "contract", "call-function", "as-transaction", CONTRACT, method,
           "json-args", json.dumps(args), "prepaid-gas", gas, "attached-deposit", deposit,
           "sign-as", signer, "network-config", "testnet",
           "sign-with-legacy-keychain", "send"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return (p.stdout or "") + (p.stderr or "")


def transfer(signer, recipient, lamports, blockhash=BH_STUB):
    return call(signer, "request_transfer",
                {"recipient": recipient, "lamports": str(lamports), "recent_blockhash": blockhash})


def set_enabled(agent, enabled):
    return call(OWNER, "set_agent_enabled", {"agent": agent, "enabled": enabled}, deposit="0 NEAR")


ARMS = []
def arm(name, expect, fn):
    ARMS.append((name, expect, fn))

# ---- the seven refusals, each reached by a DIFFERENT input -----------------------------------
arm("unknown agent",        "LEASH_REFUSED: unknown agent",
    lambda: transfer(OWNER, ALLOW, 1_000))                      # owner is not a registered agent
arm("zero amount",          "LEASH_REFUSED: zero amount",
    lambda: transfer(AGENT, ALLOW, 0))
arm("recipient malformed",  "LEASH_REFUSED: recipient malformed",
    lambda: transfer(AGENT, "0OIl-not-base58", 1_000))
arm("recipient not allowed","LEASH_REFUSED: recipient not allowed",
    lambda: transfer(AGENT, DENY, 1_000))
arm("over per-tx limit",    "LEASH_REFUSED: over per-tx limit",
    lambda: transfer(AGENT, ALLOW, 100_000_001))                # ceiling is 100_000_000
arm("over window limit",    "LEASH_REFUSED: over window limit",
    lambda: None)                                               # filled in below (stateful)
arm("agent disabled",       "LEASH_REFUSED: agent disabled",
    lambda: None)                                               # filled in below (stateful)


def main():
    results = []

    print("=" * 78)
    print("PROVE THE JAIL — live refusals on NEAR testnet")
    print("contract:", CONTRACT)
    print("agent:   ", AGENT, "(per-tx 0.1 SOL, window 0.25 SOL)")
    print("=" * 78)

    # --- POSITIVE CONTROL FIRST -------------------------------------------------------------
    # A compliant request must NOT be refused. If this arm shows LEASH_REFUSED, every refusal
    # below is meaningless: the contract is simply saying no to everything.
    print("\n[positive control] compliant request must NOT be refused")
    out = transfer(AGENT, ALLOW, 1_000)
    refused = "LEASH_REFUSED" in out
    print("   refused? ", refused, "->", "FAIL (refuses everything)" if refused else "PASS")
    results.append(("positive control: compliant request not refused", not refused))

    # --- the stateless refusal arms ----------------------------------------------------------
    for name, expect, fn in ARMS[:5]:
        print(f"\n[refusal] {name}")
        out = fn()
        ok = expect in out
        print(f"   expect {expect!r} -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("   got:", re.sub(r"\s+", " ", out)[:300])
        results.append((f"refusal reachable: {name}", ok))

    # --- over window limit: spend up to the ceiling, then exceed it --------------------------
    print("\n[refusal] over window limit (stateful: spend to the ceiling first)")
    for i in range(2):
        transfer(AGENT, ALLOW, 100_000_000)   # 2 x 0.1 = 0.2 of the 0.25 window
    out = transfer(AGENT, ALLOW, 100_000_000) # would make 0.3 > 0.25
    ok = "LEASH_REFUSED: over window limit" in out
    print("   ->", "PASS" if ok else "FAIL")
    if not ok: print("   got:", re.sub(r"\s+", " ", out)[:300])
    results.append(("refusal reachable: over window limit", ok))

    # --- agent disabled ----------------------------------------------------------------------
    print("\n[refusal] agent disabled (owner flips the switch)")
    set_enabled(AGENT, False)
    out = transfer(AGENT, ALLOW, 1_000)
    ok = "LEASH_REFUSED: agent disabled" in out
    print("   ->", "PASS" if ok else "FAIL")
    if not ok: print("   got:", re.sub(r"\s+", " ", out)[:300])
    results.append(("refusal reachable: agent disabled", ok))
    set_enabled(AGENT, True)   # restore

    # --- summary ------------------------------------------------------------------------------
    print("\n" + "=" * 78)
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{passed}/{len(results)} — ", "ALL PROVEN" if passed == len(results) else "NOT PROVEN")
    print("=" * 78)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
