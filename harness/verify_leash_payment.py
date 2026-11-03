#!/usr/bin/env python3.10
"""Is this payment's sender a POLICED Leash? A verifier for a counterparty (e.g. teletask).

Receiving a SOL payment and binding it to a sender address proves WHO signed. It does not prove a
policy was enforced -- the derived address is a function of (contract account, path) ONLY, so it
survives the contract's code being replaced. A counterparty that trusts the address alone is
satisfied by an unpoliced signer holding the same address.

Four independent checks, each of which can fail on its own:

  A  the sender address really IS derived from that NEAR account + path   (binds address -> account)
  B  the contract itself reports the same address                          (the account agrees)
  C  the account has ZERO full-access keys                                 (the code cannot be swapped)
  D  the deployed code exposes Leash's policy surface                      (it is Leash, not merely locked)

C and D are BOTH required and neither implies the other. An unlocked Leash can be replaced tomorrow.
A locked account running something else is permanently unpoliced -- the worse failure, because it
looks maximally trustworthy from the outside.
"""
import base64, json, sys, urllib.request

RPC = "https://rpc.testnet.near.org"
MPC = "v1.signer-prod.testnet"
ED25519_DOMAIN = 1

def rpc(method, params):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def view(account, method, args):
    a = base64.b64encode(json.dumps(args).encode()).decode()
    r = rpc("query", {"request_type":"call_function","finality":"final",
                      "account_id":account,"method_name":method,"args_base64":a})
    res = r.get("result") or {}
    if "error" in r or "error" in res or "result" not in res:
        return None
    return bytes(res["result"]).decode()

def derived(account, path):
    out = view(MPC, "derived_public_key",
               {"path": path, "predecessor": account, "domain_id": ED25519_DOMAIN})
    return json.loads(out).split(":", 1)[1] if out else None

def full_access_count(account):
    r = rpc("query", {"request_type":"view_access_key_list","finality":"final",
                      "account_id":account})
    keys = (r.get("result") or {}).get("keys")
    if keys is None:
        return None
    return sum(1 for k in keys if k["access_key"]["permission"] == "FullAccess")

def verify(contract, path, claimed_sender):
    checks = []

    d = derived(contract, path)
    checks.append(("A address derives from this account+path", d == claimed_sender,
                   d or "could not derive"))

    self_reported = view(contract, "get_solana_address", {})
    sr = json.loads(self_reported) if self_reported else None
    checks.append(("B contract reports the same address", sr == claimed_sender,
                   sr or "no get_solana_address"))

    fa = full_access_count(contract)
    checks.append(("C account is LOCKED (0 full-access keys)", fa == 0,
                   "unknown" if fa is None else f"{fa} full-access key(s)"))

    # D probes the POLICY surface, not a version. The first cut asked for get_totals/list_agents
    # -- both added in v3 -- and so rejected a correctly LOCKED pre-v3 Leash. That is the worst
    # shape for a trust check: locking is irreversible, so "upgrade it" is not available, and the
    # check would reject that contract forever. Probe what has existed since v1 and what actually
    # carries the guarantee: a per-agent policy and a named MPC signer.
    policy = view(contract, "get_agent_policy", {"agent": "probe.testnet"})
    mpc = view(contract, "get_mpc_contract", {})
    is_leash = policy is not None and mpc is not None
    checks.append(("D exposes a policy surface (version-independent)", is_leash,
                   f"get_agent_policy + get_mpc_contract present, signer {json.loads(mpc)}"
                   if is_leash else "policy surface ABSENT"))

    # Informational only -- NEVER a trust gate. A newer Leash has an audit ring; an older one is
    # not less trustworthy for lacking it.
    has_audit = view(contract, "get_totals", {}) is not None
    checks.append(("  (info) audit ring present", True,
                   "yes" if has_audit else "no -- pre-v3 Leash, not a trust failure"))

    return checks

def report(label, contract, path, claimed_sender, expect_trusted):
    print(f"\n--- {label}")
    print(f"    contract {contract}")
    print(f"    sender   {claimed_sender}")
    checks = verify(contract, path, claimed_sender)
    for name, ok, detail in checks:
        print(f"      {'ok  ' if ok else 'FAIL'}  {name}  [{detail}]")
    trusted = all(ok for _, ok, _ in checks)
    print(f"    VERDICT: {'TRUSTED (policed Leash)' if trusted else 'NOT TRUSTED'}")
    correct = trusted == expect_trusted
    print(f"    harness expectation {expect_trusted} -> {'PASS' if correct else 'HARNESS FAIL'}")
    return correct, [n for n, ok, _ in checks if not ok]

def main():
    import os
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rd = lambda n: open(os.path.join(ROOT, n)).read().strip()
    LOCKED  = rd(".locked-account")        # Leash, locked
    DEMO    = rd(".contract-account")      # Leash, UNLOCKED
    ROGUE   = rd(".spent-account-locked-with-rogue")  # locked, but running the rogue
    PATH    = "solana-1"

    print("=" * 78)
    print("IS THIS SENDER A POLICED LEASH?  four checks, four ways to fail")
    print("=" * 78)

    results = []
    results.append(report("1 LOCKED Leash -- should be trusted",
                          LOCKED, PATH, derived(LOCKED, PATH), True))
    results.append(report("2 UNLOCKED Leash -- policy can be replaced tomorrow",
                          DEMO, PATH, derived(DEMO, PATH), False))
    results.append(report("3 LOCKED but running a ROGUE -- immutably UNPOLICED, the worst case",
                          ROGUE, PATH, derived(ROGUE, PATH), False))
    results.append(report("4 right contract, WRONG sender -- address does not bind",
                          LOCKED, PATH, "11111111111111111111111111111111", False))

    print("\n" + "=" * 78)
    ok = sum(1 for c, _ in results if c)
    fails = [f for _, f in results[1:]]
    distinct = {tuple(f) for f in fails}
    print(f"{ok}/{len(results)} arms behaved as expected")
    print(f"the three rejections fail on {len(distinct)} DISTINCT check(s) -- "
          f"{'each for its own reason' if len(distinct) == 3 else 'NOT independent'}")
    for i, f in enumerate(fails, 2):
        print(f"   arm {i} failed: {', '.join(x[0] for x in f)}")
    print("=" * 78)
    return 0 if ok == len(results) else 1

if __name__ == "__main__":
    sys.exit(main())
