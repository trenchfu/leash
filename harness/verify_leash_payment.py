#!/usr/bin/env python3
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
import sys
if sys.version_info[:2] < (3, 8):
    sys.stderr.write(
        "WRONG INTERPRETER: the Leash harness requires python >= 3.8, got %d.%d.%d at %s.\n"
        "NOTHING RAN. Invoke an explicit interpreter, e.g. `python3.10 %s`.\n"
        % (sys.version_info[0], sys.version_info[1], sys.version_info[2],
           sys.executable, sys.argv[0]))
    sys.exit(3)
import base64, json, sys, time, urllib.request

# Endpoint list, tried in order. The official testnet RPC rate-limits hard under polling (I hit
# sustained 429s building this), so a judging-time check that depends on it alone will report
# UNMEASURED when it is actually fine. UNMEASURED is only declared when EVERY endpoint fails.
RPCS = [
    "https://test.rpc.fastnear.com",
    "https://rpc.testnet.near.org",
]
MPC = "v1.signer-prod.testnet"
ED25519_DOMAIN = 1

# A JSON-RPC error arrives inside an HTTP 200. Some of those are ANSWERS (the account really is
# unknown); others are the server declining to answer (rate limit, timeout). Collapsing them makes
# a throttled read look like a proven failure -- fail-safe, since UNMEASURED never passes, but it
# would mark a good contract NOT_TRUSTED at judging time. Unrecognised causes are treated as
# transient on purpose: UNMEASURED is the safe side of that doubt.
REAL_ANSWER_CAUSES = {
    "UNKNOWN_ACCOUNT", "UNKNOWN_ACCESS_KEY", "UNKNOWN_BLOCK",
    "METHOD_NOT_FOUND", "CONTRACT_EXECUTION_ERROR", "INVALID_ACCOUNT",
}


def classify_rpc_error(payload):
    """-> ("answer", cause) when the node answered, ("transient", cause) when it declined."""
    err = payload.get("error") or {}
    cause = ((err.get("cause") or {}).get("name")
             or err.get("name") or err.get("message") or "UNSPECIFIED")
    if isinstance(cause, str) and cause.upper() in REAL_ANSWER_CAUSES:
        return "answer", cause
    return "transient", cause


class Unmeasured(Exception):
    """The answer could not be READ. Distinct from an answer that was read and was wrong -- a
    rate limit or a timeout must never be reported as a pass, and must not be reported as a
    proven failure either."""

def rpc(method, params, tries=4):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    last = ""
    for i in range(tries):
        for url in RPCS:
            try:
                req = urllib.request.Request(url, data=body,
                                             headers={"Content-Type":"application/json"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    payload = json.loads(r.read())
                    if "error" in payload:
                        kind, cause = classify_rpc_error(payload)
                        if kind == "transient":
                            last = f"{url}: transient {cause}"
                            continue          # try the next endpoint, then back off
                    return payload
            except Exception as e:
                last = f"{url}: {e}"
        if i < tries - 1:
            time.sleep(1.0 * (2 ** i))      # backoff before the next sweep of endpoints
    raise Unmeasured(last)

def view(account, method, args):
    a = base64.b64encode(json.dumps(args).encode()).decode()
    r = rpc("query", {"request_type":"call_function","finality":"final",
                      "account_id":account,"method_name":method,"args_base64":a})
    if "error" in r:
        return None          # a real answer: the method or account is not there
    res = r.get("result") or {}
    if "error" in res or "result" not in res:
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

def code_hash(account):
    r = rpc("query", {"request_type": "view_account", "finality": "final",
                      "account_id": account})
    if "error" in r:
        return None
    return (r.get("result") or {}).get("code_hash")


def verify(contract, path, claimed_sender, pinned_hash=None):
    """Each check returns (name, state, detail) where state is "ok" | "fail" | "unmeasured"."""
    checks = []
    def guard(name, fn):
        try:
            ok, detail = fn()
            checks.append((name, "ok" if ok else "fail", detail))
        except Unmeasured as e:
            checks.append((name, "unmeasured", f"could not read: {str(e)[:60]}"))

    def a():
        d = derived(contract, path)
        return d == claimed_sender, d or "no derivation returned"
    guard("A address derives from this account+path", a)

    def b():
        sr = view(contract, "get_solana_address", {})
        sr = json.loads(sr) if sr else None
        return sr == claimed_sender, sr or "no get_solana_address"
    guard("B contract reports the same address", b)

    def c():
        fa = full_access_count(contract)
        return fa == 0, "unknown" if fa is None else f"{fa} full-access key(s)"
    guard("C account is LOCKED (0 full-access keys)", c)

    # D probes the POLICY surface, not a version. The first cut asked for get_totals/list_agents
    # -- both added in v3 -- and so rejected a correctly LOCKED pre-v3 Leash. That is the worst
    # shape for a trust check: locking is irreversible, so "upgrade it" is not available, and the
    # check would reject that contract forever. Probe what has existed since v1 and what actually
    # carries the guarantee: a per-agent policy and a named MPC signer.
    def dd():
        policy = view(contract, "get_agent_policy", {"agent": "probe.testnet"})
        mpc = view(contract, "get_mpc_contract", {})
        ok = policy is not None and mpc is not None
        return ok, (f"policy surface present, signer {json.loads(mpc)}" if ok
                    else "policy surface ABSENT")
    guard("D exposes a policy surface (version-independent)", dd)

    # E identifies the actual BYTECODE. D only shows that something policy-SHAPED is deployed, and
    # a rogue can expose get_agent_policy and get_mpc_contract while signing anything, so D alone
    # is imitable. (Found by the coordinator reviewing this file.)
    #
    # E and C are COUPLED, and that resolves what looks like a contradiction with "probe the
    # capability, not the version". Pinning an exact build is WRONG for a mutable contract -- it
    # rejects legitimate upgrades. It is RIGHT here precisely because C proves the code can never
    # legitimately change again. If C fails, E is decoration; if C holds, E is the identity check.
    def e():
        if pinned_hash is None:
            return False, "UNPINNED -- no expected build hash supplied"
        h = code_hash(contract)
        return h == pinned_hash, f"{h} vs pinned {pinned_hash}"
    guard("E deployed code hash equals the pinned Leash build", e)

    return checks

def verdict_of(checks):
    """UNMEASURED is NOT a pass. It is also not a proven failure, and collapsing the two is how a
    rate limit quietly becomes a verdict."""
    if any(st == "fail" for _, st, _ in checks):
        return "NOT_TRUSTED"
    if any(st == "unmeasured" for _, st, _ in checks):
        return "UNMEASURED"
    return "TRUSTED"

def report(label, contract, path, claimed_sender, expect_trusted, pinned_hash=None):
    print(f"\n--- {label}")
    print(f"    contract {contract}")
    print(f"    sender   {claimed_sender}")
    checks = verify(contract, path, claimed_sender, pinned_hash)
    for name, state, detail in checks:
        mark = {"ok": "ok  ", "fail": "FAIL", "unmeasured": "UNM "}[state]
        print(f"      {mark}  {name}  [{detail}]")
    verdict = verdict_of(checks)
    print(f"    VERDICT: {verdict}")
    trusted = verdict == "TRUSTED"
    correct = trusted == expect_trusted
    print(f"    harness expectation {expect_trusted} -> {'PASS' if correct else 'HARNESS FAIL'}")
    return correct, [(n, st) for n, st, _ in checks if st != "ok"]

def cli(contract, path, sender, pinned_hash=None):
    """Stable single-shot mode for a counterparty. One machine-readable line, exit 0 only on
    TRUSTED; UNMEASURED exits 2 so a caller can tell "could not read" from "read and wrong"."""
    checks = verify(contract, path, sender, pinned_hash)
    verdict = verdict_of(checks)
    bad = ",".join(n.split()[0] for n, st, _ in checks if st != "ok") or "-"
    print(f"LEASH_VERIFY contract={contract} path={path} sender={sender} "
          f"verdict={verdict} failed={bad}")
    return {"TRUSTED": 0, "NOT_TRUSTED": 1, "UNMEASURED": 2}[verdict]


def main():
    if len(sys.argv) in (4, 5):
        return cli(*sys.argv[1:])
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
    distinct = {tuple(n for n, _ in f) for f in fails}
    print(f"{ok}/{len(results)} arms behaved as expected")
    print(f"the three rejections fail on {len(distinct)} DISTINCT check(s) -- "
          f"{'each for its own reason' if len(distinct) == 3 else 'NOT independent'}")
    for i, f in enumerate(fails, 2):
        print(f"   arm {i} failed: {', '.join(x[0][0] for x in f)}")
    print("=" * 78)
    return 0 if ok == len(results) else 1

if __name__ == "__main__":
    sys.exit(main())
