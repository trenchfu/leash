#!/usr/bin/env python3
"""ON-CHAIN behavioural proof that WL-CL-020 is fixed in the RUNNING build. DRY RUN unless --apply.

WHY THIS EXISTS. The deploy of 2026-11-11T22:1xZ proved BYTE IDENTITY: the running code_hash equals
base58(sha256()) of the artifact built from the fixed source, and two machines re-derived that
artifact. What byte identity cannot show is BEHAVIOUR: the fix only manifests on a WRITE, so no view
call can distinguish the fixed contract from the buggy one. Six unit tests cover it off chain. This
covers it ON chain, which is the only place the owner's "clobber fix then lock" order is actually satisfied.

THE DISCRIMINATING SEQUENCE, against the LIVE agent:
  1. read the live policy and keep EVERY field.
  2. set_agent_enabled(agent, false)         -> enabled must read false, else abort (nothing else done)
  3. set_agent_policy(same fields, same expiry)  <- the renewal under test
  4. read back:  enabled == false  => FIXED   (the renewal carried it forward)
                 enabled == true   => STILL BUGGY (the renewal clobbered the disable)
  5. restore set_agent_enabled(agent, true).

WHY THIS IS SAFE TO RUN AGAINST THE LIVE AGENT, not a throwaway one:
  * the contract has NO remove-agent method, so probing a fresh agent id would leave permanent junk
    in the dev contract's state; this leaves the state it found.
  * step 3 re-asserts the SAME expiry it read, so the clock does not move either way.
  * the restore is installed BEFORE the mutation (try/finally) and runs on every exit path,
    including an exception; the final state is then READ BACK and printed, never assumed.
  * the benign-failure direction: under the OLD buggy code step 3 would itself re-enable the agent,
    so a crash after step 3 leaves it ENABLED. Only a crash between 2 and 3 can leave it disabled,
    and that window holds no network call but the one being guarded.
  * the audit ring's newest row is 2026-11-04T19:33:05Z -- nothing has called this contract in 7
    days -- so the disabled window denies no real traffic.
GUARDS: testnet only, leash-*.testnet only, refuses if the live code_hash is not the deployed fix
(a probe against unknown code proves nothing), refuses if the agent is already disabled (then the
sequence has no clean restore point), dry run by default.
"""
import json, os, re, shutil, subprocess, sys, time, urllib.request

NEAR = os.environ.get("NEAR_CLI") or shutil.which("near") or "near"
RPC = "https://rpc.testnet.near.org"
CONTRACT = "leash-b0c503d6.testnet"
AGENT = "leash-agent-064e6c.testnet"
OWNER = "leash-owner-4c4054.testnet"
FIX_HASH = "59HB5memEzCQMXoWe6mD7KX3ysvYMZoVBHPXVyt4tr64"
CONTRACT_RX = re.compile(r"^leash-[a-z0-9]+\.testnet$")


def guard(rpc, contract, code_hash, enabled_now):
    """PURE: every refusal reachable by a test. None means the probe may proceed."""
    if "testnet" not in rpc or "mainnet" in rpc:
        return "REFUSED: rpc %r is not testnet." % rpc
    if not CONTRACT_RX.match(contract or ""):
        return "REFUSED: contract %r does not match leash-*.testnet." % contract
    if code_hash is None:
        return "UNMEASURED: could not read the live code_hash; refusing to probe unknown code."
    if code_hash != FIX_HASH:
        return ("REFUSED: live code_hash %s is not the deployed fix %s. A probe against code I did "
                "not verify proves nothing." % (code_hash, FIX_HASH))
    if enabled_now is None:
        return "UNMEASURED: could not read the live policy; refusing to mutate what I cannot see."
    if enabled_now is not True:
        return ("REFUSED: agent is already enabled=%r. The sequence needs a known-enabled start so "
                "the restore is unambiguous." % enabled_now)
    return None


def rpc_view(method, args):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "query", "params": {
        "request_type": "call_function", "finality": "final", "account_id": CONTRACT,
        "method_name": method, "args_base64": __import__("base64").b64encode(
            json.dumps(args).encode()).decode()}}).encode()
    req = urllib.request.Request(RPC, body, {"Content-Type": "application/json"})
    r = json.loads(urllib.request.urlopen(req, timeout=25).read())
    if "error" in r or "result" not in r:
        return None, None
    res = r["result"]
    return res.get("block_height"), json.loads(bytes(res["result"]).decode())


def code_hash():
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "query", "params": {
        "request_type": "view_account", "finality": "final", "account_id": CONTRACT}}).encode()
    req = urllib.request.Request(RPC, body, {"Content-Type": "application/json"})
    try:
        r = json.loads(urllib.request.urlopen(req, timeout=25).read())
        return r["result"]["code_hash"]
    except Exception:
        return None


ALLOWED_METHODS = ("set_agent_enabled", "set_agent_policy")


def call(method, args, label):
    """`method` is the ON-CHAIN method name, `label` is for humans. Passing a label here cost me a
    run on 2026-11-11: the transaction asked for a method named "set_agent_enabled false" and the
    chain answered MethodResolveError(MethodNotFound) -- correctly. The assert makes that typo a
    local crash before anything is signed, instead of a refused transaction that reads like a
    contract defect."""
    assert method in ALLOWED_METHODS, "not an on-chain method name: %r" % method
    p = subprocess.run([NEAR, "contract", "call-function", "as-transaction", CONTRACT,
                        method, "json-args", json.dumps(args),
                        "prepaid-gas", "100.0 Tgas", "attached-deposit", "0 NEAR",
                        "sign-as", OWNER, "network-config", "testnet",
                        "sign-with-legacy-keychain", "send"],
                       capture_output=True, text=True, timeout=180)
    print("  %-28s rc=%d" % (label, p.returncode))
    if p.returncode != 0:
        for l in (p.stdout + p.stderr).strip().splitlines()[-6:]:
            print("      ", l[:180])
    return p.returncode == 0


def enabled():
    _, pol = rpc_view("get_agent_policy", {"agent": AGENT})
    return (pol or {}).get("enabled"), pol


def selftest():
    arms = []

    def ok(name, cond):
        arms.append((name, bool(cond)))
    ok("a good testnet probe passes every guard (control)",
       guard(RPC, CONTRACT, FIX_HASH, True) is None)
    ok("a mainnet rpc is refused", "mainnet" in (guard("https://rpc.mainnet.near.org", CONTRACT, FIX_HASH, True) or "").lower() or "not testnet" in (guard("https://rpc.mainnet.near.org", CONTRACT, FIX_HASH, True) or ""))
    ok("a non-leash contract is refused",
       "does not match" in (guard(RPC, "other.testnet", FIX_HASH, True) or ""))
    ok("a leash MAINNET account is refused by the same pattern",
       "does not match" in (guard(RPC, "leash-b0c503d6.near", FIX_HASH, True) or ""))
    ok("code running the OLD build is refused",
       "not the deployed fix" in (guard(RPC, CONTRACT, "FksLFKoeD6Xco1D9omAQ2hrhczMwNjVnt27T2u89kkbt", True) or ""))
    ok("an unreadable code_hash is UNMEASURED, not treated as a match",
       (guard(RPC, CONTRACT, None, True) or "").startswith("UNMEASURED"))
    ok("an unreadable policy is UNMEASURED, not treated as enabled",
       (guard(RPC, CONTRACT, FIX_HASH, None) or "").startswith("UNMEASURED"))
    ok("an ALREADY-DISABLED agent is refused (no clean restore point)",
       "already enabled=False" in (guard(RPC, CONTRACT, FIX_HASH, False) or ""))
    for n, good in arms:
        print("  %s %s" % ("ok  " if good else "FAIL", n))
    bad = [n for n, g in arms if not g]
    print("PROBESELFTEST %s (%d arms)" % ("PASS" if not bad else "FAIL", len(arms)))
    return 1 if bad else 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    apply = "--apply" in sys.argv
    for a in sys.argv[1:]:
        if a not in ("--apply", "--selftest"):
            print("REFUSED: unknown flag %r" % a); return 2

    ch = code_hash()
    en, pol = enabled()
    print("CONTRACT   %s on %s" % (CONTRACT, RPC))
    print("code_hash  %s %s" % (ch, "(the deployed fix)" if ch == FIX_HASH else "(NOT the fix)"))
    print("agent      %s enabled=%r expires_at_ms=%s" % (AGENT, en, (pol or {}).get("expires_at_ms")))
    g = guard(RPC, CONTRACT, ch, en)
    if g:
        print("\n" + g); return 1

    carry = {"agent": AGENT, "per_tx_lamports": str(pol["per_tx_lamports"]),
             "window_lamports": str(pol["window_lamports"]),
             "allowed_recipients": list(pol["allowed_recipients"]),
             "expires_at_ms": str(pol["expires_at_ms"])}
    print("\nSEQUENCE  disable -> renew(SAME expiry %s) -> read -> restore enable"
          % carry["expires_at_ms"])
    print("  the renewal re-asserts every field it read, so nothing but `enabled` can move.")
    if not apply:
        print("\nDRY RUN. Nothing sent. Re-run with --apply.")
        return 0

    verdict, observed = "UNMEASURED", None
    try:
        if not call("set_agent_enabled", {"agent": AGENT, "enabled": False}, "1 disable"):
            print("\nABORT: the disable failed. Nothing else was sent."); return 1
        time.sleep(3)
        mid, _ = enabled()
        print("  %-28s enabled=%r" % ("   after disable", mid))
        if mid is not False:
            print("\nABORT: expected enabled=False after the disable, read %r." % mid)
            return 1
        if not call("set_agent_policy", carry, "2 renew"):
            print("\nABORT: the renewal failed."); return 1
        time.sleep(3)
        observed, after = enabled()
        print("  %-28s enabled=%r" % ("   after renewal", observed))
        if observed is False:
            verdict = "FIXED: the renewal CARRIED FORWARD the disable (WL-CL-020 closed on chain)"
        elif observed is True:
            verdict = "STILL BUGGY: the renewal CLOBBERED the disable back to enabled=true"
        for k in ("per_tx_lamports", "window_lamports", "expires_at_ms"):
            same = str((after or {}).get(k)) == str(pol[k])
            print("  %-28s %s" % ("   " + k, "UNCHANGED" if same else "MOVED -- investigate"))
    finally:
        print("\nRESTORE (runs on every exit path)")
        call("set_agent_enabled", {"agent": AGENT, "enabled": True}, "3 restore")
        time.sleep(3)
        fin, _ = enabled()
        print("  %-28s enabled=%r %s" % ("   final read", fin,
              "RESTORED" if fin is True else "*** NOT RESTORED -- enabled=%r ***" % fin))

    print("\nVERDICT: %s" % verdict)
    return 0 if observed is False else 1


if __name__ == "__main__":
    sys.exit(main())
