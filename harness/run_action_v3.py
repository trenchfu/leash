#!/usr/bin/env python3
"""teletask action-v3: Leash as provider across BOTH asset kinds, plus the SPL over-cap control.

Per task: accept_task (value-free) -> transfer (SOL or SPL) -> submit_evidence + memo.

Shared legs, signing and verification are imported from run_action_v2 rather than copied. The
only new thing here is a transfer leg that branches on asset kind, so a divergence between the
two runners cannot appear in the parts that were already proven.

SET_POLICY defaults to 0 here, unlike v2. v2 rewrote the agent policy and reset the window per
task; doing that would mean the suite grades a policy MY RUNNER wrote seconds earlier instead of
the one the counterparty pinned and read. The policy under test must be the policy she pinned.
"""
import hashlib, json, os, struct, sys, time, urllib.request

import run_action_v2 as V
import solana_lib as S

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
DEVNET = V.DEVNET

# task_id lives at offset 136 of the escrow account. NOT given to me; read off chain and
# identified by PATTERN across all three escrows (three distinct ms values clustered at the
# posting time, the first two consecutive) rather than from one account, where offset 296 also
# looked plausible and is noise. If an id is wrong the escrow PDA will not match and accept_task
# fails on chain, so this is a guess the first leg immediately checks.
def task_id_of(escrow):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
                       "params": [escrow, {"encoding": "base64"}]}).encode()
    req = urllib.request.Request(DEVNET, body, {"Content-Type": "application/json"})
    import base64
    d = base64.b64decode(json.loads(urllib.request.urlopen(req, timeout=30).read())
                         ["result"]["value"]["data"][0])
    return struct.unpack_from("<Q", d, 136)[0]


TASKS = json.loads(os.environ["V3_TASKS"])
MINT = os.environ["SPL_MINT"]
SRC = os.environ["SPL_SRC"]
DECIMALS = int(os.environ.get("SPL_DECIMALS", "6"))


def transfer_leg(kind, fixture, amount, bh):
    prov = S.b58decode(V.LEASH)
    if kind == "sol":
        return V.leg(f"2 transfer {amount} lamports", "request_transfer",
                     {"recipient": fixture, "lamports": str(amount), "recent_blockhash": bh},
                     lambda: S.build_transfer_message(prov, S.b58decode(fixture), amount,
                                                      S.b58decode(bh)))
    return V.leg(f"2 transferChecked {amount} base units", "request_spl_transfer",
                 {"mint": MINT, "destination": fixture, "amount": str(amount),
                  "decimals": DECIMALS, "recent_blockhash": bh},
                 lambda: S.build_transfer_checked_message(
                     prov, S.b58decode(SRC), S.b58decode(fixture), S.b58decode(MINT),
                     S.b58decode(TOKEN_PROGRAM), amount, DECIMALS, S.b58decode(bh)))


def run(idx, n, escrow, fixture, kind, amount, expect):
    tid = task_id_of(escrow)
    print(f"\n=== TASK {idx}/{n}  {kind.upper()}  escrow {escrow[:12]}...  "
          f"task_id {tid}  expect {expect}")
    prov, esc, buy, cfg = (S.b58decode(x) for x in (V.LEASH, escrow, V.BUYER, V.CONFIG))

    bh = V.blockhash()
    if not V.leg("1 accept_task", "request_accept_task",
                 {"task_escrow": escrow, "buyer": V.BUYER, "config": V.CONFIG,
                  "task_id": str(tid), "layer": 0, "recent_blockhash": bh},
                 lambda: S.build_accept_task_message(prov, esc, buy, cfg, tid, 0,
                                                     S.b58decode(bh))):
        print("    accept_task failed -> task_id or escrow wrong, or the gate refused")
        return expect == "miss"

    bh = V.blockhash()
    xfer = transfer_leg(kind, fixture, amount, bh)
    if not xfer:
        # For the control this IS the pass condition: the refusal must be ATTEMPTED and observed.
        # A control arm that is simply not run proves nothing about the cap.
        print(f"    transfer did not land -> {'EXPECTED for the control' if expect == 'miss' else 'TASK FAILS'}")
        return expect == "miss"

    if expect == "miss":
        print("    *** CONTROL LANDED A TRANSFER. The cap did not hold. ***")
        return False

    unit = "lamports" if kind == "sol" else f"base units of {MINT}"
    ev = json.dumps({"signature": xfer, "text": f"Sent {amount} {unit} to {fixture}."},
                    separators=(",", ":"))
    ev_hash = hashlib.sha256(ev.encode()).digest()
    bh = V.blockhash()
    if not V.leg("3 submit_evidence+memo", "request_submit_evidence",
                 {"task_escrow": escrow, "buyer": V.BUYER, "task_id": str(tid),
                  "ev": ev, "recent_blockhash": bh},
                 lambda: S.build_submit_evidence_message(prov, esc, buy, tid, ev, ev_hash,
                                                         S.b58decode(bh))):
        return False
    return True


def main():
    print("=" * 78)
    print("TELETASK ACTION-V3 -- Leash as provider, SOL + SPL, with the over-cap control")
    print("=" * 78)
    print(f"  provider {V.LEASH}")
    print(f"  mint     {MINT}  source {SRC}")
    ok = []
    for i, t in enumerate(TASKS):
        ok.append(run(i + 1, len(TASKS), t["escrow"], t["fixture"], t["kind"],
                      int(t["amount"]), t["expect"]))
    print("\n" + "=" * 78)
    for t, r in zip(TASKS, ok):
        print(f"  {t['kind']:3} {t['escrow'][:12]}... expect {t['expect']:5} -> "
              f"{'OK' if r else 'NOT OK'}")
    print("  ALL ARMS AS EXPECTED" if all(ok) else "  AT LEAST ONE ARM DID NOT MATCH")
    print("=" * 78)
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main())
