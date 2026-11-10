#!/usr/bin/env python3
"""Run the teletask action-v2 certification end to end, with Leash as the provider.

Three legs per task, all signed by the NEAR MPC on Leash's behalf and all CONSTRUCTED by the
contract from parameters:
  1 accept_task        (no lamports)
  2 transfer 0.01 SOL  (the money leg, under policy)
  3 submit_evidence + TTEV1 memo in one tx

Every signature is verified locally against Leash's derived key BEFORE broadcast. The message is
rebuilt here, in python, independently of the Rust that built the signed bytes: if the two
implementations disagree the verify fails and nothing is sent.
"""
import sys
if sys.version_info[:2] < (3, 8):
    sys.stderr.write(
        "WRONG INTERPRETER: the Leash harness requires python >= 3.8, got %d.%d.%d at %s.\n"
        "NOTHING RAN. Invoke an explicit interpreter, e.g. `python3.10 %s`.\n"
        % (sys.version_info[0], sys.version_info[1], sys.version_info[2],
           sys.executable, sys.argv[0]))
    sys.exit(3)
import base64, hashlib, json, os, re, subprocess, sys, time, urllib.request
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import solana_lib as S

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from state_io import rd
# Which Leash to drive. Defaults to the dev contract; the locked snapshot is selected by env so
# the same runner proves both without a second copy that could drift from this one.
# LEASH_CONTRACT / LEASH_ADDRESS env overrides are honored inside rd().
CONTRACT = rd(".contract-account")
LEASH = rd(".solana-address")
OWNER, AGENT = rd(".owner-account"), rd(".agent-account")
NEAR = os.path.expanduser("~/.local/bin/near")
DEVNET = "https://api.devnet.solana.com"
NEAR_RPCS = ["https://test.rpc.fastnear.com", "https://rpc.testnet.near.org"]
CONFIG = "5kZkCquZpfAfXo6QAMDbne6xg3y2QiVEGtrrFXtvhV9i"
BUYER = "DEvzHWdnsZmNCUwaZ3wcy4AWuLBNf18uUnRCwNawadEP"
TASKS = json.loads(os.environ["LEASH_TASKS"]) if os.environ.get("LEASH_TASKS") else [
    ("3fJ3B6tStGs3wnsbvvJXjRR5qcoyY4dPAj1sPKkvon47", 1793731600466,
     "6rgrQQA1v2XV16wLyshyzWTBfJ48L7MreieajorszBNP"),
    ("76wJNKq9dfS24Xh2Re9RCqoGCJxQcHFVXnS6PL4qPYzZ", 1793731600467,
     "6gwA3HDRACnmA7jG3DTaMjHtHs9RqEZk2C1oZgLsBtg7"),
]
LAMPORTS = int(os.environ.get("LEASH_LAMPORTS", 10_000_000))
# The policy is set by the owner out of band for the locked account; re-setting it here would
# rewrite the very thing under test.
SET_POLICY = os.environ.get("LEASH_SET_POLICY", "1") == "1"
SKIP_ACCEPT = os.environ.get("LEASH_SKIP_ACCEPT", "0") == "1"


def rpc(url, method, params, tries=3):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = ""
    for i in range(tries):
        try:
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except Exception as e:
            last = str(e); time.sleep(1.5 * (2 ** i))
    raise RuntimeError(f"rpc {method} failed: {last}")


def near_rpc(method, params):
    last = ""
    for url in NEAR_RPCS:
        try:
            return rpc(url, method, params, tries=2)
        except Exception as e:
            last = str(e)
    raise RuntimeError(last)


def blockhash():
    # 11-05 (Cleo): was "finalized", which hands back a hash already ~32 slots behind the tip and so
    # burns a fifth of the 150-slot validity window BEFORE the MPC round-trip (a NEAR call plus up to
    # 8x2s of signature polling) even starts. Task 2 of the action-leash-sol run lost that race with
    # BlockhashNotFound while task 1 won it -- one-sided luck, not method. "confirmed" is as near the
    # tip as is safe to sign over, which is what the signing delay actually needs.
    return rpc(DEVNET, "getLatestBlockhash", [{"commitment": "confirmed"}])["result"]["value"]["blockhash"]


def call(signer, method, args, deposit="1 yoctoNEAR", gas="300.0 Tgas"):
    p = subprocess.run(
        [NEAR, "contract", "call-function", "as-transaction", CONTRACT, method,
         "json-args", json.dumps(args), "prepaid-gas", gas, "attached-deposit", deposit,
         "sign-as", signer, "network-config", "testnet", "sign-with-legacy-keychain", "send"],
        capture_output=True, text=True, timeout=200)
    return re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))


def mpc_signature(near_tx):
    """Pull the Ed25519 signature out of the v1.signer receipt."""
    for _ in range(8):
        st = near_rpc("EXPERIMENTAL_tx_status", [near_tx, AGENT])
        for ro in st.get("result", {}).get("receipts_outcome", []):
            sv = ro["outcome"].get("status", {}).get("SuccessValue")
            if not sv:
                continue
            try:
                v = json.loads(base64.b64decode(sv).decode())
            except Exception:
                continue
            if isinstance(v, dict) and "signature" in v:
                return bytes(v["signature"])
        time.sleep(2)
    return None


def leg(name, method, args, build_msg):
    """One leg: ask Leash, take the signature, verify it locally, then broadcast."""
    print(f"    [{name}] requesting signature")
    out = call(AGENT, method, args)
    if "LEASH_REFUSED" in out:
        m = re.search(r"LEASH_REFUSED[^\"\\]*", out)
        print(f"      REFUSED: {m.group(0) if m else 'unknown'}")
        return None
    tx = re.search(r"Transaction ID: ([A-Za-z0-9]+)", out)
    if not tx:
        print("      no NEAR tx id:", re.sub(r"\s+", " ", out)[-200:]); return None
    sig = mpc_signature(tx.group(1))
    if not sig:
        print("      MPC returned no signature"); return None

    msg = build_msg()
    try:
        VerifyKey(S.b58decode(LEASH)).verify(msg, sig)
    except BadSignatureError:
        print("      LOCAL VERIFY FAILED -- rust and python disagree; NOT broadcasting")
        return None
    print(f"      signature valid over {len(msg)} bytes; broadcasting")

    raw = base64.b64encode(S.build_signed_tx(sig, msg)).decode()
    res = rpc(DEVNET, "sendTransaction",
              [raw, {"encoding": "base64", "preflightCommitment": "processed"}])
    if "error" in res:
        print("      devnet rejected:", json.dumps(res["error"])[:300]); return None
    sol_sig = res["result"]
    for i in range(30):
        time.sleep(2)
        v = rpc(DEVNET, "getSignatureStatuses", [[sol_sig], {"searchTransactionHistory": True}])["result"]["value"][0]
        if v:
            if v.get("err"):
                print(f"      FAILED on chain: {v['err']}"); return None
            if v.get("confirmationStatus") in ("confirmed", "finalized"):
                print(f"      {v['confirmationStatus']}: {sol_sig[:28]}...")
                return sol_sig
    print("      not confirmed in 60s"); return None


def run_task(idx, escrow, task_id, fixture):
    print(f"\n=== TASK {idx}/2  escrow {escrow[:12]}...  fixture {fixture[:12]}...")
    if not SET_POLICY:
        print("    policy: left as configured (not rewritten by the runner)")
        return run_legs(escrow, task_id, fixture)
    future = int((time.time() + 7 * 86400) * 1000)
    call(OWNER, "set_agent_policy",
         {"agent": AGENT, "per_tx_lamports": str(LAMPORTS), "window_lamports": str(LAMPORTS * 4),
          "allowed_recipients": [fixture], "expires_at_ms": str(future)}, deposit="0 NEAR")
    call(OWNER, "reset_agent_window", {"agent": AGENT}, deposit="0 NEAR")
    print(f"    policy: per-tx {LAMPORTS}, payee {fixture[:12]}..., expires in 7d")
    return run_legs(escrow, task_id, fixture)


def run_legs(escrow, task_id, fixture):
    prov, esc, buy, cfg, fix = (S.b58decode(x) for x in (LEASH, escrow, BUYER, CONFIG, fixture))

    bh = blockhash()
    # 11-05 (Cleo): an accept leg that already landed must not be re-sent -- the program refuses the
    # second accept and the task would abort before the transfer it still owes.
    if SKIP_ACCEPT:
        print("    [1 accept_task] SKIPPED (already landed; LEASH_SKIP_ACCEPT=1)")
    elif not leg("1 accept_task", "request_accept_task",
               {"task_escrow": escrow, "buyer": BUYER, "config": CONFIG,
                "task_id": str(task_id), "layer": 0, "recent_blockhash": bh},
               lambda: S.build_accept_task_message(prov, esc, buy, cfg, task_id, 0, S.b58decode(bh))):
        return False

    bh = blockhash()
    xfer = leg("2 transfer 0.01 SOL", "request_transfer",
               {"recipient": fixture, "lamports": str(LAMPORTS), "recent_blockhash": bh},
               lambda: S.build_transfer_message(prov, fix, LAMPORTS, S.b58decode(bh)))
    if not xfer:
        return False

    ev = json.dumps({"signature": xfer, "text": f"Sent 0.01 SOL to {fixture}."},
                    separators=(",", ":"))
    ev_hash = hashlib.sha256(ev.encode()).digest()
    print(f"    evidence: {ev[:64]}...")
    bh = blockhash()
    if not leg("3 submit_evidence+memo", "request_submit_evidence",
               {"task_escrow": escrow, "buyer": BUYER, "task_id": str(task_id),
                "ev": ev, "recent_blockhash": bh},
               lambda: S.build_submit_evidence_message(prov, esc, buy, task_id, ev, ev_hash,
                                                       S.b58decode(bh))):
        return False
    return True


def main():
    print("=" * 78)
    print("TELETASK ACTION-V2 CERTIFICATION -- Leash as provider")
    print("provider:", LEASH)
    print("=" * 78)
    bal = rpc(DEVNET, "getBalance", [LEASH])["result"]["value"]
    print(f"Leash balance: {bal/1e9:.9f} SOL")
    results = [run_task(i + 1, *t) for i, t in enumerate(TASKS)]
    print("\n" + "=" * 78)
    for i, ok in enumerate(results, 1):
        print(f"  task {i}/2: {'COMPLETE' if ok else 'INCOMPLETE'}")
    after = rpc(DEVNET, "getBalance", [LEASH])["result"]["value"]
    print(f"Leash balance: {bal/1e9:.9f} -> {after/1e9:.9f} SOL  ({(after-bal)/1e9:+.9f})")
    print("=" * 78)
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
