#!/usr/bin/env python3.10
"""End to end: an agent asks Leash for a transfer, Leash checks policy, the NEAR MPC signs, and
the transaction LANDS on Solana devnet.

Everything before this proved a signature was valid. Valid is not landed: a signature over a stale
blockhash, a malformed wire envelope, or an underfunded account all produce a perfectly valid
signature that moves nothing. This script closes that gap and measures the balances on both sides.
"""
import base64, json, os, re, subprocess, sys, time, urllib.request
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from solana_lib import b58decode, b58encode, build_transfer_message, build_signed_tx

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
rd = lambda n: open(os.path.join(ROOT, n)).read().strip()

CONTRACT, AGENT = rd(".contract-account"), rd(".agent-account")
LEASH_ADDR, RECIPIENT = rd(".solana-address"), rd(".allowed-recipient")
NEAR = os.path.expanduser("~/.local/bin/near")
DEVNET = "https://api.devnet.solana.com"
NEAR_RPC = "https://rpc.testnet.near.org"
LAMPORTS = 1_000_000


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def balance(addr):
    return rpc(DEVNET, "getBalance", [addr])["result"]["value"]


def main():
    print("=" * 78)
    print("LEASH END-TO-END: policy -> MPC signature -> landed Solana devnet transfer")
    print("=" * 78)
    before_from, before_to = balance(LEASH_ADDR), balance(RECIPIENT)
    print(f"  Leash  {LEASH_ADDR}  {before_from/1e9:.9f} SOL")
    print(f"  payee  {RECIPIENT}  {before_to/1e9:.9f} SOL")

    bh = rpc(DEVNET, "getLatestBlockhash", [{"commitment": "finalized"}])["result"]["value"]["blockhash"]
    print(f"\n  blockhash {bh}")

    print(f"\n[1] agent asks Leash for {LAMPORTS} lamports -> payee")
    t0 = time.time()
    p = subprocess.run(
        [NEAR, "contract", "call-function", "as-transaction", CONTRACT, "request_transfer",
         "json-args", json.dumps({"recipient": RECIPIENT, "lamports": str(LAMPORTS),
                                  "recent_blockhash": bh}),
         "prepaid-gas", "300.0 Tgas", "attached-deposit", "1 yoctoNEAR",
         "sign-as", AGENT, "network-config", "testnet",
         "sign-with-legacy-keychain", "send"],
        capture_output=True, text=True, timeout=180)
    out = re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
    if "LEASH_REFUSED" in out:
        print("    REFUSED by policy:", re.search(r"LEASH_REFUSED[^\"\\\\]*", out).group(0))
        return 1
    tx = re.search(r"Transaction ID: ([A-Za-z0-9]+)", out)
    if not tx:
        print("    no NEAR tx id; output tail:", out[-400:]); return 1
    print(f"    NEAR tx {tx.group(1)}  ({time.time()-t0:.1f}s)")

    print("\n[2] extract the MPC signature from the receipt")
    sig = None
    for _ in range(6):
        st = rpc(NEAR_RPC, "EXPERIMENTAL_tx_status", [tx.group(1), AGENT])
        for ro in st.get("result", {}).get("receipts_outcome", []):
            sv = ro["outcome"].get("status", {}).get("SuccessValue")
            if not sv:
                continue
            try:
                v = json.loads(base64.b64decode(sv).decode())
            except Exception:
                continue
            if isinstance(v, dict) and "signature" in v:
                sig = bytes(v["signature"]); scheme = v.get("scheme")
        if sig:
            break
        time.sleep(2)
    if not sig:
        print("    no signature in receipts -> MPC call did not return one"); return 1
    print(f"    {scheme} signature, {len(sig)} bytes")

    print("\n[3] verify locally BEFORE submitting (never broadcast bytes you have not checked)")
    msg = build_transfer_message(b58decode(LEASH_ADDR), b58decode(RECIPIENT), LAMPORTS, b58decode(bh))
    try:
        VerifyKey(b58decode(LEASH_ADDR)).verify(msg, sig); print("    VALID for Leash's key")
    except BadSignatureError:
        print("    INVALID -- refusing to submit"); return 1

    print("\n[4] submit to Solana devnet")
    raw = base64.b64encode(build_signed_tx(sig, msg)).decode()
    res = rpc(DEVNET, "sendTransaction", [raw, {"encoding": "base64", "preflightCommitment": "processed"}])
    if "error" in res:
        print("    rejected:", json.dumps(res["error"])[:400]); return 1
    sol_sig = res["result"]
    print(f"    submitted: {sol_sig}")
    print(f"    https://explorer.solana.com/tx/{sol_sig}?cluster=devnet")

    print("\n[5] confirm")
    for i in range(30):
        time.sleep(2)
        st = rpc(DEVNET, "getSignatureStatuses", [[sol_sig], {"searchTransactionHistory": True}])
        v = st["result"]["value"][0]
        if v:
            if v.get("err"):
                print("    FAILED on chain:", v["err"]); return 1
            if v.get("confirmationStatus") in ("confirmed", "finalized"):
                print(f"    {v['confirmationStatus']} after {(i+1)*2}s"); break
    else:
        print("    not confirmed in 60s"); return 1

    after_from, after_to = balance(LEASH_ADDR), balance(RECIPIENT)
    print("\n" + "=" * 78)
    print(f"  Leash  {before_from/1e9:.9f} -> {after_from/1e9:.9f} SOL  (delta {(after_from-before_from)/1e9:+.9f})")
    print(f"  payee  {before_to/1e9:.9f} -> {after_to/1e9:.9f} SOL  (delta {(after_to-before_to)/1e9:+.9f})")
    moved = after_to - before_to == LAMPORTS
    print(f"\n  payee received exactly {LAMPORTS} lamports: {moved}")
    print("  " + ("LANDED UNDER POLICY" if moved else "DID NOT LAND AS EXPECTED"))
    print("=" * 78)
    return 0 if moved else 1


if __name__ == "__main__":
    sys.exit(main())
