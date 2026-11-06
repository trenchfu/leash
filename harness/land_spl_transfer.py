#!/usr/bin/env python3
"""Land a real SPL TransferChecked: Leash policy -> MPC signature -> confirmed devnet transfer.

Two deliberate choices about how this is checked:

  * The message is rebuilt HERE, independently of the Rust contract, and the contract's signature
    is verified against the Python message BEFORE anything is broadcast. If the two
    implementations disagree about a single byte, the signature fails to verify and nothing is
    submitted — instead of a transfer landing against accounts nobody intended.

  * Success is measured from the TRANSACTION's own pre/post token balances, never from an account
    balance read before and after. An account-level delta over a window assumes you were the only
    writer, and that assumption has already cost me one wrong finding that got cited upstream.
    preTokenBalances/postTokenBalances are per-transaction facts and survive concurrency.
"""
import sys
if sys.version_info[:2] < (3, 8):
    sys.stderr.write(
        "WRONG INTERPRETER: the Leash harness requires python >= 3.8, got %d.%d.%d at %s.\n"
        "NOTHING RAN. Invoke an explicit interpreter, e.g. `python3.10 %s`.\n"
        % (sys.version_info[0], sys.version_info[1], sys.version_info[2],
           sys.executable, sys.argv[0]))
    sys.exit(3)
import base64, json, os, re, subprocess, sys, time, urllib.request

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from solana_lib import b58decode, build_signed_tx, build_transfer_checked_message

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
rd = lambda n: open(os.path.join(ROOT, n)).read().strip()

CONTRACT, AGENT = rd(".contract-account"), rd(".agent-account")
LEASH_ADDR = rd(".solana-address")
NEAR = os.path.expanduser("~/.local/bin/near")
DEVNET = "https://api.devnet.solana.com"
NEAR_RPC = "https://rpc.testnet.near.org"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

MINT = os.environ["SPL_MINT"]
SRC = os.environ["SPL_SRC"]
DST = os.environ["SPL_DST"]
AMOUNT = int(os.environ.get("SPL_AMOUNT", "1000000"))
DECIMALS = int(os.environ.get("SPL_DECIMALS", "6"))
# When set, sign as the agent with THIS key file and nothing else. Naming the file is what makes
# the run attributable: a keychain holding several keys for one account can silently pick the
# full-access one, which is how a scoped-key test ends up proving nothing about scoping.
KEY_FILE = os.environ.get("LEASH_KEY_FILE", "")


def rpc(url, method, params):
    req = urllib.request.Request(
        url,
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=40).read())


def tok(addr):
    r = rpc(DEVNET, "getTokenAccountBalance", [addr])
    return int(r["result"]["value"]["amount"])


def main():
    print("=" * 78)
    print("LEASH SPL: policy -> MPC signature -> LANDED devnet TransferChecked")
    print("=" * 78)
    print(f"  mint   {MINT}  decimals {DECIMALS}")
    print(f"  source {SRC}  (owned by the Leash address)")
    print(f"  dest   {DST}")
    print(f"  amount {AMOUNT} base units")
    print(f"  pre:  source {tok(SRC)}  dest {tok(DST)}")

    bh = rpc(DEVNET, "getLatestBlockhash", [{"commitment": "finalized"}])["result"]["value"]["blockhash"]

    print(f"\n[1] agent asks Leash to transfer {AMOUNT} base units")
    p = subprocess.run(
        [NEAR, "contract", "call-function", "as-transaction", CONTRACT, "request_spl_transfer",
         "json-args", json.dumps({"mint": MINT, "destination": DST, "amount": str(AMOUNT),
                                  "decimals": DECIMALS, "recent_blockhash": bh}),
         "prepaid-gas", "300.0 Tgas",
         # A FUNCTION-CALL ACCESS KEY CANNOT ATTACH A DEPOSIT. The NEAR runtime refuses
         # "a deposit with a function call action" outright, so the agent path must be
         # deposit-free. Earlier landings attached 1 yoctoNEAR and therefore only worked
         # because they signed with the agent's FULL-ACCESS key -- they proved the contract
         # policy but not the constrained-agent path. The MPC's own 1-yoctoNEAR deposit comes
         # out of the CONTRACT's balance, not the caller's, so zero here changes nothing
         # downstream.
         "attached-deposit", "0 NEAR",
         "sign-as", AGENT, "network-config", "testnet"]
        + (["sign-with-access-key-file", KEY_FILE] if KEY_FILE
           else ["sign-with-legacy-keychain"]) + ["send"],
        capture_output=True, text=True, timeout=240)
    out = re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
    if "LEASH_REFUSED" in out:
        print("    REFUSED by policy:", re.search(r"LEASH_REFUSED[^\"\\]*", out).group(0))
        return 1
    m = re.search(r"Transaction ID: ([A-Za-z0-9]+)", out)
    if not m:
        print("    no NEAR tx id; tail:", out[-500:])
        return 1
    print(f"    NEAR tx {m.group(1)}")

    print("\n[2] extract the MPC signature from the receipts")
    sig = scheme = None
    for _ in range(8):
        st = rpc(NEAR_RPC, "EXPERIMENTAL_tx_status", [m.group(1), AGENT])
        for ro in st.get("result", {}).get("receipts_outcome", []):
            sv = ro["outcome"].get("status", {}).get("SuccessValue")
            if not sv:
                continue
            try:
                v = json.loads(base64.b64decode(sv).decode())
            except Exception:
                continue
            if isinstance(v, dict) and "signature" in v:
                sig, scheme = bytes(v["signature"]), v.get("scheme")
        if sig:
            break
        time.sleep(2)
    if not sig:
        print("    no signature in receipts")
        return 1
    print(f"    {scheme}, {len(sig)} bytes")

    print("\n[3] rebuild the message INDEPENDENTLY and verify before broadcasting")
    msg = build_transfer_checked_message(
        b58decode(LEASH_ADDR), b58decode(SRC), b58decode(DST),
        b58decode(MINT), b58decode(TOKEN_PROGRAM), AMOUNT, DECIMALS, b58decode(bh),
    )
    print(f"    python-built message: {len(msg)} bytes")
    try:
        VerifyKey(b58decode(LEASH_ADDR)).verify(msg, sig)
        print("    VALID for the Leash key -> the contract signed the SAME bytes this harness built")
    except BadSignatureError:
        print("    INVALID: the contract signed different bytes than this harness built.")
        print("    NOT submitting. Two independent implementations disagree; that is the finding.")
        return 1

    print("\n[4] submit")
    tx = base64.b64encode(build_signed_tx(sig, msg)).decode()
    r = rpc(DEVNET, "sendTransaction", [tx, {"encoding": "base64", "preflightCommitment": "processed"}])
    if "error" in r:
        print("    rejected:", json.dumps(r["error"])[:400])
        return 1
    sol_tx = r["result"]
    print(f"    {sol_tx}")
    print(f"    https://explorer.solana.com/tx/{sol_tx}?cluster=devnet")

    print("\n[5] confirm, then measure THE TRANSACTION, not the accounts")
    got = None
    for _ in range(20):
        g = rpc(DEVNET, "getTransaction",
                [sol_tx, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0,
                          "commitment": "confirmed"}])
        if g.get("result"):
            got = g["result"]
            break
        time.sleep(2)
    if not got:
        print("    not confirmed in time")
        return 1
    if got["meta"].get("err"):
        print("    ON-CHAIN ERROR:", json.dumps(got["meta"]["err"]))
        for l in got["meta"].get("logMessages", [])[:8]:
            print("      ", l)
        return 1

    pre = {b["accountIndex"]: b for b in got["meta"]["preTokenBalances"]}
    post = {b["accountIndex"]: b for b in got["meta"]["postTokenBalances"]}
    print("    per-transaction token balance deltas:")
    moved = {}
    for i in sorted(set(pre) | set(post)):
        a = pre.get(i, {}).get("uiTokenAmount", {}).get("amount", "0")
        b = post.get(i, {}).get("uiTokenAmount", {}).get("amount", "0")
        owner = (post.get(i) or pre.get(i)).get("owner", "?")
        mint = (post.get(i) or pre.get(i)).get("mint", "?")
        d = int(b) - int(a)
        moved[owner] = d
        print(f"      idx {i} owner {owner} mint {mint[:8]}..  {a} -> {b}  (delta {d:+d})")

    print()
    print("=" * 78)
    src_owner, dst_owner = LEASH_ADDR, None
    for o, d in moved.items():
        if d > 0:
            dst_owner = o
    ok = moved.get(src_owner) == -AMOUNT and dst_owner is not None and moved[dst_owner] == AMOUNT
    print(f"  source fell by exactly {AMOUNT}: {moved.get(src_owner) == -AMOUNT}")
    print(f"  destination rose by exactly {AMOUNT}: {dst_owner is not None and moved[dst_owner] == AMOUNT}")
    print(f"  fee paid by the Leash address: {got['meta']['fee']} lamports")
    print("  SPL TRANSFER LANDED UNDER POLICY" if ok else "  DELTAS DO NOT MATCH THE REQUEST")
    print("=" * 78)
    return 0 if ok else 1


sys.exit(main())
