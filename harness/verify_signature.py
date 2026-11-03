#!/usr/bin/env python3.10
"""Verify that the signature Leash obtained is a VALID Ed25519 signature by Leash's own
derived Solana address, over the exact message the contract constructed.

This is the claim that matters. "The MPC returned 64 bytes" proves nothing on its own: bytes
come back whether or not they mean anything. The signature must verify against the public key
that was derived for (contract account, path) -- and it must FAIL against a tampered message,
or the verification itself is vacuous.
"""
import sys
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw

def shortvec(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n == 0:
            out.append(b); break
        out.append(b | 0x80)
    return bytes(out)

def build_transfer_message(frm, to, lamports, blockhash):
    """Mirrors contract/src/solana.rs::build_transfer_message, re-implemented INDEPENDENTLY in a
    different language. If the two disagree the signature will not verify, which is the point."""
    m = bytearray()
    m += bytes([1, 0, 1])                      # header
    m += shortvec(3) + frm + to + b"\x00" * 32 # account keys: from, to, system program
    m += blockhash
    m += shortvec(1) + bytes([2]) + shortvec(2) + bytes([0, 1])
    data = (2).to_bytes(4, "little") + lamports.to_bytes(8, "little")
    m += shortvec(len(data)) + data
    return bytes(m)

LEASH_ADDR = "Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL"
RECIPIENT  = "7FDz21w5Rf63GDmGtQXc2Dp7SnkM2rcUq6fUtjT7rbSC"
BLOCKHASH  = "FsDtFGQd9Ap4iqWJvj2NYYDMd31s8KLgPm2rn4uumGCK"
LAMPORTS   = 1_000_000
SIG = bytes([169,230,69,114,33,71,40,76,78,5,77,36,129,121,61,198,35,132,115,73,245,206,113,17,
             154,229,120,70,65,197,103,239,138,241,86,238,158,148,97,153,171,189,28,191,117,55,
             153,219,112,27,188,51,42,128,156,240,5,123,9,30,197,212,72,10])

def verify(pub, msg, sig):
    try:
        VerifyKey(pub).verify(msg, sig); return True
    except BadSignatureError:
        return False

def main():
    pub = b58decode(LEASH_ADDR)
    msg = build_transfer_message(b58decode(LEASH_ADDR), b58decode(RECIPIENT), LAMPORTS, b58decode(BLOCKHASH))
    print("Leash address :", LEASH_ADDR)
    print("message       :", len(msg), "bytes")
    print("signature     :", len(SIG), "bytes")
    print()

    results = []

    ok = verify(pub, msg, SIG)
    print("[POSITIVE] signature verifies against Leash's derived key over the exact message")
    print("           ->", "VALID" if ok else "INVALID")
    results.append(("signature is valid for Leash's key + exact message", ok))

    # --- negative controls: a verifier that cannot fail is not a verifier -------------------
    tampered = build_transfer_message(b58decode(LEASH_ADDR), b58decode(RECIPIENT), LAMPORTS + 1,
                                      b58decode(BLOCKHASH))
    bad = verify(pub, tampered, SIG)
    print("[NEGATIVE] same signature against a message with the amount changed by 1 lamport")
    print("           ->", "INVALID (correct)" if not bad else "VALID (BROKEN)")
    results.append(("tampered amount is rejected", not bad))

    other = build_transfer_message(b58decode(LEASH_ADDR), b58decode(LEASH_ADDR), LAMPORTS,
                                   b58decode(BLOCKHASH))
    bad2 = verify(pub, other, SIG)
    print("[NEGATIVE] same signature against a message with a different recipient")
    print("           ->", "INVALID (correct)" if not bad2 else "VALID (BROKEN)")
    results.append(("tampered recipient is rejected", not bad2))

    wrongkey = b58decode(RECIPIENT)   # a different, valid 32-byte key
    bad3 = verify(wrongkey, msg, SIG)
    print("[NEGATIVE] correct message, but verified against a DIFFERENT public key")
    print("           ->", "INVALID (correct)" if not bad3 else "VALID (BROKEN)")
    results.append(("wrong public key is rejected", not bad3))

    print()
    passed = sum(1 for _, ok in results if ok)
    for n, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {n}")
    print(f"\n{passed}/{len(results)}", "- PROVEN" if passed == len(results) else "- NOT PROVEN")
    return 0 if passed == len(results) else 1

if __name__ == "__main__":
    sys.exit(main())
