"""Solana wire helpers for the Leash harness.

This mirrors contract/src/solana.rs INDEPENDENTLY, in a different language. That duplication is
deliberate: if the Rust and this disagree, the signature will not verify and the transfer will not
land. Two implementations agreeing is evidence; one implementation agreeing with itself is not.
"""
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def shortvec(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n == 0:
            out.append(b)
            break
        out.append(b | 0x80)
    return bytes(out)


def build_transfer_message(frm: bytes, to: bytes, lamports: int, blockhash: bytes) -> bytes:
    m = bytearray()
    m += bytes([1, 0, 1])
    m += shortvec(3) + frm + to + b"\x00" * 32
    m += blockhash
    m += shortvec(1) + bytes([2]) + shortvec(2) + bytes([0, 1])
    data = (2).to_bytes(4, "little") + lamports.to_bytes(8, "little")
    m += shortvec(len(data)) + data
    return bytes(m)


def build_signed_tx(signature: bytes, message: bytes) -> bytes:
    """A Solana wire transaction is shortvec(num_sigs) || signatures || message."""
    assert len(signature) == 64, f"signature must be 64 bytes, got {len(signature)}"
    return shortvec(1) + signature + message
