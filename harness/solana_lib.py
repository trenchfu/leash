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


# --- teletask task-escrow legs, mirroring contract/src/solana.rs INDEPENDENTLY ---------------
ESCROW_PROGRAM = "B7G2vXXJo1YtoiNnahWdMFHKKn51GsiKi2Miirj9DB9T"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
DISC_ACCEPT = bytes([222, 196, 79, 165, 120, 30, 38, 120])
DISC_SUBMIT = bytes([12, 169, 228, 194, 229, 31, 44, 39])


def _message(keys, nsig, nro_signed, nro_unsigned, blockhash, ixs):
    m = bytearray([nsig, nro_signed, nro_unsigned])
    m += shortvec(len(keys))
    for k in keys:
        m += k
    m += blockhash
    m += shortvec(len(ixs))
    for prog_idx, accts, data in ixs:
        m += bytes([prog_idx]) + shortvec(len(accts)) + bytes(accts) + shortvec(len(data)) + data
    return bytes(m)


def build_accept_task_message(provider, task_escrow, buyer, config, task_id, layer, blockhash):
    keys = [provider, task_escrow, buyer, config, b58decode(ESCROW_PROGRAM)]
    data = DISC_ACCEPT + task_id.to_bytes(8, "little") + layer.to_bytes(2, "little")
    return _message(keys, 1, 0, 3, blockhash, [(4, [2, 1, 0, 3], data)])


def build_submit_evidence_message(provider, task_escrow, buyer, task_id, ev, ev_hash, blockhash):
    keys = [provider, task_escrow, buyer, b58decode(ESCROW_PROGRAM), b58decode(MEMO_PROGRAM)]
    submit = DISC_SUBMIT + task_id.to_bytes(8, "little") + ev_hash
    memo = b"TTEV1|" + ev.encode()
    return _message(keys, 1, 0, 3, blockhash,
                    [(3, [2, 1, 0], submit), (4, [], memo)])
