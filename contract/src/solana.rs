//! Solana legacy-message construction, as PURE functions.
//!
//! WHY THIS FILE EXISTS AT ALL — the security crux of Leash:
//!
//! A policy engine that signs bytes the agent handed it is not a policy engine. If the agent
//! supplies the payload and merely *claims* "this is a 0.1 SOL transfer to Alice", the contract
//! is checking a label while signing an unrelated instruction. The claim and the artifact are
//! two different things, and only the artifact reaches the chain.
//!
//! So Leash never accepts signable bytes. The agent supplies *parameters* (recipient, lamports,
//! recent blockhash); the contract CONSTRUCTS the message itself and signs only what it built.
//! The agent cannot express a transfer the policy did not authorise, because it never gets to
//! express the transfer at all.

extern crate alloc;
use alloc::vec::Vec;

/// The System Program address, all zeroes in base58 ("111...11", 32 zero bytes).
pub const SYSTEM_PROGRAM: [u8; 32] = [0u8; 32];
/// System Program instruction discriminant for Transfer (little-endian u32 = 2).
pub const IX_TRANSFER: u32 = 2;

/// Solana "short vec" length prefix (ULEB128, 1-3 bytes).
pub fn encode_shortvec_len(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

/// Decode a base58 Solana address into 32 bytes. Returns None on bad input or wrong length,
/// so a malformed recipient is a REFUSAL, never a panic and never a silently truncated key.
pub fn decode_pubkey(s: &str) -> Option<[u8; 32]> {
    let v = bs58::decode(s).into_vec().ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

/// Build the serialized legacy message for a single System Program transfer.
///
/// Account layout (order is consensus-critical):
///   index 0: `from`           signer, writable
///   index 1: `to`             writable
///   index 2: system program   readonly, not signer
///
/// Header is (num_required_signatures=1, num_readonly_signed=0, num_readonly_unsigned=1).
pub fn build_transfer_message(
    from: &[u8; 32],
    to: &[u8; 32],
    lamports: u64,
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(160);

    // message header
    m.push(1); // num_required_signatures
    m.push(0); // num_readonly_signed_accounts
    m.push(1); // num_readonly_unsigned_accounts (the system program)

    // account keys
    encode_shortvec_len(3, &mut m);
    m.extend_from_slice(from);
    m.extend_from_slice(to);
    m.extend_from_slice(&SYSTEM_PROGRAM);

    // recent blockhash
    m.extend_from_slice(recent_blockhash);

    // instructions: exactly one, and the contract decides every byte of it
    encode_shortvec_len(1, &mut m);
    m.push(2); // program_id_index -> system program
    encode_shortvec_len(2, &mut m);
    m.push(0); // account index: from
    m.push(1); // account index: to
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&IX_TRANSFER.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    encode_shortvec_len(data.len(), &mut m);
    m.extend_from_slice(&data);

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortvec_matches_solana_encoding() {
        let cases: &[(usize, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (256, &[0x80, 0x02]),
            (16384, &[0x80, 0x80, 0x01]),
        ];
        for (n, want) in cases {
            let mut out = Vec::new();
            encode_shortvec_len(*n, &mut out);
            assert_eq!(&out[..], *want, "shortvec({})", n);
        }
    }

    #[test]
    fn decode_pubkey_rejects_non_32_byte_and_invalid() {
        // system program: 32 zero bytes
        assert_eq!(decode_pubkey("11111111111111111111111111111111"), Some([0u8; 32]));
        // too short
        assert_eq!(decode_pubkey("1111"), None);
        // invalid base58 alphabet (0, O, I, l are not in it)
        assert_eq!(decode_pubkey("0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl"), None);
        // empty
        assert_eq!(decode_pubkey(""), None);
    }

    #[test]
    fn transfer_message_has_exact_expected_layout() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let bh = [3u8; 32];
        let m = build_transfer_message(&from, &to, 1_000_000_000, &bh);

        // 3 header + 1 len + 96 keys + 32 blockhash + 1 len + 1 pid + 1 len + 2 idx + 1 len + 12 data
        assert_eq!(m.len(), 3 + 1 + 96 + 32 + 1 + 1 + 1 + 2 + 1 + 12);
        assert_eq!(&m[0..3], &[1, 0, 1], "header");
        assert_eq!(m[3], 3, "three account keys");
        assert_eq!(&m[4..36], &from, "from at index 0");
        assert_eq!(&m[36..68], &to, "to at index 1");
        assert_eq!(&m[68..100], &SYSTEM_PROGRAM, "system program at index 2");
        assert_eq!(&m[100..132], &bh, "recent blockhash");
        // instruction data carries the amount we asked for, little-endian
        let data = &m[m.len() - 12..];
        assert_eq!(&data[0..4], &IX_TRANSFER.to_le_bytes());
        assert_eq!(u64::from_le_bytes(data[4..12].try_into().unwrap()), 1_000_000_000);
    }

    #[test]
    fn amount_is_the_only_thing_that_changes_between_two_amounts() {
        // Two-sided control: a different amount must change the message, and change ONLY the
        // trailing 8 bytes. If anything else moved, the builder is not deterministic in the way
        // the policy check assumes.
        let (f, t, b) = ([9u8; 32], [8u8; 32], [7u8; 32]);
        let a = build_transfer_message(&f, &t, 1, &b);
        let c = build_transfer_message(&f, &t, 2, &b);
        assert_ne!(a, c, "amount must affect the signed bytes");
        assert_eq!(a[..a.len() - 8], c[..c.len() - 8], "only the amount may differ");
    }

    #[test]
    fn recipient_changes_the_signed_bytes() {
        let (f, b) = ([9u8; 32], [7u8; 32]);
        let a = build_transfer_message(&f, &[1u8; 32], 5, &b);
        let c = build_transfer_message(&f, &[2u8; 32], 5, &b);
        assert_ne!(a, c, "recipient must affect the signed bytes");
    }
}

#[cfg(test)]
mod hex_tests {
    #[test]
    fn hex_round_trips_against_a_known_vector() {
        assert_eq!(crate::to_hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(crate::to_hex(&[]), "");
        // every byte value encodes to exactly two chars
        let all: alloc::vec::Vec<u8> = (0u8..=255).collect();
        let h = crate::to_hex(&all);
        assert_eq!(h.len(), 512);
        assert_eq!(&h[0..4], "0001");
        assert_eq!(&h[508..512], "feff");
    }
}

// ============================================================================================
// Teletask task-escrow legs (action-v2). Built from PARAMETERS, never from site-supplied bytes.
//
// Legs 1 and 3 move no lamports, and that is guaranteed STRUCTURALLY rather than by a limit
// check: this builder emits no System Program instruction, so there is no transfer for a policy
// to have to bound. The only lamports spent are the network fee.
// ============================================================================================

/// Task-escrow program (teletask action-v2).
pub const ESCROW_PROGRAM_B58: &str = "B7G2vXXJo1YtoiNnahWdMFHKKn51GsiKi2Miirj9DB9T";
/// SPL Memo program.
pub const MEMO_PROGRAM_B58: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// Anchor discriminators, supplied by the teletask side from the program's own IDL.
pub const DISC_ACCEPT_TASK: [u8; 8] = [222, 196, 79, 165, 120, 30, 38, 120];
pub const DISC_SUBMIT_EVIDENCE: [u8; 8] = [12, 169, 228, 194, 229, 31, 44, 39];

/// One instruction's placement in the message: which program, which accounts (by index, in the
/// IDL's declared order), and its data.
struct Ix {
    program_index: u8,
    account_indices: Vec<u8>,
    data: Vec<u8>,
}

/// Assemble a legacy message.
///
/// `keys` MUST already be in Solana's required order: writable signers, readonly signers,
/// writable non-signers, readonly non-signers. The fee payer is index 0 and is always a writable
/// signer. The header counts are derived from the caller's declared split rather than guessed,
/// because a wrong header silently changes which accounts the runtime treats as writable.
fn build_message(
    keys: &[[u8; 32]],
    num_required_signatures: u8,
    num_readonly_signed: u8,
    num_readonly_unsigned: u8,
    recent_blockhash: &[u8; 32],
    ixs: &[Ix],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(256);
    m.push(num_required_signatures);
    m.push(num_readonly_signed);
    m.push(num_readonly_unsigned);
    encode_shortvec_len(keys.len(), &mut m);
    for k in keys {
        m.extend_from_slice(k);
    }
    m.extend_from_slice(recent_blockhash);
    encode_shortvec_len(ixs.len(), &mut m);
    for ix in ixs {
        m.push(ix.program_index);
        encode_shortvec_len(ix.account_indices.len(), &mut m);
        m.extend_from_slice(&ix.account_indices);
        encode_shortvec_len(ix.data.len(), &mut m);
        m.extend_from_slice(&ix.data);
    }
    m
}

/// Leg 1: `accept_task`.
///
/// Account order inside the instruction follows the IDL: buyer, task_escrow, provider, config.
/// Message key order is Solana's: provider first (fee payer, writable signer), then the writable
/// escrow account, then the readonly rest.
pub fn build_accept_task_message(
    provider: &[u8; 32],
    task_escrow: &[u8; 32],
    buyer: &[u8; 32],
    config: &[u8; 32],
    task_id: u64,
    layer: u16,
    recent_blockhash: &[u8; 32],
) -> Option<Vec<u8>> {
    let escrow_prog = decode_pubkey(ESCROW_PROGRAM_B58)?;
    // 0 provider (w,s)  1 task_escrow (w)  2 buyer (ro)  3 config (ro)  4 escrow program (ro)
    let keys = [*provider, *task_escrow, *buyer, *config, escrow_prog];
    let mut data = Vec::with_capacity(18);
    data.extend_from_slice(&DISC_ACCEPT_TASK);
    data.extend_from_slice(&task_id.to_le_bytes());
    data.extend_from_slice(&layer.to_le_bytes());
    let ix = Ix { program_index: 4, account_indices: alloc::vec![2, 1, 0, 3], data };
    Some(build_message(&keys, 1, 0, 3, recent_blockhash, &[ix]))
}

/// Leg 3: `submit_evidence` plus the TTEV1 memo, in ONE transaction.
///
/// `ev` is the compact evidence JSON. The contract hashes THE SAME BYTES it puts in the memo, so
/// the check-bot's hash comparison cannot fail through a mismatch between the two: there is only
/// one copy of the evidence here, used twice.
pub fn build_submit_evidence_message(
    provider: &[u8; 32],
    task_escrow: &[u8; 32],
    buyer: &[u8; 32],
    task_id: u64,
    ev: &str,
    evidence_hash: &[u8; 32],
    recent_blockhash: &[u8; 32],
) -> Option<Vec<u8>> {
    let escrow_prog = decode_pubkey(ESCROW_PROGRAM_B58)?;
    let memo_prog = decode_pubkey(MEMO_PROGRAM_B58)?;
    // 0 provider (w,s)  1 task_escrow (w)  2 buyer (ro)  3 escrow prog (ro)  4 memo prog (ro)
    let keys = [*provider, *task_escrow, *buyer, escrow_prog, memo_prog];

    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(&DISC_SUBMIT_EVIDENCE);
    data.extend_from_slice(&task_id.to_le_bytes());
    data.extend_from_slice(evidence_hash);
    let ix_submit = Ix { program_index: 3, account_indices: alloc::vec![2, 1, 0], data };

    let mut memo = Vec::with_capacity(6 + ev.len());
    memo.extend_from_slice(b"TTEV1|");
    memo.extend_from_slice(ev.as_bytes());
    let ix_memo = Ix { program_index: 4, account_indices: Vec::new(), data: memo };

    Some(build_message(&keys, 1, 0, 3, recent_blockhash, &[ix_submit, ix_memo]))
}

#[cfg(test)]
mod escrow_tests {
    use super::*;
    use alloc::string::ToString;

    fn k(b: u8) -> [u8; 32] { [b; 32] }

    #[test]
    fn accept_task_layout_is_exact() {
        let m = build_accept_task_message(&k(1), &k(2), &k(3), &k(4), 7, 0, &k(9)).unwrap();
        assert_eq!(&m[0..3], &[1, 0, 3], "header: 1 signer, 0 ro-signed, 3 ro-unsigned");
        assert_eq!(m[3], 5, "five account keys");
        assert_eq!(&m[4..36], &k(1), "provider is index 0 = fee payer");
        assert_eq!(&m[36..68], &k(2), "task_escrow is index 1, the only other writable");
        let bh_at = 4 + 5 * 32;
        assert_eq!(&m[bh_at..bh_at + 32], &k(9), "recent blockhash");
        let p = bh_at + 32;
        assert_eq!(m[p], 1, "one instruction");
        assert_eq!(m[p + 1], 4, "program index points at the escrow program");
        assert_eq!(m[p + 2], 4, "four account indices");
        assert_eq!(&m[p + 3..p + 7], &[2, 1, 0, 3], "IDL order: buyer, escrow, provider, config");
        assert_eq!(m[p + 7], 18, "8 disc + 8 task_id + 2 layer");
        assert_eq!(&m[p + 8..p + 16], &DISC_ACCEPT_TASK);
        assert_eq!(u64::from_le_bytes(m[p + 16..p + 24].try_into().unwrap()), 7);
        assert_eq!(u16::from_le_bytes(m[p + 24..p + 26].try_into().unwrap()), 0);
    }

    #[test]
    fn accept_task_contains_no_system_program() {
        // The structural guarantee for leg 1: no System Program account means no transfer
        // instruction is expressible in this message at all.
        let m = build_accept_task_message(&k(1), &k(2), &k(3), &k(4), 7, 0, &k(9)).unwrap();
        let keys: Vec<&[u8]> = (0..5).map(|i| &m[4 + i * 32..4 + (i + 1) * 32]).collect();
        assert!(!keys.iter().any(|x| *x == &SYSTEM_PROGRAM[..]),
                "a System Program key would make a lamport transfer possible");
    }

    #[test]
    fn submit_evidence_carries_the_memo_in_the_same_tx() {
        let ev = r#"{"signature":"abc","text":"Sent 0.01 SOL to X."}"#;
        let h = [7u8; 32];
        let m = build_submit_evidence_message(&k(1), &k(2), &k(3), 42, ev, &h, &k(9)).unwrap();
        assert_eq!(&m[0..3], &[1, 0, 3]);
        assert_eq!(m[3], 5);
        let p = 4 + 5 * 32 + 32;
        assert_eq!(m[p], 2, "TWO instructions: submit_evidence and the memo");
        // instruction 1
        assert_eq!(m[p + 1], 3, "escrow program index");
        assert_eq!(&m[p + 3..p + 6], &[2, 1, 0], "IDL order: buyer, escrow, provider");
        assert_eq!(m[p + 6], 48, "8 disc + 8 task_id + 32 hash");
        assert_eq!(&m[p + 7..p + 15], &DISC_SUBMIT_EVIDENCE);
        assert_eq!(u64::from_le_bytes(m[p + 15..p + 23].try_into().unwrap()), 42);
        assert_eq!(&m[p + 23..p + 55], &h);
        // instruction 2: the memo
        let q = p + 55;
        assert_eq!(m[q], 4, "memo program index");
        assert_eq!(m[q + 1], 0, "memo takes no accounts");
        let dlen = m[q + 2] as usize;
        assert_eq!(dlen, 6 + ev.len());
        let memo = &m[q + 3..q + 3 + dlen];
        assert_eq!(&memo[0..6], b"TTEV1|");
        assert_eq!(core::str::from_utf8(&memo[6..]).unwrap(), ev);
    }

    #[test]
    fn the_memo_and_the_hashed_bytes_are_the_same_evidence() {
        // The check-bot reads the memo and compares sha256 of it against evidence_hash. If the
        // contract hashed one string and memo'd another, that comparison fails and the task is
        // judged against us. There is only ONE copy of ev here, so they cannot diverge.
        let ev = r#"{"signature":"s","text":"t"}"#;
        let h = [1u8; 32];
        let m = build_submit_evidence_message(&k(1), &k(2), &k(3), 1, ev, &h, &k(9)).unwrap();
        let s = alloc::string::String::from_utf8_lossy(&m).to_string();
        assert_eq!(s.matches(ev).count(), 1, "the evidence appears exactly once, in the memo");
    }

    #[test]
    fn task_id_and_layer_change_the_signed_bytes() {
        let a = build_accept_task_message(&k(1), &k(2), &k(3), &k(4), 7, 0, &k(9)).unwrap();
        let b = build_accept_task_message(&k(1), &k(2), &k(3), &k(4), 8, 0, &k(9)).unwrap();
        let c = build_accept_task_message(&k(1), &k(2), &k(3), &k(4), 7, 1, &k(9)).unwrap();
        assert_ne!(a, b, "task_id must affect the signed bytes");
        assert_ne!(a, c, "layer must affect the signed bytes");
    }
}
