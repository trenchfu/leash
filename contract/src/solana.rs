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
