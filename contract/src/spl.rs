//! SPL / Token-2022 transfer leg: a `TransferChecked` message the contract builds byte by byte,
//! and a pure decision over a PER-MINT policy.
//!
//! ## THE CONSTRAINT THAT SHAPES THIS WHOLE MODULE
//!
//! A NEAR contract **cannot read Solana account state.** Chain Signatures produce a signature;
//! they are not a cross-chain read. So "read the Token-2022 rules from the mint" is not something
//! this contract can do, however much we would like it to. The extension scan necessarily happens
//! OFF chain, and its result arrives here as a `MintProfile` the **owner pins** when allowlisting
//! the mint.
//!
//! ## WHY A PINNED PROFILE IS NOT AUTOMATICALLY SOUND
//!
//! Several Token-2022 extensions stay MUTABLE after mint creation:
//!   * `TransferFeeConfig` — a fee-config authority can raise the fee (with an epoch delay);
//!   * `TransferHook` — a hook authority can repoint the hook at a different program;
//!   * `ConfidentialTransferMint` — has its own authority.
//! `PermanentDelegate` cannot be revoked once set, which is why it is a refusal and not a warning.
//!
//! So a pinned snapshot of a mint whose authorities are still live describes the mint **as it was
//! at pinning time**, and an attacker holding the fee authority can make our cap arithmetic wrong
//! after the fact. The profile is therefore accepted only when `authorities_revoked` is asserted:
//! a pin is sound only if the pinned thing cannot change.
//!
//! That is the SAME coupling the account lock gave us, in a second domain: `code_hash` pinning is
//! sound *because* the account is locked, and a mint profile pin is sound *because* the mint's
//! extension authorities are gone. Neither pin means anything on a mutable target. The lesson
//! transferred; it was not re-derived.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::solana::{decode_pubkey, encode_shortvec_len};

/// Classic SPL Token program.
pub const TOKEN_PROGRAM_B58: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Token-2022.
pub const TOKEN_2022_B58: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// `TransferChecked` instruction discriminant (single byte, classic + 2022 share it).
pub const IX_TRANSFER_CHECKED: u8 = 12;
/// Token-2022 caps the transfer fee at 100% in basis points; anything above is malformed input.
pub const MAX_FEE_BPS: u16 = 10_000;

/// What an off-chain scan found on the mint, as the OWNER asserts it. Every field is a claim the
/// owner is making, never something this contract observed.
///
/// Borsh lives on the DATA, not on the decision: `decide_spl()` stays a pure function of its
/// arguments. Same reasoning as `Policy` — a parallel stored type could silently drift from this one.
#[derive(Clone, Debug, PartialEq, Eq, near_sdk::borsh::BorshSerialize, near_sdk::borsh::BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct MintProfile {
    /// Token-2022 transfer fee in basis points, 0 for none or for classic SPL.
    pub fee_bps: u16,
    /// Absolute per-transfer fee ceiling in base units (Token-2022 `maximum_fee`), 0 when unset.
    pub max_fee: u64,
    /// `Some(program)` when a transfer hook is configured. Only a PINNED program is acceptable.
    pub transfer_hook: Option<String>,
    /// A permanent delegate can move the holder's tokens forever and CANNOT be revoked.
    pub permanent_delegate: Option<String>,
    /// Confidential transfers make amounts unreadable, so a cap cannot be enforced on them.
    pub confidential: bool,
    /// The owner asserts every mutable extension authority is revoked, which is what makes the
    /// rest of this struct a pin rather than a snapshot.
    pub authorities_revoked: bool,
}

/// A per-mint spending rule.
#[derive(Clone, Debug, PartialEq, Eq, near_sdk::borsh::BorshSerialize, near_sdk::borsh::BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct MintRule {
    pub enabled: bool,
    /// The token account we spend FROM, pinned by the owner.
    ///
    /// Deliberately NOT a parameter of the action. The escrow legs take caller-supplied accounts
    /// and lean on the escrow program's own validation to stay safe — a dependence I had described
    /// as a property of my own code until it was pointed out. There is no reason to repeat that
    /// here: the source is a fact about which account this contract spends, so the owner states it
    /// once and the untrusted agent never gets to name it.
    pub source_ata: String,
    /// Mint decimals. `TransferChecked` fails on chain if this disagrees with the mint, which is
    /// the point of using it over `Transfer`: a decimals mistake cannot silently move 10^n too much.
    pub decimals: u8,
    /// Largest single transfer in base units, FEE INCLUDED (see `effective_debit`).
    pub per_tx_amount: u128,
    /// Largest rolling-window total in base units, fee included.
    pub window_amount: u128,
    pub spent_in_window: u128,
    pub window_started_ms: u64,
    /// Destination token accounts this agent may pay. EMPTY MEANS NOBODY.
    pub allowed_destinations: Vec<String>,
    /// Which token program this mint lives under; decides the program id in the message.
    pub token_program: String,
    /// Hook programs the owner has pinned. A hook outside this set is refused.
    pub pinned_hooks: Vec<String>,
    pub profile: MintProfile,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SplRefusal {
    UnknownAgent,
    AgentDisabled,
    SessionExpired,
    MintNotAllowed,
    MintDisabled,
    /// The pinned profile cannot be trusted or cannot be capped. `reason` names which rule.
    MintProfileUnsafe { reason: &'static str },
    ZeroAmount,
    DecimalsMismatch { policy: u8, requested: u8 },
    DestinationMalformed,
    DestinationNotAllowed,
    /// `debit` is amount + fee, which is what the cap is actually applied to.
    OverPerTxLimit { limit: u128, debit: u128 },
    OverWindowLimit { limit: u128, spent: u128, debit: u128 },
}

#[derive(Clone, Debug, PartialEq)]
pub enum SplDecision {
    Allow {
        /// amount + fee: what the window is charged.
        debit: u128,
        new_spent_in_window: u128,
        new_window_started_ms: u64,
    },
    Refuse(SplRefusal),
}

pub struct SplRequest {
    pub mint: String,
    pub destination: String,
    pub amount: u64,
    pub decimals: u8,
}

/// Token-2022 transfer fee: `ceil(amount * bps / 10000)`, clamped by `max_fee`.
///
/// CEILING, not floor: the program rounds the fee UP, so a floor here would under-count the debit
/// and let an at-cap transfer exceed the cap by one base unit. Saturating throughout — a u128
/// product of two u64s cannot overflow, but the clamp must not be skipped when `max_fee` is 0,
/// which means "no ceiling", not "no fee".
pub fn transfer_fee(amount: u64, p: &MintProfile) -> u128 {
    if p.fee_bps == 0 {
        return 0;
    }
    let num = (amount as u128).saturating_mul(p.fee_bps as u128);
    let fee = num / 10_000 + if num % 10_000 != 0 { 1 } else { 0 };
    if p.max_fee > 0 {
        core::cmp::min(fee, p.max_fee as u128)
    } else {
        fee
    }
}

/// What the caps are applied to: the amount plus the fee the token program will take.
///
/// The fee is counted INSIDE the cap because the holder's balance falls by amount + fee. Capping
/// the amount alone would let a 100%-fee mint debit twice the ceiling while every refusal arm
/// reported the policy was honoured.
pub fn effective_debit(amount: u64, p: &MintProfile) -> u128 {
    (amount as u128).saturating_add(transfer_fee(amount, p))
}

/// Is this pinned profile one we are willing to sign against at all?
///
/// Ordered so the most structural objection is reported first: an unpinnable profile is a worse
/// finding than a cappable-but-hostile one, and a caller fixing them one at a time should be told
/// about the pin before the fee.
pub fn profile_objection(r: &MintRule) -> Option<&'static str> {
    let p = &r.profile;
    if !p.authorities_revoked {
        // the pin/lock coupling: without this the rest of the struct is a snapshot, not a pin
        return Some("mint extension authorities are not revoked, so the pinned profile is only a snapshot");
    }
    if p.confidential {
        return Some("confidential transfers hide the amount, so no cap can be enforced");
    }
    if p.permanent_delegate.is_some() {
        return Some("mint has a permanent delegate, which can move funds regardless of our policy and cannot be revoked");
    }
    if p.fee_bps > MAX_FEE_BPS {
        return Some("transfer fee exceeds 100 percent, which is malformed");
    }
    if let Some(h) = &p.transfer_hook {
        if !r.pinned_hooks.iter().any(|x| x == h) {
            return Some("transfer hook program is not pinned by the owner");
        }
    }
    None
}

/// Decide one SPL transfer. Pure: no host calls, no clock of its own, no storage.
///
/// Refusal ORDER is part of the contract, not an implementation detail. It mirrors the lamport
/// arm: identity, then authority lifetime, then the asset, then the request's own shape, then the
/// amounts. A caller that fixes refusals one at a time walks the same path in both legs.
pub fn decide_spl(
    known: bool,
    agent_enabled: bool,
    session_expires_at_ms: u64,
    rule: Option<&MintRule>,
    r: &SplRequest,
    now_ms: u64,
) -> SplDecision {
    use SplRefusal::*;
    if !known {
        return SplDecision::Refuse(UnknownAgent);
    }
    if !agent_enabled {
        return SplDecision::Refuse(AgentDisabled);
    }
    if session_expires_at_ms != 0 && now_ms >= session_expires_at_ms {
        return SplDecision::Refuse(SessionExpired);
    }
    let rule = match rule {
        None => return SplDecision::Refuse(MintNotAllowed),
        Some(x) => x,
    };
    if !rule.enabled {
        return SplDecision::Refuse(MintDisabled);
    }
    if let Some(reason) = profile_objection(rule) {
        return SplDecision::Refuse(MintProfileUnsafe { reason });
    }
    if r.amount == 0 {
        return SplDecision::Refuse(ZeroAmount);
    }
    // the caller states decimals and so does the policy; a mismatch means one of them is wrong
    // about the mint, and the chain would reject it anyway. Refuse here with both numbers rather
    // than sign a message that is guaranteed to fail.
    if r.decimals != rule.decimals {
        return SplDecision::Refuse(DecimalsMismatch {
            policy: rule.decimals,
            requested: r.decimals,
        });
    }
    if decode_pubkey(&r.destination).is_none() {
        return SplDecision::Refuse(DestinationMalformed);
    }
    if !rule.allowed_destinations.iter().any(|x| *x == r.destination) {
        return SplDecision::Refuse(DestinationNotAllowed);
    }

    let debit = effective_debit(r.amount, &rule.profile);
    if debit > rule.per_tx_amount {
        return SplDecision::Refuse(OverPerTxLimit {
            limit: rule.per_tx_amount,
            debit,
        });
    }
    // same roll test the lamport arm uses, same reason: the stored total is the PREVIOUS window's
    // until something writes it back.
    let expired = crate::policy::window_expired(now_ms, rule.window_started_ms);
    let (spent, started) = if expired {
        (0u128, now_ms)
    } else {
        (rule.spent_in_window, rule.window_started_ms)
    };
    let projected = spent.saturating_add(debit);
    if projected > rule.window_amount {
        return SplDecision::Refuse(OverWindowLimit {
            limit: rule.window_amount,
            spent,
            debit,
        });
    }
    SplDecision::Allow {
        debit,
        new_spent_in_window: projected,
        new_window_started_ms: started,
    }
}

/// Build a legacy Solana message carrying exactly one `TransferChecked`.
///
/// Account layout, fee payer first as the format requires:
///   0 authority    writable signer   (our derived address: token authority AND fee payer)
///   1 source       writable
///   2 destination  writable
///   3 mint         readonly
///   4 token_program readonly
/// header = (1 required signature, 0 readonly signed, 2 readonly unsigned)
///
/// `TransferChecked` account order is (source, mint, destination, authority) — note the mint sits
/// SECOND in the instruction while living at index 3 in the key table. Writing the key order and
/// the instruction order as if they were the same list is the easy way to build a message that
/// signs cleanly and then fails, or worse, succeeds against the wrong account.
///
/// Returns `None` when any key is malformed, duplicated, or is the system program. Duplicates
/// matter because Solana MERGES duplicate keys and takes the UNION of their privileges, so a
/// duplicate can silently promote a readonly account to writable.
pub fn build_transfer_checked_message(
    authority: &[u8; 32],
    source: &[u8; 32],
    destination: &[u8; 32],
    mint: &[u8; 32],
    token_program: &[u8; 32],
    amount: u64,
    decimals: u8,
    recent_blockhash: &[u8; 32],
) -> Option<Vec<u8>> {
    let keys = [*authority, *source, *destination, *mint, *token_program];
    for (i, k) in keys.iter().enumerate() {
        if *k == crate::solana::SYSTEM_PROGRAM {
            return None;
        }
        if keys[i + 1..].contains(k) {
            return None;
        }
    }

    let mut m = Vec::with_capacity(224);
    m.push(1); // num_required_signatures
    m.push(0); // num_readonly_signed_accounts
    m.push(2); // num_readonly_unsigned_accounts: mint + token program

    encode_shortvec_len(5, &mut m);
    for k in keys.iter() {
        m.extend_from_slice(k);
    }

    m.extend_from_slice(recent_blockhash);

    encode_shortvec_len(1, &mut m);
    m.push(4); // program_id_index -> token program
    encode_shortvec_len(4, &mut m);
    m.push(1); // source
    m.push(3); // mint
    m.push(2); // destination
    m.push(0); // authority
    let mut data = Vec::with_capacity(10);
    data.push(IX_TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    encode_shortvec_len(data.len(), &mut m);
    m.extend_from_slice(&data);

    Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_profile() -> MintProfile {
        MintProfile {
            fee_bps: 0,
            max_fee: 0,
            transfer_hook: None,
            permanent_delegate: None,
            confidential: false,
            authorities_revoked: true,
        }
    }

    fn rule(profile: MintProfile) -> MintRule {
        MintRule {
            enabled: true,
            source_ata: String::from("5ourceAtA111111111111111111111111111111111"),
            decimals: 6,
            per_tx_amount: 1_000_000,
            window_amount: 2_000_000,
            spent_in_window: 0,
            window_started_ms: 1_000_000,
            allowed_destinations: alloc::vec![String::from(
                "8pM1kPpfgEoFtuSmPx5Xk2Bu1X1bHGbVbPmZPFgcJYhP"
            )],
            token_program: String::from(TOKEN_2022_B58),
            pinned_hooks: Vec::new(),
            profile,
        }
    }

    fn req(amount: u64) -> SplRequest {
        SplRequest {
            mint: String::from("So11111111111111111111111111111111111111112"),
            destination: String::from("8pM1kPpfgEoFtuSmPx5Xk2Bu1X1bHGbVbPmZPFgcJYhP"),
            amount,
            decimals: 6,
        }
    }

    // ---- the two-sided arm: ONE unchanged policy both passes and refuses ----

    #[test]
    fn at_cap_passes_and_over_cap_refuses_under_one_policy() {
        let r = rule(safe_profile());
        match decide_spl(true, true, 0, Some(&r), &req(1_000_000), 1_000_001) {
            SplDecision::Allow { debit, .. } => assert_eq!(debit, 1_000_000),
            d => panic!("at-cap must pass, got {:?}", d),
        }
        match decide_spl(true, true, 0, Some(&r), &req(1_000_001), 1_000_001) {
            SplDecision::Refuse(SplRefusal::OverPerTxLimit { limit, debit }) => {
                assert_eq!((limit, debit), (1_000_000, 1_000_001));
            }
            d => panic!("over-cap must refuse, got {:?}", d),
        }
    }

    // ---- the fee must be INSIDE the cap ----

    #[test]
    fn fee_counts_against_the_cap() {
        let mut p = safe_profile();
        p.fee_bps = 100; // 1%
        let r = rule(p);
        // 1_000_000 amount + 10_000 fee = 1_010_000 > the 1_000_000 cap
        match decide_spl(true, true, 0, Some(&r), &req(1_000_000), 1_000_001) {
            SplDecision::Refuse(SplRefusal::OverPerTxLimit { debit, .. }) => {
                assert_eq!(debit, 1_010_000, "the fee must be in the debit");
            }
            d => panic!("a 1% fee must push an at-cap amount over, got {:?}", d),
        }
        // the largest amount that still fits once its own fee is counted
        match decide_spl(true, true, 0, Some(&r), &req(990_099), 1_000_001) {
            SplDecision::Allow { debit, .. } => assert!(debit <= 1_000_000, "debit {}", debit),
            d => panic!("990_099 must fit, got {:?}", d),
        }
    }

    #[test]
    fn fee_rounds_up_not_down() {
        let mut p = safe_profile();
        p.fee_bps = 1; // 0.01%
        // 1 base unit * 1bps = 0.0001 -> must be 1, not 0: a floor would under-charge the cap
        assert_eq!(transfer_fee(1, &p), 1);
        assert_eq!(transfer_fee(10_000, &p), 1);
        assert_eq!(transfer_fee(10_001, &p), 2);
    }

    #[test]
    fn max_fee_clamps_but_zero_max_fee_does_not_mean_zero_fee() {
        let mut p = safe_profile();
        p.fee_bps = 10_000; // 100%
        p.max_fee = 500;
        assert_eq!(transfer_fee(1_000_000, &p), 500, "clamped by max_fee");
        p.max_fee = 0; // "no ceiling", NOT "no fee"
        assert_eq!(transfer_fee(1_000_000, &p), 1_000_000);
    }

    // ---- profile objections, each one its own arm ----

    #[test]
    fn unrevoked_authorities_refuse_before_anything_else() {
        let mut p = safe_profile();
        p.authorities_revoked = false;
        let r = rule(p);
        match decide_spl(true, true, 0, Some(&r), &req(1), 1_000_001) {
            SplDecision::Refuse(SplRefusal::MintProfileUnsafe { reason }) => {
                assert!(reason.contains("snapshot"), "reason: {}", reason);
            }
            d => panic!("an unpinnable profile must refuse, got {:?}", d),
        }
    }

    #[test]
    fn confidential_and_permanent_delegate_refuse() {
        let mut p = safe_profile();
        p.confidential = true;
        assert!(profile_objection(&rule(p)).unwrap().contains("cap"));

        let mut p = safe_profile();
        p.permanent_delegate = Some(String::from("Dele11111111111111111111111111111111111111"));
        assert!(profile_objection(&rule(p)).unwrap().contains("permanent delegate"));
    }

    #[test]
    fn hook_refused_unless_pinned_and_accepted_when_pinned() {
        let hook = String::from("Hook1111111111111111111111111111111111111111");
        let mut p = safe_profile();
        p.transfer_hook = Some(hook.clone());

        let r = rule(p.clone());
        assert!(profile_objection(&r).unwrap().contains("not pinned"));

        let mut r2 = rule(p);
        r2.pinned_hooks = alloc::vec![hook];
        assert!(profile_objection(&r2).is_none(), "a pinned hook is acceptable");
    }

    // ---- request shape ----

    #[test]
    fn decimals_mismatch_refuses_with_both_numbers() {
        let r = rule(safe_profile());
        let mut q = req(1);
        q.decimals = 9;
        match decide_spl(true, true, 0, Some(&r), &q, 1_000_001) {
            SplDecision::Refuse(SplRefusal::DecimalsMismatch { policy, requested }) => {
                assert_eq!((policy, requested), (6, 9));
            }
            d => panic!("got {:?}", d),
        }
    }

    #[test]
    fn empty_destination_list_means_nobody() {
        let mut r = rule(safe_profile());
        r.allowed_destinations = Vec::new();
        assert_eq!(
            decide_spl(true, true, 0, Some(&r), &req(1), 1_000_001),
            SplDecision::Refuse(SplRefusal::DestinationNotAllowed)
        );
    }

    #[test]
    fn unknown_mint_refuses() {
        assert_eq!(
            decide_spl(true, true, 0, None, &req(1), 1_000_001),
            SplDecision::Refuse(SplRefusal::MintNotAllowed)
        );
    }

    // ---- window, including the roll ----

    #[test]
    fn window_rolls_and_the_refusal_reports_the_rolled_spend() {
        let mut r = rule(safe_profile());
        r.spent_in_window = 2_000_000; // window already exhausted
        // before expiry: refused, and `spent` reports the STORED total
        match decide_spl(true, true, 0, Some(&r), &req(1), 1_000_001) {
            SplDecision::Refuse(SplRefusal::OverWindowLimit { spent, .. }) => {
                assert_eq!(spent, 2_000_000)
            }
            d => panic!("got {:?}", d),
        }
        // at expiry: allowed, and the window restarts at now
        let at = 1_000_000 + crate::policy::WINDOW_MS;
        match decide_spl(true, true, 0, Some(&r), &req(1), at) {
            SplDecision::Allow {
                new_spent_in_window,
                new_window_started_ms,
                ..
            } => {
                assert_eq!(new_spent_in_window, 1);
                assert_eq!(new_window_started_ms, at);
            }
            d => panic!("the window must roll, got {:?}", d),
        }
    }

    // ---- the message ----

    #[test]
    fn transfer_checked_message_layout() {
        let a = [1u8; 32];
        let s = [2u8; 32];
        let d = [3u8; 32];
        let mint = [4u8; 32];
        let tp = [5u8; 32];
        let bh = [6u8; 32];
        let m = build_transfer_checked_message(&a, &s, &d, &mint, &tp, 1_234, 6, &bh).unwrap();

        assert_eq!(&m[0..3], &[1, 0, 2], "header");
        assert_eq!(m[3], 5, "five account keys");
        assert_eq!(&m[4..36], &a, "fee payer must be index 0");
        assert_eq!(&m[36..68], &s);
        assert_eq!(&m[68..100], &d);
        assert_eq!(&m[100..132], &mint);
        assert_eq!(&m[132..164], &tp);
        assert_eq!(&m[164..196], &bh, "blockhash");
        assert_eq!(m[196], 1, "one instruction");
        assert_eq!(m[197], 4, "program id index -> token program");
        assert_eq!(m[198], 4, "four instruction accounts");
        // TransferChecked order is (source, mint, destination, authority) - NOT the key order
        assert_eq!(&m[199..203], &[1u8, 3, 2, 0]);
        assert_eq!(m[203], 10, "data length: 1 + 8 + 1");
        assert_eq!(m[204], IX_TRANSFER_CHECKED);
        assert_eq!(&m[205..213], &1_234u64.to_le_bytes());
        assert_eq!(m[213], 6, "decimals");
        assert_eq!(m.len(), 214);
    }

    #[test]
    fn message_refuses_system_program_and_duplicate_keys() {
        let z = crate::solana::SYSTEM_PROGRAM;
        let (a, s, d, mint, tp, bh) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32]);
        assert!(build_transfer_checked_message(&z, &s, &d, &mint, &tp, 1, 6, &bh).is_none());
        assert!(build_transfer_checked_message(&a, &z, &d, &mint, &tp, 1, 6, &bh).is_none());
        assert!(build_transfer_checked_message(&a, &s, &d, &mint, &z, 1, 6, &bh).is_none());
        // duplicates merge on chain and take the UNION of privileges
        assert!(build_transfer_checked_message(&a, &s, &s, &mint, &tp, 1, 6, &bh).is_none());
        assert!(build_transfer_checked_message(&a, &s, &d, &mint, &mint, 1, 6, &bh).is_none());
        assert!(build_transfer_checked_message(&a, &s, &d, &mint, &tp, 1, 6, &bh).is_some());
    }
}

#[cfg(test)]
mod repin_semantics_note {
    //! The preserve-vs-reset decision lives in `lib.rs::set_mint_rule`, which needs a host and so
    //! is covered by the live arms rather than here. Recorded in this module so the reasoning sits
    //! beside the rule it governs: a re-pin PRESERVES `spent_in_window`, matching
    //! `set_agent_policy`, because a reset would make re-pinning a budget-refund primitive.
}
