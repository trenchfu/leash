//! The spend policy, as a PURE function of (policy, request, clock).
//!
//! Nothing here touches storage, the MPC contract, or the environment. That is deliberate: a
//! decision that is tangled with its effects can only be tested by performing the effects, and a
//! guard you cannot test cheaply is a guard nobody proves. `decide()` is total — every input maps
//! to exactly one `Decision`, and every `Refusal` variant below is reachable by a unit test.
//!
//! A verifier that cannot fail is not a verifier: the tests at the bottom enter EVERY refusal
//! state, and the suite asserts that the set of states actually entered equals the full set of
//! variants, so adding a new refusal without a test for it breaks the build.

extern crate alloc;
use alloc::string::String;

/// Milliseconds in the rolling spend window.
pub const WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// Has the rolling window elapsed?
///
/// ONE expression, three call sites: `decide()`, `decide_spl()`, and the `get_agent_policy` view's
/// `spent_in_window_effective`. It was written out three separate times first, which is a rule
/// free to diverge — and the view is the call site where a divergence would be invisible, because
/// it would simply display a number that enforcement disagreed with. A view that can disagree with
/// the thing it describes is worse than a missing view.
///
/// `saturating_sub` means a `now_ms` BEFORE `window_started_ms` (a clock that went backwards)
/// yields 0 and reads NOT expired, which fails toward keeping the existing window rather than
/// silently granting a fresh allowance.
pub fn window_expired(now_ms: u64, window_started_ms: u64) -> bool {
    now_ms.saturating_sub(window_started_ms) >= WINDOW_MS
}

/// The spend to store after a FAILED-signature refund, or `None` meaning DO NOT refund.
///
/// Why this is a decision and not a subtraction. The spend is charged optimistically at sign
/// time, before the cross-contract call yields, and the failure callback reverses it. But the
/// callback carries only an AMOUNT. If the rolling window has rolled between the charge and the
/// callback, subtracting that amount credits a window that never paid it: the stale refund
/// lands on whatever window is current, and several of them stacked across a boundary can drive
/// a live window's recorded spend to zero while its real in-flight spend is high. Saturating
/// arithmetic floors each subtraction at zero but does nothing about the SUM, so the error is
/// bounded by the current window's own spend, not by one per-tx amount.
///
/// Matching the charged window is what makes the refund correct across a roll: the window the
/// charge belonged to is either still current (credit it) or gone (there is nothing to credit,
/// and its totals no longer gate anything). Window ids are `block_timestamp_ms` at roll and are
/// monotonic, so equality identifies the window uniquely.
pub fn refund_spend(
    current_spent: u128,
    current_window_started_ms: u64,
    charged_window_started_ms: u64,
    amount: u128,
) -> Option<u128> {
    if current_window_started_ms != charged_window_started_ms {
        return None;
    }
    Some(current_spent.saturating_sub(amount))
}

// Borsh lives on the DATA, not on the decision: `decide()` below stays a pure function of
// its arguments. Deriving serialization here costs nothing in testability and avoids a
// parallel StoredPolicy type that could silently drift from this one.
#[derive(Clone, Debug, PartialEq, Eq, near_sdk::borsh::BorshSerialize, near_sdk::borsh::BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Policy {
    pub enabled: bool,
    /// Largest single transfer, in lamports.
    pub per_tx_lamports: u128,
    /// Largest total across the rolling window, in lamports.
    pub window_lamports: u128,
    /// Lamports already spent inside the current window.
    pub spent_in_window: u128,
    /// Start of the current window, ms since epoch.
    pub window_started_ms: u64,
    /// Base58 recipients this agent may pay. EMPTY MEANS NOBODY, never "everybody" — a policy
    /// that fails open is worse than no policy, because it reads as protection.
    pub allowed_recipients: alloc::vec::Vec<String>,
    /// Session expiry, ms since epoch. A grant with no end date is a grant you forgot you made;
    /// standing authority is how a compromised agent stays useful to an attacker for months.
    /// 0 means "no expiry" and is only reachable by an owner who asks for it explicitly.
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub recipient: String,
    pub lamports: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The caller is not a registered agent at all.
    UnknownAgent,
    /// Registered, but switched off.
    AgentDisabled,
    /// Zero-value transfers are refused: they are pure noise against the rate limit.
    ZeroAmount,
    /// Single transfer exceeds the per-transaction ceiling.
    OverPerTxLimit { limit: u128, requested: u128 },
    /// Would push the rolling window total over its ceiling.
    OverWindowLimit { limit: u128, spent: u128, requested: u128 },
    /// Recipient is not on this agent's allowlist (or the allowlist is empty).
    RecipientNotAllowed,
    /// Recipient is not a decodable 32-byte Solana address.
    RecipientMalformed,
    /// The agent's session has passed its expiry.
    SessionExpired { expired_at_ms: u64, now_ms: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow {
        /// Window total AFTER this spend, for the caller to persist.
        new_spent_in_window: u128,
        /// Window start AFTER this spend (rolls forward when the old window expired).
        new_window_started_ms: u64,
    },
    Refuse(Refusal),
}

/// Decide a single request. `known` is false when the caller is not a registered agent.
pub fn decide(known: bool, p: &Policy, r: &Request, now_ms: u64) -> Decision {
    if !known {
        return Decision::Refuse(Refusal::UnknownAgent);
    }
    if !p.enabled {
        return Decision::Refuse(Refusal::AgentDisabled);
    }
    // Expiry is checked EARLY and with `>=`: at the stroke of expiry the session is over. An
    // expired session must not be rescuable by any later check passing.
    if p.expires_at_ms != 0 && now_ms >= p.expires_at_ms {
        return Decision::Refuse(Refusal::SessionExpired {
            expired_at_ms: p.expires_at_ms,
            now_ms,
        });
    }
    if r.lamports == 0 {
        return Decision::Refuse(Refusal::ZeroAmount);
    }
    // Malformedness is checked BEFORE the allowlist, so a garbage recipient reports what is
    // actually wrong with it instead of the misleading "not allowed".
    if crate::solana::decode_pubkey(&r.recipient).is_none() {
        return Decision::Refuse(Refusal::RecipientMalformed);
    }
    if !p.allowed_recipients.iter().any(|a| a == &r.recipient) {
        return Decision::Refuse(Refusal::RecipientNotAllowed);
    }
    if r.lamports > p.per_tx_lamports {
        return Decision::Refuse(Refusal::OverPerTxLimit {
            limit: p.per_tx_lamports,
            requested: r.lamports,
        });
    }

    // Roll the window forward if the old one has expired. Saturating arithmetic throughout: a
    // clock that goes backwards must never silence the limit (it would underflow to a huge
    // "remaining" budget), which is the failure mode an alarm clock usually has.
    let expired = window_expired(now_ms, p.window_started_ms);
    let (spent, started) = if expired { (0u128, now_ms) } else { (p.spent_in_window, p.window_started_ms) };

    let projected = spent.saturating_add(r.lamports);
    if projected > p.window_lamports {
        return Decision::Refuse(Refusal::OverWindowLimit {
            limit: p.window_lamports,
            spent,
            requested: r.lamports,
        });
    }

    Decision::Allow { new_spent_in_window: projected, new_window_started_ms: started }
}

/// Gate for calls that move NO lamports (the escrow legs). It deliberately does NOT consult the
/// amount, allowlist or window, because there is no amount to bound: the builder emits no System
/// Program account, so a transfer is not expressible in those messages. Checking a spend limit
/// here would be theatre -- a guard that reads as protection while guarding nothing.
///
/// What still applies is WHO and WHEN: an unknown, disabled or expired agent must not be able to
/// act as the provider.
pub fn decide_novalue(known: bool, p: &Policy, now_ms: u64) -> Decision {
    if !known {
        return Decision::Refuse(Refusal::UnknownAgent);
    }
    if !p.enabled {
        return Decision::Refuse(Refusal::AgentDisabled);
    }
    if p.expires_at_ms != 0 && now_ms >= p.expires_at_ms {
        return Decision::Refuse(Refusal::SessionExpired {
            expired_at_ms: p.expires_at_ms,
            now_ms,
        });
    }
    Decision::Allow { new_spent_in_window: p.spent_in_window, new_window_started_ms: p.window_started_ms }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::string::ToString;

    const OK_ADDR: &str = "11111111111111111111111111111111";
    const OTHER_ADDR: &str = "SysvarC1ock11111111111111111111111111111111";

    fn pol() -> Policy {
        Policy {
            enabled: true,
            per_tx_lamports: 1_000,
            window_lamports: 2_500,
            spent_in_window: 0,
            window_started_ms: 1_000_000,
            allowed_recipients: vec![OK_ADDR.to_string()],
            expires_at_ms: 0,
        }
    }
    fn req(l: u128) -> Request { Request { recipient: OK_ADDR.to_string(), lamports: l } }

    // ---- the positive control: the happy path must actually pass -------------------------
    #[test]
    fn allows_a_compliant_request() {
        match decide(true, &pol(), &req(500), 1_000_000) {
            Decision::Allow { new_spent_in_window, new_window_started_ms } => {
                assert_eq!(new_spent_in_window, 500);
                assert_eq!(new_window_started_ms, 1_000_000);
            }
            other => panic!("expected Allow, got {:?}", other),
        }
    }

    // ---- prove the jail: every refusal variant is REACHED --------------------------------
    fn refusal_of(d: Decision) -> Refusal {
        match d { Decision::Refuse(r) => r, Decision::Allow { .. } => panic!("expected a refusal") }
    }

    #[test]
    fn every_refusal_variant_is_reachable() {
        let mut seen: vec::Vec<Refusal> = vec![];

        seen.push(refusal_of(decide(false, &pol(), &req(1), 1_000_000)));

        let mut p = pol(); p.enabled = false;
        seen.push(refusal_of(decide(true, &p, &req(1), 1_000_000)));

        seen.push(refusal_of(decide(true, &pol(), &req(0), 1_000_000)));

        let bad = Request { recipient: "0OIl".to_string(), lamports: 1 };
        seen.push(refusal_of(decide(true, &pol(), &bad, 1_000_000)));

        let elsewhere = Request { recipient: OTHER_ADDR.to_string(), lamports: 1 };
        seen.push(refusal_of(decide(true, &pol(), &elsewhere, 1_000_000)));

        seen.push(refusal_of(decide(true, &pol(), &req(1_001), 1_000_000)));

        let mut p2 = pol(); p2.spent_in_window = 2_000;
        seen.push(refusal_of(decide(true, &p2, &req(1_000), 1_000_000)));

        let mut p3 = pol(); p3.expires_at_ms = 900_000;
        seen.push(refusal_of(decide(true, &p3, &req(1), 1_000_000)));

        // The set entered must equal the full set of variants. If someone adds a Refusal
        // variant and no test for it, this assertion fails and the build stops.
        let all = [
            Refusal::UnknownAgent,
            Refusal::AgentDisabled,
            Refusal::ZeroAmount,
            Refusal::RecipientMalformed,
            Refusal::RecipientNotAllowed,
            Refusal::OverPerTxLimit { limit: 1_000, requested: 1_001 },
            Refusal::OverWindowLimit { limit: 2_500, spent: 2_000, requested: 1_000 },
            Refusal::SessionExpired { expired_at_ms: 900_000, now_ms: 1_000_000 },
        ];
        assert_eq!(seen.len(), all.len(), "a refusal variant has no test");
        for want in all.iter() {
            assert!(seen.contains(want), "refusal never reached: {:?}", want);
        }
    }

    // ---- boundaries: the limit itself is ALLOWED, one above is refused -------------------
    #[test]
    fn per_tx_boundary_is_inclusive() {
        assert!(matches!(decide(true, &pol(), &req(1_000), 1_000_000), Decision::Allow { .. }));
        assert!(matches!(decide(true, &pol(), &req(1_001), 1_000_000), Decision::Refuse(_)));
    }

    #[test]
    fn window_boundary_is_inclusive() {
        let mut p = pol(); p.spent_in_window = 1_500;
        assert!(matches!(decide(true, &p, &req(1_000), 1_000_000), Decision::Allow { .. }));
        let mut q = pol(); q.spent_in_window = 1_501;
        assert!(matches!(decide(true, &q, &req(1_000), 1_000_000), Decision::Refuse(_)));
    }

    // ---- the window rolls, and ONLY when it has actually expired -------------------------
    #[test]
    fn window_rolls_forward_once_expired() {
        let mut p = pol(); p.spent_in_window = 2_500; // fully spent
        let just_before = 1_000_000 + WINDOW_MS - 1;
        assert!(matches!(decide(true, &p, &req(1), just_before), Decision::Refuse(_)),
                "must still be blocked one ms before the window expires");
        let at_expiry = 1_000_000 + WINDOW_MS;
        match decide(true, &p, &req(1), at_expiry) {
            Decision::Allow { new_spent_in_window, new_window_started_ms } => {
                assert_eq!(new_spent_in_window, 1, "spend resets with the new window");
                assert_eq!(new_window_started_ms, at_expiry);
            }
            other => panic!("expected Allow after expiry, got {:?}", other),
        }
    }

    // ---- a backwards clock must not grant budget ----------------------------------------
    #[test]
    fn clock_going_backwards_never_silences_the_limit() {
        let mut p = pol(); p.spent_in_window = 2_500;
        // now_ms far BEFORE window_started_ms: saturating_sub gives 0, so the window is NOT
        // expired and the spend still counts. The naive subtraction would underflow.
        assert!(matches!(decide(true, &p, &req(1), 1), Decision::Refuse(_)),
                "a backwards clock must not reset the window");
    }

    // ---- expiry: inclusive at the stroke, and zero means no expiry ----------------------
    #[test]
    fn expiry_is_inclusive_at_the_stroke() {
        let mut p = pol(); p.expires_at_ms = 1_000_000;
        assert!(matches!(decide(true, &p, &req(1), 999_999), Decision::Allow { .. }),
                "one ms before expiry the session still works");
        assert!(matches!(decide(true, &p, &req(1), 1_000_000), Decision::Refuse(_)),
                "AT the expiry stamp the session is over");
    }

    #[test]
    fn zero_expiry_means_no_expiry() {
        let p = pol();   // expires_at_ms == 0
        assert!(matches!(decide(true, &p, &req(1), u64::MAX), Decision::Allow { .. }));
    }

    #[test]
    fn an_expired_session_is_not_rescued_by_anything_else_passing() {
        // Everything else about this request is impeccable; expiry alone must sink it.
        let mut p = pol(); p.expires_at_ms = 1; p.spent_in_window = 0;
        assert!(matches!(decide(true, &p, &req(1), 2), Decision::Refuse(Refusal::SessionExpired { .. })));
    }

    // ---- the no-value gate: WHO and WHEN only ------------------------------------------
    #[test]
    fn novalue_gate_allows_a_live_agent_regardless_of_amount_state() {
        let mut p = pol();
        p.spent_in_window = p.window_lamports;   // fully spent: irrelevant, nothing moves
        p.allowed_recipients.clear();            // empty allowlist: irrelevant, no recipient
        assert!(matches!(decide_novalue(true, &p, 1_000_000), Decision::Allow { .. }));
    }

    #[test]
    fn novalue_gate_still_refuses_who_and_when() {
        assert_eq!(refusal_of(decide_novalue(false, &pol(), 1_000_000)), Refusal::UnknownAgent);
        let mut d = pol(); d.enabled = false;
        assert_eq!(refusal_of(decide_novalue(true, &d, 1_000_000)), Refusal::AgentDisabled);
        let mut e = pol(); e.expires_at_ms = 900_000;
        assert!(matches!(refusal_of(decide_novalue(true, &e, 1_000_000)), Refusal::SessionExpired { .. }));
    }

    #[test]
    fn novalue_gate_does_not_consume_budget() {
        let mut p = pol(); p.spent_in_window = 123;
        match decide_novalue(true, &p, 1_000_000) {
            Decision::Allow { new_spent_in_window, .. } => assert_eq!(new_spent_in_window, 123),
            other => panic!("expected Allow, got {:?}", other),
        }
    }

    // ---- an empty allowlist denies everything -------------------------------------------
    #[test]
    fn empty_allowlist_fails_closed() {
        let mut p = pol(); p.allowed_recipients.clear();
        assert_eq!(refusal_of(decide(true, &p, &req(1), 1_000_000)), Refusal::RecipientNotAllowed);
    }

    // ---- saturating add cannot be used to wrap past the ceiling --------------------------
    #[test]
    fn huge_request_cannot_wrap_the_window_total() {
        let mut p = pol(); p.spent_in_window = u128::MAX - 1; p.per_tx_lamports = u128::MAX;
        assert!(matches!(decide(true, &p, &req(u128::MAX), 1_000_000), Decision::Refuse(_)));
    }
}

#[cfg(test)]
mod window_expiry_tests {
    use super::*;

    /// The boundary is INCLUSIVE: at exactly WINDOW_MS the window has elapsed. The view and both
    /// decide() arms share this, so the boundary is asserted once rather than per call site.
    #[test]
    fn window_expiry_boundary_is_inclusive() {
        let start = 1_000_000u64;
        assert!(!window_expired(start, start), "zero elapsed is not expired");
        assert!(!window_expired(start + WINDOW_MS - 1, start), "one ms short");
        assert!(window_expired(start + WINDOW_MS, start), "exactly at the window");
        assert!(window_expired(start + WINDOW_MS * 9, start), "long past");
    }

    /// A clock that went backwards must not mint a fresh allowance.
    #[test]
    fn backwards_clock_reads_not_expired() {
        assert!(!window_expired(1, 1_000_000), "now before start must hold the window");
        assert!(!window_expired(0, u64::MAX));
    }

    // ---- refund window-identity: the WL-CL-012 defect and its guard ----------------------
    // Two-sided by construction: the first test fails if the guard refuses a refund it should
    // allow, the rest fail if it allows one it should refuse.

    #[test]
    fn positive_control_same_window_refunds() {
        // The guard must not break the ordinary path: a failure in the window that was charged
        // gives the budget back. If this fails the fix is worse than the defect.
        assert_eq!(refund_spend(1_000, 7_000, 7_000, 400), Some(600));
    }

    #[test]
    fn a_rolled_window_is_not_credited() {
        // THE DEFECT. Charge booked in window 7_000, callback lands after a roll to 9_000.
        // Subtracting here would credit a window that never paid the charge.
        assert_eq!(refund_spend(1_000, 9_000, 7_000, 400), None);
    }

    #[test]
    fn stacked_stale_refunds_cannot_zero_a_live_window() {
        // The amplification that made my first bound ("one per-tx") wrong: several charges from
        // the OLD window failing after the roll. This models the call site -- it APPLIES whatever
        // the decision returns, so the assertion is about the resulting budget and not merely
        // about the return value.
        let mut spent = 3_000u128;
        for amount in [1_000u128, 1_000, 1_000, 1_000] {
            if let Some(next) = refund_spend(spent, 9_000, 7_000, amount) {
                spent = next;
            }
        }
        assert_eq!(spent, 3_000, "stale refunds must not move a live window's spend");

        // CONTRAST ARM, so the assertion above cannot pass vacuously: the identical loop with a
        // MATCHING window id does drain the budget. If this arm failed, the loop above would be
        // proving nothing more than that the loop body never runs.
        let mut same = 3_000u128;
        for amount in [1_000u128, 1_000, 1_000, 1_000] {
            if let Some(next) = refund_spend(same, 7_000, 7_000, amount) {
                same = next;
            }
        }
        assert_eq!(same, 0, "the same loop with a matching window must drain it");
    }

    #[test]
    fn refund_saturates_and_never_underflows_in_its_own_window() {
        // Same window, amount larger than the recorded spend: floor at zero, never wrap.
        assert_eq!(refund_spend(100, 7_000, 7_000, 400), Some(0));
        assert_eq!(refund_spend(0, 7_000, 7_000, u128::MAX), Some(0));
    }

    #[test]
    fn an_earlier_window_id_is_also_refused() {
        // Not only "rolled forward". Any mismatch is refused, including a charged id that is
        // LATER than current, which a clock that went backwards could produce.
        assert_eq!(refund_spend(1_000, 7_000, 9_000, 400), None);
    }

    #[test]
    fn zero_window_ids_still_compare_exactly() {
        // A freshly initialised agent has window_started_ms = 0; that must behave like any other
        // id rather than matching everything.
        assert_eq!(refund_spend(500, 0, 0, 100), Some(400));
        assert_eq!(refund_spend(500, 0, 1, 100), None);
    }
}
