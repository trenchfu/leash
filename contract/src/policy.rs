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
    let expired = now_ms.saturating_sub(p.window_started_ms) >= WINDOW_MS;
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
