//! Leash — an agent wallet that cryptographically cannot overspend.
//!
//! The agent does not hold the Solana key. It cannot: under NEAR Chain Signatures the foreign key
//! is derived from `(predecessor_account_id, path)` — verified in `near/mpc` @ d0fc87b1,
//! `api/sign.rs:32` and `kdf.rs:10`, whose `derive_tweak(predecessor_id, path)` admits no other
//! input. So the key belongs to THIS CONTRACT's account, and the only route to a signature runs
//! through `request_transfer` below, which refuses before it signs.
//!
//! TWO THINGS THIS DOES NOT GIVE YOU, STATED HERE RATHER THAN DISCOVERED LATER:
//!
//! 1. The key follows the ACCOUNT, not the code. A full-access key on this contract's account can
//!    redeploy it with no policy at all, or sign as the account directly. The guarantee therefore
//!    requires a LOCKED account — zero full-access keys. That is an off-chain property; the
//!    harness proves it against the live account rather than this file asserting it.
//! 2. Trust moves, it does not vanish: signatures come from an MPC committee (measured 11-of-16,
//!    epoch 14, 2026-11-03). Leash removes unilateral agent control; it does not remove the
//!    committee.

extern crate alloc;
pub mod policy;
pub mod solana;

use near_sdk::borsh::BorshSerialize;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::IterableMap;
use near_sdk::{
    env, near, require, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError,
};
use policy::{decide, decide_novalue, Decision, Policy, Refusal, Request};

/// Deposit `v1.signer.sign` requires: 1 yoctoNEAR
/// (near-mpc-contract-interface/src/deposits.rs:4, read at source).
const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);
/// Gas forwarded to the MPC sign call.
const SIGN_GAS: Gas = Gas::from_tgas(250);
/// Gas reserved for our own callback.
const CALLBACK_GAS: Gas = Gas::from_tgas(30);
/// Ed25519 domain. Live domain 1 on mainnet is Frost/Ed25519/Sign, read from `v1.signer.state`
/// at block 222869350; `sign.rs` routes `Protocol::Frost` to `payload.as_eddsa()`.
const DOMAIN_ED25519: u32 = 1;

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum Key {
    /// v1 agent records, written before `Policy` gained `expires_at_ms`. Left in place
    /// deliberately: move-never-delete, and nothing reads them under the new schema.
    Agents,
    /// v2: `Policy` with session expiry.
    AgentsV2,
    /// Bounded ring of decision records. A refusal that reverts leaves no trace, so refusals are
    /// now RETURNED rather than thrown, and written here on the way out.
    Log,
}

/// One decision, kept. `allowed` is the fact; `detail` carries the exact stable refusal string
/// so a reader never has to re-derive why.
#[derive(BorshSerialize, near_sdk::borsh::BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Record {
    pub ts_ms: near_sdk::json_types::U64,
    pub agent: AccountId,
    pub recipient: alloc::string::String,
    pub lamports: near_sdk::json_types::U128,
    pub allowed: bool,
    pub detail: alloc::string::String,
}

/// The verdict `request_transfer` hands back. A refusal is an ORDINARY OUTCOME here, not an
/// exception: panicking would revert the transaction and erase the very record a human wants.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Verdict {
    pub allowed: bool,
    /// The stable `LEASH_REFUSED: ...` string when refused, empty when allowed.
    pub reason: alloc::string::String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct PolicyView {
    pub enabled: bool,
    pub per_tx_lamports: near_sdk::json_types::U128,
    pub window_lamports: near_sdk::json_types::U128,
    pub spent_in_window: near_sdk::json_types::U128,
    pub window_started_ms: near_sdk::json_types::U64,
    pub allowed_recipients: alloc::vec::Vec<alloc::string::String>,
    pub expires_at_ms: near_sdk::json_types::U64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Leash {
    owner: AccountId,
    mpc_contract: AccountId,
    derivation_path: alloc::string::String,
    /// The Solana address this contract controls, base58. Set once at init from the derivation
    /// of (this account, path); the harness verifies it independently rather than trusting it.
    solana_address: alloc::string::String,
    agents: IterableMap<AccountId, Policy>,
    /// Ring buffer, newest appended. Bounded because NEAR charges for storage and an unbounded
    /// audit log is a slow funding leak, not a feature.
    log: near_sdk::store::Vector<Record>,
    log_cap: u32,
    /// Lifetime counts, which survive the ring dropping old entries.
    total_allowed: u64,
    total_refused: u64,
}

#[near]
impl Leash {
    #[init]
    pub fn new(
        owner: AccountId,
        mpc_contract: AccountId,
        derivation_path: alloc::string::String,
        solana_address: alloc::string::String,
    ) -> Self {
        require!(
            solana::decode_pubkey(&solana_address).is_some(),
            "solana_address must be a 32-byte base58 key"
        );
        Self {
            owner,
            mpc_contract,
            derivation_path,
            solana_address,
            agents: IterableMap::new(Key::AgentsV2),
            log: near_sdk::store::Vector::new(Key::Log),
            log_cap: 256,
            total_allowed: 0,
            total_refused: 0,
        }
    }

    /// Migrate state after `Policy` gained `expires_at_ms`.
    ///
    /// Adding a field to a Borsh-serialized map VALUE is a breaking change: records written under
    /// the old layout cannot be deserialized under the new one, and the failure surfaces as a
    /// panic on first read, not at deploy time. So this does not try to reinterpret them. It
    /// rebuilds the map under a NEW storage prefix and leaves the old records untouched.
    ///
    /// Consequence, stated rather than discovered: **every agent policy must be set again after
    /// migrating.** An agent whose policy is not re-set is refused as `unknown agent` — the
    /// failure is closed, which is the only acceptable direction for this to break in.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        // The OLD Policy, reproduced exactly as it was before `expires_at_ms` existed. It is
        // never constructed or read -- it exists only so the old map's TYPE is nameable.
        #[derive(near_sdk::borsh::BorshSerialize, near_sdk::borsh::BorshDeserialize)]
        #[borsh(crate = "near_sdk::borsh")]
        struct OldPolicy {
            enabled: bool,
            per_tx_lamports: u128,
            window_lamports: u128,
            spent_in_window: u128,
            window_started_ms: u64,
            allowed_recipients: alloc::vec::Vec<alloc::string::String>,
        }
        #[derive(near_sdk::borsh::BorshDeserialize)]
        #[borsh(crate = "near_sdk::borsh")]
        struct OldLeash {
            owner: AccountId,
            mpc_contract: AccountId,
            derivation_path: alloc::string::String,
            solana_address: alloc::string::String,
            // Borsh requires the WHOLE buffer to be consumed: omitting this field fails with
            // "Cannot deserialize the contract state." IterableMap deserializes only its own
            // metadata, so naming it here does NOT touch a single old record.
            agents: IterableMap<AccountId, OldPolicy>,
        }
        let old: OldLeash = env::state_read().unwrap_or_else(|| env::panic_str("no state to migrate"));
        Self {
            owner: old.owner,
            mpc_contract: old.mpc_contract,
            derivation_path: old.derivation_path,
            solana_address: old.solana_address,
            agents: IterableMap::new(Key::AgentsV2),
            log: near_sdk::store::Vector::new(Key::Log),
            log_cap: 256,
            total_allowed: 0,
            total_refused: 0,
        }
    }

    /// Migrate v2 -> v3: `Policy` is unchanged, so the agent map is REUSED rather than rebuilt.
    /// Only the Leash head gained fields, which is why this one keeps policies and the earlier
    /// migration could not.
    #[private]
    #[init(ignore_state)]
    pub fn migrate_v3() -> Self {
        #[derive(near_sdk::borsh::BorshDeserialize)]
        #[borsh(crate = "near_sdk::borsh")]
        struct V2 {
            owner: AccountId,
            mpc_contract: AccountId,
            derivation_path: alloc::string::String,
            solana_address: alloc::string::String,
            agents: IterableMap<AccountId, Policy>,
        }
        let old: V2 = env::state_read().unwrap_or_else(|| env::panic_str("no v2 state"));
        Self {
            owner: old.owner,
            mpc_contract: old.mpc_contract,
            derivation_path: old.derivation_path,
            solana_address: old.solana_address,
            agents: old.agents,
            log: near_sdk::store::Vector::new(Key::Log),
            log_cap: 256,
            total_allowed: 0,
            total_refused: 0,
        }
    }

    fn write_record(&mut self, agent: &AccountId, recipient: &alloc::string::String,
                    lamports: u128, allowed: bool, detail: alloc::string::String) {
        if allowed { self.total_allowed += 1 } else { self.total_refused += 1 }
        // Bounded: drop the oldest when full. `swap_remove(0)` would reorder the ring, so the
        // whole buffer shifts instead -- correctness over a micro-optimisation on a 256-slot log.
        if self.log.len() >= self.log_cap {
            let keep: alloc::vec::Vec<Record> =
                (1..self.log.len()).filter_map(|i| self.log.get(i).cloned()).collect();
            self.log.clear();
            for r in keep { self.log.push(r) }
        }
        self.log.push(Record {
            ts_ms: env::block_timestamp_ms().into(),
            agent: agent.clone(),
            recipient: recipient.clone(),
            lamports: lamports.into(),
            allowed,
            detail,
        });
    }

    // ---- owner-only policy administration --------------------------------------------------

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
    }

    pub fn set_agent_policy(
        &mut self,
        agent: AccountId,
        per_tx_lamports: near_sdk::json_types::U128,
        window_lamports: near_sdk::json_types::U128,
        allowed_recipients: alloc::vec::Vec<alloc::string::String>,
        expires_at_ms: near_sdk::json_types::U64,
    ) {
        self.assert_owner();
        for r in allowed_recipients.iter() {
            require!(solana::decode_pubkey(r).is_some(), "allowlist entry is not a valid address");
        }
        let existing = self.agents.get(&agent);
        let (spent, started) = match existing {
            Some(p) => (p.spent_in_window, p.window_started_ms),
            None => (0, env::block_timestamp_ms()),
        };
        self.agents.insert(
            agent,
            Policy {
                enabled: true,
                per_tx_lamports: per_tx_lamports.0,
                window_lamports: window_lamports.0,
                spent_in_window: spent,
                window_started_ms: started,
                allowed_recipients,
                expires_at_ms: expires_at_ms.0,
            },
        );
    }

    /// Reset an agent's rolling-window spend. Found missing while running the jail harness: the
    /// harness deliberately spends an agent to its ceiling, and there was no way to undo that
    /// without deleting the agent. Owner-only, and it does NOT touch limits or the allowlist.
    pub fn reset_agent_window(&mut self, agent: AccountId) {
        self.assert_owner();
        let now = env::block_timestamp_ms();
        let p = self.agents.get_mut(&agent).unwrap_or_else(|| env::panic_str("unknown agent"));
        p.spent_in_window = 0;
        p.window_started_ms = now;
    }

    pub fn set_agent_enabled(&mut self, agent: AccountId, enabled: bool) {
        self.assert_owner();
        let p = self.agents.get_mut(&agent).unwrap_or_else(|| env::panic_str("unknown agent"));
        p.enabled = enabled;
    }

    // ---- the only path to a signature --------------------------------------------------------

    /// The agent supplies PARAMETERS, never signable bytes. The contract builds the Solana
    /// message itself, so the agent cannot express a transfer the policy did not authorise.
    #[payable]
    pub fn request_transfer(
        &mut self,
        recipient: alloc::string::String,
        lamports: near_sdk::json_types::U128,
        recent_blockhash: alloc::string::String,
    ) -> near_sdk::PromiseOrValue<Verdict> {
        let caller = env::predecessor_account_id();
        let known = self.agents.contains_key(&caller);
        let fallback = Policy {
            enabled: false,
            per_tx_lamports: 0,
            window_lamports: 0,
            spent_in_window: 0,
            window_started_ms: 0,
            allowed_recipients: alloc::vec::Vec::new(),
            expires_at_ms: 0,
        };
        let pol = self.agents.get(&caller).cloned().unwrap_or(fallback);
        let req = Request { recipient: recipient.clone(), lamports: lamports.0 };

        match decide(known, &pol, &req, env::block_timestamp_ms()) {
            Decision::Refuse(r) => {
                // RETURNED, not thrown. A panic reverts, and a reverted refusal leaves no record
                // of the thing a human most wants to see. Nothing has been mutated at this point,
                // so there is no safety the panic was providing.
                let reason = refusal_message(&r);
                self.write_record(&caller, &recipient, lamports.0, false, reason.clone());
                env::log_str(&reason);
                near_sdk::PromiseOrValue::Value(Verdict { allowed: false, reason })
            }
            Decision::Allow { new_spent_in_window, new_window_started_ms } => {
                // Record the spend BEFORE the async call. NEAR cross-contract calls yield, so a
                // second request could otherwise pass the same check against a stale total and
                // both would be allowed. The callback refunds this if signing failed.
                if let Some(p) = self.agents.get_mut(&caller) {
                    p.spent_in_window = new_spent_in_window;
                    p.window_started_ms = new_window_started_ms;
                }

                let bh = solana::decode_pubkey(&recent_blockhash)
                    .unwrap_or_else(|| env::panic_str("recent_blockhash is not 32 bytes base58"));
                let from = solana::decode_pubkey(&self.solana_address)
                    .unwrap_or_else(|| env::panic_str("stored solana_address is invalid"));
                let to = solana::decode_pubkey(&recipient)
                    .unwrap_or_else(|| env::panic_str("recipient is not 32 bytes base58"));

                let msg = solana::build_transfer_message(&from, &to, lamports.0 as u64, &bh);

                // The wire format is NOT a guess: near-mpc-crypto-types/src/sign.rs:32 renames
                // the field to `payload_v2` (plain `payload` is the LEGACY untagged 32-byte ECDSA
                // field), and primitives.rs:100 tags Payload::Eddsa with #[serde(with =
                // "hex_serde")] -- so the bytes are HEX, not base64. Both were read at source
                // after a first attempt guessed base64 under `payload` and was rejected with
                // "invalid type: map, expected an array of length 32".
                let args = near_sdk::serde_json::json!({
                    "request": {
                        "payload_v2": { "Eddsa": to_hex(&msg) },
                        "path": self.derivation_path,
                        "domain_id": DOMAIN_ED25519,
                    }
                })
                .to_string()
                .into_bytes();

                self.write_record(&caller, &recipient, lamports.0, true,
                                  "signature requested".into());
                near_sdk::PromiseOrValue::Promise(Promise::new(self.mpc_contract.clone())
                    .function_call("sign".to_string(), args, SIGN_DEPOSIT, SIGN_GAS)
                    .then(
                        Promise::new(env::current_account_id()).function_call(
                            "on_signed".to_string(),
                            near_sdk::serde_json::json!({
                                "agent": caller,
                                "lamports": lamports,
                            })
                            .to_string()
                            .into_bytes(),
                            NearToken::from_yoctonear(0),
                            CALLBACK_GAS,
                        ),
                    ))
            }
        }
    }

    /// Leg 1 of the teletask action suite: accept a task. Built from PARAMETERS; this contract
    /// emits the instruction itself, so the site cannot hand it bytes to sign.
    #[payable]
    pub fn request_accept_task(
        &mut self,
        task_escrow: alloc::string::String,
        buyer: alloc::string::String,
        config: alloc::string::String,
        task_id: near_sdk::json_types::U64,
        layer: u16,
        recent_blockhash: alloc::string::String,
    ) -> near_sdk::PromiseOrValue<Verdict> {
        self.signed_novalue_leg("accept_task", task_escrow, buyer, Some(config), task_id,
                                layer, None, recent_blockhash)
    }

    /// Leg 3: submit evidence plus the TTEV1 memo in one transaction.
    ///
    /// `ev` is the compact evidence JSON. THE CONTRACT HASHES IT ITSELF and puts the same bytes in
    /// the memo, so the check-bot's hash comparison cannot fail through a mismatch between what was
    /// hashed and what was published. Accepting a caller-supplied hash would reintroduce exactly
    /// the gap this design exists to close.
    #[payable]
    pub fn request_submit_evidence(
        &mut self,
        task_escrow: alloc::string::String,
        buyer: alloc::string::String,
        task_id: near_sdk::json_types::U64,
        ev: alloc::string::String,
        recent_blockhash: alloc::string::String,
    ) -> near_sdk::PromiseOrValue<Verdict> {
        self.signed_novalue_leg("submit_evidence", task_escrow, buyer, None, task_id, 0,
                                Some(ev), recent_blockhash)
    }

    fn signed_novalue_leg(
        &mut self,
        leg: &str,
        task_escrow: alloc::string::String,
        buyer: alloc::string::String,
        config: Option<alloc::string::String>,
        task_id: near_sdk::json_types::U64,
        layer: u16,
        ev: Option<alloc::string::String>,
        recent_blockhash: alloc::string::String,
    ) -> near_sdk::PromiseOrValue<Verdict> {
        let caller = env::predecessor_account_id();
        let known = self.agents.contains_key(&caller);
        let pol = self.agents.get(&caller).cloned().unwrap_or(Policy {
            enabled: false, per_tx_lamports: 0, window_lamports: 0, spent_in_window: 0,
            window_started_ms: 0, allowed_recipients: alloc::vec::Vec::new(), expires_at_ms: 0,
        });
        if let Decision::Refuse(r) = decide_novalue(known, &pol, env::block_timestamp_ms()) {
            let reason = refusal_message(&r);
            self.write_record(&caller, &alloc::string::String::new(), 0, false, reason.clone());
            env::log_str(&reason);
            return near_sdk::PromiseOrValue::Value(Verdict { allowed: false, reason });
        }

        let bad = |w: &str| -> ! { env::panic_str(w) };
        let from = solana::decode_pubkey(&self.solana_address).unwrap_or_else(|| bad("bad solana_address"));
        let esc = solana::decode_pubkey(&task_escrow).unwrap_or_else(|| bad("bad task_escrow"));
        let buy = solana::decode_pubkey(&buyer).unwrap_or_else(|| bad("bad buyer"));
        let bh = solana::decode_pubkey(&recent_blockhash).unwrap_or_else(|| bad("bad recent_blockhash"));

        let msg = if leg == "accept_task" {
            let cfg = solana::decode_pubkey(&config.unwrap()).unwrap_or_else(|| bad("bad config"));
            solana::build_accept_task_message(&from, &esc, &buy, &cfg, task_id.0, layer, &bh)
        } else {
            let e = ev.unwrap();
            let h = env::sha256(e.as_bytes());
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&h);
            solana::build_submit_evidence_message(&from, &esc, &buy, task_id.0, &e, &hash, &bh)
        }
        .unwrap_or_else(|| bad("message build failed"));

        self.write_record(&caller, &task_escrow, 0, true,
                          alloc::format!("{} signature requested (no lamports)", leg));

        let args = near_sdk::serde_json::json!({
            "request": {
                "payload_v2": { "Eddsa": to_hex(&msg) },
                "path": self.derivation_path,
                "domain_id": DOMAIN_ED25519,
            }
        }).to_string().into_bytes();

        near_sdk::PromiseOrValue::Promise(
            Promise::new(self.mpc_contract.clone())
                .function_call("sign".to_string(), args, SIGN_DEPOSIT, SIGN_GAS))
    }

    /// Refund the optimistic spend when signing failed, so a failed signature does not silently
    /// consume the agent's budget.
    #[private]
    pub fn on_signed(
        &mut self,
        agent: AccountId,
        lamports: near_sdk::json_types::U128,
        #[callback_result] result: Result<near_sdk::serde_json::Value, PromiseError>,
    ) -> Verdict {
        match result {
            Ok(_) => Verdict { allowed: true, reason: alloc::string::String::new() },
            Err(_) => {
                if let Some(p) = self.agents.get_mut(&agent) {
                    p.spent_in_window = p.spent_in_window.saturating_sub(lamports.0);
                }
                let reason: alloc::string::String = "LEASH_SIGN_FAILED: refunded".into();
                self.write_record(&agent, &alloc::string::String::new(), lamports.0, false,
                                  reason.clone());
                Verdict { allowed: false, reason }
            }
        }
    }

    // ---- views -------------------------------------------------------------------------------

    pub fn get_solana_address(&self) -> alloc::string::String { self.solana_address.clone() }
    pub fn get_owner(&self) -> AccountId { self.owner.clone() }
    pub fn get_derivation_path(&self) -> alloc::string::String { self.derivation_path.clone() }
    pub fn get_mpc_contract(&self) -> AccountId { self.mpc_contract.clone() }

    /// Newest first, capped. The console asks for what it can render, not the whole ring.
    pub fn get_recent(&self, limit: u32) -> alloc::vec::Vec<Record> {
        let n = self.log.len();
        let take = core::cmp::min(limit, n);
        (0..take).filter_map(|i| self.log.get(n - 1 - i).cloned()).collect()
    }

    /// Enumerate agents. Without this a console has to be told which agent to show.
    pub fn list_agents(&self) -> alloc::vec::Vec<AccountId> {
        self.agents.keys().cloned().collect()
    }

    /// Lifetime counts, which outlive the ring dropping old entries.
    pub fn get_totals(&self) -> (u64, u64, u32) {
        (self.total_allowed, self.total_refused, self.log.len())
    }

    pub fn get_agent_policy(&self, agent: AccountId) -> Option<PolicyView> {
        self.agents.get(&agent).map(|p| PolicyView {
            enabled: p.enabled,
            per_tx_lamports: p.per_tx_lamports.into(),
            window_lamports: p.window_lamports.into(),
            spent_in_window: p.spent_in_window.into(),
            window_started_ms: p.window_started_ms.into(),
            allowed_recipients: p.allowed_recipients.clone(),
            expires_at_ms: p.expires_at_ms.into(),
        })
    }
}

/// Lowercase hex, written here rather than pulled in as a dependency: it is six lines and the
/// MPC contract's wire format depends on it being exactly right.
fn to_hex(bytes: &[u8]) -> alloc::string::String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0x0f) as usize] as char);
    }
    out
}

/// Refusal messages are STABLE STRINGS, because the harness asserts on them. A guard whose
/// refusal reason you cannot distinguish from another's is a guard you cannot prove.
pub fn refusal_message(r: &Refusal) -> alloc::string::String {
    use alloc::format;
    match r {
        Refusal::UnknownAgent => "LEASH_REFUSED: unknown agent".into(),
        Refusal::AgentDisabled => "LEASH_REFUSED: agent disabled".into(),
        Refusal::ZeroAmount => "LEASH_REFUSED: zero amount".into(),
        Refusal::RecipientMalformed => "LEASH_REFUSED: recipient malformed".into(),
        Refusal::RecipientNotAllowed => "LEASH_REFUSED: recipient not allowed".into(),
        Refusal::SessionExpired { expired_at_ms, now_ms } => format!(
            "LEASH_REFUSED: session expired (expired at {}, now {})", expired_at_ms, now_ms
        ),
        Refusal::OverPerTxLimit { limit, requested } => {
            format!("LEASH_REFUSED: over per-tx limit (limit {}, requested {})", limit, requested)
        }
        Refusal::OverWindowLimit { limit, spent, requested } => format!(
            "LEASH_REFUSED: over window limit (limit {}, spent {}, requested {})",
            limit, spent, requested
        ),
    }
}
