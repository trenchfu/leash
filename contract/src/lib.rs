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
pub mod spl;

use near_sdk::borsh::BorshSerialize;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::IterableMap;
use near_sdk::{
    env, near, require, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError,
};
use policy::{decide, decide_novalue, Decision, Policy, Refusal, Request, WINDOW_MS};

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
    /// v4: per-agent, per-mint SPL rules, keyed "<agent>|<mint>". A NEAR account id cannot
    /// contain '|' and a base58 mint cannot either, so the join is unambiguous.
    MintRules,
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

/// The mint profile as the OWNER states it, over JSON. Every field is the owner's assertion about
/// an off-chain scan; this contract cannot read a Solana mint and does not pretend to.
/// Marks an audit row as an SPL row. ONE constant, used by the writer that emits `detail` and by
/// the parser that reads it back. Written out separately first; a producer and a parser that each
/// spell a format literal are free to drift, and the drift would be SILENT — the view would simply
/// label a token amount as lamports. Same fix as `policy::window_expired`.
pub const SPL_DETAIL_PREFIX: &str = "spl ";

/// A ring row with its amount's UNIT resolved, so a third party never has to parse `detail`.
///
/// `Record.lamports` carries lamports on a native row and MINT BASE UNITS on an SPL row — a
/// consequence of the field predating the SPL leg. Renaming it would be a storage migration for a
/// cosmetic gain. Resolving the unit in a VIEW costs no migration and, being derived from the
/// stored row at read time, it cannot disagree with what is stored.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct RecordView {
    pub ts_ms: near_sdk::json_types::U64,
    pub agent: AccountId,
    pub recipient: alloc::string::String,
    pub amount: near_sdk::json_types::U128,
    /// `"lamports"` or `"base_units"`. A UI must branch on this and never format `amount` alone.
    pub unit: alloc::string::String,
    /// The mint, present only on an SPL row. `None` on a native row.
    pub mint: Option<alloc::string::String>,
    pub allowed: bool,
    /// The raw stored detail, kept so nothing is hidden behind the parse.
    pub detail: alloc::string::String,
}

/// Resolve (unit, mint) from a stored `detail`. Pure, so it is unit-tested against the exact
/// strings the writer emits rather than against strings invented for the test.
///
/// A row with amount 0 is a value-free leg (the escrow legs move no lamports); it reports
/// `"lamports"`, and a UI showing 0 cannot misprice it either way.
/// Build the `detail` for a refused or refunded SPL row.
pub fn spl_detail_note(mint: &str, note: &str) -> alloc::string::String {
    alloc::format!("{}{} :: {}", SPL_DETAIL_PREFIX, mint, note)
}

/// Build the `detail` for an allowed SPL row.
pub fn spl_detail_allow(mint: &str, debit: u128) -> alloc::string::String {
    alloc::format!("{}{} debit {} base units, signature requested", SPL_DETAIL_PREFIX, mint, debit)
}

pub fn parse_detail_unit(detail: &str) -> (alloc::string::String, Option<alloc::string::String>) {
    match detail.strip_prefix(SPL_DETAIL_PREFIX) {
        Some(rest) => {
            let mint = rest.split_whitespace().next().unwrap_or("");
            ("base_units".into(), if mint.is_empty() { None } else { Some(mint.into()) })
        }
        None => ("lamports".into(), None),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct MintProfileIn {
    pub fee_bps: u16,
    pub max_fee: near_sdk::json_types::U64,
    pub transfer_hook: Option<alloc::string::String>,
    pub permanent_delegate: Option<alloc::string::String>,
    pub confidential: bool,
    /// Asserts every mutable extension authority is revoked. Without it the rest of this struct
    /// is a snapshot rather than a pin, and `decide_spl` refuses the mint outright.
    pub authorities_revoked: bool,
}

/// One entry of `list_mint_rules`: the rule plus the (agent, mint) pair it is keyed by, so a
/// reader never has to reconstruct the composite storage key itself.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct MintRuleEntry {
    pub agent: AccountId,
    pub mint: alloc::string::String,
    pub rule: MintRuleView,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct MintRuleView {
    pub enabled: bool,
    pub source_ata: alloc::string::String,
    pub decimals: u8,
    pub per_tx_amount: near_sdk::json_types::U128,
    pub window_amount: near_sdk::json_types::U128,
    /// STORED, and stale-prone exactly as in `PolicyView`. Never render as a remaining allowance.
    pub spent_in_window: near_sdk::json_types::U128,
    /// What `decide_spl` would charge against right now. Render THIS.
    pub spent_in_window_effective: near_sdk::json_types::U128,
    pub window_started_ms: near_sdk::json_types::U64,
    pub window_ms: near_sdk::json_types::U64,
    pub window_expires_at_ms: near_sdk::json_types::U64,
    pub allowed_destinations: alloc::vec::Vec<alloc::string::String>,
    pub token_program: alloc::string::String,
    pub pinned_hooks: alloc::vec::Vec<alloc::string::String>,
    pub fee_bps: u16,
    pub max_fee: near_sdk::json_types::U64,
    pub transfer_hook: Option<alloc::string::String>,
    pub permanent_delegate: Option<alloc::string::String>,
    pub confidential: bool,
    pub authorities_revoked: bool,
    /// `None` when this profile is acceptable, otherwise the objection `decide_spl` would raise.
    /// Exposed so a reader does not re-implement the objection order and disagree with us.
    pub profile_objection: Option<alloc::string::String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct PolicyView {
    pub enabled: bool,
    pub per_tx_lamports: near_sdk::json_types::U128,
    pub window_lamports: near_sdk::json_types::U128,
    /// STORED spend. This is the raw field and it goes STALE: `decide()` rolls the window at
    /// call time, but nothing writes 0 back until the next ALLOWED transfer, so after a window
    /// has elapsed this still reads the previous window's total. Do not render a remaining
    /// allowance from it — use `spent_in_window_effective`, which applies the roll at read time.
    pub spent_in_window: near_sdk::json_types::U128,
    /// Spend as `decide()` would see it RIGHT NOW: 0 once the window has elapsed. This is the
    /// field a UI should show, because it is the one the contract will actually enforce against.
    pub spent_in_window_effective: near_sdk::json_types::U128,
    pub window_started_ms: near_sdk::json_types::U64,
    /// Rolling-window length. Exposed because a third party cannot otherwise know when the
    /// window resets, and reading it out of our source instead would hardcode a constant that
    /// only this build guarantees — the same version-coupling that made an earlier verifier
    /// reject a correctly locked contract for lacking a method it predated.
    pub window_ms: near_sdk::json_types::U64,
    /// When the current window elapses, so a reader need not re-derive it. Equals
    /// `window_started_ms + window_ms`; already in the past when the window has rolled.
    pub window_expires_at_ms: near_sdk::json_types::U64,
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
    /// v4: SPL rules keyed "<agent>|<mint>".
    mint_rules: IterableMap<alloc::string::String, spl::MintRule>,
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
            mint_rules: IterableMap::new(Key::MintRules),
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
            mint_rules: IterableMap::new(Key::MintRules),
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
            mint_rules: IterableMap::new(Key::MintRules),
        }
    }

    /// v3 -> v4: adds the SPL rule map. Agent policies are KEPT, because `Policy` is unchanged
    /// and the map is reused by the same key.
    ///
    /// The v2 migration had to DROP policies; that was a property of what changed in `Policy`,
    /// not a property of migrations, and it would be the wrong lesson to carry forward. What does
    /// carry forward: `env::state_read` requires the WHOLE buffer consumed, so the old struct
    /// below must list the v3 fields exactly, in order, and nothing else.
    #[private]
    #[init(ignore_state)]
    pub fn migrate_v4() -> Self {
        #[derive(near_sdk::borsh::BorshDeserialize)]
        #[borsh(crate = "near_sdk::borsh")]
        struct V3 {
            owner: AccountId,
            mpc_contract: AccountId,
            derivation_path: alloc::string::String,
            solana_address: alloc::string::String,
            agents: IterableMap<AccountId, Policy>,
            log: near_sdk::store::Vector<Record>,
            log_cap: u32,
            total_allowed: u64,
            total_refused: u64,
        }
        let old: V3 = env::state_read().unwrap_or_else(|| env::panic_str("no v3 state"));
        Self {
            owner: old.owner,
            mpc_contract: old.mpc_contract,
            derivation_path: old.derivation_path,
            solana_address: old.solana_address,
            agents: old.agents,
            log: old.log,
            log_cap: old.log_cap,
            total_allowed: old.total_allowed,
            total_refused: old.total_refused,
            mint_rules: IterableMap::new(Key::MintRules),
        }
    }

    fn mint_key(agent: &AccountId, mint: &str) -> alloc::string::String {
        alloc::format!("{}|{}", agent, mint)
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
        // WL-CL-020, fixed 2026-11-11. `enabled` is CARRIED FORWARD for an agent that already
        // exists, and defaults to true only for a NEW one. It used to be hardcoded `true` here,
        // which made a renewal silently undo the owner's own `set_agent_enabled(false)`: a disable
        // could not survive the next policy renewal, and renewals are routine because the session
        // expiry is what forces them. Found the hard way -- the live testnet policy lapsed on
        // 2026-11-10 and renewing it on 2026-11-11 re-armed exactly this.
        //
        // WHY CARRY-FORWARD RATHER THAN A NEW ARGUMENT: enabling and disabling already has its own
        // setter (`set_agent_enabled`), so one concern gets one writer. An owner who means to
        // re-enable says so explicitly; an owner renewing an expiry is not asked to restate a
        // decision they already made. A record-rebuilding setter preserves only the fields it
        // enumerates, so every field this function does not take as an argument must be listed
        // here on purpose.
        let (spent, started, enabled) = match existing {
            Some(p) => (p.spent_in_window, p.window_started_ms, p.enabled),
            None => (0, env::block_timestamp_ms(), true),
        };
        self.agents.insert(
            agent,
            Policy {
                enabled,
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
                                // The window the charge was booked against. Without it the
                                // refund cannot tell which window it is reversing.
                                "charged_window_ms":
                                    near_sdk::json_types::U64(new_window_started_ms),
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
        charged_window_ms: near_sdk::json_types::U64,
        #[callback_result] result: Result<near_sdk::serde_json::Value, PromiseError>,
    ) -> Verdict {
        match result {
            Ok(_) => Verdict { allowed: true, reason: alloc::string::String::new() },
            Err(_) => {
                // Credit ONLY the window that was charged. See policy::refund_spend: a refund
                // carrying just an amount lands on whichever window is current, and stacked
                // stale refunds can zero a live window's recorded spend.
                let mut refunded = false;
                if let Some(p) = self.agents.get_mut(&agent) {
                    if let Some(next) = policy::refund_spend(
                        p.spent_in_window, p.window_started_ms, charged_window_ms.0, lamports.0,
                    ) {
                        p.spent_in_window = next;
                        refunded = true;
                    }
                }
                let reason: alloc::string::String = if refunded {
                    "LEASH_SIGN_FAILED: refunded".into()
                } else {
                    "LEASH_SIGN_FAILED: stale window, not refunded".into()
                };
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
    /// The ring with units resolved. Prefer this over `get_recent` for anything that DISPLAYS an
    /// amount; `get_recent` stays for consumers already handling the raw shape.
    pub fn get_recent_typed(&self, limit: u32) -> alloc::vec::Vec<RecordView> {
        self.get_recent(limit)
            .into_iter()
            .map(|r| {
                let (unit, mint) = parse_detail_unit(&r.detail);
                RecordView {
                    ts_ms: r.ts_ms, agent: r.agent, recipient: r.recipient,
                    amount: r.lamports, unit, mint, allowed: r.allowed, detail: r.detail,
                }
            })
            .collect()
    }

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
        let now = env::block_timestamp_ms();
        self.agents.get(&agent).map(|p| PolicyView {
            enabled: p.enabled,
            per_tx_lamports: p.per_tx_lamports.into(),
            window_lamports: p.window_lamports.into(),
            spent_in_window: p.spent_in_window.into(),
            // the SAME expiry test decide() uses, so the view cannot disagree with enforcement
            spent_in_window_effective: if policy::window_expired(now, p.window_started_ms) {
                0u128.into()
            } else {
                p.spent_in_window.into()
            },
            window_started_ms: p.window_started_ms.into(),
            window_ms: WINDOW_MS.into(),
            window_expires_at_ms: p.window_started_ms.saturating_add(WINDOW_MS).into(),
            allowed_recipients: p.allowed_recipients.clone(),
            expires_at_ms: p.expires_at_ms.into(),
        })
    }

    // ---- SPL / Token-2022 leg -----------------------------------------------------------------

    /// Owner pins a per-agent, per-mint rule.
    ///
    /// Every address is validated HERE, at write time, not only when a transfer is decided. A rule
    /// holding a typo would otherwise sit in storage looking exactly like protection and fail only
    /// when someone finally used it.
    pub fn set_mint_rule(
        &mut self,
        agent: AccountId,
        mint: alloc::string::String,
        source_ata: alloc::string::String,
        decimals: u8,
        per_tx_amount: near_sdk::json_types::U128,
        window_amount: near_sdk::json_types::U128,
        allowed_destinations: alloc::vec::Vec<alloc::string::String>,
        token_program: alloc::string::String,
        pinned_hooks: alloc::vec::Vec<alloc::string::String>,
        profile: MintProfileIn,
    ) {
        self.assert_owner();
        for (what, a) in [("mint", &mint), ("source_ata", &source_ata),
                          ("token_program", &token_program)] {
            require!(solana::decode_pubkey(a).is_some(),
                     alloc::format!("{} is not a 32-byte base58 key", what));
        }
        for d in allowed_destinations.iter() {
            require!(solana::decode_pubkey(d).is_some(),
                     "every allowed destination must be a 32-byte base58 key");
        }
        for h in pinned_hooks.iter() {
            require!(solana::decode_pubkey(h).is_some(),
                     "every pinned hook must be a 32-byte base58 key");
        }
        require!(token_program == spl::TOKEN_PROGRAM_B58 || token_program == spl::TOKEN_2022_B58,
                 "token_program must be the SPL Token or Token-2022 program");
        require!(profile.fee_bps <= spl::MAX_FEE_BPS, "fee_bps exceeds 100 percent");

        let (spent, started) = match self.mint_rules.get(&Self::mint_key(&agent, &mint)) {
            Some(r) => (r.spent_in_window, r.window_started_ms),
            None => (0u128, env::block_timestamp_ms()),
        };

        let rule = spl::MintRule {
            enabled: true,
            source_ata,
            decimals,
            per_tx_amount: per_tx_amount.0,
            window_amount: window_amount.0,
            // PRESERVE the spend across a re-pin, matching `set_agent_policy`.
            //
            // My first version reset both, reasoning that a new cap states a fresh allowance.
            // That is wrong, and `set_agent_policy` had it right: a reset makes re-pinning a
            // BUDGET-REFUND primitive. An owner talked into "just raise the cap a little" would
            // also silently refund the window, and nothing in the call looks like a refund. The
            // safe direction is to carry the spend; lowering a cap below the current spend then
            // freezes the agent until the window rolls, which is the failure we want.
            //
            // Two setters on one resource must not differ on this, because a reader who learns
            // one will assume the other.
            spent_in_window: spent,
            window_started_ms: started,
            allowed_destinations,
            token_program,
            pinned_hooks,
            profile: spl::MintProfile {
                fee_bps: profile.fee_bps,
                max_fee: profile.max_fee.0,
                transfer_hook: profile.transfer_hook,
                permanent_delegate: profile.permanent_delegate,
                confidential: profile.confidential,
                authorities_revoked: profile.authorities_revoked,
            },
        };
        self.mint_rules.insert(Self::mint_key(&agent, &mint), rule);
    }

    /// Owner-only, EXPLICIT reset of a mint's rolling window.
    ///
    /// This is the budget refund that `set_mint_rule` deliberately does NOT perform. Re-pinning a
    /// rule preserves the spend, so that raising a cap cannot double as a silent refund; but a
    /// refund is still a thing an owner legitimately wants (re-running a graded suite, for one),
    /// so it exists as its own named call. Mirrors `reset_agent_window` for the lamport arm.
    ///
    /// The point is not that the capability is absent. It is that it cannot be reached by
    /// accident, and that the audit trail names it for what it is.
    pub fn reset_mint_window(&mut self, agent: AccountId, mint: alloc::string::String) {
        self.assert_owner();
        let now = env::block_timestamp_ms();
        if let Some(r) = self.mint_rules.get_mut(&Self::mint_key(&agent, &mint)) {
            r.spent_in_window = 0;
            r.window_started_ms = now;
        }
    }

    pub fn set_mint_rule_enabled(&mut self, agent: AccountId, mint: alloc::string::String,
                                 enabled: bool) {
        self.assert_owner();
        if let Some(r) = self.mint_rules.get_mut(&Self::mint_key(&agent, &mint)) {
            r.enabled = enabled;
        }
    }

    /// Refund a charge whose signed transfer provably can never land (WL-CL-015).
    ///
    /// WHY A CHARGE CAN STRAND. Leash charges at SIGNATURE ISSUANCE, not at settlement, and that
    /// is deliberate: the signed message is a broadcastable Solana transaction, so declining to
    /// charge until it lands would let an agent harvest signatures for free and settle them at
    /// leisure. The cost of that choice is the case measured on 11-04 -- a transfer signed and
    /// charged, then refused by the cluster with BlockhashNotFound, holding 10,000,000 lamports
    /// of a window against a transfer that can never settle. `on_signed` covers signing FAILURE;
    /// this covers signing SUCCESS with failed SETTLEMENT.
    ///
    /// WHY IT IS ATTESTED AND NOT PROVEN. The condition is "the `recent_blockhash` is past at
    /// finalized AND no such signature exists". This contract cannot read Solana and does not
    /// pretend to, so it cannot evaluate either half. The owner performs those two reads off
    /// chain and attests the result here.
    ///
    /// WHY OWNER-ONLY IS NOT A NEW TRUST ASSUMPTION. The owner can already call
    /// `reset_agent_window` and `reset_mint_window`, which zero a budget's spend outright. This
    /// method is strictly NARROWER than the authority the owner already holds: it subtracts one
    /// named amount from the one window that was charged, and only if that window is still
    /// current. It therefore needs no new state, no replay set and no migration -- an owner who
    /// wanted to zero a spend never needed this method to do it. It must NOT be opened to the
    /// agent: the contract cannot check the attestation, so an agent-callable version would hand
    /// out free budget for transfers that did land.
    ///
    /// WHAT THE CONTRACT STILL ENFORCES ITSELF: the charged window must be the current one. An
    /// attestation that arrives after a roll credits NOTHING rather than crediting a window that
    /// never paid -- the same guard, and the same `policy::refund_spend`, that WL-CL-012 put on
    /// the failure path. Returns true only if a spend was actually credited back.
    pub fn refund_expired(
        &mut self,
        agent: AccountId,
        mint: Option<alloc::string::String>,
        recipient: alloc::string::String,
        amount: near_sdk::json_types::U128,
        charged_window_ms: near_sdk::json_types::U64,
    ) -> bool {
        self.assert_owner();
        let mut refunded = false;
        match &mint {
            None => {
                if let Some(p) = self.agents.get_mut(&agent) {
                    if let Some(next) = policy::refund_spend(
                        p.spent_in_window, p.window_started_ms, charged_window_ms.0, amount.0,
                    ) {
                        p.spent_in_window = next;
                        refunded = true;
                    }
                }
                let detail: alloc::string::String = if refunded {
                    "LEASH_EXPIRED_REFUND: refunded".into()
                } else {
                    "LEASH_EXPIRED_REFUND: stale window, not refunded".into()
                };
                self.write_record(&agent, &recipient, amount.0, refunded, detail);
            }
            Some(m) => {
                if let Some(r) = self.mint_rules.get_mut(&Self::mint_key(&agent, m)) {
                    if let Some(next) = policy::refund_spend(
                        r.spent_in_window, r.window_started_ms, charged_window_ms.0, amount.0,
                    ) {
                        r.spent_in_window = next;
                        refunded = true;
                    }
                }
                // The SPL detail template, so `get_recent_typed` reports this row as base_units
                // of that mint instead of lamports. A hand-written string would parse as native.
                let detail = spl_detail_note(m, if refunded {
                    "expired refund applied"
                } else {
                    "expired refund, stale window, not refunded"
                });
                self.write_record(&agent, &recipient, amount.0, refunded, detail);
            }
        }
        refunded
    }

    /// Third-party readable SPL rule, with the same effective-vs-stored treatment the lamport
    /// view got: a UI must never render the stored total as a remaining allowance.
    pub fn get_mint_rule(&self, agent: AccountId, mint: alloc::string::String)
                         -> Option<MintRuleView> {
        let now = env::block_timestamp_ms();
        self.mint_rules.get(&Self::mint_key(&agent, &mint)).map(|r| Self::mint_rule_view(now, r))
    }

    /// Every pinned rule, with the agent and mint each one belongs to.
    ///
    /// Why this exists, and why it had to exist BEFORE the account is locked: `get_mint_rule`
    /// requires the caller to already know the mint, there is no pairing for `list_agents`, and
    /// the audit ring is a bounded 25 rows that drops history. So without this view an SPL rule
    /// for a mint nobody wrote down is undiscoverable -- and a locked contract can never gain a
    /// view, so the omission would have been permanent.
    pub fn list_mint_rules(&self) -> alloc::vec::Vec<MintRuleEntry> {
        let now = env::block_timestamp_ms();
        self.mint_rules
            .iter()
            .filter_map(|(k, r)| {
                // `mint_key` joins with '|'. Neither a NEAR account id nor a base58 mint can
                // contain that byte, so the first '|' is the only possible boundary.
                k.split_once('|').and_then(|(a, m)| {
                    a.parse::<AccountId>().ok().map(|agent| MintRuleEntry {
                        agent,
                        mint: m.into(),
                        rule: Self::mint_rule_view(now, r),
                    })
                })
            })
            .collect()
    }

    fn mint_rule_view(now: u64, r: &spl::MintRule) -> MintRuleView {
        MintRuleView {
            enabled: r.enabled,
            source_ata: r.source_ata.clone(),
            decimals: r.decimals,
            per_tx_amount: r.per_tx_amount.into(),
            window_amount: r.window_amount.into(),
            spent_in_window: r.spent_in_window.into(),
            spent_in_window_effective: if policy::window_expired(now, r.window_started_ms) {
                0u128.into()
            } else {
                r.spent_in_window.into()
            },
            window_started_ms: r.window_started_ms.into(),
            window_ms: policy::WINDOW_MS.into(),
            window_expires_at_ms: r.window_started_ms.saturating_add(policy::WINDOW_MS).into(),
            allowed_destinations: r.allowed_destinations.clone(),
            token_program: r.token_program.clone(),
            pinned_hooks: r.pinned_hooks.clone(),
            fee_bps: r.profile.fee_bps,
            max_fee: r.profile.max_fee.into(),
            transfer_hook: r.profile.transfer_hook.clone(),
            permanent_delegate: r.profile.permanent_delegate.clone(),
            confidential: r.profile.confidential,
            authorities_revoked: r.profile.authorities_revoked,
            // what `decide_spl` would say about this profile right now, so a reader does not
            // re-implement the objection order and reach a different answer
            profile_objection: spl::profile_objection(r).map(alloc::string::String::from),
        }
    }

    /// Request an SPL / Token-2022 `TransferChecked`.
    ///
    /// The SOURCE is not a parameter: it comes from the owner-pinned rule. The escrow legs take
    /// caller-supplied accounts and rely on the escrow program validating them, which is someone
    /// else's code guarding a property I was describing as mine. Here the untrusted agent names
    /// only the mint, the destination and the amount.
    #[payable]
    pub fn request_spl_transfer(
        &mut self,
        mint: alloc::string::String,
        destination: alloc::string::String,
        amount: near_sdk::json_types::U64,
        decimals: u8,
        recent_blockhash: alloc::string::String,
    ) -> near_sdk::PromiseOrValue<Verdict> {
        let caller = env::predecessor_account_id();
        let known = self.agents.contains_key(&caller);
        let (enabled, expires) = match self.agents.get(&caller) {
            Some(p) => (p.enabled, p.expires_at_ms),
            None => (false, 0),
        };
        let key = Self::mint_key(&caller, &mint);
        let rule = self.mint_rules.get(&key).cloned();
        let req = spl::SplRequest {
            mint: mint.clone(),
            destination: destination.clone(),
            amount: amount.0,
            decimals,
        };

        match spl::decide_spl(known, enabled, expires, rule.as_ref(), &req,
                              env::block_timestamp_ms()) {
            spl::SplDecision::Refuse(r) => {
                let reason = spl_refusal_message(&r);
                // NOTE for anyone reading the audit ring: `lamports` carries BASE UNITS on an SPL
                // row, not lamports. The field predates this leg and renaming it would be a fourth
                // migration for a cosmetic gain; the mint is in `detail` so the row stays
                // interpretable. A UI must read `detail` before formatting the amount.
                self.write_record(&caller, &destination, amount.0 as u128, false,
                                  spl_detail_note(&mint, &reason));
                env::log_str(&reason);
                near_sdk::PromiseOrValue::Value(Verdict { allowed: false, reason })
            }
            spl::SplDecision::Allow { debit, new_spent_in_window, new_window_started_ms } => {
                // charge the window BEFORE yielding, same reason as the lamport arm: a second
                // request would otherwise pass against a stale total.
                if let Some(r) = self.mint_rules.get_mut(&key) {
                    r.spent_in_window = new_spent_in_window;
                    r.window_started_ms = new_window_started_ms;
                }
                let rule = rule.unwrap_or_else(|| env::panic_str("rule vanished"));

                let bh = solana::decode_pubkey(&recent_blockhash)
                    .unwrap_or_else(|| env::panic_str("recent_blockhash is not 32 bytes base58"));
                let auth = solana::decode_pubkey(&self.solana_address)
                    .unwrap_or_else(|| env::panic_str("stored solana_address is invalid"));
                let src = solana::decode_pubkey(&rule.source_ata)
                    .unwrap_or_else(|| env::panic_str("pinned source_ata is invalid"));
                let dst = solana::decode_pubkey(&destination)
                    .unwrap_or_else(|| env::panic_str("destination is not 32 bytes base58"));
                let mnt = solana::decode_pubkey(&mint)
                    .unwrap_or_else(|| env::panic_str("mint is not 32 bytes base58"));
                let tp = solana::decode_pubkey(&rule.token_program)
                    .unwrap_or_else(|| env::panic_str("token_program is invalid"));

                let msg = spl::build_transfer_checked_message(
                    &auth, &src, &dst, &mnt, &tp, amount.0, decimals, &bh,
                )
                .unwrap_or_else(|| env::panic_str("spl message build failed"));

                let args = near_sdk::serde_json::json!({
                    "request": {
                        "payload_v2": { "Eddsa": to_hex(&msg) },
                        "path": self.derivation_path,
                        "domain_id": DOMAIN_ED25519,
                    }
                })
                .to_string()
                .into_bytes();

                self.write_record(&caller, &destination, debit, true,
                                  spl_detail_allow(&mint, debit));
                near_sdk::PromiseOrValue::Promise(Promise::new(self.mpc_contract.clone())
                    .function_call("sign".to_string(), args, SIGN_DEPOSIT, SIGN_GAS)
                    .then(Promise::new(env::current_account_id()).function_call(
                        "on_signed_spl".to_string(),
                        near_sdk::serde_json::json!({
                            "agent": caller, "mint": mint,
                            "debit": near_sdk::json_types::U128(debit),
                            "charged_window_ms":
                                near_sdk::json_types::U64(new_window_started_ms),
                        })
                        .to_string()
                        .into_bytes(),
                        NearToken::from_yoctonear(0),
                        CALLBACK_GAS,
                    )))
            }
        }
    }

    /// Refund the SPL window when signing failed. A separate callback from `on_signed` because it
    /// must restore the PER-MINT window; reusing the lamport callback would refund the wrong
    /// budget and leave the mint's window permanently short.
    #[private]
    pub fn on_signed_spl(
        &mut self,
        agent: AccountId,
        mint: alloc::string::String,
        debit: near_sdk::json_types::U128,
        charged_window_ms: near_sdk::json_types::U64,
        #[callback_result] result: Result<near_sdk::serde_json::Value, PromiseError>,
    ) -> Verdict {
        match result {
            Ok(_) => Verdict { allowed: true, reason: alloc::string::String::new() },
            Err(_) => {
                // Same guard on the PER-MINT window.
                let mut refunded = false;
                if let Some(r) = self.mint_rules.get_mut(&Self::mint_key(&agent, &mint)) {
                    if let Some(next) = policy::refund_spend(
                        r.spent_in_window, r.window_started_ms, charged_window_ms.0, debit.0,
                    ) {
                        r.spent_in_window = next;
                        refunded = true;
                    }
                }
                let reason: alloc::string::String = if refunded {
                    "LEASH_SIGN_FAILED: spl refunded".into()
                } else {
                    "LEASH_SIGN_FAILED: spl stale window, not refunded".into()
                };
                self.write_record(&agent, &alloc::string::String::new(), debit.0, false,
                                  spl_detail_note(&mint, &reason));
                Verdict { allowed: false, reason }
            }
        }
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

/// Stable refusal strings for the SPL leg. Same `LEASH_REFUSED:` prefix so one log grep finds
/// both legs, and every arm names the numbers that decided it — a refusal a human cannot check
/// against the policy is only an assertion that the policy was applied.
pub fn spl_refusal_message(r: &spl::SplRefusal) -> alloc::string::String {
    use alloc::format;
    use spl::SplRefusal as R;
    match r {
        R::UnknownAgent => "LEASH_REFUSED: unknown agent".into(),
        R::AgentDisabled => "LEASH_REFUSED: agent disabled".into(),
        R::SessionExpired => "LEASH_REFUSED: session expired".into(),
        R::MintNotAllowed => "LEASH_REFUSED: mint not allowed for this agent".into(),
        R::MintDisabled => "LEASH_REFUSED: mint rule disabled".into(),
        R::MintProfileUnsafe { reason } => {
            format!("LEASH_REFUSED: mint profile unsafe ({})", reason)
        }
        R::ZeroAmount => "LEASH_REFUSED: zero amount".into(),
        R::DecimalsMismatch { policy, requested } => format!(
            "LEASH_REFUSED: decimals mismatch (policy {}, requested {})", policy, requested
        ),
        R::DestinationMalformed => "LEASH_REFUSED: destination malformed".into(),
        R::DestinationNotAllowed => "LEASH_REFUSED: destination not allowed".into(),
        R::OverPerTxLimit { limit, debit } => format!(
            "LEASH_REFUSED: over per-tx limit (limit {}, debit {} incl fee)", limit, debit
        ),
        R::OverWindowLimit { limit, spent, debit } => format!(
            "LEASH_REFUSED: over window limit (limit {}, spent {}, debit {} incl fee)",
            limit, spent, debit
        ),
    }
}

#[cfg(test)]
mod detail_roundtrip_tests {
    use super::*;

    const MINT: &str = "So11111111111111111111111111111111111111112";

    /// ROUND TRIP, not a parse test against invented strings: every `detail` the WRITER can emit
    /// is built by the same functions the contract uses, then read back by the parser. A parser
    /// tested against hand-written strings proves only that I can write a string.
    #[test]
    fn every_spl_detail_the_writer_emits_parses_as_base_units_with_its_mint() {
        let emitted = [
            spl_detail_allow(MINT, 10_000_000),
            spl_detail_note(MINT, "LEASH_REFUSED: over per-tx limit (limit 1, debit 2 incl fee)"),
            spl_detail_note(MINT, "LEASH_SIGN_FAILED: spl refunded"),
            spl_detail_note(MINT, "LEASH_SIGN_FAILED: spl stale window, not refunded"),
        ];
        for d in emitted.iter() {
            let (unit, mint) = parse_detail_unit(d);
            assert_eq!(unit, "base_units", "detail: {}", d);
            assert_eq!(mint.as_deref(), Some(MINT), "detail: {}", d);
        }
    }

    /// The native rows the contract writes must NOT be labelled base_units. These are the literal
    /// strings the lamport and escrow legs emit today.
    #[test]
    fn native_details_parse_as_lamports_with_no_mint() {
        for d in [
            "signature requested",
            "LEASH_SIGN_FAILED: refunded",
            "accept_task signature requested (no lamports)",
            "submit_evidence signature requested (no lamports)",
            "LEASH_REFUSED: over per-tx limit (limit 10000000, requested 20000000)",
            "",
        ] {
            let (unit, mint) = parse_detail_unit(d);
            assert_eq!(unit, "lamports", "detail: {:?}", d);
            assert_eq!(mint, None, "detail: {:?}", d);
        }
    }

    /// The prefix must not match a native detail that merely CONTAINS "spl" later in the string,
    /// and must not claim a mint it did not find.
    #[test]
    fn prefix_is_anchored_and_a_bare_prefix_yields_no_mint() {
        let (u, m) = parse_detail_unit("transfer to spl holder");
        assert_eq!((u.as_str(), m), ("lamports", None));
        let (u, m) = parse_detail_unit(SPL_DETAIL_PREFIX);
        assert_eq!(u, "base_units");
        assert_eq!(m, None, "a prefix with no mint must not invent one");
    }
}

/// ARMING tests for the two sign-failure callbacks.
///
/// Why this module exists, stated plainly because the gap it fills was mine: `policy::refund_spend`
/// is a pure function with six exhaustive arms, and the 11-05 fix threaded it into BOTH callbacks.
/// Nothing tested the THREADING. A pure decision function proves the decision; it proves nothing
/// about the call site that arms it, and the call site is where a copy-paste lives -- passing the
/// agent policy's `window_started_ms` into the SPL callback compiles, passes every existing test,
/// and silently refunds against the wrong budget. The lamport arming has a chain receipt (the
/// 11-04 rig race, ARM B 5/5). The SPL arming had neither a unit test nor a chain receipt.
///
/// Two things are checked that the pure function cannot see:
///   * the CONSUMER: each callback must compare against the window of the budget it is crediting
///     -- the agent's for lamports, that mint's for SPL. The discriminating arms roll the OTHER
///     leg's window and require the refund to still apply.
///   * the PRODUCER: `request_*` must hand its callback the window it actually charged. Asserted
///     on the created receipt's args, not inferred from the source.
///
/// It also closes the item the 11-05 replica race recorded as NOT PROVEN: a stale refund being
/// dropped while a NON-ZERO spend sits in the live window. On chain the reset zeroed spend, so
/// every stale refund there was observed against 0 and the saturating subtraction would have
/// looked identical. Here the live window is deliberately re-charged first.
#[cfg(test)]
mod callback_arming_tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, NearToken, PromiseError};

    const MINT: &str = "So11111111111111111111111111111111111111112";
    const DEST: &str = "8pM1kPpfgEoFtuSmPx5Xk2Bu1X1bHGbVbPmZPFgcJYhP";
    const ATA: &str = "KgXf6AAZJQtFdZiurUKBZJe3CWV6fTeKvf5fLp5aVdW";  // sha256("leash-test-ata"), a VALID 32-byte key: the spl.rs fixture builds MintRule directly and its ata is one set_mint_rule would reject
    const BH: &str = "3fHXu9SNZnoWXFMTkB6HGLBfYENn5dFY8kJ9mVCzJ8ZT";   // sha256("leash-test-mint"), any 32 bytes
    /// The contract's OWN Solana address. It must not alias the mint, the ATA or the destination:
    /// `build_transfer_checked_message` refuses an aliased account set, and initialising the
    /// contract with the mint's key made every SPL arm fail as "spl message build failed".
    const LEASH_ADDR: &str = "FKeKVx1cfzqadpQJTsoGArAhPiVMKg3FHFJh2kBR2Ap9";

    fn owner() -> AccountId { "owner.testnet".parse().unwrap() }
    fn agent() -> AccountId { "agent.testnet".parse().unwrap() }

    /// `ms` is the block time this call sees. Window ids ARE block timestamps, so every call that
    /// must land in a distinguishable window gets its own.
    fn ctx(who: AccountId, ms: u64) {
        testing_env!(VMContextBuilder::new()
            .current_account_id("leash.testnet".parse().unwrap())
            .predecessor_account_id(who)
            .block_timestamp(ms * 1_000_000)
            .account_balance(NearToken::from_near(100))
            .attached_deposit(NearToken::from_yoctonear(0))
            .build());
    }

    fn fresh(ms: u64) -> Leash {
        ctx(owner(), ms);
        let mut c = Leash::new(
            owner(),
            "mpc.testnet".parse().unwrap(),
            "leash-1".to_string(),
            LEASH_ADDR.to_string(),
        );
        c.set_agent_policy(
            agent(),
            10_000_000u128.into(),
            40_000_000u128.into(),
            alloc::vec![DEST.to_string()],
            0u64.into(),
        );
        c.set_mint_rule(
            agent(), MINT.to_string(), ATA.to_string(), 6,
            1_000_000u128.into(), 4_000_000u128.into(),
            alloc::vec![DEST.to_string()],
            spl::TOKEN_PROGRAM_B58.to_string(),
            alloc::vec![],
            MintProfileIn {
                fee_bps: 0,
                max_fee: 0u64.into(),
                transfer_hook: None,
                permanent_delegate: None,
                confidential: false,
                authorities_revoked: true,
            },
        );
        c
    }

    fn lam_spent(c: &Leash) -> u128 { c.agents.get(&agent()).unwrap().spent_in_window }
    fn lam_window(c: &Leash) -> u64 { c.agents.get(&agent()).unwrap().window_started_ms }
    fn spl_spent(c: &Leash) -> u128 {
        c.mint_rules.get(&Leash::mint_key(&agent(), MINT)).unwrap().spent_in_window
    }
    fn spl_window(c: &Leash) -> u64 {
        c.mint_rules.get(&Leash::mint_key(&agent(), MINT)).unwrap().window_started_ms
    }
    fn newest_detail(c: &Leash) -> alloc::string::String {
        c.get_recent(1).first().map(|r| r.detail.clone()).unwrap_or_default()
    }
    fn charge_lam(c: &mut Leash, ms: u64, lamports: u128) {
        ctx(agent(), ms);
        let _ = c.request_transfer(DEST.to_string(), lamports.into(), BH.to_string());
    }
    fn charge_spl(c: &mut Leash, ms: u64, amount: u64) {
        ctx(agent(), ms);
        let _ = c.request_spl_transfer(MINT.to_string(), DEST.to_string(), amount.into(), 6, BH.to_string());
    }

    // ---- the consumer, lamport leg ---------------------------------------------------------

    #[test]
    fn lamport_refund_credits_the_window_it_charged() {
        let mut c = fresh(1_000);
        charge_lam(&mut c, 2_000, 10_000_000);
        let w = lam_window(&c);
        assert_eq!(lam_spent(&c), 10_000_000, "the charge must land before the yield");
        ctx("leash.testnet".parse().unwrap(), 3_000);
        let v = c.on_signed(agent(), 10_000_000u128.into(), w.into(), Err(PromiseError::Failed));
        assert!(!v.allowed);
        assert_eq!(v.reason, "LEASH_SIGN_FAILED: refunded");
        assert_eq!(lam_spent(&c), 0, "a same-window refund must return the budget");
        assert_eq!(newest_detail(&c), "LEASH_SIGN_FAILED: refunded");
    }

    /// THE ARM THE CHAIN RACE COULD NOT PRODUCE. The live window holds a non-zero spend when the
    /// stale callback arrives, so a refund landing on the wrong window is visible as a number and
    /// not merely as a saturating subtraction of 0.
    #[test]
    fn a_stale_lamport_refund_cannot_eat_a_live_windows_non_zero_spend() {
        let mut c = fresh(1_000);
        charge_lam(&mut c, 2_000, 10_000_000);
        let charged = lam_window(&c);

        ctx(owner(), 50_000);
        c.reset_agent_window(agent());
        charge_lam(&mut c, 60_000, 10_000_000);
        let live = lam_window(&c);
        assert_ne!(charged, live, "the reset must produce a distinguishable window");
        assert_eq!(lam_spent(&c), 10_000_000, "the live window carries a real spend");

        ctx("leash.testnet".parse().unwrap(), 70_000);
        let v = c.on_signed(agent(), 10_000_000u128.into(), charged.into(), Err(PromiseError::Failed));
        assert_eq!(v.reason, "LEASH_SIGN_FAILED: stale window, not refunded");
        assert_eq!(lam_spent(&c), 10_000_000, "the live window's spend must be untouched");
        assert_eq!(newest_detail(&c), "LEASH_SIGN_FAILED: stale window, not refunded",
                   "a dropped refund must still be RECORDED");
    }

    /// DISCRIMINATOR: the lamport callback must read the AGENT's window. Rolling a mint's window
    /// must not make an otherwise-current lamport refund look stale.
    #[test]
    fn the_lamport_callback_reads_the_agents_window_not_a_mints() {
        let mut c = fresh(1_000);
        charge_lam(&mut c, 2_000, 10_000_000);
        let w = lam_window(&c);
        ctx(owner(), 50_000);
        c.reset_mint_window(agent(), MINT.to_string());
        ctx("leash.testnet".parse().unwrap(), 60_000);
        let v = c.on_signed(agent(), 10_000_000u128.into(), w.into(), Err(PromiseError::Failed));
        assert_eq!(v.reason, "LEASH_SIGN_FAILED: refunded",
                   "a mint's roll is not the agent window's roll");
        assert_eq!(lam_spent(&c), 0);
    }

    // ---- the consumer, SPL leg -------------------------------------------------------------

    #[test]
    fn spl_refund_credits_the_mint_window_it_charged() {
        let mut c = fresh(1_000);
        charge_spl(&mut c, 2_000, 1_000_000);
        let w = spl_window(&c);
        assert_eq!(spl_spent(&c), 1_000_000, "the SPL charge must land before the yield");
        ctx("leash.testnet".parse().unwrap(), 3_000);
        let v = c.on_signed_spl(agent(), MINT.to_string(), 1_000_000u128.into(), w.into(),
                                Err(PromiseError::Failed));
        assert!(!v.allowed);
        assert_eq!(v.reason, "LEASH_SIGN_FAILED: spl refunded");
        assert_eq!(spl_spent(&c), 0);
        assert_eq!(newest_detail(&c), spl_detail_note(MINT, "LEASH_SIGN_FAILED: spl refunded"));
    }

    #[test]
    fn a_stale_spl_refund_cannot_eat_a_live_mint_windows_non_zero_spend() {
        let mut c = fresh(1_000);
        charge_spl(&mut c, 2_000, 1_000_000);
        let charged = spl_window(&c);

        ctx(owner(), 50_000);
        c.reset_mint_window(agent(), MINT.to_string());
        charge_spl(&mut c, 60_000, 1_000_000);
        let live = spl_window(&c);
        assert_ne!(charged, live);
        assert_eq!(spl_spent(&c), 1_000_000);

        ctx("leash.testnet".parse().unwrap(), 70_000);
        let v = c.on_signed_spl(agent(), MINT.to_string(), 1_000_000u128.into(), charged.into(),
                                Err(PromiseError::Failed));
        assert_eq!(v.reason, "LEASH_SIGN_FAILED: spl stale window, not refunded");
        assert_eq!(spl_spent(&c), 1_000_000, "the live mint window's spend must be untouched");
        assert_eq!(newest_detail(&c),
                   spl_detail_note(MINT, "LEASH_SIGN_FAILED: spl stale window, not refunded"));
    }

    /// THE DISCRIMINATOR THIS MODULE WAS WRITTEN FOR. The SPL callback must read THAT MINT's
    /// window. Passing the agent policy's `window_started_ms` here is the one-token copy-paste
    /// that the pure function's six arms cannot see: roll only the AGENT window, and a correct
    /// SPL callback still refunds while the mutant drops the refund.
    #[test]
    fn the_spl_callback_reads_the_mints_window_not_the_agents() {
        let mut c = fresh(1_000);
        charge_spl(&mut c, 2_000, 1_000_000);
        let w = spl_window(&c);
        ctx(owner(), 50_000);
        c.reset_agent_window(agent());
        assert_ne!(lam_window(&c), w, "the agent window must have moved");
        assert_eq!(spl_window(&c), w, "the mint window must NOT have moved");
        ctx("leash.testnet".parse().unwrap(), 60_000);
        let v = c.on_signed_spl(agent(), MINT.to_string(), 1_000_000u128.into(), w.into(),
                                Err(PromiseError::Failed));
        assert_eq!(v.reason, "LEASH_SIGN_FAILED: spl refunded",
                   "the agent window rolling is not this mint's window rolling");
        assert_eq!(spl_spent(&c), 0);
    }

    // ---- the producer: what the request actually hands its callback ------------------------

    /// Read the ARGS the contract actually attached to its callback receipt. The method name and
    /// args are raw bytes in the mock, so they are decoded rather than matched through `Debug`:
    /// a Debug string prints them as byte numbers and a substring test against it passes for the
    /// wrong reasons.
    fn callback_args(method: &str) -> alloc::string::String {
        let mut found = alloc::string::String::new();
        for r in near_sdk::test_utils::get_created_receipts() {
            for a in r.actions.iter() {
                if let near_sdk::mock::MockAction::FunctionCallWeight { method_name, args, .. } = a {
                    if alloc::string::String::from_utf8_lossy(method_name) == method {
                        found = alloc::string::String::from_utf8_lossy(args).into_owned();
                    }
                }
            }
        }
        assert!(!found.is_empty(), "no receipt action called {}", method);
        found
    }

    #[test]
    fn request_spl_transfer_hands_its_callback_the_mint_window_it_charged() {
        let mut c = fresh(1_000);
        charge_spl(&mut c, 2_000, 1_000_000);
        let w = spl_window(&c);
        let args = callback_args("on_signed_spl");
        // The FIELD, not the number. A bare substring test passed this test even under a mutant
        // that hands the callback 0, because the debit "1000000" contains the window id "1000".
        // A control that cannot fail is not a control -- the mutant is what exposed it.
        assert!(args.contains(&alloc::format!("\"charged_window_ms\":\"{}\"", w)),
                "callback args must carry the charged mint window {}: {}", w, args);
    }

    #[test]
    fn request_transfer_hands_its_callback_the_agent_window_it_charged() {
        let mut c = fresh(1_000);
        charge_lam(&mut c, 2_000, 10_000_000);
        let w = lam_window(&c);
        let args = callback_args("on_signed");
        assert!(args.contains(&alloc::format!("\"charged_window_ms\":\"{}\"", w)),
                "callback args must carry the charged agent window {}: {}", w, args);
    }

    // ---- WL-CL-020: a renewal must not undo a deliberate disable ---------------------------

    /// THE DEFECT ITSELF. `set_agent_policy` rebuilt the record with `enabled: true` hardcoded, so
    /// an owner's `set_agent_enabled(false)` could not survive the next renewal -- and renewals are
    /// routine, because the session expiry is what forces them. This is the arm the live chain
    /// produced on 2026-11-11: the testnet policy lapsed on 11-10 and renewing it re-enabled the
    /// agent as a side effect nobody asked for.
    #[test]
    fn a_renewal_does_not_re_enable_a_disabled_agent() {
        let mut c = fresh(1_000);
        ctx(owner(), 2_000);
        c.set_agent_enabled(agent(), false);
        assert!(!c.agents.get(&agent()).unwrap().enabled, "precondition: the disable landed");
        ctx(owner(), 3_000);
        c.set_agent_policy(agent(), 10_000_000u128.into(), 40_000_000u128.into(),
                           alloc::vec![DEST.to_string()], 9_000u64.into());
        assert!(!c.agents.get(&agent()).unwrap().enabled,
                "a renewal must carry the disable FORWARD, not reset it");
        assert_eq!(c.agents.get(&agent()).unwrap().expires_at_ms, 9_000,
                   "and it must still renew the expiry it was actually called for");
    }

    /// TWO-SIDED CONTROL. The fix must not make every renewal land disabled -- without this arm,
    /// `enabled: false` hardcoded would pass the test above just as well as the real fix.
    #[test]
    fn a_renewal_keeps_an_enabled_agent_enabled() {
        let mut c = fresh(1_000);
        assert!(c.agents.get(&agent()).unwrap().enabled, "precondition: enabled");
        ctx(owner(), 3_000);
        c.set_agent_policy(agent(), 10_000_000u128.into(), 40_000_000u128.into(),
                           alloc::vec![DEST.to_string()], 9_000u64.into());
        assert!(c.agents.get(&agent()).unwrap().enabled, "an enabled agent stays enabled");
    }

    /// ONBOARDING IS UNCHANGED: a FIRST policy for an unknown agent still enables it, which is the
    /// `None` arm of the carry-forward and the reason the default could not simply be removed.
    #[test]
    fn a_new_agent_is_enabled_by_its_first_policy() {
        let mut c = fresh(1_000);
        let fresh_agent: AccountId = "agent2.testnet".parse().unwrap();
        assert!(c.agents.get(&fresh_agent).is_none(), "precondition: unknown agent");
        ctx(owner(), 2_000);
        c.set_agent_policy(fresh_agent.clone(), 1_000u128.into(), 2_000u128.into(),
                           alloc::vec![DEST.to_string()], 0u64.into());
        assert!(c.agents.get(&fresh_agent).unwrap().enabled,
                "a new agent's first policy still enables it");
    }

    /// THE DISABLE STAYS REVERSIBLE by its own setter after a renewal, so the fix adds no trap.
    #[test]
    fn set_agent_enabled_still_re_enables_after_a_renewal() {
        let mut c = fresh(1_000);
        ctx(owner(), 2_000);
        c.set_agent_enabled(agent(), false);
        ctx(owner(), 3_000);
        c.set_agent_policy(agent(), 10_000_000u128.into(), 40_000_000u128.into(),
                           alloc::vec![DEST.to_string()], 9_000u64.into());
        ctx(owner(), 4_000);
        c.set_agent_enabled(agent(), true);
        assert!(c.agents.get(&agent()).unwrap().enabled,
                "an explicit re-enable still works, and is now the ONLY way to re-enable");
    }

    /// THE CONSEQUENCE, NOT THE FLAG. A bool carried forward is worth nothing unless the signing
    /// path still refuses, so this arm drives the real caller and reads the audit ring.
    #[test]
    fn a_disabled_then_renewed_agent_is_still_refused_end_to_end() {
        let mut c = fresh(1_000);
        ctx(owner(), 2_000);
        c.set_agent_enabled(agent(), false);
        ctx(owner(), 3_000);
        c.set_agent_policy(agent(), 10_000_000u128.into(), 40_000_000u128.into(),
                           alloc::vec![DEST.to_string()], 9_000u64.into());
        charge_lam(&mut c, 5_000, 1_000_000);
        assert_eq!(newest_detail(&c), "LEASH_REFUSED: agent disabled",
                   "the renewed-but-disabled agent must still be refused on the signing path");
        assert_eq!(lam_spent(&c), 0, "and a refused request must not charge the window");
    }

    /// THE FIELDS THE SETTER ALREADY CARRIED must be unaffected by adding a third to the match.
    #[test]
    fn a_renewal_still_preserves_spend_and_window() {
        let mut c = fresh(1_000);
        charge_lam(&mut c, 2_000, 10_000_000);
        let (spent_before, window_before) = (lam_spent(&c), lam_window(&c));
        assert_eq!(spent_before, 10_000_000, "precondition: the charge landed");
        ctx(owner(), 3_000);
        c.set_agent_policy(agent(), 10_000_000u128.into(), 40_000_000u128.into(),
                           alloc::vec![DEST.to_string()], 9_000u64.into());
        assert_eq!(lam_spent(&c), spent_before, "the spend must survive a renewal");
        assert_eq!(lam_window(&c), window_before, "and so must the window start");
    }
}

/// Tests for `list_mint_rules`, the view WL-CL-018 was filed for.
///
/// What is actually at risk here is not the iteration but the KEY SPLIT: rules are stored under
/// `format!("{}|{}", agent, mint)`, so an enumerator has to take that composite apart again, and
/// the failure modes are silent -- returning one rule under every key, swapping the two halves,
/// or dropping an account id that contains a dot or a hyphen. Each test below fails on one of
/// those and not merely on "the list was empty".
#[cfg(test)]
mod mint_rule_enumeration_tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, NearToken};

    const MINT_A: &str = "So11111111111111111111111111111111111111112";
    const MINT_B: &str = "6L87xhJ9kz8f4cVKHiAG1ehycv77CJL35Wp2FMFtUKWo";
    const ATA: &str = "KgXf6AAZJQtFdZiurUKBZJe3CWV6fTeKvf5fLp5aVdW";
    const DEST: &str = "8pM1kPpfgEoFtuSmPx5Xk2Bu1X1bHGbVbPmZPFgcJYhP";
    const LEASH_ADDR: &str = "FKeKVx1cfzqadpQJTsoGArAhPiVMKg3FHFJh2kBR2Ap9";

    fn owner() -> AccountId { "owner.testnet".parse().unwrap() }
    /// Deliberately the shape production uses -- dots AND hyphens -- because an id that survives
    /// `split_once('|')` but not `parse::<AccountId>()` would be dropped silently by `filter_map`.
    fn agent_one() -> AccountId { "leash-agent-064e6c.testnet".parse().unwrap() }
    fn agent_two() -> AccountId { "second-agent-99.testnet".parse().unwrap() }

    fn ctx(who: AccountId, ms: u64) {
        testing_env!(VMContextBuilder::new()
            .current_account_id("leash.testnet".parse().unwrap())
            .predecessor_account_id(who)
            .block_timestamp(ms * 1_000_000)
            .account_balance(NearToken::from_near(100))
            .attached_deposit(NearToken::from_yoctonear(0))
            .build());
    }

    fn profile() -> MintProfileIn {
        MintProfileIn {
            fee_bps: 0,
            max_fee: 0u64.into(),
            transfer_hook: None,
            permanent_delegate: None,
            confidential: false,
            authorities_revoked: true,
        }
    }

    fn bare(ms: u64) -> Leash {
        ctx(owner(), ms);
        Leash::new(owner(), "mpc.testnet".parse().unwrap(), "leash-1".to_string(),
                   LEASH_ADDR.to_string())
    }

    /// `decimals` and `per_tx_amount` differ per rule so an entry cannot be matched to its pair
    /// by accident: if the split swapped agent and mint, or reused one rule everywhere, the
    /// per-entry assertions below would disagree.
    fn pin(c: &mut Leash, who: AccountId, mint: &str, decimals: u8, per_tx: u128, ms: u64) {
        ctx(owner(), ms);
        c.set_mint_rule(
            who, mint.to_string(), ATA.to_string(), decimals,
            per_tx.into(), (per_tx * 4).into(),
            alloc::vec![DEST.to_string()],
            spl::TOKEN_PROGRAM_B58.to_string(),
            alloc::vec![],
            profile(),
        );
    }

    #[test]
    fn an_unpinned_contract_lists_nothing() {
        // The vacuity guard. Without this, a `list_mint_rules` that always returned an empty
        // vector would pass nothing below and still look like a working enumerator.
        let c = bare(1_000);
        assert!(c.list_mint_rules().is_empty(), "nothing is pinned, so nothing may be listed");
    }

    #[test]
    fn every_pinned_rule_is_listed_with_the_agent_and_mint_it_belongs_to() {
        let mut c = bare(1_000);
        pin(&mut c, agent_one(), MINT_A, 9, 10_000_000, 1_000);
        pin(&mut c, agent_one(), MINT_B, 6, 1_000_000, 1_000);
        pin(&mut c, agent_two(), MINT_B, 6, 7_000_000, 1_000);

        let listed = c.list_mint_rules();
        assert_eq!(listed.len(), 3, "three rules pinned, three listed");

        // Each (agent, mint) pair must be the one that rule was stored under. `decimals` and
        // `per_tx_amount` are the discriminators: a swapped or reused pair fails here.
        let find = |a: &AccountId, m: &str| -> MintRuleView {
            listed.iter().find(|e| &e.agent == a && e.mint == m)
                .unwrap_or_else(|| panic!("no entry for {} / {}", a, m)).rule.clone()
        };
        let one_a = find(&agent_one(), MINT_A);
        let one_b = find(&agent_one(), MINT_B);
        let two_b = find(&agent_two(), MINT_B);
        assert_eq!((one_a.decimals, one_a.per_tx_amount.0), (9, 10_000_000));
        assert_eq!((one_b.decimals, one_b.per_tx_amount.0), (6, 1_000_000));
        assert_eq!((two_b.decimals, two_b.per_tx_amount.0), (6, 7_000_000));

        // The same mint under two agents must stay two entries: the agent half of the key is
        // load-bearing, and an enumerator keyed on the mint alone would collapse them.
        assert_eq!(listed.iter().filter(|e| e.mint == MINT_B).count(), 2);
    }

    #[test]
    fn the_listed_entry_agrees_with_get_mint_rule_field_for_field() {
        // The two readers must not drift: `list_mint_rules` exists so a caller who does NOT know
        // the mint gets exactly what the caller who does would have got.
        let mut c = bare(1_000);
        pin(&mut c, agent_one(), MINT_A, 9, 10_000_000, 1_000);
        ctx(owner(), 2_000);
        let listed = c.list_mint_rules();
        let e = listed.first().expect("one entry");
        let direct = c.get_mint_rule(e.agent.clone(), e.mint.clone()).expect("same rule directly");
        assert_eq!(e.rule.source_ata, direct.source_ata);
        assert_eq!(e.rule.enabled, direct.enabled);
        assert_eq!(e.rule.window_started_ms.0, direct.window_started_ms.0);
        assert_eq!(e.rule.spent_in_window.0, direct.spent_in_window.0);
        assert_eq!(e.rule.spent_in_window_effective.0, direct.spent_in_window_effective.0);
        assert_eq!(e.rule.allowed_destinations, direct.allowed_destinations);
        assert_eq!(e.rule.profile_objection, direct.profile_objection);
    }

    #[test]
    fn a_disabled_rule_is_still_listed_because_discoverability_is_the_point() {
        // A rule you cannot find is a rule you cannot audit or disable. Production's wSOL rule
        // was disabled on 11-05 precisely because it was findable; that must not hide it.
        let mut c = bare(1_000);
        pin(&mut c, agent_one(), MINT_A, 9, 10_000_000, 1_000);
        ctx(owner(), 1_500);
        c.set_mint_rule_enabled(agent_one(), MINT_A.to_string(), false);
        let listed = c.list_mint_rules();
        assert_eq!(listed.len(), 1, "disabling a rule does not unpin it");
        assert!(!listed[0].rule.enabled, "and the listing must say it is disabled");
    }

    #[test]
    fn the_listing_applies_the_window_roll_at_read_time_like_the_single_reader_does() {
        // Two-sided: the SAME pinned rule must read effective-non-zero inside its window and
        // effective-zero past it, in the listing, from one stored spend.
        let mut c = bare(1_000);
        pin(&mut c, agent_one(), MINT_A, 9, 10_000_000, 1_000);
        c.mint_rules
            .get_mut(&Leash::mint_key(&agent_one(), MINT_A))
            .expect("pinned")
            .spent_in_window = 4_000_000;

        ctx(owner(), 1_000 + policy::WINDOW_MS - 1);
        let live = c.list_mint_rules();
        assert_eq!(live[0].rule.spent_in_window.0, 4_000_000);
        assert_eq!(live[0].rule.spent_in_window_effective.0, 4_000_000,
                   "inside the window the effective spend is the stored spend");

        ctx(owner(), 1_000 + policy::WINDOW_MS + 1);
        let rolled = c.list_mint_rules();
        assert_eq!(rolled[0].rule.spent_in_window.0, 4_000_000, "the stored counter is untouched");
        assert_eq!(rolled[0].rule.spent_in_window_effective.0, 0,
                   "past the window the listing must report the roll, not the stored total");
    }
}

/// Tests for `refund_expired` (WL-CL-015).
///
/// The method is owner-attested, so what can be tested is not the attestation but the three
/// things the contract enforces for itself: the window guard, the per-leg targeting, and that it
/// subtracts a NAMED AMOUNT rather than zeroing a budget the way `reset_*_window` does. The last
/// one is the whole reason this method exists instead of telling the owner to reset the window.
#[cfg(test)]
mod expired_refund_tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, NearToken};

    const MINT: &str = "6L87xhJ9kz8f4cVKHiAG1ehycv77CJL35Wp2FMFtUKWo";
    const ATA: &str = "KgXf6AAZJQtFdZiurUKBZJe3CWV6fTeKvf5fLp5aVdW";
    const DEST: &str = "8pM1kPpfgEoFtuSmPx5Xk2Bu1X1bHGbVbPmZPFgcJYhP";
    const LEASH_ADDR: &str = "FKeKVx1cfzqadpQJTsoGArAhPiVMKg3FHFJh2kBR2Ap9";
    const W: u64 = 5_000_000;

    fn owner() -> AccountId { "owner.testnet".parse().unwrap() }
    fn agent() -> AccountId { "agent.testnet".parse().unwrap() }

    fn ctx(who: AccountId, ms: u64) {
        testing_env!(VMContextBuilder::new()
            .current_account_id("leash.testnet".parse().unwrap())
            .predecessor_account_id(who)
            .block_timestamp(ms * 1_000_000)
            .account_balance(NearToken::from_near(100))
            .attached_deposit(NearToken::from_yoctonear(0))
            .build());
    }

    /// Both budgets carry a NON-ZERO spend in the SAME window id, so a method that credited the
    /// wrong leg, or zeroed instead of subtracting, is visible in either number.
    fn armed() -> Leash {
        ctx(owner(), W);
        let mut c = Leash::new(owner(), "mpc.testnet".parse().unwrap(), "leash-1".to_string(),
                               LEASH_ADDR.to_string());
        c.set_agent_policy(
            agent(), 10_000_000u128.into(), 40_000_000u128.into(),
            alloc::vec![DEST.to_string()], 0u64.into(),
        );
        c.set_mint_rule(
            agent(), MINT.to_string(), ATA.to_string(), 6,
            1_000_000u128.into(), 4_000_000u128.into(),
            alloc::vec![DEST.to_string()], spl::TOKEN_PROGRAM_B58.to_string(), alloc::vec![],
            MintProfileIn { fee_bps: 0, max_fee: 0u64.into(), transfer_hook: None,
                            permanent_delegate: None, confidential: false,
                            authorities_revoked: true },
        );
        c.agents.get_mut(&agent()).unwrap().spent_in_window = 30_000_000;
        c.agents.get_mut(&agent()).unwrap().window_started_ms = W;
        let k = Leash::mint_key(&agent(), MINT);
        c.mint_rules.get_mut(&k).unwrap().spent_in_window = 3_000_000;
        c.mint_rules.get_mut(&k).unwrap().window_started_ms = W;
        c
    }

    fn lam(c: &Leash) -> u128 { c.agents.get(&agent()).unwrap().spent_in_window }
    fn spl(c: &Leash) -> u128 {
        c.mint_rules.get(&Leash::mint_key(&agent(), MINT)).unwrap().spent_in_window
    }
    fn newest(c: &Leash) -> Record { c.get_recent(1).first().cloned().expect("a row") }

    #[test]
    fn a_dead_lamport_charge_is_credited_back_to_the_window_that_paid_it() {
        let mut c = armed();
        ctx(owner(), W + 60_000);
        let applied = c.refund_expired(agent(), None, DEST.to_string(),
                                       10_000_000u128.into(), W.into());
        assert!(applied, "the charged window is still current, so the credit must apply");
        // Subtracted, NOT zeroed: that is the difference from reset_agent_window.
        assert_eq!(lam(&c), 20_000_000, "exactly the attested amount comes back");
        assert_eq!(spl(&c), 3_000_000, "the per-mint budget is untouched");
        let r = newest(&c);
        assert!(r.allowed, "an applied credit is recorded as allowed");
        assert_eq!(r.detail, "LEASH_EXPIRED_REFUND: refunded");
        assert_eq!(r.lamports.0, 10_000_000);
    }

    #[test]
    fn a_late_attestation_cannot_eat_a_live_windows_non_zero_spend() {
        // The WL-CL-012 class, on the new path. The window rolled after the charge; crediting the
        // current window would take 10,000,000 from a budget that never paid it.
        let mut c = armed();
        ctx(owner(), W + policy::WINDOW_MS + 1);
        c.agents.get_mut(&agent()).unwrap().window_started_ms = W + policy::WINDOW_MS + 1;
        let before = lam(&c);
        let applied = c.refund_expired(agent(), None, DEST.to_string(),
                                       10_000_000u128.into(), W.into());
        assert!(!applied, "the window that was charged is gone");
        assert_eq!(lam(&c), before, "and nothing is credited to the window that is live now");
        assert_eq!(newest(&c).detail, "LEASH_EXPIRED_REFUND: stale window, not refunded");
        assert!(!newest(&c).allowed, "a dropped attestation is not recorded as allowed");
    }

    #[test]
    fn a_dead_spl_charge_credits_the_mint_window_and_records_base_units() {
        let mut c = armed();
        ctx(owner(), W + 60_000);
        let applied = c.refund_expired(agent(), Some(MINT.to_string()), DEST.to_string(),
                                       1_000_000u128.into(), W.into());
        assert!(applied);
        assert_eq!(spl(&c), 2_000_000, "exactly the attested amount comes back");
        assert_eq!(lam(&c), 30_000_000, "and the agent's lamport budget is untouched");
        // The row must carry the SPL template, or a reader formats token units as lamports.
        let typed = c.get_recent_typed(1);
        let v = typed.first().expect("a typed row");
        assert_eq!(v.unit, "base_units");
        assert_eq!(v.mint.as_deref(), Some(MINT));
    }

    #[test]
    fn a_late_spl_attestation_is_dropped_against_a_live_mint_window() {
        let mut c = armed();
        let k = Leash::mint_key(&agent(), MINT);
        ctx(owner(), W + policy::WINDOW_MS + 1);
        c.mint_rules.get_mut(&k).unwrap().window_started_ms = W + policy::WINDOW_MS + 1;
        let before = spl(&c);
        let applied = c.refund_expired(agent(), Some(MINT.to_string()), DEST.to_string(),
                                       1_000_000u128.into(), W.into());
        assert!(!applied);
        assert_eq!(spl(&c), before);
        assert_eq!(lam(&c), 30_000_000);
    }

    #[test]
    fn the_mint_argument_picks_the_leg_and_a_wrong_one_credits_nothing() {
        // `mint: None` must never reach a mint rule, and a mint with no rule must not fall
        // through to the lamport budget.
        let mut c = armed();
        ctx(owner(), W + 60_000);
        let unknown = "So11111111111111111111111111111111111111112".to_string();
        let applied = c.refund_expired(agent(), Some(unknown), DEST.to_string(),
                                       1_000_000u128.into(), W.into());
        assert!(!applied, "there is no rule for that mint");
        assert_eq!(lam(&c), 30_000_000, "and it must NOT be taken off the lamport budget");
        assert_eq!(spl(&c), 3_000_000, "nor off the other mint's budget");
    }

    #[test]
    #[should_panic(expected = "owner")]
    fn the_agent_cannot_attest_its_own_expiry() {
        // The contract cannot check the attestation, so an agent-callable version would be free
        // budget for transfers that DID land.
        let mut c = armed();
        ctx(agent(), W + 60_000);
        c.refund_expired(agent(), None, DEST.to_string(), 10_000_000u128.into(), W.into());
    }

    #[test]
    fn an_unknown_agent_is_refused_without_panicking_and_leaves_a_row() {
        let mut c = armed();
        ctx(owner(), W + 60_000);
        let stranger: AccountId = "nobody.testnet".parse().unwrap();
        let applied = c.refund_expired(stranger.clone(), None, DEST.to_string(),
                                       1u128.into(), W.into());
        assert!(!applied);
        assert_eq!(newest(&c).agent, stranger, "the attempt is still audited");
        assert_eq!(lam(&c), 30_000_000);
    }
}
