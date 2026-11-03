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
use policy::{decide, Decision, Policy, Refusal, Request};

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
    Agents,
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
            agents: IterableMap::new(Key::Agents),
        }
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
            },
        );
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
    ) -> Promise {
        let caller = env::predecessor_account_id();
        let known = self.agents.contains_key(&caller);
        let fallback = Policy {
            enabled: false,
            per_tx_lamports: 0,
            window_lamports: 0,
            spent_in_window: 0,
            window_started_ms: 0,
            allowed_recipients: alloc::vec::Vec::new(),
        };
        let pol = self.agents.get(&caller).cloned().unwrap_or(fallback);
        let req = Request { recipient: recipient.clone(), lamports: lamports.0 };

        match decide(known, &pol, &req, env::block_timestamp_ms()) {
            Decision::Refuse(r) => env::panic_str(&refusal_message(&r)),
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

                Promise::new(self.mpc_contract.clone())
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
                    )
            }
        }
    }

    /// Refund the optimistic spend when signing failed, so a failed signature does not silently
    /// consume the agent's budget.
    #[private]
    pub fn on_signed(
        &mut self,
        agent: AccountId,
        lamports: near_sdk::json_types::U128,
        #[callback_result] result: Result<near_sdk::serde_json::Value, PromiseError>,
    ) -> bool {
        match result {
            Ok(_) => true,
            Err(_) => {
                if let Some(p) = self.agents.get_mut(&agent) {
                    p.spent_in_window = p.spent_in_window.saturating_sub(lamports.0);
                }
                false
            }
        }
    }

    // ---- diagnostic probes (temporary): locate where execution traps -----------------------
    pub fn dbg_ok(&self) -> alloc::string::String {
        env::log_str("dbg_ok: reached");
        "ok".into()
    }
    pub fn dbg_panic_static(&self) {
        env::log_str("dbg_panic_static: before panic");
        env::panic_str("DBG_STATIC_MESSAGE");
    }
    pub fn dbg_panic_alloc(&self) {
        env::log_str("dbg_panic_alloc: before panic");
        let m: alloc::string::String = alloc::format!("DBG_ALLOC_{}", 42);
        env::panic_str(&m);
    }
    pub fn dbg_require(&self) {
        env::log_str("dbg_require: before require");
        require!(false, "DBG_REQUIRE_MESSAGE");
    }

    // ---- views -------------------------------------------------------------------------------

    pub fn get_solana_address(&self) -> alloc::string::String { self.solana_address.clone() }
    pub fn get_owner(&self) -> AccountId { self.owner.clone() }
    pub fn get_derivation_path(&self) -> alloc::string::String { self.derivation_path.clone() }
    pub fn get_mpc_contract(&self) -> AccountId { self.mpc_contract.clone() }

    pub fn get_agent_policy(&self, agent: AccountId) -> Option<PolicyView> {
        self.agents.get(&agent).map(|p| PolicyView {
            enabled: p.enabled,
            per_tx_lamports: p.per_tx_lamports.into(),
            window_lamports: p.window_lamports.into(),
            spent_in_window: p.spent_in_window.into(),
            window_started_ms: p.window_started_ms.into(),
            allowed_recipients: p.allowed_recipients.clone(),
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
        Refusal::OverPerTxLimit { limit, requested } => {
            format!("LEASH_REFUSED: over per-tx limit (limit {}, requested {})", limit, requested)
        }
        Refusal::OverWindowLimit { limit, spent, requested } => format!(
            "LEASH_REFUSED: over window limit (limit {}, spent {}, requested {})",
            limit, spent, requested
        ),
    }
}
