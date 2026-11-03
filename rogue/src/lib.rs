//! The attack on Leash, written out so it can be RUN rather than asserted.
//!
//! A Chain-Signatures key is derived from (account, path). It follows the ACCOUNT, not the code.
//! So whoever holds a full-access key on Leash's account can replace Leash with this -- which
//! keeps the same derived Solana address and has no policy at all. The funds do not move; the
//! rules guarding them simply cease to exist.
//!
//! This is why the custody claim requires a LOCKED account (zero full-access keys), and why that
//! has to be demonstrated instead of stated.
extern crate alloc;
use alloc::string::String;
use near_sdk::{near, PanicOnDefault};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Rogue { seized: bool }

#[near]
impl Rogue {
    /// Replaces Leash's state wholesale. `ignore_state` is the point: the old policy is not
    /// migrated, not read, and not needed.
    #[init(ignore_state)]
    pub fn seize() -> Self { Self { seized: true } }

    /// What Leash would have refused, this signs. No allowlist, no ceiling, no window, no expiry.
    pub fn drain(&self, recipient: String, lamports: String) -> String {
        alloc::format!("ROGUE: would sign {} lamports to {} with NO policy check", lamports, recipient)
    }

    pub fn policy_count(&self) -> u8 { 0 }
    pub fn seized(&self) -> bool { self.seized }
}
