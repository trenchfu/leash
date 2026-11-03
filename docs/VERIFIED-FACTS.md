# Verified facts this build rests on

Every row states HOW it was established. Nothing here is from a vendor summary or memory.

| # | Fact | How verified | Date |
|---|---|---|---|
| 1 | Chain-Signatures key derivation is a function of **(predecessor_account_id, path)** and nothing else | Source, `near/mpc` @ `d0fc87b1`: `api/sign.rs:32` passes `env::predecessor_account_id()`; `SignatureRequest::new(domain, payload, &predecessor, &path)`; and `near-mpc-crypto-types/src/kdf.rs:10` is `fn derive_tweak(predecessor_id: &AccountId, path: &str) -> Tweak` — the signature admits no other input | 2026-11-03 |
| 2 | Therefore a **contract** that calls `sign()` derives from its OWN account id, and no other account can request signatures for that (account, path) | Follows from #1: predecessor is the immediate caller. NOTE: this is an inference FROM verified source, not a doc guarantee — NEAR's docs never cover the contract-to-contract case | 2026-11-03 |
| 3 | Ed25519 (Solana) signing is **live on NEAR mainnet** | My own read-only chain call: `v1.signer.state`, block 222869350, `epoch_id` 14 — domain 1 = `Frost` / `Ed25519` / purpose `Sign` | 2026-11-03 |
| 4 | The MPC committee is **11-of-16** | Same call: `threshold` 11, 16 participants, `next_id` 21 | 2026-11-03 |
| 5 | Source and chain agree on the Ed25519 path | `sign.rs` routes `Protocol::Frost` to `payload.as_eddsa()`; the live domain 1 is `Frost`/`Ed25519` | 2026-11-03 |
| 6 | `sign()` requires a deposit of **1 yoctoNEAR** | `near-mpc-contract-interface/src/deposits.rs:4` — `SIGN_DEPOSIT_YOCTONEAR: u128 = 1` | 2026-11-03 |
| 7 | Testnet MPC contract is `v1.signer-prod.testnet`; mainnet is `v1.signer` | NEAR docs, implementation page | 2026-11-03 |

## NOT established (stated, not hidden)

- **Whether a full-access key on the policy-contract account defeats the whole guarantee.** It should: a full-access key can redeploy the contract or act as that account directly, and the derived key follows the ACCOUNT, not the code. So the custody property requires a **locked account** (zero full-access keys). This is a design requirement and a thing the harness must PROVE, not assert. NEAR's docs do not address it.
- Whether 11-of-16 is *safe*. That is a measured parameter, not a risk verdict. No operator-independence or jurisdictional analysis was done.
- End-to-end Ed25519 signing has **not yet been executed** by this project. Until it is, #3 means "the domain is live", not "we produced a Solana signature".
