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

## Live testnet measurements (2026-11-03)

Accounts created for this build (NEAR testnet, no real funds):

| role | account |
|---|---|
| contract | `leash-b0c503d6.testnet` |
| owner | `leash-owner-4c4054.testnet` |
| agent | `leash-agent-064e6c.testnet` |

**Testnet MPC committee** (`v1.signer-prod.testnet.state`, block 276052031): `epoch_id` 27,
**11 of 16** participants, domains identical in layout to mainnet —
domain **1 = Frost / Ed25519 / Sign**. Checked rather than assumed to match mainnet.

**Leash's Solana address:** `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL`
derived from (`leash-b0c503d6.testnet`, `solana-1`, domain 1).

### The exclusivity claim, measured rather than inferred

Fact #2 in the table above was an *inference from source*. It is now an empirical result from
`v1.signer-prod.testnet.derived_public_key`:

| arm | predecessor | path | derived address |
|---|---|---|---|
| A | contract | `solana-1` | `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL` |
| B | **agent** | `solana-1` | `7FDz21w5Rf63GDmGtQXc2Dp7SnkM2rcUq6fUtjT7rbSC` |
| C | contract | `solana-2` | `8PeSZNcHaLZM2DAa8VSYquB99fWbx3Ff7HdeEeMDYRnX` |
| D | contract | `solana-1` | `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL` |

A vs **B** is the security property: the *agent*, asking for the *same path*, gets a **different
key**. It cannot reach Leash's address. A vs C shows the path is also bound. **D repeats A exactly**
— the positive control, without which "A and B differ" could just mean the function is noisy.

## Threat model additions from an independent blind review (2026-11-03)

Q commissioned a separate research pass that did not know what this project had built. Two of its
findings are material to Leash's threat model and were NOT in my own research:

- **NEAR Intents / HOT Bridge incident, 2026-09-29 to 10-01.** A refund/notification flaw created
  unbacked internal balances; verified BNB-chain withdrawals totalled **3,865,021 USDT**. The
  postmortem blamed the **Intents contract**, not Omni. Relevance: this is the *Intents* layer, not
  Chain Signatures. It is direct evidence for the distinction Leash is built on — Intents is
  custodial during a swap and carries application-layer risk; Chain Signatures is a signing
  primitive with a different (MPC committee) trust model. Leash deliberately uses the latter.
- **Trail of Bits audit of the MPC, Mar 2025: 15 findings / 7 medium**, remediation status
  unresolved in that review. Leash does not depend on the MPC being flawless, but this belongs in
  the honest statement of what the committee is.

### The committee drifts — measured, not argued

That review cited **11-of-17** operators from a near.org blog dated 2026-10-23. My own read on
**2026-11-03T14:20Z** returns **11-of-16** on BOTH networks (mainnet block 222881663 epoch 14;
testnet block 276060489 epoch 27), with `next_id` 21 and 27 respectively against 16 active seats.

The threshold held; **the denominator moved**. Whether the set shrank or the blog counted a pending
participant, the lesson is the same and it is the one written into this project: **a consumer that
caches the committee is wrong within eleven days.** Leash reads `state` rather than storing a copy.

## NOT established (stated, not hidden)

- **Whether a full-access key on the policy-contract account defeats the whole guarantee.** It should: a full-access key can redeploy the contract or act as that account directly, and the derived key follows the ACCOUNT, not the code. So the custody property requires a **locked account** (zero full-access keys). This is a design requirement and a thing the harness must PROVE, not assert. NEAR's docs do not address it.
- Whether 11-of-16 is *safe*. That is a measured parameter, not a risk verdict. No operator-independence or jurisdictional analysis was done.
- End-to-end Ed25519 signing has **not yet been executed** by this project. Until it is, #3 means "the domain is live", not "we produced a Solana signature".
