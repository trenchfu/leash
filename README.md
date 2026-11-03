# Leash

**An agent wallet that cryptographically cannot overspend.**

Not a rule the agent is asked to respect. A key it does not have.

---

## The problem

Give an AI agent a wallet and you have given it the private key. Every safeguard after that — a
spending limit in the prompt, a policy in the orchestration layer, a human-in-the-loop check — is
something the agent is *asked* to honour. It holds the key. The limit is a convention.

## What Leash does

Leash is a NEAR contract that **exclusively owns a Solana address** and will only sign transfers
that pass its policy. Agents call the contract. The contract calls the MPC signer. The agent never
holds the key and never sees a signature it did not earn.

```
  agent ──calls──▶  Leash contract  ──policy passes?──▶  v1.signer (MPC, 11-of-16)
                          │                                      │
                          └── refuses ◀── policy fails           └──▶ Ed25519 signature
                                                                       for Solana
```

### Why the agent cannot go around it

Under NEAR Chain Signatures the foreign key is derived from **`(predecessor_account_id, path)`** —
the *immediate caller* and a path string, and nothing else. Verified at source in
[`near/mpc`](https://github.com/near/mpc) @ `d0fc87b1`:

- `crates/contract/src/api/sign.rs:32` — `sign()` passes `env::predecessor_account_id()`
- same file — `SignatureRequest::new(domain, payload, &predecessor, &path)`
- `crates/near-mpc-crypto-types/src/kdf.rs:10` — `fn derive_tweak(predecessor_id: &AccountId, path: &str) -> Tweak`

That function signature admits no other input. When the **contract** calls `sign()`, the contract
is the predecessor, so the derived Solana address belongs to the contract's account. No other
account can be the predecessor for it. The contract is the custody boundary.

NEAR's own docs never state this: every example is a wallet calling directly, and the
contract-to-contract case is not covered. We read the source because the guarantee had to be
established, not assumed.

### Why it cannot sign something other than what it checked

**A policy engine that signs bytes the agent handed it is not a policy engine.** If the agent
supplies the payload and merely *claims* "0.1 SOL to Alice", the contract validates a label and
signs an unrelated instruction. The claim and the artifact are different things, and only the
artifact reaches the chain.

So Leash never accepts signable bytes. The agent supplies **parameters** — recipient, lamports,
recent blockhash — and the contract **constructs** the Solana transfer message itself
(`contract/src/solana.rs`). The agent cannot express a transfer the policy did not authorise,
because it never gets to express the transfer at all.

---

## The attack on Leash, which Leash does not fix by itself

**The derived key follows the ACCOUNT, not the code.** A full-access key on the contract's account
can redeploy it with no policy, or act as that account directly. So the guarantee requires a
**locked account — zero full-access keys**.

This is not a footnote; it is the whole thing. A policy contract on an unlocked account is
security theatre. The harness therefore proves the account is locked against the live network
rather than this README asserting it.

And trust **moves**, it does not vanish: signatures come from an MPC committee measured at
**11-of-16** (`v1.signer.state`, epoch 14, block 222869350, read 2026-11-03). Leash removes
unilateral agent control. It does not remove the committee.

---

## What is proven, and how

Every claim in this project carries how it was established. See
[`docs/VERIFIED-FACTS.md`](docs/VERIFIED-FACTS.md) — including a **NOT established** section.

The test suite is built on one rule: **a verifier that cannot fail is not a verifier.**

- `contract/src/policy.rs` — the spend decision is a **pure function** of (policy, request, clock).
  No storage, no environment, no network. A guard tangled with its effects can only be tested by
  performing them, and a guard that is expensive to test is a guard nobody proves.
- Every refusal reason is a distinct variant, and the suite asserts that the set of refusal states
  actually *entered by tests* equals the full set of variants. Add a refusal without a test and the
  build fails.
- Boundaries are tested on both sides: the limit itself is allowed, one unit above is refused.
- A **backwards clock** must not silence the limit (naive subtraction underflows into a huge
  remaining budget — the classic way an alarm clock fails open).
- An **empty allowlist denies everything**. A policy that fails open is worse than no policy,
  because it reads as protection.

## Run it

```bash
cd contract && cargo test          # pure policy + message-construction suite, no network needed
```

Deployment, the live signature, and the locked-account proof are in `harness/` — see
[`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## Status

Built for the NEAR Hackathon (Nov 2026), **AI Security & Defense** track.
Targets NEAR **testnet** (`v1.signer-prod.testnet`).

| | |
|---|---|
| Policy core + Solana message builder | implemented, 14 unit tests, mutation-checked |
| Contract deployed | `leash-b0c503d6.testnet` |
| Leash's Solana address | `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL` |
| Live Ed25519 signature from the MPC | **executed and cryptographically verified** |
| Transfer landed on Solana devnet | **yes** — finalized in 2 s, payee received exactly 1,000,000 lamports |
| Refusals proven against the live contract | `harness/prove_the_jail.py` |
| Locked-account proof | **not yet** — the property is stated, not demonstrated |
| Session expiry / function-call-key layer | **not yet** |

### The landed transfer

```
agent asks ->  policy passes ->  v1.signer (Ed25519, 11-of-16) ->  verified locally ->  devnet
Leash  0.500000000 -> 0.498995000 SOL   (-1,005,000 = 1,000,000 transfer + 5,000 fee)
payee  0.000000000 -> 0.001000000 SOL   (+1,000,000, exactly as the policy authorised)
```

Run it yourself: `harness/land_transfer.py`. It verifies the signature **before** broadcasting —
never submit bytes you have not checked — and asserts the payee's balance moved by exactly the
authorised amount, not merely that a transaction succeeded.
