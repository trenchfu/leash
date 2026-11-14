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
the *immediate caller* and a path string, and nothing else. The relevant code in
[`near/mpc`](https://github.com/near/mpc) @ `d0fc87b1`:

- `crates/contract/src/api/sign.rs:36` — `sign()` resolves the caller:
  `let (domain_config, predecessor) = self.check_request_preconditions(...)`
- `crates/contract/src/api/sign.rs:63` — that same `predecessor` is what reaches the request:
  `SignatureRequest::new(request.domain_id, request.payload, &predecessor, &request.path)`
- `crates/near-mpc-crypto-types/src/kdf.rs:10` — `fn derive_tweak(predecessor_id: &AccountId, path: &str) -> Tweak`

That function signature admits no other input. When the **contract** calls `sign()`, the contract
is the predecessor, so the derived Solana address belongs to the contract's account. No other
account can be the predecessor for it. The contract is the custody boundary.

NEAR's documentation does not cover the contract-to-contract case; the behaviour above comes from the source.

### Why it cannot sign something other than what it checked

**A policy engine that signs bytes the agent handed it is not a policy engine.** If the agent supplies the
payload and a label such as "0.1 SOL to Alice", the contract would validate the label and sign something else.

So Leash never accepts signable bytes. The agent supplies **parameters** — recipient, lamports,
recent blockhash — and the contract **constructs** the Solana transfer message itself
(`contract/src/solana.rs`). The agent cannot express a transfer the policy did not authorise,
because it never gets to express the transfer at all.

---

## The lock

**The derived key follows the account, not the code.** A full-access key on the contract's account can
redeploy it without the policy, or act as that account directly. The guarantee therefore needs a
**locked account: zero full-access keys**. `harness/prove_locked_account.py` runs the attack on an unlocked
account and shows the chain refusing it on a locked one.

### Custody status

Both accounts carry zero access keys of any kind. Check with `view_access_key_list` on either one; it is a
public read.

`leash-b0c503d6.testnet`, the main contract, was locked on 2026-11-11 in tx
`DFG8xfJR6TMar32CGWG31GE4T6JpZMWVQJk6ydsghmGW`, after the last code change. A locked account cannot be
upgraded, so the lock comes last. No key holder can redeploy the contract without the policy.

After the lock:

* **The chain refuses a redeploy.** A redeploy of different bytes
  (`9gZgpFd9gSiD94k38DreFL9Md3ZxiVzXwS4wP7VZvceN`) with the signing key file still on disk was rejected with
  *"Access key for public key ed25519:8B88Ef… does not exist"*. `view_code` still returns the deployed hash.
* **The contract still works.** A native SOL transfer (devnet
  `ahYCpEPMJV9umftwL6EFH4qCH67M7i6zuG4U4onxHoGkyjoqzTmuRRuWN4rtg2orUZzgMx7mq9iLfbWxCdGT6xQ`) and an SPL
  `TransferChecked` (devnet
  `3Kz2cSWxRcFR3teYw9HVhU6TTtihQLpSQCs8xtGzq73Kwq2cUgTjqgkT4QVQfwDvJxRGdQ6zsDR2kHUHsZH2Xg8p`) each moved the
  exact amount. Owner- and agent-gated function calls and MPC signing need no access key on the account.
* **State is unchanged.** Lifetime counters, agent policy and both mint rules read the same before and after.

`leash-locked-7f0c6d.testnet` is the account used for the locked-versus-unlocked experiment. It is locked on
earlier code that predates the `enabled`-flag renewal fix.

Trust moves to the MPC committee, currently **11-of-16** (`v1.signer.state`, epoch 14, block 222869350,
read 2026-11-03). Leash removes unilateral agent control. It does not remove the committee.

---

## Tests

Status, deployed state and how to re-read it: [`docs/STATUS.md`](docs/STATUS.md).

The suite follows one rule: **a test that cannot fail is not a test.**

- `contract/src/policy.rs` — the spend decision is a **pure function** of (policy, request, clock).
  No storage, no environment, no network.
- Every refusal reason is a distinct variant, and the suite asserts that the set of refusal states
  actually *entered by tests* equals the full set of variants. Add a refusal without a test and the
  build fails.
- Boundaries are tested on both sides: the limit itself is allowed, one unit above is refused.
- A **backwards clock** does not silence the limit.
- An **empty allowlist denies everything**.

## Run it

```bash
cd contract && cargo test          # pure policy + message-construction suite, no network needed
```

Deployment, the live signature, and the locked-account experiment are in `harness/` — see
[`docs/RUNBOOK.md`](docs/RUNBOOK.md). Local harness account/address fixtures live in
`harness/.state/` (gitignored) or env vars — not in the repo root.

## Mainnet

**Testnet only today.** There is no mainnet deploy. How to build and verify a portable code hash,
how to deploy with placeholders, policy defaults, costs ("measure before deploy"), and the trust
model: [`docs/MAINNET.md`](docs/MAINNET.md). Build record: [`CHANGELOG.md`](CHANGELOG.md).

## Status

Built for the NEAR Hackathon (Nov 2026), **AI Security & Defense** track.
Targets NEAR **testnet** (`v1.signer-prod.testnet`).

| | |
|---|---|
| Policy core + Solana message builder | implemented, **72 unit tests**, mutation-checked |
| Contract deployed | `leash-b0c503d6.testnet` — 458,248 B, `59HB5memEzCQMXoWe6mD7KX3ysvYMZoVBHPXVyt4tr64`, **locked 2026-11-11: 0 access keys** |
| Leash's Solana address | `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL` (testnet contract, devnet only: do not send mainnet funds here) |
| Live Ed25519 signature from the MPC | executed; the signature is checked locally before broadcast |
| Transfer landed on Solana devnet | **yes** — finalized in 2 s, payee received exactly 1,000,000 lamports |
| Refusals exercised against the live contract | `harness/prove_the_jail.py` |
| Refusals recorded on chain | **yes** — returned as a verdict and written to a bounded ring, not reverted |
| Agent enumeration + lifetime counters | `list_agents`, `get_totals`, `get_recent` |
| Locked-account experiment | **15/15** — attack succeeds on an unlocked account, refused by the chain on a locked one (`leash-locked-7f0c6d.testnet`, **0 keys**) |
| Main contract locked | **yes, 2026-11-11** — `leash-b0c503d6.testnet` 1 → **0** keys (tx `DFG8xfJR…`); redeploy of different bytes refused by the chain; both money paths still land after the lock |
| Session expiry | live, two-sided, mutation-checked |
| Function-call-key layer | two locks in series, two-sided |

### The landed transfer

```
agent asks ->  policy passes ->  v1.signer (Ed25519, 11-of-16) ->  verified locally ->  devnet
Leash  0.500000000 -> 0.498995000 SOL   (-1,005,000 = 1,000,000 transfer + 5,000 fee)
payee  0.000000000 -> 0.001000000 SOL   (+1,000,000, exactly as the policy authorised)
```

`harness/land_transfer.py` runs it. It verifies the signature before broadcasting and checks that the payee's
balance moved by exactly the authorised amount.
