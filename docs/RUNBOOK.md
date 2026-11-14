# Runbook

Three tiers, separated on purpose: what **anyone** can run, what **anyone can verify on chain
without our keys**, and what **only the account holder** can execute.

A reviewer should be able to reach a verdict from the first two tiers alone.

---

## Tier 1 — runs offline, no keys, no network

```bash
./verify.sh          # all three tiers below, one command
cd contract && cargo test   # or just the offline suite
```

**72 tests, 0 failed.** This is the whole policy core and the Solana message builder. It needs no
network because `contract/src/policy.rs` keeps the spend decision a pure function of
`(policy, request, clock)` — that is the design, not a convenience.

What it establishes: boundary behaviour on both sides of each limit, that a backwards clock cannot
silence a limit, that an empty allowlist denies everything, and that the set of refusal variants
actually entered by tests equals the full set declared. Add a refusal without a test and the build
fails.

Toolchain: Rust stable with `wasm32-unknown-unknown` for a build; the test suite itself is host-native.

## Tier 2 — verify our claims on chain, with no keys at all

Every live claim resolves to a public record. Independent checks, no credentials:

```bash
# the deployed contract and its exact bytes
curl -s -X POST https://rpc.testnet.near.org -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":"1","method":"query",
  "params":{"request_type":"view_code","finality":"final",
            "account_id":"leash-b0c503d6.testnet"}}' | head -c 200
```

| claim | account / id | independent check |
|---|---|---|
| contract deployed | `leash-b0c503d6.testnet` | `view_code` → 458,248 bytes, hash `59HB5memEzCQMXoWe6mD7KX3ysvYMZoVBHPXVyt4tr64` (redeployed 2026-11-11 as the reproducible build; the previous 459,050 B / `FksLFKoe…` artifact is superseded and is **not** re-derivable — see VERSIONS.md) |
| the account is **locked** | `leash-locked-7f0c6d.testnet` | `view_access_key_list` → **zero** `FullAccess` keys |
| the MAIN contract is **locked** | `leash-b0c503d6.testnet` | `view_access_key_list` → **zero** keys of any kind, since 2026-11-11 (tx `DFG8xfJR6TMar32CGWG31GE4T6JpZMWVQJk6ydsghmGW`) |
| Leash's Solana address | `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL` | Solana **devnet** account history |
| the MPC signer | `v1.signer-prod.testnet` | `state` → committee threshold |

The locked-account check is the one that matters most, and it is the one you should not take on
trust: a policy contract on an **unlocked** account is theatre, because a full-access key can
redeploy it without the policy. `view_access_key_list` returning no `FullAccess` entry is the
whole guarantee, and it is a public read.

## Tier 3 — requires our testnet account keys (not in this repo)

These scripts drive accounts whose keys are **not** committed and never will be. They are here so
the method is auditable, not so a stranger can re-run them.

| script | what it proves |
|---|---|
| `harness/land_transfer.py` | end to end: agent asks → policy passes → MPC signs → devnet transfer lands. Verifies the Ed25519 signature **before** broadcast and asserts the payee balance moved by exactly the authorised amount |
| `harness/prove_the_jail.py` | every refusal the contract claims is **reachable** against the live contract — a verifier that cannot fail is not a verifier |
| `harness/prove_locked_account.py` | the attack is demonstrated on an unlocked account, then refused by the chain on a locked one |
| `harness/verify_signature.py` | the signature is a valid Ed25519 signature by Leash's own derived key |
| `harness/verify_leash_payment.py` | counterparty view: is this payment's sender a *policed* Leash? |
| `harness/run_action_v2.py`, `run_action_v3.py` | teletask certification with Leash as the provider, across both asset kinds |
| `harness/land_spl_transfer.py` | the same guarantee for an SPL `TransferChecked`, not just lamports |

### Local fixtures (`harness/.state/`)

Harness scripts need NEAR account ids and Solana addresses from a lab run. Those used to sit as
tracked dot-files in the repo root; they are now **local-only**:

- Put fixtures in `harness/.state/` (gitignored), same filenames as before
  (`.contract-account`, `.agent-account`, `.solana-address`, …).
- Or set env overrides (see `harness/state_io.py`): `LEASH_CONTRACT`, `LEASH_ADDRESS`,
  `LEASH_RECIPIENT`, `LEASH_AGENT`, `LEASH_OWNER`, `LEASH_LOCKED`, `LEASH_ATTACK`,
  `LEASH_ROGUE_ACCOUNT`, `LEASH_DENIED_RECIPIENT`, plus `LEASH_STATE_DIR` to relocate the folder.
- Also used by runners: `LEASH_LAMPORTS`, `LEASH_TASKS`, `LEASH_SET_POLICY`, `LEASH_SKIP_ACCEPT`.

Widening the harness widens no authority: the policy still refuses any recipient the owner has not
allowlisted, on chain.

### Interpreter

Scripts use `#!/usr/bin/env python3` and need **3.8+**. They carry a guard that refuses an older
interpreter with a verdict rather than a traceback — but state its real coverage honestly: the
guard is reachable on 3.6 and 3.7, while **3.5 and below fail earlier, at parse time**, because the
files use modern syntax. That is still a refusal; it is just not one we designed, and we will not
claim otherwise.

---

## What this repo does NOT establish

Read [`VERIFIED-FACTS.md`](VERIFIED-FACTS.md) for the full list, and [`../VERSIONS.md`](../VERSIONS.md)
for the build record. The two limits worth stating here:

1. **Signature provenance beyond the committee.** The build *is* byte-reproducible (`./verify.sh`
   proves it), but reproducibility of the code says nothing about who holds the signing shares.
2. **Trust moves, it does not vanish.** Signatures come from an MPC committee. Leash removes
   unilateral agent control over a key; it does not remove the committee.
