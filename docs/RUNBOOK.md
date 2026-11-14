# Runbook

Three tiers: what anyone can run offline, what anyone can read on chain without keys, and what needs the
account holder's keys.

---

## Tier 1 — runs offline, no keys, no network

```bash
./verify.sh          # Tiers 1-2 below, one command (Tier 3 needs keys)
cd contract && cargo test   # or just the offline suite
```

**72 tests, 0 failed.** They cover the policy core and the Solana message builder. No network is needed
because `contract/src/policy.rs` keeps the spend decision a pure function of `(policy, request, clock)`.

The tests check boundary behaviour on both sides of each limit, that a backwards clock cannot silence a limit,
that an empty allowlist denies everything, and that the refusal variants entered by tests equal the full set
declared. Adding a refusal without a test fails the build.

Toolchain: Rust stable with `wasm32-unknown-unknown` for a build; the test suite itself is host-native.

## Tier 2 — read the chain, no keys

Public records only, no credentials:

```bash
# the deployed contract and its exact bytes
curl -s -X POST https://rpc.testnet.near.org -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":"1","method":"query",
  "params":{"request_type":"view_code","finality":"final",
            "account_id":"leash-b0c503d6.testnet"}}' | head -c 200
```

| item | account / id | check |
|---|---|---|
| contract deployed | `leash-b0c503d6.testnet` | `view_code` returns 458,248 bytes, hash `59HB5memEzCQMXoWe6mD7KX3ysvYMZoVBHPXVyt4tr64` (redeployed 2026-11-11 as the reproducible build; see [`CHANGELOG.md`](../CHANGELOG.md)) |
| snapshot account locked | `leash-locked-7f0c6d.testnet` | `view_access_key_list` returns zero `FullAccess` keys |
| main contract locked | `leash-b0c503d6.testnet` | `view_access_key_list` returns zero keys of any kind, since 2026-11-11 (tx `DFG8xfJR6TMar32CGWG31GE4T6JpZMWVQJk6ydsghmGW`) |
| Leash's Solana address | `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL` | Solana **devnet** account history (devnet only: do not send mainnet funds here) |
| MPC signer | `v1.signer-prod.testnet` | `state` shows the committee threshold |

The lock is the most important check. A policy contract on an unlocked account can be redeployed by a
full-access key without the policy. `view_access_key_list` with no `FullAccess` entry is a public read.

## Tier 3 — requires our testnet account keys (not in this repo)

These scripts drive accounts whose keys are not in the repo. They document the method and are not meant to be re-run by third parties.

| script | what it does |
|---|---|
| `harness/land_transfer.py` | end to end: agent asks → policy passes → MPC signs → devnet transfer lands. Verifies the Ed25519 signature **before** broadcast and asserts the payee balance moved by exactly the authorised amount |
| `harness/prove_the_jail.py` | calls the live contract so that every refusal reason is triggered |
| `harness/prove_locked_account.py` | runs the redeploy attack on an unlocked account, then on a locked one where the chain refuses it |
| `harness/verify_signature.py` | checks that the signature is a valid Ed25519 signature by Leash's derived key |
| `harness/verify_leash_payment.py` | counterparty view: checks whether a payment's sender is a policed Leash |
| `harness/run_action_v2.py`, `run_action_v3.py` | teletask certification with Leash as the provider, across both asset kinds |
| `harness/land_spl_transfer.py` | the same flow for an SPL `TransferChecked`, not just lamports |

### Local fixtures (`harness/.state/`)

Harness scripts read NEAR account ids and Solana addresses from local fixtures:

- Put fixtures in `harness/.state/` (gitignored), for example
  `.contract-account`, `.agent-account`, `.solana-address`.
- Or set env overrides (see `harness/state_io.py`): `LEASH_CONTRACT`, `LEASH_ADDRESS`,
  `LEASH_RECIPIENT`, `LEASH_AGENT`, `LEASH_OWNER`, `LEASH_LOCKED`, `LEASH_ATTACK`,
  `LEASH_ROGUE_ACCOUNT`, `LEASH_DENIED_RECIPIENT`, plus `LEASH_STATE_DIR` to relocate the folder.
- Also used by runners: `LEASH_LAMPORTS`, `LEASH_TASKS`, `LEASH_SET_POLICY`, `LEASH_SKIP_ACCEPT`.

The policy still refuses any recipient the owner has not allowlisted, on chain.

### Interpreter

Scripts use `#!/usr/bin/env python3` and need Python 3.8 or newer. On 3.6 and 3.7 they print a refusal message;
3.5 and below fail at parse time.

---

## Limits

Deployed state and open limits are in [`STATUS.md`](STATUS.md); the build record is in
[`../CHANGELOG.md`](../CHANGELOG.md).

1. **Signing shares.** The build is byte-reproducible (`./verify.sh`), but that says nothing about who holds the
   MPC signing shares.
2. **The committee.** Signatures come from an MPC committee. Leash removes unilateral agent control over a key;
   it does not remove the committee.
