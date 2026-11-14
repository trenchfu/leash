# Mainnet

Leash is deployed on NEAR **testnet only**. There is no mainnet deployment. Account ids and figures below are
in [`../CHANGELOG.md`](../CHANGELOG.md).

## What is deployed where

| network | status |
|---|---|
| NEAR **testnet** | deployed, see below |
| NEAR **mainnet** | not deployed |
| Solana | the derived address is used on **devnet** for transfers; Solana mainnet funds wait for a NEAR mainnet deploy |

| account (testnet) | role | notes |
|---|---|---|
| `leash-b0c503d6.testnet` | main contract | **zero** access keys, locked 2026-11-11 in tx `DFG8xfJR6TMar32CGWG31GE4T6JpZMWVQJk6ydsghmGW`; the policy is a custody boundary on this account |
| `leash-locked-7f0c6d.testnet` | locked snapshot | **zero** access keys; custody demonstration account |
| MPC signer | `v1.signer-prod.testnet` | 11-of-16 (see [`STATUS.md`](STATUS.md)) |

Pinned reproducible build: **458,248 bytes**, sha256 prefix `3d8dae96c0eea6ee`, produced by
`./contract/build.sh`, the only build recipe. The deployed testnet artifact is byte-identical to it, and
`./verify.sh` checks that.

## Build and check a code hash

```bash
# Produce the reproducible wasm (no host paths in the artifact)
./contract/build.sh

# Hash the local build. ./verify.sh also queries testnet RPC (view_code, access keys),
# so run just this check when offline:
sha256sum contract/target/wasm32-unknown-unknown/release/leash.wasm
# expect prefix: 3d8dae96c0eea6ee  (full digest in CHANGELOG.md)
```

To compare with a **deployed** account (any network), fetch `view_code`, sha256 the returned bytes, and
compare with your local rebuild. Hash the bytes rather than reading the RPC's `code_hash` field.

Offline policy suite (no network):

```bash
cd contract && cargo test
```

## Deploy to mainnet (placeholders only)

Replace every placeholder; do not reuse testnet account ids. Keep the steps in this order. A wrong
`solana_address` cannot be fixed after the lock.

1. **Create** a NEAR mainnet account you control, `<ACCOUNT_ID>`, and **fund** it.
2. **Build** the reproducible artifact: `./contract/build.sh`.
3. **Deploy** the wasm to `<ACCOUNT_ID>` (near-cli or equivalent) and assemble the `new` arguments:
   - `owner`: `<OWNER_ACCOUNT_ID>`
   - `mpc_contract`: the mainnet Chain Signatures signer account id for your domain (check the current NEAR docs and the `v1.signer` mainnet state; the testnet id does not apply)
   - `derivation_path`: for example `solana-1`
   - `solana_address`: `<SOLANA_ADDRESS>`, derived for `(<ACCOUNT_ID>, <path>)`
4. **Derive and verify the Solana address** for that account id and path against the **mainnet** signer, before
   calling `new`. `new` only checks that `solana_address` decodes to a 32-byte base58 key; it does not check
   that the MPC will sign for it. The derivation depends on the signer's root key, the predecessor account id and
   the path, and all three differ between networks, so a testnet-derived address is never valid on mainnet. If the
   derived address does not match, stop. When it matches, send `new`.
5. **Initialise** with `new`, then set agent policy (owner only, see below).
6. **Fund** the derived Solana address on the cluster you will pay on, and send small test transfers (dust)
   through the contract to confirm signing and landing.
7. **Lock** the NEAR account (delete every full-access key) last, after the final code change. A locked account
   cannot be upgraded, and until it is locked the policy is not a custody boundary.
8. **Record** the deployed sha256 and code hash in your own runbook.

Example (flags vary by CLI version):

```bash
near contract deploy <ACCOUNT_ID> use-file contract/target/wasm32-unknown-unknown/release/leash.wasm \
  network-config mainnet

near contract call-function as-transaction <ACCOUNT_ID> new \
  json-args '{
    "owner": "<OWNER_ACCOUNT_ID>",
    "mpc_contract": "<MPC_SIGNER_ACCOUNT_ID>",
    "derivation_path": "solana-1",
    "solana_address": "<SOLANA_ADDRESS>"
  }' \
  prepaid-gas '<TGAS>' attached-deposit '0 NEAR' \
  sign-as <ACCOUNT_ID> network-config mainnet
# `new` does not check the caller. Sign it with a full-access key on <ACCOUNT_ID> in the same session as the
# deploy, before anyone else can call it. Measure the gas on testnet first.
```

## Policy defaults and how an owner sets them

There is **no ambient default spend policy**. After `new`, the agent map is empty: any caller is
an `unknown agent` until the owner registers them.

Owner-only `set_agent_policy` fields:

| field | meaning |
|---|---|
| `agent` | NEAR account id allowed to request transfers |
| `per_tx_lamports` | hard ceiling for a single native transfer |
| `window_lamports` | hard ceiling across the rolling window |
| `allowed_recipients` | base58 Solana addresses; **empty means nobody** |
| `expires_at_ms` | session end (ms since epoch); `0` means no expiry |

Rolling window length is a contract constant: **24 hours** (`WINDOW_MS` in `contract/src/policy.rs`).

Related owner calls: `set_agent_enabled`, `reset_agent_window`, plus the SPL mint-rule setters for
token transfers. Agents never hold the Solana key; they only call the contract with parameters.

## Costs (measure before deploy)

No gas or storage figures are published here. Before a mainnet deploy, measure on the target network (or a
fresh testnet account with the same wasm):

- **Storage staking** for the contract wasm + initial state (`new`, empty agent map, log ring).
- **Gas** for `new`, `set_agent_policy`, and a sample `request_transfer` (includes the cross-contract
  MPC `sign` deposit of 1 yoctoNEAR plus forwarded gas — see `SIGN_GAS` / `SIGN_DEPOSIT` in
  `contract/src/lib.rs`).
- **Ongoing**: each agent policy and mint rule adds storage; the decision log is a bounded ring
  (`log_cap`, default 256).

## Trust model

**What the contract enforces**

- The Solana key is derived from the **contract account** as MPC predecessor + path. The agent
  never holds that key and never supplies signable bytes — only parameters the contract turns into
  a message it constructed itself.
- Spend decisions are policy-gated: known agent, enabled, non-zero amount, allowlist, per-tx and
  window ceilings, optional session expiry. Refusals are returned and logged, not silent.
- For transfers (`request_transfer`), an empty allowlist denies every recipient. Unknown agents are refused on every call.
  The no-value actions (`request_accept_task`, `request_submit_evidence`) are checked for a known, enabled, unexpired agent
  but do not consult `allowed_recipients`, because they move no value.

**What it cannot**

- It cannot protect you if a **full-access key** remains on the contract account: that key can
  redeploy code or act as the account. Locking (zero full-access keys) is required for custody.
- It cannot remove the MPC committee: signatures still come from the signer set (trust moves).
- It cannot see Solana mint metadata or balances; SPL rules are the owner's asserted parameters.
- It cannot make a locked account's deployed code correct. Check the code hash before you treat a sender as a
  policed Leash (`harness/verify_leash_payment.py` describes the counterparty checks).
