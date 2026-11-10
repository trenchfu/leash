# Mainnet

Leash is deployed on **NEAR testnet only** today. There is no mainnet deployment. Figures and
account ids below are from [`VERSIONS.md`](../VERSIONS.md); treat that file as the build record.

## What is deployed where (today)

| network | status |
|---|---|
| NEAR **testnet** | deployed — see table below |
| NEAR **mainnet** | **not deployed** |
| Solana | the derived address is used on **devnet** for live transfer proofs; mainnet Solana funds are out of scope until a mainnet NEAR deploy exists |

| account (testnet) | role | notes |
|---|---|---|
| `leash-b0c503d6.testnet` | main development contract | still holds **1 full-access key** — policy is not yet a custody boundary on this account |
| `leash-locked-7f0c6d.testnet` | locked snapshot | **zero** access keys; custody demonstration account |
| MPC signer | `v1.signer-prod.testnet` | measured 11-of-16 (see README / VERIFIED-FACTS) |

Pinned portable rebuild (what you should put on chain next): **458,234 bytes**, sha256 prefix
`c70089857a9efaa0` — produced by `./build-reproducible.sh`. The currently deployed testnet artifact
is an older, host-path-embedded build and is **not** byte-identical to the portable rebuild; see
VERSIONS.md.

## Build reproducibly and verify a code hash

```bash
# Produce the portable wasm (no host paths in the artifact)
./build-reproducible.sh

# Assert the local rebuild matches the portable hash claimed in VERSIONS.md.
# Full ./verify.sh also hits testnet RPC (view_code / access keys); skip that
# offline, or run only the local build + sha256 check yourself:
sha256sum contract/target/wasm32-unknown-unknown/release/leash.wasm
# expect prefix: c70089857a9efaa0  (full digest in VERSIONS.md)
```

To compare against a **deployed** account's code (any network), fetch `view_code`, sha256 the
returned bytes yourself, and compare to your local rebuild. Do not trust the RPC's `code_hash`
field alone as your only check — derive the hash from the bytes.

Offline policy suite (no network):

```bash
cd contract && cargo test
```

## How to deploy to mainnet (placeholders only)

Do **not** copy testnet account ids into mainnet commands. Replace every placeholder.

1. **Create / fund** a NEAR mainnet account you control: `<ACCOUNT_ID>`.
2. **Build** the portable artifact: `./build-reproducible.sh`.
3. **Deploy** the wasm to `<ACCOUNT_ID>` (near-cli or equivalent), then call `new` with:
   - `owner`: `<OWNER_ACCOUNT_ID>`
   - `mpc_contract`: the mainnet Chain Signatures signer account id for your intended domain
     (confirm against current NEAR docs / `v1.signer` mainnet state — do not assume the testnet id)
   - `derivation_path`: e.g. `solana-1` (must match how you derive / publish the Solana address)
   - `solana_address`: `<SOLANA_ADDRESS>` derived for `(<ACCOUNT_ID>, <path>)` under that MPC
4. **Set agent policy** (owner only) — see below.
5. **Fund** the derived Solana address on the Solana cluster you intend to pay on.
6. **Lock** the NEAR account (delete every full-access key) **only after** the last intended code
   change. A locked account cannot be upgraded. Until then, the policy is not a custody boundary.
7. **Record** the deployed sha256 / code hash in your own runbook (this repo's VERSIONS.md is the
   testnet record).

Example shape (illustrative; tool flags change — check your CLI):

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
  prepaid-gas '<MEASURED_TGAS>' attached-deposit '0 NEAR' \
  sign-as <ACCOUNT_ID> network-config mainnet
# `new` does not check the caller, so it must be signed by a full-access key on <ACCOUNT_ID> itself, in the same
# session as the deploy (deploy + init together), before anyone else can call it. Measure the gas on testnet first.
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
| `allowed_recipients` | base58 Solana addresses; **empty means nobody** (fail-closed) |
| `expires_at_ms` | session end (ms since epoch); `0` means no expiry (owner must ask for it) |

Rolling window length is a contract constant: **24 hours** (`WINDOW_MS` in `contract/src/policy.rs`).

Related owner calls: `set_agent_enabled`, `reset_agent_window`, plus the SPL mint-rule setters for
token transfers. Agents never hold the Solana key; they only call the contract with parameters.

## Costs (measure before deploy)

Do **not** invent gas or storage numbers here. Before a mainnet deploy, measure on the target
network (or a fresh testnet account with the same wasm):

- **Storage staking** for the contract wasm + initial state (`new`, empty agent map, log ring).
- **Gas** for `new`, `set_agent_policy`, and a sample `request_transfer` (includes the cross-contract
  MPC `sign` deposit of 1 yoctoNEAR plus forwarded gas — see `SIGN_GAS` / `SIGN_DEPOSIT` in
  `contract/src/lib.rs`).
- **Ongoing**: each agent policy and mint rule adds storage; the decision log is a bounded ring
  (`log_cap`, default 256).

If a figure is not measured for your account size and toolchain, leave it unstated.

## Trust model (plain words)

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
- It cannot stop a locked account's past deploy from being wrong — verify the code hash yourself
  before you treat a sender as policed Leash (`harness/verify_leash_payment.py` describes the
  counterparty checks).
