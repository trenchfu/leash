# Status

## Deployed state

| item | value |
|---|---|
| Network | NEAR testnet; MPC signer `v1.signer-prod.testnet` |
| Contract | `leash-b0c503d6.testnet` |
| Owner / agent | `leash-owner-4c4054.testnet` / `leash-agent-064e6c.testnet` |
| Code | 458,248 bytes, code hash `59HB5memEzCQMXoWe6mD7KX3ysvYMZoVBHPXVyt4tr64`, sha256 prefix `3d8dae96c0eea6ee` |
| Access keys | 0 on `leash-b0c503d6.testnet` (locked 2026-11-11, tx `DFG8xfJR6TMar32CGWG31GE4T6JpZMWVQJk6ydsghmGW`) and 0 on `leash-locked-7f0c6d.testnet` |
| Solana address | `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL`, derived from (`leash-b0c503d6.testnet`, `solana-1`, domain 1). Testnet contract, devnet only: do not send mainnet funds here |
| MPC committee | 11 of 16. Mainnet `v1.signer`: block 222881663, epoch 14. Testnet `v1.signer-prod.testnet`: block 276060489, epoch 27 |
| Signing domain | domain 1 = Frost / Ed25519 / Sign on both networks |
| Policy | 72 unit tests; 24-hour rolling window; decision log is a ring of 256 records |

Demo transfer on Solana devnet: the agent asks, the policy passes, `v1.signer` signs with Ed25519, the
signature is checked locally, and the transaction is broadcast. Leash went from 0.500000000 to 0.498995000 SOL
(-1,005,000 lamports: 1,000,000 transfer plus 5,000 fee); the payee went from 0 to 0.001000000 SOL
(+1,000,000 lamports). After the lock, a native SOL transfer
(`ahYCpEPMJV9umftwL6EFH4qCH67M7i6zuG4U4onxHoGkyjoqzTmuRRuWN4rtg2orUZzgMx7mq9iLfbWxCdGT6xQ`) and an SPL
`TransferChecked` (`3Kz2cSWxRcFR3teYw9HVhU6TTtihQLpSQCs8xtGzq73Kwq2cUgTjqgkT4QVQfwDvJxRGdQ6zsDR2kHUHsZH2Xg8p`)
each moved the exact authorised amount on devnet.

## Design facts

- Chain Signatures derive a key from `(predecessor_account_id, path)` and nothing else
  (`near/mpc` @ `d0fc87b1`, `near-mpc-crypto-types/src/kdf.rs:10`). A contract that calls `sign()` is the
  predecessor, so the derived address belongs to the contract account.
- Derived addresses on `v1.signer-prod.testnet`:

  | predecessor | path | address |
  |---|---|---|
  | contract | `solana-1` | `Gqa8HZcVBJ8oHGbUDCxU1DFVfimNKxF1w3jJY9kx5DUL` |
  | agent | `solana-1` | `7FDz21w5Rf63GDmGtQXc2Dp7SnkM2rcUq6fUtjT7rbSC` |
  | contract | `solana-2` | `8PeSZNcHaLZM2DAa8VSYquB99fWbx3Ff7HdeEeMDYRnX` |

  The agent asking for the same path gets a different key, so it cannot reach Leash's address.
- `sign()` requires a deposit of 1 yoctoNEAR (`near-mpc-contract-interface/src/deposits.rs:4`).
- The MPC contract is `v1.signer-prod.testnet` on testnet and `v1.signer` on mainnet.
- The agent holds a function-call access key limited to receiver `leash-b0c503d6.testnet`, method
  `request_transfer`, allowance 0.25 NEAR. The policy then limits what that call can do: allowlist, per-tx
  ceiling, rolling window, session expiry.
- A refusal is a returned outcome, for example
  `{"allowed": false, "reason": "LEASH_REFUSED: over per-tx limit (limit 100000000, requested 500000000)"}`.
  The transaction succeeds, the reason is logged, and a record is written. The log is a bounded ring (256);
  lifetime counters outlive the ring.
- A key stays bound to the account, not the code. On an unlocked account a full-access key can replace Leash and
  keep the same address; on a locked account the chain refuses the redeploy (15/15 in
  `harness/prove_locked_account.py`). Lock the account last.

## Limits

- 11-of-16 is the current committee parameter, not a risk assessment. No operator-independence or jurisdiction analysis has been done.
- Access-key restrictions on the function-call key are checked client-side by `near-cli-rs`; a transaction
  submitted straight to the RPC has not been tested.
- The committee size can change. Leash reads `v1.signer.state` instead of storing a copy.
- Context: a refund flaw in NEAR Intents / HOT Bridge (2026-09-29 to 10-01) created unbacked balances, with
  3,865,021 USDT withdrawn on BNB chain. That is the Intents layer, not Chain Signatures. A Trail of Bits audit of
  the MPC (March 2025) reported 15 findings, 7 of them medium.

## How to re-read it yourself

Everything above except the demo transfers is a public read and needs no keys.

```bash
# deployed contract: bytes and hash (view_code)
curl -s -X POST https://rpc.testnet.near.org -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":"1","method":"query",
  "params":{"request_type":"view_code","finality":"final",
            "account_id":"leash-b0c503d6.testnet"}}' | head -c 200

# access keys: expect an empty list (view_access_key_list)
curl -s -X POST https://rpc.testnet.near.org -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":"1","method":"query",
  "params":{"request_type":"view_access_key_list","finality":"final",
            "account_id":"leash-b0c503d6.testnet"}}'
```

The MPC committee is the `state` view of `v1.signer-prod.testnet` (testnet) or `v1.signer` (mainnet).

Offline and on-chain checks in one command: `./verify.sh`. It rebuilds with `contract/build.sh`, compares
bytes and sha256 against the deployed contract, and reads access keys. Tier 3 in
[RUNBOOK.md](RUNBOOK.md) needs account keys and is not reproducible by third parties.
