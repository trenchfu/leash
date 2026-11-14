# Changelog

Newest first. Build recipe: `contract/build.sh`, toolchain `1.95.0` pinned in
`contract/rust-toolchain.toml`. `./verify.sh` checks the figures below against the chain.

## 2026-11-14

- Documentation rewritten; `VERSIONS.md` is now this file and `docs/VERIFIED-FACTS.md` is now `docs/STATUS.md`.
- Added `docs/MAINNET.md` step that checks the derived Solana address before `new`.

## 2026-11-11

- `leash-b0c503d6.testnet` is locked: zero access keys, tx `DFG8xfJR6TMar32CGWG31GE4T6JpZMWVQJk6ydsghmGW`.
  A redeploy of different bytes is refused by the chain; both the native SOL and SPL `TransferChecked` paths still work.
  Lifetime counters, agent policy and mint rules are unchanged by the lock.
- Redeployed `leash-b0c503d6.testnet` as the reproducible build. 458,248 bytes, sha256
  `3d8dae96c0eea6ee999c333031ae9b6152174c017830046cf7737a1eae91bf11`, code hash
  `59HB5memEzCQMXoWe6mD7KX3ysvYMZoVBHPXVyt4tr64`. Replaces `FksLFKoeD6Xco1D9omAQ2hrhczMwNjVnt27T2u89kkbt`
  (459,050 bytes, sha256 prefix `db40808d5b6ad22f`, deployed 2026-11-05), which cannot be rebuilt because its
  build machine had the optional `rust-src` component installed. State was not migrated; `struct Leash`,
  `enum Key` and `struct Policy` are unchanged.
- Fix: `set_agent_policy` keeps `enabled` for an existing agent and defaults it to `true` only for a new one.
  Before, a renewal re-enabled a disabled agent. `tools/leash_wlcl020_probe.py` exercises it against the live agent.
- `contract/build.sh` maps the `rust-src` tree onto the canonical `/rustc/<commit>` path, so the build is
  identical with or without that component (458,248 bytes, `3d8dae96c0eea6ee` either way). With `rust-src`
  installed, the earlier recipe produced 457,760 bytes (`84f9da6cbcd797e7`).
- `build.sh` is the only build recipe. `build-reproducible.sh` (458,234 bytes, `c70089857a9efaa0`) is retired and
  exits with status 2. `verify.sh` calls `build.sh`.
- To rebuild without reading any expected figure: clone, check out the commit, run `cd contract && ./build.sh`,
  record the bytes and sha256, then run `./verify.sh` to compare against the deployed contract.

## 2026-11-07

- `near-sdk` is pinned exactly (`=5.30.0`); `contract/Cargo.lock` fixes the resolved version.
  A caret requirement (`5.6.0`) would let `cargo update` move 12 packages.
- Dependency licence inventory added (`docs/DEPENDENCY-LICENSES.md`); the crate declares Apache-2.0.

## 2026-11-06

- `verify.sh` added. Compiler pinned through `rust-toolchain.toml`.
- Build settings: `rustflags = ["--cfg", "near"]`, `opt-level = "z"`, `lto = true`, `codegen-units = 1`,
  `overflow-checks = true`, target `wasm32-unknown-unknown`.

## 2026-11-05

- Deployed `leash-b0c503d6.testnet` as 459,050 bytes, code hash `FksLFKoeD6Xco1D9omAQ2hrhczMwNjVnt27T2u89kkbt`.
  Includes the stale-window refund fix, `list_mint_rules` and owner-attested `refund_expired`.

## 2026-11-03

- Refusals are returned and recorded instead of reverted. The decision log is a bounded ring of 256 records.
  Added `list_agents`, `get_totals`, `get_recent`. The v3 migration keeps agent policies.
- Function-call access key in front of the policy; locked-account experiment (15/15).
  `leash-locked-7f0c6d.testnet` is locked with zero keys, 305,580 bytes, code hash
  `4iHvhQNszRYgJsU27o37okn5nZ1n9icYJ68RjaksfLYq` (sha256 prefix `372703139fccf4e6`). It runs code from before the
  2026-11-11 `enabled` fix.
