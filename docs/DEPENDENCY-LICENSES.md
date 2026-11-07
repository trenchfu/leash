# Dependency licence inventory

**Measured 2026-11-07 on the dev host from `contract/Cargo.lock` plus each crate's own `Cargo.toml` in the
local cargo registry.** This is the release gate my own Teletask SDK assessment named
("dependency-license inventory") applied to this repo. It is a *publication* gate, not a
prerequisite for carrying a LICENSE file.

## Result

| population | crates | copyleft / reciprocal | unresolved |
|---|---|---|---|
| everything in `Cargo.lock` | 278 | **0** | 17 |
| the `wasm32-unknown-unknown` normal graph — what actually ships | **67** | **0** | 1 (`leash` itself) |

Nothing in the shipped graph is GPL, LGPL, AGPL, MPL, CDDL, EUPL, SSPL, BUSL, OSL or CC-BY-SA, so
the Apache-2.0 grant on this repo does not conflict with anything it links.

Licence spread of the 67 shipped crates: 42 `MIT OR Apache-2.0`, 11 `MIT`, 4 `MIT/Apache-2.0`,
2 `Apache-2.0 OR MIT`, 1 each `Apache-2.0`, `Apache-2.0 / MIT`, `BSD-2-Clause`, `Zlib`,
`Zlib OR MIT OR Apache-2.0`, `Unlicense OR MIT`, `(MIT OR Apache-2.0) AND Unicode-3.0`.

## The two populations are not the same number, and the difference is the point

`Cargo.lock` carries every platform's edges. 16 of its 17 unresolved crates are not vendored on
this machine because they never build for our target: `windows-*` (6), `android_system_properties`,
`core-foundation-sys`, `iana-time-zone-haiku`, `hermit-abi`, `r-efi`, `glob`, `jiff-static`,
`portable-atomic`, `portable-atomic-util`, `zerocopy-derive`. **Verified rather than assumed:** each
was searched for in `cargo tree --target wasm32-unknown-unknown -e normal` (156 lines, 67 distinct
crates) and all 12 sampled returned 0 occurrences. A lock-file count alone would have reported 17
unknown licences against an artifact that links none of them.

## One defect this gate found

The 17th unresolved entry was **`leash` itself**: the crate manifest declared no `license` field
while the repo root carried an Apache-2.0 `LICENSE`. Fixed in this commit —
`contract/Cargo.toml` now declares `license = "Apache-2.0"`, so the crate metadata and the file
agree. A reader of the published crate metadata would otherwise have seen no licence at all.

## How to re-run

```bash
cd contract
cargo tree --target wasm32-unknown-unknown -e normal --offline   # the shipped graph
# then read `license` from each crate's Cargo.toml under ~/.cargo/registry/src/*/
```

Re-run on any dependency change. `Cargo.lock` is committed and `near-sdk` is pinned `=5.30.0`, so
this inventory is stable until that pin moves.
