# Versions

Every tag maps to a crate version, an exact dependency pin, the build flags, and the on-chain
artifact it corresponds to. Figures below were re-read from `rpc.testnet.near.org` at block
276550495 / 276550502 and the sha256 was re-derived from the returned bytes, not copied from the
RPC's own `code_hash` field (the two agree).

## v0.1.0

| field | value |
|---|---|
| crate | `leash` 0.1.0 (`contract/Cargo.toml`) |
| near-sdk, resolved | **5.30.0** (`contract/Cargo.lock`) |
| near-sdk, declared | `5.6.0` — a **caret** requirement, i.e. a floor, not the shipped version |
| build flags | `rustflags = ["--cfg", "near"]` (`contract/.cargo/config.toml`) |
| profile | `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `overflow-checks = true` |
| target | `wasm32-unknown-unknown` |

### Deployed artifacts

| account | role | bytes | code hash (base58) | sha256[:16] |
|---|---|---:|---|---|
| `leash-b0c503d6.testnet` | main contract | 459,050 | `FksLFKoeD6Xco1D9omAQ2hrhczMwNjVnt27T2u89kkbt` | `db40808d5b6ad22f` |
| `leash-locked-7f0c6d.testnet` | locked snapshot (access-key-less) | 305,580 | `4iHvhQNszRYgJsU27o37okn5nZ1n9icYJ68RjaksfLYq` | `372703139fccf4e6` |

### Reproducibility status — VERIFIED

**The deployed artifact rebuilds byte-for-byte from this tree.** Proven with a clean build into an
empty target directory (46.8 s, no cache):

```
rebuilt   459,050 bytes  sha256 db40808d5b6ad22f733f2ff674d91913af1eb21a2e81a5f41e4012816922b30b
deployed  459,050 bytes  sha256 db40808d5b6ad22f733f2ff674d91913af1eb21a2e81a5f41e4012816922b30b
IDENTICAL
```

Reproduce it yourself with `./verify.sh` at the repo root — it rebuilds, fetches the deployed code
from `rpc.testnet.near.org`, and derives the hash **from the returned bytes** rather than trusting
the RPC's own `code_hash` field.

**CORRECTION, 2026-11-06.** An earlier revision of this file stated the opposite — that a rebuild
gave 459,042 against 459,050, an 8-byte gap. That was wrong. The 459,042 figure came from rebuilding
a separate *evidence package* tree, not this repository, at a time when this repository was wrongly
believed not to exist. The gap measured a difference between that package and this repo; it was
never a property of this source. Recorded here rather than quietly deleted, because anyone who read
the earlier claim deserves to find its retraction in the same place.

### Dependency pinning

`near-sdk` is pinned **exactly** (`=5.30.0`), not by caret. The pin was landed with a two-sided
control, because a pin that constrains nothing is decoration:

- **It binds:** under the pin, `cargo update -p near-sdk` locks 0 packages.
- **The drift it prevents is real:** under the previous caret `^5.6.0`, `cargo update` moves 12
  packages, `near-sdk` among them (5.30.0 → 5.30.1).
- **It is byte-neutral:** a clean rebuild under the pin produces the same 459,050 bytes and the same
  sha256, and `Cargo.lock` is unchanged. The pin removes a future hazard without moving the artifact.

### Why the declared dependency is not the shipped one

`near-sdk = "5.6.0"` is a caret requirement and resolves today to a much later release. The
committed `Cargo.lock` is what actually fixes the version at 5.30.0. Reading a dependency's version
off `Cargo.toml` instead of off the lock or the artifact is how this repo's own history recorded a
wrong SDK version once; the lock is the source of truth here.
