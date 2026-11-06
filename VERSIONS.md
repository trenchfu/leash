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

### Reproducibility status — READ THIS BEFORE CITING A BUILD

**The deployed artifact is not yet byte-reproducible from this tree.** Rebuilding the deployed
source with the pinned dependency tree and `--cfg near` yields **459,042 bytes**, against the
deployed **459,050**. The 8-byte gap is unexplained and is *not* attributed to any source change.
What *is* measured: applying the WL-CL-020 patch to that same tree changes the output by exactly
**29 bytes**, and host-import sets are identical (37 imports, none only-deployed, none only-local).

Consequences, stated rather than buried:

- A claim of the form "this source produced that on-chain artifact" is **UNVERIFIED** at byte level.
- A claim of the form "this patch costs 29 bytes against its own baseline" **is** verified, because
  both sides of that comparison were built here under identical flags.
- `--cfg near` is load-bearing, not cosmetic: without it the build substitutes a software sha256 for
  the host function, which moves gas. A rebuild that omits it is a different contract.

### Why the declared dependency is not the shipped one

`near-sdk = "5.6.0"` is a caret requirement and resolves today to a much later release. The
committed `Cargo.lock` is what actually fixes the version at 5.30.0. Reading a dependency's version
off `Cargo.toml` instead of off the lock or the artifact is how this repo's own history recorded a
wrong SDK version once; the lock is the source of truth here.
