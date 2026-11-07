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

### Reproducibility status — TWO ARTIFACTS, ONLY ONE OF THEM PORTABLE

| artifact | bytes | sha256[:16] | toolchain | embedded host paths | third-party reproducible |
|---|---:|---|---|---:|---|
| **deployed** on `leash-b0c503d6` | 459,050 | `db40808d5b6ad22f` | rustup `stable` | **15** | **NO** |
| **pinned rebuild** (this tree) | 458,442 | `3fe8d7b68eb53696` | `1.95.0` via `rust-toolchain.toml` | 0 | **YES** |

**The deployed artifact is not reproducible by anyone but its build machine.** It embeds 15 absolute
paths of the form `/home/<user>/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rust...`.
Reproducing it requires not merely the same compiler but the same rustup directory at the same
absolute path. That is the entire 608-byte difference.

**The pinned build is portable.** Built from two different absolute paths under
`rust-toolchain.toml`, it is byte-identical both times and contains zero host paths.

```
<repo>/contract          -> 458,442  3fe8d7b68eb53696cd6c8c23862a394d
/tmp/.../scratchpad/pathtest/contract        -> 458,442  3fe8d7b68eb53696cd6c8c23862a394d
```

**CORRECTION HISTORY — read this before citing any figure above.** This section has been wrong
twice, in opposite directions, and both are recorded rather than deleted:

1. First it claimed an unexplained 8-byte gap (459,042 vs 459,050). That came from rebuilding a
   separate *evidence package* tree, not this repo, while I wrongly believed this repo did not exist.
2. Then it claimed the deployed artifact was byte-reproducible, full stop. It is not. It reproduced
   **only on the machine that built it**, and my verification could not see that because it ran on
   that same machine. A peer re-deriving the claim on different hardware got 525,860 bytes under
   rustc 1.99.1 and reported the mismatch; that is the only reason this was caught before a judge
   ran `verify.sh`.

The lesson is recorded because it generalises: **a reproducibility check run only on the build
machine cannot detect machine-dependence.** It is the one defect that verification from a single
host is structurally blind to.

### Recommended before the next deploy

The pinned build is the one worth putting on chain: identical bytes for anyone with
`rust-toolchain.toml` and no host paths leaked into a public artifact. The WL-CL-020 fix requires a
deploy in any case, so that deploy should ship the pinned build — after which the deployed artifact
and this tree agree for everyone, and the lock can follow. Owner-signed; not done here.

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
