# Versions

Every tag maps to a crate version, an exact dependency pin, the build flags, and the on-chain
artifact it corresponds to. Figures below were re-read from `rpc.testnet.near.org` and the sha256
was re-derived from the returned bytes, not copied from the RPC's own `code_hash` field (the two
agree).

> **READ THIS FIRST — 2026-11-11.** `leash-b0c503d6.testnet` was **redeployed** with the WL-CL-020
> fix, shipping the **reproducible** build. For the first time the deployed artifact and this tree
> are byte-identical **for anyone**, so `./verify.sh` now asserts IDENTICAL and fails on a gap
> instead of explaining one. Everything below about a non-reproducible deployed artifact is
> **history**, kept deliberately — it describes the artifact that was replaced. The live figures are
> in *Deployed 2026-11-11* immediately below.

## Deployed 2026-11-11 — the reproducible build

| field | value |
|---|---|
| account | `leash-b0c503d6.testnet` (testnet dev contract) |
| bytes | **458,248** |
| sha256 | `3d8dae96c0eea6ee999c333031ae9b6152174c017830046cf7737a1eae91bf11` |
| code hash (base58) | `59HB5memEzCQMXoWe6mD7KX3ysvYMZoVBHPXVyt4tr64` |
| source | `9a05275` + `2b24f30` on `fix/wlcl020-renewal-preserves-enabled` (fix itself: `61023ca`) |
| recipe | `contract/build.sh` — the ONLY recipe; `verify.sh` runs the same script |
| toolchain | `1.95.0` via `rust-toolchain.toml`, `profile = "minimal"` |
| replaced | `FksLFKoeD6Xco1D9omAQ2hrhczMwNjVnt27T2u89kkbt`, 459,050 B, deployed 2026-11-05 |

**Re-derived on two machines before it was deployed.** the dev host and the build host independently produced
458,248 bytes and the same sha256 from the same commits, on different hardware and different
`$CARGO_HOME` paths. The deploy tool refuses any artifact whose hash is not the re-derived one, so
a binary nobody else reproduced cannot reach the chain through it.

**What changed functionally: one thing.** `set_agent_policy` now carries `enabled` forward for an
agent that already exists, and defaults it to `true` only for a new one (WL-CL-020). Previously a
renewal silently re-enabled a deliberately disabled agent.

**State was not migrated, because it did not need to be.** `struct Leash`, `enum Key` and
`struct Policy` are byte-identical between the replaced build's evidence copy and this source,
verified by diff rather than assumed. `get_totals`, `list_agents` and the agent policy were captured
before the deploy and re-read after: all three UNCHANGED.

**The fix was then proven ON CHAIN, not only by hash identity.** Byte identity shows the running
code is this source; it cannot show behaviour, because the defect only manifests on a write. So the
discriminating sequence was run against the live agent with `tools/leash_wlcl020_probe.py`:
disable → renew re-asserting every field including the same expiry → read back → restore.

```
after disable   enabled=False
after renewal   enabled=False     <- FIXED. Under the old build this read True.
                per_tx_lamports / window_lamports / expires_at_ms all UNCHANGED
restore         enabled=True      (the state the probe found; read back, not assumed)
```

The restore is installed before the mutation and runs on every exit path including an exception.
WL-CL-020 is therefore closed **on chain**, which is what Q's "clobber fix, then lock" order
requires before the lock.

### Why the REPLACED artifact can never be re-derived — cause located, not left open

`FksLFKoe…` (459,050 B) **cannot be made reproducible after the fact, and that is now a closed
question rather than an open one.** The cause: its build machine had **rust-src installed**, so
rustc spelled std paths as `/home/<user>/.rustup/toolchains/.../rust-src/...` instead of the
canonical `/rustc/<40-hex>/...` that is baked into the shipped std rlib. That machine state was
never recorded, and it is not recoverable from the artifact, the repo or the evidence package.
Three consequences, stated plainly:

- it is a **known, explained gap**, not a mystery hash;
- the recipe **cannot be repeated by accident** — `rust-toolchain.toml` pins `profile = "minimal"`,
  which excludes rust-src;
- replacing it **retires the question**: the old hash now survives only in testnet tx history.

The arithmetic is still not fully reconciled and is recorded as such: 15 std paths × 35 bytes = 525
against an observed 608-byte gap, the remainder coming from differing distinct-string counts
(15 vs 27). The *direction and cause* are established; the exact byte accounting is not.

### rust-src is a build input, and the first fix for it pointed at the wrong token

**Found 2026-11-11, second pass, by a positive control the first pass never ran.** The deployed
artifact is unchanged and needs no redeploy — but the *reproducibility claim* about it was false for
a large class of machines, and `build.sh` printed `-> reproducible` while it was false.

rustc spells std source paths two ways depending on an **optional component**:

| machine state | spelling | artifact under the FIRST fix |
|---|---|---:|
| rust-src **absent** | `/rustc/<40-hex-commit>/library/...` (canonical, in the shipped rlib) | 458,248 B `3d8dae96c0eea6ee` |
| rust-src **present** | `$SYSROOT/lib/rustlib/src/rust/library/...` | **457,760 B** `84f9da6cbcd797e7` |

The first fix remapped the rust-src tree to an **invented** token, `/rust-std`. That did not make the
two states agree — it gave the rust-src machine a *third* spelling. And the guard accepted
`/rust-std` **OR** `/rustc/`, so it could not tell the two apart and passed either way.

**Why two independent machines agreeing did not catch it:** neither had rust-src installed, so the
sysroot flag **fired zero times on both**. Their agreement was real and told us nothing about this
flag. A control that never executes the branch it guards is not a control —
the agreement was over a code path that was never taken.

**THE FIX:** remap the rust-src tree onto the **canonical** token the shipped std rlib already
carries, `/rustc/<40-hex-commit>`, which `rustc -vV` reports and which is identical on any machine
running the same pinned rustc. `RUSTC_HASH` was already being computed in `build.sh` and never used.
The guard now counts **only** the canonical form and **hard-refuses** any surviving `/rust-std`.

**TWO-SIDED CONTROL, measured on this machine by installing and removing the component:**

```
rust-src PRESENT, old script   457,760 B  84f9da6cbcd797e7   <- the hazard, reported "reproducible"
rust-src PRESENT, fixed script 458,248 B  3d8dae96c0eea6ee   <- matches the chain
rust-src ABSENT,  fixed script 458,248 B  3d8dae96c0eea6ee   <- matches the chain
```

**Why this mattered in practice:** `rustup component add rust-src` is what **rust-analyzer** needs,
so a large share of ordinary developers have it. Under the old recipe every one of them would have
got different bytes and — now that `verify.sh` correctly fails on a gap — a **REAL FAILURE on a
correct tree**. `profile = "minimal"` reduces the odds; it does not stop anyone adding the component
afterwards, which is why the recipe, not the toolchain file, has to be invariant to it.

### ONE RECIPE — three scripts was the hazard

This repo briefly held three remap recipes producing three different artifacts:

| script | bytes | sha256[:16] | status |
|---|---:|---|---|
| `contract/build.sh` | 458,248 | `3d8dae96c0eea6ee` | **the one that ships, and the one `verify.sh` runs** |
| `build-reproducible.sh` | 458,234 | `c70089857a9efaa0` | **SUPERSEDED**, now refuses to run (exit 2) |
| `verify.sh`'s own inline flags | 458,442 | `3fe8d7b68eb53696` | **removed**; it now calls `build.sh` |

A verifier with its own private recipe cannot verify the recipe that shipped. The superseded script
is kept rather than deleted so that its hash can be *traced* if it turns up in an old note.

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
| `leash-b0c503d6.testnet` | main contract | 459,050 | `FksLFKoeD6Xco1D9omAQ2hrhczMwNjVnt27T2u89kkbt` | `db40808d5b6ad22f` | **REPLACED 2026-11-11** — see *Deployed 2026-11-11* |
| `leash-locked-7f0c6d.testnet` | locked snapshot (access-key-less) | 305,580 | `4iHvhQNszRYgJsU27o37okn5nZ1n9icYJ68RjaksfLYq` | `372703139fccf4e6` |

### Reproducibility status — TWO ARTIFACTS, ONLY ONE OF THEM PORTABLE

| artifact | bytes | sha256[:16] | toolchain | embedded host paths | third-party reproducible |
|---|---:|---|---|---:|---|
| **deployed** on `leash-b0c503d6` | 459,050 | `db40808d5b6ad22f` | rustup `stable` | **15** | **NO** |
| **pinned rebuild**, plain `cargo build` | 458,442 | `3fe8d7b68eb53696` | `1.95.0` via `rust-toolchain.toml` | **19** | **NO** |
| **remapped rebuild** (`./build-reproducible.sh`) | 458,234 | `c70089857a9efaa0` | `1.95.0` via `rust-toolchain.toml` | **0** | **YES**, see the control below |

**The deployed artifact is not reproducible by anyone but its build machine.** It embeds 15 absolute
paths of the form `/home/<user>/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rust...`.
Reproducing it requires not merely the same compiler but the same rustup directory at the same
absolute path. That is the entire 608-byte difference.

**RETRACTED 2026-11-07: the plain pinned build is NOT portable.** The claim below was that it
"contains zero host paths". It contains **nineteen** — every dependency source file that appears in
a panic message, under `$CARGO_HOME/registry/src/...`. The control that produced the claim moved the
SOURCE tree and left `$CARGO_HOME` where it was, so it was blind to the one prefix that actually
leaked. Measured both ways:

```
plain build, CARGO_HOME=/home/<user>/.cargo        -> 458,442 B  3fe8d7b68eb53696   19 host paths
plain build, CARGO_HOME=<another absolute path>    -> 459,714 B  31076872899ecb49   19 host paths
remapped build, either CARGO_HOME                  -> 458,234 B  c70089857a9efaa0    0 host paths
```

The middle row is the falsifier the first claim never ran: a different `$CARGO_HOME` gives a
different artifact. The third row is the fix — `./build-reproducible.sh` passes
`--remap-path-prefix` for both `$CARGO_HOME` and the source dir, and the result is **byte-identical
from two different `$CARGO_HOME` paths** with no `/home`, `/Users` or `/root` string left in it.
`trim-paths = "all"` would be the one-line in-tree version and is **unstable on cargo 1.95.0**
(nightly only), which is why this is a script and not a profile key.

**PROVEN ON A SECOND MACHINE, 2026-11-07 — the coordinator's receipt, not my own measurement.** She pulled
`7de6acf`, ran `./build-reproducible.sh` on the build host (different hardware,
`CARGO_HOME=~/.cargo`) without reading this file first, and reported **458,234 bytes,
`c70089857a9efaa02f72be3469ebe31830a55237b1eaae1515f03a321154fece`, 0 host paths left, rc 0** —
equal to the the dev host build byte for byte. The remapped artifact therefore reproduces across two
machines, two `$CARGO_HOME` paths and two source paths. Still untested: a different OS, a different
libc, and a toolchain installed from anything but rustup.

**A DEFECT SHE FOUND IN MY OWN SCRIPT, worth more than the agreement.** `build-reproducible.sh`
ended by echoing the hash this file documents, directly under the one it had just computed. Her run
was already finished and the build is deterministic, so her result stands — but that line would
anchor the *next* independent re-derivation, and an independent re-derivation is the only instrument
that can falsify a reproducibility claim. **Removed.** The script now states only what it measured,
this file carries the claim, and `verify.sh` does the assertion and exits non-zero on drift. Three
jobs, three places.

**Original claim, left here un-deleted:** "Built from two different absolute paths under
`rust-toolchain.toml`, it is byte-identical both times and contains zero host paths." True about the
source path, false about the artifact.

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

### Recommended before the next deploy — **DONE 2026-11-11**

The recommendation was: ship the reproducible build with the WL-CL-020 fix, after which the deployed
artifact and this tree agree for everyone, and the lock can follow. **That deploy happened** —
figures in *Deployed 2026-11-11*, `./verify.sh` now reports IDENTICAL, and the lock is the remaining
step. The lock is irreversible and is Q's call, not taken here.

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
