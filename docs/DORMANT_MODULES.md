# The dormant `ghost::net` modules

`src/ghost/net/mod.rs` declares more modules than the node's data path uses.
Everything declared there is compiled into every build, linted by the `-D
warnings` clippy gate, and covered by whatever tests the module carries. The
README calls these "dormant research primitives". This file records which ones
are actually dormant, and what removing them from the default build would take.

## Measured state

Counted from `src/ghost/net/mod.rs` and from the call sites of each module
outside its own file:

| Module | Lines | Inline tests | Reachable from the daemon | Reached only by |
| --- | ---: | ---: | --- | --- |
| `dispatcher` | 144 | 0 | yes | live: `main.rs` packet intake |
| `orbit` | 402 | 8 | yes | live: `main.rs` disjoint-route constraint, `net/routing.rs` |
| `dtn_reconcile` | 203 | 1 | no | `tests/semantic_fuzzer.rs`, `tests/test_skywave_carrier.rs` |
| `dead_drop` | 212 | 3 | no | `tests/semantic_fuzzer.rs` |
| `pow` | 340 | 5 | no | its own tests |
| `rendezvous` | 307 | 3 | no | its own tests |
| `universal_tunnel` | 222 | 2 | no | its own tests |
| `sharded_compute` | 199 | 2 | no | its own tests |
| `diffusion` | 192 | 2 | no | its own tests |
| `energy_currency` | 178 | 1 | no | its own tests |
| `bandwidth_voucher` | 154 | 1 | no | its own tests |
| `sovereign_cloud` | 143 | 1 | no | its own tests |
| `collective_defense` | 133 | 1 | no | its own tests |
| `model_gossip` | 125 | 1 | no | its own tests |
| `mesh_archive` | 104 | 1 | no | its own tests |
| `entropy_beacon` | 103 | 1 | no | its own tests |
| `stego_physics` | 96 | 1 | no | its own tests |

Two corrections to the earlier count: `dispatcher` and `orbit` are on the packet
path and are not dormant. `dtn_reconcile` and `dead_drop` are compiled against by
two integration tests, so `--no-default-features` will not remove them unless
those tests are gated too.

## Decision

The 15 unreachable modules stay in the repository as source and leave the
default build. Deleting them would discard working, tested research code that
`docs/SOTA.md` cites; leaving them in the default binary means every audit of a
shipping daemon includes a sharded-inference runtime, a steganographic
side-channel modulator and a credits ledger that cannot execute.

## What the change is, concretely

1. Add a feature to `Cargo.toml`, defaulting off:

   ```toml
   research = []
   ```

2. Put the 15 declarations in `src/ghost/net/mod.rs` behind it:

   ```rust
   #[cfg(feature = "research")]
   pub mod sovereign_cloud;
   ```

3. `#![cfg(feature = "research")]` at the top of each module file, so the file's
   own tests compile only when the feature is on.
4. Add `--features research` to the CI test job, next to the existing
   `hardware-tpm,pkcs11` and `quic` gate steps, so the modules stay compiled and
   tested somewhere rather than rotting.
5. Gate the two integration tests that import `dead_drop` and `dtn_reconcile`.
6. Note the feature in `README.md` where it lists the dormant primitives.

## Why this is not done in this pass

Steps 1 to 6 span `Cargo.toml`, `src/ghost/net/mod.rs`, 15 module files, two test
files, `.github/workflows/ci.yml` and `README.md`. Those files are held by three
different writers in the current change, and the clippy gate runs over whichever
subset is enabled, so a partial landing is a red build. It is one mechanical
change with one owner, and it should be its own commit.
