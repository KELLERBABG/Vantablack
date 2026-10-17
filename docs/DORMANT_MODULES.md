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
`docs/SOTA.md` cites; the open gap is that they still land in the default binary
(every audit of a shipping daemon then includes a sharded-inference runtime, a
steganographic side-channel modulator and a credits ledger that cannot execute).

## What the change would be, concretely

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
   tested somewhere rather than rotting. (CI does not yet ship that gate step.)
5. Gate the two integration tests that import `dead_drop` and `dtn_reconcile`.
6. Note the feature in `README.md` where it lists the dormant primitives.

## Current status (v0.8.12)

The `research` feature gate is **landed**: the 15 unreachable modules are gated behind `#[cfg(feature = "research")]` (off by default) so the default binary only compiles live packet-path modules, while `.github/workflows/ci.yml` compiles, lints (`-D warnings`), and runs their unit and integration tests under `--features research`.
