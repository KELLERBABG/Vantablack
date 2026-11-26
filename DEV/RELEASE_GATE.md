# `v3.0.0` Release Gate — measured status

Stage 7 of [`DEV/V3_PIPELINE.md`](V3_PIPELINE.md) is the release stage. Its gate
has five items. Each one is listed with what was actually run on this host, not
with what the pipeline wishes it were.

Measured on `x86_64-pc-windows-msvc`, 2026-11-25, tree at `HEAD 807e37c` plus the
uncommitted Stage 7 work.

| Gate item | State | Evidence |
|---|---|---|
| Full E2E multi-NAT & multi-hop suite | **pass** | `cargo test --features research --no-fail-fast`: every integration target green, including `multi_nat_e2e`, `wan_full_e2e`, `wan_resilience_e2e`, `p1_nat`, `p1_relay`, `p1_quic` |
| Non-vacuous ProVerif pass | **pass** | `scripts/formal_verify.sh` run in WSL Ubuntu with ProVerif 2.05: all five models reproduce the committed attestation's RESULT lines exactly (18 results, including every `false` reachability witness), and each model's SHA-256 still matches `formal/attestations.json`. `build.rs` refuses a changed model without re-attestation; `xray::tests::formal_attestation_matches_the_committed_models` asserts the same in-tree |
| Reproducible build hashes | **pass** | `scripts/reproducible_hash.sh`; see below |
| Signed packages | **withheld** | `packaging/verify_signed_release.sh` is the gate, but this host holds no Authenticode / Homebrew / `.deb` / APK signing keys. Nothing is claimed signed |
| `X-Ray` live truth ledger | **pass (code path)** | `cargo test --lib --features research xray` green, including the census lower bound, witness freshness decay and the formal provenance check. Census tickets are now ingested from PEX in a running daemon, but no multi-host mesh was attached in this session |

## Reproducible builds

`scripts/reproducible_hash.sh` performs two measurements:

1. **Source manifest.** Every tracked file, sorted by path, with its SHA-256,
   written to `target/source-manifest.txt` and hashed again.
   Last run: `87715a4c1d6990674ac856fc39595f8051aab74e4577aa59e86a0cca0c57e5dd`
   over 530 files.
2. **Two binary builds.** `cargo build --locked --release --no-default-features
   --bin ggn` in two *fresh* target directories with `CARGO_INCREMENTAL=0`.
   Result: **byte-identical**, both
   `5f5cc0a1871b0f3bacf071c0e946f4a212bbef4c5d51a2c680436bc835ba32da`.

The measurement found a real defect before it passed. Without a linker flag the
two builds differed in exactly 24 bytes, at the COFF header and debug directory,
and the differing values were link timestamps about as far apart as the two
builds. `/Brepro` (passed as `-C link-arg=/Brepro`) removed them, and the script
now applies it automatically on a `windows-msvc` host. A different linker on
another OS is not claimed reproducible by this script; rerun it there before
making that claim.

## What this document does not claim

- It does not claim the release is signed.
- It does not claim ProVerif was run on Windows; the check ran in WSL Ubuntu against the same bytes.
- It does not claim any of the four Stage 7 primitives were exercised on a real
  multi-host mesh; their tests run in-process against pinned clocks and peers.
- It does not claim the `X-Ray` ledger was observed live; only that its
  non-fabrication rules and attestation hold under test.
