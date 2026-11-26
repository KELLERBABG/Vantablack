# Stage 5 (`v2.6.0`) — Adoption Engine — progress log

Spec: `DEV/V3_PIPELINE.md` Stage 5 (read-only; stayed 9,132 bytes).
Rule: a box is ticked only when the code exists and a test or gate proves it.

## Read and map

- [x] Read Stage 5 spec and `DEV/ROADMAP.md` / `DEV/future_upgrades.md`
- [x] Map existing TUN/DNS, Drop/Expose/Party, BTCr relay, dashboard and packaging code

## Deliverables

- [x] 1-click DNS (`POST /api/v2/adopt/dns`, real `vbdns::spawn`; test `a_one_click_dns_stub_binds_and_answers_with_an_address`)
- [x] 1-click TUN — `POST /api/v2/adopt/tun` opens the platform device and holds it (`tun_running` in status); a second click reports `already_running`, `{"action":"stop"}` releases it, and a refusal is a `409` with `privilege_denied`, `device_missing`, `feature_missing` or `unsupported`; tests `the_tun_device_really_opens_and_is_released_instead_of_being_claimed`, `a_refused_tun_device_is_classified_by_privilege_or_driver` (real interface still needs host privilege)
- [x] 1-click Drop room code (`portal::DropSession` + `vb-drop://`; test `a_one_click_drop_returns_a_parsable_room_code`)
- [x] 1-click Expose room code (`expose::bind/serve` + `vb-expose://`; test `a_one_click_expose_returns_a_token_and_room_code`)
- [x] 1-click Party room code (both UDP ports preflighted + `vb-party://`; test `a_one_click_party_preflights_both_ports_and_returns_a_room_code`)
- [x] Opt-in AC-powered Blind Relay toggle feeding BTCr v2 — persisted toggle + settings refusal without fresh AC; boot creates the relay role only when the same measured policy says `Serving`; activation applies at restart; test `blind_relaying_is_off_until_opted_in_and_withholds_without_fresh_ac`
- [ ] Signed installer: winget — **withheld**: Authenticode gate is wired into status; no production signature/keys in the repo
- [ ] Signed installer: brew — **withheld**: bottle detached-signature gate is wired into status; no key/bottle signature produced
- [ ] Signed installer: .deb — **withheld**: `*.deb.sig` gate is wired into status; no key/signature produced
- [ ] Signed installer: APK — **withheld**: `apksigner` gate is wired into status; release signing requires `ANDROID_KEYSTORE_B64`, which is not configured here
- [x] Verifier evidence reaches adoption status — `packaging/verify_signed_release.sh --json` emits `{kind, artifact, signed, sha256}` per family; `adopt::installer_report` runs it when `GGN_SIGNED_DIST` is set, caches for 300 s, and status reports `installers` + `installer_evidence {ran, source, checked_at}`; test `the_signed_release_verifier_decides_the_installer_claim`; the script's success path was checked with stub signers (four families and real digests)
- [x] 1-line `--relay-only` Docker container (`deploy/docker-compose.relay.yml`; test `the_relay_container_really_runs_relay_only`)

## Controls and tests

- [x] Every new action has a test that fails without the code (13 `adopt` tests)
- [x] AC probe is cached for 60 s and forced only on explicit opt-in; test `the_ac_probe_is_cached_for_the_ttl_instead_of_running_per_request`
- [x] Missing/failed evidence withholds the claim instead of asserting it (AC, installers, TUN)
- [x] Negative-path tests for each gate (expired/wrong room codes, battery/stale/absent AC, missing/unsigned installer, absent TUN feature)
- [x] Full library suite: `cargo test --lib --no-fail-fast` → **701 passed, 0 failed, 1 ignored**
- [x] Clippy: `cargo clippy --all-targets -- -D warnings` → clean
- [x] Format: `cargo fmt -- --check` → clean

## Release bookkeeping

- [x] `Cargo.toml` / `Cargo.lock` root / `assets/app.rc` at 2.6.0 / 2,6,0,0; no stale 2.5.0 in config/resource files; Android `versionCode 260`, `versionName 2.6.0`
- [x] Dated `[2.6.0]` changelog with the real test evidence above
- [x] `DEV/V3_PIPELINE.md` still 9,132 bytes
- [x] HEAD still `807e37c`; nothing committed/pushed; fuzz corpus and `data/bundles.sled` untouched

## Still open

- **A real TUN interface needs host privilege.** The endpoint opens it and reports a typed refusal when the OS denies it; CI only exercises the in-memory device, so a privileged wintun/`/dev/net/tun` open was not run here. Starting the device does not attach the daemon's forwarding pump (`GHOST_VPN=client` at boot).
- **Relay activation applies on the next daemon restart.** The persisted opt-in is read at boot, rechecks fresh AC evidence, and then builds the relay role. A runtime flip cannot replace `DerpRelay` safely.
- **No installer family carries a production signature here.** The verifier now feeds status (`GGN_SIGNED_DIST=...`), so the claim becomes `verified` as soon as four real signatures verify; until then it stays `withheld`. Homebrew/deb also need detached signatures produced by the release process, and APK release signing needs `ANDROID_KEYSTORE_B64`.
- **TUN/DNS dashboard controls were not visually inspected in a browser**; compilation, JS syntax and the endpoint tests are the checks performed.
