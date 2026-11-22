//! Command-line interface and argument handling for Vantablack (GGN).

use rand::RngCore;
use std::path::PathBuf;
use std::time::Duration;
use vantablack::ghost::v2::regime::Regime;
use vantablack::ghost::v2::{
    btcr, continuum, expose::ExposeConfig, fleet, party::PartyConfig, racs, vbdns, xray,
};

/// Handles command line subcommands and flags.
/// Returns `Some(result)` if the CLI invocation was handled (and the process should terminate),
/// or `None` if the daemon should proceed with standard boot.
pub fn handle_cli_args() -> Option<anyhow::Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None;
    }
    // Global runtime flags. The daemon reads the resolved environment variables,
    // so flags set here survive into `run_node` and subsystem daemons unchanged.
    apply_global_flags(&args);
    match args[1].as_str() {
        "split-key" | "split_key" => {
            let secret = if args.len() >= 3 {
                let hex_str = args[2].trim();
                let bytes = match hex::decode(hex_str) {
                    Ok(b) => b,
                    Err(e) => return Some(Err(anyhow::anyhow!("Invalid hex key: {e}"))),
                };
                if bytes.len() != 32 {
                    return Some(Err(anyhow::anyhow!(
                        "Key must be exactly 32 bytes (64 hex characters), got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            } else {
                let mut arr = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut arr);
                println!("Generated fresh 32-byte secret key: {}", hex::encode(arr));
                arr
            };
            let shares = vantablack::ghost::layers::l3_shamir::split_secret_bytes(&secret);
            println!("L3 Shamir Secret Sharing (2-of-3 threshold split):");
            for (i, share) in shares.iter().enumerate() {
                println!("  Share {}: {}", i + 1, hex::encode(share));
            }
            println!("Any 2 of these 3 shares will reconstruct the original secret.");
            Some(Ok(()))
        }
        "join-key" | "join_key" => {
            if args.len() < 4 {
                println!("Usage: ggn join-key <share1_hex> <share2_hex>");
                return Some(Err(anyhow::anyhow!("Two hex shares required")));
            }
            let s1 = match hex::decode(args[2].trim()) {
                Ok(b) => b,
                Err(e) => return Some(Err(anyhow::anyhow!("Invalid hex for share 1: {e}"))),
            };
            let s2 = match hex::decode(args[3].trim()) {
                Ok(b) => b,
                Err(e) => return Some(Err(anyhow::anyhow!("Invalid hex for share 2: {e}"))),
            };
            let secret = vantablack::ghost::layers::l3_shamir::join_shares(&s1, &s2);
            println!(
                "Reconstructed secret ({} bytes): {}",
                secret.len(),
                hex::encode(&secret)
            );
            Some(Ok(()))
        }
        "skywave-status" | "sdr-status" => {
            println!("Atmospheric Broadcast OS (ABOS) Skywave Interface:");
            println!("  Carrier Band: 2–10 MHz (NVIS Skywave)");
            println!("  Propagation: 70°–90° Near-Vertical Incidence (Zero Skip Zone)");
            println!("  Modulation: DSSS below-noise + LDPC(256/512)");
            println!(
                "  Status: {}",
                if cfg!(feature = "sdr") {
                    "Enabled (compiled with --features sdr)"
                } else {
                    "Disabled (compile with --features sdr)"
                }
            );
            Some(Ok(()))
        }
        "drop" => {
            let Some(file) = args.get(2).filter(|a| !a.starts_with("--")) else {
                println!("Usage: ggn drop <file> [--port 8787] [--bind 0.0.0.0:8787] [--ttl-secs 86400] [--once]");
                return Some(Err(anyhow::anyhow!("a file is required")));
            };
            let port = flag_u64(&args, "--port", 8787) as u16;
            let bind = flag_value(&args, "--bind").unwrap_or_else(|| format!("0.0.0.0:{port}"));
            let ttl = flag_u64(&args, "--ttl-secs", 86_400);
            let max_downloads = if has_flag(&args, "--once") { 1 } else { 0 };
            let path = PathBuf::from(file);
            Some(block_on(async move {
                vantablack::ghost::v2::portal::run_cli(
                    path,
                    bind,
                    Duration::from_secs(ttl),
                    max_downloads,
                )
                .await
            }))
        }
        "expose" => {
            let target = flag_value(&args, "--target")
                .or_else(|| args.get(2).filter(|a| !a.starts_with("--")).cloned())
                .unwrap_or_else(|| "127.0.0.1:3000".to_string());
            let listen = flag_value(&args, "--listen").unwrap_or_else(|| "127.0.0.1:8787".to_string());
            let token = flag_value(&args, "--token").unwrap_or_else(random_token);
            let cfg = ExposeConfig {
                listen,
                target,
                token,
            };
            Some(block_on(vantablack::ghost::v2::expose::run_cli(cfg)))
        }
        "party" => {
            let port = flag_u64(&args, "--port", 47_077);
            let listen = flag_value(&args, "--listen").unwrap_or_else(|| format!("0.0.0.0:{port}"));
            let peer = flag_value(&args, "--peer");
            let mut cfg = PartyConfig::new(&listen, peer.as_deref());
            cfg.peer_listen = flag_value(&args, "--peer-listen");
            cfg.copies = flag_u64(&args, "--copies", 2) as usize;
            cfg.jitter_ms = flag_u64(&args, "--jitter-ms", 0);
            Some(block_on(vantablack::ghost::v2::party::run(cfg)))
        }
        "reality" => {
            let listen = flag_value(&args, "--listen").unwrap_or_else(|| "127.0.0.1:8443".into());
            let origin = flag_value(&args, "--origin").unwrap_or_else(|| "example.com:443".into());
            let token = flag_value(&args, "--token")
                .or_else(|| std::env::var("GHOST_REALITY_TOKEN").ok())
                .filter(|t| !t.is_empty());
            let Some(token) = token else {
                println!("Usage: ggn reality [--listen 127.0.0.1:8443] [--origin example.com:443] --token <LABEL>");
                return Some(Err(anyhow::anyhow!(
                    "a knock label is required (--token or GHOST_REALITY_TOKEN)"
                )));
            };
            Some(run_reality(listen, origin, token))
        }
        "masque" => {
            let listen = flag_value(&args, "--listen").unwrap_or_else(|| "127.0.0.1:8443".into());
            let connect = flag_value(&args, "--connect").unwrap_or_else(|| listen.clone());
            let token = flag_value(&args, "--token")
                .or_else(|| std::env::var("GHOST_MASQUE_TOKEN").ok())
                .filter(|t| !t.is_empty());
            let Some(token) = token else {
                println!("Usage: ggn masque [--listen 127.0.0.1:8443] --token LABEL [--sni msq.example] [--client] [--connect ADDR]");
                return Some(Err(anyhow::anyhow!("a token label is required")));
            };
            let sni = flag_value(&args, "--sni").unwrap_or_else(|| "msq.example".into());
            Some(run_masque(
                listen,
                connect,
                token,
                sni,
                flag_value(&args, "--cert-out"),
                has_flag(&args, "--client"),
            ))
        }
        "hpeb" => {
            let listen = flag_value(&args, "--listen").unwrap_or_else(|| "127.0.0.1:47900".into());
            let paths = flag_value(&args, "--paths")
                .unwrap_or_else(|| "127.0.0.2,127.0.0.3".into())
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if has_flag(&args, "--client") {
                let Some(file) = flag_value(&args, "--file") else {
                    return Some(Err(anyhow::anyhow!("--client needs --file")));
                };
                let connect = flag_value(&args, "--connect").unwrap_or(listen);
                Some(
                    vantablack::ghost::v2::hpeb::run_multipath_client(
                        &connect,
                        &paths,
                        &PathBuf::from(file),
                        has_flag(&args, "--single-source"),
                    )
                    .map_err(anyhow::Error::msg),
                )
            } else {
                let out = flag_value(&args, "--out").unwrap_or_else(|| ".hpeb-recovered.bin".into());
                Some(
                    vantablack::ghost::v2::hpeb::run_multipath_server(
                        &listen,
                        &PathBuf::from(out),
                    )
                    .map_err(anyhow::Error::msg),
                )
            }
        }
        "fleet" => Some(run_fleet(&args)),
        "btcr" => Some(run_btcr(&args)),
        "ladder" | "continuum" => Some(block_on(run_ladder(&args))),
        "racs" => Some(run_racs(&args)),
        "mode" | "regime" => Some(run_mode(&args)),
        "vb-dns" | "vbdns" => Some(run_vb_dns(&args)),
        "xray" => Some(block_on(run_xray(&args))),
        "--version" | "-v" | "version" => {
            println!("vantablack {}", env!("CARGO_PKG_VERSION"));
            println!("https://github.com/KELLERBABG/Vantablack");
            Some(Ok(()))
        }
        "--help" | "-h" | "help" => {
            println!("Vantablack (GGN) — Post-Quantum WAN Mesh Daemon");
            println!("Usage:");
            println!("  ggn                             Run node daemon");
            println!("  ggn split-key [32B_HEX_KEY]     Split secret into 3 Shamir shares (2-of-3 threshold)");
            println!(
                "  ggn join-key <SHARE1> <SHARE2>  Reconstruct secret from any 2 Shamir shares"
            );
            println!(
                "  ggn sdr-status                  Show atmospheric skywave (ABOS) carrier status"
            );
            println!("  --skywave                       Activate the ABOS skywave fallback carrier (GHOST_SKYWAVE=1)");
            println!("  --quantum                       Activate the QEL quantum anchor (GHOST_QUANTUM=1)");
            println!("  --relay-only                    Run as a headless blind relay (GHOST_RELAY=1, GHOST_EXIT=0, GHOST_NO_GUI=1, GHOST_VPN=off)");
            println!();
            println!("v2 commands:");
            println!("  ggn drop <file>                 Share a file with a browser link (key stays in the URL fragment)");
            println!("  ggn expose <host:port>          Token-gated relay to one local server, no port forwarding");
            println!("  ggn party [--peer ADDR] [--peer-listen ADDR]  UDP bridge for LAN games (dedupe + jitter buffer)");
            println!("  ggn mode [fast|shielded|ghost|vantablack]  Show or set the operating regime");
            println!("  ggn vb-dns [--map name=NODEID]  Serve <name>.vb on a loopback DNS stub");
            println!("  ggn xray [--json]               What your ISP, the guard and the website can see");
            println!("  ggn fleet [--init|--issue PK|--revoke PK|--admit URI]  Fleet subkeys, vb-fleet:// QR onboarding, revocation");
            println!("  ggn reality --token LABEL       TLS 1.3 front: authenticated SNI tunnels, all other probes spliced to a borrowed origin");
            println!("  ggn masque --token LABEL        QUIC/h3 endpoint: CONNECT-UDP capsules + bidirectional datagrams (--client for the probe)");
            println!("  ggn btcr [--demo|--wallet]     Blind-signed relay credits (Ristretto255 VOPRF + DLEQ)");
            println!("  ggn ladder [--demo|--json]      Six-rung Continuum ladder, GhostCell-Nano, mule DTN");
            println!("  ggn racs [--bench]              Cover-traffic shaping and measured preemption latency");
            println!("  ggn hpeb [--listen ADDR] [--paths A,B]  AONT+RS multipath: one bound UDP socket per path (--client --file F)");
            println!("  ggn --version                   Show version information");
            println!("  ggn --help                      Show this help");
            println!();
            println!("Source & releases: https://github.com/KELLERBABG/Vantablack");
            Some(Ok(()))
        }

        _ => None,
    }
}

#[cfg(feature = "reality-front")]
fn run_reality(listen: String, origin: String, token: String) -> anyhow::Result<()> {
    block_on(vantablack::ghost::v2::front::run_cli(
        listen, origin, token,
    ))
}

#[cfg(not(feature = "reality-front"))]
fn run_reality(_listen: String, _origin: String, _token: String) -> anyhow::Result<()> {
    println!(
        "REALITY TLS front is not compiled in this build. Rebuild with --features reality-front."
    );
    Ok(())
}

#[cfg(feature = "quic")]
fn run_masque(
    listen: String,
    connect: String,
    token: String,
    sni: String,
    cert_out: Option<String>,
    client: bool,
) -> anyhow::Result<()> {
    let listen: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --listen address: {e}"))?;
    let connect: std::net::SocketAddr = connect
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --connect address: {e}"))?;
    block_on(async move {
        if client {
            vantablack::ghost::v2::masque::run_client(connect, token, sni).await
        } else {
            vantablack::ghost::v2::masque::run_server(listen, token, sni, cert_out).await
        }
    })
}

#[cfg(not(feature = "quic"))]
fn run_masque(
    listen: String,
    connect: String,
    token: String,
    sni: String,
    cert_out: Option<String>,
    client: bool,
) -> anyhow::Result<()> {
    let _ = (listen, connect, token, sni, cert_out, client);
    println!("MASQUE QUIC is not compiled in this build. Rebuild with --features quic.");
    Ok(())
}

fn apply_global_flags(args: &[String]) {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--quantum" => {
                std::env::set_var("GHOST_QUANTUM", "1");
            }
            "--skywave" => {
                std::env::set_var("GHOST_SKYWAVE", "1");
            }
            "--relay-only" => {
                std::env::set_var("GHOST_RELAY", "1");
                std::env::set_var("GHOST_EXIT", "0");
                std::env::set_var("GHOST_NO_GUI", "1");
                std::env::set_var("GHOST_VPN", "off");
            }
            "--zero-admin" | "--userspace" => {
                std::env::set_var("GHOST_ZERO_ADMIN", "1");
                std::env::set_var("GHOST_SOCKS5", "1");
                vantablack::ghost::net::set_zero_admin(true);
            }
            "--low-latency" | "--turbo" => {
                std::env::set_var("GHOST_LOW_LATENCY", "1");
                vantablack::ghost::net::set_low_latency(true);
            }
            "--mix-batch-ms" if i + 1 < args.len() => {
                std::env::set_var("GHOST_MIX_BATCH_MS", &args[i + 1]);
                if let Ok(ms) = args[i + 1].parse::<u64>() {
                    vantablack::ghost::net::set_mix_batch_delay_ms(ms);
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn flag_u64(args: &[String], name: &str, default: u64) -> u64 {
    flag_value(args, name)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn block_on<F>(future: F) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(future)
}

/// `ggn btcr` — inspect credits, or demonstrate blind issuance end to end.
fn run_btcr(args: &[String]) -> anyhow::Result<()> {
    use btcr::{blind, issue_for_work, sign_receipt, spend, Issuer, Receipt, Wallet};
    use ed25519_dalek::SigningKey;

    if has_flag(args, "--wallet") {
        let path = btcr::wallet_path();
        let wallet = Wallet::load(&path);
        println!("Wallet: {}", path.display());
        println!("  tickets {}", wallet.tickets.len());
        println!("  credit  {} bytes", wallet.total_credit());
        for ticket in &wallet.tickets {
            println!(
                "  · {} work={} expires={}",
                &ticket.m[..16.min(ticket.m.len())],
                ticket.work_bytes,
                ticket.expires_at
            );
        }
        return Ok(());
    }

    if !has_flag(args, "--demo") {
        println!("{}", serde_json::to_string_pretty(&btcr::status_json("cli"))?);
        return Ok(());
    }

    let issuer = Issuer::for_node("ggn-btcr-demo");
    let beneficiary = SigningKey::from_bytes(&[11u8; 32]);
    let now = vantablack::ghost::v2::now_secs();
    let to_any = |e: String| anyhow::anyhow!(e);
    let receipt = sign_receipt(&beneficiary, "demo-home-pc", 4_000_000, now / 3600)
        .map_err(to_any)?;

    // A tampered receipt must be refused before anything is minted.
    let mut forged: Receipt = receipt.clone();
    forged.work_bytes = 400_000_000;
    let refused = btcr::verify_receipt(&forged, &beneficiary.verifying_key()).is_err();

    let request = blind(b"phone-demo-session");
    let (ticket, proof) = issue_for_work(
        &issuer,
        &receipt,
        &beneficiary.verifying_key(),
        &request,
        now,
    )
    .map_err(to_any)?;
    let encoded = ticket.encode().map_err(to_any)?;
    let decoded = btcr::Ticket::decode(&encoded).map_err(to_any)?;
    let verified = issuer.verify_ticket(&decoded);
    let first_spend = spend(&issuer, &decoded, now);
    let replay = spend(&issuer, &decoded, now);

    let mut wallet = Wallet::load(&btcr::wallet_path());
    wallet.tickets.push(decoded.clone());
    wallet.save(&btcr::wallet_path()).map_err(to_any)?;

    println!("BTCr / Blind-Pass demo (Ristretto255 VOPRF + Chaum–Pedersen DLEQ)");
    println!("  issuer key        {}", issuer.public_hex());
    println!("  beneficiary       {}", hex::encode(beneficiary.verifying_key().to_bytes()));
    println!("  receipt           {} bytes of relay work, epoch {}", receipt.work_bytes, receipt.epoch);
    println!("  tampered receipt  {}", if refused { "refused" } else { "ACCEPTED — bug" });
    println!("  blind request     {}", &request.blinded[..32]);
    let (eval_hex, _) = issuer.evaluate(&request.blinded).map_err(to_any)?;
    let dleq_ok = btcr::decode_point(&request.blinded)
        .ok()
        .zip(btcr::decode_point(&eval_hex).ok())
        .map(|(b, e)| proof.verify(&issuer.public(), &b, &e))
        .unwrap_or(false);
    println!("  DLEQ verified     {dleq_ok}");
    println!("  ticket            {}", &encoded[..32]);
    println!(
        "  ticket length     {} bytes, verifies {}",
        decoded.encode().map(|v| v.len() / 2).unwrap_or(0),
        verified
    );
    println!("  first spend       {:?}", first_spend.map(|_| "ok"));
    println!("  replay            {}", replay.err().unwrap_or_else(|| "ACCEPTED — bug".into()));
    println!("  wallet            {}", btcr::wallet_path().display());
    println!("  wallet credit     {} bytes", wallet.total_credit());
    println!("  note              signature is bound to the receipt message; issuance without it is refused");
    Ok(())
}

/// `ggn ladder` — rung availability, or a real UDP + mule-store demo.
async fn run_ladder(args: &[String]) -> anyhow::Result<()> {
    if has_flag(args, "--demo") {
        let report = continuum::loopback_demo()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if has_flag(args, "--json") {
        println!("{}", serde_json::to_string_pretty(&continuum::status_json())?);
        return Ok(());
    }
    println!("Continuum ladder — {}-byte GhostCell-Nano", continuum::CELL_LEN);
    for rung in continuum::ladder() {
        println!(
            "  [{}] {:14} mtu={}  {}",
            if rung.available { "up" } else { "--" },
            rung.rung,
            rung.mtu,
            rung.reason
        );
    }
    let store = continuum::MuleStore::new(continuum::MuleStore::default_path());
    println!();
    println!("Mule store: {}", store.dir().display());
    println!("  bundles     {}", store.list().len());
    println!("  merkle root {}", store.merkle_root());
    println!();
    println!("`ggn ladder --demo` sends three real cells over loopback UDP and unions two mule stores.");
    Ok(())
}

/// `ggn racs` — live shaper state, or a real preemption measurement.
fn run_racs(args: &[String]) -> anyhow::Result<()> {
    if has_flag(args, "--bench") {
        let stats = racs::bench(10_000);
        println!("{}", serde_json::to_string_pretty(&stats)?);
        if !stats.under_100us {
            return Err(anyhow::anyhow!(
                "preemption p99 is {} µs, above the 100 µs budget",
                stats.p99_us
            ));
        }
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&racs::status_json())?);
    Ok(())
}

/// `ggn mode` — read or set the persisted regime.
/// `ggn fleet` — offline-root issuance, `vb-fleet://` onboarding and revocation.
fn run_fleet(args: &[String]) -> anyhow::Result<()> {
    use fleet::{RevocationSet, RevokeReason};

    let seed = flag_value(args, "--seed");
    let root_from_seed = |seed: &str| -> anyhow::Result<fleet::FleetRoot> {
        let raw = hex::decode(seed.trim()).map_err(|e| anyhow::anyhow!("seed is not hex: {e}"))?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
        Ok(fleet::FleetRoot::from_seed(seed))
    };
    let parse_pk = |raw: &str| -> anyhow::Result<[u8; 32]> {
        let bytes = hex::decode(raw.trim())
            .map_err(|e| anyhow::anyhow!("device key is not hex: {e}"))?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("device key must be 32 bytes"))
    };

    if args.iter().any(|a| a == "--init") {
        let (root, seed) = fleet::FleetRoot::generate();
        println!("Fleet root created.");
        println!("  fleet id   {}", root.fleet_id());
        println!("  public key {}", root.public_key_hex());
        println!("  seed       {}", hex::encode(seed));
        println!();
        println!("Keep the seed offline; anyone holding it can mint devices for this fleet.");
        return Ok(());
    }

    if let Some(pk_hex) = flag_value(args, "--issue") {
        let seed = seed.ok_or_else(|| anyhow::anyhow!("--issue needs --seed <32-byte hex>"))?;
        let root = root_from_seed(&seed)?;
        let pk = parse_pk(&pk_hex)?;
        let label = flag_value(args, "--label").unwrap_or_else(|| "device".to_string());
        let cert = root.issue(
            pk,
            &label,
            vantablack::ghost::v2::now_secs(),
            fleet::DEFAULT_CERT_TTL_SECS,
        );
        let uri = fleet::encode_invite(&root.public_key(), &cert)
            .ok_or_else(|| anyhow::anyhow!("cannot encode fleet invite"))?;
        println!("Device certificate issued.");
        println!("  device   {}", cert.device_pk);
        println!("  id       {}", hex::encode(cert.device_id().unwrap_or([0u8; 8])));
        println!("  expires  {}", cert.expires_at);
        println!("  onboard  {uri}");
        println!();
        println!("The onboard URI is the QR payload; it carries the root public key and the signed cert.");
        return Ok(());
    }

    if let Some(pk_hex) = flag_value(args, "--revoke") {
        let seed = seed.ok_or_else(|| anyhow::anyhow!("--revoke needs --seed <32-byte hex>"))?;
        let root = root_from_seed(&seed)?;
        let pk = parse_pk(&pk_hex)?;
        let reason = match flag_value(args, "--reason").as_deref() {
            Some("stolen") => RevokeReason::Stolen,
            Some("lost") => RevokeReason::Lost,
            Some("decommissioned") => RevokeReason::Decommissioned,
            Some("compromised") => RevokeReason::Compromised,
            _ => RevokeReason::Other,
        };
        let rev = root.revoke(&pk, reason, vantablack::ghost::v2::now_secs());
        let wire = rev
            .encode()
            .ok_or_else(|| anyhow::anyhow!("cannot encode revocation"))?;
        println!("Device revoked.");
        println!("  device id {}", rev.device_id);
        println!("  wire      {} bytes  {}", wire.len(), hex::encode(&wire));
        println!("  signature {}", if rev.verify(&root.public_key()) { "valid" } else { "INVALID" });
        return Ok(());
    }

    if let Some(uri) = flag_value(args, "--admit") {
        let (root_pk, cert) = fleet::decode_invite(&uri).map_err(anyhow::Error::msg)?;
        let mut revoked = RevocationSet::new();
        if let Some(wire_hex) = flag_value(args, "--revoked") {
            let wire = hex::decode(wire_hex.trim())
                .map_err(|e| anyhow::anyhow!("revocation is not hex: {e}"))?;
            let rev = fleet::Revocation::decode(&wire)
                .ok_or_else(|| anyhow::anyhow!("revocation wire form is invalid"))?;
            if !revoked.merge(&rev, &root_pk) {
                return Err(anyhow::anyhow!("revocation signature is invalid"));
            }
        }
        let pk = fleet::admit(
            &cert,
            &root_pk,
            &revoked,
            vantablack::ghost::v2::now_secs(),
        )
        .map_err(|e| anyhow::anyhow!("device refused: {e}"))?;
        println!("Device admitted.");
        println!("  fleet  {}", cert.fleet_id);
        println!("  device {}", cert.label);
        println!("  id     {}", hex::encode(fleet::device_id_for(&pk)));
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "usage: ggn fleet --init | --issue <PK> --seed <HEX> [--label NAME] | --revoke <PK> --seed <HEX> [--reason lost|stolen] | --admit <vb-fleet://URI> [--revoked <WIRE>]"
    ))
}

fn run_mode(args: &[String]) -> anyhow::Result<()> {
    let path = vantablack::ghost::v2::regime::config_path();
    if let Some(raw) = args.get(2).filter(|a| !a.starts_with("--")) {
        let Some(regime) = Regime::parse(raw) else {
            return Err(anyhow::anyhow!(
                "{raw:?} is not one of fast, shielded, ghost, vantablack"
            ));
        };
        vantablack::ghost::v2::regime::save_persisted(&path, regime)
            .map_err(|e| anyhow::anyhow!("cannot save {}: {e}", path.display()))?;
        std::env::set_var(vantablack::ghost::v2::regime::REGIME_ENV, regime.as_str());
        println!("Regime set to {} — {}", regime.as_str(), regime.describe());
        println!("  plane          {}", regime.plane().as_str());
        println!("  hops           {}", regime.hops().hops());
        println!("  SOCKS5         :{}", 1080 + regime.socks_offset());
        println!("  cover traffic  {}", regime.cover_traffic());
        println!("  saved to       {}", path.display());
        println!();
        println!("Restart the node to rebind the SOCKS5 hop listeners.");
        return Ok(());
    }
    let active = vantablack::ghost::v2::regime::active().map_err(|e| anyhow::anyhow!(e))?;
    println!("Active regime: {} ({})", active.as_str(), active.plane().as_str());
    println!("{}", active.describe());
    println!();
    for regime in Regime::ALL {
        let marker = if regime == active { "*" } else { " " };
        println!(
            "{marker} {:10} :{}  {} hop(s)  cover={}  diversity={}",
            regime.as_str(),
            1080 + regime.socks_offset(),
            regime.hops().hops(),
            regime.cover_traffic(),
            regime.requires_asn_diversity()
        );
    }
    println!();
    println!("Anonymity is only ever claimed by `vantablack`, and only above {} public relays.", vantablack::ghost::v2::regime::MIN_ANONYMITY_RELAYS);
    Ok(())
}

/// `ggn vb-dns` — run the `.vb` stub, or answer one name and exit.
fn run_vb_dns(args: &[String]) -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use vantablack::ghost::v2::vbdns::NameRegistry;

    let registry = Arc::new(NameRegistry::new());
    // `--map name=<28 hex chars>` binds a name to the first 14 bytes of a node id.
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--map" {
            if let Some(spec) = args.get(i + 1) {
                let Some((name, id)) = spec.split_once('=') else {
                    return Err(anyhow::anyhow!("--map expects name=<28 hex chars>"));
                };
                // Accept both `laptop` and `laptop.vb`; a bare label is the
                // common case at a shell and requiring the suffix is friction.
                let parsed = vbdns::VbName::parse(name)
                    .or_else(|| vbdns::VbName::parse(&format!("{name}.vb")))
                    .ok_or_else(|| anyhow::anyhow!("{name:?} is not a valid <name>.vb"))?;
                let bytes = hex::decode(id.trim()).map_err(|e| anyhow::anyhow!("bad node id: {e}"))?;
                if bytes.is_empty() || bytes.len() > 16 {
                    return Err(anyhow::anyhow!("node id must be 1..=16 bytes of hex"));
                }
                let mut node = [0u8; 16];
                node[..bytes.len()].copy_from_slice(&bytes);
                registry.bind(parsed, node);
            }
            i += 2;
            continue;
        }
        i += 1;
    }

    if let Some(name) = flag_value(args, "--check") {
        let Some(parsed) = vbdns::VbName::parse(&name)
            .or_else(|| vbdns::VbName::parse(&format!("{name}.vb")))
        else {
            return Err(anyhow::anyhow!("{name:?} is not a valid <name>.vb"));
        };
        match registry.resolve(&parsed) {
            Some(addr) => println!("{name} -> {addr}"),
            None => println!("{name} -> NXDOMAIN (no binding; bind one with --map)"),
        }
        return Ok(());
    }

    let bind_raw = flag_value(args, "--bind").unwrap_or_else(|| vbdns::VB_DNS_BIND.to_string());
    let bind: SocketAddr = bind_raw
        .parse()
        .map_err(|e| anyhow::anyhow!("{bind_raw:?} is not an address: {e}"))?;
    let names = registry.list();
    block_on(async move {
        let (addr, task) = vbdns::spawn(Arc::clone(&registry), bind)
            .await
            .map_err(|e| anyhow::anyhow!("cannot bind {bind}: {e}"))?;
        println!(".vb DNS stub listening on {addr}");
        for (name, target) in names {
            println!("  {name} -> {target}");
        }
        println!("Set the OS resolver for `.vb` (or the whole resolver) to {addr}.");
        println!("Port 53 usually needs administrator rights; use --bind 127.0.0.53:5353 for a test.");
        tokio::signal::ctrl_c().await.ok();
        task.abort();
        println!(".vb DNS stub stopped.");
        Ok(())
    })
}

/// `ggn xray` — read the control center's status and print the truth ledger.
async fn run_xray(args: &[String]) -> anyhow::Result<()> {
    use vantablack::ghost::v2::xray::LedgerInput;

    let port = std::env::var("GHOST_WEB_PORT")
        .or_else(|_| std::env::var("GHOST_METRICS_PORT"))
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(2270);
    let url = format!("http://127.0.0.1:{port}/api/status");

    let status: serde_json::Value = match reqwest::get(&url).await {
        Ok(resp) => resp.json().await.unwrap_or(serde_json::Value::Null),
        Err(_) => serde_json::Value::Null,
    };
    let peers = status
        .get("peers_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let regime = vantablack::ghost::v2::regime::active().map_err(|e| anyhow::anyhow!(e))?;
    let input = LedgerInput {
        regime: Some(regime),
        public_relays: Some(peers),
        circuit_hops: (peers > 0).then(|| regime.hops().hops()),
        transport: (peers > 0).then(|| "udp".to_string()),
        cover_traffic: regime.cover_traffic() && peers > 0,
        pq_hybrid: (peers > 0).then_some(true),
        ..Default::default()
    };
    let ledger = xray::build(&input);

    if has_flag(args, "--json") {
        println!("{}", serde_json::to_string_pretty(&ledger)?);
        return Ok(());
    }

    println!("What can they see?");
    println!("  {}", ledger.headline);
    for obs in &ledger.observations {
        println!();
        println!("  {} sees:", obs.observer);
        for s in &obs.sees {
            println!("    - {s}");
        }
        println!("  {} does not see:", obs.observer);
        for s in &obs.does_not_see {
            println!("    - {s}");
        }
    }
    println!();
    println!("Invariants:");
    for inv in &ledger.invariants {
        println!(
            "  [{:8}] {:24} {}",
            inv.state.as_str(),
            inv.id,
            inv.detail
        );
    }
    if status.is_null() {
        println!();
        println!("Note: the control center on port {port} did not answer, so the relay count is 0.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_only_flag_sets_headless_blind_relay_env() {
        let args = vec!["ggn".to_string(), "--relay-only".to_string()];
        apply_global_flags(&args);
        assert_eq!(std::env::var("GHOST_RELAY").as_deref(), Ok("1"));
        assert_eq!(std::env::var("GHOST_EXIT").as_deref(), Ok("0"));
        assert_eq!(std::env::var("GHOST_NO_GUI").as_deref(), Ok("1"));
        assert_eq!(std::env::var("GHOST_VPN").as_deref(), Ok("off"));
    }
}
