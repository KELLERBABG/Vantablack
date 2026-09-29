//! # Atmospheric Broadcast OS (ABOS) — Command-Line Interface
//!
//! The `abos` binary: 8 core subcommands plus mesh/forwarding status.
//! Argument parsing, validation and exit codes come from clap.

use abos::ABOSSystem;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "abos",
    version,
    about = "Atmospheric Broadcast OS — covert, resilient NVIS mesh radio",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the ABOS system and hold it until Ctrl+C
    Start,
    /// Stop a running ABOS system
    Stop,
    /// Transmit a file through the full RF chain
    Transmit {
        /// File to transmit
        file: PathBuf,
    },
    /// Listen for bursts and save the first decoded payload
    Receive {
        /// Number of receive attempts before giving up
        #[arg(short, long, default_value_t = 10)]
        attempts: u32,
    },
    /// Scan the spectrum and report white space / interferers
    Scan,
    /// Show loaded configuration and node identity
    Status,
    /// Print current configuration values
    Configure,
    /// Generate a chirp-sounder waveform
    Chirp {
        /// Start frequency in MHz
        #[arg(default_value_t = 3.0)]
        start_mhz: f64,
        /// Stop frequency in MHz
        #[arg(default_value_t = 10.0)]
        stop_mhz: f64,
        /// Duration in seconds
        #[arg(default_value_t = 0.1)]
        duration_s: f64,
    },
    /// Show mesh coordination state (peers, pending ACKs, availability)
    Mesh,
    /// Show the retransmit/forwarding queue and stored bundles
    Forward,
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Entry point used by the `abos` binary. Returns the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start => cmd_start(),
        Commands::Stop => cmd_stop(),
        Commands::Transmit { file } => cmd_transmit(&file),
        Commands::Receive { attempts } => cmd_receive(attempts),
        Commands::Scan => cmd_scan(),
        Commands::Status => cmd_status(),
        Commands::Configure => cmd_configure(),
        Commands::Chirp {
            start_mhz,
            stop_mhz,
            duration_s,
        } => cmd_chirp(start_mhz, stop_mhz, duration_s),
        Commands::Mesh => cmd_mesh(),
        Commands::Forward => cmd_forward(),
    }
}

fn cmd_start() -> i32 {
    println!("[ABOS] Starting system...");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(mut system) => {
                if let Err(e) = system.start().await {
                    eprintln!("[ABOS] Failed to start: {}", e);
                    return 1;
                }
                println!("[ABOS] System started.");
                println!("[ABOS] Node ID: {}", hex32(&system.node_id()));
                println!(
                    "[ABOS] Center Frequency: {} Hz",
                    system.config().center_frequency
                );
                println!("[ABOS] Sample Rate: {} sps", system.config().sample_rate);
                println!("[ABOS] Bandwidth: {} Hz", system.config().bandwidth);
                println!("[ABOS] Default MCS: {:?}", system.config().default_mcs);
                println!("[ABOS] Press Ctrl+C to stop.");
                tokio::signal::ctrl_c().await.ok();
                let _ = system.stop().await;
                println!("[ABOS] System stopped.");
                0
            }
            Err(e) => {
                eprintln!("[ABOS] Failed to initialize: {}", e);
                1
            }
        }
    })
}

fn cmd_stop() -> i32 {
    println!("[ABOS] Stopping system...");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(mut system) => {
                let _ = system.stop().await;
                println!("[ABOS] System stopped.");
                0
            }
            Err(e) => {
                eprintln!("[ABOS] System not running: {}", e);
                1
            }
        }
    })
}

fn cmd_transmit(path: &PathBuf) -> i32 {
    println!("[ABOS] Loading file: {}", path.display());
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ABOS] Failed to read file: {}", e);
            return 1;
        }
    };
    println!("[ABOS] File size: {} bytes", data.len());

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(mut system) => {
                system.init_dsss(64);
                if let Err(e) = system.start().await {
                    eprintln!("[ABOS] Failed to start: {}", e);
                    return 1;
                }
                println!("[ABOS] Transmitting...");
                let result = system.transmit(&data).await;
                let _ = system.stop().await;
                match result {
                    Ok(_) => {
                        println!(
                            "[ABOS] Transmission complete! ({} shards sent)",
                            data.len() / 1024 + 1
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!("[ABOS] Transmission failed: {}", e);
                        1
                    }
                }
            }
            Err(e) => {
                eprintln!("[ABOS] System init failed: {}", e);
                1
            }
        }
    })
}

fn cmd_receive(attempts: u32) -> i32 {
    println!("[ABOS] Listening for signals...");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(mut system) => {
                system.init_dsss(64);
                if let Err(e) = system.start().await {
                    eprintln!("[ABOS] Failed to start: {}", e);
                    return 1;
                }
                println!("[ABOS] Waiting for bursts ({} attempts)...", attempts);
                let mut buffer = vec![num_complex::Complex64::new(0.0, 0.0); 4096];
                let mut exit = 1;
                for _ in 0..attempts {
                    match system.receive(&mut buffer).await {
                        Ok(data) => {
                            println!("[ABOS] Received {} bytes", data.len());
                            let path = format!("received_{}.bin", now_secs());
                            match std::fs::write(&path, &data) {
                                Ok(_) => println!("[ABOS] Saved to {}", path),
                                Err(e) => eprintln!("[ABOS] Save failed: {}", e),
                            }
                            exit = 0;
                            break;
                        }
                        Err(abos_common::error::Error::SyncLost) => {}
                        Err(e) => eprintln!("[ABOS] Error: {}", e),
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
                let _ = system.stop().await;
                exit
            }
            Err(e) => {
                eprintln!("[ABOS] System init failed: {}", e);
                1
            }
        }
    })
}

fn cmd_scan() -> i32 {
    println!("[ABOS] Scanning spectrum...");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(mut system) => {
                if let Err(e) = system.start().await {
                    eprintln!("[ABOS] Failed to start: {}", e);
                    return 1;
                }
                let mut buffer = vec![num_complex::Complex64::new(0.0, 0.0); 2048];
                let _ = system.receive(&mut buffer).await;

                let spectrum = system.scan_spectrum(&buffer);
                let noise_floor = spectrum.iter().sum::<f64>() / spectrum.len() as f64;
                let whitespace = system.find_whitespace(&spectrum, noise_floor * 1.5);

                println!("[ABOS] Spectrum scan complete ({} bins)", spectrum.len());
                println!("[ABOS] Noise floor: {:.2}", noise_floor);
                println!("[ABOS] White space regions: {}", whitespace.len());
                for (i, (start, end)) in whitespace.iter().enumerate().take(10) {
                    println!("[ABOS]   Region {}: bins {}-{}", i, start, end);
                }

                let jammers = system.detect_interferers(&spectrum, noise_floor * 5.0);
                if !jammers.is_empty() {
                    println!(
                        "[ABOS] Potential interferers at bins: {:?}",
                        &jammers[..jammers.len().min(10)]
                    );
                }

                let _ = system.stop().await;
                0
            }
            Err(e) => {
                eprintln!("[ABOS] System init failed: {}", e);
                1
            }
        }
    })
}

fn cmd_status() -> i32 {
    println!("[ABOS] System Status");
    println!("===================");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(system) => {
                println!("Node ID:              {}", hex32(&system.node_id()));
                println!("Running:              {}", system.is_running());
                println!(
                    "Center Frequency:     {} Hz",
                    system.config().center_frequency
                );
                println!("Sample Rate:          {} sps", system.config().sample_rate);
                println!("TX Gain:              {} dB", system.config().tx_gain);
                println!("RX Gain:              {} dB", system.config().rx_gain);
                println!("Bandwidth:            {} Hz", system.config().bandwidth);
                println!("Default MCS:          {:?}", system.config().default_mcs);
                println!(
                    "Data Directory:       {}",
                    system.config().data_dir.display()
                );
                println!("Log Level:            {}", system.config().log_level);
                println!("Bundles stored:       {}", system.stored_bundle_count());
                0
            }
            Err(e) => {
                eprintln!("[ABOS] Status check failed: {}", e);
                1
            }
        }
    })
}

fn cmd_configure() -> i32 {
    println!("[ABOS] Current Configuration:");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(system) => {
                let config = system.config();
                println!("  center_frequency: {} Hz", config.center_frequency);
                println!("  sample_rate: {} sps", config.sample_rate);
                println!("  tx_gain: {} dB", config.tx_gain);
                println!("  rx_gain: {} dB", config.rx_gain);
                println!("  bandwidth: {} Hz", config.bandwidth);
                println!("  default_mcs: {:?}", config.default_mcs);
                println!("  data_dir: {}", config.data_dir.display());
                println!("  log_level: {}", config.log_level);
                0
            }
            Err(e) => {
                eprintln!("[ABOS] Config load failed: {}", e);
                1
            }
        }
    })
}

fn cmd_chirp(start_mhz: f64, stop_mhz: f64, duration_s: f64) -> i32 {
    if start_mhz <= 0.0 || stop_mhz <= start_mhz || duration_s <= 0.0 {
        eprintln!(
            "[ABOS] Invalid chirp range: need 0 < start < stop and duration > 0 \
             (got {} → {} MHz over {} s)",
            start_mhz, stop_mhz, duration_s
        );
        return 2;
    }
    println!("[ABOS] Generating chirp sounder waveform...");
    let chirp = ABOSSystem::generate_chirp(start_mhz * 1.0e6, stop_mhz * 1.0e6, duration_s);
    println!(
        "[ABOS] Chirp generated: {} samples ({} ms)",
        chirp.len(),
        (chirp.len() as f64 / 1_000_000.0 * 1000.0) as u64
    );
    0
}

fn cmd_mesh() -> i32 {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(mut system) => {
                // A freshly booted node has an empty peer table; this
                // command shows the live coordination state.
                let _ = system.maybe_emit_beacon("cli-probe");
                let dropped = system.expire_mesh_peers();
                let mesh = system.mesh();
                println!("[ABOS] Mesh state");
                println!("  Node ID:            {}", hex32(&mesh.local_id()));
                println!("  Live peers:         {}", mesh.peer_count());
                for peer in mesh.peers() {
                    println!(
                        "    {}  alias={}  last_seen={}s ago  beacons={}",
                        hex32(&peer.node_id),
                        peer.alias,
                        now_secs().saturating_sub(peer.last_seen),
                        peer.beacon_count
                    );
                }
                println!("  Pending ACKs:       {}", mesh.pending_count());
                println!("  Peers expired:      {}", dropped);
                0
            }
            Err(e) => {
                eprintln!("[ABOS] Mesh query failed: {}", e);
                1
            }
        }
    })
}

fn cmd_forward() -> i32 {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match ABOSSystem::new().await {
            Ok(mut system) => {
                let due = system.retransmit_queue();
                let evicted = system.evict_expired_bundles();
                println!("[ABOS] Forwarding state");
                println!("  Retransmit due now: {}", due.len());
                for id in due.iter().take(10) {
                    println!("    {}", hex32(id));
                }
                println!("  Bundles in store:   {}", system.stored_bundle_count());
                println!("  Expired evicted:    {}", evicted);
                0
            }
            Err(e) => {
                eprintln!("[ABOS] Forward query failed: {}", e);
                1
            }
        }
    })
}
