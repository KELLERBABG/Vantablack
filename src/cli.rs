//! Command-line interface and argument handling for Vantablack (GGN).

use rand::RngCore;

/// Handles command line subcommands and flags.
/// Returns `Some(result)` if the CLI invocation was handled (and the process should terminate),
/// or `None` if the daemon should proceed with standard boot.
pub fn handle_cli_args() -> Option<anyhow::Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None;
    }
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
            println!("  Status: {}", if cfg!(feature = "sdr") { "Enabled (compiled with --features sdr)" } else { "Disabled (compile with --features sdr)" });
            Some(Ok(()))
        }
        "--version" | "-v" | "version" => {
            println!("vantablack {}", env!("CARGO_PKG_VERSION"));
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
            println!("  ggn sdr-status                  Show atmospheric skywave (ABOS) carrier status");
            println!("  ggn --version                   Show version information");
            println!("  ggn --help                      Show this help");
            Some(Ok(()))
        }

        _ => None,
    }
}
