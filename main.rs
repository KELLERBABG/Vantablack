mod session;
mod crypto;
mod network;

use session::SessionGuard;
use crypto::{
    encrypt_message, decrypt_message,
    rs_encode, rs_reconstruct,
    shamir_split, shamir_join,
    random_key, PeerIdentity,
    HANDSHAKE_BLOB_LEN,
};
use network::{
    HANDSHAKE_ID,
    send_handshake_packets, send_data_packets,
    parse_counter, shard_len_for,
    OFFSET_MSG_ID, OFFSET_ORIG_LEN,
    OFFSET_SHARE_START, OFFSET_SHARE_END, OFFSET_SHARD_START,
};

use reed_solomon_erasure::galois_8::ReedSolomon;
use std::net::UdpSocket;
use std::{sync::Arc, io::{self, Write}, collections::HashMap};
use rand::Rng;
use tokio::time::{sleep, Duration};
use tokio::sync::RwLock;

use x25519_dalek::EphemeralSecret;
use ed25519_dalek::{Verifier, VerifyingKey as EdPublicKey, Signature};

#[tokio::main]
async fn main() {
    println!("--- GHOST-CHAT V2.0 (DYNAMIC PORT & IDENTITY) ---");

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't find a UDP Port");
    let local_addr = socket.local_addr().unwrap();
    println!("[INFO] Bound to: {}", local_addr);

    print!("Nickname: "); io::stdout().flush().unwrap();
    let mut nickname = String::new(); io::stdin().read_line(&mut nickname).unwrap();
    let nickname = nickname.trim().to_string();

    print!("Ziel-IP: "); io::stdout().flush().unwrap();
    let mut target_ip_raw = String::new(); io::stdin().read_line(&mut target_ip_raw).unwrap();
    let target_ip = target_ip_raw.trim().to_string();

    // If no port is given, 9000 is used by default.
    // IPv6 addresses must be given in full form with brackets, e.g. [2001:db8::1]:9000
    let initial_target = if target_ip.contains(':') { target_ip } else { format!("{}:9000", target_ip) };
    let target_addr = Arc::new(RwLock::new(initial_target));

    let target_addr_rx   = Arc::clone(&target_addr);
    let target_addr_tx   = Arc::clone(&target_addr);
    let target_addr_chat = Arc::clone(&target_addr);

    socket.set_nonblocking(true).unwrap();
    let socket = Arc::new(socket);
    let socket_rx = Arc::clone(&socket);
    let socket_tx = Arc::clone(&socket);

    let master_key: Arc<RwLock<Option<[u8; 32]>>> = Arc::new(RwLock::new(None));
    let master_key_rx = Arc::clone(&master_key);
    let master_key_tx = Arc::clone(&master_key);
    let global_tx_counter = Arc::new(RwLock::new(0u64));

    // --- IDENTITY ---
    let mut seed = [0u8; 32];
    rand::thread_rng().fill(&mut seed);
    let x_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let identity = PeerIdentity::generate(&seed, x_secret);
    println!("[SYSTEM] Your ID Fingerprint: {}", identity.fingerprint());

    // Pre-build the handshake blob and encode it into RS shards + Shamir shares
    let hs_blob = identity.build_handshake_blob();
    let mut hs_temp_key = random_key();
    let hs_shares = shamir_split(&mut hs_temp_key);
    let mut hs_shards = vec![
        hs_blob[0..480].to_vec(),
        hs_blob[480..960].to_vec(),
        vec![0u8; 480],
    ];
    ReedSolomon::new(2, 1).unwrap().encode(&mut hs_shards).unwrap();

    // --- RECEIVER TASK ---
    tokio::spawn(async move {
        // pool: msg_id -> (shares, shards, original_len, counter)
        let mut pool: HashMap<u8, (Vec<Vec<u8>>, Vec<Vec<u8>>, usize, u64)> = HashMap::new();
        let mut guard = SessionGuard::new();

        loop {
            let mut buf = [0u8; 2048];
            if let Ok((len, from_addr)) = socket_rx.recv_from(&mut buf) {
                let msg_id  = buf[OFFSET_MSG_ID];
                let msg_len = buf[OFFSET_ORIG_LEN] as usize;

                // Update peer address dynamically on every handshake packet
                if msg_id == HANDSHAKE_ID {
                    let mut t = target_addr_rx.write().await;
                    let new_addr = from_addr.to_string();
                    if *t != new_addr {
                        *t = new_addr;
                        println!("\n[INFO] Target address updated to {}.", from_addr);
                    }
                }

                if msg_id == 0 { continue; } // reserved / padding packet

                let packet_counter = parse_counter(&buf);
                let shard_len = shard_len_for(msg_id, msg_len);

                if len >= OFFSET_SHARD_START + shard_len {
                    let share = buf[OFFSET_SHARE_START..OFFSET_SHARE_END].to_vec();
                    let shard = buf[OFFSET_SHARD_START..OFFSET_SHARD_START + shard_len].to_vec();

                    let entry = pool
                        .entry(msg_id)
                        .or_insert((Vec::new(), Vec::new(), msg_len, packet_counter));
                    entry.0.push(share);
                    entry.1.push(shard);

                    if entry.0.len() >= 2 {
                        // Replay / session check (handshake packets are exempt)
                        if msg_id != HANDSHAKE_ID && !guard.check_and_update(entry.3) {
                            pool.remove(&msg_id);
                            continue;
                        }

                        let key_recovered = shamir_join(&entry.0[0], &entry.0[1]);
                        let mut recover = vec![
                            Some(entry.1[0].clone()),
                            Some(entry.1[1].clone()),
                            None,
                        ];

                        if rs_reconstruct(&mut recover).is_ok() {
                            let mut combined = [
                                recover[0].as_ref().unwrap().as_slice(),
                                recover[1].as_ref().unwrap().as_slice(),
                            ]
                            .concat();

                            if msg_id == HANDSHAKE_ID {
                                // Accept only the first handshake
                                if master_key_rx.read().await.is_some() {
                                    pool.remove(&msg_id);
                                    continue;
                                }

                                // combined layout: [magic(16)|x_pub(32)|kyber_pub(800)|ed_vk(32)|sig(64)]
                                let received_kyber_pk = &combined[48..848];
                                let ed_pk_res  = EdPublicKey::from_bytes(combined[848..880].try_into().expect("Key len"));
                                let sig_res    = Signature::from_bytes(combined[880..944].try_into().expect("Sig len"));

                                if let Ok(peer_pk) = ed_pk_res {
                                    if peer_pk.verify(received_kyber_pk, &sig_res).is_ok() {
                                        let mut mk = master_key_rx.write().await;
                                        if mk.is_none() {
                                            let mut k = [0u8; 32];
                                            k.copy_from_slice(&key_recovered[0..32]);
                                            *mk = Some(k);
                                            guard = SessionGuard::new();
                                            println!(
                                                "\n[TRUST] Handshake verified! ID: {}",
                                                hex::encode(&combined[848..856])
                                            );
                                            println!("You can now send messages.\n> ");
                                            io::stdout().flush().unwrap();
                                        }
                                    }
                                }
                            } else {
                                // Data message — decrypt using the packet counter as nonce
                                let packet_counter = entry.3;
                                combined.truncate(entry.2 + 16);
                                if let Ok(dec) = decrypt_message(&key_recovered, packet_counter, &mut combined) {
                                    println!("\rPartner: {}\n> ", String::from_utf8_lossy(dec));
                                    io::stdout().flush().unwrap();
                                }
                            }
                        }
                        pool.remove(&msg_id);
                    }
                }
            }
            sleep(Duration::from_millis(5)).await;
        }
    });

    // --- HANDSHAKE TASK ---
    let tx_hs       = Arc::clone(&socket_tx);
    let addr_hs     = Arc::clone(&target_addr_tx);
    let mk_checker  = Arc::clone(&master_key);

    tokio::spawn(async move {
        loop {
            if mk_checker.read().await.is_some() {
                sleep(Duration::from_secs(10)).await;
                continue;
            }
            let target = addr_hs.read().await;
            send_handshake_packets(&hs_shares, &hs_shards, &tx_hs, &*target);
            drop(target);
            sleep(Duration::from_millis(1500)).await;
        }
    });

    // --- CHAT LOOP (main task) ---
    loop {
        print!("> "); io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let raw = input.trim();
        if raw.is_empty() { continue; }

        let mk_opt = master_key_tx.read().await;
        if let Some(mk) = *mk_opt {
            let target = target_addr_chat.read().await;
            let msg = format!("{}: {}", nickname, raw);
            let mut data = msg.as_bytes().to_vec();
            let original_len = data.len();

            let mut c_guard = global_tx_counter.write().await;
            *c_guard += 1;
            let current_c = *c_guard;

            encrypt_message(&mk, current_c, &mut data);
            let shards = rs_encode(&mut data);
            let shard_len = shards[0].len();

            let id = rand::thread_rng().gen_range(1u8..254);
            let mut mk_clone = mk;
            let mk_shares = shamir_split(&mut mk_clone);

            send_data_packets(
                id,
                original_len,
                &mk_shares,
                &shards,
                shard_len,
                current_c,
                &socket_tx,
                &*target,
            );
        }
    }
}
