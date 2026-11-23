//! daemon::beacon — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

/// Optional beacon sections (Phase 1 P1-1). Each is `[4 magic][u16 len][bytes]`,
/// appended after the 112-byte signed prefix.
///
/// The frame is self-describing and validated by *tiling*: a datagram is only
/// read as sectioned when its sections consume it exactly. That is what lets the
/// pre-P1-1 fixed layouts keep parsing — see [`parse_beacon_sections`].
pub(crate) const BEACON_SECTION_ZK: &[u8; 4] = b"ZKPR";
pub(crate) const BEACON_SECTION_ICE: &[u8; 4] = b"ICEO";
/// Empty section: "this node will relay for others" (`GHOST_RELAY=1`).
///
/// Capability, not address. A relay is reached at the address its beacon came
/// from — the same socket it forwards on — so carrying an address would let a
/// peer advertise someone else's. Its presence is the whole message, which is
/// why the payload must be empty.
pub(crate) const BEACON_SECTION_RELAY: &[u8; 4] = b"RLYC";
/// 32-byte SHA-256 commitment to the sender's ML-DSA-65 public key (P2-1).
///
/// A commitment and not the key: the key is 1952 bytes and its signature 3309,
/// so a hybrid proof cannot travel in a 512–1472-byte datagram at all. What fits
/// is the name of the key, and a verifier that remembers it (`Carrier::
/// pin_commitment`) can then refuse a later session that presents a different
/// post-quantum key — which is what stops a forger with the classical private key
/// from substituting one of their own.
pub(crate) const BEACON_SECTION_PQ_COMMIT: &[u8; 4] = b"PQK!";
/// 2-byte big-endian `u16` carrying the sender's actual UDP mesh listening port (`nc.socket`).
/// Allows peers discovering us via an ephemeral-port multicast `beacon_sock` to learn our real
/// mesh port for relay candidates and handshakes.
pub(crate) const BEACON_SECTION_PORT: &[u8; 4] = b"PORT";

/// How long a measured direct contact stays valid before it must be re-observed.
/// A NAT mapping is typically torn down after 30–120 s of silence, so a contact
/// is not treated as permanent.
pub(crate) const ICE_CONTACT_WINDOW_SECS: f64 = 120.0;

/// Wall-clock seconds since the Unix epoch, the clock `ContactPlan` timestamps
/// live on.
pub(crate) fn unix_now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// The legacy fixed beacon layout, still accepted from older peers. The 208-byte
/// variant that carried a ZK block at fixed offsets is gone with the hard switch
/// A datagram that long is now read as a bare, identity-only
/// beacon, never as a peer that proved membership.
pub(crate) const BEACON_LEGACY_LEN: usize = 112;

/// Optional sections carried by an extended beacon.
pub(crate) struct BeaconSections<'a> {
    /// `(context, proof)` when a ZK membership proof is present. The context is
    /// the timestamp the proof is bound to; the proof is `R ‖ z`.
    pub(crate) zk: Option<(&'a [u8; 32], &'a [u8])>,
    /// The sender's ICE offer, as produced by `ice::IceOffer::encode`.
    pub(crate) ice_offer: Option<&'a str>,
    /// Whether the sender advertises relay capability.
    pub(crate) relay_capable: bool,
    /// SHA-256 commitment to the sender's post-quantum public key (P2-1).
    pub(crate) pq_commitment: Option<&'a [u8; 32]>,
    /// Sender's real mesh UDP listening port (`nc.socket`).
    pub(crate) mesh_port: Option<u16>,
    /// Coarse, bucketed loss observation for collective defense
    /// (`exp_collective_defense`), when the sender has that toggle on.
    pub(crate) cdef: Option<&'a [u8]>,
}

/// Parse the trailing optional sections of a beacon.
///
/// Returns `None` when the datagram does not tile as sections. That fallback is
/// what keeps the parser honest about older layouts — the trailing bytes of a
/// legacy beacon are arbitrary, and a coincidence must be read as a legacy
/// beacon rather than as a section whose contents were never intended.
pub(crate) fn parse_beacon_sections(buf: &[u8], amt: usize) -> Option<BeaconSections<'_>> {
    let mut pos = BEACON_LEGACY_LEN;
    let mut zk = None;
    let mut ice_offer = None;
    let mut relay_capable = false;
    let mut pq_commitment = None;
    let mut mesh_port = None;
    let mut cdef = None;
    while pos < amt {
        if pos + 6 > amt {
            return None;
        }
        let magic = &buf[pos..pos + 4];
        let len = u16::from_be_bytes([buf[pos + 4], buf[pos + 5]]) as usize;
        let start = pos + 6;
        let end = start + len;
        if end > amt {
            return None;
        }
        if magic == BEACON_SECTION_ZK {
            if len != ZK_CONTEXT_LEN + ZK_PROOF_LEN {
                return None;
            }
            let context: &[u8; 32] = buf[start..start + ZK_CONTEXT_LEN].try_into().ok()?;
            zk = Some((context, &buf[start + ZK_CONTEXT_LEN..end]));
        } else if magic == BEACON_SECTION_ICE {
            ice_offer = Some(std::str::from_utf8(&buf[start..end]).ok()?);
        } else if magic == BEACON_SECTION_RELAY {
            if len != 0 {
                return None;
            }
            relay_capable = true;
        } else if magic == BEACON_SECTION_PQ_COMMIT {
            // A commitment section of the wrong size is a malformed section, not a
            // shorter commitment: fall back to the legacy reading (below), where it
            // is ignored. A beacon without a usable commitment pins nothing, which
            // is the same as a peer that never sent one.
            if len != 32 {
                return None;
            }
            pq_commitment = buf[start..end].try_into().ok();
        } else if magic == BEACON_SECTION_PORT {
            if len != 2 {
                return None;
            }
            mesh_port = Some(u16::from_be_bytes([buf[start], buf[start + 1]]));
        } else if magic == super::experimental::BEACON_SECTION_CDEF {
            if len != 15 {
                return None;
            }
            cdef = Some(&buf[start..end]);
        } else {
            return None;
        }
        pos = end;
    }
    Some(BeaconSections {
        zk,
        ice_offer,
        relay_capable,
        pq_commitment,
        mesh_port,
        cdef,
    })
}

/// Append one optional beacon section.
pub(crate) fn push_beacon_section(buf: &mut Vec<u8>, magic: &[u8; 4], payload: &[u8]) {
    buf.extend_from_slice(magic);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
}

/// Assemble a beacon from its signed prefix and optional sections.
///
/// `zk` is the membership proof to carry, already created for this identity: the
/// builder never sees the PSK, so it cannot be asked for a proof it has no secret
/// to make. The boolean this replaced could not tell "no proof wanted" from "no
/// secret to prove with", and emitted a signature-shaped block for neither
pub(crate) fn build_beacon_packet(
    pk: &[u8; 32],
    signer: impl Fn(&[u8]) -> [u8; 64],
    zk: Option<([u8; 32], [u8; 64])>,
    ice_offer: Option<&str>,
    relay_capable: bool,
    pq_commitment: Option<&[u8; 32]>,
    mesh_port: Option<u16>,
) -> Vec<u8> {
    // Signed prefix: [16 magic][32 full Ed25519 pk][64 signature over pk].
    let mut buf = vec![0u8; BEACON_LEGACY_LEN];
    buf[0..16].copy_from_slice(BEACON_PREFIX);
    buf[16..48].copy_from_slice(pk);
    let sig = signer(&buf[16..48]);
    buf[48..112].copy_from_slice(&sig);

    if let Some((context, proof)) = zk {
        // A membership proof, already created for this identity. The builder
        // never sees the PSK, so it cannot be asked for a proof it has no secret
        // to make — the old boolean could not tell "no proof wanted" from "no
        // secret to prove with" and would emit a signature-shaped block for
        // neither.
        let mut section = Vec::with_capacity(ZK_CONTEXT_LEN + ZK_PROOF_LEN);
        section.extend_from_slice(&context);
        section.extend_from_slice(&proof);
        push_beacon_section(&mut buf, BEACON_SECTION_ZK, &section);
    }
    if let Some(offer) = ice_offer {
        push_beacon_section(&mut buf, BEACON_SECTION_ICE, offer.as_bytes());
    }
    if relay_capable {
        push_beacon_section(&mut buf, BEACON_SECTION_RELAY, &[]);
    }
    if let Some(commitment) = pq_commitment {
        push_beacon_section(&mut buf, BEACON_SECTION_PQ_COMMIT, commitment);
    }
    if let Some(port) = mesh_port.filter(|&p| p != 0) {
        push_beacon_section(&mut buf, BEACON_SECTION_PORT, &port.to_be_bytes());
    }
    buf
}

pub(crate) fn is_single_device_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return false;
            }
            let octets = v4.octets();
            v4.is_private() || (octets[0] == 100 && (octets[1] & 0xc0) == 64) || v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => !v6.is_loopback(),
    }
}

pub(crate) fn register_peer_session(
    node: &Arc<GhostNode>,
    peers: &DashMap<String, SocketAddr>,
    fp: &str,
    src: SocketAddr,
    session: Session,
    vpn_mode: Option<&VpnMode>,
) {
    let _ = vpn_mode;
    let stale_fps: Vec<String> = peers
        .iter()
        .filter(|entry| {
            if entry.key().as_str() == fp {
                return false;
            }
            if *entry.value() == src {
                return true;
            }
            if is_single_device_ip(src.ip()) && entry.value().ip() == src.ip() {
                return true;
            }
            false
        })
        .map(|entry| entry.key().clone())
        .collect();

    for stale in stale_fps {
        tracing::info!(stale_fp = %stale, new_fp = %fp, ip = %src, "Evicting stale peer mapping and session for endpoint");
        peers.remove(&stale);
        node.sessions.remove(&stale);
        #[cfg(feature = "vpn")]
        if let Some(VpnMode::Hub(hub)) = vpn_mode {
            hub.on_disconnect(&stale);
        }
    }

    peers.insert(fp.to_string(), src);
    node.sessions.insert(fp.to_string(), session);
    record_active_peer(src);
}

#[cfg(test)]
mod beacon_section_tests {
    use crate::*;

    pub(crate) fn test_pk() -> [u8; 32] {
        [7u8; 32]
    }

    pub(crate) fn stub_signer(_d: &[u8]) -> [u8; 64] {
        [9u8; 64]
    }

    /// A real identity, because the beacon's prefix signature must verify against
    /// the key it names — a stub signer can never produce one. The membership
    /// proof itself no longer involves the signing key at all: it is a Schnorr
    /// proof about the PSK and the public key.
    pub(crate) fn real_identity() -> l0_identity::GhostIdentity {
        l0_identity::GhostIdentity::generate_fresh()
    }

    /// The mesh membership secret these tests prove knowledge of.
    pub(crate) fn test_psk() -> [u8; 32] {
        [0x33; 32]
    }

    /// Build an offer through the real encoder, so these tests cannot drift away
    /// from the signalling format they are meant to cover.
    pub(crate) fn sample_offer(controlling: bool) -> String {
        use std::net::SocketAddr;
        use vantablack::ghost::net::ice::{
            Candidate, CandidateType, IceCredentials, IceOffer, DEFAULT_COMPONENT,
        };
        let base: SocketAddr = "192.168.1.5:40000".parse().unwrap();
        IceOffer::new(
            IceCredentials {
                ufrag: "deadbeef".into(),
                password: "00112233445566778899aabbccddeeff".into(),
            },
            vec![Candidate::new(
                CandidateType::Host,
                base,
                base,
                DEFAULT_COMPONENT,
                None,
            )],
            controlling,
        )
        .encode()
    }

    #[test]
    pub(crate) fn a_plain_beacon_keeps_the_legacy_112_byte_layout() {
        let b = build_beacon_packet(&test_pk(), stub_signer, None, None, false, None, None);
        assert_eq!(b.len(), BEACON_LEGACY_LEN);
        assert_eq!(&b[..16], BEACON_PREFIX);
        let sections = parse_beacon_sections(&b, b.len()).expect("parses with no sections");
        assert!(sections.zk.is_none());
        assert!(sections.ice_offer.is_none());
        assert!(sections.mesh_port.is_none());
    }

    #[test]
    pub(crate) fn a_membership_proof_beacon_uses_the_sectioned_layout() {
        // Hard switch: the 208-byte layout that carried a
        // signature-shaped block at fixed offsets is gone, so a node with nothing
        // else to say still says this in a section.
        let identity = real_identity();
        let pk = identity.public_key_bytes();
        let psk = test_psk();
        let b = build_beacon_packet(
            &pk,
            |d| identity.sign(d).to_bytes(),
            Some(ZkAuthenticator::create_proof(&pk, &psk)),
            None,
            false,
            None,
            None,
        );
        assert!(b.len() > BEACON_LEGACY_LEN);

        let sections = parse_beacon_sections(&b, b.len()).expect("the section must tile");
        let (context, proof) = sections.zk.expect("a membership proof is present");
        assert!(ZkAuthenticator::verify_proof(
            &pk,
            Some(&psk),
            context,
            proof
        ));
        // A verifier checking the wrong identity, or holding a different
        // membership secret, accepts nothing.
        assert!(!ZkAuthenticator::verify_proof(
            &test_pk(),
            Some(&psk),
            context,
            proof
        ));
        assert!(!ZkAuthenticator::verify_proof(
            &pk,
            Some(&[0x44; 32]),
            context,
            proof
        ));
    }

    #[test]
    pub(crate) fn a_proof_made_for_one_identity_is_not_accepted_in_another_beacon() {
        // The statement names the pk it was made for, so even a member of the
        // same mesh — holding the same PSK — cannot lift its own proof into
        // another node's beacon. What ties the pk to the sender is the beacon's
        // prefix signature, and this test asserts the split rather than hiding
        // it.
        let mine = real_identity();
        let theirs = real_identity();
        let psk = test_psk();
        let (context, proof) = ZkAuthenticator::create_proof(&mine.public_key_bytes(), &psk);
        let b = build_beacon_packet(
            &theirs.public_key_bytes(),
            |d| theirs.sign(d).to_bytes(),
            Some((context, proof)),
            None,
            false,
            None,
            None,
        );
        let sections = parse_beacon_sections(&b, b.len()).expect("the section must tile");
        let (ctx, pr) = sections.zk.expect("a membership proof is present");
        assert!(
            !ZkAuthenticator::verify_proof(&theirs.public_key_bytes(), Some(&psk), ctx, pr),
            "a proof made for another identity must not verify against this beacon"
        );
        assert!(ZkAuthenticator::verify_proof(
            &mine.public_key_bytes(),
            Some(&psk),
            ctx,
            pr
        ));
    }

    #[test]
    pub(crate) fn an_offer_beacon_round_trips_through_its_sections() {
        let offer = sample_offer(true);
        let b = build_beacon_packet(
            &test_pk(),
            stub_signer,
            None,
            Some(&offer),
            false,
            None,
            None,
        );
        assert!(b.len() > BEACON_LEGACY_LEN);

        let sections = parse_beacon_sections(&b, b.len()).expect("sections must tile exactly");
        assert!(sections.zk.is_none(), "no proof was attached");
        assert_eq!(sections.ice_offer, Some(offer.as_str()));

        // And it decodes back into a usable offer, candidates included.
        let decoded = vantablack::ghost::net::ice::IceOffer::decode(sections.ice_offer.unwrap())
            .expect("a well-formed offer must decode");
        assert_eq!(decoded.credentials.ufrag, "deadbeef");
        assert!(decoded.controlling);
        assert_eq!(
            decoded.candidates[0].addr,
            "192.168.1.5:40000".parse().unwrap()
        );
    }

    #[test]
    pub(crate) fn a_zk_beacon_with_an_offer_carries_both_sections() {
        let offer = sample_offer(false);
        let identity = real_identity();
        let pk = identity.public_key_bytes();
        let psk = test_psk();
        let b = build_beacon_packet(
            &pk,
            |d| identity.sign(d).to_bytes(),
            Some(ZkAuthenticator::create_proof(&pk, &psk)),
            Some(&offer),
            false,
            None,
            None,
        );
        let sections = parse_beacon_sections(&b, b.len()).expect("both sections must parse");

        let (context, proof) = sections.zk.expect("membership proof present");
        assert!(
            ZkAuthenticator::verify_proof(&pk, Some(&psk), context, proof),
            "the proof must verify for the identity it was made for"
        );
        assert_eq!(sections.ice_offer, Some(offer.as_str()));
        let decoded =
            vantablack::ghost::net::ice::IceOffer::decode(sections.ice_offer.unwrap()).unwrap();
        assert!(!decoded.controlling);
    }

    /// The post-quantum commitment rides its own section and round-trips (P2-1).
    #[test]
    pub(crate) fn a_pq_commitment_section_names_the_post_quantum_key() {
        let identity = real_identity();
        let pk = identity.public_key_bytes();
        let commitment = identity.pq_commitment();
        let b = build_beacon_packet(
            &pk,
            |d| identity.sign(d).to_bytes(),
            None,
            None,
            false,
            Some(&commitment),
            Some(55225),
        );
        let sections = parse_beacon_sections(&b, b.len()).expect("the section must tile exactly");
        assert_eq!(sections.pq_commitment, Some(&commitment));
        assert_eq!(sections.mesh_port, Some(55225));
        // And it is the commitment to *this* identity's key, so a verifier that
        // remembers it can check the key the peer later proves on the carrier.
        assert_eq!(
            commitment,
            l0_identity::pq_commitment(&identity.pq_public_key_bytes())
        );
        // A section with no commitment anywhere is not invented.
        let plain = build_beacon_packet(&pk, stub_signer, None, None, false, None, None);
        assert_eq!(plain.len(), BEACON_LEGACY_LEN);
        assert!(parse_beacon_sections(&plain, plain.len())
            .expect("a bare beacon parses")
            .pq_commitment
            .is_none());
        // A wrongly sized commitment section is malformed, not truncated.
        let mut bad = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut bad, BEACON_SECTION_PQ_COMMIT, &commitment[..31]);
        assert!(parse_beacon_sections(&bad, bad.len()).is_none());
    }

    #[test]
    pub(crate) fn malformed_or_unknown_sections_fall_back_to_the_legacy_layout() {
        // A length that runs past the datagram must not be trusted.
        let mut buf = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf, BEACON_SECTION_ICE, b"x");
        let amt = buf.len();
        buf[BEACON_LEGACY_LEN + 4..BEACON_LEGACY_LEN + 6].copy_from_slice(&9999u16.to_be_bytes());
        assert!(parse_beacon_sections(&buf, amt).is_none());

        // An unknown magic is not a section either.
        let mut buf2 = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf2, b"XXXX", b"payload");
        let amt2 = buf2.len();
        assert!(parse_beacon_sections(&buf2, amt2).is_none());

        // A ZK section of the wrong size is rejected rather than misread.
        let mut buf3 = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf3, BEACON_SECTION_ZK, &[0u8; 40]);
        let amt3 = buf3.len();
        assert!(parse_beacon_sections(&buf3, amt3).is_none());

        // A trailing partial header is rejected.
        let mut buf4 = vec![0u8; BEACON_LEGACY_LEN + 3];
        buf4[BEACON_LEGACY_LEN] = b'I';
        let amt4 = buf4.len();
        assert!(parse_beacon_sections(&buf4, amt4).is_none());
    }

    #[test]
    pub(crate) fn an_empty_offer_section_is_absent_not_empty_text() {
        // A zero-length ICEO section is a present-but-empty offer, which the
        // decoder rejects; the framing itself must still tile.
        let mut buf = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf, BEACON_SECTION_ICE, b"");
        let amt = buf.len();
        let sections = parse_beacon_sections(&buf, amt).expect("tiles exactly");
        assert_eq!(sections.ice_offer, Some(""));
        assert!(vantablack::ghost::net::ice::IceOffer::decode("").is_err());
    }
}
