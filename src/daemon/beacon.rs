//! daemon::beacon — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

pub(crate) const BEACON_SECTION_ZK: &[u8; 4] = b"ZKPR";
pub(crate) const BEACON_SECTION_ICE: &[u8; 4] = b"ICEO";
pub(crate) const BEACON_SECTION_RELAY: &[u8; 4] = b"RLYC";
pub(crate) const BEACON_SECTION_PQ_COMMIT: &[u8; 4] = b"PQK!";
pub(crate) const BEACON_SECTION_PORT: &[u8; 4] = b"PORT";

pub(crate) const ICE_CONTACT_WINDOW_SECS: f64 = 120.0;

pub(crate) fn unix_now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub(crate) const BEACON_LEGACY_LEN: usize = 112;

pub(crate) struct BeaconSections<'a> {
    pub(crate) zk: Option<(&'a [u8; 32], &'a [u8])>,
    pub(crate) ice_offer: Option<&'a str>,
    pub(crate) relay_capable: bool,
    pub(crate) pq_commitment: Option<&'a [u8; 32]>,
    pub(crate) mesh_port: Option<u16>,
    pub(crate) cdef: Option<&'a [u8]>,
}

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

pub(crate) fn push_beacon_section(buf: &mut Vec<u8>, magic: &[u8; 4], payload: &[u8]) {
    buf.extend_from_slice(magic);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
}

pub(crate) fn build_beacon_packet(
    pk: &[u8; 32],
    signer: impl Fn(&[u8]) -> [u8; 64],
    zk: Option<([u8; 32], [u8; 64])>,
    ice_offer: Option<&str>,
    relay_capable: bool,
    pq_commitment: Option<&[u8; 32]>,
    mesh_port: Option<u16>,
) -> Vec<u8> {
    let mut buf = vec![0u8; BEACON_LEGACY_LEN];
    buf[0..16].copy_from_slice(BEACON_PREFIX);
    buf[16..48].copy_from_slice(pk);
    let sig = signer(&buf[16..48]);
    buf[48..112].copy_from_slice(&sig);

    if let Some((context, proof)) = zk {
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

    #[cfg(feature = "research")]
    let session_master = session.master_key;
    peers.insert(fp.to_string(), src);
    node.sessions.insert(fp.to_string(), session);
    record_active_peer(src);

    #[cfg(feature = "research")]
    {
        let our_fp = node.fingerprint();
        #[cfg(not(test))]
        super::research_hooks::braid::init(&our_fp);
        let _ = super::research_hooks::braid::advance_and_tip(&our_fp, fp, &session_master);
    }
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

    pub(crate) fn real_identity() -> l0_identity::GhostIdentity {
        l0_identity::GhostIdentity::generate_fresh()
    }

    pub(crate) fn test_psk() -> [u8; 32] {
        [0x33; 32]
    }

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
        assert_eq!(
            commitment,
            l0_identity::pq_commitment(&identity.pq_public_key_bytes())
        );
        let plain = build_beacon_packet(&pk, stub_signer, None, None, false, None, None);
        assert_eq!(plain.len(), BEACON_LEGACY_LEN);
        assert!(parse_beacon_sections(&plain, plain.len())
            .expect("a bare beacon parses")
            .pq_commitment
            .is_none());
        let mut bad = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut bad, BEACON_SECTION_PQ_COMMIT, &commitment[..31]);
        assert!(parse_beacon_sections(&bad, bad.len()).is_none());
    }

    #[test]
    pub(crate) fn malformed_or_unknown_sections_fall_back_to_the_legacy_layout() {
        let mut buf = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf, BEACON_SECTION_ICE, b"x");
        let amt = buf.len();
        buf[BEACON_LEGACY_LEN + 4..BEACON_LEGACY_LEN + 6].copy_from_slice(&9999u16.to_be_bytes());
        assert!(parse_beacon_sections(&buf, amt).is_none());

        let mut buf2 = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf2, b"XXXX", b"payload");
        let amt2 = buf2.len();
        assert!(parse_beacon_sections(&buf2, amt2).is_none());

        let mut buf3 = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf3, BEACON_SECTION_ZK, &[0u8; 40]);
        let amt3 = buf3.len();
        assert!(parse_beacon_sections(&buf3, amt3).is_none());

        let mut buf4 = vec![0u8; BEACON_LEGACY_LEN + 3];
        buf4[BEACON_LEGACY_LEN] = b'I';
        let amt4 = buf4.len();
        assert!(parse_beacon_sections(&buf4, amt4).is_none());
    }

    #[test]
    pub(crate) fn an_empty_offer_section_is_absent_not_empty_text() {
        let mut buf = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf, BEACON_SECTION_ICE, b"");
        let amt = buf.len();
        let sections = parse_beacon_sections(&buf, amt).expect("tiles exactly");
        assert_eq!(sections.ice_offer, Some(""));
        assert!(vantablack::ghost::net::ice::IceOffer::decode("").is_err());
    }
}
