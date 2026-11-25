//! JSON surface for the v2 features, consumed by the dashboard and by
//! `ggn xray`.
//!
//! Everything here is a pure function of [`ApiState`] so the control-center
//! handler stays a two-line dispatch and this module can be tested without a
//! socket. The state is deliberately small: only fields the node can actually
//! measure are included, and anything absent becomes `Unknown` in the ledger
//! rather than a flattering default.

use serde_json::{json, Value};

use super::btcr::{self, Bucket, Issuer, Receipt, Ticket};
use super::regime::{self, effective_policy, Regime};
use super::xray::{self, CircuitHops, CoverTx, LedgerInput, NonceEchoHops, WireWitness};
use std::fmt;

/// A private identity seed held by the running node, with a redacting `Debug`
/// so `{:?}` on [`ApiState`] can never print it into a log line.
#[derive(Clone)]
pub struct NodeSecret([u8; 32]);

impl NodeSecret {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NodeSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NodeSecret(<hidden>)")
    }
}

/// Measurements the daemon actually took. Every field is `Option`: the ledger
/// turns a missing measurement into `Unknown`, so this struct must not carry a
/// default that reads like a pass.
#[derive(Debug, Clone, Default)]
pub struct Witnesses {
    /// Hops in the circuit currently in use, if one is established. This is a
    /// [`WireWitness`]: the HTTP layer can pass the measurement through but
    /// cannot construct one, so a config value or a peer's claim cannot become
    /// a verified circuit length here.
    pub circuit_hops: Option<WireWitness<CircuitHops>>,
    /// Distinct ASNs among those hops.
    pub circuit_asns: Option<usize>,
    /// Peers whose CAP_RELAY bit verified against a signed descriptor.
    pub cap_relay_verified: Option<usize>,
    /// Hop count of the last signed nonce echo that came back.
    pub nonce_echo_hops: Option<WireWitness<NonceEchoHops>>,
    /// Cover frames emitted by this process.
    pub cover_tx: Option<WireWitness<CoverTx>>,
    /// Verified peers advertising CAP_RELAY — the raw population.
    pub relay_population: Option<usize>,
    /// That population grouped by routing-domain cluster.
    pub relay_domains: Option<Vec<usize>>,
    pub dns_leak: Option<bool>,
    pub outer_sni: Option<String>,
}

/// What the HTTP layer knows about the running node.
#[derive(Debug, Clone)]
pub struct ApiState {
    /// Peers currently connected. Used as the live relay population.
    pub peers: usize,
    pub regime: Regime,
    /// The node's first SOCKS5 listener.
    pub socks_port: u16,
    /// Outer transport label, when a session exists.
    pub transport: Option<String>,
    /// Address websites see, when this node is exiting.
    pub exit_ip: Option<String>,
    /// This node's fingerprint, for the home-exit view.
    pub node_fingerprint: String,
    /// Live measurements. Configured regime booleans are not witnesses.
    pub witnesses: Witnesses,
    /// The private seed the ticket issuer derives from. `None` in a view that
    /// has no node identity, which makes `/api/v2/btcr` report unavailability
    /// rather than minting from a guess.
    pub identity_seed: Option<NodeSecret>,
}

impl Default for ApiState {
    fn default() -> Self {
        Self {
            peers: 0,
            regime: Regime::Ghost,
            socks_port: 1080,
            transport: None,
            exit_ip: None,
            node_fingerprint: String::new(),
            witnesses: Witnesses::default(),
            identity_seed: None,
        }
    }
}

fn ledger_input(state: &ApiState) -> LedgerInput {
    let connected = state.peers > 0;
    LedgerInput {
        regime: Some(state.regime),
        // Prefer the verified relay population; a live session count is a
        // fallback that the ledger still has to treat as domain-ungrouped.
        public_relays: state
            .witnesses
            .relay_population
            .or(connected.then_some(state.peers)),
        circuit_hops: state.witnesses.circuit_hops.clone(),
        circuit_asns: state.witnesses.circuit_asns,
        transport: state.transport.clone(),
        outer_sni: state.witnesses.outer_sni.clone(),
        exit_ip: state.exit_ip.clone(),
        cover_tx: state.witnesses.cover_tx.clone(),
        dns_leak: state.witnesses.dns_leak,
        // The hybrid handshake is mandatory in this build: a session cannot be
        // established without it, so a live session is direct evidence.
        pq_hybrid: connected.then_some(true),
        chronos: super::chronos::evidence(),
        shaping: super::racs::shaping_evidence(),
        nvis: super::nvis::last_profile(),
        cap_relay_verified: state.witnesses.cap_relay_verified,
        nonce_echo_hops: state.witnesses.nonce_echo_hops.clone(),
        relay_domains: state.witnesses.relay_domains.clone(),
        census: super::xray::census::current_estimate(),
    }
}

/// `GET /api/v2/xray` — the truth ledger.
pub fn xray(state: &ApiState) -> Value {
    let ledger = xray::build(&ledger_input(state));
    json!({
        "headline": ledger.headline,
        "claim": ledger.claim,
        "regime": ledger.regime,
        "plane": ledger.plane,
        "observations": ledger.observations,
        "invariants": ledger.invariants,
        "formal": ledger.formal,
        "generated_at": ledger.generated_at,
    })
}

/// `GET /api/v2/regime` — the active policy plus every option.
pub fn regime(state: &ApiState) -> Value {
    let policy = effective_policy(state.regime, state.peers, state.socks_port);
    let options: Vec<Value> = Regime::ALL
        .iter()
        .map(|r| {
            let p = effective_policy(*r, state.peers, state.socks_port);
            json!({
                "regime": r.as_str(),
                "plane": r.plane().as_str(),
                "hops": r.hops().hops(),
                "socks_port": p.socks_port,
                "cover_traffic": r.cover_traffic(),
                "asn_diversity": r.requires_asn_diversity(),
                "description": r.describe(),
                "refuse_reason": p.refuse_reason,
                "claim": p.claim,
            })
        })
        .collect();
    json!({
        "active": policy.regime.as_str(),
        "plane": policy.plane.as_str(),
        "hops": policy.hops.hops(),
        "socks_port": policy.socks_port,
        "cover_traffic": policy.cover_traffic,
        "asn_diversity": policy.asn_diversity,
        "refuse_reason": policy.refuse_reason,
        "claim": policy.claim,
        "options": options,
    })
}

/// `GET /api/v2/capabilities` — what this build contains.
pub fn capabilities() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "surfaces": super::V2_SURFACES
            .iter()
            .map(|(id, description)| json!({"id": id, "description": description}))
            .collect::<Vec<_>>(),
        "min_anonymity_relays": regime::MIN_ANONYMITY_RELAYS,
        "deferred": [
            {
                "capability": "continuum_wifi_aware_ble_radio",
                "reason": "no Wi-Fi Aware or BLE transport in this build; the mule rung syncs removable media instead",
            },
            {
                "capability": "continuum_lora_kiss",
                "reason": "no KISS TNC serial transport or attached LoRa radio in this build",
            },
        ],
    })
}

/// Dispatch a `GET /api/v2/...` request. `None` means "not a v2 route".
pub fn handle(state: &ApiState, req: &str) -> Option<Value> {
    let path = req
        .strip_prefix("GET ")
        .unwrap_or(req)
        .split(['?', ' '])
        .next()
        .unwrap_or("");
    match path {
        "/api/v2/xray" => Some(xray(state)),
        "/api/v2/regime" => Some(regime(state)),
        "/api/v2/capabilities" => Some(capabilities()),
        "/api/v2/home-exit" => Some(super::boomerang::view(&state.node_fingerprint)),
        "/api/v2/btcr" => Some(match state.identity_seed.as_ref() {
            Some(seed) => {
                let issuer = Issuer::from_identity_seed(seed.expose());
                btcr::status_json(&issuer, super::now_secs())
            }
            None => json!({
                "issuer": null,
                "available": false,
                "note": "this view has no node identity seed, so no ticket issuer exists here",
            }),
        }),
        "/api/v2/fleet" => Some(super::fleet::status_json()),
        "/api/v2/ladder" => Some(super::continuum::status_json()),
        "/api/v2/racs" => Some(super::racs::status_json()),
        "/api/v2/chronos" => Some(super::chronos::status_json()),
        "/api/v2/nvis" => Some(super::nvis::status_json()),
        _ => None,
    }
}

/// Apply a `POST /api/v2/regime` body `{"regime": "fast|shielded|ghost|vantablack"}`.
///
/// Persists the choice and sets it for this process. The SOCKS listeners are
/// bound at startup, so a change takes effect on restart; the response says so
/// instead of implying a live switch that did not happen.
pub fn apply_regime(body: &Value) -> Result<Value, String> {
    let raw = body
        .get("regime")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "body must contain a \"regime\" string".to_string())?;
    let parsed = Regime::parse(raw)
        .ok_or_else(|| format!("{raw:?} is not one of fast, shielded, ghost, vantablack"))?;
    let path = regime::config_path();
    regime::save_persisted(&path, parsed)
        .map_err(|e| format!("cannot save {}: {e}", path.display()))?;
    std::env::set_var(regime::REGIME_ENV, parsed.as_str());
    let policy = effective_policy(parsed, 0, 1080);
    Ok(json!({
        "success": true,
        "regime": parsed.as_str(),
        "plane": policy.plane.as_str(),
        "hops": policy.hops.hops(),
        "socks_port": policy.socks_port,
        "restart_required": true,
        "note": "SOCKS listeners are bound at startup; restart the node to apply the new hop policy.",
    }))
}

/// `POST /api/v2/btcr/issue` — blind-evaluate a request against a work receipt.
///
/// The caller supplies the **blinded** point and a beneficiary-signed receipt.
/// The node returns `E = k·B` plus the DLEQ proof; it never sees the ticket
/// input, so it cannot link issuance to a later spend. Without a configured
/// beneficiary key the endpoint refuses rather than minting unearned tickets.
pub fn btcr_issue(body: &Value, identity_seed: &[u8; 32]) -> Result<Value, String> {
    let beneficiary_hex = std::env::var("GHOST_BTCR_BENEFICIARY").map_err(|_| {
        "GHOST_BTCR_BENEFICIARY is not set; refusing to mint tickets without a trusted work signer"
            .to_string()
    })?;
    let key_bytes = hex::decode(beneficiary_hex.trim())
        .map_err(|e| format!("GHOST_BTCR_BENEFICIARY is not hex: {e}"))?;
    if key_bytes.len() != 32 {
        return Err("GHOST_BTCR_BENEFICIARY must be a 32-byte Ed25519 public key".into());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let beneficiary = ed25519_dalek::VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| format!("beneficiary key is invalid: {e}"))?;

    let blinded = body
        .get("blinded")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "body must contain a \"blinded\" point (32-byte hex)".to_string())?;
    let receipt: Receipt = serde_json::from_value(
        body.get("receipt")
            .cloned()
            .ok_or_else(|| "body must contain a \"receipt\" object".to_string())?,
    )
    .map_err(|e| format!("receipt is malformed: {e}"))?;

    if let Err(e) = btcr::verify_receipt(&receipt, &beneficiary) {
        btcr::record_rejected_receipt();
        return Err(e);
    }
    // The issuer lives in the node's private identity; the caller's fingerprint
    // is not an input anywhere in this derivation.
    let issuer = Issuer::from_identity_seed(identity_seed);
    let now = super::now_secs();
    let bucket = Bucket {
        day: btcr::bucket_day(now),
        tier: btcr::tier_for(receipt.work_bytes),
    };
    let (eval, dleq) = issuer
        .evaluate(blinded, bucket.day, bucket.tier)
        .inspect_err(|_| btcr::record_rejected_receipt())?;
    // Only claim the receipt once the request is known to be well-formed; a
    // malformed body must not burn a unit of work.
    btcr::redeem_receipt(&receipt)?;
    btcr::record_issue();
    Ok(json!({
        "success": true,
        "issuer": issuer.public_hex_for(bucket.day, bucket.tier),
        "eval": eval,
        "dleq": dleq,
        "bucket": { "day": bucket.day, "tier": bucket.tier },
        "work_bytes": btcr::tier_bytes(bucket.tier),
        "expires_at": btcr::expiry_for_day(bucket.day),
        "algorithm": "ristretto255-voprf+dleq+bucket-keys",
        "note": "unblind E with your blinding factor; the node never saw the input",
    }))
}

/// `POST /api/v2/btcr/spend` — verify and spend a bearer ticket once.
pub fn btcr_spend(body: &Value, identity_seed: &[u8; 32]) -> Result<Value, String> {
    let encoded = body
        .get("ticket")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "body must contain an encoded \"ticket\"".to_string())?;
    let ticket = Ticket::decode(encoded)?;
    let issuer = Issuer::from_identity_seed(identity_seed);
    btcr::spend(&issuer, &ticket, super::now_secs())?;
    Ok(json!({
        "success": true,
        "spent": true,
        "work_bytes": ticket.work_bytes,
        "nullifier": ticket.nullifier(),
        "ledger": btcr::snapshot(),
    }))
}

/// `POST /api/v2/fleet/invite` — render a `vb-fleet://` invite URI and SVG QR code
/// from a caller-supplied `root_pk` (hex) + `cert` JSON, or `seed` (32-byte hex) +
/// `device_pk` (32-byte hex) + `label`.
pub fn fleet_invite_qr(body: &Value) -> Result<Value, String> {
    let (root_pk, cert) = if let Some(uri) = body.get("uri").and_then(|v| v.as_str()) {
        super::fleet::decode_invite(uri)?
    } else {
        let seed_hex = body
            .get("root_seed")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                "body must contain \"uri\" or \"root_seed\" (32-byte hex)".to_string()
            })?;
        let seed_raw = hex::decode(seed_hex.trim()).map_err(|e| format!("root_seed hex: {e}"))?;
        let seed: [u8; 32] = seed_raw
            .try_into()
            .map_err(|_| "root_seed must be 32 bytes".to_string())?;
        let dev_hex = body
            .get("device_pk")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "body must contain \"device_pk\" (32-byte hex)".to_string())?;
        let dev_raw = hex::decode(dev_hex.trim()).map_err(|e| format!("device_pk hex: {e}"))?;
        let dev_pk: [u8; 32] = dev_raw
            .try_into()
            .map_err(|_| "device_pk must be 32 bytes".to_string())?;
        let label = body
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("device");
        let root = super::fleet::FleetRoot::from_seed(seed);
        super::fleet::configure_root_pk(root.public_key());
        let cert = root.issue(
            dev_pk,
            label,
            super::now_secs(),
            super::fleet::DEFAULT_CERT_TTL_SECS,
        );
        (root.public_key(), cert)
    };
    let uri = super::fleet::encode_invite(&root_pk, &cert)
        .ok_or_else(|| "failed to encode vb-fleet:// invite".to_string())?;
    let qr_svg = super::fleet::render_qr_svg(&uri)?;
    Ok(json!({
        "success": true,
        "fleet_id": super::fleet::fleet_id_for(&root_pk),
        "uri": uri,
        "qr_svg": qr_svg,
    }))
}

/// `POST /api/v2/fleet/revoke` — record a signed [`Revocation`] for mesh gossip.
pub fn fleet_revoke(body: &Value) -> Result<Value, String> {
    let root_hex = body
        .get("root_pk")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "body must contain \"root_pk\" (32-byte hex)".to_string())?;
    let root_raw = hex::decode(root_hex.trim()).map_err(|e| format!("root_pk hex: {e}"))?;
    let root_pk: [u8; 32] = root_raw
        .try_into()
        .map_err(|_| "root_pk must be 32 bytes".to_string())?;
    let rev_hex = body
        .get("revocation_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "body must contain \"revocation_hex\" (85-byte hex)".to_string())?;
    let rev_raw = hex::decode(rev_hex.trim()).map_err(|e| format!("revocation_hex: {e}"))?;
    let rev = super::fleet::Revocation::decode(&rev_raw)
        .ok_or_else(|| "revocation payload must be 85 valid bytes".to_string())?;
    if !super::fleet::record_revocation(rev, &root_pk) {
        return Err("revocation signature failed or was already recorded".into());
    }
    Ok(json!({
        "success": true,
        "fleet": super::fleet::status_json(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvis_endpoint_reports_unmeasured_without_a_radio_measurement() {
        let value = handle(&ApiState::default(), "GET /api/v2/nvis").unwrap();
        assert_eq!(value["claim"], "unmeasured");
        assert!(value["profile"].is_null());
        assert_eq!(value["bounds"]["cell_bytes"], 180);
    }

    #[test]
    fn xray_endpoint_uses_neff_domain_clustering() {
        // 400 addresses on one host are one anonymity bucket. The API must
        // report the failed population check, not the raw count.
        let state = ApiState {
            peers: 400,
            regime: Regime::Vantablack,
            witnesses: Witnesses {
                relay_population: Some(400),
                relay_domains: Some(vec![400]),
                cap_relay_verified: Some(400),
                ..Default::default()
            },
            ..Default::default()
        };
        let value = xray(&state);
        let population = value["invariants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == "relay_population")
            .expect("relay_population invariant is always reported");
        assert_eq!(population["state"], "failed");
        assert!(population["detail"].as_str().unwrap().contains("N_eff"));
        assert!(value["claim"].as_str().unwrap().contains("withheld"));
    }

    #[test]
    fn xray_endpoint_reflects_the_live_population() {
        let state = ApiState {
            peers: 4,
            regime: Regime::Vantablack,
            socks_port: 1080,
            transport: Some("quic".into()),
            exit_ip: None,
            node_fingerprint: "self".into(),
            ..Default::default()
        };
        let value = xray(&state);
        // Four peers with no circuit, no cover count and no domain grouping is
        // not evidence of anonymity: every witness is Unknown, never Verified.
        assert!(value["claim"].as_str().unwrap().contains("withheld"));
        assert!(value["headline"].as_str().unwrap().contains("unmeasured"));
        assert!(value["observations"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn the_identity_seed_is_never_printed() {
        let seed = NodeSecret::new([0xAB; 32]);
        assert_eq!(format!("{seed:?}"), "NodeSecret(<hidden>)");
        assert!(format!(
            "{:?}",
            ApiState {
                identity_seed: Some(seed),
                ..Default::default()
            }
        )
        .contains("NodeSecret(<hidden>)"));
    }

    #[test]
    fn regime_endpoint_lists_every_option() {
        let value = regime(&ApiState::default());
        assert_eq!(value["active"], "ghost");
        assert_eq!(value["options"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn dispatch_ignores_unknown_paths() {
        let state = ApiState::default();
        assert!(handle(&state, "GET /api/v2/xray HTTP/1.1").is_some());
        assert!(handle(&state, "GET /api/v2/regime HTTP/1.1").is_some());
        assert!(handle(&state, "GET /api/v2/capabilities HTTP/1.1").is_some());
        assert!(handle(&state, "GET /api/v2/home-exit HTTP/1.1").is_some());
        assert!(handle(&state, "GET /api/v2/btcr HTTP/1.1").is_some());
        assert!(handle(&state, "GET /api/v2/ladder HTTP/1.1").is_some());
        assert!(handle(&state, "GET /api/v2/racs HTTP/1.1").is_some());
        assert!(handle(&state, "GET /api/status HTTP/1.1").is_none());
    }

    #[test]
    fn applying_a_bad_regime_is_refused() {
        assert!(apply_regime(&json!({"regime": "anon"})).is_err());
        assert!(apply_regime(&json!({})).is_err());
    }
}
