//! JSON surface for the v2 features, consumed by the dashboard and by
//! `ggn xray`.
//!
//! Everything here is a pure function of [`ApiState`] so the control-center
//! handler stays a two-line dispatch and this module can be tested without a
//! socket. The state is deliberately small: only fields the node can actually
//! measure are included, and anything absent becomes `Unknown` in the ledger
//! rather than a flattering default.

use serde_json::{json, Value};

use super::btcr::{self, Issuer, Receipt, Ticket};
use super::regime::{self, effective_policy, Regime};
use super::xray::{self, LedgerInput};

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
        }
    }
}

fn ledger_input(state: &ApiState) -> LedgerInput {
    let connected = state.peers > 0;
    LedgerInput {
        regime: Some(state.regime),
        public_relays: Some(state.peers),
        circuit_hops: connected.then(|| state.regime.hops().hops()),
        circuit_asns: None,
        transport: state.transport.clone(),
        outer_sni: None,
        exit_ip: state.exit_ip.clone(),
        cover_traffic: state.regime.cover_traffic() && connected,
        dns_leak: None,
        // The hybrid handshake is mandatory in this build: a session cannot be
        // established without it, so a live session is direct evidence.
        pq_hybrid: connected.then_some(true),
        clock_consistent: None,
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
                "capability": "boomerang_guard_middle_home_circuit",
                "reason": "runtime three-hop assembly is not implemented; home-exit selection pins the exit on the direct path",
            },
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
        "/api/v2/btcr" => Some(btcr::status_json(&state.node_fingerprint)),
        "/api/v2/ladder" => Some(super::continuum::status_json()),
        "/api/v2/racs" => Some(super::racs::status_json()),
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
    let parsed = Regime::parse(raw).ok_or_else(|| {
        format!("{raw:?} is not one of fast, shielded, ghost, vantablack")
    })?;
    let path = regime::config_path();
    regime::save_persisted(&path, parsed).map_err(|e| format!("cannot save {}: {e}", path.display()))?;
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
pub fn btcr_issue(body: &Value, fingerprint: &str) -> Result<Value, String> {
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
    let issuer = Issuer::for_node(fingerprint);
    let (eval, dleq) = issuer
        .evaluate(blinded)
        .inspect_err(|_| btcr::record_rejected_receipt())?;
    btcr::record_issue();
    Ok(json!({
        "success": true,
        "issuer": issuer.public_hex(),
        "eval": eval,
        "dleq": dleq,
        "work_bytes": receipt.work_bytes,
        "expires_at": super::now_secs() + btcr::DEFAULT_TICKET_TTL_SECS,
        "algorithm": "ristretto255-voprf+dleq",
        "note": "unblind E with your blinding factor; the node never saw the input",
    }))
}

/// `POST /api/v2/btcr/spend` — verify and spend a bearer ticket once.
pub fn btcr_spend(body: &Value, fingerprint: &str) -> Result<Value, String> {
    let encoded = body
        .get("ticket")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "body must contain an encoded \"ticket\"".to_string())?;
    let ticket = Ticket::decode(encoded)?;
    let issuer = Issuer::for_node(fingerprint);
    btcr::spend(&issuer, &ticket, super::now_secs())?;
    Ok(json!({
        "success": true,
        "spent": true,
        "work_bytes": ticket.work_bytes,
        "nullifier": ticket.nullifier(),
        "ledger": btcr::snapshot(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_endpoint_reflects_the_live_population() {
        let state = ApiState {
            peers: 4,
            regime: Regime::Vantablack,
            socks_port: 1080,
            transport: Some("quic".into()),
            exit_ip: None,
            node_fingerprint: "self".into(),
        };
        let value = xray(&state);
        assert!(value["claim"].as_str().unwrap().contains("withheld"));
        assert!(value["headline"].as_str().unwrap().contains("failing"));
        assert!(value["observations"].as_array().unwrap().len() >= 3);
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
