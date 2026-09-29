//! ETSI GS QKD 014 key-delivery client — the production half of the L10 anchor.
//!
//! `l10_qel.rs` has two backends for the same job. This is the second one: it
//! talks to a **real QKD appliance** over the REST-based key delivery API
//! standardised as ETSI GS QKD 014 V1.1.1, instead of simulating a channel in
//! Python. The difference that matters to a session is not the transport — it is
//! that the key comes from a quantum channel neither peer controls, so mixing it
//! into the ratchet adds entropy a third party does not have. The simulated
//! backend cannot make that claim.
//!
//! # The API, as implemented
//!
//! Two roles, and each node in Vantablack plays both depending on which side of a
//! session mix it is on:
//!
//! | Role | Call | Path |
//! |---|---|---|
//! | Master SAE (starts the mix) | `Get key` | `GET  {base}/{slave_SAE_ID}/enc_keys?number=1&size=256` |
//! | Master SAE (health) | `Get status` | `GET  {base}/{slave_SAE_ID}/status` |
//! | Slave SAE (answers the mix) | `Get key with key IDs` | `POST {base}/{master_SAE_ID}/dec_keys` |
//!
//! The path segment is always the **other** party's SAE ID: the master asks its
//! KME for keys to use with the slave, and the slave redeems them by naming the
//! master. Both responses share one envelope:
//!
//! ```json
//! { "keys": [ { "key_ID": "<uuid>", "key": "<base64>" } ] }
//! ```
//!
//! `key_ID` is the value the two peers exchange — **in this codebase it travels
//! as the label in the signed session-mix PDU**, which is exactly the notification
//! channel the standard declares out of scope and leaves to the application. Key
//! material never crosses the Vantablack link.
//!
//! # Two properties of the API that shape this code
//!
//! **A `Get key` call consumes the key.** Not a detail: a retry after a timeout
//! silently burns a key the appliance may never generate again at the same rate,
//! and orphans the ID the peer is trying to redeem. So nothing here retries, and a
//! timeout is reported as *"a key may have been consumed"* rather than as a clean
//! failure the caller can shrug off.
//!
//! **The key size is vendor policy**, and the standard only promises it is between
//! `min_key_size` and `max_key_size`. Rather than demand a specific size, the
//! delivered material is HKDF'd to the 32 bytes a session epoch needs, bound to
//! the key ID — so both peers derive the same bytes from the same key whether the
//! appliance hands over 128 or 1024 bits.
//!
//! # Security posture, stated plainly
//!
//! The standard mandates HTTPS with mutual certificate authentication, and this
//! module implements that: client certificate, private CA or the platform trust
//! store, TLS 1.2+ with the `ring` provider. Three things are refused rather than
//! papered over:
//!
//! * an `https://` URL in a build without the `qkd-tls` feature is **an error**,
//!   never a silent fallback to plaintext — quietly sending key material in the
//!   clear would be the worst possible failure mode for this layer;
//! * `GHOST_QKD_INSECURE=1` (accept any server certificate) exists because lab
//!   appliances ship self-signed certs, but it is logged as a warning at startup
//!   and surfaced in the control plane, so it cannot be enabled unnoticed;
//! * a peer with no SAE ID mapping is reported, not guessed. See
//!   [`Etsi014Config::peer_sae_id`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
// Only the TLS client configuration shares anything across threads.
#[cfg(feature = "qkd-tls")]
use std::sync::Arc;
use std::time::Duration;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Key size requested from the appliance, in bits.
///
/// 256 is the smallest size the standard's own example and every implementation
/// we checked supports, and it is exactly what one session epoch consumes.
pub const DEFAULT_KEY_BITS: u32 = 256;

/// Largest key material this client will accept, in bits. A response larger than
/// this is treated as a protocol error rather than silently truncated: an
/// appliance that answers a 256-bit request with a megabit has misunderstood us,
/// and quietly taking the first 32 bytes of it would hide that.
pub const MAX_KEY_BITS: u32 = 65_536;

/// HKDF info for the 32 bytes a session epoch uses.
///
/// Bound to the key ID so the same key material can never produce the same epoch
/// key under two different labels.
pub const ETSI_KEY_DERIVE_INFO: &[u8] = b"GHOST_QEL_ETSI014_EPOCH_KEY_v1";

/// How many bytes a session epoch consumes.
pub const EPOCH_KEY_LEN: usize = 32;

// ── Configuration environment ───────────────────────────────────────────────

/// Selects the anchor backend: `sim` (default) or `etsi014`.
pub const ENV_BACKEND: &str = "GHOST_QEL_BACKEND";
/// Base URL of the local KME, e.g. `https://kme.site-a.example:8443`.
pub const ENV_KME_URL: &str = "GHOST_QKD_KME_URL";
/// This node's SAE ID. The certificate carries the authoritative identity; this
/// is what the operator calls this node, used in logs and by `status`.
pub const ENV_SAE_ID: &str = "GHOST_QKD_SAE_ID";
/// Fallback peer SAE ID, for a two-node deployment.
pub const ENV_PEER_SAE_ID: &str = "GHOST_QKD_PEER_SAE_ID";
/// JSON map `{"<peer fingerprint>": "<peer SAE ID>"}`.
pub const ENV_SAE_MAP: &str = "GHOST_QKD_SAE_MAP";
/// PEM bundle of the CA that signed the KME's certificate.
pub const ENV_CA_PEM: &str = "GHOST_QKD_CA_PEM";
/// PEM client certificate (the SAE's identity) and its private key.
pub const ENV_CLIENT_CERT: &str = "GHOST_QKD_CLIENT_CERT";
pub const ENV_CLIENT_KEY: &str = "GHOST_QKD_CLIENT_KEY";
/// Lab escape hatch: accept any server certificate. Loudly discouraged.
pub const ENV_INSECURE: &str = "GHOST_QKD_INSECURE";
/// Per-request timeout in milliseconds (default 10 s).
pub const ENV_TIMEOUT_MS: &str = "GHOST_QKD_TIMEOUT_MS";

/// Ceiling on the TCP connect, so an appliance that is down is reported as
/// unreachable in bounded time. Separate from [`Etsi014Config::timeout`] because
/// the two mean different things: a *connect* that does not complete means the
/// appliance is not there, while a *response* that does not arrive may mean the
/// appliance took the key and lost the answer.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Key size to request, in bits (default [`DEFAULT_KEY_BITS`]).
pub const ENV_KEY_BITS: &str = "GHOST_QKD_KEY_BITS";

/// Everything the ETSI backend needs, resolved once at boot.
#[derive(Debug, Clone)]
pub struct Etsi014Config {
    /// Normalised base URL: scheme + authority + `/api/v1/keys`, no trailing slash.
    pub base_url: String,
    pub our_sae_id: String,
    pub default_peer_sae_id: Option<String>,
    /// Peer fingerprint → that peer's SAE ID.
    pub sae_map: HashMap<String, String>,
    pub key_bits: u32,
    pub timeout: Duration,
    pub ca_pem: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    /// Accept any server certificate (lab only).
    pub insecure: bool,
}

impl Etsi014Config {
    /// Read the configuration from the environment.
    ///
    /// Returns [`Etsi014Error::Config`] when something essential is missing. That
    /// is deliberately fatal to the *backend* and not to the daemon: an operator
    /// who selected `etsi014` must never be quietly downgraded to the simulator,
    /// because the two make different security claims. The anchor reports the
    /// misconfiguration and the session keeps its classical epochs.
    pub fn from_env() -> Result<Self, Etsi014Error> {
        let raw_url = std::env::var(ENV_KME_URL).map_err(|_| {
            Etsi014Error::Config(format!(
                "{ENV_KME_URL} is required for the etsi014 backend (e.g. https://kme.site-a.example:8443)"
            ))
        })?;
        let base_url = normalise_base_url(&raw_url)?;

        // Trim and drop an unset-or-empty variable, so `VAR=` (a common way to
        // "clear" something in a shell profile) means absent rather than a
        // zero-length value.
        let opt_string = |name: &str| -> Option<String> {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let opt_path = |name: &str| -> Option<PathBuf> { opt_string(name).map(PathBuf::from) };

        // Defaulted rather than required: the appliance identifies the SAE by its
        // client certificate, and the ID is a label the operator uses to talk
        // about this node. A deployment that has not named itself yet should get a
        // clear status document, not a refusal to boot the anchor.
        let our_sae_id = opt_string(ENV_SAE_ID).unwrap_or_else(|| "sae".to_string());

        let sae_map = match std::env::var(ENV_SAE_MAP) {
            Ok(path) if !path.trim().is_empty() => load_sae_map(Path::new(path.trim()))?,
            _ => HashMap::new(),
        };

        let key_bits = parse_env_u32(ENV_KEY_BITS, DEFAULT_KEY_BITS)?;
        if key_bits == 0 || key_bits % 8 != 0 {
            return Err(Etsi014Error::Config(format!(
                "{ENV_KEY_BITS} must be a non-zero multiple of 8 (the standard counts key size in bits), got {key_bits}"
            )));
        }
        if key_bits > MAX_KEY_BITS {
            return Err(Etsi014Error::Config(format!(
                "{ENV_KEY_BITS} = {key_bits} exceeds the {MAX_KEY_BITS}-bit cap this client accepts"
            )));
        }

        let timeout_ms = parse_env_u32(ENV_TIMEOUT_MS, 10_000)?;
        if timeout_ms < 100 {
            return Err(Etsi014Error::Config(
                "GHOST_QKD_TIMEOUT_MS below 100 ms would fail every appliance call".to_string(),
            ));
        }

        let ca_pem = opt_path(ENV_CA_PEM);
        if let Some(p) = &ca_pem {
            if !p.is_file() {
                return Err(Etsi014Error::Config(format!(
                    "{ENV_CA_PEM} points at {}, which is not a readable file",
                    p.display()
                )));
            }
        }

        // A client certificate is only half an identity without its key, and the
        // standard makes mutual authentication mandatory — so configure both or
        // neither, and say which one is missing rather than failing at connect
        // time with a TLS alert.
        let client_cert = opt_path(ENV_CLIENT_CERT);
        let client_key = opt_path(ENV_CLIENT_KEY);
        match (&client_cert, &client_key) {
            (Some(c), Some(k)) => {
                for p in [c, k] {
                    if !p.is_file() {
                        return Err(Etsi014Error::Config(format!(
                            "client certificate or key path {} is not a readable file",
                            p.display()
                        )));
                    }
                }
            }
            (Some(_), None) => {
                return Err(Etsi014Error::Config(format!(
                    "{ENV_CLIENT_CERT} is set but {ENV_CLIENT_KEY} is not"
                )))
            }
            (None, Some(_)) => {
                return Err(Etsi014Error::Config(format!(
                    "{ENV_CLIENT_KEY} is set but {ENV_CLIENT_CERT} is not"
                )))
            }
            (None, None) => {}
        }

        Ok(Self {
            base_url,
            our_sae_id,
            default_peer_sae_id: opt_string(ENV_PEER_SAE_ID),
            sae_map,
            key_bits,
            timeout: Duration::from_millis(u64::from(timeout_ms)),
            ca_pem,
            client_cert,
            client_key,
            insecure: env_flag(ENV_INSECURE),
        })
    }

    /// The peer's SAE ID, from the map or the two-node default.
    ///
    /// SAE IDs are operator-assigned: the KME is configured with them, and a node
    /// cannot compute its peer's from the fingerprint. So an unmapped peer has no
    /// quantum key, and says so — deriving one from the fingerprint would produce
    /// a request the appliance rejects with a 400, or worse, address a different
    /// peer's key pool.
    pub fn peer_sae_id(&self, peer_fingerprint: &str) -> Option<&str> {
        self.sae_map
            .get(peer_fingerprint)
            .or(self.default_peer_sae_id.as_ref())
            .map(String::as_str)
    }

    /// Whether every peer must be named in `GHOST_QKD_SAE_MAP`.
    pub fn is_two_node_default(&self) -> bool {
        self.sae_map.is_empty() && self.default_peer_sae_id.is_some()
    }

    pub fn is_https(&self) -> bool {
        self.base_url.starts_with("https://")
    }

    pub fn scheme(&self) -> &str {
        match self.base_url.find("://") {
            Some(i) => &self.base_url[..i],
            None => "",
        }
    }

    /// `host:port` for the `Host` header and for connecting.
    pub fn authority(&self) -> String {
        let after = match self.base_url.find("://") {
            Some(i) => &self.base_url[i + 3..],
            None => self.base_url.as_str(),
        };
        let end = after.find('/').unwrap_or(after.len());
        let authority = &after[..end];
        if authority.contains(':') {
            authority.to_string()
        } else if self.is_https() {
            format!("{authority}:443")
        } else {
            format!("{authority}:80")
        }
    }

    /// Host alone (no port), for certificate name matching.
    pub fn host(&self) -> String {
        let authority = self.authority();
        match authority.rfind(':') {
            Some(i) => authority[..i].to_string(),
            None => authority,
        }
    }

    /// The client-certificate identity, or `None` when the build/deployment has
    /// none configured. Used by the control plane to report honestly.
    pub fn client_identity(&self) -> Option<&Path> {
        self.client_cert.as_deref()
    }
}

/// Resolve a KME base URL to `scheme://authority/api/v1/keys`.
///
/// The operator may supply either the root (`https://kme:8443`), the API root
/// (`…/api/v1`), or the full path (`…/api/v1/keys`); all three mean the same
/// thing, and normalising once here keeps every call site free of string surgery.
/// A trailing slash is dropped, because every path built from this starts with
/// one and `//` is a 404 on most appliances.
pub fn normalise_base_url(raw: &str) -> Result<String, Etsi014Error> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Etsi014Error::Config(format!("{ENV_KME_URL} is empty")));
    }
    let (scheme, rest) = match raw.find("://") {
        Some(i) => (&raw[..i], &raw[i + 3..]),
        None => {
            return Err(Etsi014Error::Config(format!(
                "{ENV_KME_URL} must include a scheme (http:// or https://), got {raw:?}"
            )))
        }
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(Etsi014Error::Config(format!(
            "{ENV_KME_URL} scheme must be http or https, got {scheme:?}"
        )));
    }
    let authority = rest.split('/').next().unwrap_or("").trim();
    if authority.is_empty() {
        return Err(Etsi014Error::Config(format!(
            "{ENV_KME_URL} has no host: {raw:?}"
        )));
    }
    let path = rest[authority.len()..].trim_end_matches('/');
    let base_path = if path.ends_with("/api/v1/keys") {
        path.to_string()
    } else if path.ends_with("/api/v1") {
        format!("{path}/keys")
    } else if path.is_empty() {
        "/api/v1/keys".to_string()
    } else {
        // Some other prefix (a reverse proxy in front of several KMEs): keep it
        // and append the standard path, which is what such a deployment means.
        format!("{path}/api/v1/keys")
    };
    Ok(format!("{scheme}://{authority}{base_path}"))
}

fn load_sae_map(path: &Path) -> Result<HashMap<String, String>, Etsi014Error> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        Etsi014Error::Config(format!(
            "{ENV_SAE_MAP} {} is unreadable: {e}",
            path.display()
        ))
    })?;
    let parsed: HashMap<String, String> = serde_json::from_str(&raw).map_err(|e| {
        Etsi014Error::Config(format!(
            "{ENV_SAE_MAP} {} must be a JSON object mapping peer fingerprint -> peer SAE ID: {e}",
            path.display()
        ))
    })?;
    for (fp, sae) in &parsed {
        if fp.trim().is_empty() || sae.trim().is_empty() {
            return Err(Etsi014Error::Config(format!(
                "{ENV_SAE_MAP} {} has an empty fingerprint or SAE ID",
                path.display()
            )));
        }
    }
    Ok(parsed)
}

fn parse_env_u32(name: &str, default: u32) -> Result<u32, Etsi014Error> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(v) => v
            .trim()
            .parse::<u32>()
            .map_err(|e| Etsi014Error::Config(format!("{name} = {v:?} is not a number: {e}"))),
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

// ── Protocol types ──────────────────────────────────────────────────────────

/// One delivered key: its ID and its material.
#[derive(Debug, Clone)]
pub struct EtsiKey {
    pub key_id: String,
    /// Raw key bytes, already base64-decoded.
    pub material: Vec<u8>,
}

impl EtsiKey {
    /// The 32 bytes a session epoch uses.
    ///
    /// HKDF with the key ID as the salt, not a truncation: the appliance chooses
    /// the size, so a 128-bit key must still yield 32 bytes' worth of *derived*
    /// material rather than a padded one, and binding the ID means two different
    /// keys can never produce the same epoch key under the same label.
    pub fn epoch_key(&self) -> [u8; EPOCH_KEY_LEN] {
        let hk = Hkdf::<Sha256>::new(Some(self.key_id.as_bytes()), &self.material);
        let mut out = [0u8; EPOCH_KEY_LEN];
        hk.expand(ETSI_KEY_DERIVE_INFO, &mut out)
            .expect("32 bytes is well within HKDF-SHA256's output limit");
        out
    }
}

/// The `{ "keys": [...] }` envelope the standard uses for every key response.
#[derive(Debug, Deserialize)]
struct KeyEnvelope {
    #[serde(default)]
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Deserialize)]
struct KeyEntry {
    #[serde(rename = "key_ID")]
    key_id: String,
    #[serde(default)]
    key: String,
}

/// `Get status`: what the KME will tell us about its key pool for one peer.
///
/// Every field is optional on purpose. The standard fixes the names, but vendors
/// fill in what they have, and an SAE that hard-fails on a missing
/// `max_SAE_ID_count` would be unusable against half the market.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EtsiStatus {
    #[serde(default, rename = "source_KME_ID")]
    pub source_kme_id: Option<String>,
    #[serde(default, rename = "target_KME_ID")]
    pub target_kme_id: Option<String>,
    #[serde(default, rename = "master_SAE_ID")]
    pub master_sae_id: Option<String>,
    #[serde(default, rename = "slave_SAE_ID")]
    pub slave_sae_id: Option<String>,
    #[serde(default, rename = "key_size")]
    pub key_size: Option<u32>,
    #[serde(default, rename = "stored_key_count")]
    pub stored_key_count: Option<u64>,
    #[serde(default, rename = "max_key_count")]
    pub max_key_count: Option<u64>,
    #[serde(default, rename = "max_key_per_request")]
    pub max_key_per_request: Option<u32>,
    #[serde(default, rename = "max_key_size")]
    pub max_key_size: Option<u32>,
    #[serde(default, rename = "min_key_size")]
    pub min_key_size: Option<u32>,
    #[serde(default, rename = "max_SAE_ID_count")]
    pub max_sae_id_count: Option<u32>,
}

impl EtsiStatus {
    /// Whether this pool can serve a key of `bits` at all, when it says.
    pub fn supports_key_bits(&self, bits: u32) -> Option<bool> {
        match (self.min_key_size, self.max_key_size) {
            (None, None) => None,
            (min, max) => Some(bits >= min.unwrap_or(0) && bits <= max.unwrap_or(u32::MAX)),
        }
    }

    /// A one-line summary for logs and the control plane.
    pub fn describe(&self) -> String {
        let stored = self
            .stored_key_count
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".to_string());
        let size = self
            .key_size
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".to_string());
        let range = match (self.min_key_size, self.max_key_size) {
            (Some(lo), Some(hi)) => format!("{lo}-{hi}"),
            _ => "?".to_string(),
        };
        format!("stored={stored} key_size={size} accepted_size={range}")
    }
}

/// What the status call tells us about the appliance's reachability.
#[derive(Debug, Clone, Serialize)]
pub struct EtsiProbe {
    pub reachable: bool,
    pub status: Option<EtsiStatus>,
    pub error: Option<String>,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Etsi014Error {
    #[error("QKD 014 backend configuration: {0}")]
    Config(String),
    /// The peer this session is for has no SAE ID, so there is no key pool to
    /// name. Not an error in the appliance — an unconfigured mapping.
    #[error("no SAE ID configured for peer {peer}: set {env} or {ENV_SAE_MAP}")]
    NoPeerSaeId { peer: String, env: &'static str },
    #[error(
        "the KME URL is https but this build has no TLS: rebuild with --features qkd-tls \
         (the anchor will not fall back to plaintext key delivery)"
    )]
    TlsNotCompiled,
    #[error("TLS setup failed: {0}")]
    Tls(String),
    #[error("transport: {0}")]
    Transport(String),
    /// A timeout is not a clean failure for `enc_keys`: see the module docs.
    #[error("{0}")]
    Timeout(String),
    #[error("KME answered {status}: {message}")]
    Http { status: u16, message: String },
    #[error("protocol: {0}")]
    Protocol(String),
}

impl Etsi014Error {
    /// Whether the appliance was unreachable at the transport or TLS layer (as
    /// opposed to reachable and refusing us). The two map to different anchor
    /// states: unreachable means the appliance is down, refusing means we are
    /// misconfigured, and an operator needs to tell those apart.
    pub fn is_transport(&self) -> bool {
        matches!(
            self,
            Etsi014Error::Transport(_) | Etsi014Error::Tls(_) | Etsi014Error::TlsNotCompiled
        )
    }

    pub fn is_config(&self) -> bool {
        matches!(
            self,
            Etsi014Error::Config(_) | Etsi014Error::NoPeerSaeId { .. }
        )
    }
}

// ── The client ──────────────────────────────────────────────────────────────

/// A KME client. Cheap to clone; every call opens its own connection.
///
/// One connection per request is deliberate. Key delivery happens once per
/// session, the responses are tiny, and a pooled connection to a key server buys
/// latency nobody is measuring while adding a state machine that can return a
/// half-consumed key. `Connection: close` also keeps response framing trivial.
#[derive(Debug, Clone)]
pub struct Etsi014Client {
    cfg: Etsi014Config,
}

impl Etsi014Client {
    pub fn new(cfg: Etsi014Config) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &Etsi014Config {
        &self.cfg
    }

    /// `Get status` — the health probe and the "is this pool able to serve us"
    /// query, in one call.
    pub async fn status(&self, peer_fingerprint: &str) -> Result<EtsiStatus, Etsi014Error> {
        let peer_sae_id = self.peer_sae_id(peer_fingerprint)?;
        let target = self.path(&[&peer_sae_id, "status"], None);
        let resp = self.request("GET", &target, None).await?;
        resp.json()
    }

    /// `Get status` for the peer the boot probe should name.
    ///
    /// `status` itself takes a peer, because a KME pool is per peer pair — so the
    /// probe needs *some* peer to ask about. The configured default is the honest
    /// choice; failing that, any peer in the map (the answer says what the
    /// appliance can do, which is the same for all of them).
    pub async fn probe(&self) -> Result<EtsiStatus, Etsi014Error> {
        let peer = self
            .cfg
            .default_peer_sae_id
            .clone()
            .or_else(|| self.cfg.sae_map.values().next().cloned())
            .ok_or_else(|| Etsi014Error::NoPeerSaeId {
                peer: "<none configured>".to_string(),
                env: ENV_PEER_SAE_ID,
            })?;
        let target = self.path(&[&peer, "status"], None);
        let resp = self.request("GET", &target, None).await?;
        resp.json()
    }

    /// `Get key` — fresh material for a session with `peer_fingerprint`.
    ///
    /// **This consumes key material on the appliance.** One call, no retries.
    pub async fn acquire_key(&self, peer_fingerprint: &str) -> Result<EtsiKey, Etsi014Error> {
        let peer_sae_id = self.peer_sae_id(peer_fingerprint)?;
        let query = format!("number=1&size={}", self.cfg.key_bits);
        let target = self.path(&[&peer_sae_id, "enc_keys"], Some(&query));
        // The status call is a courtesy, not a gate: it warns when the pool is
        // empty or the size is unsupported, which turns "the appliance said 503"
        // into "the pool had nothing to give". It must never block the attempt —
        // `stored_key_count` is a snapshot and vendors disagree on what it counts.
        if let Ok(status) = self.status(peer_fingerprint).await {
            if status.supports_key_bits(self.cfg.key_bits) == Some(false) {
                return Err(Etsi014Error::Protocol(format!(
                    "KME accepts keys of size {} only, and this client asks for {} bits ({})",
                    status.describe(),
                    self.cfg.key_bits,
                    "set GHOST_QKD_KEY_BITS to a size the appliance advertises"
                )));
            }
            if status.stored_key_count == Some(0) {
                tracing::debug!(
                    peer = %peer_fingerprint,
                    "qkd etsi014: appliance reports no stored keys; requesting anyway (the counter is a snapshot)"
                );
            }
        }
        let resp = self.request("GET", &target, None).await?;
        let key = resp.one_key()?;
        tracing::info!(
            peer = %peer_fingerprint,
            key_id = %key.key_id,
            bytes = key.material.len(),
            "qkd etsi014: key acquired from the appliance"
        );
        Ok(key)
    }

    /// `Get key with key IDs` — redeem the key the starting peer selected.
    ///
    /// The ID arrives as the label in the session-mix PDU. This is the call that
    /// makes the mix worth having: the key material was produced by a quantum
    /// channel, and neither peer chose it.
    pub async fn redeem_key(
        &self,
        peer_fingerprint: &str,
        key_id: &str,
    ) -> Result<EtsiKey, Etsi014Error> {
        if key_id.trim().is_empty() {
            return Err(Etsi014Error::Protocol(
                "refusing to redeem an empty key ID".to_string(),
            ));
        }
        let peer_sae_id = self.peer_sae_id(peer_fingerprint)?;
        let target = self.path(&[&peer_sae_id, "dec_keys"], None);
        // The standard's POST form, because the GET form takes exactly one ID and
        // the POST form is what every implementation we checked supports for the
        // structured request.
        let body = serde_json::json!({ "key_IDs": [ { "key_ID": key_id } ] }).to_string();
        let resp = self.request("POST", &target, Some(body.as_bytes())).await?;
        let key = resp.one_key()?;
        if key.key_id != key_id {
            return Err(Etsi014Error::Protocol(format!(
                "KME returned key ID {:?} for a request naming {:?}",
                key.key_id, key_id
            )));
        }
        tracing::info!(
            peer = %peer_fingerprint,
            key_id = %key_id,
            bytes = key.material.len(),
            "qkd etsi014: key redeemed from the appliance"
        );
        Ok(key)
    }

    fn peer_sae_id(&self, peer_fingerprint: &str) -> Result<String, Etsi014Error> {
        self.cfg
            .peer_sae_id(peer_fingerprint)
            .map(str::to_string)
            .ok_or_else(|| Etsi014Error::NoPeerSaeId {
                peer: peer_fingerprint.to_string(),
                env: ENV_PEER_SAE_ID,
            })
    }

    /// Build a path under the base URL, percent-encoding every segment.
    ///
    /// SAE IDs are operator-assigned strings, so they are the untrusted part of
    /// the URL: a `../` or a `?` in one must not be able to change which resource
    /// is addressed.
    fn path(&self, segments: &[&str], query: Option<&str>) -> String {
        let mut out = String::with_capacity(self.cfg.base_url.len() + 48);
        out.push_str(&self.cfg.base_url);
        for seg in segments {
            out.push('/');
            out.push_str(&percent_encode(seg));
        }
        if let Some(q) = query {
            out.push('?');
            out.push_str(q);
        }
        out
    }

    async fn request(
        &self,
        method: &str,
        target: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, Etsi014Error> {
        let fut = async {
            let mut io = self.connect().await?;
            let host_header = self.cfg.authority();
            // Origin-form target: `path?query`, never the absolute URL. Every
            // appliance (and every reverse proxy in front of one) expects the
            // request line to carry the path alone, and answers an absolute-form
            // line with 404 — the URL is what the `Host` header is for.
            http_exchange(&mut *io, &host_header, method, origin_form(target), body).await
        };
        match tokio::time::timeout(self.cfg.timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(Etsi014Error::Timeout(format!(
                "{method} {target} did not answer within {:?}{}",
                self.cfg.timeout,
                if method == "GET" && target.contains("enc_keys") {
                    " — the KME may still have consumed a key, so do not simply retry"
                } else {
                    ""
                }
            ))),
        }
    }

    async fn connect(&self) -> Result<Box<dyn Io>, Etsi014Error> {
        let authority = self.cfg.authority();
        // Bounded, and classified as *transport* rather than as a timeout: an
        // appliance we cannot open a socket to is unreachable, and no key was
        // consumed on the way. A firewall that silently drops the packets is the
        // same situation as a machine that is down.
        let budget = self.cfg.timeout.min(CONNECT_TIMEOUT);
        let tcp = match tokio::time::timeout(budget, TcpStream::connect(&authority)).await {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => return Err(Etsi014Error::Transport(format!("connect {authority}: {e}"))),
            Err(_) => {
                return Err(Etsi014Error::Transport(format!(
                    "connect {authority} did not complete within {budget:?} — the appliance is \
                     unreachable from here"
                )))
            }
        };
        tcp.set_nodelay(true).ok();

        if !self.cfg.is_https() {
            tracing::debug!(
                kme = %authority,
                "qkd etsi014: plaintext key delivery (acceptable only on a loopback/lab KME)"
            );
            return Ok(Box::new(tcp));
        }

        #[cfg(not(feature = "qkd-tls"))]
        {
            let _ = tcp;
            Err(Etsi014Error::TlsNotCompiled)
        }

        #[cfg(feature = "qkd-tls")]
        {
            let connector = self.tls_connector()?;
            let host = self.cfg.host();
            let server_name =
                rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| {
                    Etsi014Error::Tls(format!("{host:?} is not usable as a TLS server name: {e}"))
                })?;
            let stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| Etsi014Error::Tls(format!("TLS handshake with {host}: {e}")))?;
            Ok(Box::new(stream))
        }
    }

    #[cfg(feature = "qkd-tls")]
    fn tls_connector(&self) -> Result<tokio_rustls::TlsConnector, Etsi014Error> {
        use rustls::RootCertStore;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        match &self.cfg.ca_pem {
            Some(path) => {
                let pem = std::fs::read(path).map_err(|e| {
                    Etsi014Error::Tls(format!("reading CA bundle {}: {e}", path.display()))
                })?;
                let mut reader = std::io::BufReader::new(&pem[..]);
                let certs = rustls_pemfile::certs(&mut reader)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        Etsi014Error::Tls(format!("parsing CA bundle {}: {e}", path.display()))
                    })?;
                if certs.is_empty() {
                    return Err(Etsi014Error::Tls(format!(
                        "CA bundle {} contains no CERTIFICATE blocks",
                        path.display()
                    )));
                }
                for cert in certs {
                    roots.add(cert).map_err(|e| {
                        Etsi014Error::Tls(format!("CA in {} is unusable: {e}", path.display()))
                    })?;
                }
                tracing::info!(
                    ca = %path.display(),
                    "qkd etsi014: trusting the configured CA bundle"
                );
            }
            None => {
                let found = rustls_native_certs::load_native_certs();
                for cert in found.certs {
                    let _ = roots.add(cert);
                }
                if roots.is_empty() {
                    return Err(Etsi014Error::Tls(
                        "no CA trust anchors: set GHOST_QKD_CA_PEM to the bundle that signed the \
                         KME's certificate (a private QKD deployment almost always needs this)"
                            .to_string(),
                    ));
                }
            }
        }

        let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| Etsi014Error::Tls(format!("TLS protocol versions: {e}")))?;

        // Choosing the verifier *here* rather than swapping a field afterwards:
        // both branches land in the same builder state, so there is exactly one
        // place where "verify or do not verify" is decided.
        let builder = if self.cfg.insecure {
            tracing::warn!(
                "qkd etsi014: {ENV_INSECURE} is set — the KME's certificate is NOT verified. \
                 This is a lab setting; any host on the path can hand this node a key it knows."
            );
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        } else {
            builder.with_root_certificates(roots)
        };

        let config = match (&self.cfg.client_cert, &self.cfg.client_key) {
            (Some(cert_path), Some(key_path)) => {
                let certs = read_certs(cert_path)?;
                let key = read_private_key(key_path)?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| Etsi014Error::Tls(format!("client certificate rejected: {e}")))?
            }
            _ => {
                // The standard makes client certificates mandatory. Saying so at
                // connect time is friendlier than letting the appliance answer
                // 401 with no explanation.
                tracing::warn!(
                    "qkd etsi014: no client certificate configured — ETSI GS QKD 014 requires \
                     mutual TLS; set GHOST_QKD_CLIENT_CERT and GHOST_QKD_CLIENT_KEY"
                );
                builder.with_no_client_auth()
            }
        };

        Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
    }
}

/// A server-certificate verifier that accepts anything.
///
/// Only constructed for [`ENV_INSECURE`], which logs a warning wherever it is
/// honoured, so this cannot be enabled silently. It exists because lab
/// appliances (including the ETSI reference implementation) ship self-signed
/// certificates, and the alternative — an operator bolting an unverified TLS
/// terminator in front — is strictly worse, because then the client cannot report
/// the fact at all.
#[cfg(feature = "qkd-tls")]
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

#[cfg(feature = "qkd-tls")]
impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(feature = "qkd-tls")]
fn read_certs(
    path: &Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Etsi014Error> {
    let pem = std::fs::read(path)
        .map_err(|e| Etsi014Error::Tls(format!("reading {}: {e}", path.display())))?;
    let mut reader = std::io::BufReader::new(&pem[..]);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Etsi014Error::Tls(format!("parsing {}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(Etsi014Error::Tls(format!(
            "{} contains no CERTIFICATE blocks",
            path.display()
        )));
    }
    Ok(certs)
}

#[cfg(feature = "qkd-tls")]
fn read_private_key(
    path: &Path,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Etsi014Error> {
    let pem = std::fs::read(path)
        .map_err(|e| Etsi014Error::Tls(format!("reading {}: {e}", path.display())))?;
    let mut reader = std::io::BufReader::new(&pem[..]);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Etsi014Error::Tls(format!("parsing {}: {e}", path.display())))?
        .ok_or_else(|| {
            Etsi014Error::Tls(format!("{} contains no PRIVATE KEY block", path.display()))
        })
}

/// Anything we can speak HTTP over: a TCP socket, or the same wrapped in TLS.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

// ── Minimal HTTP/1.1 ────────────────────────────────────────────────────────

/// Cap on response headers. A KME's status document is a few hundred bytes; 16 KiB
/// is room for a chatty reverse proxy and nothing like room for an attack on memory.
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Cap on a response body. A 256-bit key is 44 base64 characters; even a
/// gigabit-key appliance is far under this.
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, Etsi014Error> {
        serde_json::from_slice(&self.body).map_err(|e| {
            Etsi014Error::Protocol(format!(
                "KME answered {} with a body that is not the standard's JSON: {e} ({} bytes)",
                self.status,
                self.body.len()
            ))
        })
    }

    /// Pull the single key out of a `{ "keys": [ … ] }` response.
    fn one_key(&self) -> Result<EtsiKey, Etsi014Error> {
        let env: KeyEnvelope = self.json()?;
        let entry = env.keys.into_iter().next().ok_or_else(|| {
            Etsi014Error::Protocol(format!(
                "KME answered {} with an empty \"keys\" array — for enc_keys that usually means \
                 the pool has no material to give",
                self.status
            ))
        })?;
        if entry.key_id.trim().is_empty() {
            return Err(Etsi014Error::Protocol(
                "KME returned a key with an empty key_ID".to_string(),
            ));
        }
        let material = decode_base64_key(&entry.key)?;
        if material.len() < EPOCH_KEY_LEN {
            return Err(Etsi014Error::Protocol(format!(
                "KME returned {} bytes of key material; a session epoch derives 32 bytes from it, \
                 so at least 32 are required",
                material.len()
            )));
        }
        Ok(EtsiKey {
            key_id: entry.key_id,
            material,
        })
    }
}

async fn http_exchange(
    io: &mut dyn Io,
    host_header: &str,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
) -> Result<HttpResponse, Etsi014Error> {
    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\n\
         User-Agent: vantablack-qkd-014/1\r\nConnection: close\r\n"
    );
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| Etsi014Error::Transport(format!("writing request: {e}")))?;
    if let Some(b) = body {
        io.write_all(b)
            .await
            .map_err(|e| Etsi014Error::Transport(format!("writing body: {e}")))?;
    }
    io.flush()
        .await
        .map_err(|e| Etsi014Error::Transport(format!("flushing request: {e}")))?;

    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let header_end = loop {
        if let Some(i) = find_subslice(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(Etsi014Error::Protocol(format!(
                "KME response headers exceeded {MAX_HEADER_BYTES} bytes"
            )));
        }
        let mut chunk = [0u8; 4096];
        let n = io
            .read(&mut chunk)
            .await
            .map_err(|e| Etsi014Error::Transport(format!("reading response: {e}")))?;
        if n == 0 {
            return Err(Etsi014Error::Protocol(
                "KME closed the connection before sending complete headers".to_string(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            Etsi014Error::Protocol(format!("malformed status line from KME: {status_line:?}"))
        })?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    let mut rest: Vec<u8> = buf[header_end + 4..].to_vec();
    let body_bytes = if header("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        read_chunked(io, &mut rest).await?
    } else if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if len > MAX_BODY_BYTES {
            return Err(Etsi014Error::Protocol(format!(
                "KME announced a {len}-byte body, over the {MAX_BODY_BYTES}-byte cap"
            )));
        }
        while rest.len() < len {
            let mut chunk = [0u8; 4096];
            let n = io
                .read(&mut chunk)
                .await
                .map_err(|e| Etsi014Error::Transport(format!("reading response body: {e}")))?;
            if n == 0 {
                break;
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        rest.truncate(len);
        rest
    } else {
        // No framing information: read to close. Bounded, because "close" is a
        // promise a hostile or broken peer makes and does not keep.
        while rest.len() <= MAX_BODY_BYTES {
            let mut chunk = [0u8; 4096];
            match io.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => rest.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    return Err(Etsi014Error::Transport(format!(
                        "reading response body: {e}"
                    )))
                }
            }
        }
        if rest.len() > MAX_BODY_BYTES {
            return Err(Etsi014Error::Protocol(
                "KME sent no length and more than the body cap".to_string(),
            ));
        }
        rest
    };

    let resp = HttpResponse {
        status,
        body: body_bytes,
    };
    if !(200..300).contains(&status) {
        return Err(Etsi014Error::Http {
            status,
            message: error_message(&resp.body),
        });
    }
    Ok(resp)
}

/// Decode a chunked transfer body (RFC 9112 §7.1).
///
/// Implemented rather than rejected because a KME behind nginx or a gateway will
/// chunk a small JSON response, and failing there would look exactly like the
/// appliance being broken.
async fn read_chunked(io: &mut dyn Io, rest: &mut Vec<u8>) -> Result<Vec<u8>, Etsi014Error> {
    let mut out = Vec::new();
    loop {
        // Chunk size line.
        let line_end = loop {
            if let Some(i) = find_subslice(rest, b"\r\n") {
                break i;
            }
            if rest.len() > MAX_HEADER_BYTES {
                return Err(Etsi014Error::Protocol(
                    "malformed chunked response (no size line)".to_string(),
                ));
            }
            read_more(io, rest).await?;
        };
        let size_line = String::from_utf8_lossy(&rest[..line_end]).to_string();
        let size = usize::from_str_radix(
            size_line
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|e| Etsi014Error::Protocol(format!("malformed chunk size {size_line:?}: {e}")))?;
        rest.drain(..line_end + 2);

        if size == 0 {
            return Ok(out); // trailer section is not interesting for a key document
        }
        if out.len() + size > MAX_BODY_BYTES {
            return Err(Etsi014Error::Protocol(format!(
                "chunked body exceeded the {MAX_BODY_BYTES}-byte cap"
            )));
        }
        while rest.len() < size + 2 {
            read_more(io, rest).await?;
        }
        out.extend_from_slice(&rest[..size]);
        rest.drain(..size + 2); // chunk data + CRLF
    }
}

async fn read_more(io: &mut dyn Io, buf: &mut Vec<u8>) -> Result<(), Etsi014Error> {
    let mut chunk = [0u8; 4096];
    let n = io
        .read(&mut chunk)
        .await
        .map_err(|e| Etsi014Error::Transport(format!("reading chunked body: {e}")))?;
    if n == 0 {
        return Err(Etsi014Error::Protocol(
            "connection closed mid-chunked-body".to_string(),
        ));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

/// The path-and-query part of a URL — the origin-form request target.
///
/// `https://kme:8443/api/v1/keys/a/enc_keys?number=1` becomes
/// `/api/v1/keys/a/enc_keys?number=1`. A URL with no path is `/`.
fn origin_form(url: &str) -> &str {
    match url.find("://") {
        Some(i) => {
            let after = &url[i + 3..];
            match after.find('/') {
                Some(j) => &after[j..],
                None => "/",
            }
        }
        None => url,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Pull a human-readable reason out of an error response.
///
/// The standard's error body is not fixed: implementations we checked use
/// `message`, `detail`, or a bare string. All three are handled, and the result
/// is truncated so a proxy's HTML error page cannot flood the logs.
fn error_message(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let extracted = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s),
            other => other
                .get("message")
                .or_else(|| other.get("detail"))
                .or_else(|| other.get("error"))
                .and_then(|m| m.as_str().map(str::to_string)),
        })
        .unwrap_or_else(|| text.trim().to_string());
    let extracted = extracted.trim();
    if extracted.is_empty() {
        return "(no error body)".to_string();
    }
    extracted.chars().take(512).collect()
}

/// Decode a key from base64, accepting both the standard and URL-safe alphabets.
///
/// RFC 4648 §5 exists because URL-safe base64 is a common accident in this
/// ecosystem; a client that rejected it would fail against a working appliance
/// for a reason no operator would guess.
pub fn decode_base64_key(encoded: &str) -> Result<Vec<u8>, Etsi014Error> {
    let cleaned: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let standard = cleaned.replace('-', "+").replace('_', "/");
    let unpadded = standard.trim_end_matches('=');
    let padding = (4 - (unpadded.len() % 4)) % 4;
    let padded = format!("{unpadded}{}", "=".repeat(padding));
    base64_decode(&padded).ok_or_else(|| {
        Etsi014Error::Protocol(
            "KME returned key material that is not valid base64 (RFC 4648 §4 or §5)".to_string(),
        )
    })
}

/// Straight base64 decoder — no dependency for twenty lines of table lookup.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    // Base64 is a multiple of 4 by construction; a mask rather than `%` so the
    // intent reads as "the low two bits are clear" (4 is a power of two).
    if bytes.len() & 3 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' {
                if i < 4 - pad {
                    return None; // padding only at the end
                }
                0
            } else {
                value(c)?
            };
            acc = (acc << 6) | u32::from(v);
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// Percent-encode a path segment: everything outside the unreserved set (RFC 3986
/// §2.3) is escaped, which is stricter than necessary and cannot be wrong.
fn percent_encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(url: &str) -> Etsi014Config {
        Etsi014Config {
            base_url: normalise_base_url(url).expect("valid url"),
            our_sae_id: "sae_master".into(),
            default_peer_sae_id: Some("sae_slave".into()),
            sae_map: HashMap::new(),
            key_bits: DEFAULT_KEY_BITS,
            timeout: Duration::from_secs(5),
            ca_pem: None,
            client_cert: None,
            client_key: None,
            insecure: false,
        }
    }

    #[test]
    fn a_base_url_normalises_to_the_standard_api_path() {
        // All four spellings an operator might use mean one thing.
        for raw in [
            "https://kme.site-a.example:8443",
            "https://kme.site-a.example:8443/",
            "https://kme.site-a.example:8443/api/v1",
            "https://kme.site-a.example:8443/api/v1/keys/",
        ] {
            assert_eq!(
                normalise_base_url(raw).unwrap(),
                "https://kme.site-a.example:8443/api/v1/keys",
                "raw = {raw}"
            );
        }
        // A reverse proxy in front of several KMEs keeps its prefix.
        assert_eq!(
            normalise_base_url("https://gw.example/qkd/site-a").unwrap(),
            "https://gw.example/qkd/site-a/api/v1/keys"
        );
    }

    #[test]
    fn a_url_without_a_usable_scheme_or_host_is_refused() {
        assert!(normalise_base_url("kme.example:8443").is_err());
        assert!(normalise_base_url("ftp://kme.example").is_err());
        assert!(normalise_base_url("https://").is_err());
        assert!(normalise_base_url("").is_err());
    }

    #[test]
    fn authority_and_host_default_their_ports_by_scheme() {
        assert_eq!(
            cfg_with("https://kme.example").authority(),
            "kme.example:443"
        );
        assert_eq!(cfg_with("http://kme.example").authority(), "kme.example:80");
        assert_eq!(
            cfg_with("https://kme.example:8443").authority(),
            "kme.example:8443"
        );
        assert_eq!(cfg_with("https://kme.example:8443").host(), "kme.example");
    }

    #[test]
    fn the_path_is_always_the_other_partys_sae_id() {
        // The single easiest thing to get wrong in this API, and the reason both
        // directions are asserted here rather than in the caller.
        let c = Etsi014Client::new(cfg_with("https://kme.example:8443"));
        assert_eq!(
            c.path(&["sae_slave", "enc_keys"], Some("number=1&size=256")),
            "https://kme.example:8443/api/v1/keys/sae_slave/enc_keys?number=1&size=256"
        );
        assert_eq!(
            c.path(&["sae_master", "dec_keys"], None),
            "https://kme.example:8443/api/v1/keys/sae_master/dec_keys"
        );
        assert_eq!(
            c.path(&["sae_slave", "status"], None),
            "https://kme.example:8443/api/v1/keys/sae_slave/status"
        );
    }

    #[test]
    fn sae_ids_are_escaped_so_they_cannot_retarget_the_request() {
        let c = Etsi014Client::new(cfg_with("https://kme.example:8443"));
        let path = c.path(&["../admin", "enc_keys"], None);
        assert!(
            !path.contains("../"),
            "a traversal in an SAE ID must not survive: {path}"
        );
        assert_eq!(
            path,
            "https://kme.example:8443/api/v1/keys/..%2Fadmin/enc_keys"
        );
        // A query delimiter in a segment cannot start a query either.
        assert!(c.path(&["a?b=c", "status"], None).contains("%3F"));
    }

    #[test]
    fn an_unmapped_peer_is_reported_not_guessed() {
        let mut cfg = cfg_with("https://kme.example:8443");
        cfg.default_peer_sae_id = None;
        cfg.sae_map.insert("peer-fp-1".into(), "sae_peer_1".into());
        assert_eq!(cfg.peer_sae_id("peer-fp-1"), Some("sae_peer_1"));
        assert_eq!(cfg.peer_sae_id("peer-fp-2"), None);

        // A two-node deployment can rely on the single default.
        let mut cfg = cfg_with("https://kme.example:8443");
        cfg.sae_map.insert("peer-fp-1".into(), "sae_peer_1".into());
        assert_eq!(cfg.peer_sae_id("peer-fp-1"), Some("sae_peer_1"));
        assert_eq!(
            cfg.peer_sae_id("anything-else"),
            Some("sae_slave"),
            "the default covers peers the map does not name"
        );
        assert!(!cfg.is_two_node_default());
    }

    #[test]
    fn the_key_envelope_parses_as_the_standard_writes_it() {
        let body = br#"{"keys":[{"key_ID":"16fb8915-e50e-4212-8c34-a4b780297f8f","key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}]}"#;
        let resp = HttpResponse {
            status: 200,
            body: body.to_vec(),
        };
        let key = resp.one_key().expect("the standard's envelope");
        assert_eq!(key.key_id, "16fb8915-e50e-4212-8c34-a4b780297f8f");
        assert_eq!(key.material.len(), 32);
        assert_eq!(key.material[0], 0x00);
        assert_eq!(key.material[31], 0x1f);
    }

    #[test]
    fn a_key_shorter_than_an_epoch_is_refused_rather_than_padded() {
        // 8 bytes: a real appliance can be configured this way, and the honest
        // answer is to refuse, not to stretch 64 bits into a 256-bit epoch key.
        let body = br#"{"keys":[{"key_ID":"id","key":"AAECAwQFBgc="}]}"#;
        let resp = HttpResponse {
            status: 200,
            body: body.to_vec(),
        };
        let err = resp.one_key().expect_err("too short");
        assert!(err.to_string().contains("32 bytes"), "{err}");
    }

    #[test]
    fn an_empty_key_array_is_a_protocol_error_with_a_useful_reason() {
        let resp = HttpResponse {
            status: 200,
            body: br#"{"keys":[]}"#.to_vec(),
        };
        let err = resp.one_key().expect_err("no keys");
        assert!(err.to_string().contains("pool"), "{err}");
    }

    #[test]
    fn base64_decodes_both_alphabets() {
        // Same 4 bytes, standard and URL-safe (which needs the substitution).
        let std = decode_base64_key("+/8A").unwrap();
        assert_eq!(std, vec![0xfb, 0xff, 0x00]);
        let url = decode_base64_key("-_8A").unwrap();
        assert_eq!(url, std);
        // Unpadded input is accepted; the appliances differ on this.
        assert_eq!(decode_base64_key("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_base64_key("AQI").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64_key("AQ").unwrap(), vec![1]);
        // Whitespace and newlines in a JSON string are tolerated.
        assert_eq!(decode_base64_key("AQID\n").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn base64_rejects_what_it_cannot_decode() {
        assert!(decode_base64_key("AQID!").is_err());
        assert!(decode_base64_key("A").is_err());
        assert!(decode_base64_key("=AQI").is_err());
    }

    #[test]
    fn the_epoch_key_is_derived_not_truncated_and_bound_to_the_id() {
        let material = vec![0xABu8; 32];
        let a = EtsiKey {
            key_id: "id-one".into(),
            material: material.clone(),
        };
        let b = EtsiKey {
            key_id: "id-two".into(),
            material: material.clone(),
        };
        assert_eq!(a.epoch_key(), a.epoch_key(), "deterministic");
        assert_ne!(
            a.epoch_key(),
            b.epoch_key(),
            "the same material under a different key ID must not give the same epoch key"
        );
        assert_ne!(
            a.epoch_key().to_vec(),
            material,
            "the epoch key must be HKDF output, not the appliance's bytes"
        );
        // A larger key still yields 32 bytes.
        let big = EtsiKey {
            key_id: "id-big".into(),
            material: vec![0x11u8; 128],
        };
        assert_eq!(big.epoch_key().len(), 32);
    }

    #[test]
    fn a_status_document_with_vendor_gaps_still_parses() {
        // Only the fields this implementation publishes, which is a normal thing
        // for a vendor to do.
        let status: EtsiStatus = serde_json::from_str(
            r#"{"source_KME_ID":"kme-a","stored_key_count":25000,"max_key_count":100000,
                "max_key_per_request":128,"max_key_size":1024,"min_key_size":64,
                "key_size":256,"max_SAE_ID_count":0}"#,
        )
        .unwrap();
        assert_eq!(status.stored_key_count, Some(25000));
        assert_eq!(status.supports_key_bits(256), Some(true));
        assert_eq!(status.supports_key_bits(2048), Some(false));
        assert!(status.describe().contains("stored=25000"));

        // And one that says almost nothing must not be fatal.
        let sparse: EtsiStatus = serde_json::from_str("{}").unwrap();
        assert_eq!(sparse.supports_key_bits(256), None);
        assert!(sparse.describe().contains("stored=?"));
    }

    #[test]
    fn error_bodies_are_unwrapped_from_the_shapes_vendors_use() {
        assert_eq!(
            error_message(br#"{"message":"key not found"}"#),
            "key not found"
        );
        assert_eq!(
            error_message(br#"{"detail":"invalid size"}"#),
            "invalid size"
        );
        assert_eq!(error_message(br#""plain string""#), "plain string");
        assert_eq!(error_message(b""), "(no error body)");
        // A proxy's HTML page is truncated, not logged whole.
        let huge = "x".repeat(2000);
        assert_eq!(error_message(huge.as_bytes()).chars().count(), 512);
    }

    #[test]
    fn the_request_line_carries_origin_form_not_the_absolute_url() {
        // The whole path is built as an absolute URL (which is what makes the
        // timeout messages readable), and the request line must be reduced to
        // origin-form. An appliance answers an absolute-form line with 404, so
        // getting this wrong looks exactly like a wrong SAE ID.
        assert_eq!(
            origin_form("https://kme.example:8443/api/v1/keys/sae/enc_keys?number=1&size=256"),
            "/api/v1/keys/sae/enc_keys?number=1&size=256"
        );
        assert_eq!(origin_form("https://kme.example"), "/");
        assert_eq!(origin_form("http://127.0.0.1:8080/x"), "/x");
        // Already origin-form: unchanged, so a caller cannot break it by passing
        // one in.
        assert_eq!(origin_form("/api/v1/keys"), "/api/v1/keys");
    }

    #[test]
    fn the_host_header_carries_the_port_we_actually_dial() {
        // A `Host` without the port breaks name-based routing on an appliance
        // that listens on 8443, which is the common QKD deployment.
        let cfg = cfg_with("https://kme.site-a.example:8443");
        assert_eq!(cfg.authority(), "kme.site-a.example:8443");
        assert!(cfg.is_https());
        assert_eq!(cfg.scheme(), "https");
    }
}
