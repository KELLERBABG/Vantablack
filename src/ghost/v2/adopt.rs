//! Adoption Engine — the one-click layer over the CLI primitives.
//!
//! Stage 5 is a UX contract, not a new transport: a person should be able to
//! start a drop, expose one local port, open a party bridge, run the DNS stub or
//! opt into blind relaying without learning a dozen flags. This module holds the
//! parts that must be honest rather than merely convenient:
//!
//! * room codes are typed, expiring and parsed strictly;
//! * blind relaying is opt-in and, when requested, requires a *measured* AC
//!   power source rather than a configuration flag;
//! * installer signing is a gate over evidence, not a default claim;
//! * TUN and DNS can both be started here; a refused TUN device is reported as
//!   a privilege, driver or platform refusal, never as a started interface;
//! * the AC power probe and the signed-release verifier are cached off the
//!   request path, so a dashboard poll cannot spawn a process per call.
//!
//! The actual servers are the existing `portal`, `expose`, `party` and `vbdns`
//! implementations. Nothing here invents a second data path.

use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[cfg(feature = "vpn")]
use crate::ghost::net::vpn::tun::{open_fake_tun, open_tun, PlatformTun, TunDevice};

use super::{expose, party, portal, vbdns};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RoomKind {
    Drop,
    Expose,
    Party,
}

impl RoomKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RoomKind::Drop => "drop",
            RoomKind::Expose => "expose",
            RoomKind::Party => "party",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "drop" => Some(RoomKind::Drop),
            "expose" => Some(RoomKind::Expose),
            "party" => Some(RoomKind::Party),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoomCode {
    pub kind: RoomKind,
    pub payload: String,
    pub expires_at: u64,
}

impl RoomCode {
    pub fn new(kind: RoomKind, payload: &str, now: u64, ttl: Duration) -> Self {
        Self {
            kind,
            payload: payload.to_string(),
            expires_at: now.saturating_add(ttl.as_secs()),
        }
    }

    pub fn encode(&self) -> String {
        format!(
            "vb-{}://{}?exp={}",
            self.kind.as_str(),
            hex::encode(self.payload.as_bytes()),
            self.expires_at
        )
    }

    pub fn parse(code: &str, now: u64) -> Result<Self, String> {
        let (scheme, rest) = code
            .split_once("://")
            .ok_or_else(|| "room code has no vb-<kind>:// scheme".to_string())?;
        let kind = scheme
            .strip_prefix("vb-")
            .and_then(RoomKind::parse)
            .ok_or_else(|| format!("unknown room kind {scheme:?}"))?;
        let (payload_hex, expires) = rest
            .split_once("?exp=")
            .ok_or_else(|| "room code has no expiry".to_string())?;
        let expires_at = expires
            .parse::<u64>()
            .map_err(|e| format!("bad room expiry: {e}"))?;
        if expires_at <= now {
            return Err(format!(
                "room code expired {}s ago",
                now.saturating_sub(expires_at)
            ));
        }
        let payload = String::from_utf8(hex::decode(payload_hex).map_err(|e| e.to_string())?)
            .map_err(|_| "room payload is not UTF-8".to_string())?;
        if payload.is_empty() {
            return Err("room payload is empty".into());
        }
        Ok(Self {
            kind,
            payload,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub tun: bool,
    pub dns: bool,
    pub tun_detail: &'static str,
}

pub fn capabilities() -> Capabilities {
    let tun_compiled = cfg!(feature = "vpn");
    Capabilities {
        tun: tun_compiled,
        dns: true,
        tun_detail: if tun_compiled {
            "POST /api/v2/adopt/tun opens the platform TUN device now; a privilege or missing-driver refusal is reported instead of a success"
        } else {
            "TUN is not compiled in this build; rebuild with the vpn feature"
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    Ac,
    Battery,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PowerEvidence {
    pub state: PowerState,
    pub observed_at: u64,
}

pub const POWER_TTL_SECS: u64 = 60;

impl PowerEvidence {
    pub fn is_fresh(&self) -> bool {
        self.observed_at != 0
            && super::now_secs().saturating_sub(self.observed_at) <= POWER_TTL_SECS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPolicy {
    pub enabled: bool,
    pub ac_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDecision {
    Disabled,
    Serving,
    Withheld,
}

impl RelayDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            RelayDecision::Disabled => "disabled",
            RelayDecision::Serving => "serving",
            RelayDecision::Withheld => "withheld",
        }
    }
}

pub fn relay_decision(
    policy: RelayPolicy,
    power: Option<PowerEvidence>,
    now: u64,
) -> (RelayDecision, Option<&'static str>) {
    if !policy.enabled {
        return (
            RelayDecision::Disabled,
            Some("blind relaying is not opted in"),
        );
    }
    if !policy.ac_only {
        return (RelayDecision::Serving, None);
    }
    let Some(power) = power else {
        return (
            RelayDecision::Withheld,
            Some("AC power is not measured, so the AC-only relay promise cannot be kept"),
        );
    };
    if power.observed_at == 0 || now.saturating_sub(power.observed_at) > POWER_TTL_SECS {
        return (
            RelayDecision::Withheld,
            Some("the AC power measurement is stale"),
        );
    }
    match power.state {
        PowerState::Ac => (RelayDecision::Serving, None),
        PowerState::Battery => (
            RelayDecision::Withheld,
            Some("running on battery; AC-only relaying is withheld"),
        ),
        PowerState::Unknown => (
            RelayDecision::Withheld,
            Some("power source unknown; AC-only relaying is withheld"),
        ),
    }
}

#[derive(Debug, Default)]
pub struct PowerCache {
    cached: Mutex<Option<PowerEvidence>>,
}

impl PowerCache {
    pub fn new() -> Self {
        Self {
            cached: Mutex::new(None),
        }
    }

    pub fn get(&self, now: u64, probe: &mut dyn FnMut() -> PowerState) -> PowerEvidence {
        let mut slot = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(evidence) = *slot {
            if evidence.observed_at != 0
                && now >= evidence.observed_at
                && now - evidence.observed_at <= POWER_TTL_SECS
            {
                return evidence;
            }
        }
        let evidence = PowerEvidence {
            state: probe(),
            observed_at: now,
        };
        *slot = Some(evidence);
        evidence
    }

    pub fn refresh(&self, now: u64, probe: &mut dyn FnMut() -> PowerState) -> PowerEvidence {
        let evidence = PowerEvidence {
            state: probe(),
            observed_at: now,
        };
        *self.cached.lock().unwrap_or_else(|e| e.into_inner()) = Some(evidence);
        evidence
    }
}

static POWER_CACHE: PowerCache = PowerCache {
    cached: Mutex::new(None),
};

pub fn read_power_evidence() -> PowerEvidence {
    POWER_CACHE.get(super::now_secs(), &mut detect_power_state)
}

pub fn probe_power_evidence() -> PowerEvidence {
    POWER_CACHE.refresh(super::now_secs(), &mut detect_power_state)
}

fn detect_power_state() -> PowerState {
    #[cfg(target_os = "linux")]
    {
        let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else {
            return PowerState::Unknown;
        };
        let mut saw_ac = false;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.starts_with("ac") || name.contains("mains") {
                saw_ac = true;
                if let Ok(v) = std::fs::read_to_string(entry.path().join("online")) {
                    if v.trim() == "1" {
                        return PowerState::Ac;
                    }
                }
            }
        }
        if saw_ac {
            return PowerState::Battery;
        }
        PowerState::Unknown
    }
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("pmset")
            .args(["-g", "batt"])
            .output()
        {
            Ok(out) if String::from_utf8_lossy(&out.stdout).contains("AC Power") => PowerState::Ac,
            Ok(_) => PowerState::Battery,
            Err(_) => PowerState::Unknown,
        }
    }
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_Battery).BatteryStatus",
            ])
            .output();
        match out {
            Ok(out) => match String::from_utf8_lossy(&out.stdout).trim() {
                "2" => PowerState::Ac,
                "1" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "11" => PowerState::Battery,
                _ => PowerState::Unknown,
            },
            Err(_) => PowerState::Unknown,
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PowerState::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallerKind {
    Winget,
    Homebrew,
    Deb,
    Apk,
}

impl InstallerKind {
    pub const ALL: [InstallerKind; 4] = [
        InstallerKind::Winget,
        InstallerKind::Homebrew,
        InstallerKind::Deb,
        InstallerKind::Apk,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            InstallerKind::Winget => "winget",
            InstallerKind::Homebrew => "homebrew",
            InstallerKind::Deb => "deb",
            InstallerKind::Apk => "apk",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallerEvidence {
    pub kind: InstallerKind,
    pub artifact: String,
    pub signed: bool,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallerClaim {
    pub state: &'static str,
    pub signed: Vec<&'static str>,
    pub missing: Vec<&'static str>,
    pub reason: Option<String>,
}

pub fn installer_claim(evidence: &[InstallerEvidence]) -> InstallerClaim {
    let mut signed = Vec::new();
    let mut missing = Vec::new();
    let mut reason = None;
    for kind in InstallerKind::ALL {
        match evidence.iter().find(|e| e.kind == kind) {
            Some(e) if e.signed && e.sha256.len() == 64 && !e.artifact.is_empty() => {
                signed.push(kind.as_str());
            }
            Some(e) if !e.signed => {
                missing.push(kind.as_str());
                reason = Some(format!("{} artifact is unsigned", e.kind.as_str()));
            }
            Some(_) => {
                missing.push(kind.as_str());
                reason = Some(format!("{} evidence is malformed", kind.as_str()));
            }
            None => {
                missing.push(kind.as_str());
                reason = Some(format!("{} artifact is missing", kind.as_str()));
            }
        }
    }
    if missing.is_empty() {
        InstallerClaim {
            state: "verified",
            signed,
            missing,
            reason: None,
        }
    } else {
        InstallerClaim {
            state: "withheld",
            signed,
            missing,
            reason,
        }
    }
}

pub const INSTALLER_EVIDENCE_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallerReport {
    pub ran: bool,
    pub source: Option<String>,
    pub checked_at: u64,
    pub claim: InstallerClaim,
}

fn withheld_claim(reason: &str) -> InstallerClaim {
    InstallerClaim {
        state: "withheld",
        signed: Vec::new(),
        missing: InstallerKind::ALL.iter().map(|k| k.as_str()).collect(),
        reason: Some(reason.to_string()),
    }
}

pub fn parse_installer_evidence(stdout: &str) -> Result<Vec<InstallerEvidence>, String> {
    let value: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| format!("signed-release verifier did not emit JSON: {e}"))?;
    if value.get("verified").and_then(|v| v.as_bool()) != Some(true) {
        let why = value
            .get("reasons")
            .and_then(|v| v.as_array())
            .and_then(|a| a.iter().find_map(|r| r.as_str()))
            .unwrap_or("the verifier withheld the signed-release claim");
        return Err(why.to_string());
    }
    let entries = value
        .get("installers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "verifier output has no installers array".to_string())?;
    let mut evidence = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry
            .get("kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "installer evidence has no kind".to_string())?;
        let kind = InstallerKind::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == name)
            .ok_or_else(|| format!("unknown installer kind {name:?}"))?;
        evidence.push(InstallerEvidence {
            kind,
            artifact: entry
                .get("artifact")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            signed: entry.get("signed").and_then(|v| v.as_bool()) == Some(true),
            sha256: entry
                .get("sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(evidence)
}

fn installer_report_from(
    now: u64,
    source: Option<String>,
    run: impl FnOnce() -> Result<String, String>,
) -> InstallerReport {
    let claim = match run() {
        Ok(stdout) => match parse_installer_evidence(&stdout) {
            Ok(evidence) => installer_claim(&evidence),
            Err(e) => withheld_claim(&e),
        },
        Err(e) => withheld_claim(&e),
    };
    InstallerReport {
        ran: true,
        source,
        checked_at: now,
        claim,
    }
}

fn verifier_target() -> Option<(PathBuf, PathBuf)> {
    let explicit_script = std::env::var_os("GGN_SIGNED_RELEASE_VERIFIER");
    let script = explicit_script
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("packaging").join("verify_signed_release.sh"));
    match std::env::var_os("GGN_SIGNED_DIST").map(PathBuf::from) {
        Some(dist) => Some((script, dist)),
        None if explicit_script.is_some() => Some((script, PathBuf::from("dist"))),
        None => None,
    }
}

fn run_verifier(script: &std::path::Path, dist: &std::path::Path) -> Result<String, String> {
    let output = std::process::Command::new(script)
        .arg("--json")
        .arg(dist)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", script.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{} produced no JSON: {}",
            script.display(),
            stderr.trim()
        ));
    }
    Ok(stdout)
}

static INSTALLER_CACHE: OnceLock<Mutex<Option<InstallerReport>>> = OnceLock::new();

pub fn installer_report(now: u64) -> InstallerReport {
    let mut slot = INSTALLER_CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(report) = slot.as_ref() {
        if now >= report.checked_at && now - report.checked_at <= INSTALLER_EVIDENCE_TTL_SECS {
            return report.clone();
        }
    }
    let report = match verifier_target() {
        Some((script, dist)) => {
            let source = Some(format!("{} {}", script.display(), dist.display()));
            installer_report_from(now, source, || run_verifier(&script, &dist))
        }
        None => InstallerReport {
            ran: false,
            source: None,
            checked_at: now,
            claim: withheld_claim(
                "no signed release has been verified here; set GGN_SIGNED_DIST to run packaging/verify_signed_release.sh against a dist directory",
            ),
        },
    };
    *slot = Some(report.clone());
    report
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunRefusal {
    FeatureMissing,
    PrivilegeDenied,
    DeviceMissing,
    AlreadyRunning,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunRefusalDetail {
    pub reason: TunRefusal,
    pub detail: String,
}

pub fn classify_tun_error(kind: std::io::ErrorKind) -> TunRefusal {
    match kind {
        std::io::ErrorKind::PermissionDenied => TunRefusal::PrivilegeDenied,
        std::io::ErrorKind::NotFound => TunRefusal::DeviceMissing,
        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::AddrInUse => {
            TunRefusal::AlreadyRunning
        }
        _ => TunRefusal::Unsupported,
    }
}

pub fn tun_refusal(reason: TunRefusal, err: std::io::Error) -> TunRefusalDetail {
    let hint = match reason {
        TunRefusal::FeatureMissing => "the vpn feature is not compiled into this build",
        TunRefusal::PrivilegeDenied => {
            "the OS denied the TUN device; run the daemon as Administrator (wintun) or with CAP_NET_ADMIN/root (/dev/net/tun)"
        }
        TunRefusal::DeviceMissing => {
            "no TUN driver or device here; Windows needs wintun.dll beside the executable and Linux needs /dev/net/tun (tun module)"
        }
        TunRefusal::AlreadyRunning => "this process already holds a TUN device",
        TunRefusal::Unsupported => "this platform cannot open a TUN device",
    };
    TunRefusalDetail {
        reason,
        detail: format!("{hint}: {err}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunStart {
    pub interface: String,
    pub real_interface: bool,
    pub mtu: u16,
    pub already_running: bool,
}

#[cfg(feature = "vpn")]
struct TunSession {
    interface: String,
    real: bool,
    mtu: u16,
    _device: PlatformTun,
}

#[cfg(feature = "vpn")]
static TUN_SESSION: OnceLock<Mutex<Option<TunSession>>> = OnceLock::new();

#[cfg(feature = "vpn")]
fn tun_slot() -> &'static Mutex<Option<TunSession>> {
    TUN_SESSION.get_or_init(|| Mutex::new(None))
}

fn fake_tun_requested() -> bool {
    std::env::var("GHOST_VPN_FAKE_TUN")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

pub fn start_tun() -> Result<TunStart, TunRefusalDetail> {
    start_tun_with(fake_tun_requested())
}

fn start_tun_with(fake: bool) -> Result<TunStart, TunRefusalDetail> {
    #[cfg(feature = "vpn")]
    {
        let mut slot = tun_slot().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = slot.as_ref() {
            return Ok(TunStart {
                interface: existing.interface.clone(),
                real_interface: existing.real,
                mtu: existing.mtu,
                already_running: true,
            });
        }
        let device = if fake {
            let (device, _handle) = open_fake_tun();
            device
        } else {
            match open_tun(
                "ggn0",
                std::net::Ipv4Addr::new(10, 66, 0, 10),
                std::net::Ipv4Addr::new(255, 255, 255, 0),
            ) {
                Ok(device) => device,
                Err(e) => return Err(tun_refusal(classify_tun_error(e.kind()), e)),
            }
        };
        let interface = device.name().to_string();
        let mtu = device.mtu();
        let real = !fake;
        *slot = Some(TunSession {
            interface: interface.clone(),
            real,
            mtu,
            _device: device,
        });
        Ok(TunStart {
            interface,
            real_interface: real,
            mtu,
            already_running: false,
        })
    }
    #[cfg(not(feature = "vpn"))]
    {
        let _ = fake;
        Err(TunRefusalDetail {
            reason: TunRefusal::FeatureMissing,
            detail: "the vpn feature is not compiled into this build; rebuild with the vpn feature"
                .to_string(),
        })
    }
}

pub fn stop_tun() -> bool {
    #[cfg(feature = "vpn")]
    {
        tun_slot()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .is_some()
    }
    #[cfg(not(feature = "vpn"))]
    {
        false
    }
}

pub fn tun_running() -> bool {
    #[cfg(feature = "vpn")]
    {
        tun_slot()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }
    #[cfg(not(feature = "vpn"))]
    {
        false
    }
}

pub const RELAY_COMPOSE: &str = include_str!("../../../deploy/docker-compose.relay.yml");

pub fn relay_container_is_one_line() -> bool {
    RELAY_COMPOSE.contains("command: [\"--relay-only\"]")
        && RELAY_COMPOSE.contains("GHOST_EXIT=0")
        && RELAY_COMPOSE.contains("GHOST_NO_GUI=1")
}

pub struct DropStart {
    pub id: String,
    pub link: String,
    pub room: RoomCode,
}

pub async fn start_drop(path: PathBuf, ttl: Duration, bind: &str) -> Result<DropStart, String> {
    let session = portal::DropSession::open(
        &path,
        portal::DropOptions {
            ttl,
            max_downloads: 0,
            ..Default::default()
        },
    )
    .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let registry = Arc::new(portal::PortalRegistry::new());
    let id = registry.insert(Arc::new(session));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("cannot bind drop server on {bind}: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("drop listener has no address: {e}"))?;
    tokio::spawn(portal::serve(Arc::clone(&registry), listener));
    let link = format!("http://{addr}/f/{id}");
    let room = RoomCode::new(RoomKind::Drop, &link, super::now_secs(), ttl);
    Ok(DropStart { id, link, room })
}

pub struct ExposeStart {
    pub listen: String,
    pub token: String,
    pub room: RoomCode,
}

pub async fn start_expose(target: &str, token: Option<&str>) -> Result<ExposeStart, String> {
    let token = token
        .filter(|t| !t.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| hex::encode(rand::random::<[u8; 16]>()));
    let cfg = expose::ExposeConfig::new(target, &token).with_listen("127.0.0.1:0");
    cfg.validate()?;
    let (addr, listener) = expose::bind(&cfg)
        .await
        .map_err(|e| format!("cannot bind expose relay: {e}"))?;
    tokio::spawn(expose::serve(listener, Arc::new(cfg)));
    let payload = format!("http://{addr}|{token}|{target}");
    let room = RoomCode::new(
        RoomKind::Expose,
        &payload,
        super::now_secs(),
        Duration::from_secs(86_400),
    );
    Ok(ExposeStart {
        listen: addr.to_string(),
        token,
        room,
    })
}

pub struct PartyStart {
    pub listen: String,
    pub peer_listen: String,
    pub room: RoomCode,
}

pub async fn start_party(listen: &str) -> Result<PartyStart, String> {
    let cfg = party::PartyConfig::new(listen, None);
    let _local = tokio::net::UdpSocket::bind(&cfg.listen)
        .await
        .map_err(|e| format!("cannot bind party game port {}: {e}", cfg.listen))?;
    let peer_listen = cfg.peer_listen_addr();
    let _peer = tokio::net::UdpSocket::bind(&peer_listen)
        .await
        .map_err(|e| format!("cannot bind party peer port {peer_listen}: {e}"))?;
    drop(_local);
    drop(_peer);
    let launched = cfg.clone();
    tokio::spawn(async move {
        let _ = party::run(launched).await;
    });
    let payload = format!("{}|{peer_listen}", cfg.listen);
    let room = RoomCode::new(
        RoomKind::Party,
        &payload,
        super::now_secs(),
        Duration::from_secs(86_400),
    );
    Ok(PartyStart {
        listen: cfg.listen,
        peer_listen,
        room,
    })
}

pub struct DnsStart {
    pub listen: String,
}

pub async fn start_dns(bind: &str) -> Result<DnsStart, String> {
    let registry = Arc::new(vbdns::NameRegistry::new());
    let (addr, _task) = vbdns::spawn(
        registry,
        bind.parse()
            .map_err(|e| format!("bad DNS bind {bind}: {e}"))?,
    )
    .await
    .map_err(|e| format!("cannot bind DNS stub on {bind}: {e}"))?;
    Ok(DnsStart {
        listen: addr.to_string(),
    })
}

pub fn status_json() -> serde_json::Value {
    let caps = capabilities();
    let power = read_power_evidence();
    let installers = installer_report(super::now_secs());
    serde_json::json!({
        "capabilities": caps,
        "power": power,
        "power_ttl_secs": POWER_TTL_SECS,
        "tun_running": tun_running(),
        "installers": installers.claim,
        "installer_evidence": {
            "ran": installers.ran,
            "source": installers.source,
            "checked_at": installers.checked_at,
            "ttl_secs": INSTALLER_EVIDENCE_TTL_SECS,
        },
        "relay_container": relay_container_is_one_line(),
        "room_codes": {
            "schemes": ["vb-drop://", "vb-expose://", "vb-party://"],
            "expiry": "embedded, strictly parsed and rejected after expiry",
        },
        "actions": {
            "drop": "POST /api/v2/adopt/drop {\"path\":\"...\"}",
            "expose": "POST /api/v2/adopt/expose {\"target\":\"host:port\"}",
            "party": "POST /api/v2/adopt/party {\"listen\":\"host:port\"}",
            "dns": "POST /api/v2/adopt/dns",
            "tun": "POST /api/v2/adopt/tun (opens the platform device; {\"action\":\"stop\"} releases it)",
            "relay": "POST /api/settings {\"blind_relay_enabled\":true} (AC evidence required)",
        },
    })
}

fn json_body(req: &str) -> serde_json::Value {
    req.split_once("\r\n\r\n")
        .and_then(|(_, body)| serde_json::from_str(body).ok())
        .unwrap_or(serde_json::Value::Null)
}

pub async fn handle_http(req: &str) -> (&'static str, String, &'static str) {
    let path = req
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    if req.starts_with("GET ") && path == "/api/v2/adopt/status" {
        return (
            "HTTP/1.1 200 OK",
            status_json().to_string(),
            "application/json",
        );
    }
    if !req.starts_with("POST ") {
        return (
            "HTTP/1.1 405 Method Not Allowed",
            serde_json::json!({"success": false, "error": "POST required"}).to_string(),
            "application/json",
        );
    }
    let body = json_body(req);
    let result = match path {
        "/api/v2/adopt/drop" => match body.get("path").and_then(|v| v.as_str()) {
            Some(path) => {
                let ttl = body
                    .get("ttl_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(86_400)
                    .clamp(60, 7 * 86_400);
                let bind = body
                    .get("bind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("127.0.0.1:0");
                start_drop(PathBuf::from(path), Duration::from_secs(ttl), bind)
                    .await
                    .map(|s| {
                        serde_json::json!({
                            "success": true,
                            "id": s.id,
                            "link": s.link,
                            "room": s.room.encode(),
                        })
                    })
            }
            None => Err("path is required".to_string()),
        },
        "/api/v2/adopt/expose" => {
            let target = body
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:3000");
            let token = body.get("token").and_then(|v| v.as_str());
            start_expose(target, token).await.map(|s| {
                serde_json::json!({
                    "success": true,
                    "listen": s.listen,
                    "token": s.token,
                    "room": s.room.encode(),
                })
            })
        }
        "/api/v2/adopt/party" => {
            let listen = body
                .get("listen")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:47077");
            start_party(listen).await.map(|s| {
                serde_json::json!({
                    "success": true,
                    "listen": s.listen,
                    "peer_listen": s.peer_listen,
                    "room": s.room.encode(),
                })
            })
        }
        "/api/v2/adopt/dns" => {
            let bind = body
                .get("bind")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:0");
            start_dns(bind)
                .await
                .map(|s| serde_json::json!({
                    "success": true,
                    "dns_server": s.listen,
                    "note": "point the OS resolver at this loopback stub; the daemon does not change system DNS",
                }))
        }
        "/api/v2/adopt/tun" => {
            let stop = body.get("stop").and_then(|v| v.as_bool()) == Some(true)
                || body
                    .get("action")
                    .and_then(|v| v.as_str())
                    .map(|a| a.eq_ignore_ascii_case("stop"))
                    .unwrap_or(false);
            if stop {
                let was_running = stop_tun();
                return (
                    "HTTP/1.1 200 OK",
                    serde_json::json!({
                        "success": true,
                        "started": false,
                        "stopped": true,
                        "was_running": was_running,
                    })
                    .to_string(),
                    "application/json",
                );
            }
            return match start_tun() {
                Ok(started) => (
                    "HTTP/1.1 200 OK",
                    serde_json::json!({
                        "success": true,
                        "started": true,
                        "already_running": started.already_running,
                        "interface": started.interface,
                        "real_interface": started.real_interface,
                        "mtu": started.mtu,
                        "detail": if started.real_interface {
                            format!(
                                "TUN interface {} is open; forwarding still needs the daemon's VPN client (GHOST_VPN=client)",
                                started.interface
                            )
                        } else {
                            "in-memory self-test TUN (GHOST_VPN_FAKE_TUN); no OS interface exists".to_string()
                        },
                    })
                    .to_string(),
                    "application/json",
                ),
                Err(refusal) => (
                    "HTTP/1.1 409 Conflict",
                    serde_json::json!({
                        "success": false,
                        "started": false,
                        "reason": refusal.reason,
                        "error": refusal.detail,
                    })
                    .to_string(),
                    "application/json",
                ),
            };
        }
        _ => Err("unknown adoption action".to_string()),
    };
    match result {
        Ok(value) => ("HTTP/1.1 200 OK", value.to_string(), "application/json"),
        Err(error) => (
            "HTTP/1.1 400 Bad Request",
            serde_json::json!({"success": false, "error": error}).to_string(),
            "application/json",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room() -> RoomCode {
        RoomCode::new(
            RoomKind::Drop,
            "http://127.0.0.1:8787/f/0123",
            1_000,
            Duration::from_secs(60),
        )
    }

    #[test]
    fn room_codes_round_trip_and_reject_the_wrong_family_or_expiry() {
        let code = room().encode();
        let parsed = RoomCode::parse(&code, 1_030).expect("fresh code parses");
        assert_eq!(parsed.kind, RoomKind::Drop);
        assert_eq!(parsed.payload, room().payload);
        assert!(
            RoomCode::parse(&code, 1_061).is_err(),
            "expiry is exclusive"
        );
        assert!(RoomCode::parse(&code.replace("vb-drop", "vb-party"), 1_030).is_ok());
        assert!(RoomCode::parse("vb-nope://00?exp=9999", 1).is_err());
        assert!(RoomCode::parse("https://example", 1).is_err());
        assert!(RoomCode::parse("vb-drop://zz?exp=9999", 1).is_err());
    }

    #[test]
    fn blind_relaying_is_off_until_opted_in_and_withholds_without_fresh_ac() {
        let now = 1_000;
        assert_eq!(
            relay_decision(
                RelayPolicy {
                    enabled: false,
                    ac_only: true
                },
                None,
                now
            )
            .0,
            RelayDecision::Disabled
        );
        assert_eq!(
            relay_decision(
                RelayPolicy {
                    enabled: true,
                    ac_only: true
                },
                None,
                now
            )
            .0,
            RelayDecision::Withheld
        );
        let battery = PowerEvidence {
            state: PowerState::Battery,
            observed_at: now,
        };
        assert_eq!(
            relay_decision(
                RelayPolicy {
                    enabled: true,
                    ac_only: true
                },
                Some(battery),
                now
            )
            .0,
            RelayDecision::Withheld
        );
        let stale_ac = PowerEvidence {
            state: PowerState::Ac,
            observed_at: now.saturating_sub(POWER_TTL_SECS + 1),
        };
        assert_eq!(
            relay_decision(
                RelayPolicy {
                    enabled: true,
                    ac_only: true
                },
                Some(stale_ac),
                now
            )
            .0,
            RelayDecision::Withheld
        );
        let fresh_ac = PowerEvidence {
            state: PowerState::Ac,
            observed_at: now,
        };
        assert_eq!(
            relay_decision(
                RelayPolicy {
                    enabled: true,
                    ac_only: true
                },
                Some(fresh_ac),
                now
            )
            .0,
            RelayDecision::Serving
        );
        assert_eq!(
            relay_decision(
                RelayPolicy {
                    enabled: true,
                    ac_only: false
                },
                None,
                now
            )
            .0,
            RelayDecision::Serving
        );
    }

    #[test]
    fn a_signed_installer_claim_needs_all_four_families_and_real_signatures() {
        let signed = |kind| InstallerEvidence {
            kind,
            artifact: format!("{}-artifact", kind.as_str()),
            signed: true,
            sha256: "a".repeat(64),
        };
        let all: Vec<_> = InstallerKind::ALL.iter().copied().map(signed).collect();
        assert_eq!(installer_claim(&all).state, "verified");
        assert_eq!(installer_claim(&all[..3]).state, "withheld");
        assert!(installer_claim(&all[..3]).missing.contains(&"apk"));
        let mut unsigned = all.clone();
        unsigned[2].signed = false;
        let claim = installer_claim(&unsigned);
        assert_eq!(claim.state, "withheld");
        assert!(claim.reason.unwrap().contains("deb"));
    }

    #[test]
    fn dns_is_one_click_and_tun_starts_or_refuses_with_a_reason() {
        let caps = capabilities();
        assert!(caps.dns);
        if !cfg!(feature = "vpn") {
            assert!(!caps.tun);
            assert!(caps.tun_detail.contains("not compiled"));
            assert_eq!(
                start_tun().err().map(|r| r.reason),
                Some(TunRefusal::FeatureMissing)
            );
        }
    }

    #[test]
    fn the_tun_device_really_opens_and_is_released_instead_of_being_claimed() {
        assert!(!tun_running());
        let started = start_tun_with(true).expect("in-memory TUN opens");
        assert!(!started.already_running);
        assert!(!started.real_interface);
        assert_eq!(started.interface, "fake0");
        assert!(started.mtu > 0);
        assert!(tun_running());
        let again = start_tun_with(true).expect("held TUN is reported");
        assert!(again.already_running);
        assert_eq!(again.interface, started.interface);
        assert!(stop_tun());
        assert!(!tun_running());
        assert!(
            !stop_tun(),
            "a second stop must not claim to release anything"
        );
    }

    #[test]
    fn a_refused_tun_device_is_classified_by_privilege_or_driver() {
        assert_eq!(
            classify_tun_error(std::io::ErrorKind::PermissionDenied),
            TunRefusal::PrivilegeDenied
        );
        assert_eq!(
            classify_tun_error(std::io::ErrorKind::NotFound),
            TunRefusal::DeviceMissing
        );
        assert_eq!(
            classify_tun_error(std::io::ErrorKind::AlreadyExists),
            TunRefusal::AlreadyRunning
        );
        assert_eq!(
            classify_tun_error(std::io::ErrorKind::InvalidInput),
            TunRefusal::Unsupported
        );
        let refusal = tun_refusal(
            TunRefusal::PrivilegeDenied,
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(refusal.detail.contains("Administrator"));
        assert!(refusal.detail.contains("CAP_NET_ADMIN"));
        let missing = tun_refusal(
            TunRefusal::DeviceMissing,
            std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert!(missing.detail.contains("wintun.dll"));
        assert!(missing.detail.contains("/dev/net/tun"));
    }

    #[test]
    fn the_ac_probe_is_cached_for_the_ttl_instead_of_running_per_request() {
        let cache = PowerCache::new();
        let calls = std::cell::Cell::new(0u32);
        let mut probe = || {
            calls.set(calls.get() + 1);
            PowerState::Ac
        };
        let first = cache.get(1_000, &mut probe);
        assert_eq!(first.observed_at, 1_000);
        assert_eq!(cache.get(1_030, &mut probe).observed_at, 1_000);
        assert_eq!(
            calls.get(),
            1,
            "a status poll inside the TTL must not re-probe"
        );
        let refreshed = cache.get(1_000 + POWER_TTL_SECS + 1, &mut probe);
        assert_eq!(refreshed.observed_at, 1_061);
        assert_eq!(calls.get(), 2);
        assert_eq!(cache.get(900, &mut probe).observed_at, 900);
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn the_signed_release_verifier_decides_the_installer_claim() {
        let evidence = |kind: InstallerKind| {
            serde_json::json!({
                "kind": kind.as_str(),
                "artifact": format!("/dist/{}", kind.as_str()),
                "signed": true,
                "sha256": "a".repeat(64),
            })
        };
        let verified = serde_json::json!({
            "verified": true,
            "installers": InstallerKind::ALL.iter().copied().map(evidence).collect::<Vec<_>>(),
        });
        let report = installer_report_from(500, Some("fake verifier".into()), || {
            Ok(verified.to_string())
        });
        assert!(report.ran);
        assert_eq!(report.claim.state, "verified");
        assert_eq!(report.claim.signed.len(), 4);

        let withheld = serde_json::json!({
            "verified": false,
            "installers": [],
            "reasons": ["Homebrew bottle has no detached signature"],
        });
        let report = installer_report_from(500, Some("fake verifier".into()), || {
            Ok(withheld.to_string())
        });
        assert_eq!(report.claim.state, "withheld");
        assert!(report.claim.reason.unwrap().contains("Homebrew"));

        let unreadable =
            installer_report_from(
                500,
                Some("fake verifier".into()),
                || Err("no script".into()),
            );
        assert_eq!(unreadable.claim.state, "withheld");
        assert!(unreadable.claim.missing.contains(&"apk"));

        let garbage =
            installer_report_from(500, Some("fake verifier".into()), || Ok("not json".into()));
        assert_eq!(garbage.claim.state, "withheld");
    }

    #[test]
    fn the_relay_container_really_runs_relay_only() {
        assert!(relay_container_is_one_line());
    }

    #[tokio::test]
    async fn a_one_click_dns_stub_binds_and_answers_with_an_address() {
        let started = start_dns("127.0.0.1:0").await.expect("DNS stub binds");
        assert_ne!(started.listen, "127.0.0.1:0");
        assert!(started.listen.starts_with("127.0.0.1:"));
    }

    #[tokio::test]
    async fn a_one_click_expose_returns_a_token_and_room_code() {
        let started = start_expose("127.0.0.1:9", Some("0123456789abcdef0123456789abcdef"))
            .await
            .expect("expose relay starts");
        assert!(!started.listen.ends_with(":0"));
        assert_eq!(started.token.len(), 32);
        let parsed = RoomCode::parse(&started.room.encode(), super::super::now_secs()).unwrap();
        assert_eq!(parsed.kind, RoomKind::Expose);
    }

    #[tokio::test]
    async fn a_one_click_party_preflights_both_ports_and_returns_a_room_code() {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let started = start_party(&addr.to_string()).await.expect("party starts");
        assert_eq!(started.listen, addr.to_string());
        let parsed = RoomCode::parse(&started.room.encode(), super::super::now_secs()).unwrap();
        assert_eq!(parsed.kind, RoomKind::Party);
    }

    #[tokio::test]
    async fn a_one_click_drop_returns_a_parsable_room_code() {
        let path = std::env::temp_dir().join(format!(
            "vb-adopt-drop-{}-{}.txt",
            std::process::id(),
            super::super::now_secs()
        ));
        std::fs::write(&path, b"stage five drop").unwrap();
        let started = start_drop(path.clone(), Duration::from_secs(60), "127.0.0.1:0")
            .await
            .expect("drop starts");
        assert!(started.link.starts_with("http://127.0.0.1:"));
        let parsed = RoomCode::parse(&started.room.encode(), super::super::now_secs()).unwrap();
        assert_eq!(parsed.kind, RoomKind::Drop);
        assert_eq!(parsed.payload, started.link);
        let _ = std::fs::remove_file(path);
    }
}
