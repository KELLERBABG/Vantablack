//! UPnP-IGD and NAT-PMP port mapping (SOTA Phase 1 P1-1).
//!
//! STUN tells us what our NAT *would* map, and ICE then has to punch a hole
//! through it. Both of those are workarounds for not being allowed to ask. When
//! the gateway is willing, the cheaper path is to simply ask it for a mapping:
//! the NAT opens a port for us, our address becomes a plain reachable candidate,
//! and no hole needs punching at all.
//!
//! Two protocols do this, and a residential router may speak either:
//!
//! | | Discovery | Control | Transport |
//! |---|---|---|---|
//! | **UPnP-IGD** | SSDP `M-SEARCH` to `239.255.255.250:1900` | SOAP `AddPortMapping` on the WAN connection service | UDP + TCP |
//! | **NAT-PMP** (RFC 6886) | none — the gateway is the default route | 12-byte binary request to gateway:5351 | UDP only |
//!
//! ## "Opportunistic" is the whole design
//!
//! Most networks answer neither: the gateway may have UPnP disabled, the port may
//! be filtered upstream, or a CGNAT may be in the way. So nothing here is
//! required for connectivity — [`opportunistic_public_addr`] is called with a
//! short deadline, and a failure is a log line rather than an error. ICE still
//! runs; this only ever *adds* a candidate that ICE did not have to work for.
//!
//! ## Parsing, not an XML library
//!
//! The device description is XML, and this module extracts the two fields it
//! needs with string scanning rather than pulling in an XML parser. That is a
//! deliberate trade: the input is a handful of elements from a device on the
//! local link, the fields are simple text, and a full parser would be a new
//! dependency (and a new attack surface) for a best-effort hint. What it must not
//! do is *guess*: [`find_wan_control`] takes the first `WANIPConnection` /
//! `WANPPPConnection` service with a usable `controlURL`, and returns `None`
//! rather than a plausible-looking wrong endpoint.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info};

/// The SSDP multicast group and port every UPnP device listens on.
pub const SSDP_MULTICAST: &str = "239.255.255.250:1900";

/// The port a NAT-PMP gateway answers on.
pub const NAT_PMP_PORT: u16 = 5351;

/// Mapping lifetime requested by default, in seconds.
pub const DEFAULT_LIFETIME_SECS: u32 = 3600;

/// The search target that returns internet gateway devices.
const SSDP_ST: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

/// UPnP service types we can drive, most specific first.
const WAN_SERVICE_TYPES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
];

/// Errors from a mapping attempt. Every one of them is recoverable — the caller
/// carries on with ICE.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpnpError {
    #[error("no internet gateway answered on this network")]
    NoGateway,
    #[error("the gateway's description carries no WAN connection service")]
    NoWanService,
    #[error("the gateway refused the mapping: {0} ({1})")]
    Refused(String, String),
    #[error("the gateway's reply was malformed: {0}")]
    Malformed(&'static str),
    #[error("NAT-PMP version {0} is not supported (expected 0)")]
    UnsupportedVersion(u8),
    #[error("I/O error: {0}")]
    Io(String),
}

/// Where to send a SOAP control call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgdControl {
    /// The service type the call is for (the SOAPAction namespace).
    pub service_type: String,
    /// The absolute control URL, already resolved against the description URL.
    pub control_url: String,
    /// The `Host:` header value for the call.
    pub host: String,
}

/// A mapping the gateway granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The public address the gateway reports for us.
    pub external: SocketAddr,
    /// The port it mapped.
    pub internal_port: u16,
    /// Lifetime in seconds, as granted (may be shorter than requested).
    pub lifetime_secs: u32,
}

// ═════════════════════════════════════════════════════════════════════════════
// SSDP
// ═════════════════════════════════════════════════════════════════════════════

/// The `M-SEARCH` datagram that asks for internet gateway devices.
pub fn ssdp_search() -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {SSDP_MULTICAST}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: {SSDP_ST}\r\n\
         \r\n"
    )
}

/// Pull the `LOCATION:` header out of an SSDP response.
///
/// Returns `None` for anything that is not a response carrying a location — a
/// notification (`NOTIFY`) from a device we did not ask, or a response with no
/// location, is not a gateway we can control.
pub fn parse_ssdp_location(raw: &str) -> Option<String> {
    let mut lines = raw.lines();
    let status = lines.next()?;
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return None;
    }
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("location") {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

// ═════════════════════════════════════════════════════════════════════════════
// Device description
// ═════════════════════════════════════════════════════════════════════════════

/// The text between the first `<tag>` and its closing tag, ignoring attributes.
///
/// Scans rather than parses, which is why it is this small — and why it is
/// tested against a longer tag name that starts with the same characters: a
/// lookup for `<serviceType>` must not be satisfied by `<serviceTypeX>`.
fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after_open = &rest[start + open.len()..];
        let Some(gt) = after_open.find('>') else {
            return None;
        };
        let attrs = &after_open[..gt];
        let inner = &after_open[gt + 1..];
        // `<tag>` and `<tag attr=…>` are this element; `<tagOther>` is a
        // different one that merely shares a prefix, so keep looking. Skipping
        // the match rather than failing is the point: a document is full of
        // near-misses, and giving up on the first one would miss the real field.
        let is_ours = attrs.is_empty() || attrs.starts_with([' ', '\t', '\n', '\r']);
        if is_ours {
            if !attrs.ends_with('/') {
                if let Some(end) = inner.find(&close) {
                    return Some(inner[..end].trim());
                }
            }
        }
        rest = &rest[start + 1..];
    }
    None
}

/// Resolve a `controlURL` from a device description against its `LOCATION`.
///
/// Descriptions in the wild use both relative (`/ctl/IPConn`) and absolute
/// (`http://192.168.1.1:5000/ctl/IPConn`) forms, so both are handled; anything
/// else — a different host, a scheme we cannot speak — is refused rather than
/// guessed at, because a control URL pointing somewhere unexpected is exactly
/// the kind of thing an attacker on the local link would like to supply.
pub fn resolve_control_url(location: &str, control_url: &str) -> Option<(String, String)> {
    let location = location.trim();
    let origin_end = location
        .strip_prefix("http://")
        .map(|_| 7)
        .or_else(|| location.strip_prefix("https://").map(|_| 8))?;
    let origin = &location[origin_end..];
    let host = origin.split(['/', '?']).next()?;
    if host.is_empty() {
        return None;
    }
    let control_url = control_url.trim();
    let resolved = if control_url.starts_with("http://") || control_url.starts_with("https://") {
        // Absolute: it must still point at the same origin we discovered.
        let c_origin_end = control_url
            .strip_prefix("http://")
            .map(|_| 7)
            .or_else(|| control_url.strip_prefix("https://").map(|_| 8))?;
        let c_origin = &control_url[c_origin_end..];
        let c_host = c_origin.split(['/', '?']).next()?;
        if c_host != host {
            return None;
        }
        control_url.to_string()
    } else if let Some(path) = control_url.strip_prefix('/') {
        format!("http://{host}/{path}")
    } else {
        // Relative to the description's directory.
        let dir = match location.rfind('/') {
            Some(i) if i > origin_end => &location[..i + 1],
            _ => return None,
        };
        format!("{dir}{control_url}")
    };
    Some((resolved, host.to_string()))
}

/// Find the WAN connection control endpoint in a device description.
///
/// Only services whose `serviceType` is a WAN connection type are considered —
/// the description of an internet gateway device also contains LAN host
/// configuration and layer-3 forwarding services, and mapping a port on one of
/// those is not something that can work.
pub fn find_wan_control(description: &str, location: &str) -> Option<IgdControl> {
    for service in description.split("<service>").skip(1) {
        let Some(service) = service.split("</service>").next() else {
            continue;
        };
        let Some(service_type) = element(service, "serviceType") else {
            continue;
        };
        if !WAN_SERVICE_TYPES.contains(&service_type) {
            continue;
        }
        let Some(control_url) = element(service, "controlURL") else {
            continue;
        };
        let Some((control_url, host)) = resolve_control_url(location, control_url) else {
            continue;
        };
        return Some(IgdControl {
            service_type: service_type.to_string(),
            control_url,
            host,
        });
    }
    None
}

// ═════════════════════════════════════════════════════════════════════════════
// SOAP
// ═════════════════════════════════════════════════════════════════════════════

/// The `<soap:Body>` a WAN connection service expects, wrapped in an envelope.
pub fn soap_envelope(service_type: &str, action: &str, args: &str) -> String {
    let ns = service_type
        .rsplit_once(':')
        .map(|(n, _)| n)
        .unwrap_or(service_type);
    format!(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body>\
         <u:{action} xmlns:u=\"{ns}\">\
         {args}\
         </u:{action}>\
         </s:Body>\
         </s:Envelope>"
    )
}

/// A complete HTTP/1.1 `POST` for a SOAP call.
///
/// `Connection: close` is deliberate: the reply is read to EOF, which makes this
/// work whether or not the gateway bothers to send a `Content-Length`.
pub fn soap_http_request(control: &IgdControl, action: &str, body: &str) -> String {
    let path = control
        .control_url
        .split_once(&control.host)
        .map(|(_, rest)| if rest.is_empty() { "/" } else { rest })
        .unwrap_or("/");
    let path = if path.starts_with('/') { path } else { "/" };
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{ns}#{action}\"\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        host = control.host,
        ns = control.service_type,
        len = body.len(),
    )
}

/// The arguments for `AddPortMapping` for one internal port.
pub fn add_port_mapping_args(
    external_port: u16,
    internal_ip: Ipv4Addr,
    internal_port: u16,
    lifetime_secs: u32,
    description: &str,
) -> String {
    format!(
        "<NewRemoteHost></NewRemoteHost>\
         <NewExternalPort>{external_port}</NewExternalPort>\
         <NewProtocol>UDP</NewProtocol>\
         <NewInternalPort>{internal_port}</NewInternalPort>\
         <NewInternalClient>{internal_ip}</NewInternalClient>\
         <NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>{description}</NewPortMappingDescription>\
         <NewLeaseDuration>{lifetime_secs}</NewLeaseDuration>"
    )
}

/// The arguments for `DeletePortMapping`.
pub fn delete_port_mapping_args(external_port: u16) -> String {
    format!(
        "<NewRemoteHost></NewRemoteHost>\
         <NewExternalPort>{external_port}</NewExternalPort>\
         <NewProtocol>UDP</NewProtocol>"
    )
}

/// Read the body out of an HTTP response.
pub fn http_body(response: &str) -> &str {
    match response.find("\r\n\r\n") {
        Some(i) => &response[i + 4..],
        None => "",
    }
}

/// Extract `NewExternalIPAddress` from a `GetExternalIPAddress` reply.
pub fn parse_external_ip(body: &str) -> Option<Ipv4Addr> {
    element(body, "NewExternalIPAddress")?.parse().ok()
}

/// Extract the SOAP fault, if the reply carries one.
pub fn parse_soap_fault(body: &str) -> Option<(String, String)> {
    let code = element(body, "errorCode").unwrap_or("").to_string();
    let description = element(body, "errorDescription").unwrap_or("").to_string();
    if code.is_empty() && description.is_empty() {
        None
    } else {
        Some((code, description))
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// NAT-PMP (RFC 6886)
// ═════════════════════════════════════════════════════════════════════════════

/// NAT-PMP opcodes we use.
pub const PMP_OP_EXTERNAL_ADDRESS: u8 = 0;
/// Map a UDP port.
pub const PMP_OP_MAP_UDP: u8 = 1;

/// A NAT-PMP request is 12 bytes: version, opcode, reserved, internal port,
/// requested external port, lifetime.
pub fn pmp_request(
    opcode: u8,
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = 0; // version
    out[1] = opcode;
    // out[2] reserved, zero
    out[4..6].copy_from_slice(&internal_port.to_be_bytes());
    out[6..8].copy_from_slice(&external_port.to_be_bytes());
    out[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    out
}

/// A gateway's mapping result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmpMapping {
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime_secs: u32,
}

/// Parse a NAT-PMP external-address response (opcode 128).
pub fn parse_pmp_external_address(resp: &[u8]) -> Result<SocketAddr, UpnpError> {
    check_pmp_header(resp, PMP_OP_EXTERNAL_ADDRESS + 128)?;
    if resp.len() < 12 {
        return Err(UpnpError::Malformed("short external-address reply"));
    }
    let ip = Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11]);
    // No port is carried: the caller pairs this with the port it mapped.
    Ok(SocketAddr::new(IpAddr::V4(ip), 0))
}

/// Parse a NAT-PMP map response (opcode 129).
pub fn parse_pmp_map_response(resp: &[u8]) -> Result<PmpMapping, UpnpError> {
    check_pmp_header(resp, PMP_OP_MAP_UDP + 128)?;
    if resp.len() < 16 {
        return Err(UpnpError::Malformed("short map reply"));
    }
    Ok(PmpMapping {
        internal_port: u16::from_be_bytes([resp[4], resp[5]]),
        external_port: u16::from_be_bytes([resp[6], resp[7]]),
        lifetime_secs: u32::from_be_bytes([resp[8], resp[9], resp[10], resp[11]]),
    })
}

/// The version, opcode and result code every NAT-PMP reply shares.
fn check_pmp_header(resp: &[u8], expected_opcode: u8) -> Result<(), UpnpError> {
    if resp.len() < 4 {
        return Err(UpnpError::Malformed("truncated NAT-PMP reply"));
    }
    if resp[0] != 0 {
        return Err(UpnpError::UnsupportedVersion(resp[0]));
    }
    if resp[1] != expected_opcode {
        return Err(UpnpError::Malformed("unexpected NAT-PMP opcode"));
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    let lifetime = if resp.len() >= 12 {
        u32::from_be_bytes([resp[8], resp[9], resp[10], resp[11]])
    } else {
        0
    };
    if result != 0 {
        // A zero lifetime with a non-zero result means the port could not be
        // mapped; the codes are the value in the result field (RFC 6886 §3.5).
        return Err(UpnpError::Refused(
            format!("result code {result}"),
            describe_pmp_code(result),
        ));
    }
    if lifetime == 0 {
        return Err(UpnpError::Refused(
            "lifetime 0".to_string(),
            "the gateway granted a mapping that expires immediately".to_string(),
        ));
    }
    Ok(())
}

/// Human-readable NAT-PMP result codes (RFC 6886 §3.5).
pub fn describe_pmp_code(code: u16) -> String {
    match code {
        0 => "success".to_string(),
        1 => "unsupported version".to_string(),
        2 => "not authorized to create the mapping".to_string(),
        3 => "network failure".to_string(),
        4 => "out of resources".to_string(),
        5 => "unsupported opcode".to_string(),
        other => format!("unknown code {other}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Network paths
// ═════════════════════════════════════════════════════════════════════════════

/// Ask the local link for an internet gateway and return its control endpoint.
pub async fn discover_igd(timeout: Duration) -> Result<IgdControl, UpnpError> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    let search = ssdp_search();
    let multicast: SocketAddr = SSDP_MULTICAST.parse().expect("SSDP_MULTICAST is a literal");
    if let Err(e) = sock.send_to(search.as_bytes(), multicast).await {
        debug!("UPnP: SSDP search could not be sent: {e}");
        return Err(UpnpError::NoGateway);
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = vec![0u8; 2048];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(UpnpError::NoGateway);
        }
        let (n, from) = match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(UpnpError::Io(e.to_string())),
            Err(_) => return Err(UpnpError::NoGateway),
        };
        let Ok(text) = std::str::from_utf8(&buf[..n]) else {
            continue;
        };
        let Some(location) = parse_ssdp_location(text) else {
            continue;
        };
        debug!(gateway = %from, %location, "UPnP: internet gateway answered");
        let description = http_get(&location, timeout).await?;
        match find_wan_control(&description, &location) {
            Some(control) => {
                info!(
                    gateway = %from,
                    service = %control.service_type,
                    "UPnP: WAN connection service located"
                );
                return Ok(control);
            }
            None => {
                debug!(gateway = %from, "UPnP: description has no WAN connection service");
            }
        }
    }
}

/// `GET` a URL and return the body, reading to EOF.
async fn http_get(url: &str, timeout: Duration) -> Result<String, UpnpError> {
    let (host, path) = split_url(url).ok_or(UpnpError::Malformed("unusable device URL"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let response = http_exchange(&host, &request, timeout).await?;
    Ok(http_body(&response).to_string())
}

/// Send a raw HTTP request and read the whole response.
async fn http_exchange(host: &str, request: &str, timeout: Duration) -> Result<String, UpnpError> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(host))
        .await
        .map_err(|_| UpnpError::Io("connect timed out".to_string()))?
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    let mut stream = stream;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = match tokio::time::timeout(timeout, stream.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(UpnpError::Io(e.to_string())),
            Err(_) => break, // the gateway simply did not close; take what we have
        };
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        // Descriptions and SOAP replies are small; stop rather than grow without
        // bound on a gateway that streams.
        if response.len() > 128 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&response).into_owned())
}

/// Split `http://host:port/path` into a `host:port` and a path.
fn split_url(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), path.to_string()))
}

/// Map `internal_port` for UDP through the discovered gateway and return the
/// public address it granted.
pub async fn map_udp_port_via_igd(
    control: &IgdControl,
    internal_ip: Ipv4Addr,
    internal_port: u16,
    lifetime_secs: u32,
    timeout: Duration,
) -> Result<Mapping, UpnpError> {
    let args = add_port_mapping_args(
        internal_port,
        internal_ip,
        internal_port,
        lifetime_secs,
        "ggn",
    );
    let body = soap_envelope(&control.service_type, "AddPortMapping", &args);
    let request = soap_http_request(control, "AddPortMapping", &body);
    let response = http_exchange(&control.host, &request, timeout).await?;
    let body = http_body(&response);
    if let Some((code, description)) = parse_soap_fault(body) {
        return Err(UpnpError::Refused(code, description));
    }
    if !body.contains("AddPortMappingResponse") {
        return Err(UpnpError::Malformed(
            "reply is not an AddPortMapping response",
        ));
    }
    // The mapping succeeded; ask what address it is reachable at.
    let ip_args = "<NewRemoteHost></NewRemoteHost>";
    let ip_body = soap_envelope(&control.service_type, "GetExternalIPAddress", ip_args);
    let ip_request = soap_http_request(control, "GetExternalIPAddress", &ip_body);
    let ip_response = http_exchange(&control.host, &ip_request, timeout).await?;
    let external_ip = parse_external_ip(http_body(&ip_response)).ok_or(UpnpError::Malformed(
        "gateway did not report a public address",
    ))?;
    Ok(Mapping {
        external: SocketAddr::new(IpAddr::V4(external_ip), internal_port),
        internal_port,
        lifetime_secs,
    })
}

/// Remove a mapping we created.
pub async fn delete_udp_mapping(
    control: &IgdControl,
    internal_port: u16,
    timeout: Duration,
) -> Result<(), UpnpError> {
    let args = delete_port_mapping_args(internal_port);
    let body = soap_envelope(&control.service_type, "DeletePortMapping", &args);
    let request = soap_http_request(control, "DeletePortMapping", &body);
    let response = http_exchange(&control.host, &request, timeout).await?;
    let body = http_body(&response);
    match parse_soap_fault(body) {
        Some((code, description)) => Err(UpnpError::Refused(code, description)),
        None => Ok(()),
    }
}

/// The default gateway, read from `/proc/net/route` where that exists.
///
/// NAT-PMP has no discovery step: the protocol is addressed to the default
/// gateway, so the gateway address *is* the discovery. On platforms without
/// `/proc` this returns `None` and UPnP-IGD is the only route — which is why the
/// SSDP path is tried first.
pub fn default_gateway_ipv4() -> Option<Ipv4Addr> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in route.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        // Destination 00000000 is the default route.
        if fields[1] != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(fields[2], 16).ok()?;
        // /proc writes the address little-endian as a u32.
        let bytes = raw.to_le_bytes();
        if bytes == [0, 0, 0, 0] {
            continue;
        }
        return Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
    }
    None
}

/// Ask a NAT-PMP gateway to map `internal_port` for UDP.
///
/// Retries follow RFC 6886 §3.3: three attempts, doubling the wait each time, and
/// no retry once a response (including an error response) arrives.
pub async fn nat_pmp_map_udp(
    gateway: Ipv4Addr,
    internal_port: u16,
    lifetime_secs: u32,
    timeout: Duration,
) -> Result<Mapping, UpnpError> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    let dest = SocketAddr::new(IpAddr::V4(gateway), NAT_PMP_PORT);
    let request = pmp_request(PMP_OP_MAP_UDP, internal_port, internal_port, lifetime_secs);

    let mut buf = vec![0u8; 64];
    let deadline = tokio::time::Instant::now() + timeout;
    let mut wait = Duration::from_millis(250);
    for _ in 0..3 {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        if sock.send_to(&request, dest).await.is_err() {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(wait.min(remaining), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) if from.ip() == IpAddr::V4(gateway) => {
                let mapping = parse_pmp_map_response(&buf[..n])?;
                // The external address comes from a separate rendezvous.
                let addr_request = pmp_request(PMP_OP_EXTERNAL_ADDRESS, 0, 0, 0);
                sock.send_to(&addr_request, dest)
                    .await
                    .map_err(|e| UpnpError::Io(e.to_string()))?;
                let external_ip = match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) => parse_pmp_external_address(&buf[..n])
                        .map(|a| a.ip())
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                };
                return Ok(Mapping {
                    external: SocketAddr::new(external_ip, mapping.external_port),
                    internal_port: mapping.internal_port,
                    lifetime_secs: mapping.lifetime_secs,
                });
            }
            _ => {
                wait *= 2;
            }
        }
    }
    Err(UpnpError::NoGateway)
}

/// Best effort: try UPnP-IGD, then NAT-PMP, and return the public address the
/// gateway opened for `local_port`.
///
/// Nothing here is required for the tunnel to work. A failure is expected on most
/// networks — upnp disabled, an enterprise gateway, a CGNAT — so the caller logs
/// and carries on with STUN/ICE.
pub async fn opportunistic_public_addr(local_ip: Ipv4Addr, local_port: u16) -> Option<SocketAddr> {
    let timeout = Duration::from_secs(2);

    // The gateway's LAN address is where a NAT-PMP request goes, and it is also
    // the most likely owner of the control URL; try IGD first because it needs
    // no guess at all.
    match discover_igd(timeout).await {
        Ok(control) => {
            match map_udp_port_via_igd(
                &control,
                local_ip,
                local_port,
                DEFAULT_LIFETIME_SECS,
                timeout,
            )
            .await
            {
                Ok(mapping) => {
                    info!(public = %mapping.external, "UPnP: gateway mapped a UDP port for us");
                    return Some(mapping.external);
                }
                Err(e) => debug!("UPnP: mapping refused or failed: {e}"),
            }
        }
        Err(e) => debug!("UPnP: no internet gateway found: {e}"),
    }

    let Some(gateway) = default_gateway_ipv4() else {
        debug!("UPnP: no default gateway to ask with NAT-PMP");
        return None;
    };
    match nat_pmp_map_udp(gateway, local_port, DEFAULT_LIFETIME_SECS, timeout).await {
        Ok(mapping) => {
            info!(public = %mapping.external, gateway = %gateway, "NAT-PMP: gateway mapped a UDP port for us");
            Some(mapping.external)
        }
        Err(e) => {
            debug!("NAT-PMP: mapping failed: {e}");
            None
        }
    }
}

/// Keep a mapping alive for as long as the node runs.
///
/// A lease is not permanent: the gateway hands back however long it is willing to
/// grant, and takes the mapping away when it expires. Renewing every half of the
/// granted lifetime leaves room for one attempt to be lost before the mapping
/// does — renewing at the deadline would mean a gap whenever a packet is dropped.
pub async fn renew_udp_mapping(local_ip: Ipv4Addr, local_port: u16) {
    loop {
        let Some(public) = opportunistic_public_addr(local_ip, local_port).await else {
            // Nothing to renew; try again later rather than spinning.
            tokio::time::sleep(Duration::from_secs(300)).await;
            continue;
        };
        debug!(public = %public, "UPnP/NAT-PMP: mapping renewed");
        tokio::time::sleep(Duration::from_secs((DEFAULT_LIFETIME_SECS / 2) as u64)).await;
    }
}

/// Log the outcome of an opportunistic attempt in the terms an operator needs.
pub fn describe_attempt(public: Option<SocketAddr>) -> String {
    match public {
        Some(addr) => format!("gateway mapping granted: {addr} (no hole punching needed)"),
        None => "no gateway mapping available — falling back to STUN/ICE".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSDP_REPLY: &str = "HTTP/1.1 200 OK\r\n\
        CACHE-CONTROL: max-age=120\r\n\
        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
        LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\
        SERVER: Linux/3.4 UPnP/1.0 MiniUPnPd/1.9\r\n\
        \r\n";

    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
        <controlURL>/ctl/L3F</controlURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl/IPConn</controlURL>
      </service>
    </serviceList>
  </device>
</root>"#;

    #[test]
    fn the_search_asks_for_gateway_devices_over_multicast() {
        let s = ssdp_search();
        assert!(s.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(s.contains("MAN: \"ssdp:discover\""));
        assert!(s.contains(&format!("HOST: {SSDP_MULTICAST}")));
        assert!(s.contains(SSDP_ST));
        assert!(
            s.ends_with("\r\n\r\n"),
            "the request must end with a blank line"
        );
    }

    #[test]
    fn a_location_is_read_from_a_response_but_not_from_a_notification() {
        assert_eq!(
            parse_ssdp_location(SSDP_REPLY).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
        // Header name case varies between stacks.
        let lower = SSDP_REPLY.replace("LOCATION:", "location:");
        assert!(
            parse_ssdp_location(&lower).is_some(),
            "headers are case-insensitive"
        );
        // A `NOTIFY` is a device announcing itself unprompted: not our answer.
        let notify = SSDP_REPLY.replace("HTTP/1.1 200 OK", "NOTIFY * HTTP/1.1");
        assert_eq!(parse_ssdp_location(&notify), None);
        // A 404 from a device that is not an IGD carries no location.
        assert_eq!(parse_ssdp_location("HTTP/1.1 404 Not Found\r\n\r\n"), None);
    }

    #[test]
    fn the_wan_connection_service_is_found_and_others_are_not() {
        let control = find_wan_control(DESCRIPTION, "http://192.168.1.1:5000/rootDesc.xml")
            .expect("the description names a WAN connection service");
        assert_eq!(
            control.service_type,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );
        assert_eq!(control.control_url, "http://192.168.1.1:5000/ctl/IPConn");
        assert_eq!(control.host, "192.168.1.1:5000");
        // Layer3Forwarding is a service in the same description and must not be
        // mistaken for one we can map a port on.
        assert!(!control.control_url.contains("L3F"));
        // A description with no WAN service yields nothing rather than a guess.
        let no_wan = DESCRIPTION.replace("WANIPConnection", "WANIPv6FirewallControl");
        assert_eq!(
            find_wan_control(&no_wan, "http://192.168.1.1:5000/rootDesc.xml"),
            None
        );
    }

    #[test]
    fn a_control_url_pointing_at_another_host_is_refused() {
        // The description is on the gateway; a control URL on a different origin
        // is not something to send a mapping request to.
        assert_eq!(
            resolve_control_url(
                "http://192.168.1.1:5000/rootDesc.xml",
                "http://10.0.0.9/ctl"
            ),
            None
        );
        // Absolute URLs on the same origin are fine, and so are both relative
        // forms — real devices use all three.
        assert!(resolve_control_url(
            "http://192.168.1.1:5000/d/x.xml",
            "http://192.168.1.1:5000/ctl"
        )
        .is_some());
        assert_eq!(
            resolve_control_url("http://192.168.1.1:5000/d/x.xml", "ctl/IPConn"),
            Some((
                "http://192.168.1.1:5000/d/ctl/IPConn".to_string(),
                "192.168.1.1:5000".to_string()
            ))
        );
        // Not a URL at all.
        assert_eq!(resolve_control_url("192.168.1.1:5000/x.xml", "/ctl"), None);
    }

    #[test]
    fn the_soap_call_carries_the_action_the_service_and_a_real_length() {
        let control = IgdControl {
            service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
            control_url: "http://192.168.1.1:5000/ctl/IPConn".to_string(),
            host: "192.168.1.1:5000".to_string(),
        };
        let args = add_port_mapping_args(2270, Ipv4Addr::new(192, 168, 1, 50), 2270, 3600, "ggn");
        let body = soap_envelope(&control.service_type, "AddPortMapping", &args);
        assert!(body.contains(
            "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection\">"
        ));
        assert!(body.contains("<NewExternalPort>2270</NewExternalPort>"));
        assert!(body.contains("<NewInternalClient>192.168.1.50</NewInternalClient>"));
        assert!(body.contains("<NewProtocol>UDP</NewProtocol>"));
        assert!(body.contains("<NewLeaseDuration>3600</NewLeaseDuration>"));

        let request = soap_http_request(&control, "AddPortMapping", &body);
        assert!(request.starts_with("POST /ctl/IPConn HTTP/1.1\r\n"));
        assert!(request.contains("Host: 192.168.1.1:5000\r\n"));
        assert!(request.contains(
            "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\""
        ));
        // A wrong Content-Length makes the call hang or truncate; the framing is
        // the part of a hand-rolled client that actually breaks.
        assert!(request.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(request.contains("Connection: close\r\n"));
        assert_eq!(request.split("\r\n\r\n").nth(1), Some(body.as_str()));
    }

    #[test]
    fn a_soap_fault_and_a_public_address_are_both_read_correctly() {
        let ok = "<?xml version=\"1.0\"?><s:Envelope><s:Body>\
            <u:GetExternalIPAddressResponse><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>\
            </u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(
            parse_external_ip(ok),
            Some(Ipv4Addr::new(203, 0, 113, 7)),
            "the element must be read with its attributes ignored"
        );
        assert_eq!(parse_soap_fault(ok), None, "a success is not a fault");

        let fault = "HTTP/1.1 500 Internal Server Error\r\n\r\n\
            <s:Envelope><s:Body><s:Fault><detail>\
            <UPnPError><errorCode>718</errorCode>\
            <errorDescription>ConflictInMappingEntry</errorDescription>\
            </UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        let body = http_body(fault);
        assert_eq!(
            parse_soap_fault(body),
            Some(("718".to_string(), "ConflictInMappingEntry".to_string()))
        );
        // A body with no address yields None rather than a zero address.
        assert_eq!(parse_external_ip(body), None);
    }

    #[test]
    fn http_bodies_are_read_after_the_header_block() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(http_body(response), "hello");
        assert_eq!(http_body("no header block at all"), "");
    }

    #[test]
    fn a_nat_pmp_request_is_twelve_bytes_in_network_order() {
        let req = pmp_request(PMP_OP_MAP_UDP, 2270, 2270, 3600);
        assert_eq!(req.len(), 12);
        assert_eq!(req[0], 0, "version 0");
        assert_eq!(req[1], 1, "opcode 1 is \"map UDP\" (RFC 6886 §3.5)");
        assert_eq!(&req[2..4], &[0, 0], "reserved");
        assert_eq!(u16::from_be_bytes([req[4], req[5]]), 2270, "internal port");
        assert_eq!(
            u16::from_be_bytes([req[6], req[7]]),
            2270,
            "suggested external port"
        );
        assert_eq!(u32::from_be_bytes([req[8], req[9], req[10], req[11]]), 3600);
    }

    #[test]
    fn nat_pmp_replies_are_parsed_and_refusals_are_not_successes() {
        // A granted mapping: opcode 129, result 0, ports, lifetime, then the
        // external address.
        let mut reply = vec![0u8, 129, 0, 0];
        reply.extend_from_slice(&2270u16.to_be_bytes());
        reply.extend_from_slice(&41000u16.to_be_bytes());
        reply.extend_from_slice(&3600u32.to_be_bytes());
        reply.extend_from_slice(&[203, 0, 113, 7]);
        let mapping = parse_pmp_map_response(&reply).expect("a granted mapping must parse");
        assert_eq!(mapping.external_port, 41000);
        assert_eq!(mapping.lifetime_secs, 3600);

        // The external address arrives in its own reply, with a zero port.
        let addr_reply = vec![0u8, 128, 0, 0, 0, 0, 0, 0, 203, 0, 113, 7];
        assert_eq!(
            parse_pmp_external_address(&addr_reply).map(|a| a.ip()),
            Ok(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        );

        // Result code 2 is "not authorized": granting a mapping here would be a
        // lie, and the caller would advertise an address nobody can reach.
        let mut refused = reply.clone();
        refused[3] = 2;
        match parse_pmp_map_response(&refused) {
            Err(UpnpError::Refused(code, description)) => {
                assert_eq!(code, "result code 2");
                assert!(description.contains("not authorized"));
            }
            other => panic!("a refusal must not parse as a mapping: {other:?}"),
        }

        // A lifetime of zero means the mapping is already gone.
        let mut expired = reply.clone();
        expired[8..12].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            parse_pmp_map_response(&expired),
            Err(UpnpError::Refused(_, _))
        ));

        // Version and opcode mismatches are rejected rather than reinterpreted.
        let bad_version = [1u8, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_pmp_map_response(&bad_version),
            Err(UpnpError::UnsupportedVersion(1))
        );
        assert!(matches!(
            parse_pmp_map_response(&[0u8, 130, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(UpnpError::Malformed(_))
        ));
        assert!(matches!(
            parse_pmp_map_response(&[0u8, 129]),
            Err(UpnpError::Malformed(_))
        ));
    }

    #[test]
    fn the_attempt_is_described_in_operator_terms() {
        let granted = describe_attempt(Some("203.0.113.7:2270".parse().unwrap()));
        assert!(granted.contains("203.0.113.7:2270"));
        assert!(granted.contains("no hole punching needed"));
        assert!(describe_attempt(None).contains("STUN/ICE"));
    }

    #[test]
    fn elements_are_read_without_matching_a_longer_tag_name() {
        // `<serviceType>` must not be found by looking for `<service`.
        let xml =
            "<service><serviceTypeX>nope</serviceTypeX><serviceType>yes</serviceType></service>";
        assert_eq!(element(xml, "serviceType"), Some("yes"));
        assert_eq!(element(xml, "missing"), None);
        // A self-closing element carries no text.
        assert_eq!(element("<a/><b>1</b>", "a"), None);
    }
}
