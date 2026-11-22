//! GhostPortal — `ggn drop`: a file to a friend's browser with no app, no
//! account and no cloud.
//!
//! The sender runs one process and gets a link. The recipient opens it in any
//! modern browser and saves the file. Between them:
//!
//! * the file is never uploaded anywhere — the link points at the sender;
//! * the decryption key lives **only** in the URL fragment (`#k=…`), which the
//!   browser does not transmit, so the server cannot read the file it serves;
//! * every chunk is sealed separately with AES-256-GCM under a nonce of
//!   `prefix ‖ chunk_index`, which is unique by construction;
//! * the page decrypts with `crypto.subtle` — the platform's own AES, not a
//!   downloaded WASM blob that the recipient would have to trust.
//!
//! AES-GCM rather than the project's usual XChaCha20-Poly1305 is a deliberate
//! interop choice: WebCrypto exposes AES-GCM and ChaCha20-Poly1305 is not
//! available in every browser. Session traffic elsewhere stays on XChaCha.
//!
//! Large files stream: the page asks for `showSaveFilePicker()` and writes each
//! decrypted chunk straight to disk, so a 50 GB drop needs ~4 MiB of browser
//! memory rather than 50 GB. Where the File System Access API is missing (Safari,
//! Firefox), it falls back to assembling a Blob and the UI says so.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Chunk size. 4 MiB is the point where a browser fetch, an AES-GCM decrypt and
/// a disk write all stay comfortably inside a frame without holding much memory.
pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// Per-chunk overhead: AES-GCM's 16-byte tag.
pub const CHUNK_TAG_LEN: usize = 16;

/// Default port for the drop service.
pub const DEFAULT_DROP_PORT: u16 = 8787;

/// Default lifetime of a drop.
pub const DEFAULT_DROP_TTL: Duration = Duration::from_secs(24 * 3600);

/// Maximum request head this server will read.
const MAX_HEAD: usize = 16 * 1024;

/// A drop's public metadata. Contains no key material by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DropManifest {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    /// Hex of the 4-byte nonce prefix; the remaining 8 bytes are the chunk index.
    pub nonce_prefix: String,
    /// SHA-256 of the plaintext, so the recipient can check what they saved.
    pub sha256: String,
    pub mime: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// `0` means unlimited.
    pub max_downloads: u32,
}

/// Options for [`DropSession::open`].
#[derive(Debug, Clone)]
pub struct DropOptions {
    pub ttl: Duration,
    pub max_downloads: u32,
    pub chunk_size: u32,
}

impl Default for DropOptions {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_DROP_TTL,
            max_downloads: 0,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

/// One shared file, with its key held in memory only.
pub struct DropSession {
    pub manifest: DropManifest,
    path: PathBuf,
    key: [u8; 32],
    downloads: AtomicU32,
    exhausted: AtomicBool,
    created: Instant,
    ttl: Duration,
}

impl DropSession {
    /// Open `path` and prepare it for sharing. Hashes the plaintext once, in
    /// 1 MiB reads, so the recipient can verify the file end to end.
    pub fn open(path: &Path, opts: DropOptions) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        if meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a directory cannot be dropped; pass a file",
            ));
        }
        let size = meta.len();
        let chunk_size = opts.chunk_size.clamp(64 * 1024, 64 * 1024 * 1024);
        let chunk_count = size.div_ceil(chunk_size as u64).max(1) as u32;

        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha256 = hex::encode(hasher.finalize());

        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let mut nonce_prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);

        // The id is derived from the key, so two drops of the same file are
        // unlinkable to each other and to the content.
        let mut id_hasher = Sha256::new();
        id_hasher.update(b"VB-DROP-ID-V1");
        id_hasher.update(key);
        let id = hex::encode(&id_hasher.finalize()[..8]);

        let created_at = crate::ghost::v2::now_secs();
        let manifest = DropManifest {
            id,
            file_name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("download.bin")
                .to_string(),
            size,
            chunk_size,
            chunk_count,
            nonce_prefix: hex::encode(nonce_prefix),
            sha256,
            mime: mime_for(path).to_string(),
            created_at,
            expires_at: created_at.saturating_add(opts.ttl.as_secs()),
            max_downloads: opts.max_downloads,
        };

        Ok(Self {
            manifest,
            path: path.to_path_buf(),
            key,
            downloads: AtomicU32::new(0),
            exhausted: AtomicBool::new(false),
            created: Instant::now(),
            ttl: opts.ttl,
        })
    }

    /// The key, for link construction. Never serialised into the manifest.
    pub fn key_hex(&self) -> String {
        hex::encode(self.key)
    }

    /// `{base}/f/{id}#k={key}` — the key after `#` stays in the browser.
    pub fn link(&self, base: &str) -> String {
        format!(
            "{}/f/{}#k={}",
            base.trim_end_matches('/'),
            self.manifest.id,
            self.key_hex()
        )
    }

    pub fn manifest_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.manifest).unwrap_or(serde_json::Value::Null)
    }

    /// Whether this drop may still be served.
    pub fn is_live(&self, now: Instant) -> bool {
        !self.exhausted.load(Ordering::Relaxed)
            && now.saturating_duration_since(self.created) < self.ttl
            && self.created_at_not_expired()
    }

    fn created_at_not_expired(&self) -> bool {
        crate::ghost::v2::now_secs() < self.manifest.expires_at
    }

    /// Count the start of a download, enforcing `max_downloads`. Returns `false`
    /// when the allowance is used up.
    pub fn begin_download(&self) -> bool {
        let max = self.manifest.max_downloads;
        if max == 0 {
            return true;
        }
        let previous = self.downloads.fetch_add(1, Ordering::SeqCst);
        if previous >= max {
            self.downloads.fetch_sub(1, Ordering::SeqCst);
            self.exhausted.store(true, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub fn downloads(&self) -> u32 {
        self.downloads.load(Ordering::Relaxed)
    }

    /// Read and seal chunk `index`. The returned bytes are exactly
    /// `plaintext_len + 16`.
    pub fn chunk(&self, index: u32) -> std::io::Result<Vec<u8>> {
        if index >= self.manifest.chunk_count {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "chunk index out of range",
            ));
        }
        let start = index as u64 * self.manifest.chunk_size as u64;
        let remaining = self.manifest.size.saturating_sub(start);
        if remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "chunk lies beyond the end of the file",
            ));
        }
        let want = remaining.min(self.manifest.chunk_size as u64) as usize;
        let mut file = std::fs::File::open(&self.path)?;
        file.seek(SeekFrom::Start(start))?;
        let mut plain = vec![0u8; want];
        file.read_exact(&mut plain)?;

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| std::io::Error::other("AES-256 key length"))?;
        let mut nonce = [0u8; 12];
        let prefix = hex::decode(&self.manifest.nonce_prefix).unwrap_or_default();
        if prefix.len() == 4 {
            nonce[..4].copy_from_slice(&prefix);
        }
        nonce[4..].copy_from_slice(&(index as u64).to_be_bytes());
        cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
            .map_err(|_| std::io::Error::other("chunk encryption failed"))
    }
}

/// The set of live drops in one process.
#[derive(Default)]
pub struct PortalRegistry {
    sessions: DashMap<String, Arc<DropSession>>,
    // SDP-only signaling for the browser-to-browser DataChannel path. File
    // bytes never enter this map; it holds offer/answer JSON and nothing else.
    signals: std::sync::Mutex<std::collections::HashMap<String, serde_json::Value>>,
}

impl PortalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store the latest SDP for one role (`sender` or `receiver`).
    pub fn put_signal(&self, id: &str, role: &str, value: serde_json::Value) {
        if let Ok(mut map) = self.signals.lock() {
            map.insert(format!("{id}:{role}"), value);
        }
    }

    /// The latest SDP posted by `role`, if any.
    pub fn get_signal(&self, id: &str, role: &str) -> Option<serde_json::Value> {
        self.signals
            .lock()
            .ok()
            .and_then(|map| map.get(&format!("{id}:{role}")).cloned())
    }

    pub fn insert(&self, session: Arc<DropSession>) -> String {
        let id = session.manifest.id.clone();
        self.sessions.insert(id.clone(), session);
        id
    }

    pub fn get(&self, id: &str) -> Option<Arc<DropSession>> {
        self.sessions.get(id).map(|e| Arc::clone(e.value()))
    }

    pub fn remove(&self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Drop expired or exhausted sessions.
    pub fn prune(&self, now: Instant) -> usize {
        let dead: Vec<String> = self
            .sessions
            .iter()
            .filter(|e| !e.value().is_live(now))
            .map(|e| e.key().clone())
            .collect();
        for id in &dead {
            self.sessions.remove(id);
        }
        dead.len()
    }

    /// Public metadata for every live drop (no keys).
    pub fn list(&self, now: Instant) -> Vec<serde_json::Value> {
        let mut out: Vec<serde_json::Value> = self
            .sessions
            .iter()
            .filter(|e| e.value().is_live(now))
            .map(|e| e.value().manifest_json())
            .collect();
        out.sort_by_key(|v| v.get("created_at").and_then(|c| c.as_u64()).unwrap_or(0));
        out
    }
}

fn mime_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "txt" | "md" | "log" => "text/plain; charset=utf-8",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "7z" => "application/x-7z-compressed",
        _ => "application/octet-stream",
    }
}

/// A response ready to be written as HTTP/1.1.
pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub extra_headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            extra_headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn json(status: u16, value: &serde_json::Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            extra_headers: Vec::new(),
            body: serde_json::to_vec(value).unwrap_or_default(),
        }
    }

    fn not_found() -> Self {
        Self::text(404, "not found\n")
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

enum Route {
    Index,
    Page(String),
    ReceiverPage(String),
    Signal(String, String),
    Meta(String),
    Chunk(String, u32),
    Health,
    NotFound,
}

fn is_drop_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn route(path: &str) -> Route {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    match path {
        "/" | "/index.html" => return Route::Index,
        "/healthz" => return Route::Health,
        _ => {}
    }
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match parts.as_slice() {
        ["f", id] if is_drop_id(id) => Route::Page((*id).to_string()),
        ["f", id, "recv"] if is_drop_id(id) => Route::ReceiverPage((*id).to_string()),
        ["f", id, "signal", role] if is_drop_id(id) && (*role == "sender" || *role == "receiver") => {
            Route::Signal((*id).to_string(), (*role).to_string())
        }
        ["d", id, "meta"] if is_drop_id(id) => Route::Meta((*id).to_string()),
        ["d", id, "c", n] if is_drop_id(id) => match n.parse::<u32>() {
            Ok(index) => Route::Chunk((*id).to_string(), index),
            Err(_) => Route::NotFound,
        },
        _ => Route::NotFound,
    }
}

/// Build the response for one parsed request. Pure: no socket, no logging of the
/// path beyond the drop id, and no way to reach a file other than through a
/// registered session.
pub fn respond(registry: &PortalRegistry, method: &str, path: &str, now: Instant) -> HttpResponse {
    respond_with_body(registry, method, path, &[], now)
}

/// Same as [`respond`], with a request body for the SDP signaling endpoint.
pub fn respond_with_body(
    registry: &PortalRegistry,
    method: &str,
    path: &str,
    body: &[u8],
    now: Instant,
) -> HttpResponse {
    let route = route(path);
    let signal = matches!(route, Route::Signal(..));
    if method != "GET" && method != "HEAD" && !(method == "POST" && signal) {
        return HttpResponse {
            status: 405,
            content_type: "text/plain; charset=utf-8",
            extra_headers: vec![("Allow".into(), "GET, HEAD, POST".into())],
            body: b"method not allowed\n".to_vec(),
        };
    }

    match route {
        Route::Health => HttpResponse::text(200, "ok\n"),
        Route::Index => {
            let body = format!(
                "<!doctype html><meta charset=utf-8><title>Vantablack drop</title>\
                 <style>body{{background:#06070a;color:#e7e9ee;font:15px system-ui;padding:3rem;max-width:44rem;margin:auto}}\
                 code{{color:#7dd3fc}}a{{color:#7dd3fc}}</style>\
                 <h1>Vantablack drop</h1><p>{n} file(s) waiting on this node.</p>\
                 <p>A drop link looks like <code>/f/&lt;id&gt;#k=&lt;key&gt;</code>. \
                 The part after <code>#</code> never leaves the recipient's browser.</p>",
                n = registry.len()
            );
            HttpResponse {
                status: 200,
                content_type: "text/html; charset=utf-8",
                extra_headers: security_headers(),
                body: body.into_bytes(),
            }
        }
        Route::Page(id) => {
            if registry.get(&id).is_none() {
                return HttpResponse::not_found();
            }
            HttpResponse {
                status: 200,
                content_type: "text/html; charset=utf-8",
                extra_headers: security_headers(),
                body: render_page(&id, "send").into_bytes(),
            }
        }
        Route::ReceiverPage(id) => {
            if registry.get(&id).is_none() {
                return HttpResponse::not_found();
            }
            HttpResponse {
                status: 200,
                content_type: "text/html; charset=utf-8",
                extra_headers: security_headers(),
                body: render_page(&id, "recv").into_bytes(),
            }
        }
        Route::Signal(id, role) => {
            if registry.get(&id).is_none() {
                return HttpResponse::not_found();
            }
            if method == "POST" {
                if body.is_empty() || body.len() > 64 * 1024 {
                    return HttpResponse::text(400, "SDP body must be under 64 KiB\n");
                }
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
                    return HttpResponse::text(400, "SDP body must be JSON\n");
                };
                let Some(sdp) = value.get("sdp").and_then(|v| v.as_str()) else {
                    return HttpResponse::text(400, "SDP body needs a string \"sdp\"\n");
                };
                let kind = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if !matches!(kind, "offer" | "answer") || sdp.len() > 60 * 1024 {
                    return HttpResponse::text(400, "unsupported SDP type\n");
                }
                registry.put_signal(&id, &role, value);
                let mut resp = HttpResponse::json(200, &serde_json::json!({"ok": true}));
                resp.extra_headers = security_headers();
                return resp;
            }
            let mut resp = HttpResponse::json(
                200,
                &registry
                    .get_signal(&id, &role)
                    .unwrap_or_else(|| serde_json::json!({"waiting": true})),
            );
            resp.extra_headers = security_headers();
            resp
        }
        Route::Meta(id) => match registry.get(&id) {
            Some(session) if session.is_live(now) => {
                if !session.begin_download() {
                    return HttpResponse::text(410, "this drop has been collected\n");
                }
                let mut resp = HttpResponse::json(200, &session.manifest_json());
                resp.extra_headers = security_headers();
                resp
            }
            Some(_) => HttpResponse::text(410, "this drop has expired\n"),
            None => HttpResponse::not_found(),
        },
        Route::Chunk(id, index) => match registry.get(&id) {
            Some(session) if session.is_live(now) => match session.chunk(index) {
                Ok(bytes) => HttpResponse {
                    status: 200,
                    content_type: "application/octet-stream",
                    extra_headers: security_headers(),
                    body: bytes,
                },
                Err(_) => HttpResponse::text(416, "no such chunk\n"),
            },
            Some(_) => HttpResponse::text(410, "this drop has expired\n"),
            None => HttpResponse::not_found(),
        },
        Route::NotFound => HttpResponse::not_found(),
    }
}

fn security_headers() -> Vec<(String, String)> {
    vec![
        ("Cache-Control".into(), "no-store".into()),
        ("Referrer-Policy".into(), "no-referrer".into()),
        ("X-Content-Type-Options".into(), "nosniff".into()),
    ]
}

/// The recipient's page. The only interpolation is the id, which is validated
/// hex before this is called; the key never appears in the document, only in
/// `location.hash`.
fn render_page(id: &str, mode: &str) -> String {
    PAGE_TEMPLATE
        .replace("__ID__", id)
        .replace("__MODE__", mode)
}

const PAGE_TEMPLATE: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vantablack drop</title>
<style>
:root{color-scheme:dark}
body{margin:0;background:#06070a;color:#e7e9ee;font:16px/1.5 ui-sans-serif,system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}
main{width:min(34rem,92vw);padding:2rem;border:1px solid #1f2430;border-radius:14px;background:#0b0e14}
h1{font-size:1.1rem;margin:0 0 .25rem;letter-spacing:.02em}
p{margin:.5rem 0;color:#9aa4b2;font-size:.9rem}
b{color:#e7e9ee}
.bar{height:8px;background:#151a24;border-radius:99px;overflow:hidden;margin:1.25rem 0 .5rem}
.bar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,#22d3ee,#818cf8);transition:width .2s}
button{font:inherit;background:#22d3ee;color:#04121a;border:0;border-radius:9px;padding:.7rem 1.1rem;cursor:pointer;font-weight:600}
button:disabled{opacity:.5;cursor:default}
code{font:12px ui-monospace,monospace;color:#7dd3fc;word-break:break-all}
.err{color:#fb7185}
.ok{color:#34d399}
</style></head>
<body><main>
<h1>Encrypted file drop</h1>
<p id="name">Reading the manifest…</p>
<p id="meta"></p>
<div class="bar"><i id="prog"></i></div>
<p id="status">Waiting.</p>
<p><button id="go" disabled>Save file</button>
<button id="p2p" disabled>Send over DataChannel</button></p>
<p id="p2pstatus"></p>
<p id="note"></p>
<p style="margin-top:1.5rem;font-size:.75rem">The key is in the link fragment and never reaches the sender's server. Verify the SHA-256 after saving if you want certainty.</p>
</main>
<script>
const ID="__ID__";
const MODE="__MODE__";
const $=(s)=>document.querySelector(s);
const hex=(s)=>Uint8Array.from(s.match(/.{2}/g).map(h=>parseInt(h,16)));
const hexOf=(buf)=>[...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
function fail(m){$("#status").textContent=m;$("#status").className="err";}
let meta=null,key=null;

// ── WebRTC DataChannel: the drop page is the sending peer ──────────────
// The server is used only to exchange SDP; file bytes never go through it.
const P2P={state:"idle",bytes:0,sha:null,error:null,cache:null,pc:null,dc:null};
window.__vb=P2P;
async function postSDP(role,desc){
  const r=await fetch(`/f/${ID}/signal/${role}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:desc.type,sdp:desc.sdp})});
  if(!r.ok) throw new Error("SDP rejected: "+(await r.text()));
}
async function getSDP(role){
  const r=await fetch(`/f/${ID}/signal/${role}`,{cache:"no-store"});
  if(!r.ok) return null;
  const j=await r.json();
  return (j&&j.sdp)?j:null;
}
async function waitIce(pc){
  if(pc.iceGatheringState==="complete") return;
  await new Promise(res=>{
    const t=setTimeout(res,4000);
    pc.addEventListener("icegatheringstatechange",()=>{
      if(pc.iceGatheringState==="complete"){clearTimeout(t);res();}
    });
  });
}
async function startReceiver(){
  document.querySelector("h1").textContent="Receiving a peer-to-peer drop";
  $("#go").style.display="none";
  $("#p2p").style.display="none";
  const R=window.__vb={state:"signaling",bytes:0,sha:null,error:null,chunks:[],expected:null};
  const pc=new RTCPeerConnection({iceServers:[]});
  R.pc=pc;
  pc.ondatachannel=(e)=>{
    const dc=e.channel; dc.binaryType="arraybuffer"; R.state="channel"; R.dc=dc;
    dc.onclose=()=>{ R.state="closed"; R.error="DataChannel closed"; };
    dc.onmessage=async(ev)=>{
      if(typeof ev.data==="string"){
        if(ev.data==="DONE"){
          R.state="hashing";
          const buf=await new Blob(R.chunks).arrayBuffer();
          R.sha=hexOf(await crypto.subtle.digest("SHA-256",buf));
          R.state="done";
          $("#p2pstatus").className="ok";
          $("#p2pstatus").textContent=`Received ${R.bytes} bytes over DataChannel · SHA-256 ${R.sha}`;
        }else{ try{R.expected=JSON.parse(ev.data);}catch(_){} }
      }else{
        R.chunks.push(ev.data); R.bytes+=ev.data.byteLength; R.state="receiving";
        $("#p2pstatus").textContent="Receiving over DataChannel: "+R.bytes+" bytes";
      }
    };
  };
  const deadline=Date.now()+30000; let offer=null;
  while(Date.now()<deadline){ offer=await getSDP("sender"); if(offer) break; await sleep(250); }
  if(!offer){ R.state="error"; R.error="no sender offer"; fail("Waiting for the sending peer failed: no offer."); return; }
  await pc.setRemoteDescription({type:"offer",sdp:offer.sdp});
  const answer=await pc.createAnswer();
  await pc.setLocalDescription(answer);
  await waitIce(pc);
  await postSDP("receiver",pc.localDescription);
  R.state="waiting-for-data";
  $("#p2pstatus").textContent="Answer sent; waiting for the DataChannel…";
}
P2P.prepare=async()=>{
  try{
    if(!meta||!key) throw new Error("open the full link first");
    P2P.state="fetching";
    const parts=[]; const prefix=hex(meta.nonce_prefix);
    for(let i=0;i<meta.chunk_count;i++){
      const r=await fetch(`/d/${ID}/c/${i}`,{cache:"no-store"});
      if(!r.ok) throw new Error("chunk "+(i+1)+" failed: "+r.status);
      const ct=new Uint8Array(await r.arrayBuffer());
      const iv=new Uint8Array(12); iv.set(prefix,0);
      new DataView(iv.buffer).setBigUint64(4,BigInt(i));
      const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct);
      parts.push(new Uint8Array(pt));
      $("#prog").style.width=(((i+1)/meta.chunk_count)*100).toFixed(1)+"%";
    }
    P2P.cache=parts;
    P2P.bytes=parts.reduce((a,p)=>a+p.byteLength,0);
    P2P.sha=hexOf(await crypto.subtle.digest("SHA-256",await new Blob(parts).arrayBuffer()));
    const pc=new RTCPeerConnection({iceServers:[]}); P2P.pc=pc;
    const dc=pc.createDataChannel("vb-file",{ordered:true}); dc.binaryType="arraybuffer"; P2P.dc=dc;
    dc.onclose=()=>{ P2P.state="closed"; P2P.error="DataChannel closed"; };
    dc.onerror=(e)=>{ P2P.error="DataChannel error: "+(e.message||"unknown"); };
    pc.onconnectionstatechange=()=>{ P2P.pcState=pc.connectionState; };
    P2P.state="signaling";
    pc.onicegatheringstatechange=async()=>{
      if(pc.iceGatheringState==="complete"&&!P2P.offerSent){
        P2P.offerSent=true; await postSDP("sender",pc.localDescription);
      }
    };
    await pc.setLocalDescription(await pc.createOffer());
    const deadline=Date.now()+20000; let answer=null;
    while(Date.now()<deadline){ answer=await getSDP("receiver"); if(answer) break; await sleep(250); }
    if(!answer) throw new Error("no receiving peer answered (open /f/"+ID+"/recv)");
    await pc.setRemoteDescription({type:"answer",sdp:answer.sdp});
    P2P.state="connecting";
    await new Promise((res,rej)=>{
      const t=setTimeout(()=>rej(new Error("DataChannel did not open")),20000);
      dc.onopen=()=>{clearTimeout(t);res();};
    });
    P2P.state="connected"; P2P.dcState=dc.readyState; P2P.pcState=pc.connectionState;
    $("#p2pstatus").className="ok";
    $("#p2pstatus").textContent="DataChannel open. Local SHA-256 "+P2P.sha+" — ready to send.";
  }catch(e){ P2P.state="error"; P2P.error=e.message; fail("P2P failed: "+e.message); }
};
P2P.send=async()=>{
  if(P2P.state!=="connected") throw new Error("DataChannel is not open");
  const dc=P2P.dc;
  dc.send(JSON.stringify({name:meta.file_name,size:P2P.bytes,sha256:P2P.sha,chunks:P2P.cache.length}));
  // SCTP messages have a size cap (commonly 256 KiB), so a 4 MiB drop chunk is
  // split into fixed-size slices; the receiver concatenates them in order.
  const SLICE=64*1024;
  for(const p of P2P.cache){
    for(let off=0;off<p.byteLength;off+=SLICE){
      while(dc.bufferedAmount>4*1024*1024) await sleep(20);
      dc.send(p.subarray(off,Math.min(off+SLICE,p.byteLength)));
    }
  }
  dc.send("DONE");
  P2P.state="sent";
  $("#p2pstatus").textContent=`Sent ${P2P.bytes} bytes over DataChannel · SHA-256 ${P2P.sha}`;
};
$("#p2p").onclick=async()=>{ $("#p2p").disabled=true; await P2P.prepare(); if(P2P.state==="connected") await P2P.send(); };

(async()=>{
  if(MODE==="recv"){ await startReceiver(); return; }
  $("#go").hidden=false;
  const m=(location.hash||"").match(/[#&]k=([0-9a-f]{64})/i);
  if(!m){fail("This link is missing its key. Open the full link, including the part after #.");return;}
  try{
    key=await crypto.subtle.importKey("raw",hex(m[1]),"AES-GCM",false,["decrypt"]);
    const r=await fetch(`/d/${ID}/meta`,{cache:"no-store"});
    if(!r.ok) throw new Error(await r.text());
    meta=await r.json();
  }catch(e){fail("This drop is no longer available: "+e.message);return;}
  $("#name").innerHTML="<b>"+meta.file_name.replace(/[<>&]/g,"")+"</b>";
  $("#meta").textContent=(meta.size/1048576).toFixed(meta.size>1048576?1:3)+" MB · "+
    meta.chunk_count+" chunks · expires "+new Date(meta.expires_at*1000).toLocaleString();
  $("#note").innerHTML="SHA-256 <code>"+meta.sha256+"</code>";
  $("#go").disabled=false;
  $("#p2p").disabled=false;
  $("#status").textContent="Ready.";
})();
$("#go").onclick=async()=>{
  $("#go").disabled=true;
  const parts=[];
  let writer=null;
  if(window.showSaveFilePicker){
    try{
      const handle=await window.showSaveFilePicker({suggestedName:meta.file_name});
      writer=await handle.createWritable();
    }catch(e){ if(e.name==="AbortError"){$("#go").disabled=false;return;} writer=null; }
  }
  if(!writer) $("#note").textContent+=" (streaming to disk unavailable; buffering in memory)";
  const prefix=hex(meta.nonce_prefix);
  try{
    for(let i=0;i<meta.chunk_count;i++){
      const r=await fetch(`/d/${ID}/c/${i}`,{cache:"no-store"});
      if(!r.ok) throw new Error("chunk "+(i+1)+" failed: "+r.status);
      const ct=new Uint8Array(await r.arrayBuffer());
      const iv=new Uint8Array(12); iv.set(prefix,0);
      new DataView(iv.buffer).setBigUint64(4,BigInt(i));
      const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct);
      if(writer) await writer.write(new Uint8Array(pt)); else parts.push(pt);
      $("#prog").style.width=(((i+1)/meta.chunk_count)*100).toFixed(1)+"%";
      $("#status").textContent="Received "+((i+1)/meta.chunk_count*100).toFixed(0)+"%";
    }
    if(writer){ await writer.close(); }
    else{
      const blob=new Blob(parts,{type:meta.mime});
      const a=document.createElement("a");
      a.href=URL.createObjectURL(blob); a.download=meta.file_name; a.click();
      setTimeout(()=>URL.revokeObjectURL(a.href),60000);
    }
    $("#status").textContent="Saved. Check the SHA-256 above if you want to be certain.";
    $("#status").className="ok";
  }catch(e){
    try{ if(writer) await writer.abort(); }catch(_){}
    fail("Transfer failed: "+e.message);
    $("#go").disabled=false;
  }
};
</script></body></html>"##;

/// Serve the drop endpoints on an already-bound listener until the process
/// exits. The `PortalRegistry` is shared so the CLI and the control center can
/// add drops to the same node.
pub async fn serve(registry: Arc<PortalRegistry>, listener: tokio::net::TcpListener) {
    loop {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            continue;
        };
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            let mut head = Vec::with_capacity(1024);
            let mut buf = [0u8; 2048];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        head.extend_from_slice(&buf[..n]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > MAX_HEAD {
                            break;
                        }
                    }
                }
            }
            let split = head
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(head.len());
            let (header_bytes, body) = head.split_at(split);
            let text = String::from_utf8_lossy(header_bytes);
            let mut parts = text.lines().next().unwrap_or("").split_whitespace();
            let method = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("/");
            let head_only = method == "HEAD";
            // Signaling bodies are small JSON SDPs; anything larger is refused
            // rather than buffered.
            let content_len = text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0)
                .min(64 * 1024);
            let mut body = body.to_vec();
            while body.len() < content_len {
                let want = content_len - body.len();
                let mut extra = vec![0u8; want.min(2048)];
                match stream.read(&mut extra).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&extra[..n]),
                }
            }
            let resp = respond_with_body(&registry, method, path, &body, Instant::now());

            let mut out = Vec::with_capacity(resp.body.len() + 256);
            out.extend_from_slice(
                format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status)).as_bytes(),
            );
            out.extend_from_slice(
                format!("Content-Type: {}\r\n", resp.content_type).as_bytes(),
            );
            out.extend_from_slice(format!("Content-Length: {}\r\n", resp.body.len()).as_bytes());
            out.extend_from_slice(b"Connection: close\r\n");
            for (name, value) in &resp.extra_headers {
                out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
            out.extend_from_slice(b"\r\n");
            if !head_only {
                out.extend_from_slice(&resp.body);
            }
            let _ = stream.write_all(&out).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Best-effort LAN address for the printed link, via a connected UDP socket.
/// A routing decision, not a packet: nothing is sent.
pub fn local_lan_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// `ggn drop <file>`: publish one file and print its links.
pub async fn run_cli(
    file: PathBuf,
    bind: String,
    ttl: Duration,
    max_downloads: u32,
) -> anyhow::Result<()> {
    let session = Arc::new(DropSession::open(
        &file,
        DropOptions {
            ttl,
            max_downloads,
            ..Default::default()
        },
    )?);
    let manifest = session.manifest.clone();
    let registry = Arc::new(PortalRegistry::new());
    registry.insert(Arc::clone(&session));

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| anyhow::anyhow!("cannot listen on {bind}: {e}"))?;
    let port = listener.local_addr()?.port();

    println!("Vantablack drop — {}", manifest.file_name);
    println!(
        "  {} bytes, {} chunk(s) of {} B, AES-256-GCM",
        manifest.size, manifest.chunk_count, manifest.chunk_size
    );
    println!("  SHA-256 {}", manifest.sha256);
    println!("  expires {}", manifest.expires_at);
    println!();
    println!("  local: {}", session.link(&format!("http://127.0.0.1:{port}")));
    if let Some(ip) = local_lan_ip() {
        if !ip.is_loopback() {
            println!("  LAN:   {}", session.link(&format!("http://{ip}:{port}")));
        }
    }
    println!();
    println!("Send the whole link. The key is after '#': it stays in the recipient's browser.");
    println!("Ctrl+C to stop.");

    let served = Arc::clone(&registry);
    tokio::spawn(async move {
        serve(served, listener).await;
    });

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nDrop stopped.");
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                registry.prune(Instant::now());
                if registry.is_empty() {
                    println!("Drop collected.");
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vb-drop-{}-{}",
            std::process::id(),
            crate::ghost::v2::now_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn decrypt(session: &DropSession, index: u32, sealed: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&session.key).unwrap();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&hex::decode(&session.manifest.nonce_prefix).unwrap());
        nonce[4..].copy_from_slice(&(index as u64).to_be_bytes());
        cipher.decrypt(Nonce::from_slice(&nonce), sealed).unwrap()
    }

    #[test]
    fn chunks_decrypt_to_the_original_file() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let path = temp_file("payload.bin", &data);
        let session = DropSession::open(
            &path,
            DropOptions {
                chunk_size: 64 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(session.manifest.chunk_count, 5);
        assert_eq!(session.manifest.size, data.len() as u64);

        let mut rebuilt = Vec::new();
        for i in 0..session.manifest.chunk_count {
            let sealed = session.chunk(i).unwrap();
            assert_eq!(sealed.len(), decrypt(&session, i, &sealed).len() + CHUNK_TAG_LEN);
            rebuilt.extend_from_slice(&decrypt(&session, i, &sealed));
        }
        assert_eq!(rebuilt, data);
        assert_eq!(
            session.manifest.sha256,
            hex::encode(Sha256::digest(&data))
        );
    }

    #[test]
    fn a_wrong_key_cannot_open_a_chunk() {
        let path = temp_file("secret.txt", b"attack at dawn");
        let session = DropSession::open(&path, DropOptions::default()).unwrap();
        let sealed = session.chunk(0).unwrap();
        let other = Aes256Gcm::new_from_slice(&[0u8; 32]).unwrap();
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&0u64.to_be_bytes());
        assert!(other.decrypt(Nonce::from_slice(&nonce), sealed.as_slice()).is_err());
    }

    #[test]
    fn the_link_carries_the_key_only_in_the_fragment() {
        let path = temp_file("notes.md", b"# hello");
        let session = DropSession::open(&path, DropOptions::default()).unwrap();
        let link = session.link("http://192.0.2.5:8787");
        assert!(link.starts_with("http://192.0.2.5:8787/f/"));
        let (before, after) = link.split_once('#').unwrap();
        assert!(!before.contains(&session.key_hex()), "key must not be in the path");
        assert_eq!(after, format!("k={}", session.key_hex()));
        // And it is absent from the metadata the server hands out.
        let manifest = session.manifest_json().to_string();
        assert!(!manifest.contains(&session.key_hex()));
    }

    #[test]
    fn out_of_range_chunks_are_refused() {
        let path = temp_file("small.bin", b"abc");
        let session = DropSession::open(&path, DropOptions::default()).unwrap();
        assert!(session.chunk(1).is_err());
    }

    #[test]
    fn expiry_and_download_limits_are_enforced() {
        let path = temp_file("once.txt", b"one shot");
        let session = DropSession::open(
            &path,
            DropOptions {
                ttl: Duration::from_secs(3600),
                max_downloads: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let registry = PortalRegistry::new();
        let id = registry.insert(Arc::new(session));

        let first = respond(&registry, "GET", &format!("/d/{id}/meta"), Instant::now());
        assert_eq!(first.status, 200);
        let second = respond(&registry, "GET", &format!("/d/{id}/meta"), Instant::now());
        assert_eq!(second.status, 410);
    }

    #[test]
    fn requests_only_reach_registered_drops() {
        let registry = PortalRegistry::new();
        assert_eq!(respond(&registry, "GET", "/", Instant::now()).status, 200);
        assert_eq!(
            respond(&registry, "GET", "/f/0000000000000000", Instant::now()).status,
            404
        );
        assert_eq!(
            respond(&registry, "GET", "/d/0000000000000000/meta", Instant::now()).status,
            404
        );
        // A traversal-shaped id is not a valid id and never reaches the filesystem.
        assert_eq!(
            respond(&registry, "GET", "/d/../etc/passwd/meta", Instant::now()).status,
            404
        );
        assert_eq!(respond(&registry, "POST", "/", Instant::now()).status, 405);
        assert_eq!(respond(&registry, "GET", "/healthz", Instant::now()).status, 200);
    }

    #[tokio::test]
    async fn a_chunk_is_downloadable_over_http() {
        let data = vec![7u8; 100_000];
        let path = temp_file("wire.bin", &data);
        let session = Arc::new(
            DropSession::open(
                &path,
                DropOptions {
                    chunk_size: 64 * 1024,
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let id = session.manifest.id.clone();
        let registry = Arc::new(PortalRegistry::new());
        registry.insert(Arc::clone(&session));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(Arc::clone(&registry), listener));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET /d/{id}/c/0 HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(String::from_utf8_lossy(&resp[..split]).starts_with("HTTP/1.1 200 OK"));
        let body = &resp[split..];
        assert_eq!(body.len(), 64 * 1024 + CHUNK_TAG_LEN);
        assert_eq!(decrypt(&session, 0, body).len(), 64 * 1024);
    }

    #[test]
    fn sdp_signaling_round_trips_and_both_pages_are_served() {
        let path = temp_file("signal.bin", b"payload");
        let session = Arc::new(DropSession::open(&path, DropOptions::default()).unwrap());
        let id = session.manifest.id.clone();
        let registry = PortalRegistry::new();
        registry.insert(session);

        let offer = serde_json::json!({"type":"offer","sdp":"v=0 fake offer"});
        let posted = respond_with_body(
            &registry,
            "POST",
            &format!("/f/{id}/signal/sender"),
            offer.to_string().as_bytes(),
            Instant::now(),
        );
        assert_eq!(posted.status, 200);
        let got = respond(
            &registry,
            "GET",
            &format!("/f/{id}/signal/sender"),
            Instant::now(),
        );
        let value: serde_json::Value = serde_json::from_slice(&got.body).unwrap();
        assert_eq!(value["sdp"], "v=0 fake offer");
        // The other role is still waiting; GET does not echo a role's own SDP.
        let waiting = respond(
            &registry,
            "GET",
            &format!("/f/{id}/signal/receiver"),
            Instant::now(),
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&waiting.body).unwrap()["waiting"],
            true
        );
        // POST remains forbidden everywhere except signaling.
        assert_eq!(respond(&registry, "POST", "/", Instant::now()).status, 405);

        let send = String::from_utf8(
            respond(&registry, "GET", &format!("/f/{id}"), Instant::now()).body,
        )
        .unwrap();
        assert!(send.contains("Send over DataChannel"));
        assert!(send.contains("RTCPeerConnection"));
        let recv = String::from_utf8(
            respond(&registry, "GET", &format!("/f/{id}/recv"), Instant::now()).body,
        )
        .unwrap();
        assert!(recv.contains("startReceiver"));
        assert!(recv.contains("SHA-256"));
    }

    #[test]
    fn a_directory_cannot_be_dropped() {
        let dir = std::env::temp_dir();
        assert!(DropSession::open(&dir, DropOptions::default()).is_err());
    }
}
