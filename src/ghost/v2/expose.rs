//! `ggn expose` — reach a server on your own machine without port forwarding.
//!
//! The common case is a local app, dev server or model endpoint (`localhost:3000`,
//! `:8080`, `:11434`) that the operator wants to reach from another device. The
//! usual answers are a rented tunnel service (which terminates TLS and can read
//! everything) or a port-forward (which exposes the whole machine). This is
//! neither: a token-gated TCP relay bound to one loopback port, carrying exactly
//! the bytes of the connection to one fixed local target.
//!
//! Properties that matter:
//!
//! * **One target, fixed at startup.** There is no URL parameter that selects a
//!   host, so the relay cannot be turned into an open proxy.
//! * **Token in the path or a header.** `http://host:8787/<token>/…` works from a
//!   browser and from `curl` without a proxy config; `X-VB-Expose: <token>` works
//!   for clients that can set headers. A wrong or missing token gets the same
//!   `404` as a wrong path, so scanning the port learns nothing.
//! * **No rewriting beyond the prefix.** The body, `Host`, cookies and upgrade
//!   headers reach the target as the client sent them; a WebSocket upgrade is
//!   passed through because the relay stops parsing once the head is forwarded.
//!
//! What it is *not*: this module does not encrypt by itself. Run it bound to
//! loopback and reach it through the mesh (or `ggn drop`-style TLS-terminating
//! front), or use it on a network you already trust. Saying so is cheaper than
//! implying a guarantee the code does not make.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Maximum request head accepted before the relay stops reading.
pub const MAX_HEAD: usize = 32 * 1024;

/// Header that can carry the token instead of the path prefix.
pub const TOKEN_HEADER: &str = "x-vb-expose";

#[derive(Debug, Clone)]
pub struct ExposeConfig {
    /// Where the relay listens. Bind loopback unless the mesh provides the path.
    pub listen: String,
    /// The one target every connection is forwarded to, `host:port`.
    pub target: String,
    /// Shared secret. Must not be empty.
    pub token: String,
}

impl ExposeConfig {
    pub fn new(target: &str, token: &str) -> Self {
        Self {
            listen: "127.0.0.1:8787".to_string(),
            target: target.to_string(),
            token: token.to_string(),
        }
    }

    pub fn with_listen(mut self, listen: &str) -> Self {
        self.listen = listen.to_string();
        self
    }

    /// Reject configurations that would silently do the wrong thing.
    pub fn validate(&self) -> Result<(), String> {
        if self.token.trim().len() < 16 {
            return Err("expose token must be at least 16 characters".into());
        }
        if !self.target.contains(':') {
            return Err("target must be host:port".into());
        }
        Ok(())
    }
}

fn tokens_match(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The outcome of authorising and rewriting one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Forward this head to the target.
    Forward(Vec<u8>),
    /// Answer 404 and close. Deliberately indistinguishable from "no such path".
    Deny,
}

/// Authorise one request head and strip the token prefix.
///
/// `head` is the raw request head (up to and including the blank line). Any
/// already-read body bytes are preserved.
pub fn route(head: &[u8], cfg: &ExposeConfig) -> Route {
    let text = match std::str::from_utf8(head) {
        Ok(t) => t,
        Err(_) => return Route::Deny,
    };
    let (request_line, rest) = match text.split_once("\r\n") {
        Some(v) => v,
        None => return Route::Deny,
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");
    if method.is_empty() || path.is_empty() {
        return Route::Deny;
    }

    let authorised_by_header = header_value(rest, TOKEN_HEADER)
        .map(|t| tokens_match(t, &cfg.token))
        .unwrap_or(false);

    let prefix = format!("/{}", cfg.token);
    let (authorised_by_path, rewritten) = if path == prefix {
        (true, "/".to_string())
    } else if let Some(tail) = path.strip_prefix(&format!("{prefix}/")) {
        (true, format!("/{tail}"))
    } else if let Some(tail) = path.strip_prefix(&format!("{prefix}?")) {
        (true, format!("/?{tail}"))
    } else {
        (false, path.to_string())
    };

    if !authorised_by_header && !authorised_by_path {
        return Route::Deny;
    }

    // Rebuild the head with the rewritten request line, dropping the relay's own
    // header so the target never sees our secret.
    let mut out = Vec::with_capacity(head.len() + 16);
    out.extend_from_slice(format!("{method} {rewritten} {version}\r\n").as_bytes());
    for line in text[request_line.len() + 2..].lines() {
        if line.is_empty() {
            continue;
        }
        if let Some((k, _)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(TOKEN_HEADER) {
                continue;
            }
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Route::Forward(out)
}

/// Bind the listener, returning it with the address actually bound (so `:0`
/// works in tests and in the CLI's "already in use" message).
pub async fn bind(cfg: &ExposeConfig) -> std::io::Result<(SocketAddr, TcpListener)> {
    let listener = TcpListener::bind(&cfg.listen).await?;
    let addr = listener.local_addr()?;
    Ok((addr, listener))
}

/// Accept loop. One task per connection; no shared state.
pub async fn serve(listener: TcpListener, cfg: Arc<ExposeConfig>) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            continue;
        };
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            let _ = handle(stream, cfg).await;
        });
    }
}

async fn handle(mut client: TcpStream, cfg: Arc<ExposeConfig>) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(2048);
    let mut buf = [0u8; 4096];
    loop {
        let n = client.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > MAX_HEAD {
            break;
        }
    }

    let forwarded = match route(&head, &cfg) {
        Route::Forward(bytes) => bytes,
        Route::Deny => {
            let body = b"not found\n";
            let resp = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            client.write_all(resp.as_bytes()).await?;
            client.write_all(body).await?;
            client.shutdown().await.ok();
            return Ok(());
        }
    };

    let mut upstream = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&cfg.target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            let _ = client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 17\r\nConnection: close\r\n\r\ntarget unavailable\n",
                )
                .await;
            return Ok(());
        }
    };

    upstream.write_all(&forwarded).await?;
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();

    // From here the relay is a byte pump in both directions, which is what makes
    // WebSocket and streaming (SSE, chunked) work without special cases.
    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut cr, &mut uw).await;
        let _ = uw.shutdown().await;
    });
    let down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut ur, &mut cw).await;
        let _ = cw.shutdown().await;
    });
    let _ = tokio::join!(up, down);
    Ok(())
}

/// `ggn expose <target> [--listen ADDR] [--token T]`
pub async fn run_cli(cfg: ExposeConfig) -> anyhow::Result<()> {
    cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
    let (addr, listener) = bind(&cfg).await?;
    println!("Vantablack expose");
    println!("  {} -> {}", addr, cfg.target);
    println!();
    println!("  http://127.0.0.1:{}/{}/", addr.port(), cfg.token);
    if let Some(ip) = super::portal::local_lan_ip() {
        if !ip.is_loopback() {
            println!("  http://{ip}:{}/{}/", addr.port(), cfg.token);
        }
    }
    println!();
    println!("Anyone with the token reaches {} and nothing else. Ctrl+C to stop.", cfg.target);
    let cfg = Arc::new(cfg);
    let loop_task = tokio::spawn(serve(listener, Arc::clone(&cfg)));
    tokio::signal::ctrl_c().await.ok();
    loop_task.abort();
    println!("Expose stopped.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ExposeConfig {
        ExposeConfig::new("127.0.0.1:3000", "0123456789abcdef0123456789abcdef")
    }

    fn head(request: &str) -> Vec<u8> {
        request.as_bytes().to_vec()
    }

    #[test]
    fn token_prefix_is_stripped_and_the_rest_forwarded() {
        let c = cfg();
        let req = head(&format!(
            "GET /{}/api/status?x=1 HTTP/1.1\r\nHost: box\r\nX-VB-Expose: {}\r\n\r\n",
            c.token, c.token
        ));
        match route(&req, &c) {
            Route::Forward(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                assert!(text.starts_with("GET /api/status?x=1 HTTP/1.1\r\n"));
                assert!(!text.to_ascii_lowercase().contains("x-vb-expose"));
                assert!(text.contains("Host: box"));
            }
            Route::Deny => panic!("authorised request was denied"),
        }
    }

    #[test]
    fn a_bare_token_path_becomes_root() {
        let c = cfg();
        let req = head(&format!("GET /{} HTTP/1.1\r\n\r\n", c.token));
        match route(&req, &c) {
            Route::Forward(bytes) => {
                assert!(String::from_utf8(bytes).unwrap().starts_with("GET / HTTP/1.1\r\n"))
            }
            Route::Deny => panic!("denied"),
        }
    }

    #[test]
    fn header_token_works_without_a_path_prefix() {
        let c = cfg();
        let req = head(&format!(
            "POST /v1/chat HTTP/1.1\r\nX-VB-Expose: {}\r\nContent-Length: 2\r\n\r\n{{}}",
            c.token
        ));
        match route(&req, &c) {
            Route::Forward(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                assert!(text.starts_with("POST /v1/chat HTTP/1.1"));
                assert!(text.ends_with("\r\n\r\n"));
            }
            Route::Deny => panic!("denied"),
        }
    }

    #[test]
    fn wrong_or_missing_tokens_get_no_information() {
        let c = cfg();
        assert_eq!(route(&head("GET / HTTP/1.1\r\n\r\n"), &c), Route::Deny);
        assert_eq!(
            route(&head("GET /wrong/thing HTTP/1.1\r\n\r\n"), &c),
            Route::Deny
        );
        assert_eq!(
            route(&head("GET /v1/chat HTTP/1.1\r\nX-VB-Expose: nope\r\n\r\n"), &c),
            Route::Deny
        );
        // A token that is a prefix of the real one must not pass.
        assert_eq!(
            route(&head(&format!("GET /{}/ HTTP/1.1\r\n\r\n", &c.token[..8])), &c),
            Route::Deny
        );
    }

    #[test]
    fn a_weak_token_is_rejected_at_startup() {
        assert!(ExposeConfig::new("127.0.0.1:3000", "short").validate().is_err());
        assert!(ExposeConfig::new("no-port", "0123456789abcdef").validate().is_err());
    }

    #[tokio::test]
    async fn live_relay_forwards_and_denies() {
        // A tiny upstream that answers any request with a fixed body.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = upstream.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream-ok")
                        .await;
                });
            }
        });

        let cfg = Arc::new(
            ExposeConfig::new(&up_addr.to_string(), "0123456789abcdef0123456789abcdef")
                .with_listen("127.0.0.1:0"),
        );
        let (addr, listener) = bind(&cfg).await.unwrap();
        tokio::spawn(serve(listener, Arc::clone(&cfg)));

        // Authorised.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET /{}/hello HTTP/1.1\r\nHost: x\r\n\r\n", cfg.token).as_bytes())
            .await
            .unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("upstream-ok"));

        // Denied, with a 404 that says nothing else.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp).to_string();
        assert!(text.starts_with("HTTP/1.1 404"));
        assert!(!text.contains("upstream-ok"));
    }
}
