//! Direct HTTP(S) banner probe: `HEAD /` (GET after a 405), same-origin redirects only, one
//! 3.5 s deadline for the whole chain including the body. HTTP/1.1 only, never re-resolves.
use std::net::SocketAddr;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{ProbePath, Timed, TimedStatus, elapsed_ms, net, timeouts, tls};

/// Direct HTTP result (`http` in the row).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpInfo {
    #[serde(flatten)]
    pub timed: Timed,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// `HTTP/1.1` / `HTTP/1.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_header: Option<String>,
    /// `scheme://host[:port]/path` of the final response's `Location` (query, fragment and
    /// userinfo dropped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Body bytes read, at most [`MAX_BODY`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_size: Option<u64>,
    #[serde(default)]
    pub target_port: u16,
    #[serde(default)]
    pub is_tls: bool,
}

/// Body bytes read at most (old MAX_HTTP_BODY_BYTES).
pub const MAX_BODY: u64 = 8192;
/// Same-origin redirects followed at most.
pub const MAX_REDIRECTS: u8 = 3;
const USER_AGENT: &str = "VPNTE-Diagnostics/1.0";
const MAX_HEAD: usize = 16 * 1024;

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// The parsed head of one response.
struct Head {
    status: u16,
    minor: u8,
    headers: Vec<(String, String)>,
}

impl Head {
    /// All values of a header joined with `, ` (Node's multi-value form).
    fn get(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }
}

/// Probes `addr` speaking for `authority` (Host header, SNI unless `sni` overrides or it is an IP).
pub async fn probe_http(
    addr: SocketAddr,
    is_tls: bool,
    authority: &str,
    sni: Option<&str>,
    path: &ProbePath,
    cancel: &CancellationToken,
) -> HttpInfo {
    let base = HttpInfo {
        target_port: addr.port(),
        is_tls,
        ..HttpInfo::default()
    };
    if cancel.is_cancelled() {
        return HttpInfo {
            timed: Timed::cancelled(),
            ..base
        };
    }
    let start = Instant::now();
    let chain = run_chain(addr, is_tls, authority, sni.unwrap_or(authority), path);
    let outcome = tokio::select! {
        biased;
        _ = cancel.cancelled() => return HttpInfo { timed: Timed::cancelled(), ..base },
        r = tokio::time::timeout(timeouts::HTTP, chain) => r,
    };
    let ms = elapsed_ms(start);
    match outcome {
        Ok(Ok(done)) => HttpInfo {
            timed: Timed::done(TimedStatus::Ok, done.ms_at(start), None, path.route()),
            ..done.into_info(base)
        },
        Ok(Err(error)) => HttpInfo {
            timed: Timed::done(TimedStatus::Error, ms, Some(error), path.route()),
            ..base
        },
        Err(_) => HttpInfo {
            timed: Timed::done(
                TimedStatus::Error,
                ms,
                Some("HTTP overall deadline exceeded".into()),
                path.route(),
            ),
            ..base
        },
    }
}

/// The final response of a chain.
struct Done {
    head: Head,
    body: u64,
    location: Option<String>,
    /// When the response completed (socket teardown is not timed).
    finished: Instant,
}

impl Done {
    fn ms_at(&self, start: Instant) -> u64 {
        let ms = self.finished.saturating_duration_since(start).as_millis();
        u64::try_from(ms).unwrap_or(u64::MAX)
    }

    fn into_info(self, base: HttpInfo) -> HttpInfo {
        HttpInfo {
            status_code: Some(self.head.status),
            protocol: Some(format!("HTTP/1.{}", self.head.minor)),
            server_header: self.head.get("server"),
            via_header: self.head.get("via"),
            location_header: self.location,
            content_type: self.head.get("content-type"),
            body_size: Some(self.body),
            ..base
        }
    }
}

async fn run_chain(
    addr: SocketAddr,
    is_tls: bool,
    authority: &str,
    sni: &str,
    path: &ProbePath,
) -> Result<Done, String> {
    let scheme = if is_tls { "https" } else { "http" };
    let host = if authority.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{authority}]")
    } else {
        authority.to_owned()
    };
    let origin = Url::parse(&format!("{scheme}://{host}:{}/", addr.port()))
        .map_err(|e| format!("HTTP probe failed: {e}"))?;
    let (mut url, mut method, mut redirects) = (origin.clone(), "HEAD", 0u8);
    loop {
        // Each hop gets a fresh connection; the previous one is dropped before the next dial.
        let (head, mut io, leftover) = request(addr, is_tls, sni, path, method, &url).await?;
        let location = head.get("location").and_then(|l| url.join(&l).ok());
        if matches!(head.status, 301 | 302 | 303 | 307 | 308)
            && let Some(next) = location.as_ref().filter(|n| same_origin(n, &origin))
            && redirects < MAX_REDIRECTS
        {
            url = next.clone();
            redirects += 1;
            continue;
        }
        if head.status == 405 && method == "HEAD" {
            method = "GET";
            continue;
        }
        let bodiless = method == "HEAD" || matches!(head.status, 204 | 304);
        let body = if bodiless {
            0
        } else {
            read_body(&mut io, leftover, &head).await?
        };
        let finished = Instant::now();
        let location = location.map(|l| stored_location(&l));
        return Ok(Done {
            head,
            body,
            location,
            finished,
        });
    }
}

/// Same scheme, host and port, and no userinfo (a redirect never wanders to a third party).
fn same_origin(next: &Url, origin: &Url) -> bool {
    next.scheme() == origin.scheme()
        && next.host_str() == origin.host_str()
        && next.port_or_known_default() == origin.port_or_known_default()
        && next.username().is_empty()
        && next.password().is_none()
}

/// `Host` as WHATWG `URL.host`: brackets for IPv6, the port only when not the default.
fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// What the row keeps of a `Location`: scheme, host and path only.
fn stored_location(url: &Url) -> String {
    format!("{}://{}{}", url.scheme(), host_header(url), url.path())
}

async fn request(
    addr: SocketAddr,
    is_tls: bool,
    sni: &str,
    path: &ProbePath,
    method: &str,
    url: &Url,
) -> Result<(Head, Box<dyn Io>, Vec<u8>), String> {
    let tcp = net::connect(addr, path, timeouts::HTTP).await?;
    let mut io: Box<dyn Io> = if is_tls {
        // No ALPN, like the old Node client: the probe speaks HTTP/1.x only.
        let connector = tokio_rustls::TlsConnector::from(tls::client_config(&[])?);
        let name = tls::server_name(sni, addr.ip());
        let stream = connector
            .connect(name, tcp)
            .await
            .map_err(|e| tls::tls_error_text(&e))?;
        Box::new(stream)
    } else {
        Box::new(tcp)
    };
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        host_header(url)
    );
    io.write_all(request.as_bytes())
        .await
        .map_err(|_| "HTTP request closed before completion".to_owned())?;
    let (head, leftover) = read_head(&mut io).await?;
    Ok((head, io, leftover))
}

/// Reads one more piece into `buf`; EOF means the server gave up mid-response.
async fn fill(io: &mut Box<dyn Io>, buf: &mut Vec<u8>) -> Result<(), String> {
    let mut chunk = [0u8; 4096];
    let n = io.read(&mut chunk).await.map_err(|e| net::errno_name(&e))?;
    if n == 0 {
        return Err("HTTP response interrupted".into());
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

/// Reads the status line and headers (1xx interim responses skipped); returns the body bytes
/// that came with them.
async fn read_head(io: &mut Box<dyn Io>) -> Result<(Head, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(4096);
    loop {
        if !buf.is_empty() {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&buf) {
                Ok(httparse::Status::Complete(len)) => {
                    let head = Head {
                        status: resp.code.unwrap_or(0),
                        minor: resp.version.unwrap_or(1),
                        headers: resp
                            .headers
                            .iter()
                            .map(|h| {
                                (
                                    h.name.to_owned(),
                                    String::from_utf8_lossy(h.value).trim().to_owned(),
                                )
                            })
                            .collect(),
                    };
                    buf.drain(..len);
                    if (100..200).contains(&head.status) {
                        continue;
                    }
                    return Ok((head, buf));
                }
                Ok(httparse::Status::Partial) if buf.len() >= MAX_HEAD => {
                    return Err("HTTP response header too large".into());
                }
                Ok(httparse::Status::Partial) => {}
                Err(e) => return Err(format!("HTTP parse error: {e}")),
            }
        }
        fill(io, &mut buf)
            .await
            .map_err(|_| "HTTP response closed before completion".to_owned())?;
    }
}

/// Counts body bytes (Content-Length, chunked or until close), stopping at [`MAX_BODY`].
async fn read_body(io: &mut Box<dyn Io>, mut buf: Vec<u8>, head: &Head) -> Result<u64, String> {
    let chunked = head
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return read_chunked(io, buf).await;
    }
    let length = head
        .get("content-length")
        .and_then(|v| v.parse::<u64>().ok());
    let want = length.map_or(MAX_BODY, |l| l.min(MAX_BODY));
    while (buf.len() as u64) < want {
        match fill(io, &mut buf).await {
            Ok(()) => {}
            // Without a length the body ends when the server closes.
            Err(_) if length.is_none() => break,
            Err(e) => return Err(e),
        }
    }
    Ok((buf.len() as u64).min(want))
}

async fn read_chunked(io: &mut Box<dyn Io>, mut buf: Vec<u8>) -> Result<u64, String> {
    let mut total = 0u64;
    loop {
        let line_end = loop {
            if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                break i;
            }
            if buf.len() > 1024 {
                return Err("HTTP malformed chunk".into());
            }
            fill(io, &mut buf).await?;
        };
        let line = String::from_utf8_lossy(&buf[..line_end]).into_owned();
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size =
            u64::from_str_radix(size_text, 16).map_err(|_| "HTTP malformed chunk".to_owned())?;
        buf.drain(..line_end + 2);
        if size == 0 {
            return Ok(total.min(MAX_BODY));
        }
        let mut remaining = size;
        loop {
            let take = remaining.min(buf.len() as u64);
            buf.drain(..take as usize);
            total += take;
            remaining -= take;
            if total >= MAX_BODY {
                return Ok(MAX_BODY);
            }
            if remaining == 0 {
                break;
            }
            fill(io, &mut buf).await?;
        }
        while buf.len() < 2 {
            fill(io, &mut buf).await?;
        }
        buf.drain(..2);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use parking_lot::Mutex;
    use tokio::net::TcpListener;

    use super::*;
    use crate::live_stages::{CANCELLED, ProbeRoute};

    type Log = Arc<Mutex<Vec<String>>>;
    /// (response bytes, then dribble the rest of a 40-byte body one byte per 100 ms).
    type Handler = fn(&str, &str, u16) -> (Vec<u8>, bool);

    fn reply(head: &str, body: &[u8]) -> (Vec<u8>, bool) {
        let mut bytes = head.replace('\n', "\r\n").into_bytes();
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(body);
        (bytes, false)
    }

    /// Loopback server (TLS when `tls`) logging `METHOD target host` per request.
    async fn serve(handler: Handler, tls: bool) -> (SocketAddr, Log) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log: Log = Arc::default();
        let seen = log.clone();
        let acceptor =
            tokio_rustls::TlsAcceptor::from(crate::live_stages::tls::tests::server_config(&[]));
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let (seen, acceptor) = (seen.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let mut io: Box<dyn Io> = if tls {
                        Box::new(acceptor.accept(sock).await.unwrap())
                    } else {
                        Box::new(sock)
                    };
                    let mut buf = Vec::new();
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        if fill(&mut io, &mut buf).await.is_err() {
                            return;
                        }
                    }
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    let mut words = text.split_whitespace();
                    let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
                    let host = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Host: "))
                        .unwrap_or("");
                    seen.lock().push(format!("{method} {target} {host}"));
                    let (bytes, dribble) = handler(method, target, addr.port());
                    let _ = io.write_all(&bytes).await;
                    if dribble {
                        for _ in 0..40 {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            if io.write_all(b"x").await.is_err() {
                                return;
                            }
                        }
                    }
                    let _ = io.shutdown().await;
                });
            }
        });
        (addr, log)
    }

    async fn probe(addr: SocketAddr, authority: &str, tls: bool) -> HttpInfo {
        probe_http(
            addr,
            tls,
            authority,
            None,
            &ProbePath::Os,
            &CancellationToken::new(),
        )
        .await
    }

    /// AT-05-001: HEAD banner (§7.1).
    #[tokio::test]
    async fn head_banner() {
        let (addr, log) = serve(
            |_, _, _| reply("HTTP/1.1 200 OK\nServer: test-server/1.0\nVia: 1.1 test-proxy\nContent-Length: 0\n", b""),
            false,
        )
        .await;
        let info = probe(addr, "127.0.0.1", false).await;
        assert_eq!(info.timed.status, TimedStatus::Ok, "{info:?}");
        assert_eq!(info.status_code, Some(200));
        assert_eq!(info.server_header.as_deref(), Some("test-server/1.0"));
        assert_eq!(info.via_header.as_deref(), Some("1.1 test-proxy"));
        assert_eq!(info.protocol.as_deref(), Some("HTTP/1.1"));
        assert_eq!((info.target_port, info.is_tls), (addr.port(), false));
        assert_eq!(info.timed.route, Some(ProbeRoute::Os));
        assert_eq!(
            log.lock().clone(),
            [format!("HEAD / 127.0.0.1:{}", addr.port())]
        );
    }

    /// AT-00-003: 405 on HEAD retries GET; the body is counted (§7.5).
    #[tokio::test]
    async fn head_405_retries_get() {
        let (addr, log) = serve(
            |m, _, _| match m {
                "HEAD" => reply("HTTP/1.1 405 Method Not Allowed\nContent-Length: 0\n", b""),
                _ => reply(
                    "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 4\n",
                    b"body",
                ),
            },
            false,
        )
        .await;
        let info = probe(addr, "127.0.0.1", false).await;
        assert_eq!(
            (info.status_code, info.body_size),
            (Some(200), Some(4)),
            "{info:?}"
        );
        assert_eq!(info.content_type.as_deref(), Some("text/plain"));
        let methods: Vec<String> = log.lock().iter().map(|l| l[..4].to_owned()).collect();
        assert_eq!(methods, ["HEAD", "GET "]);
    }

    /// AT-05-001 (audit 275-290): same-origin redirect keeps method, query and the original
    /// authority + port in Host; 405 then GET; final 204 (§7.5, §7.11).
    #[tokio::test]
    async fn follows_same_origin_redirects() {
        let (addr, log) = serve(
            |m, t, _| match (m, t) {
                ("HEAD", "/") => reply(
                    "HTTP/1.1 302 Found\nLocation: /next?value=1\nContent-Length: 0\n",
                    b"",
                ),
                ("HEAD", _) => reply("HTTP/1.1 405 No\nContent-Length: 0\n", b""),
                _ => reply("HTTP/1.1 204 No Content\n", b""),
            },
            false,
        )
        .await;
        let info = probe(addr, "audit.example", false).await;
        assert_eq!(info.status_code, Some(204), "{info:?}");
        assert_eq!(info.target_port, addr.port());
        let host = format!("audit.example:{}", addr.port());
        assert_eq!(
            log.lock().clone(),
            [
                format!("HEAD / {host}"),
                format!("HEAD /next?value=1 {host}"),
                format!("GET /next?value=1 {host}")
            ]
        );
    }

    /// B-06 guard: a cross-origin redirect is reported, never followed; the stored Location
    /// has no query, fragment or userinfo.
    #[tokio::test]
    async fn cross_origin_redirect_is_not_followed() {
        let (addr, log) = serve(
            |_, _, _| reply("HTTP/1.1 302 Found\nLocation: http://user:pw@other.example/target?token=secret123#frag\nContent-Length: 0\n", b""),
            false,
        )
        .await;
        let info = probe(addr, "127.0.0.1", false).await;
        assert_eq!(info.status_code, Some(302));
        assert_eq!(
            info.location_header.as_deref(),
            Some("http://other.example/target")
        );
        assert_eq!(log.lock().len(), 1);
    }

    /// At most 3 redirects; the last 3xx is the result.
    #[tokio::test]
    async fn redirect_cap() {
        let (addr, log) = serve(
            |_, _, port| reply(&format!("HTTP/1.1 301 Moved\nLocation: http://127.0.0.1:{port}/loop?x=1\nContent-Length: 0\n"), b""),
            false,
        )
        .await;
        let info = probe(addr, "127.0.0.1", false).await;
        assert_eq!(info.status_code, Some(301));
        let expected = format!("http://127.0.0.1:{}/loop", addr.port());
        assert_eq!(info.location_header.as_deref(), Some(expected.as_str()));
        assert_eq!(log.lock().len(), 4);
    }

    /// AT-00-003: body cap 8192 (Content-Length and chunked) (§7.5).
    #[tokio::test]
    async fn body_is_capped() {
        let (addr, _) = serve(
            |m, _, _| match m {
                "HEAD" => reply("HTTP/1.1 405 No\nContent-Length: 0\n", b""),
                _ => reply("HTTP/1.1 200 OK\nContent-Length: 9000\n", &[b'a'; 9000]),
            },
            false,
        )
        .await;
        assert_eq!(probe(addr, "127.0.0.1", false).await.body_size, Some(8192));
        let chunked = serve(
            |m, _, _| match m {
                "HEAD" => reply("HTTP/1.1 405 No\nContent-Length: 0\n", b""),
                _ => reply(
                    "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n",
                    b"4\r\nbody\r\n2;x=y\r\nok\r\n0\r\n\r\n",
                ),
            },
            false,
        )
        .await;
        assert_eq!(
            probe(chunked.0, "127.0.0.1", false).await.body_size,
            Some(6)
        );
    }

    /// AT-00-003 (audit second review): the 3.5 s deadline covers a dribbling body.
    #[tokio::test]
    async fn deadline_covers_the_body() {
        let (addr, _) = serve(
            |m, _, _| match m {
                "HEAD" => reply("HTTP/1.1 405 No\nContent-Length: 0\n", b""),
                _ => (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n".to_vec(),
                    true,
                ),
            },
            false,
        )
        .await;
        let info = probe(addr, "127.0.0.1", false).await;
        assert_eq!(info.timed.status, TimedStatus::Error);
        assert!(info.timed.error.as_deref().unwrap().contains("deadline"));
        assert!(info.timed.duration_ms < 4100, "{}", info.timed.duration_ms);
    }

    /// AT-00-003: cancelled before start -> skipped, no request; early close -> error.
    #[tokio::test]
    async fn cancel_and_early_close() {
        let (addr, log) = serve(|_, _, _| (Vec::new(), false), false).await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        let info = probe_http(addr, false, "127.0.0.1", None, &ProbePath::Os, &cancel).await;
        assert_eq!(info.timed.status, TimedStatus::Skipped);
        assert_eq!(info.timed.error.as_deref(), Some(CANCELLED));
        assert!(log.lock().is_empty());
        let info = probe(addr, "127.0.0.1", false).await;
        assert_eq!(info.timed.status, TimedStatus::Error);
        assert_eq!(
            info.timed.error.as_deref(),
            Some("HTTP response closed before completion")
        );
    }

    /// HTTPS against a self-signed certificate still answers (we inspect, not trust).
    #[tokio::test]
    async fn https_banner() {
        let (addr, log) = serve(
            |_, _, _| {
                reply(
                    "HTTP/1.1 200 OK\nServer: tls-test\nContent-Length: 0\n",
                    b"",
                )
            },
            true,
        )
        .await;
        let info = probe_http(
            addr,
            true,
            "unrelated.example",
            None,
            &ProbePath::Os,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(info.timed.status, TimedStatus::Ok, "{info:?}");
        assert_eq!(
            (info.server_header.as_deref(), info.is_tls),
            (Some("tls-test"), true)
        );
        assert_eq!(
            log.lock()[0],
            format!("HEAD / unrelated.example:{}", addr.port())
        );
    }
}
