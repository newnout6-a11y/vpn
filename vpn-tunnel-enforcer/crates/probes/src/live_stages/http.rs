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

/// A byte stream an HTTP exchange runs over (TCP, TLS, or a tunnelled stream).
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
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
        let connector = tokio_rustls::TlsConnector::from(
            crate::tls_client::inspecting(&[]).map_err(|e| e.to_string())?,
        );
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
mod tests;
