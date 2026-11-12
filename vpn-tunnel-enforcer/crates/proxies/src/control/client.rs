//! Client side of the control API, for the `vpnte_proxy` CLI: loopback-only control URLs,
//! endpoint discovery and one blocking HTTP/1.1 request over `std::net` (no runtime needed).
use std::fmt;
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use super::http::find;
use super::router::TOKEN_HEADER;
use crate::slot::{CONTROL_HOST, CONTROL_PORT};

/// Client-side override of the control URL (must be a loopback `http` URL).
pub const ENV_CONTROL_URL: &str = "VPNTE_CONTROL_URL";
/// Client-side override of the token (else the token file is read).
pub const ENV_CONTROL_TOKEN: &str = "VPNTE_CONTROL_TOKEN";
/// Largest answer the client accepts (a `/list` of thousands of profiles stays far below).
const MAX_REPLY: usize = 32 * 1024 * 1024;

/// A validated control URL: `http`, host `127.0.0.1` or `localhost`, port 1..=65535, optional
/// path prefix (e.g. `/api/external-proxy`). The token is only ever sent to such a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlUrl {
    host: String,
    port: u16,
    prefix: String,
}

impl ControlUrl {
    /// `http://127.0.0.1:17873`, the old fixed endpoint.
    pub fn local_default() -> Self {
        Self {
            host: CONTROL_HOST.into(),
            port: CONTROL_PORT,
            prefix: String::new(),
        }
    }

    /// Validates a control URL; trailing slashes are dropped. `[::1]` is refused: the server
    /// listens on 127.0.0.1 only and its Host guard rejects it.
    pub fn parse(raw: &str) -> Option<Self> {
        let url = url::Url::parse(raw.trim()).ok()?;
        let host = url.host_str()?;
        let port = url.port_or_known_default()?;
        let loopback = host == CONTROL_HOST || host == "localhost";
        let plain = url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none();
        (url.scheme() == "http" && loopback && plain && port != 0).then(|| Self {
            host: host.to_owned(),
            port,
            prefix: url.path().trim_end_matches('/').to_owned(),
        })
    }

    /// The port the server should be listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Sends one request (`path_and_query` starts with `/`) and returns the status and body.
    /// POST requests carry an empty body.
    pub fn request(
        &self,
        method: &str,
        path_and_query: &str,
        token: Option<&str>,
        timeout: Duration,
    ) -> io::Result<Reply> {
        // `localhost` may resolve to ::1 first; the server is on 127.0.0.1 only.
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let mut head = format!(
            "{method} {}{path_and_query} HTTP/1.1\r\nHost: {}:{}\r\nAccept: */*\r\n",
            self.prefix, self.host, self.port
        );
        if let Some(token) = token {
            head.push_str(&format!("{TOKEN_HEADER}: {token}\r\n"));
        }
        if method == "POST" {
            head.push_str("Content-Length: 0\r\n");
        }
        head.push_str("Connection: close\r\n\r\n");
        stream.write_all(head.as_bytes())?;
        read_reply(&mut stream)
    }
}

impl fmt::Display for ControlUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http://{}:{}{}", self.host, self.port, self.prefix)
    }
}

/// The control URL announced by an endpoint file: its `url`, else `http://<host>:<port>`, each
/// only if it passes [`ControlUrl::parse`].
pub fn discover(endpoint_file: &Path) -> Option<ControlUrl> {
    let text = std::fs::read_to_string(endpoint_file).ok()?;
    let value: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    value
        .get("url")
        .and_then(Value::as_str)
        .and_then(ControlUrl::parse)
        .or_else(|| {
            let host = value.get("host")?.as_str()?;
            let port = value.get("port")?.as_u64()?;
            ControlUrl::parse(&format!("http://{host}:{port}"))
        })
}

/// An HTTP answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

/// Reads one answer: until the announced length is complete or the server closes.
pub(super) fn read_reply(stream: &mut impl io::Read) -> io::Result<Reply> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // Saturating: `VPNTE_CONTROL_URL` may name any loopback server, which may announce
        // any length.
        if let Some((end, Some(length))) = head_info(&raw)
            && raw.len() >= length.saturating_add(end + 4)
        {
            return parse(&raw);
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return parse(&raw);
        }
        if raw.len() + n > MAX_REPLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "answer too large",
            ));
        }
        raw.extend_from_slice(&chunk[..n]);
    }
}

/// End of the head and the announced `Content-Length`, once the head is complete.
fn head_info(raw: &[u8]) -> Option<(usize, Option<usize>)> {
    let end = find(raw, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let length = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())?
    });
    Some((end, length))
}

/// Status and body of a received answer (the body cut to its announced length).
fn parse(raw: &[u8]) -> io::Result<Reply> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP answer");
    let (end, length) = head_info(raw).ok_or_else(bad)?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|_| head.starts_with("HTTP/1."))
        .ok_or_else(bad)?;
    let body = &raw[end + 4..];
    let keep = if status == 204 {
        0
    } else {
        length.unwrap_or(body.len()).min(body.len())
    };
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&body[..keep]).into_owned(),
    })
}
