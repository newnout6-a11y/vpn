//! The little HTTP/1.1 the control API needs: one request per connection (`Connection: close`),
//! bodies by `Content-Length` or chunked, at most 64 KiB, answers always with a length.
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Request line plus headers may not exceed this.
const MAX_HEAD: usize = 16 * 1024;
/// Largest accepted request body (old limit).
pub(super) const MAX_BODY: usize = 64 * 1024;
/// How long a closing connection is drained so unread input does not turn into a TCP reset
/// that destroys the answer before the client reads it.
const LINGER: Duration = Duration::from_secs(1);

/// Request line and headers (names lowercased, values trimmed, in arrival order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Head {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// First value of a header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Every value of a header.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Why no (complete) request could be read.
#[derive(Debug, thiserror::Error)]
pub(super) enum ReadError {
    /// The peer closed the connection before a complete request arrived.
    #[error("connection closed")]
    Closed,
    #[error("malformed request")]
    Malformed,
    #[error("request body too large")]
    TooLarge,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// An answer: status plus a JSON or text body (text bodies get the old trailing newline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Response {
    pub status: u16,
    pub text: bool,
    pub body: String,
}

impl Response {
    /// JSON body, pretty-printed with two spaces like the old `JSON.stringify(x, null, 2)`.
    pub fn json<T: serde::Serialize + ?Sized>(status: u16, payload: &T) -> Self {
        let body = serde_json::to_string_pretty(payload).unwrap_or_else(|_| "null".into());
        Self {
            status,
            text: false,
            body,
        }
    }

    /// `text/plain` body.
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            text: true,
            body: body.into(),
        }
    }

    /// The whole response on the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let content_type = if self.text {
            "text/plain; charset=utf-8"
        } else {
            "application/json; charset=utf-8"
        };
        let mut body = self.body.clone();
        if self.text {
            body.push('\n');
        }
        // 204 carries neither a body nor a length (RFC 9110 §8.6).
        let length = if self.status == 204 {
            body.clear();
            String::new()
        } else {
            format!("Content-Length: {}\r\n", body.len())
        };
        let mut out = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\n\
             Access-Control-Allow-Origin: http://127.0.0.1\r\n\
             Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type, x-vpnte-control-token, Authorization\r\n\
             Vary: Origin\r\n{length}Connection: close\r\n\r\n",
            self.status,
            reason(self.status),
        )
        .into_bytes();
        out.extend_from_slice(body.as_bytes());
        out
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

/// One client connection: buffered reads of a single request, then the answer.
pub(super) struct Conn<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    /// Reads the request line and headers.
    pub async fn read_head(&mut self) -> Result<Head, ReadError> {
        loop {
            if let Some(end) = find(&self.buf, b"\r\n\r\n") {
                let raw: Vec<u8> = self.buf.drain(..end + 4).collect();
                return parse_head(&raw[..end]).ok_or(ReadError::Malformed);
            }
            if self.buf.len() > MAX_HEAD {
                return Err(ReadError::Malformed);
            }
            self.fill().await?;
        }
    }

    /// Reads the body announced by `head` (empty when none is announced).
    pub async fn read_body(&mut self, head: &Head) -> Result<Vec<u8>, ReadError> {
        let chunked = match head.header("transfer-encoding") {
            None => false,
            // A length next to a transfer coding is the classic smuggling shape: refuse it.
            Some(_) if head.header("content-length").is_some() => {
                return Err(ReadError::Malformed);
            }
            Some(te) if te.eq_ignore_ascii_case("chunked") => true,
            Some(_) => return Err(ReadError::Malformed),
        };
        let length = if chunked { None } else { content_length(head)? };
        if length == Some(0) || (!chunked && length.is_none()) {
            return Ok(Vec::new());
        }
        if length.is_some_and(|n| n > MAX_BODY) {
            return Err(ReadError::TooLarge);
        }
        if head
            .header("expect")
            .is_some_and(|e| e.eq_ignore_ascii_case("100-continue"))
        {
            self.stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await?;
        }
        match length {
            Some(n) => self.take(n).await,
            None => self.read_chunked().await,
        }
    }

    /// Writes the answer, then closes the connection gracefully.
    pub async fn respond(mut self, response: &Response) -> io::Result<()> {
        self.stream.write_all(&response.to_bytes()).await?;
        self.stream.flush().await?;
        self.stream.shutdown().await?;
        let drain = async {
            let mut sink = [0u8; 4096];
            let mut left = MAX_BODY;
            while left > 0 {
                match self.stream.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => left = left.saturating_sub(n),
                }
            }
        };
        let _ = tokio::time::timeout(LINGER, drain).await;
        Ok(())
    }

    async fn read_chunked(&mut self) -> Result<Vec<u8>, ReadError> {
        let mut body = Vec::new();
        loop {
            let line = self.line().await?;
            let size = line.split(|&b| b == b';').next().unwrap_or_default();
            let size = std::str::from_utf8(size)
                .ok()
                .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
                .ok_or(ReadError::Malformed)?;
            if size == 0 {
                // Trailer fields up to the empty line are read and ignored.
                while !self.line().await?.is_empty() {}
                return Ok(body);
            }
            if body.len() + size > MAX_BODY {
                return Err(ReadError::TooLarge);
            }
            body.extend(self.take(size).await?);
            if !self.line().await?.is_empty() {
                return Err(ReadError::Malformed);
            }
        }
    }

    /// The next CRLF-terminated line, without the CRLF.
    async fn line(&mut self) -> Result<Vec<u8>, ReadError> {
        loop {
            if let Some(end) = find(&self.buf, b"\r\n") {
                let mut line: Vec<u8> = self.buf.drain(..end + 2).collect();
                line.truncate(end);
                return Ok(line);
            }
            if self.buf.len() > MAX_HEAD {
                return Err(ReadError::Malformed);
            }
            self.fill().await?;
        }
    }

    async fn take(&mut self, n: usize) -> Result<Vec<u8>, ReadError> {
        while self.buf.len() < n {
            self.fill().await?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    async fn fill(&mut self) -> Result<(), ReadError> {
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk).await? {
            0 => Err(ReadError::Closed),
            n => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(())
            }
        }
    }
}

/// Position of `needle` in `haystack` (the CRLF delimiters of requests and answers).
pub(super) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// `Content-Length` as a number; repeated headers must agree.
fn content_length(head: &Head) -> Result<Option<usize>, ReadError> {
    let mut found = None;
    for raw in head.all("content-length") {
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ReadError::Malformed);
        }
        // Too many digits for usize is certainly more than the limit.
        let n = raw.parse::<usize>().unwrap_or(usize::MAX);
        if found.is_some_and(|f| f != n) {
            return Err(ReadError::Malformed);
        }
        found = Some(n);
    }
    Ok(found)
}

fn parse_head(raw: &[u8]) -> Option<Head> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    let token = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic());
    if parts.next().is_some()
        || !token(method)
        || !token(target)
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
    {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        // No obsolete line folding, no blanks before the colon (RFC 9112 §5.1).
        if !token(name) {
            return None;
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    Some(Head {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
    })
}
