//! One `GET` over a SOCKS-tunnelled stream: TLS (SNI, ALPN http/1.1, verified certificates),
//! the request bytes and a small HTTP/1.1 response reader (Content-Length, chunked or EOF body,
//! capped). Hand-written on purpose: one GET does not justify an HTTP client stack here.
use rustls::pki_types::ServerName;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Response head cap (status line + headers).
const HEAD_CAP: u64 = 16 * 1024;
/// Chunk-size line cap.
const LINE_CAP: u64 = 1024;

/// Why the exchange failed (mapped to log stage and code by the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpFail {
    /// TLS handshake (including an untrusted certificate).
    Tls,
    /// Writing the request or reading the response head.
    Io,
    /// A status other than 200 (redirects are never followed).
    Status(u16),
    /// The body is larger than the cap.
    TooLarge,
    /// The body could not be read completely.
    BodyIo,
}

/// The transport put on top of the tunnelled TCP stream.
pub(crate) enum Wrap {
    Tls(TlsConnector),
    /// Tests only: plain HTTP over the tunnel, to exercise the reader without certificates.
    #[cfg(test)]
    Plain,
}

impl Wrap {
    /// TLS with the Windows trust store (platform verifier), ALPN `http/1.1`; rustls never
    /// negotiates below TLS 1.2.
    pub(crate) fn tls() -> Result<Self, rustls::Error> {
        let config = crate::tls_client::verified(&[b"http/1.1".as_slice()])?;
        Ok(Wrap::Tls(TlsConnector::from(config)))
    }

    /// TLS with a given client config (ALPN set here).
    #[cfg(test)]
    pub(crate) fn with_config(mut config: rustls::ClientConfig) -> Self {
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Wrap::Tls(TlsConnector::from(std::sync::Arc::new(config)))
    }

    /// `GET path` on `host` over `stream`; the body when the status is 200 and the body fits.
    pub(crate) async fn get(
        &self,
        stream: TcpStream,
        host: &str,
        path: &str,
        cap: usize,
    ) -> Result<Vec<u8>, HttpFail> {
        match self {
            Wrap::Tls(connector) => {
                let name = ServerName::try_from(host.to_owned()).map_err(|_| HttpFail::Tls)?;
                let tls = connector
                    .connect(name, stream)
                    .await
                    .map_err(|_| HttpFail::Tls)?;
                exchange(tls, host, path, cap).await
            }
            #[cfg(test)]
            Wrap::Plain => exchange(stream, host, path, cap).await,
        }
    }
}

/// Writes the request and reads the response (exactly the old headers plus `Host`, which
/// Node's `https.request` added implicitly).
pub(crate) async fn exchange<S>(
    mut stream: S,
    host: &str,
    path: &str,
    cap: usize,
) -> Result<Vec<u8>, HttpFail>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: text/plain\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| HttpFail::Io)?;
    stream.flush().await.map_err(|_| HttpFail::Io)?;
    let mut reader = tokio::io::BufReader::new(stream);
    let head = read_head(&mut reader).await?;
    let (status, length, chunked) = parse_head(&head)?;
    if status != 200 {
        return Err(HttpFail::Status(status));
    }
    if chunked {
        return read_chunked(&mut reader, cap).await;
    }
    match length {
        Some(len) if len > cap => Err(HttpFail::TooLarge),
        Some(len) => {
            let mut body = vec![0; len];
            reader
                .read_exact(&mut body)
                .await
                .map_err(|_| HttpFail::BodyIo)?;
            Ok(body)
        }
        None => read_to_close(&mut reader, cap).await,
    }
}

/// Status line and headers up to the empty line.
async fn read_head<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, HttpFail> {
    let mut head = Vec::new();
    let mut limited = reader.take(HEAD_CAP);
    loop {
        let start = head.len();
        let n = limited
            .read_until(b'\n', &mut head)
            .await
            .map_err(|_| HttpFail::Io)?;
        if n == 0 {
            return Err(HttpFail::Io);
        }
        if head[start..] == *b"\r\n" || head[start..] == *b"\n" {
            return Ok(head);
        }
    }
}

/// `(status, content-length, chunked)` of a response head.
fn parse_head(head: &[u8]) -> Result<(u16, Option<usize>, bool), HttpFail> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(HttpFail::Io),
    }
    let status = response.code.ok_or(HttpFail::Io)?;
    let mut length = None;
    let mut chunked = false;
    for header in response.headers.iter() {
        let value = String::from_utf8_lossy(header.value);
        if header.name.eq_ignore_ascii_case("content-length") {
            length = Some(value.trim().parse::<usize>().map_err(|_| HttpFail::Io)?);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    Ok((status, length, chunked))
}

/// A chunked body (trailers ignored), refused as soon as it exceeds `cap`.
async fn read_chunked<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> Result<Vec<u8>, HttpFail> {
    let mut body = Vec::new();
    loop {
        let mut line = String::new();
        (&mut *reader)
            .take(LINE_CAP)
            .read_line(&mut line)
            .await
            .map_err(|_| HttpFail::BodyIo)?;
        let size = line.trim().split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| HttpFail::BodyIo)?;
        if size == 0 {
            return Ok(body);
        }
        if body.len() + size > cap {
            return Err(HttpFail::TooLarge);
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader
            .read_exact(&mut body[start..])
            .await
            .map_err(|_| HttpFail::BodyIo)?;
        let mut crlf = [0; 2];
        reader
            .read_exact(&mut crlf)
            .await
            .map_err(|_| HttpFail::BodyIo)?;
        if crlf != *b"\r\n" {
            return Err(HttpFail::BodyIo);
        }
    }
}

/// A body delimited by the connection close. A peer closing without TLS `close_notify` (common
/// with `Connection: close`) still ends the body.
async fn read_to_close<R: AsyncRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> Result<Vec<u8>, HttpFail> {
    let mut body = Vec::new();
    let read = reader.take(cap as u64 + 1).read_to_end(&mut body).await;
    match read {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(_) => return Err(HttpFail::BodyIo),
    }
    if body.len() > cap {
        return Err(HttpFail::TooLarge);
    }
    Ok(body)
}
