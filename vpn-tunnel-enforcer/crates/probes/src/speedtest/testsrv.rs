//! A tiny loopback HTTP/1.1 server for the transfer tests of this package (no real Internet,
//! no large payloads): one request per connection, scripted replies, a request log.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// What the server saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub method: String,
    /// Path with query.
    pub target: String,
    /// `content-length` of the request, when sent.
    pub content_length: Option<u64>,
}

/// How to answer.
pub(crate) enum Reply {
    /// Status, extra header lines, body.
    Full(u16, Vec<(&'static str, String)>, Vec<u8>),
    /// 200 with `len` bytes, written in 16 KiB pieces with `delay` between them.
    Stream { len: u64, delay: Option<Duration> },
    /// Never answer; `Server::closed` fires when the client goes away.
    Hang,
    /// Close the connection without a word.
    Close,
}

type Route = dyn Fn(&Request) -> Reply + Send + Sync;

/// A running server; dropped with the test runtime.
pub(crate) struct Server {
    pub addr: SocketAddr,
    pub log: Arc<Mutex<Vec<Request>>>,
    /// Fires (one permit) when a hung request's client closed the connection.
    pub closed: Arc<Notify>,
    /// Fires (one permit) when a request that will hang arrived.
    pub hanging: Arc<Notify>,
}

impl Server {
    pub(crate) async fn start(route: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let log = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(Notify::new());
        let hanging = Arc::new(Notify::new());
        let route: Arc<Route> = Arc::new(route);
        let (log2, closed2, hanging2) = (log.clone(), closed.clone(), hanging.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (route, log, closed, hanging) = (
                    route.clone(),
                    log2.clone(),
                    closed2.clone(),
                    hanging2.clone(),
                );
                tokio::spawn(async move {
                    let _ = serve(stream, &*route, &log, &closed, &hanging).await;
                });
            }
        });
        Server {
            addr,
            log,
            closed,
            hanging,
        }
    }

    /// `http://127.0.0.1:<port><path>`.
    pub(crate) fn url(&self, path: &str) -> url::Url {
        url::Url::parse(&format!("http://{}{path}", self.addr)).expect("test URL")
    }

    pub(crate) fn requests(&self) -> Vec<Request> {
        self.log.lock().clone()
    }
}

async fn serve(
    stream: TcpStream,
    route: &Route,
    log: &Mutex<Vec<Request>>,
    closed: &Notify,
    hanging: &Notify,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut parts = line.split_whitespace();
    let (method, target) = (
        parts.next().unwrap_or_default().to_owned(),
        parts.next().unwrap_or_default().to_owned(),
    );
    let mut content_length = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse::<u64>().ok();
        }
    }
    let request = Request {
        method,
        target,
        content_length,
    };
    log.lock().push(request.clone());
    let reply = route(&request);
    if let Some(len) = content_length {
        // Take the whole body first (an aborted upload ends here with an error).
        let mut body = (&mut reader).take(len);
        tokio::io::copy(&mut body, &mut tokio::io::sink()).await?;
    }
    let mut stream = reader.into_inner();
    match reply {
        Reply::Full(status, headers, body) => {
            let mut head = format!(
                "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(&body).await?;
        }
        Reply::Stream { len, delay } => {
            let head =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n");
            stream.write_all(head.as_bytes()).await?;
            let piece = vec![0x5au8; 16 * 1024];
            let mut left = len;
            while left > 0 {
                let n = left.min(piece.len() as u64) as usize;
                stream.write_all(&piece[..n]).await?;
                left -= n as u64;
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Reply::Hang => {
            hanging.notify_one();
            let mut buf = [0u8; 64];
            while stream.read(&mut buf).await.unwrap_or(0) > 0 {}
            closed.notify_one();
            return Ok(());
        }
        Reply::Close => return Ok(()),
    }
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// The `bytes=<n>` query value of a target, if any.
pub(crate) fn bytes_param(target: &str) -> Option<u64> {
    target
        .split(['?', '&'])
        .find_map(|kv| kv.strip_prefix("bytes=")?.parse().ok())
}
