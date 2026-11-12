//! The real transport of the chain: DoH through reqwest (rustls; HTTP/2 when the server offers
//! it, which Quad9 requires) and DNS over TCP with the RFC 1035 §4.2.2 length prefix. Both go
//! direct, never through the system proxy (contract §3.9).
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::Context as _;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vpnte_base::http;
use vpnte_base::types::Loopback;

use super::chain::{Transport, UPSTREAM_LIMIT, Upstream};
use crate::net::HostPort;
use crate::socks5;

const MESSAGE: &str = "application/dns-message";
/// DoH bodies above this are refused instead of buffered (a DNS message never needs more).
pub(super) const BODY_CAP: usize = 64 * 1024;
const CONNECT_LIMIT: Duration = Duration::from_secs(2);
/// Pooled DoH connections are dropped soon: one opened before the TUN came up must not be
/// reused long after it.
const POOL_IDLE: Duration = Duration::from_secs(30);

/// DoH and TCP/53 over the network.
pub(super) struct Net {
    /// `None` only when the TLS client cannot be built: TCP/53 is then all that is left.
    client: Option<reqwest::Client>,
    /// Through this loopback SOCKS5 inbound instead of direct (the network-mode check while our
    /// TUN runs: the app's own sockets would otherwise enter the tunnel).
    via: Option<Loopback>,
}

impl Net {
    pub(super) fn new() -> Net {
        Net::build(None)
    }

    /// Every exchange through `proxy` (SOCKS5, names resolved by the proxy).
    pub(super) fn via(proxy: &Loopback) -> Net {
        Net::build(Some(proxy.clone()))
    }

    fn build(via: Option<Loopback>) -> Net {
        let mut builder = http::client_builder(UPSTREAM_LIMIT)
            .connect_timeout(CONNECT_LIMIT)
            .pool_idle_timeout(POOL_IDLE);
        if let Some(proxy) = &via {
            match socks_proxy(proxy) {
                Ok(p) => builder = builder.proxy(p),
                Err(err) => tracing::warn!(error = %err, "DoH proxy route not usable"),
            }
        }
        let client = builder.build();
        if let Err(err) = &client {
            tracing::warn!(error = %err, "DoH client could not be built; only DNS over TCP is left");
        }
        Net {
            client: client.ok(),
            via,
        }
    }
}

/// `socks5h://user:pass@127.0.0.1:port` (credentials percent-encoded by `Url`).
fn socks_proxy(proxy: &Loopback) -> anyhow::Result<reqwest::Proxy> {
    let mut url = url::Url::parse(&format!("socks5h://127.0.0.1:{}", proxy.port))?;
    if let Some(creds) = &proxy.creds {
        url.set_username(&creds.user)
            .and_then(|()| url.set_password(Some(&creds.pass)))
            .map_err(|()| anyhow::anyhow!("credentials do not fit a proxy URL"))?;
    }
    Ok(reqwest::Proxy::all(url.as_str())?)
}

impl Transport for Net {
    async fn exchange(&self, upstream: Upstream, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match upstream {
            Upstream::Doh(url) => {
                let client = self.client.as_ref().context("no DoH client")?;
                doh(client, url, query).await
            }
            Upstream::Tcp(server) => Ok(tcp(server, self.via.as_ref(), query).await?),
        }
    }
}

/// One RFC 8484 POST.
pub(super) async fn doh(
    client: &reqwest::Client,
    url: &str,
    query: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let response = client
        .post(url)
        .header(ACCEPT, MESSAGE)
        .header(CONTENT_TYPE, MESSAGE)
        .body(query.to_vec())
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;
    let status = response.status();
    anyhow::ensure!(status.is_success(), "DoH refused with HTTP {status}");
    read_capped(response, BODY_CAP).await
}

/// One question over a fresh TCP connection, direct or through `via` (SOCKS5 CONNECT).
pub(super) async fn tcp(
    server: SocketAddr,
    via: Option<&Loopback>,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let mut stream = match via {
        None => tokio::time::timeout(CONNECT_LIMIT, TcpStream::connect(server))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??,
        Some(proxy) => {
            let local = SocketAddr::from((Ipv4Addr::LOCALHOST, proxy.port));
            let target = HostPort::new(&server.ip().to_string(), server.port())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            socks5::connect(local, proxy.creds.as_ref(), &target, CONNECT_LIMIT)
                .await
                .map_err(io::Error::other)?
        }
    };
    let len =
        u16::try_from(query.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

/// The body; refused when it exceeds `cap` bytes.
async fn read_capped(mut response: reqwest::Response, cap: usize) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)?
    {
        anyhow::ensure!(body.len() + chunk.len() <= cap, "DoH body over {cap} bytes");
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests;
