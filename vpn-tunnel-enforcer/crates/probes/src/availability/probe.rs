//! The measuring stages of one path. Each stage opens its own connection, as the old app did,
//! so every stage is an independent fact (a TLS failure is not hidden by a reused socket).
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{ACCEPT, CACHE_CONTROL, RANGE, SERVER};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::{TcpSocket, TcpStream};
use url::{Host, Url};
use vpnte_core::net::{self, Route};
use vpnte_core::resolve::{self, How, ResolveError};

use super::geo_block::{PageSignal, html_to_signal};
use super::report::{DnsStage, ErrorCode, HttpStage, TcpStage, TlsStage};
use super::target::ProbeTarget;

pub(super) const DNS_LIMIT: Duration = Duration::from_secs(5);
pub(super) const TCP_LIMIT: Duration = Duration::from_secs(5);
pub(super) const TLS_LIMIT: Duration = Duration::from_secs(6);
/// Per request (HEAD, then the ranged GET fallback).
pub(super) const HTTP_LIMIT: Duration = Duration::from_secs(8);
pub(super) const PAGE_LIMIT: Duration = Duration::from_secs(8);
/// Page bodies beyond this are cut (the signal needs the first screen, not the whole site).
const PAGE_BODY_CAP: usize = 512 * 1024;
/// Addresses tried per stage before giving up.
const MAX_ADDRS: usize = 3;
/// Answers kept in the report.
const MAX_IPS: usize = 8;
/// A common desktop browser: some origins refuse unknown clients with a 403 the user never sees.
const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
/// Landing addresses of Russian block pages (publicly documented); kept as data, may age.
const KNOWN_STUB_IPS: [IpAddr; 5] = [
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V4(Ipv4Addr::new(109, 207, 10, 100)),
    IpAddr::V4(Ipv4Addr::new(95, 213, 255, 114)),
    IpAddr::V4(Ipv4Addr::new(178, 176, 106, 249)),
];
/// Last labels of names that legitimately resolve to private addresses.
const LOCAL_SUFFIXES: [&str; 11] = [
    "local",
    "localhost",
    "localdomain",
    "lan",
    "home",
    "internal",
    "intranet",
    "corp",
    "arpa",
    "test",
    "invalid",
];

/// Local addresses the protected side binds its sockets to. Under Windows' strong-host send
/// model a socket bound to the TUN address can only leave through the TUN, so the measurement is
/// provably "with protection" and a TUN outage is an error instead of a silent direct dial.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Bind {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

impl Bind {
    /// `None`: this family may not be dialled; `Some(None)`: dial unbound.
    fn local_for(self, target: SocketAddr) -> Option<Option<IpAddr>> {
        if self.v4.is_none() && self.v6.is_none() {
            return Some(None);
        }
        match target {
            SocketAddr::V4(_) => self.v4.map(|ip| Some(IpAddr::V4(ip))),
            SocketAddr::V6(_) => self.v6.map(|ip| Some(IpAddr::V6(ip))),
        }
    }

    /// Address for reqwest's `local_address` (IPv4 preferred: the TUN is IPv4 first).
    fn http_local(self) -> Option<IpAddr> {
        self.v4.map(IpAddr::V4).or(self.v6.map(IpAddr::V6))
    }
}

/// Milliseconds since `start`, saturated.
pub(super) fn ms(start: Instant) -> u32 {
    u32::try_from(start.elapsed().as_millis()).unwrap_or(u32::MAX)
}

/// Runs `fut` for at most `cap`, and never past `deadline`.
pub(super) async fn limited<T>(
    deadline: Instant,
    cap: Duration,
    fut: impl Future<Output = T>,
) -> Result<T, ErrorCode> {
    let left = deadline.saturating_duration_since(Instant::now());
    tokio::time::timeout(cap.min(left), fut)
        .await
        .map_err(|_| ErrorCode::TimedOut)
}

/// A name expected to have public addresses (has a dot, no local suffix).
fn public_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, last)| !LOCAL_SUFFIXES.contains(&last))
}

/// Suspected DNS spoofing: a known stub address, or a non-public answer for a public name.
pub(super) fn suspicious(name: &str, ips: &[IpAddr]) -> bool {
    ips.iter().any(|ip| {
        let ip = net::unmap(*ip);
        KNOWN_STUB_IPS.contains(&ip) || (public_name(name) && !net::is_public_ip(ip))
    })
}

/// An answer no site can be measured at (block-page stub, loopback, unspecified).
fn undialable(ip: IpAddr) -> bool {
    let ip = net::unmap(ip);
    KNOWN_STUB_IPS.contains(&ip) || ip.is_loopback() || ip.is_unspecified()
}

/// DNS stage through the OS resolver (the TUN's DNS while protection is on). IP literals need
/// no lookup. Returns the stage and, when the path must stop here, the cause.
pub(super) async fn dns_stage(
    host: &Host<String>,
    deadline: Instant,
) -> (DnsStage, Option<ErrorCode>) {
    let name = match host {
        Host::Domain(name) => name,
        Host::Ipv4(ip) => return (literal(IpAddr::V4(*ip)), None),
        Host::Ipv6(ip) => return (literal(IpAddr::V6(*ip)), None),
    };
    let start = Instant::now();
    let answer = limited(
        deadline,
        DNS_LIMIT,
        resolve::resolve_host(name, How::System, |_| true),
    )
    .await;
    let ms = Some(ms(start));
    let failed = |code| {
        let stage = DnsStage {
            resolved: false,
            ips: Vec::new(),
            ms,
            poisoned: false,
        };
        (stage, Some(code))
    };
    match answer {
        Ok(Ok(mut ips)) => {
            ips.truncate(MAX_IPS);
            let poisoned = suspicious(name, &ips);
            // A stub or loopback answer cannot measure the site; other suspicious answers (a
            // private address of a split-horizon name) are still dialled and only flagged.
            let stop = ips
                .iter()
                .any(|ip| undialable(*ip))
                .then_some(ErrorCode::DnsSuspect);
            (
                DnsStage {
                    resolved: true,
                    ips,
                    ms,
                    poisoned,
                },
                stop,
            )
        }
        Ok(Err(ResolveError::Failed)) => failed(ErrorCode::DnsTemporary),
        Ok(Err(_)) => failed(ErrorCode::NameNotFound),
        Err(code) => failed(code),
    }
}

fn literal(ip: IpAddr) -> DnsStage {
    DnsStage {
        resolved: true,
        ips: vec![ip],
        ms: Some(0),
        poisoned: false,
    }
}

/// Connects to the first reachable address allowed by `bind` (at most [`MAX_ADDRS`] tries).
async fn connect_any(addrs: &[SocketAddr], bind: Bind) -> Result<TcpStream, ErrorCode> {
    let mut last = ErrorCode::NetUnreachable;
    for addr in addrs
        .iter()
        .copied()
        .filter(|a| bind.local_for(*a).is_some())
        .take(MAX_ADDRS)
    {
        match connect(addr, bind).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last = ErrorCode::classify(&err),
        }
    }
    Err(last)
}

async fn connect(addr: SocketAddr, bind: Bind) -> std::io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(Some(local)) = bind.local_for(addr) {
        socket.bind(SocketAddr::new(local, 0))?;
    }
    socket.connect(addr).await
}

/// TCP stage: a plain connect, closed at once.
pub(super) async fn tcp_stage(
    addrs: &[SocketAddr],
    bind: Bind,
    deadline: Instant,
) -> (TcpStage, Option<ErrorCode>) {
    let start = Instant::now();
    match limited(deadline, TCP_LIMIT, connect_any(addrs, bind)).await {
        Ok(Ok(_stream)) => (
            TcpStage {
                connected: true,
                ms: Some(ms(start)),
            },
            None,
        ),
        Ok(Err(code)) | Err(code) => (
            TcpStage {
                connected: false,
                ms: None,
            },
            Some(code),
        ),
    }
}

/// TLS stage: a fresh connection and a handshake with SNI (none for IP literals) that accepts
/// any certificate: a self-signed or mismatched certificate still proves TLS reachability.
pub(super) async fn tls_stage(
    target: &ProbeTarget,
    addrs: &[SocketAddr],
    bind: Bind,
    deadline: Instant,
) -> (TlsStage, Option<ErrorCode>) {
    let failed = |code| {
        (
            TlsStage {
                handshake_ok: false,
                ms: None,
                protocol: None,
                cipher: None,
            },
            Some(code),
        )
    };
    let name = match target.host() {
        Host::Domain(name) => ServerName::try_from(name.clone()),
        Host::Ipv4(ip) => Ok(ServerName::from(IpAddr::V4(*ip))),
        Host::Ipv6(ip) => Ok(ServerName::from(IpAddr::V6(*ip))),
    };
    let (Ok(name), Some(config)) = (name, tls_config()) else {
        return failed(ErrorCode::TlsProtocol);
    };
    let start = Instant::now();
    let handshake = async {
        let stream = connect_any(addrs, bind).await?;
        tokio_rustls::TlsConnector::from(config)
            .connect(name, stream)
            .await
            .map_err(|err| ErrorCode::classify(&err))
    };
    match limited(deadline, TLS_LIMIT, handshake).await {
        Ok(Ok(tls)) => {
            let (_, conn) = tls.get_ref();
            let protocol = conn.protocol_version().map(|v| match v {
                rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_owned(),
                rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_owned(),
                other => format!("{other:?}"),
            });
            let cipher = conn
                .negotiated_cipher_suite()
                .map(|s| format!("{:?}", s.suite()));
            (
                TlsStage {
                    handshake_ok: true,
                    ms: Some(ms(start)),
                    protocol,
                    cipher,
                },
                None,
            )
        }
        Ok(Err(code)) | Err(code) => failed(code),
    }
}

/// rustls client config of the TLS stage (ring provider, browser-like ALPN, any certificate).
fn tls_config() -> Option<Arc<ClientConfig>> {
    crate::tls_client::inspecting(&[b"h2".as_slice(), b"http/1.1".as_slice()]).ok()
}

/// The two HTTP clients of one path: the status probe (≤ 3 redirects, as before) and the page
/// fetch (≤ 5 redirects). Both validate certificates and never use the system proxy.
pub(super) struct Clients {
    status: reqwest::Client,
    page: reqwest::Client,
}

impl Clients {
    /// Clients for `route`, bound to the protected-side address when `bind` has one.
    pub(super) fn new(route: &Route, bind: Bind) -> Option<Clients> {
        let build = |limit: Duration, redirects: usize| {
            let mut builder = net::builder_for(route, limit)
                .ok()?
                .redirect(reqwest::redirect::Policy::limited(redirects))
                .user_agent(BROWSER_UA);
            if let Some(local) = bind.http_local() {
                builder = builder.local_address(local);
            }
            builder.build().ok()
        };
        Some(Clients {
            status: build(HTTP_LIMIT, 3)?,
            page: build(PAGE_LIMIT, 5)?,
        })
    }
}

/// HTTP stage: HEAD, and a one-byte ranged GET when HEAD fails or is refused (405 / 501).
pub(super) async fn http_stage(
    clients: &Clients,
    url: &Url,
    deadline: Instant,
) -> (HttpStage, Option<ErrorCode>) {
    let start = Instant::now();
    let request = async {
        let client = &clients.status;
        let head = client
            .head(url.clone())
            .header(CACHE_CONTROL, "no-cache")
            .send()
            .await;
        match head {
            Ok(resp) if !matches!(resp.status().as_u16(), 405 | 501) => Ok(resp),
            _ => {
                let get = client.get(url.clone()).header(RANGE, "bytes=0-0");
                get.header(CACHE_CONTROL, "no-cache").send().await
            }
        }
    };
    // Two requests of up to HTTP_LIMIT each.
    match limited(deadline, HTTP_LIMIT * 2, request).await {
        Ok(Ok(resp)) => {
            let server = resp
                .headers()
                .get(SERVER)
                .and_then(|v| v.to_str().ok())
                .map(|s| {
                    s.chars()
                        .filter(|c| c.is_ascii_graphic() || *c == ' ')
                        .take(64)
                        .collect()
                })
                .filter(|s: &String| !s.is_empty());
            let stage = HttpStage {
                status: Some(resp.status().as_u16()),
                ms: Some(ms(start)),
                server,
            };
            (stage, None)
        }
        Ok(Err(err)) => (
            HttpStage {
                status: None,
                ms: None,
                server: None,
            },
            Some(classify_http(&err)),
        ),
        Err(code) => (
            HttpStage {
                status: None,
                ms: None,
                server: None,
            },
            Some(code),
        ),
    }
}

/// Error code of a reqwest failure; SOCKS replies of the engine's direct inbound only carry
/// their meaning in the message ("host unreachable", "connection refused").
fn classify_http(err: &reqwest::Error) -> ErrorCode {
    let code = ErrorCode::classify(err);
    if code != ErrorCode::Unknown {
        return code;
    }
    let mut text = String::new();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        text.push_str(&e.to_string().to_lowercase());
        text.push('\n');
        current = e.source();
    }
    const HINTS: [(&str, ErrorCode); 7] = [
        ("connection refused", ErrorCode::ConnRefused),
        ("connection closed", ErrorCode::Closed),
        ("connection reset", ErrorCode::ConnReset),
        ("host unreachable", ErrorCode::HostUnreachable),
        ("network unreachable", ErrorCode::NetUnreachable),
        ("ttl expired", ErrorCode::TimedOut),
        ("timed out", ErrorCode::TimedOut),
    ];
    HINTS.iter().find(|(hint, _)| text.contains(hint)).map_or(
        if err.is_body() || err.is_decode() {
            ErrorCode::BadResponse
        } else {
            code
        },
        |(_, c)| *c,
    )
}

/// Fetches the page the way a browser would request it and turns it into a [`PageSignal`].
/// Any failure is "no signal" (never "not blocked").
pub(super) async fn page_signal(
    clients: &Clients,
    url: &Url,
    deadline: Instant,
) -> Option<PageSignal> {
    let fetch = async {
        let mut resp = clients
            .page
            .get(url.clone())
            .header(ACCEPT, "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
            .header(CACHE_CONTROL, "no-cache")
            .send()
            .await
            .ok()?;
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.ok()? {
            body.extend_from_slice(&chunk);
            if body.len() >= PAGE_BODY_CAP {
                body.truncate(PAGE_BODY_CAP);
                break;
            }
        }
        let html = String::from_utf8_lossy(&body);
        Some(html_to_signal(
            url.as_str(),
            Some(&final_url),
            Some(status),
            &html,
        ))
    };
    limited(deadline, PAGE_LIMIT, fetch).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    /// B-UA-9: stub addresses and non-public answers for public names are suspicious; a
    /// private answer for a local name is not.
    #[test]
    fn dns_suspicion() {
        assert!(suspicious("rutracker.org", &ips(&["95.213.255.114"])));
        assert!(suspicious("rutracker.org", &ips(&["127.0.0.1"])));
        assert!(suspicious(
            "example.com",
            &ips(&["93.184.215.14", "10.0.0.5"])
        ));
        assert!(suspicious("example.com", &ips(&["::ffff:0.0.0.0"])));
        assert!(!suspicious(
            "example.com",
            &ips(&["93.184.215.14", "2606:2800:21f:cb07::1"])
        ));
        assert!(!suspicious("nas.local", &ips(&["192.168.1.10"])));
        assert!(!suspicious("intranet", &ips(&["10.1.2.3"])));
        assert!(undialable("127.0.0.1".parse().unwrap()));
        assert!(undialable("::".parse().unwrap()));
        assert!(!undialable("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn binding_follows_the_family() {
        let any = Bind::default();
        let v4 = "1.2.3.4:443".parse().unwrap();
        let v6 = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(any.local_for(v6), Some(None));
        let tun = Bind {
            v4: Some(Ipv4Addr::new(192, 168, 250, 254)),
            v6: None,
        };
        assert_eq!(
            tun.local_for(v4),
            Some(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 250, 254))))
        );
        assert_eq!(tun.local_for(v6), None, "no IPv6 around the tunnel");
        assert!(tls_config().is_some());
    }
}
