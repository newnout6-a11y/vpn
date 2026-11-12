//! The real measurements of the network-mode check. Probes never leave through a VPN: with our
//! TUN up, TCP / TLS / DoH / the transfer go through the session's direct-out (`mixed-direct-in`,
//! SOCKS5) and UDP / ICMP from the uplink's address (strong host model; the kill switch permits
//! our own executable); without it, sockets bind to the uplink so another client's TUN does not
//! carry them either. The uplink is the adapter that carries the default route once every
//! tunnel is set aside (a PPPoE line included), not a guessed network card.
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Loopback;
use vpnte_base::{AppError, AppResult};
use vpnte_core::net::{HostPort, is_public_ip};
use vpnte_core::resolve::{self, DohByName, How};
use vpnte_core::socks5::{self, SocksError};

use super::{HostFacts, NetProbe, Outcome, quic, stun};
use crate::discipline::{self, Limits, Reach, TRANSFER_HOST, Transfer};
use crate::live::wire::{Dial, Wire};
use crate::live_stages::{self, ProbePath};

const DNS_LIMIT: Duration = Duration::from_secs(4);
const TCP_LIMIT: Duration = Duration::from_secs(4);
const TLS_LIMIT: Duration = Duration::from_secs(5);
/// Per QUIC or STUN datagram (two are sent).
const UDP_LIMIT: Duration = Duration::from_millis(1500);

/// [`NetProbe`] on the real network.
pub struct LiveProbe {
    /// The physical uplink (`Os` when none is up).
    path: ProbePath,
    /// The running TUN session's direct-out.
    session: Option<Loopback>,
    /// TLS with certificate verification, for the transfer.
    wire: Wire,
}

impl LiveProbe {
    /// `session` = the running session's `mixed-direct-in` while our TUN is up (`None` in Soft
    /// mode and between sessions: our own sockets go direct then); `own_tun` = our TUN's LUID
    /// when known. Sockets bind to the adapter that carries the default route past every tunnel
    /// ([`live_stages::route_uplink`]); without one, UDP and the reach are not run.
    pub async fn new(session: Option<Loopback>, own_tun: Option<u64>) -> AppResult<Self> {
        let path = tokio::task::spawn_blocking(move || live_stages::route_uplink(own_tun))
            .await
            .map_err(AppError::internal)?
            .map(|(path, _)| path)
            .unwrap_or(ProbePath::Os);
        let wire = Wire::verified().map_err(AppError::internal)?;
        Ok(LiveProbe {
            path,
            session,
            wire,
        })
    }

    /// The probes go through the session's direct-out.
    pub fn via_session(&self) -> bool {
        self.session.is_some()
    }

    /// The first address of `host` from the Windows resolver, IPv4 first.
    async fn address(&self, host: &str, port: u16) -> Option<SocketAddr> {
        let found = timeout(
            DNS_LIMIT,
            resolve::resolve_host(host, How::System, is_public_ip),
        );
        let ip = found.await.ok()?.ok()?.into_iter().next()?;
        Some(SocketAddr::new(ip, port))
    }

    async fn tcp(&self, host: &str) -> Result<TcpStream, Outcome> {
        match &self.session {
            Some(proxy) => {
                let target =
                    HostPort::new(host, super::refs::HTTPS).map_err(|_| Outcome::NotRun)?;
                let local = SocketAddr::from((Ipv4Addr::LOCALHOST, proxy.port));
                socks5::connect(local, proxy.creds.as_ref(), &target, TCP_LIMIT)
                    .await
                    .map_err(socks_outcome)
            }
            None => {
                let addr = self
                    .address(host, super::refs::HTTPS)
                    .await
                    .ok_or(Outcome::NotRun)?;
                live_stages::connect(addr, &self.path, TCP_LIMIT)
                    .await
                    .map_err(|code| match code.as_str() {
                        "ECONNREFUSED" => Outcome::Reset,
                        "ETIMEDOUT" => Outcome::Silent,
                        _ => Outcome::Failed,
                    })
            }
        }
    }
}

/// The SOCKS reply of the direct-out as a probe outcome (RFC 1928 codes).
fn socks_outcome(e: SocksError) -> Outcome {
    match e {
        SocksError::UpstreamRejected(5) => Outcome::Reset,
        // Host / network unreachable and TTL expired: the exit's dial timed out or was dropped.
        SocksError::UpstreamRejected(3 | 4 | 6) | SocksError::Io(io::ErrorKind::TimedOut) => {
            Outcome::Silent
        }
        _ => Outcome::Failed,
    }
}

/// Why a handshake did not complete.
fn tls_outcome(e: &io::Error) -> Outcome {
    match e.kind() {
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::UnexpectedEof => Outcome::Reset,
        _ => Outcome::Failed,
    }
}

impl NetProbe for LiveProbe {
    async fn system_dns(&self, name: &str) -> Outcome {
        match timeout(
            DNS_LIMIT,
            resolve::resolve_host(name, How::System, is_public_ip),
        )
        .await
        {
            Ok(Ok(_)) => Outcome::Ok,
            Ok(Err(_)) => Outcome::Failed,
            Err(_) => Outcome::Silent,
        }
    }

    async fn doh(&self, resolver: DohByName, name: &str) -> Outcome {
        let via = self.session.as_ref();
        match resolve::resolve_with(name, resolver, via, is_public_ip).await {
            Ok(_) => Outcome::Ok,
            Err(_) => Outcome::Failed,
        }
    }

    /// The handshake is judged by the inspecting client (any certificate): a completed
    /// handshake proves the path carried the server's answer, whatever the Windows store thinks
    /// of its issuer (some Russian sites use a Russian CA).
    async fn https(&self, host: &str) -> HostFacts {
        let tcp = match self.tcp(host).await {
            Ok(tcp) => tcp,
            Err(outcome) => {
                return HostFacts {
                    tcp: outcome,
                    tls: Outcome::NotRun,
                };
            }
        };
        let Ok(config) = crate::tls_client::inspecting(&[b"http/1.1".as_slice()]) else {
            return HostFacts {
                tcp: Outcome::Ok,
                tls: Outcome::NotRun,
            };
        };
        let name = live_stages::tls::server_name(host, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let handshake = tokio_rustls::TlsConnector::from(config).connect(name, tcp);
        let tls = match timeout(TLS_LIMIT, handshake).await {
            Ok(Ok(_)) => Outcome::Ok,
            Ok(Err(e)) => tls_outcome(&e),
            Err(_) => Outcome::Silent,
        };
        HostFacts {
            tcp: Outcome::Ok,
            tls,
        }
    }

    async fn transfer(&self) -> Option<Transfer> {
        let addr = match &self.session {
            Some(_) => None,
            None => Some(self.address(TRANSFER_HOST, super::refs::HTTPS).await?),
        };
        let dial = match (&self.session, addr) {
            (Some(proxy), _) => Dial::Socks(proxy),
            (None, Some(addr)) => Dial::Direct {
                addr,
                path: &self.path,
            },
            (None, None) => return None,
        };
        let cancel = CancellationToken::new();
        discipline::transfer_check(&self.wire, dial, false, Limits::STANDARD, &cancel)
            .await
            .ok()
            .map(|report| report.transfer)
    }

    async fn quic(&self, host: &str) -> Outcome {
        let Some(dst) = self.address(host, super::refs::HTTPS).await else {
            return Outcome::NotRun;
        };
        quic::probe(dst, self.path.source_for(dst.ip()), UDP_LIMIT).await
    }

    async fn stun(&self, host: &str, port: u16) -> Outcome {
        let Some(dst) = self.address(host, port).await else {
            return Outcome::NotRun;
        };
        stun::probe(dst, self.path.source_for(dst.ip()), UDP_LIMIT).await
    }

    async fn reach(&self, dst: SocketAddr) -> Reach {
        let source = self.path.source_for(dst.ip());
        discipline::reach_from(dst, source, false, self.session.is_some()).await
    }
}
