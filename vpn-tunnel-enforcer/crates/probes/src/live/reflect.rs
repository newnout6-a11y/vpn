//! Egress reflectors and the media (Twitch HLS) endpoints, each through its own SOCKS
//! connection to the probe inbound and under one deadline (live-probe §3.12-§3.14.3; B-17,
//! B-29, B-31, B-34, B-35). A status line read through the tunnel is the end-to-end proof the
//! handshake verdict needs (B-04).
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::Loopback;
use vpnte_core::net::is_public_ip;

use super::model::{
    Egress, EgressStatus, Ipv6Status, MediaEndpoint, MediaStatus, MediaStream, Reflector,
    ReflectorStatus,
};
use super::ms;
use super::wire::{HeadError, Wire, exchange_head, read_body};
use crate::key_health::parse_trace;
use crate::live_stages::CANCELLED;

/// What one request through the tunnel showed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Attempt {
    /// Wire, HTTP or parse failure; `None` on success.
    pub error: Option<String>,
    /// The SOCKS CONNECT was accepted.
    pub socks_ok: bool,
    /// An HTTP status line came back through the tunnel.
    pub proof: bool,
    /// Milliseconds from the attempt's start to its end.
    pub ms: u64,
    pub timed_out: bool,
    /// The exit cannot reach this address family (SOCKS reply 3 / 4 / 8).
    pub unsupported: bool,
}

/// Status, body and negotiated TLS version of a response.
type Response = (u16, Vec<u8>, Option<String>);

/// One HTTPS request through `proxy` under `limit`: `GET` (reflectors, body ≤ 4 KiB) or `HEAD`
/// (media, status only).
async fn request(
    wire: &Wire,
    proxy: &Loopback,
    target: (&str, &str),
    head_only: bool,
    path: &str,
    limit: Duration,
    cancel: &CancellationToken,
) -> (Attempt, Result<Response, String>) {
    let (connect_host, sni) = target;
    let start = Instant::now();
    let mut attempt = Attempt::default();
    let work = async {
        let (mut stream, version) = match wire.open(proxy, connect_host, 443, sni).await {
            Ok(s) => s,
            Err(e) => {
                attempt.unsupported = e.unsupported_family();
                attempt.socks_ok = matches!(e, super::wire::WireError::Tls(_));
                return Err(e.text());
            }
        };
        attempt.socks_ok = true;
        let request = if head_only {
            format!(
                "HEAD {path} HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nConnection: close\r\n\r\n"
            )
        } else {
            format!("GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n")
        };
        let (head, rest) = exchange_head(&mut stream, &request)
            .await
            .map_err(|e: HeadError| e.text())?;
        attempt.proof = true;
        if head_only {
            return Ok((head.status, Vec::new(), version));
        }
        if !(200..300).contains(&head.status) {
            return Err(format!("reflector returned HTTP {}", head.status));
        }
        let body = read_body(&mut stream, &head, rest, 4096).await?;
        Ok((head.status, body, version))
    };
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => Err(CANCELLED.to_owned()),
        r = tokio::time::timeout(limit, work) => r.unwrap_or_else(|_| Err("timeout".into())),
    };
    attempt.timed_out = result.as_ref().is_err_and(|e| e == "timeout");
    attempt.ms = ms(start.elapsed());
    attempt.error = result.as_ref().err().cloned();
    (attempt, result)
}

/// One reflector: where to connect, the SNI / Host, the path and its deadline.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReflectorSpec {
    pub source: &'static str,
    pub connect: &'static str,
    pub sni: &'static str,
    pub path: &'static str,
    pub limit: Duration,
    /// 0 = Cloudflare trace (any family), 4 / 6 = plain-text IP of that family.
    pub family: u8,
}

/// The three reflectors (§3.14.3). The trace dials an IP literal so no DNS is needed at the exit.
pub(crate) const REFLECTORS: [ReflectorSpec; 3] = [
    ReflectorSpec {
        source: "cloudflare-trace",
        connect: "1.1.1.1",
        sni: "cloudflare-dns.com",
        path: "/cdn-cgi/trace",
        limit: Duration::from_millis(4000),
        family: 0,
    },
    ReflectorSpec {
        source: "ipify",
        connect: "api.ipify.org",
        sni: "api.ipify.org",
        path: "/?format=text",
        limit: Duration::from_millis(3500),
        family: 4,
    },
    ReflectorSpec {
        source: "ipify-v6",
        connect: "api6.ipify.org",
        sni: "api6.ipify.org",
        path: "/?format=text",
        limit: Duration::from_millis(3500),
        family: 6,
    },
];

/// The two media endpoints (label, host).
pub(crate) const MEDIA: [(&str, &str); 2] = [
    ("usher.ttvnw.net (HLS Origin)", "usher.ttvnw.net"),
    ("static.twitchcdn.net (Twitch CDN)", "static.twitchcdn.net"),
];
/// Deadline of one media endpoint (dial + TLS + HEAD).
pub(crate) const MEDIA_DEADLINE: Duration = Duration::from_millis(3500);

/// Plain-text (or `{"ip": …}`) body of ipify as an address.
fn body_ip(body: &[u8]) -> Option<IpAddr> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    let ip = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) => v.get("ip")?.as_str()?.trim().to_owned(),
        Err(_) => text.to_owned(),
    };
    ip.parse().ok()
}

fn family_of(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 4 } else { 6 }
}

/// Runs one reflector and turns its outcome into a row entry; `attempt.error` is the entry's.
pub(crate) async fn reflector(
    wire: &Wire,
    proxy: &Loopback,
    spec: ReflectorSpec,
    cancel: &CancellationToken,
) -> (Reflector, Attempt) {
    let target = (spec.connect, spec.sni);
    let (mut attempt, response) =
        request(wire, proxy, target, false, spec.path, spec.limit, cancel).await;
    let mut row = Reflector {
        source: spec.source.to_owned(),
        ip: None,
        family: (spec.family != 0).then_some(spec.family),
        country: None,
        duration_ms: attempt.ms,
        status: ReflectorStatus::Error,
        error: None,
    };
    let found = match &response {
        Ok((_, body, _)) if spec.family == 0 => {
            let (ip, country) = parse_trace(&String::from_utf8_lossy(body));
            row.country = country.map(|c| c.as_str().to_owned());
            ip.ok_or("Cloudflare trace did not contain valid public IP")
        }
        Ok((_, body, _)) => body_ip(body)
            .filter(|ip| is_public_ip(*ip) && family_of(*ip) == spec.family)
            .ok_or(if spec.family == 6 {
                "IPv6 reflector returned no valid IPv6 address"
            } else {
                "ipify did not return a valid public IP"
            }),
        Err(e) => {
            row.status = if attempt.timed_out {
                ReflectorStatus::Timeout
            } else if attempt.unsupported && spec.family == 6 {
                ReflectorStatus::Unsupported
            } else {
                ReflectorStatus::Error
            };
            row.error = Some(e.clone());
            return (row, attempt);
        }
    };
    match found {
        Ok(ip) => {
            row.status = ReflectorStatus::Ok;
            row.family = Some(family_of(ip));
            row.ip = Some(ip.to_string());
        }
        Err(why) => {
            row.error = Some(why.to_owned());
            attempt.error = Some(why.to_owned());
        }
    }
    (row, attempt)
}

/// Runs one media endpoint: reachable when any status line arrived (§3.12).
pub(crate) async fn media_endpoint(
    wire: &Wire,
    proxy: &Loopback,
    (label, host): (&str, &str),
    cancel: &CancellationToken,
) -> (MediaEndpoint, Attempt) {
    let (attempt, response) =
        request(wire, proxy, (host, host), true, "/", MEDIA_DEADLINE, cancel).await;
    let row = MediaEndpoint {
        endpoint: label.to_owned(),
        reachable: response.is_ok(),
        latency_ms: Some(attempt.ms),
        protocol: response.ok().and_then(|(_, _, version)| version),
        error: attempt.error.clone(),
    };
    (row, attempt)
}

/// Egress verdict from the reflector rows (§3.14.3 with B-09, B-34): `ok` needs two answers and
/// no IPv4 disagreement; the IPv6 status is derived once from all IPv6 evidence.
pub(crate) fn aggregate_egress(
    reflectors: Vec<Reflector>,
    endpoint_ip: Option<IpAddr>,
    duration_ms: u64,
) -> Egress {
    let answered: Vec<&Reflector> = reflectors
        .iter()
        .filter(|r| r.status == ReflectorStatus::Ok && r.ip.is_some())
        .collect();
    let v4: Vec<&Reflector> = answered
        .iter()
        .copied()
        .filter(|r| r.family == Some(4))
        .collect();
    let exit_ipv4 = v4.first().and_then(|r| r.ip.clone());
    let exit_ipv6 = answered
        .iter()
        .find(|r| r.family == Some(6))
        .and_then(|r| r.ip.clone());
    let discrepancy = v4.first().and_then(|first| {
        let other = v4.iter().skip(1).find(|r| r.ip != first.ip)?;
        let pair = |r: &Reflector| format!("{}={}", r.source, r.ip.as_deref().unwrap_or_default());
        Some(
            Msg::new("probes.live.egress.discrepancy")
                .arg("first", pair(first))
                .arg("second", pair(other)),
        )
    });
    let status = match answered.len() {
        0 => EgressStatus::Error,
        1 => EgressStatus::Partial,
        _ if discrepancy.is_some() => EgressStatus::Partial,
        _ => EgressStatus::Ok,
    };
    let v6_row = reflectors.iter().find(|r| r.source == "ipify-v6");
    let ipv6_status = if exit_ipv6.is_some() {
        Some(Ipv6Status::Ok)
    } else {
        v6_row.map(|r| match r.status {
            ReflectorStatus::Unsupported => Ipv6Status::Unsupported,
            ReflectorStatus::Timeout => Ipv6Status::Timeout,
            _ => Ipv6Status::Error,
        })
    };
    let error = (status == EgressStatus::Error)
        .then(|| reflectors.iter().find_map(|r| r.error.clone()))
        .flatten();
    Egress {
        status,
        duration_ms,
        matches_endpoint: match (&exit_ipv4, endpoint_ip) {
            (Some(exit), Some(ep)) => Some(*exit == ep.to_string()),
            _ => None,
        },
        exit_ipv4,
        exit_ipv6,
        ipv6_status,
        country: reflectors
            .iter()
            .find(|r| r.source == "cloudflare-trace")
            .and_then(|r| r.country.clone()),
        endpoint_ip: endpoint_ip.map(|ip| ip.to_string()),
        discrepancy: discrepancy.map(Into::into),
        error,
        reflectors,
        ..Egress::default()
    }
}

/// Media verdict (§3.13): unreachable → error; a TCP-only profile whose QUIC is not rejected →
/// warning (Twitch error #2000: the browser's HTTP/3 packets vanish); else ok.
pub(crate) fn summarize_media(
    endpoints: Vec<MediaEndpoint>,
    udp_capable: bool,
    quic_blocked: bool,
    duration_ms: u64,
) -> MediaStream {
    let reachable = endpoints.iter().any(|e| e.reachable);
    let risk = !udp_capable && !quic_blocked;
    let (status, key) = if !reachable && !endpoints.is_empty() {
        (MediaStatus::Error, "probes.live.media.unreachable")
    } else if risk {
        (MediaStatus::Warning, "probes.live.media.risk")
    } else if quic_blocked {
        // The guard text wins over the UDP one (old order).
        (MediaStatus::Ok, "probes.live.media.guarded")
    } else {
        (MediaStatus::Ok, "probes.live.media.udp")
    };
    MediaStream {
        status,
        duration_ms,
        twitch_hls_reachable: Some(reachable),
        quic_fallback_guarded: Some(udp_capable || quic_blocked),
        error2000_risk: Some(risk),
        tested_endpoints: endpoints,
        detail: Some(Msg::new(key).into()),
        ..MediaStream::default()
    }
}
