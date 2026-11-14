//! Routing self-test, "is the split real?": the egress IP through the TUN must differ from the
//! real ISP IP seen through the engine's direct inbound (`mixed-direct-in`, hard-routed to
//! direct-out). With Smart RU on, a Russian echo reached through the normal TUN path must show
//! the real IP. Reusing the direct path for the RU check only proves that direct-out works and
//! once created false "smart RU ok" confidence, so without a reliable echo the RU part is unknown.
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Loopback, UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::net::{self, HostPort, Route};

/// Echo services for the TUN path: HTTPS only, the body must be exactly an IP (B-RS-1).
pub const TUNNEL_ECHOES: [&str; 2] = ["https://api.ipify.org/", "https://ifconfig.me/ip"];
/// Echo services for the direct path. Disjoint from [`TUNNEL_ECHOES`], so one provider never
/// sees both the VPN exit and the real address of the same user seconds apart.
pub const DIRECT_ECHOES: [&str; 2] = ["https://1.1.1.1/cdn-cgi/trace", "https://icanhazip.com/"];
/// Russian echo reached through the TUN path (Yandex Internetometer machine endpoint; answers
/// a JSON string). Never `2ip.ru`.
pub const RU_ECHOES: [&str; 1] = ["https://ipv4-internet.yandex.net/api/v0/ip"];
/// Deadline of one echo request.
pub const ECHO_TIMEOUT: Duration = Duration::from_secs(8);

/// Verdict of the self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingVerdict {
    Ok,
    Partial,
    Leak,
    TunnelOff,
    Inconclusive,
}

/// The Smart-RU part of the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartRuCheck {
    pub enabled: bool,
    pub ru_host_ip: Option<IpAddr>,
    pub ru_goes_direct: Option<bool>,
}

/// Result shown on the diagnostics page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingResult {
    pub ran_at: UnixMs,
    pub tunnel_active: bool,
    pub vpn_ip: Option<IpAddr>,
    /// The real ISP address (also what the IP monitor needs as `real_ip`).
    pub direct_ip: Option<IpAddr>,
    pub split_works: bool,
    pub smart_ru: SmartRuCheck,
    pub verdict: RoutingVerdict,
    pub message: Msg,
}

/// The verdict, its message, `split_works` and `ru_goes_direct` (texts of the old app).
pub fn derive_routing_verdict(
    tunnel_active: bool,
    vpn: Option<IpAddr>,
    direct: Option<IpAddr>,
    smart_ru: bool,
    ru: Option<IpAddr>,
) -> (RoutingVerdict, Msg, bool, Option<bool>) {
    use RoutingVerdict::*;
    if !tunnel_active {
        return (TunnelOff, Msg::new("probes.routing.tunnelOff"), false, None);
    }
    let (Some(vpn), Some(direct)) = (vpn, direct) else {
        return (
            Inconclusive,
            Msg::new("probes.routing.inconclusive"),
            false,
            None,
        );
    };
    if vpn == direct {
        return (
            Leak,
            Msg::new("probes.routing.leak").arg("vpn", vpn),
            false,
            None,
        );
    }
    let msg = |key: &'static str| Msg::new(key).arg("vpn", vpn).arg("direct", direct);
    match (smart_ru, ru) {
        (true, None) => (Partial, msg("probes.routing.smartUnverified"), true, None),
        (true, Some(ru)) if ru == direct => (Ok, msg("probes.routing.smartOk"), true, Some(true)),
        (true, Some(ru)) => (
            Partial,
            msg("probes.routing.ruViaVpn").arg("ru", ru),
            true,
            Some(false),
        ),
        (false, _) => (Ok, msg("probes.routing.ok"), true, None),
    }
}

/// An echo body that is exactly an address: the whole trimmed body (quotes allowed, as in a
/// JSON string) or an `ip=` line (Cloudflare trace). Anything else is refused, so a captive
/// portal page with some dotted quad in it never passes as an egress IP.
pub fn parse_echo(body: &str) -> Option<IpAddr> {
    let whole = body.trim().trim_matches('"');
    whole.parse().ok().or_else(|| {
        body.lines().find_map(|l| {
            l.trim()
                .strip_prefix("ip=")
                .and_then(|ip| ip.trim().parse().ok())
        })
    })
}

/// The first dotted quad whose octets are all ≤ 255 (skips junk like `384.518.844.978`).
pub fn first_ipv4(text: &str) -> Option<Ipv4Addr> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !is_word(bytes[i - 1])) {
            let end = bytes[i..]
                .iter()
                .position(|&b| !(b.is_ascii_digit() || b == b'.'))
                .map_or(bytes.len(), |p| i + p);
            let token = text[i..end].trim_end_matches('.');
            let parts: Vec<&str> = token.split('.').collect();
            let boundary = end == bytes.len() || !is_word(bytes[end]);
            if boundary
                && parts.len() == 4
                && parts.iter().all(|p| (1..=3).contains(&p.len()))
                && let Ok(ip) = token.parse::<Ipv4Addr>()
            {
                return Some(ip);
            }
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }
    None
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Which way an echo request leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EchoPath {
    /// The normal OS route (= the TUN while it runs), optionally bound to the TUN address.
    Tunnel,
    /// The engine's direct inbound.
    Direct,
}

/// Fetches one echo URL over a path; `None` on any failure. The real one is [`HttpEcho`].
pub type EchoFn =
    Arc<dyn Fn(EchoPath, &'static str) -> BoxFuture<'static, Option<String>> + Send + Sync>;

/// What the self-test needs from the running session.
#[derive(Debug, Clone, Default)]
pub struct RoutingInputs {
    pub tunnel_active: bool,
    /// `mixed-direct-in` with its per-session credentials; `None` = no direct measurement.
    pub direct: Option<Loopback>,
    /// Source address for the TUN-path requests (the TUN interface address); `None` = OS route.
    pub tun_source: Option<IpAddr>,
    pub smart_ru: bool,
    /// Geo lookups off: the Russian echo is not asked.
    pub disable_geo_lookup: bool,
}

/// Echo requests over reqwest: no system proxy, no redirects, [`ECHO_TIMEOUT`] each.
pub struct HttpEcho {
    tunnel: Option<reqwest::Client>,
    direct: Option<reqwest::Client>,
}

impl HttpEcho {
    /// Clients for both paths (a path whose client cannot be built answers `None`).
    pub fn new(inputs: &RoutingInputs) -> Self {
        let tunnel = net::builder_for(&Route::Direct, ECHO_TIMEOUT)
            .ok()
            .map(|b| b.local_address(inputs.tun_source).pool_max_idle_per_host(0))
            .and_then(|b| b.build().ok());
        let direct = inputs.direct.as_ref().and_then(|d| direct_client(d).ok());
        Self { tunnel, direct }
    }

    /// The echo function over these clients.
    pub fn into_fn(self) -> EchoFn {
        let this = Arc::new(self);
        Arc::new(move |path, url| {
            let client = match path {
                EchoPath::Tunnel => this.tunnel.clone(),
                EchoPath::Direct => this.direct.clone(),
            };
            Box::pin(async move { fetch(client?, url).await })
        })
    }
}

fn direct_client(direct: &Loopback) -> AppResult<reqwest::Client> {
    let hp = HostPort::new("127.0.0.1", direct.port).map_err(AppError::from)?;
    let route = Route::proxy(
        vpnte_base::types::ProxyKind::Socks5,
        &hp,
        direct.creds.as_ref(),
    );
    net::client_for(&route, ECHO_TIMEOUT)
}

async fn fetch(client: reqwest::Client, url: &str) -> Option<String> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.text().await.ok()
}

async fn first_echo(
    echo: &EchoFn,
    path: EchoPath,
    urls: &[&'static str],
    parse: fn(&str) -> Option<IpAddr>,
) -> Option<IpAddr> {
    for url in urls {
        let body = tokio::time::timeout(ECHO_TIMEOUT, echo(path, url))
            .await
            .ok()
            .flatten();
        if let Some(ip) = body.as_deref().and_then(parse) {
            return Some(ip);
        }
    }
    None
}

fn parse_ru(body: &str) -> Option<IpAddr> {
    parse_echo(body).or_else(|| first_ipv4(body).map(IpAddr::V4))
}

/// The real ISP address through the engine's direct inbound (also used for the IP monitor's
/// `real_ip` after connect).
pub async fn direct_egress_ip(direct: &Loopback) -> Option<IpAddr> {
    let client = direct_client(direct).ok()?;
    for url in DIRECT_ECHOES {
        if let Some(ip) = fetch(client.clone(), url)
            .await
            .as_deref()
            .and_then(parse_echo)
        {
            return Some(ip);
        }
    }
    None
}

/// Runs the self-test over the real network.
pub async fn routing_test(
    inputs: RoutingInputs,
    cancel: CancellationToken,
) -> AppResult<RoutingResult> {
    let echo = HttpEcho::new(&inputs).into_fn();
    routing_test_with(&inputs, &echo, cancel).await
}

/// The self-test over a given echo function. The VPN and direct reads run in parallel; the RU
/// echo only with Smart RU on and geo lookups allowed. Cancellation wins at any point.
pub async fn routing_test_with(
    inputs: &RoutingInputs,
    echo: &EchoFn,
    cancel: CancellationToken,
) -> AppResult<RoutingResult> {
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    let ru_wanted = inputs.smart_ru && !inputs.disable_geo_lookup;
    let work = async {
        if !inputs.tunnel_active {
            return (None, None, None);
        }
        let vpn = first_echo(echo, EchoPath::Tunnel, &TUNNEL_ECHOES, parse_echo);
        let direct = async {
            match inputs.direct {
                Some(_) => first_echo(echo, EchoPath::Direct, &DIRECT_ECHOES, parse_echo).await,
                None => None,
            }
        };
        let (vpn, direct) = tokio::join!(vpn, direct);
        let ru = match ru_wanted {
            true => first_echo(echo, EchoPath::Tunnel, &RU_ECHOES, parse_ru).await,
            false => None,
        };
        (vpn, direct, ru)
    };
    let (vpn, direct, ru) = tokio::select! {
        _ = cancel.cancelled() => return Err(AppError::cancelled()),
        r = work => r,
    };
    let (verdict, message, split_works, ru_goes_direct) =
        derive_routing_verdict(inputs.tunnel_active, vpn, direct, inputs.smart_ru, ru);
    let tail = |ip: Option<IpAddr>| {
        ip.map(|ip| {
            ip.to_string()
                .rsplit(['.', ':'])
                .next()
                .unwrap_or_default()
                .to_owned()
        })
    };
    tracing::info!(
        verdict = ?verdict,
        split_works,
        smart_ru = inputs.smart_ru,
        vpn_ip_tail = tail(vpn).as_deref(),
        direct_ip_tail = tail(direct).as_deref(),
        ru_echo_skipped = inputs.smart_ru && !ru_wanted,
        "routing self-test completed"
    );
    Ok(RoutingResult {
        ran_at: now_ms(),
        tunnel_active: inputs.tunnel_active,
        vpn_ip: vpn,
        direct_ip: direct,
        split_works,
        smart_ru: SmartRuCheck {
            enabled: inputs.smart_ru,
            ru_host_ip: ru,
            ru_goes_direct,
        },
        verdict,
        message,
    })
}
