//! A fake [`AvailabilityApi`] with realistic data (documentation IP ranges, no real servers):
//! used by `demo_tools` and the page tests. The verdict depends on words in the link
//! (`youtube`, `.ru`, `chatgpt`, `down`, `login`, anything else works both ways);
//! `error.test` fails with a network error, a non-HTTP scheme is a validation error.
use std::cell::Cell;
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::AvailabilityApi;
use super::model::{
    AvailabilityState, DnsStage, GeoInfo, HttpStage, PathReport, PathSource, RoutingReport,
    RoutingVerdict, TcpStage, TlsStage, UrlCheck, UrlVerdict,
};

const MINUTE: UnixMs = 60_000;

/// The fake backend of the Availability page.
pub struct DemoAvailability {
    state: watch::Sender<AvailabilityState>,
    delay: Duration,
    routing_runs: Cell<u32>,
    next_id: Cell<u32>,
}

impl DemoAvailability {
    /// Tunnel up or down, with four saved checks.
    pub fn new(tunnel_running: bool) -> Self {
        let now = now_ms();
        Self::with_state(AvailabilityState {
            tunnel_running,
            history: vec![
                sample("https://www.youtube.com/", now - 4 * MINUTE, tunnel_running),
                sample("https://chatgpt.com/", now - 52 * MINUTE, tunnel_running),
                sample(
                    "https://www.gosuslugi.ru/",
                    now - 5 * 60 * MINUTE,
                    tunnel_running,
                ),
                sample(
                    "https://example.com/",
                    now - 49 * 60 * MINUTE,
                    tunnel_running,
                ),
            ],
            history_error: None,
        })
    }

    /// Exactly this state.
    pub fn with_state(state: AvailabilityState) -> Self {
        Self {
            state: watch::Sender::new(state),
            delay: Duration::from_millis(1400),
            routing_runs: Cell::new(0),
            next_id: Cell::new(1),
        }
    }

    /// How long each fake call takes (zero in tests).
    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Pushes a state change, as the app does when the tunnel or the history changes.
    pub fn update(&self, change: impl FnOnce(&mut AvailabilityState)) {
        self.state.send_modify(change);
    }

    async fn wait(&self, cancel: &CancellationToken) -> AppResult<()> {
        tokio::select! {
            () = cancel.cancelled() => Err(AppError::cancelled()),
            () = tokio::time::sleep(self.delay) => Ok(()),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl AvailabilityApi for DemoAvailability {
    fn state(&self) -> watch::Receiver<AvailabilityState> {
        self.state.subscribe()
    }

    async fn check_url(&self, input: String, cancel: CancellationToken) -> AppResult<UrlCheck> {
        let url = normalize(&input)
            .ok_or_else(|| AppError::validation(Msg::new("ui.tools.demo.badUrl")))?;
        self.wait(&cancel).await?;
        if url.contains("error.test") {
            return Err(AppError::new(ErrorKind::Network));
        }
        let tunnel = self.state.borrow().tunnel_running;
        let mut check = sample(&url, now_ms(), tunnel);
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        check.id = format!("demo-check-{id}");
        self.state.send_modify(|state| {
            state.history.insert(0, check.clone());
            state.history.truncate(50);
        });
        Ok(check)
    }

    async fn routing_test(&self, cancel: CancellationToken) -> AppResult<RoutingReport> {
        self.wait(&cancel).await?;
        if !self.state.borrow().tunnel_running {
            return Ok(routing(RoutingVerdict::TunnelOff, None, None, false, None));
        }
        let run = self.routing_runs.get();
        self.routing_runs.set(run + 1);
        let (vpn, direct, ru) = ("198.51.100.23", "203.0.113.47", "198.51.100.23");
        let ip = |s: &str| s.parse().ok();
        Ok(match run % 5 {
            0 => routing(RoutingVerdict::Ok, ip(vpn), ip(direct), true, ip(direct)),
            1 => routing(RoutingVerdict::Partial, ip(vpn), ip(direct), true, ip(ru)),
            2 => routing(RoutingVerdict::Leak, ip(direct), ip(direct), false, None),
            3 => routing(RoutingVerdict::Inconclusive, ip(vpn), None, false, None),
            _ => return Err(AppError::new(ErrorKind::Timeout)),
        })
    }

    async fn clear_history(&self) -> AppResult<()> {
        tokio::time::sleep(self.delay / 4).await;
        self.state.send_modify(|state| state.history.clear());
        Ok(())
    }
}

fn routing(
    verdict: RoutingVerdict,
    vpn_ip: Option<std::net::IpAddr>,
    direct_ip: Option<std::net::IpAddr>,
    smart_ru: bool,
    ru_ip: Option<std::net::IpAddr>,
) -> RoutingReport {
    let key = match verdict {
        RoutingVerdict::Ok if smart_ru => "ui.tools.demo.routing.okSmart",
        RoutingVerdict::Ok => "ui.tools.demo.routing.ok",
        RoutingVerdict::Partial => "ui.tools.demo.routing.partial",
        RoutingVerdict::Leak => "ui.tools.demo.routing.leak",
        RoutingVerdict::TunnelOff => "ui.tools.demo.routing.tunnelOff",
        RoutingVerdict::Inconclusive => "ui.tools.demo.routing.inconclusive",
    };
    let show =
        |ip: Option<std::net::IpAddr>| ip.map_or_else(|| "—".to_owned(), |ip| ip.to_string());
    RoutingReport {
        ran_at: now_ms(),
        verdict,
        message: Msg::new(key)
            .arg("vpn", show(vpn_ip))
            .arg("direct", show(direct_ip))
            .arg("ru", show(ru_ip)),
        vpn_ip,
        direct_ip,
        smart_ru,
        ru_ip,
    }
}

/// The demo's stand-in for the backend normaliser: `https://` by default, no query, no
/// fragment, lower-case host; anything but HTTP(S) is refused.
fn normalize(input: &str) -> Option<String> {
    let input = input.trim();
    let (scheme, rest) = match input.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("https".to_owned(), input),
    };
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    Some(format!("{scheme}://{}/{path}", host.to_ascii_lowercase()))
}

/// A complete, successful native measurement.
fn full_path(ip: &str, server: &str, ms: u32) -> PathReport {
    PathReport {
        source: PathSource::Native,
        measured: true,
        available: true,
        geo_blocked: false,
        total_ms: Some(ms),
        message: None,
        dns: Some(DnsStage {
            resolved: true,
            ips: vec![ip.to_owned(), "93.184.215.15".to_owned()],
            poisoned: false,
            ms: Some(ms / 8),
        }),
        tcp: Some(TcpStage {
            connected: true,
            ms: Some(ms / 5),
        }),
        tls: Some(TlsStage {
            ok: true,
            protocol: Some("TLSv1.3".to_owned()),
            cipher: Some("TLS_AES_128_GCM_SHA256".to_owned()),
            ms: Some(ms / 4),
        }),
        http: Some(HttpStage {
            status: Some(200),
            server: Some(server.to_owned()),
            ms: Some(ms / 3),
        }),
        geo: Some(GeoInfo {
            country: "Netherlands".to_owned(),
            org: "Example Hosting B.V.".to_owned(),
        }),
    }
}

/// One HTTP request through the engine's direct exit.
fn direct_http(status: Option<u16>, ms: Option<u32>, message: Option<&'static str>) -> PathReport {
    PathReport {
        source: PathSource::DirectInbound,
        measured: true,
        available: status.is_some_and(|s| s < 500),
        total_ms: ms,
        message: message.map(Msg::new),
        http: Some(HttpStage {
            status,
            server: status.map(|_| "cloudflare".to_owned()),
            ms,
        }),
        ..PathReport::default()
    }
}

/// `ok` with the TLS handshake cut (DPI by SNI): DNS and TCP pass, nothing after.
fn sni_blocked(ok: &PathReport) -> PathReport {
    PathReport {
        available: false,
        total_ms: None,
        tls: Some(TlsStage {
            ok: false,
            protocol: None,
            cipher: None,
            ms: None,
        }),
        http: None,
        message: Some(Msg::new("ui.tools.demo.msg.tls")),
        ..ok.clone()
    }
}

/// A check of `url` as the backend would report it (keyword driven, see the module docs).
fn sample(url: &str, tested_at: UnixMs, tunnel: bool) -> UrlCheck {
    use UrlVerdict as V;
    let has = |words: &[&str]| words.iter().any(|w| url.contains(w));
    let ok = full_path("93.184.215.14", "ECAcc (nyd/D13F)", 184);
    let (protected, mut direct, verdict, reco) = if has(&["youtube", "instagram", "x.com"]) {
        // Through the engine's direct exit only the HTTP stage is seen (the TLS detail of the
        // block shows on the native path, i.e. with the tunnel off).
        let blocked = direct_http(None, None, Some("ui.tools.demo.msg.reset"));
        (
            Some(ok.clone()),
            Some(blocked),
            V::WorksOnlyWithVpn,
            "ui.tools.demo.reco.onlyVpn",
        )
    } else if has(&[".ru/", "yandex"]) {
        let mut failed = ok.clone();
        failed.available = false;
        failed.total_ms = None;
        (failed.tls, failed.http, failed.geo) = (None, None, None);
        failed.tcp = Some(TcpStage {
            connected: false,
            ms: None,
        });
        failed.message = Some(Msg::new("ui.tools.demo.msg.tcp"));
        let direct = direct_http(Some(200), Some(96), None);
        (
            Some(failed),
            Some(direct),
            V::WorksOnlyWithoutVpn,
            "ui.tools.demo.reco.onlyDirect",
        )
    } else if has(&["chatgpt", "gemini", "openai"]) {
        let mut geo = direct_http(Some(403), Some(210), Some("ui.tools.demo.msg.geo"));
        (geo.available, geo.geo_blocked) = (false, true);
        (
            Some(ok.clone()),
            Some(geo),
            V::WorksOnlyWithVpn,
            "ui.tools.demo.reco.geo",
        )
    } else if has(&["down", "offline"]) {
        let mut dead = ok.clone();
        dead.available = false;
        dead.total_ms = None;
        dead.dns = Some(DnsStage {
            resolved: false,
            ips: Vec::new(),
            poisoned: false,
            ms: Some(1020),
        });
        (dead.tcp, dead.tls, dead.http, dead.geo) = (None, None, None, None);
        dead.message = Some(Msg::new("ui.tools.demo.msg.dns"));
        let direct = direct_http(None, None, Some("ui.tools.demo.msg.timeout"));
        (
            Some(dead),
            Some(direct),
            V::BlockedEverywhere,
            "ui.tools.demo.reco.blocked",
        )
    } else if has(&["login", "auth"]) {
        let mut auth = ok.clone();
        auth.http = Some(HttpStage {
            status: Some(403),
            server: Some("nginx".to_owned()),
            ms: Some(61),
        });
        let direct = direct_http(Some(403), Some(88), None);
        (
            Some(auth),
            Some(direct),
            V::AuthRequired,
            "ui.tools.demo.reco.auth",
        )
    } else {
        (
            Some(ok.clone()),
            Some(direct_http(Some(200), Some(142), None)),
            V::WorksBoth,
            "ui.tools.demo.reco.both",
        )
    };
    let (protected, verdict, reco) = if tunnel {
        (protected, verdict, reco)
    } else {
        // Tunnel off: the native probe IS the direct path, and the VPN path is unmeasured.
        let native = if matches!(verdict, V::WorksOnlyWithVpn | V::BlockedEverywhere) {
            sni_blocked(&ok)
        } else {
            ok.clone()
        };
        let (v, r) = if native.available {
            (V::WorksBoth, "ui.tools.demo.reco.directOnly")
        } else {
            (V::Unknown, "ui.tools.demo.reco.directFailed")
        };
        direct = Some(native);
        (None, v, r)
    };
    UrlCheck {
        id: format!("demo-{tested_at}"),
        url: url.to_owned(),
        tested_at,
        tunnel_active: tunnel,
        protected,
        direct,
        verdict,
        recommendation: Msg::new(reco),
    }
}
