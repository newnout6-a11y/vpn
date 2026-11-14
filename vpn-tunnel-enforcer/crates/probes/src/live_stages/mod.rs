//! Direct measurement stages of the live server check: DNS (system + DoH comparison), TCP
//! latency and port reachability, TLS certificate inspection, HTTP banner, ICMP traceroute and
//! path MTU, route / interface facts, ASN lookup and the target safety filter.
//!
//! Every stage is an independent async function returning a typed result. The result types are
//! the row format of `live-server-checks.json`: field names and enum strings follow the Electron
//! app so imported history deserialises (unknown legacy fields are ignored, never written).
//! The orchestrator (`live`) decides which stages run (mode, UDP transport, REALITY, tunnel state).
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;

pub mod dns;
mod dns_win;
pub mod geo;
pub mod http;
pub mod icmp;
mod net;
pub mod path;
pub mod target;
pub mod tcp;
pub mod tls;
mod x509;

pub use dns::{DnsBackend, DnsDiagnostics, probe_dns};
pub use dns_win::SystemDns;
pub(crate) use dns_win::wire_addrs;
pub use geo::{AsnInfo, GeoCache, Infrastructure, infrastructure, lookup_asn};
pub use http::{HttpInfo, probe_http};
pub use icmp::{Pmtu, RouteTrace, probe_pmtu, trace_route};
pub(crate) use net::connect;
pub use path::{PathInfo, path_info, physical_uplink, route_uplink};
pub use target::{TargetClass, classify_target, normalize_host_port};
pub use tcp::{LatencyStats, PortItem, Reachability, sample_latency, scan_ports};
pub use tls::{TlsInfo, inspect_tls};

/// Ports scanned in extended mode (CDN-friendly ports a censor may single out).
pub const RESTRICTED_PORTS: [u16; 8] = [80, 443, 8080, 8443, 2053, 2083, 2087, 2096];

/// Service label of a well-known port (`None` for a custom port).
pub fn service_hint(port: u16) -> Option<&'static str> {
    Some(match port {
        80 => "HTTP",
        443 => "HTTPS",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        2053 | 2083 | 2087 | 2096 => "Cloudflare-TLS",
        _ => return None,
    })
}

/// Timeouts of the stages (live-probe spec §2.3).
pub mod timeouts {
    use super::Duration;
    /// One system DNS query (A, AAAA, PTR of an IP literal).
    pub const DNS_QUERY: Duration = Duration::from_millis(2500);
    /// PTR of each resolved address.
    pub const DNS_PTR: Duration = Duration::from_millis(1200);
    /// One DoH request.
    pub const DOH: Duration = Duration::from_millis(3000);
    /// One TCP latency sample.
    pub const TCP_CONNECT: Duration = Duration::from_millis(1500);
    /// Whole latency stage, basic mode.
    pub const LATENCY_BASIC: Duration = Duration::from_millis(6000);
    /// Whole latency stage, extended mode.
    pub const LATENCY_EXTENDED: Duration = Duration::from_millis(9000);
    /// Pause between latency samples.
    pub const SAMPLE_GAP: Duration = Duration::from_millis(60);
    /// One port of the port scan.
    pub const PORT: Duration = Duration::from_millis(1200);
    /// Direct TLS handshake.
    pub const TLS: Duration = Duration::from_millis(3500);
    /// Whole HTTP chain (redirects included).
    pub const HTTP: Duration = Duration::from_millis(3500);
    /// One traceroute probe (all TTLs run concurrently).
    pub const TRACE_HOP: Duration = Duration::from_millis(1000);
    /// PMTU control ping.
    pub const PMTU_CONTROL: Duration = Duration::from_millis(700);
    /// One PMTU ladder rung.
    pub const PMTU_RUNG: Duration = Duration::from_millis(600);
    /// One geo provider request.
    pub const GEO: Duration = Duration::from_millis(4000);
}

/// Text stored in a history row: a message for new rows, the literal (mostly Russian) text the
/// Electron app wrote into imported rows. The UI renders `Msg` and shows `Legacy` verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Text {
    Msg(Msg),
    Legacy(String),
}

impl From<Msg> for Text {
    fn from(msg: Msg) -> Self {
        Text::Msg(msg)
    }
}

/// Status of a direct stage. Legacy `unavailable` (tracert missing / timed out) reads as
/// `NotChecked`: it never meant "the server failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimedStatus {
    Ok,
    Error,
    Skipped,
    #[default]
    #[serde(alias = "unavailable")]
    NotChecked,
}

/// Why a stage was not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotCheckedReason {
    /// The protocol runs over UDP: TCP / TLS / HTTP probes say nothing about it.
    UdpTransport,
    /// REALITY front: the certificate is the camouflage site's and a direct ClientHello risks a block.
    Reality,
    /// Only extended mode runs this stage.
    BasicMode,
    /// The tunnel is connecting or switching: the path is not stable.
    TunnelTransition,
    /// The user turned geo lookups off.
    GeoDisabled,
    /// The server's TLS handshake budget had no slot before the deadline (RU freeze discipline).
    HandshakeBudget,
}

impl NotCheckedReason {
    /// The sentence the UI shows for a stage that was not run.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            NotCheckedReason::UdpTransport => "probes.liveStages.notChecked.udpTransport",
            NotCheckedReason::Reality => "probes.liveStages.notChecked.reality",
            NotCheckedReason::BasicMode => "probes.liveStages.notChecked.basicMode",
            NotCheckedReason::TunnelTransition => "probes.liveStages.notChecked.tunnelTransition",
            NotCheckedReason::GeoDisabled => "probes.liveStages.notChecked.geoDisabled",
            NotCheckedReason::HandshakeBudget => "probes.liveStages.notChecked.handshakeBudget",
        })
    }
}

/// Which way a stage's packets went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeRoute {
    /// Wherever the OS routes it (through our TUN while it is up).
    Os,
    /// Bound to the physical uplink, outside our TUN.
    Physical,
}

/// Common head of a stage result (`status`, `durationMs`, `error` of the old rows), flattened
/// into each stage struct.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Timed {
    pub status: TimedStatus,
    #[serde(default)]
    pub duration_ms: u64,
    /// Technical cause (English, never localised): `ECONNREFUSED`, `TLS handshake timeout`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Set together with `NotChecked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NotCheckedReason>,
    /// Absent in imported rows and when nothing was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<ProbeRoute>,
}

impl Timed {
    /// A stage the orchestrator decided not to run.
    pub fn not_checked(reason: NotCheckedReason) -> Self {
        Timed {
            reason: Some(reason),
            ..Timed::default()
        }
    }

    /// A stage cancelled before it sent anything (old wording kept: `Cancelled`).
    pub fn cancelled() -> Self {
        Timed {
            status: TimedStatus::Skipped,
            error: Some(CANCELLED.into()),
            ..Timed::default()
        }
    }

    fn done(status: TimedStatus, ms: u64, error: Option<String>, route: ProbeRoute) -> Self {
        Timed {
            status,
            duration_ms: ms,
            error,
            reason: None,
            route: Some(route),
        }
    }
}

/// Error text of a cancelled stage (the old rows use exactly this word).
pub const CANCELLED: &str = "Cancelled";

/// Milliseconds since `start`, saturating.
fn elapsed_ms(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// How sockets and pings to the probed server leave this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePath {
    /// OS routing: our tunnel is down.
    Os,
    /// Our tunnel is up: bind to the physical uplink so the server is measured outside the TUN
    /// (B-02; the kill switch permits our own executable).
    Physical {
        if_index: u32,
        luid: u64,
        src_v4: Option<std::net::Ipv4Addr>,
        src_v6: Option<std::net::Ipv6Addr>,
    },
}

impl ProbePath {
    /// The route recorded in the stage results.
    pub fn route(&self) -> ProbeRoute {
        match self {
            ProbePath::Os => ProbeRoute::Os,
            ProbePath::Physical { .. } => ProbeRoute::Physical,
        }
    }

    /// Physical source address for pings to `dst` (same family), when bound.
    pub fn source_for(&self, dst: std::net::IpAddr) -> Option<std::net::IpAddr> {
        match (self, dst) {
            (ProbePath::Physical { src_v4, .. }, std::net::IpAddr::V4(_)) => {
                src_v4.map(std::net::IpAddr::V4)
            }
            (ProbePath::Physical { src_v6, .. }, std::net::IpAddr::V6(_)) => {
                src_v6.map(std::net::IpAddr::V6)
            }
            (ProbePath::Os, _) => None,
        }
    }

    /// Interface index to bind sockets to, when bound.
    pub fn if_index(&self) -> Option<u32> {
        match self {
            ProbePath::Os => None,
            ProbePath::Physical { if_index, .. } => Some(*if_index),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::icmp::{PmtuObservation, RungOutcome, classify_pmtu};
    use super::*;
    use crate::test_support::{flatten, placeholders};

    const RU: &str = include_str!("../../locales/probes-live-stages.ru.json");
    const EN: &str = include_str!("../../locales/probes-live-stages.en.json");

    /// Locale fragments: valid JSON, one `probes` root, equal keys and placeholders in ru / en.
    #[test]
    fn locale_fragments_match() {
        let (ru, en) = (flatten(RU), flatten(EN));
        assert_eq!(ru.keys().collect::<Vec<_>>(), en.keys().collect::<Vec<_>>());
        for (key, text) in &ru {
            assert!(key.starts_with("probes.liveStages."), "{key}");
            assert_eq!(placeholders(text), placeholders(&en[key]), "{key}");
        }
    }

    /// Every message the stages emit has a text with all of its arguments, in both languages.
    #[test]
    fn emitted_keys_exist() {
        use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NOT_FOUND};
        let mut msgs: Vec<Msg> = [
            NotCheckedReason::UdpTransport,
            NotCheckedReason::Reality,
            NotCheckedReason::BasicMode,
            NotCheckedReason::TunnelTransition,
            NotCheckedReason::GeoDisabled,
            NotCheckedReason::HandshakeBudget,
        ]
        .map(NotCheckedReason::msg)
        .to_vec();
        msgs.push(target::require_host("").unwrap_err().user_msg());
        msgs.push(target::refused_error([127, 0, 0, 1].into()).user_msg());
        for id in ["system", "google-doh", "cloudflare-doh"] {
            let Text::Msg(m) = dns::resolver_label(id) else {
                panic!("{id}")
            };
            msgs.push(m);
        }
        let ips = ["198.51.100.1".to_owned()];
        msgs.push(dns::system_vs_doh(&ips, &ips));
        msgs.push(dns::google_vs_cloudflare(&ips, &ips));
        for code in [ERROR_NOT_FOUND, ERROR_ACCESS_DENIED] {
            msgs.push(Msg::new(path::route_error_key(&code.to_hresult().into())));
        }
        for error in ["HTTP 429", "timeout", "Cancelled", "Reserved IP Address"] {
            msgs.push(geo::geo_error_msg(error));
        }
        let ladder = |rungs: &[(u16, RungOutcome)]| PmtuObservation {
            control_ok: true,
            rungs: rungs.to_vec(),
        };
        use RungOutcome::{Accepted as A, TimedOut as T, TooBig as B};
        let blocked = PmtuObservation {
            control_ok: false,
            rungs: Vec::new(),
        };
        let cases = [
            classify_pmtu(false, Some(&blocked), None),
            classify_pmtu(false, Some(&ladder(&[(1472, A)])), None),
            classify_pmtu(false, Some(&ladder(&[(1472, B), (1464, A)])), None),
            classify_pmtu(false, Some(&ladder(&[(1472, B), (1400, A)])), None),
            classify_pmtu(false, Some(&ladder(&[(1472, T), (1400, A)])), None),
            classify_pmtu(false, None, Some(1500)),
            classify_pmtu(false, None, None),
        ];
        msgs.extend(cases.into_iter().map(|v| v.detail));
        let (ru, en) = (flatten(RU), flatten(EN));
        for msg in msgs {
            for lang in [&ru, &en] {
                let text = lang
                    .get(msg.key.as_ref())
                    .unwrap_or_else(|| panic!("missing {}", msg.key));
                let args: BTreeSet<&str> = msg.args.iter().map(|(k, _)| k.as_ref()).collect();
                assert_eq!(placeholders(text), args, "{}", msg.key);
            }
        }
    }

    /// Stored text: new rows carry a message object, imported rows their literal string.
    #[test]
    fn text_round_trip() {
        let msg: Text = Msg::new("probes.liveStages.pmtu.atLeast")
            .arg("top", 1472)
            .into();
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<Text>(&json).unwrap(), msg);
        let legacy: Text = serde_json::from_str("\"PMTU не удалось определить\"").unwrap();
        assert_eq!(legacy, Text::Legacy("PMTU не удалось определить".into()));
        let old: Timed = serde_json::from_str(
            r#"{"status":"unavailable","durationMs":3500,"error":"Traceroute timed out"}"#,
        )
        .unwrap();
        assert_eq!(old.status, TimedStatus::NotChecked);
    }
}
