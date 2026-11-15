//! Pure text and tone rules of the Availability page. The page passes the [`Lang`] it read
//! from `LANG`; the words come from the app catalog.
use vpnte_base::i18n::{self, Lang};
use vpnte_base::types::UnixMs;

use super::model::{PathReport, RoutingVerdict, UrlVerdict};
use crate::widgets::Tone;

/// History rows shown (the backend keeps more).
pub const HISTORY_ROWS: usize = 20;

/// The text of `key` in `lang`.
pub(crate) fn text(lang: Lang, key: &str) -> String {
    i18n::lookup(lang, key, &[], None)
}

/// The text of `key` in `lang` with `{{name}}` placeholders filled from `vars`.
pub(crate) fn text_with(lang: Lang, key: &str, vars: &[(&str, String)]) -> String {
    i18n::lookup(lang, key, vars, None)
}

/// Label key and badge tone of a URL verdict (old `verdictTone`; `AuthRequired` is new).
pub fn verdict_look(verdict: UrlVerdict) -> (&'static str, Tone) {
    match verdict {
        UrlVerdict::WorksBoth => ("ui.availability.verdict.worksBoth", Tone::Ok),
        UrlVerdict::WorksOnlyWithVpn => ("ui.availability.verdict.worksOnlyWithVpn", Tone::Neutral),
        UrlVerdict::WorksOnlyWithoutVpn => {
            ("ui.availability.verdict.worksOnlyWithoutVpn", Tone::Warn)
        }
        UrlVerdict::BlockedEverywhere => ("ui.availability.verdict.blockedEverywhere", Tone::Fail),
        UrlVerdict::AuthRequired => ("ui.availability.verdict.authRequired", Tone::Warn),
        UrlVerdict::Unknown => ("ui.availability.verdict.unknown", Tone::Unknown),
    }
}

/// Label key and tone of a routing verdict (old border colours: ok / partial / leak / other).
pub fn routing_look(verdict: RoutingVerdict) -> (&'static str, Tone) {
    match verdict {
        RoutingVerdict::Ok => ("ui.availability.routing.verdict.ok", Tone::Ok),
        RoutingVerdict::Partial => ("ui.availability.routing.verdict.partial", Tone::Warn),
        RoutingVerdict::Leak => ("ui.availability.routing.verdict.leak", Tone::Fail),
        RoutingVerdict::TunnelOff => ("ui.availability.routing.verdict.tunnelOff", Tone::Unknown),
        RoutingVerdict::Inconclusive => (
            "ui.availability.routing.verdict.inconclusive",
            Tone::Unknown,
        ),
    }
}

/// Status word of a path: opens / geo block / not measured / does not open.
pub fn path_status(path: &PathReport) -> (&'static str, Tone) {
    if path.available {
        ("ui.availability.path.opens", Tone::Ok)
    } else if path.geo_blocked {
        ("ui.availability.path.geoBlock", Tone::Warn)
    } else if !path.measured {
        ("ui.availability.path.notMeasured", Tone::Unknown)
    } else {
        ("ui.availability.path.fails", Tone::Fail)
    }
}

/// «N с назад» … «N д назад» (old `formatAge`: whole units, floor; a future time reads as 0 s).
pub fn format_age(lang: Lang, now: UnixMs, then: UnixMs) -> String {
    let sec = (now - then).max(0) / 1000;
    let (key, n) = if sec < 60 {
        ("ui.availability.ago.seconds", sec)
    } else if sec < 3600 {
        ("ui.availability.ago.minutes", sec / 60)
    } else if sec < 86_400 {
        ("ui.availability.ago.hours", sec / 3600)
    } else {
        ("ui.availability.ago.days", sec / 86_400)
    };
    text_with(lang, key, &[("n", n.to_string())])
}

/// How a stage value reads: plain, worth a look, or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Plain,
    Warn,
    Fail,
}

impl Mark {
    pub(crate) fn class(self) -> &'static str {
        match self {
            Mark::Plain => "av-stage-value",
            Mark::Warn => "av-stage-value is-warn",
            Mark::Fail => "av-stage-value is-fail",
        }
    }
}

/// One detail line of a path card: «DNS  93.184.215.14 (+1)  12 мс».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRow {
    pub label: String,
    pub value: String,
    pub mark: Mark,
    pub ms: Option<u32>,
}

/// The detail lines of a path in the old order (DNS, TCP, TLS, HTTP, «Где»); a stage that did
/// not run has no line.
pub fn stage_rows(lang: Lang, path: &PathReport) -> Vec<StageRow> {
    let t = |key: &str| text(lang, key);
    let mut rows = Vec::new();
    if let Some(dns) = &path.dns {
        let first = dns.ips.first().cloned().unwrap_or_default();
        let (value, mark) = match (dns.resolved, dns.poisoned) {
            (false, _) => (t("ui.availability.path.dnsFailed"), Mark::Fail),
            (true, true) => (
                text_with(lang, "ui.availability.path.dnsSuspicious", &[("ip", first)]),
                Mark::Warn,
            ),
            (true, false) if dns.ips.len() > 1 => {
                (format!("{first} (+{})", dns.ips.len() - 1), Mark::Plain)
            }
            (true, false) => (first, Mark::Plain),
        };
        rows.push(StageRow {
            label: "DNS".into(),
            value,
            mark,
            ms: dns.ms,
        });
    }
    if let Some(tcp) = &path.tcp {
        let (value, mark) = if tcp.connected {
            (t("ui.availability.path.tcpOk"), Mark::Plain)
        } else {
            (t("ui.availability.path.tcpFailed"), Mark::Fail)
        };
        rows.push(StageRow {
            label: "TCP".into(),
            value,
            mark,
            ms: tcp.ms,
        });
    }
    if let Some(tls) = &path.tls {
        let (value, mark) = if tls.ok {
            let protocol = tls.protocol.clone().filter(|p| !p.is_empty());
            let mut value = protocol.unwrap_or_else(|| "OK".into());
            if let Some(cipher) = tls.cipher.as_deref().filter(|c| !c.is_empty()) {
                value = format!("{value} · {cipher}");
            }
            (value, Mark::Plain)
        } else {
            (t("ui.availability.path.tlsFailed"), Mark::Fail)
        };
        rows.push(StageRow {
            label: "TLS".into(),
            value,
            mark,
            ms: tls.ms,
        });
    }
    if let Some(http) = &path.http {
        let (value, mark) = match http.status {
            Some(status) => {
                let server = http.server.as_deref().filter(|s| !s.is_empty());
                let value = server.map_or(status.to_string(), |s| format!("{status} · {s}"));
                (
                    value,
                    if status < 400 {
                        Mark::Plain
                    } else {
                        Mark::Warn
                    },
                )
            }
            None => (t("ui.availability.path.httpNone"), Mark::Fail),
        };
        rows.push(StageRow {
            label: "HTTP".into(),
            value,
            mark,
            ms: http.ms,
        });
    }
    if let Some(geo) = &path.geo {
        rows.push(StageRow {
            label: t("ui.availability.path.where"),
            value: format!("{} · {}", geo.country, geo.org),
            mark: Mark::Plain,
            ms: None,
        });
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::availability::model::{DnsStage, GeoInfo, HttpStage, TcpStage, TlsStage};

    fn ru(key: &str) -> String {
        crate::test_locales::init_locales();
        text(Lang::Ru, key)
    }

    /// ui-pages §7.13 `formatAge`: 59 s, 61 s, 2 h, 49 h; a future time reads as 0 s.
    #[test]
    fn ages_use_whole_units() {
        crate::test_locales::init_locales();
        let now = 1_000_000_000_000;
        let age = |ms: i64| format_age(Lang::Ru, now, now - ms);
        assert_eq!(age(59_000), "59 с назад");
        assert_eq!(age(61_000), "1 мин назад");
        assert_eq!(age(2 * 3_600_000), "2 ч назад");
        assert_eq!(age(49 * 3_600_000), "2 д назад");
        assert_eq!(age(-5_000), "0 с назад");
        assert_eq!(format_age(Lang::En, now, now - 61_000), "1 min ago");
    }

    /// AT-00-008 / ui-pages §7.5 verdict labels (`Availability.tsx:54-67`); "unknown" never looks
    /// like a success.
    #[test]
    fn verdict_labels_are_the_old_ones() {
        let label = |v| ru(verdict_look(v).0);
        assert_eq!(label(UrlVerdict::WorksBoth), "Доступен и так и так");
        assert_eq!(label(UrlVerdict::WorksOnlyWithVpn), "Нужен VPN");
        assert_eq!(label(UrlVerdict::WorksOnlyWithoutVpn), "Только без VPN");
        assert_eq!(label(UrlVerdict::BlockedEverywhere), "Не отвечает");
        assert_eq!(label(UrlVerdict::Unknown), "Неопределённо");
        assert_eq!(label(UrlVerdict::AuthRequired), "Требует авторизацию");
        assert_eq!(verdict_look(UrlVerdict::Unknown).1, Tone::Unknown);
        assert_eq!(verdict_look(UrlVerdict::BlockedEverywhere).1, Tone::Fail);
        assert_eq!(routing_look(RoutingVerdict::Leak).1, Tone::Fail);
        assert_eq!(routing_look(RoutingVerdict::Inconclusive).1, Tone::Unknown);
    }

    /// B-UA-3: an unmeasured path is "not measured", never "does not open".
    #[test]
    fn path_status_never_blames_an_unmeasured_path() {
        let mut path = PathReport {
            measured: true,
            available: true,
            ..PathReport::default()
        };
        assert_eq!(path_status(&path), ("ui.availability.path.opens", Tone::Ok));
        path.available = false;
        assert_eq!(path_status(&path).1, Tone::Fail);
        path.geo_blocked = true;
        assert_eq!(
            path_status(&path),
            ("ui.availability.path.geoBlock", Tone::Warn)
        );
        path.geo_blocked = false;
        path.measured = false;
        assert_eq!(
            path_status(&path),
            ("ui.availability.path.notMeasured", Tone::Unknown)
        );
    }

    fn row(label: &str, value: &str, mark: Mark, ms: Option<u32>) -> StageRow {
        StageRow {
            label: label.into(),
            value: value.into(),
            mark,
            ms,
        }
    }

    /// The stage lines of the old path card (`Availability.tsx:121-176`), in order.
    #[test]
    fn stage_rows_follow_the_old_card() {
        crate::test_locales::init_locales();
        let ru = Lang::Ru;
        let path = PathReport {
            measured: true,
            dns: Some(DnsStage {
                resolved: true,
                ips: vec![
                    "192.0.2.10".into(),
                    "192.0.2.11".into(),
                    "192.0.2.12".into(),
                ],
                poisoned: false,
                ms: Some(12),
            }),
            tcp: Some(TcpStage {
                connected: true,
                ms: Some(30),
            }),
            tls: Some(TlsStage {
                ok: true,
                protocol: None,
                cipher: Some("AES".into()),
                ms: None,
            }),
            http: Some(HttpStage {
                status: Some(403),
                server: Some("nginx".into()),
                ms: Some(70),
            }),
            geo: Some(GeoInfo {
                country: "Netherlands".into(),
                org: "Example B.V.".into(),
            }),
            ..PathReport::default()
        };
        assert_eq!(
            stage_rows(ru, &path),
            vec![
                row("DNS", "192.0.2.10 (+2)", Mark::Plain, Some(12)),
                row("TCP", "соединение открыто", Mark::Plain, Some(30)),
                row("TLS", "OK · AES", Mark::Plain, None),
                row("HTTP", "403 · nginx", Mark::Warn, Some(70)),
                row("Где", "Netherlands · Example B.V.", Mark::Plain, None),
            ]
        );
        let failed = PathReport {
            dns: Some(DnsStage {
                resolved: true,
                ips: vec!["0.0.0.0".into()],
                poisoned: true,
                ms: None,
            }),
            tcp: Some(TcpStage {
                connected: false,
                ms: None,
            }),
            tls: Some(TlsStage::default()),
            http: Some(HttpStage::default()),
            ..PathReport::default()
        };
        let rows = stage_rows(ru, &failed);
        assert_eq!(
            rows[0],
            row("DNS", "подозрительно: 0.0.0.0", Mark::Warn, None)
        );
        assert_eq!(rows[1], row("TCP", "не открылось", Mark::Fail, None));
        assert_eq!(rows[2], row("TLS", "handshake не прошёл", Mark::Fail, None));
        assert_eq!(rows[3], row("HTTP", "нет ответа", Mark::Fail, None));
        let unresolved = PathReport {
            dns: Some(DnsStage::default()),
            ..PathReport::default()
        };
        assert_eq!(
            stage_rows(ru, &unresolved),
            vec![row("DNS", "не разрешился", Mark::Fail, None)]
        );
        assert!(stage_rows(ru, &PathReport::default()).is_empty());
    }
}
