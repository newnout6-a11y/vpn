//! History of availability checks: `history/url-checks.json`, newest first, at most 50.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vpnte_core::store::Document;

use super::report::{
    DnsStage, ErrorCode, GeoInfo, HttpStage, PathReport, PathSource, TcpStage, TlsStage,
};
use super::{AvailabilityResult, AvailabilityVerdict, ProbeTarget, Recommendation};

/// Rows kept.
pub const MAX_HISTORY: usize = 50;

/// The persisted history document.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct UrlChecks {
    #[serde(default)]
    pub history: Vec<AvailabilityResult>,
}

impl Document for UrlChecks {
    const FILE: &'static str = "history/url-checks.json";
    const VERSION: u32 = 1;
}

impl UrlChecks {
    /// Puts a result at the front and drops the oldest beyond [`MAX_HISTORY`].
    pub fn push(&mut self, result: AvailabilityResult) {
        self.history.insert(0, result);
        self.history.truncate(MAX_HISTORY);
    }

    /// Empties the history (the page's "clear" action).
    pub fn clear(&mut self) {
        self.history.clear();
    }

    /// Imports the old `url-availability` store (`{history: [...]}`, already opened). Rows
    /// without a usable URL or time are skipped; URLs are re-normalised (no userinfo / query),
    /// old free-text messages are reduced to the error codes they name, an `api` failure (no
    /// Clash API) becomes "not measured" and the advice is re-derived from the verdict.
    pub fn from_legacy(legacy: &Value) -> UrlChecks {
        let rows = legacy.get("history").and_then(Value::as_array);
        let history = rows
            .into_iter()
            .flatten()
            .filter_map(legacy_row)
            .take(MAX_HISTORY)
            .collect();
        UrlChecks { history }
    }
}

fn legacy_row(row: &Value) -> Option<AvailabilityResult> {
    let url = ProbeTarget::parse(row.get("url")?.as_str()?)
        .ok()?
        .history_url();
    let tested_at = row.get("testedAt")?.as_i64()?;
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned);
    let verdict = row
        .get("verdict")
        .and_then(|v| serde_json::from_value::<AvailabilityVerdict>(v.clone()).ok())
        .unwrap_or_default();
    Some(AvailabilityResult {
        id,
        url,
        tested_at,
        tunnel_active: flag(row, "tunnelActive"),
        protected: row.get("tunnel").and_then(legacy_path),
        direct: row.get("direct").and_then(legacy_path),
        verdict,
        recommendation: Recommendation::for_verdict(verdict),
    })
}

fn flag(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn millis(v: &Value, key: &str) -> Option<u32> {
    v.get(key)?
        .as_f64()
        .filter(|n| *n >= 0.0)
        .map(|n| n.min(f64::from(u32::MAX)) as u32)
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)?
        .as_str()
        .filter(|s| !s.is_empty() && *s != "неизвестно")
        .map(str::to_owned)
}

fn legacy_path(v: &Value) -> Option<PathReport> {
    v.as_object()?;
    let source = match v.get("source").and_then(Value::as_str) {
        Some("clash-direct-out") => PathSource::DirectInbound,
        _ => PathSource::Native,
    };
    let stage = v.get("errorStage").and_then(Value::as_str);
    let error = v
        .get("errorMessage")
        .and_then(Value::as_str)
        .and_then(legacy_code);
    if stage == Some("api") {
        return Some(PathReport::unmeasured(
            source,
            error.unwrap_or(ErrorCode::ProxyFailed),
        ));
    }
    let object = |key: &str| v.get(key).filter(|o| o.is_object());
    Some(PathReport {
        available: flag(v, "available"),
        total_ms: millis(v, "totalMs"),
        error_stage: stage.and_then(|s| serde_json::from_value(Value::from(s)).ok()),
        error,
        dns: object("dns").map(|d| DnsStage {
            resolved: flag(d, "resolved"),
            ips: d
                .get("ips")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|ip| ip.as_str()?.parse::<IpAddr>().ok())
                .collect(),
            ms: millis(d, "ms"),
            poisoned: flag(d, "poisoned"),
        }),
        tcp: object("tcp").map(|t| TcpStage {
            connected: flag(t, "connected"),
            ms: millis(t, "ms"),
        }),
        tls: object("tls").map(|t| TlsStage {
            handshake_ok: flag(t, "handshakeOk"),
            ms: millis(t, "ms"),
            protocol: text(t, "protocol"),
            cipher: text(t, "cipher"),
        }),
        http: object("http").map(|h| HttpStage {
            status: h
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|s| u16::try_from(s).ok()),
            ms: millis(h, "ms"),
            server: text(h, "server"),
        }),
        geo: object("asn")
            .map(|a| GeoInfo {
                country: text(a, "country"),
                org: text(a, "org"),
            })
            .filter(|g| g.country.is_some() || g.org.is_some()),
        geo_blocked: flag(v, "geoBlocked"),
        ..PathReport::new(source)
    })
}

/// The error token an old message carried (the old allow-list put the code in the text).
fn legacy_code(message: &str) -> Option<ErrorCode> {
    const TOKENS: [(&str, ErrorCode); 15] = [
        ("ECONNRESET", ErrorCode::ConnReset),
        ("ECONNREFUSED", ErrorCode::ConnRefused),
        ("ETIMEDOUT", ErrorCode::TimedOut),
        ("ECONNABORTED", ErrorCode::TimedOut),
        ("ENOTFOUND", ErrorCode::NameNotFound),
        ("EAI_AGAIN", ErrorCode::DnsTemporary),
        ("ENETUNREACH", ErrorCode::NetUnreachable),
        ("EHOSTUNREACH", ErrorCode::HostUnreachable),
        ("EPROTO", ErrorCode::TlsProtocol),
        ("CERT_HAS_EXPIRED", ErrorCode::TlsCertExpired),
        ("ERR_TLS_CERT_ALTNAME_INVALID", ErrorCode::TlsCertName),
        ("DEPTH_ZERO_SELF_SIGNED_CERT", ErrorCode::TlsCertUntrusted),
        (
            "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
            ErrorCode::TlsCertUntrusted,
        ),
        ("EOF", ErrorCode::Closed),
        ("timeout", ErrorCode::TimedOut),
    ];
    TOKENS
        .iter()
        .find(|(token, _)| message.contains(token))
        .map(|(_, code)| *code)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::Stage;
    use super::*;

    /// storage §2.4 H4: old rows are re-normalised and their free text reduced to codes.
    #[test]
    fn legacy_rows() {
        let legacy = json!({"history": [
            {"id": "a", "url": "youtube.com", "testedAt": 1_700_000_000_000_i64, "tunnelActive": true,
             "tunnel": {"available": true, "totalMs": 120, "errorStage": null, "errorMessage": null,
                        "dns": {"resolved": true, "ips": ["203.0.113.5", "bad"], "ms": 3, "poisoned": false},
                        "tcp": {"connected": true, "ms": 10},
                        "tls": {"handshakeOk": true, "ms": 20, "cipher": "TLS_AES_128_GCM_SHA256", "protocol": "TLSv1.3"},
                        "http": {"status": 200, "ms": 40, "server": "gws"},
                        "asn": {"country": "неизвестно", "org": "Example AS"}, "source": "native"},
             "direct": {"available": false, "totalMs": null, "errorStage": "api",
                        "errorMessage": "sing-box clash API недоступен.", "source": "clash-direct-out"},
             "verdict": "works-only-with-vpn", "recommendation": "Сайт работает только через VPN"},
            {"id": "b", "url": "https://user:pw@example.com/p?token=secret", "testedAt": 1,
             "tunnel": null,
             "direct": {"available": false, "errorStage": "tcp", "source": "native",
                        "errorMessage": "TCP-соединение не открылось: ECONNRESET соединение сброшено."},
             "verdict": "unknown", "recommendation": "x"},
            {"id": "c", "url": "ftp://example.test", "testedAt": 2, "verdict": "unknown"},
            {"id": "d", "url": "example.com"}
        ]});
        let doc = UrlChecks::from_legacy(&legacy);
        assert_eq!(doc.history.len(), 2);
        let a = &doc.history[0];
        assert_eq!(a.url, "https://youtube.com/");
        let protected = a.protected.as_ref().unwrap();
        assert!(protected.available && protected.measured);
        assert_eq!(protected.dns.as_ref().unwrap().ips.len(), 1);
        assert_eq!(protected.geo.as_ref().unwrap().country, None);
        assert_eq!(
            protected.geo.as_ref().unwrap().org.as_deref(),
            Some("Example AS")
        );
        let direct = a.direct.as_ref().unwrap();
        assert!(!direct.measured, "an `api` failure was never a measurement");
        assert_eq!(direct.source, PathSource::DirectInbound);
        assert_eq!(a.verdict, AvailabilityVerdict::WorksOnlyWithVpn);
        assert_eq!(a.recommendation, Recommendation::OnlyWithVpn);
        let b = &doc.history[1];
        assert_eq!(b.url, "https://example.com/p");
        let direct = b.direct.as_ref().unwrap();
        assert_eq!(
            (direct.error_stage, direct.error),
            (Some(Stage::Tcp), Some(ErrorCode::ConnReset))
        );
        let json = serde_json::to_value(&doc).unwrap();
        assert!(!json.to_string().contains("secret"));
        assert_eq!(serde_json::from_value::<UrlChecks>(json).unwrap(), doc);
    }

    #[test]
    fn push_keeps_newest_fifty() {
        let legacy = json!({"history": (0..60).map(|i| json!({
            "id": format!("r{i}"), "url": "example.com", "testedAt": i, "verdict": "works-both"
        })).collect::<Vec<_>>()});
        let mut doc = UrlChecks::from_legacy(&legacy);
        assert_eq!(doc.history.len(), MAX_HISTORY);
        let newest = doc.history[0].clone();
        doc.push(AvailabilityResult {
            id: "new".into(),
            ..newest
        });
        assert_eq!(doc.history.len(), MAX_HISTORY);
        assert_eq!(doc.history[0].id, "new");
        assert_eq!(doc.history[1].id, "r0");
        doc.clear();
        assert!(doc.history.is_empty());
    }
}
