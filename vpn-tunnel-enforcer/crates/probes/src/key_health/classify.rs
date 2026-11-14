//! Verdict reasons from engine output and errors, and the Cloudflare trace parser
//! (keyHealthChecker.ts:76-87, 383-420; patterns verbatim except the two fixes noted below).
use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;
use vpnte_core::net::is_public_ip;
use vpnte_profiles::countries::Iso2;

use super::HealthReason;

fn re(pattern: &str) -> Regex {
    // Constant patterns, compiled by the tests.
    Regex::new(pattern).expect("static regex")
}

static HY2_CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"unknown field|decode config|parse config|invalid|unsupported|missing required|check outbound",
    )
});
static HY2_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    // `\bauth\b`, not the old bare `auth`: Go's "x509: certificate signed by unknown authority"
    // (a self-signed server without `insecure`) is a certificate failure, not a wrong password.
    re(
        r"\bauth\b|authentication|unauthori[sz]ed|password|bad key|permission denied|obfs|salamander",
    )
});
static HY2_UDP: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"no recent network activity|handshake.*timeout|timeout|deadline exceeded|i/o timeout|",
        r"network is unreachable|host unreachable|operation timed out|udp",
    ))
});
static HY2_TLS: LazyLock<Regex> = LazyLock::new(|| re(r"tls|certificate|x509|server name|sni"));
static CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"unknown field|decode config|parse config|invalid config|unsupported|missing required|check outbound",
    )
});
static TLS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"tls|certificate|x509|server name|sni|reality verification|reality.*invalid connection|bad reality",
    )
});
static AUTH: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\bauth\b|authentication|\bunauthori[sz]ed\b|bad key|wrong (?:uuid|password)|permission denied",
    )
});
static TIMEOUT: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"timeout|deadline exceeded|i/o timeout|network is unreachable|host unreachable|",
        r"operation timed out",
    ))
});
// A reset is not a timeout (RU audit item 6): Go on Windows words it "actively refused it".
static REFUSED: LazyLock<Regex> =
    LazyLock::new(|| re(r"connection refused|actively refused|econnrefused"));
static TRACE_IP: LazyLock<Regex> = LazyLock::new(|| re(r"\bip=([0-9a-fA-F:.]+)"));
static TRACE_LOC: LazyLock<Regex> = LazyLock::new(|| re(r"\bloc=([A-Za-z]{2})\b"));

/// Why a key is offline, from the probe engine's output (`log`, kept at debug level: the
/// patterns come from debug and error lines) and the error texts of the attempt (`err`).
/// Hysteria2 has its own ladder: an empty text means the QUIC handshake never completed.
pub fn classify_failure(hysteria2: bool, log: &str, err: &str) -> HealthReason {
    let text = format!("{log}\n{err}").to_lowercase();
    if hysteria2 {
        return if text.trim().is_empty() {
            HealthReason::Hy2HandshakeFailed
        } else if HY2_CONFIG.is_match(&text) {
            HealthReason::Hy2ConfigFailed
        } else if HY2_AUTH.is_match(&text) {
            HealthReason::Hy2AuthFailed
        } else if HY2_UDP.is_match(&text) {
            HealthReason::Hy2UdpBlocked
        } else if HY2_TLS.is_match(&text) {
            HealthReason::Hy2TlsFailed
        } else {
            HealthReason::Hy2HandshakeFailed
        };
    }
    // Auth before the broad `tls` pattern (live-probe B-37): in the old order a "tls" substring
    // anywhere in the debug log turned a rejected key into `tls-failed`. A refused dial never
    // reached TLS, so it goes before that pattern for the same reason.
    if CONFIG.is_match(&text) {
        HealthReason::ConfigFailed
    } else if AUTH.is_match(&text) {
        HealthReason::AuthFailed
    } else if REFUSED.is_match(&text) {
        HealthReason::ConnectionRefused
    } else if TLS.is_match(&text) {
        HealthReason::TlsFailed
    } else if TIMEOUT.is_match(&text) {
        HealthReason::Timeout
    } else {
        HealthReason::HandshakeFailed
    }
}

/// The reason for a profile the engines cannot even be configured for.
pub(crate) fn config_failed(hysteria2: bool) -> HealthReason {
    if hysteria2 {
        HealthReason::Hy2ConfigFailed
    } else {
        HealthReason::ConfigFailed
    }
}

/// `(egress IP, country)` of a Cloudflare trace body: the IP only when public, the country only
/// when it is a real ISO code (the old code stored `XX` as a country).
pub fn parse_trace(text: &str) -> (Option<IpAddr>, Option<Iso2>) {
    let ip = TRACE_IP
        .captures(text)
        .and_then(|c| c[1].trim().parse::<IpAddr>().ok())
        .filter(|ip| is_public_ip(*ip));
    let country = TRACE_LOC.captures(text).and_then(|c| Iso2::new(&c[1]));
    (ip, country)
}
