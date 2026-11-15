//! What one path measurement found: per-stage facts, a sanitised error code and the HTTP class.
//! Only fixed vocabulary crosses into the UI and the history, never an OS or library message
//! (they can carry paths, hosts or credentials).
use std::error::Error;
use std::io;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;

use super::geo_block::GeoReason;

/// Probe stage, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Dns,
    Tcp,
    Tls,
    Http,
}

/// How a path was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathSource {
    /// From the app itself: DNS, TCP, TLS and HTTP stages.
    Native,
    /// Through the engine's direct inbound (`mixed-direct-in`): HTTP stage only.
    DirectInbound,
}

/// What an HTTP status means for availability (B-UA-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpClass {
    /// 1xx, 2xx, 3xx.
    Success,
    /// 401 / 403: the origin answered but refuses (login or IP policy).
    AuthRequired,
    NotFound,
    RateLimited,
    /// Any other 4xx.
    ClientError,
    /// 5xx.
    ServerError,
    /// 451 Unavailable For Legal Reasons.
    Legal,
}

impl HttpClass {
    /// Class of a status code.
    pub fn of(status: u16) -> HttpClass {
        match status {
            401 | 403 => HttpClass::AuthRequired,
            404 => HttpClass::NotFound,
            429 => HttpClass::RateLimited,
            451 => HttpClass::Legal,
            400..=499 => HttpClass::ClientError,
            500.. => HttpClass::ServerError,
            _ => HttpClass::Success,
        }
    }

    /// Text shown next to the status (`probes.availability.http.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            HttpClass::Success => "probes.availability.http.success",
            HttpClass::AuthRequired => "probes.availability.http.authRequired",
            HttpClass::NotFound => "probes.availability.http.notFound",
            HttpClass::RateLimited => "probes.availability.http.rateLimited",
            HttpClass::ClientError => "probes.availability.http.clientError",
            HttpClass::ServerError => "probes.availability.http.serverError",
            HttpClass::Legal => "probes.availability.http.legal",
        })
    }
}

/// Sanitised cause of a failed stage (the old `probeError` allow-list, §3.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    ConnRefused,
    ConnReset,
    ConnAborted,
    /// The remote side closed the connection (EOF), typical of DPI dropping a handshake.
    Closed,
    TimedOut,
    AccessDenied,
    NetUnreachable,
    HostUnreachable,
    NameNotFound,
    DnsTemporary,
    /// The answer looks like DNS spoofing (a stub address); a suspicion, not proof.
    DnsSuspect,
    TlsProtocol,
    TlsCertName,
    TlsCertExpired,
    TlsCertUntrusted,
    /// The engine's direct inbound could not be used.
    ProxyFailed,
    /// The peer answered, but not with a usable HTTP response.
    BadResponse,
    Unknown,
}

impl ErrorCode {
    /// User text of the cause (`probes.availability.error.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            ErrorCode::ConnRefused => "probes.availability.error.connRefused",
            ErrorCode::ConnReset => "probes.availability.error.connReset",
            ErrorCode::ConnAborted => "probes.availability.error.connAborted",
            ErrorCode::Closed => "probes.availability.error.closed",
            ErrorCode::TimedOut => "probes.availability.error.timedOut",
            ErrorCode::AccessDenied => "probes.availability.error.accessDenied",
            ErrorCode::NetUnreachable => "probes.availability.error.netUnreachable",
            ErrorCode::HostUnreachable => "probes.availability.error.hostUnreachable",
            ErrorCode::NameNotFound => "probes.availability.error.nameNotFound",
            ErrorCode::DnsTemporary => "probes.availability.error.dnsTemporary",
            ErrorCode::DnsSuspect => "probes.availability.error.dnsSuspect",
            ErrorCode::TlsProtocol => "probes.availability.error.tlsProtocol",
            ErrorCode::TlsCertName => "probes.availability.error.tlsCertName",
            ErrorCode::TlsCertExpired => "probes.availability.error.tlsCertExpired",
            ErrorCode::TlsCertUntrusted => "probes.availability.error.tlsCertUntrusted",
            ErrorCode::ProxyFailed => "probes.availability.error.proxyFailed",
            ErrorCode::BadResponse => "probes.availability.error.badResponse",
            ErrorCode::Unknown => "probes.availability.error.unknown",
        })
    }

    /// Classifies an error chain (io / rustls / reqwest) into the fixed vocabulary.
    pub fn classify(err: &(dyn Error + 'static)) -> ErrorCode {
        let mut timeout = false;
        let mut current = Some(err);
        while let Some(e) = current {
            if let Some(io) = e.downcast_ref::<io::Error>() {
                // `io::Error::source` skips the wrapped error itself (tokio-rustls puts the
                // rustls error there), so look inside first.
                if let Some(inner) = io.get_ref() {
                    let code = ErrorCode::classify(inner);
                    if code != ErrorCode::Unknown {
                        return code;
                    }
                }
                if let Some(code) = from_io(io) {
                    return code;
                }
            }
            if let Some(tls) = e.downcast_ref::<rustls::Error>() {
                return from_tls(tls);
            }
            if let Some(req) = e.downcast_ref::<reqwest::Error>() {
                timeout |= req.is_timeout();
            }
            if e.is::<tokio::time::error::Elapsed>() {
                return ErrorCode::TimedOut;
            }
            current = e.source();
        }
        if timeout {
            ErrorCode::TimedOut
        } else {
            ErrorCode::Unknown
        }
    }

    /// A failure of the network itself (as opposed to the origin's answer): the kind of failure
    /// that may be blamed on the provider (B-UA-3).
    pub fn is_network(self) -> bool {
        !matches!(
            self,
            ErrorCode::ProxyFailed | ErrorCode::BadResponse | ErrorCode::Unknown
        )
    }
}

fn from_io(err: &io::Error) -> Option<ErrorCode> {
    // WSA codes first: tokio and hyper keep the raw OS error even when the kind is generic.
    let by_code = match err.raw_os_error() {
        Some(10061) => Some(ErrorCode::ConnRefused),
        Some(10054) => Some(ErrorCode::ConnReset),
        Some(10053) => Some(ErrorCode::ConnAborted),
        Some(10060) => Some(ErrorCode::TimedOut),
        Some(10013) => Some(ErrorCode::AccessDenied),
        Some(10051) => Some(ErrorCode::NetUnreachable),
        Some(10065) => Some(ErrorCode::HostUnreachable),
        Some(11001 | 11004) => Some(ErrorCode::NameNotFound),
        Some(11002) => Some(ErrorCode::DnsTemporary),
        _ => None,
    };
    by_code.or(match err.kind() {
        io::ErrorKind::ConnectionRefused => Some(ErrorCode::ConnRefused),
        io::ErrorKind::ConnectionReset => Some(ErrorCode::ConnReset),
        io::ErrorKind::ConnectionAborted => Some(ErrorCode::ConnAborted),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe => Some(ErrorCode::Closed),
        io::ErrorKind::TimedOut => Some(ErrorCode::TimedOut),
        io::ErrorKind::PermissionDenied => Some(ErrorCode::AccessDenied),
        io::ErrorKind::NetworkUnreachable => Some(ErrorCode::NetUnreachable),
        io::ErrorKind::HostUnreachable => Some(ErrorCode::HostUnreachable),
        _ => None,
    })
}

fn from_tls(err: &rustls::Error) -> ErrorCode {
    use rustls::CertificateError as Cert;
    match err {
        rustls::Error::InvalidCertificate(Cert::Expired | Cert::ExpiredContext { .. }) => {
            ErrorCode::TlsCertExpired
        }
        rustls::Error::InvalidCertificate(
            Cert::NotValidForName | Cert::NotValidForNameContext { .. },
        ) => ErrorCode::TlsCertName,
        rustls::Error::InvalidCertificate(_) => ErrorCode::TlsCertUntrusted,
        _ => ErrorCode::TlsProtocol,
    }
}

/// DNS stage: the OS resolver's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsStage {
    pub resolved: bool,
    #[serde(default)]
    pub ips: Vec<IpAddr>,
    #[serde(default)]
    pub ms: Option<u32>,
    /// Suspected spoofing (stub or non-public answer for a public name); never proof.
    #[serde(default)]
    pub poisoned: bool,
}

/// TCP stage: a plain connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpStage {
    pub connected: bool,
    #[serde(default)]
    pub ms: Option<u32>,
}

/// TLS stage: a handshake with SNI that accepts any certificate (a self-signed or mismatched
/// certificate still proves TLS reachability; validity is judged by the HTTP stage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsStage {
    pub handshake_ok: bool,
    #[serde(default)]
    pub ms: Option<u32>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub cipher: Option<String>,
}

/// HTTP stage: HEAD (ranged GET fallback) with certificate validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpStage {
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub ms: Option<u32>,
    /// The `Server` header (printable ASCII, at most 64 chars).
    #[serde(default)]
    pub server: Option<String>,
}

impl HttpStage {
    /// Class of the status, when there is one.
    pub fn class(&self) -> Option<HttpClass> {
        self.status.map(HttpClass::of)
    }
}

/// Country / network of the first resolved address (from the app's geo lookup).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 code.
    #[serde(default)]
    pub country: Option<String>,
    /// Organisation or AS name.
    #[serde(default)]
    pub org: Option<String>,
}

/// The measurement of one path ("с защитой" or "без VPN").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathReport {
    pub source: PathSource,
    /// `false`: the path could not be measured at all (no direct inbound, setup failed); such
    /// a side never counts as "blocked" (B-UA-3).
    pub measured: bool,
    /// The origin answered meaningfully: a status that is neither 5xx nor 451, no geo block.
    pub available: bool,
    #[serde(default)]
    pub total_ms: Option<u32>,
    #[serde(default)]
    pub error_stage: Option<Stage>,
    #[serde(default)]
    pub error: Option<ErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoInfo>,
    /// The page says the site refuses this region (page signal or HTTP 451).
    #[serde(default)]
    pub geo_blocked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub geo_reasons: Vec<GeoReason>,
}

impl PathReport {
    /// An empty, measured report; stages fill it in.
    pub fn new(source: PathSource) -> PathReport {
        PathReport {
            source,
            measured: true,
            available: false,
            total_ms: None,
            error_stage: None,
            error: None,
            dns: None,
            tcp: None,
            tls: None,
            http: None,
            geo: None,
            geo_blocked: false,
            geo_reasons: Vec::new(),
        }
    }

    /// A side that could not be measured.
    pub fn unmeasured(source: PathSource, error: ErrorCode) -> PathReport {
        PathReport {
            measured: false,
            error: Some(error),
            ..PathReport::new(source)
        }
    }

    /// Class of the HTTP status, when the origin answered.
    pub fn http_class(&self) -> Option<HttpClass> {
        self.http.as_ref().and_then(HttpStage::class)
    }

    /// The origin answered with some HTTP status.
    pub fn reached(&self) -> bool {
        self.http.as_ref().is_some_and(|h| h.status.is_some())
    }

    /// Available and not merely an access refusal (401 / 403).
    pub fn works(&self) -> bool {
        self.available && self.http_class() != Some(HttpClass::AuthRequired)
    }

    /// Available but refused (401 / 403).
    pub fn refused(&self) -> bool {
        self.available && self.http_class() == Some(HttpClass::AuthRequired)
    }

    /// Failed at a measured network stage (DNS / TCP / TLS, or a transport error before any
    /// HTTP status): the only failure the provider may be blamed for (B-UA-3).
    pub fn failed_in_network(&self) -> bool {
        if !self.measured || self.available || self.geo_blocked {
            return false;
        }
        match self.error_stage {
            Some(Stage::Dns | Stage::Tcp | Stage::Tls) => true,
            Some(Stage::Http) => !self.reached() && self.error.is_some_and(ErrorCode::is_network),
            None => false,
        }
    }

    /// One sentence for the user about why the path failed; `None` when it worked.
    pub fn summary(&self) -> Option<Msg> {
        if !self.measured {
            return Some(Msg::new("probes.availability.fail.notMeasured"));
        }
        if self.available {
            return None;
        }
        let status = self.http.as_ref().and_then(|h| h.status);
        Some(match self.error_stage {
            _ if self.geo_blocked && status == Some(451) => {
                Msg::new("probes.availability.fail.legal")
            }
            _ if self.geo_blocked => Msg::new("probes.availability.fail.geoBlock"),
            Some(Stage::Dns) if self.dns.as_ref().is_some_and(|d| d.poisoned) => {
                let ips = self
                    .dns
                    .as_ref()
                    .map(|d| d.ips.as_slice())
                    .unwrap_or_default();
                let ips: Vec<String> = ips.iter().map(ToString::to_string).collect();
                Msg::new("probes.availability.fail.dnsSuspect").arg("ips", ips.join(", "))
            }
            Some(Stage::Dns) => Msg::new("probes.availability.fail.dns"),
            Some(Stage::Tcp) => Msg::new("probes.availability.fail.tcp"),
            Some(Stage::Tls) => Msg::new("probes.availability.fail.tls"),
            _ => match status {
                Some(status) => {
                    Msg::new("probes.availability.fail.httpStatus").arg("status", status)
                }
                None => Msg::new("probes.availability.fail.http"),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The old `probeError` allow-list (AT-07-002): codes only, never the message text.
    #[test]
    fn classifies_io_and_tls_errors() {
        let os = |code| io::Error::from_raw_os_error(code);
        assert_eq!(ErrorCode::classify(&os(10061)), ErrorCode::ConnRefused);
        assert_eq!(ErrorCode::classify(&os(10054)), ErrorCode::ConnReset);
        assert_eq!(ErrorCode::classify(&os(10060)), ErrorCode::TimedOut);
        assert_eq!(ErrorCode::classify(&os(11001)), ErrorCode::NameNotFound);
        assert_eq!(ErrorCode::classify(&os(11002)), ErrorCode::DnsTemporary);
        let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof C:\\secret");
        assert_eq!(ErrorCode::classify(&eof), ErrorCode::Closed);
        let expired = rustls::Error::InvalidCertificate(rustls::CertificateError::Expired);
        let wrapped = io::Error::new(io::ErrorKind::InvalidData, expired);
        assert_eq!(ErrorCode::classify(&wrapped), ErrorCode::TlsCertExpired);
        let name = rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName);
        assert_eq!(ErrorCode::classify(&name), ErrorCode::TlsCertName);
        let alert = rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure);
        assert_eq!(ErrorCode::classify(&alert), ErrorCode::TlsProtocol);
        let other = io::Error::other("dial FAKE-private C:\\secret");
        assert_eq!(ErrorCode::classify(&other), ErrorCode::Unknown);
        assert!(!ErrorCode::Unknown.is_network() && ErrorCode::ConnReset.is_network());
    }

    #[tokio::test]
    async fn classifies_elapsed_deadlines() {
        let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        assert_eq!(ErrorCode::classify(&elapsed), ErrorCode::TimedOut);
    }

    #[test]
    fn http_classes_and_summaries() {
        let class = |s| HttpClass::of(s);
        assert_eq!(
            [200, 301, 401, 403, 404, 429, 418, 451, 503].map(class),
            [
                HttpClass::Success,
                HttpClass::Success,
                HttpClass::AuthRequired,
                HttpClass::AuthRequired,
                HttpClass::NotFound,
                HttpClass::RateLimited,
                HttpClass::ClientError,
                HttpClass::Legal,
                HttpClass::ServerError,
            ]
        );
        let dns = PathReport {
            error_stage: Some(Stage::Dns),
            error: Some(ErrorCode::DnsSuspect),
            dns: Some(DnsStage {
                resolved: true,
                ips: vec!["127.0.0.1".parse().unwrap()],
                ms: Some(4),
                poisoned: true,
            }),
            ..PathReport::new(PathSource::Native)
        };
        let msg = dns.summary().unwrap();
        assert_eq!(
            msg,
            Msg::new("probes.availability.fail.dnsSuspect").arg("ips", "127.0.0.1")
        );
        assert!(dns.failed_in_network());
        let server_error = PathReport {
            error_stage: Some(Stage::Http),
            http: Some(HttpStage {
                status: Some(502),
                ms: Some(9),
                server: None,
            }),
            ..PathReport::new(PathSource::DirectInbound)
        };
        assert_eq!(
            server_error.summary().unwrap().key,
            "probes.availability.fail.httpStatus"
        );
        assert!(
            !server_error.failed_in_network(),
            "an origin's 5xx is not the provider"
        );
        let unmeasured = PathReport::unmeasured(PathSource::DirectInbound, ErrorCode::ProxyFailed);
        assert_eq!(
            unmeasured.summary().unwrap().key,
            "probes.availability.fail.notMeasured"
        );
        assert!(!unmeasured.failed_in_network());
    }
}
