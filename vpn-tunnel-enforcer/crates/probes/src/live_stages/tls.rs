//! Direct TLS inspection: what certificate the server presents, whether Windows trusts it and
//! whether it names the identity we dial. Never fails the probe on trust (we inspect, not trust).
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rustls::ProtocolVersion;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{ProbePath, Timed, TimedStatus, elapsed_ms, net, timeouts, x509};

/// Direct TLS result (`tls` in the row). `status: ok` with an `error` = handshake done but the
/// certificate does not name the identity (old semantics).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    #[serde(flatten)]
    pub timed: Timed,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_verified: Option<bool>,
    /// Chain trusted by the Windows store (`None`: verification did not finish).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
    /// Node / OpenSSL style code: `DEPTH_ZERO_SELF_SIGNED_CERT`, `CERT_HAS_EXPIRED`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// OpenSSL text (`Jan  1 00:00:00 2027 GMT`), as the old rows store it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_remaining: Option<i64>,
    /// SHA-256 of the leaf, upper-case hex with colons (Node `fingerprint256`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    /// `TLSv1.3` / `TLSv1.2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

/// How long the Windows chain check may take after the handshake (it can fetch revocation data).
const TRUST_CHECK: Duration = Duration::from_secs(3);

/// Handshakes with `addr` (ALPN h2 + http/1.1) within 3.5 s and describes the certificate.
/// `identity` = SNI or host; SNI is sent only for DNS names (RFC 6066).
pub async fn inspect_tls(
    addr: SocketAddr,
    identity: &str,
    path: &ProbePath,
    cancel: &CancellationToken,
) -> TlsInfo {
    if cancel.is_cancelled() {
        return TlsInfo {
            timed: Timed::cancelled(),
            ..TlsInfo::default()
        };
    }
    let start = Instant::now();
    let fail = |error: String| TlsInfo {
        timed: Timed::done(
            TimedStatus::Error,
            elapsed_ms(start),
            Some(error),
            path.route(),
        ),
        ..TlsInfo::default()
    };
    let name = server_name(identity, addr.ip());
    let handshake = async {
        let tcp = net::connect(addr, path, timeouts::TLS).await?;
        let config = crate::tls_client::inspecting(&[b"h2".as_slice(), b"http/1.1".as_slice()])
            .map_err(|e| e.to_string())?;
        tokio_rustls::TlsConnector::from(config)
            .connect(name.clone(), tcp)
            .await
            .map_err(|e| tls_error_text(&e))
    };
    let stream = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            return TlsInfo { timed: Timed::cancelled(), ..TlsInfo::default() };
        }
        r = tokio::time::timeout(timeouts::TLS, handshake) => match r {
            Err(_) => return fail("TLS handshake timeout".into()),
            Ok(Err(e)) => return fail(e),
            Ok(Ok(stream)) => stream,
        },
    };
    let ms = elapsed_ms(start);
    let conn = stream.get_ref().1;
    let chain: Vec<CertificateDer<'static>> = conn.peer_certificates().unwrap_or_default().to_vec();
    let protocol = conn.protocol_version().map(protocol_text);
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|s| cipher_text(&format!("{:?}", s.suite())));
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    drop(stream);
    let Some(leaf) = chain.first() else {
        return fail("No peer certificate returned".into());
    };
    let Some(cert) = x509::parse(leaf) else {
        return fail("Certificate parsing error: not an X.509 certificate".into());
    };
    let trust = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            return TlsInfo { timed: Timed::cancelled(), ..TlsInfo::default() };
        }
        t = windows_trust(chain.clone(), name) => t,
    };
    let (authorized, authorization_error) = match trust {
        Some(verdict) => {
            let (ok, code) = authorization(verdict, cert.subject == cert.issuer);
            (Some(ok), code)
        }
        None => (None, None),
    };
    let verified = cert.matches_identity(identity);
    let verify_error = (!verified)
        .then(|| format!("Hostname/IP does not match certificate's altnames: {identity}"));
    TlsInfo {
        timed: Timed::done(TimedStatus::Ok, ms, verify_error, path.route()),
        hostname_verified: Some(verified),
        authorized,
        authorization_error,
        subject: Some(cert.subject_text()),
        issuer: Some(cert.issuer_text()),
        valid_from: Some(cert.not_before.openssl_text()),
        valid_to: Some(cert.not_after.openssl_text()),
        days_remaining: Some(days_remaining(
            cert.not_after.unix_secs(),
            vpnte_base::types::now_ms(),
        )),
        fingerprint: Some(fingerprint(leaf)),
        sans: cert.sans(),
        protocol,
        cipher,
        alpn,
    }
}

/// SNI / verification name: a DNS name, or the IP (no SNI is sent for IPs).
pub(crate) fn server_name(identity: &str, fallback: IpAddr) -> ServerName<'static> {
    let id = identity.trim().trim_end_matches('.');
    let unbracketed = id.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return ServerName::IpAddress(ip.into());
    }
    ServerName::try_from(id.to_owned()).unwrap_or(ServerName::IpAddress(fallback.into()))
}

/// Technical text of a failed handshake.
pub(crate) fn tls_error_text(err: &std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        return "TLS connection closed before handshake".into();
    }
    match err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        Some(tls) => tls.to_string(),
        None => net::errno_name(err),
    }
}

fn protocol_text(v: ProtocolVersion) -> String {
    match v {
        ProtocolVersion::TLSv1_3 => "TLSv1.3".into(),
        ProtocolVersion::TLSv1_2 => "TLSv1.2".into(),
        other => format!("{other:?}"),
    }
}

/// IANA suite name (rustls spells the TLS 1.3 suites `TLS13_…`).
fn cipher_text(debug: &str) -> String {
    match debug.strip_prefix("TLS13_") {
        Some(rest) => format!("TLS_{rest}"),
        None => debug.to_owned(),
    }
}

/// Windows chain verdict, off the runtime threads (`None`: it did not finish in time).
async fn windows_trust(
    chain: Vec<CertificateDer<'static>>,
    name: ServerName<'static>,
) -> Option<Result<(), rustls::Error>> {
    let job = tokio::task::spawn_blocking(move || {
        let verifier =
            rustls_platform_verifier::Verifier::new(crate::tls_client::provider()).ok()?;
        let (leaf, intermediates) = chain.split_first()?;
        let now = UnixTime::now();
        Some(
            verifier
                .verify_server_cert(leaf, intermediates, &name, &[], now)
                .map(drop),
        )
    });
    tokio::time::timeout(TRUST_CHECK, job).await.ok()?.ok()?
}

/// Node's `authorized` (chain trusted; a name mismatch is reported separately) and error code.
fn authorization(verdict: Result<(), rustls::Error>, self_signed: bool) -> (bool, Option<String>) {
    use rustls::CertificateError as C;
    let code = match verdict {
        Ok(()) => return (true, None),
        Err(rustls::Error::InvalidCertificate(e)) => match e {
            C::NotValidForName | C::NotValidForNameContext { .. } => return (true, None),
            C::UnknownIssuer if self_signed => "DEPTH_ZERO_SELF_SIGNED_CERT".into(),
            C::UnknownIssuer => "UNABLE_TO_GET_ISSUER_CERT_LOCALLY".into(),
            C::Expired | C::ExpiredContext { .. } => "CERT_HAS_EXPIRED".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "CERT_NOT_YET_VALID".into(),
            C::Revoked => "CERT_REVOKED".into(),
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => "INVALID_PURPOSE".into(),
            other => rustls::Error::InvalidCertificate(other).to_string(),
        },
        Err(other) => other.to_string(),
    };
    (false, Some(code))
}

/// Whole days until `not_after`, rounded like JS `Math.round`.
fn days_remaining(not_after_secs: i64, now_ms: i64) -> i64 {
    let days = (not_after_secs as f64 * 1000.0 - now_ms as f64) / 86_400_000.0;
    (days + 0.5).floor() as i64
}

/// Node `fingerprint256`: SHA-256, upper-case hex, colon-separated.
fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
pub(crate) mod tests;
