use std::sync::Arc;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;

use super::*;
use crate::live_stages::{CANCELLED, ProbeRoute};

const CERT: &[u8] = include_bytes!("../testdata/self-signed.der");
const KEY: &[u8] = include_bytes!("../testdata/self-signed.key.der");
const FINGERPRINT: &str = "8E:83:17:E6:3A:B1:3D:9B:A8:93:6E:35:B3:2B:42:7F:EB:26:9C:0A:BB:90:A6:C1:1F:9F:94:2A:69:84:8A:1E";

/// rustls server config with the fake self-signed certificate.
pub(crate) fn server_config(alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec()));
    let mut config = rustls::ServerConfig::builder_with_provider(crate::tls_client::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(CERT.to_vec())], key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// A loopback TLS server answering handshakes until the test ends.
async fn tls_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config(&[b"h2".as_slice()]));
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(sock).await {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    drop(stream);
                }
            });
        }
    });
    addr
}

/// AT-05-001 (audit defect 4): identity checked against the IP; self-signed is untrusted
/// but still `ok`; ALPN, fingerprint and validity are reported.
#[tokio::test]
async fn inspects_a_self_signed_certificate_by_ip() {
    let addr = tls_server().await;
    let cancel = CancellationToken::new();
    let info = inspect_tls(addr, "127.0.0.1", &ProbePath::Os, &cancel).await;
    assert_eq!(info.timed.status, TimedStatus::Ok, "{info:?}");
    assert_eq!(info.hostname_verified, Some(false));
    assert!(
        info.timed
            .error
            .as_deref()
            .unwrap()
            .contains("does not match")
    );
    assert_eq!(info.authorized, Some(false));
    assert_eq!(
        info.authorization_error.as_deref(),
        Some("DEPTH_ZERO_SELF_SIGNED_CERT")
    );
    assert_eq!(info.alpn.as_deref(), Some("h2"));
    assert_eq!(info.protocol.as_deref(), Some("TLSv1.3"));
    assert!(info.cipher.as_deref().unwrap().starts_with("TLS_"));
    assert_eq!(info.fingerprint.as_deref(), Some(FINGERPRINT));
    assert_eq!(info.subject.as_deref(), Some("unrelated.example"));
    assert_eq!(info.issuer.as_deref(), Some("Test Org"));
    assert_eq!(info.valid_to.as_deref(), Some("Oct 18 04:12:44 2126 GMT"));
    assert_eq!(info.sans.len(), 4);
    assert!(info.days_remaining.unwrap() > 36_000);
    assert_eq!(info.timed.route, Some(ProbeRoute::Os));
}

/// The SNI identity named by the certificate verifies.
#[tokio::test]
async fn matching_identity_verifies() {
    let addr = tls_server().await;
    let cancel = CancellationToken::new();
    let info = inspect_tls(addr, "unrelated.example", &ProbePath::Os, &cancel).await;
    assert_eq!(info.timed.status, TimedStatus::Ok, "{info:?}");
    assert_eq!(info.hostname_verified, Some(true));
    assert_eq!(info.timed.error, None);
}

/// AT-00-003: cancel -> skipped, nothing sent; early close -> error (§7.7).
#[tokio::test]
async fn cancel_and_close() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let info = inspect_tls(addr, "x.example", &ProbePath::Os, &cancel).await;
    assert_eq!(info.timed.status, TimedStatus::Skipped);
    assert_eq!(info.timed.error.as_deref(), Some(CANCELLED));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            drop(sock);
        }
    });
    let info = inspect_tls(addr, "x.example", &ProbePath::Os, &CancellationToken::new()).await;
    assert_eq!(info.timed.status, TimedStatus::Error);
    assert!(info.timed.error.is_some());
    assert_eq!(info.fingerprint, None);
}

/// AT-00-003: a server that never answers the ClientHello -> `TLS handshake timeout` at 3.5 s.
#[tokio::test]
async fn silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    let info = inspect_tls(addr, "x.example", &ProbePath::Os, &CancellationToken::new()).await;
    assert_eq!(info.timed.status, TimedStatus::Error);
    assert_eq!(info.timed.error.as_deref(), Some("TLS handshake timeout"));
    assert!(
        (3500..4000).contains(&info.timed.duration_ms),
        "{}",
        info.timed.duration_ms
    );
}

#[test]
fn helpers() {
    assert_eq!(
        cipher_text("TLS13_AES_128_GCM_SHA256"),
        "TLS_AES_128_GCM_SHA256"
    );
    assert_eq!(
        cipher_text("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    );
    let ip = IpAddr::from([192, 0, 2, 1]);
    assert!(matches!(
        server_name("192.0.2.1", ip),
        ServerName::IpAddress(_)
    ));
    assert!(matches!(
        server_name("vpn.example.com.", ip),
        ServerName::DnsName(_)
    ));
    assert!(matches!(
        server_name("bad name", ip),
        ServerName::IpAddress(_)
    ));
    // 1.5 days rounds up, 1.4 down, -0.5 to 0 (JS Math.round).
    assert_eq!(days_remaining(129_600, 0), 2);
    assert_eq!(days_remaining(120_960, 0), 1);
    assert_eq!(days_remaining(0, 43_200_000), 0);
}

#[test]
fn authorization_codes() {
    use rustls::CertificateError as C;
    let bad = |e| Err(rustls::Error::InvalidCertificate(e));
    assert_eq!(authorization(Ok(()), false), (true, None));
    assert_eq!(authorization(bad(C::NotValidForName), false), (true, None));
    assert_eq!(
        authorization(bad(C::UnknownIssuer), true).1.as_deref(),
        Some("DEPTH_ZERO_SELF_SIGNED_CERT")
    );
    assert_eq!(
        authorization(bad(C::Expired), false),
        (false, Some("CERT_HAS_EXPIRED".into()))
    );
}
