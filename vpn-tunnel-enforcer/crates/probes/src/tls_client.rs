//! rustls client configs of the probes (ring provider, TLS 1.2 / 1.3): one that checks only the
//! handshake signatures (stages that inspect a server's certificate instead of trusting it) and
//! one verified against the Windows trust store (answers that must come from the real service:
//! a censor's block page must not count).
use std::sync::{Arc, OnceLock};

use rustls::ClientConfig;
use rustls::crypto::CryptoProvider;

/// The ring provider, built once.
pub(crate) fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

fn with_alpn(mut config: ClientConfig, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// Any certificate accepted (we inspect, not trust), handshake signatures still checked.
pub(crate) fn inspecting(alpn: &[&[u8]]) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = provider();
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(inspect::Inspect(provider)))
        .with_no_client_auth();
    Ok(with_alpn(config, alpn))
}

/// Certificates verified against the Windows trust store (platform verifier).
pub(crate) fn verified(alpn: &[&[u8]]) -> Result<Arc<ClientConfig>, rustls::Error> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth();
    Ok(with_alpn(config, alpn))
}

mod inspect {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    /// Accepts any certificate but still checks the handshake signatures.
    #[derive(Debug)]
    pub(super) struct Inspect(pub(super) Arc<CryptoProvider>);

    impl ServerCertVerifier for Inspect {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            let algs = &self.0.signature_verification_algorithms;
            rustls::crypto::verify_tls12_signature(message, cert, dss, algs)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            let algs = &self.0.signature_verification_algorithms;
            rustls::crypto::verify_tls13_signature(message, cert, dss, algs)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
