//! HTTP plumbing shared by every crate: one TLS stack (rustls + ring, Windows trust store) and
//! client builders with the app's defaults.
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Set by [`verify_offline`]: every client of this process checks certificates offline.
static OFFLINE: AtomicBool = AtomicBool::new(false);

/// Installs the process-wide rustls crypto provider. Call once at startup (idempotent).
pub fn init_tls() {
    // An Err only means a provider is already installed, which is what we want.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Client builder with the app defaults: no system proxy, no redirects, bounded timeouts.
///
/// WHY no system proxy: in Soft mode the app points the per-user system proxy and the proxy
/// environment variables at its own engine; our own requests must not loop through it unless a
/// caller routes them explicitly.
pub fn client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    init_tls();
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout);
    if OFFLINE.load(Ordering::Relaxed) {
        offline(builder)
    } else {
        builder
    }
}

/// From now on every client this process builds checks certificates offline ([`offline`]).
/// The helper service calls it once at start: its HTTPS (DoH, exit proofs) runs while the kill
/// switch's DNS block is held, where an online certificate check cannot finish.
pub fn verify_offline() {
    OFFLINE.store(true, Ordering::Relaxed);
}

/// `builder` with a certificate check that never goes online: rustls over the bundled Mozilla
/// roots plus the Windows root store, read once per process. Chain and host-name checks stay.
///
/// WHY (lab F-3, speed audit conn1, 14.11.2026): the platform verifier asks CryptoAPI, whose
/// end-certificate revocation fetch resolves its URL through the DNS client service; under the
/// kill switch's DNS block (a Tunnel start in the helper service, every recovery) that fetch
/// waits up to 10 s inside the handshake, and exit proofs failed on working servers. Revocation
/// is soft-fail there anyway. Bundled roots as well: Windows installs roots on demand, so a
/// fresh PC's store may lack the one a service needs.
pub fn offline(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder.tls_backend_preconfigured(offline_config().clone())
}

/// The rustls config behind [`offline`], built on first use.
fn offline_config() -> &'static rustls::ClientConfig {
    static CONFIG: OnceLock<rustls::ClientConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        init_tls();
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        let native = rustls_native_certs::load_native_certs();
        let errors = native.errors.len();
        let (added, ignored) = roots.add_parsable_certificates(native.certs);
        tracing::debug!(
            added,
            ignored,
            errors,
            "Windows roots read for offline checks"
        );
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // A preconfigured backend is used as it is: offer what reqwest offers on its own.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds_with_the_ring_provider() {
        assert!(client_builder(Duration::from_secs(5)).build().is_ok());
    }

    /// Speed audit conn1: the offline check trusts the bundled roots (a fresh PC's Windows store
    /// may lack them) and offers both HTTP versions like reqwest's own config.
    #[test]
    fn the_offline_check_carries_bundled_roots_and_builds() {
        let config = offline_config();
        assert_eq!(
            config.alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert!(webpki_root_certs::TLS_SERVER_ROOT_CERTS.len() > 100);
        let builder = offline(client_builder(Duration::from_secs(5)));
        assert!(builder.build().is_ok());
    }
}
