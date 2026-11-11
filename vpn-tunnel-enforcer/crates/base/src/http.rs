//! HTTP plumbing shared by every crate: one TLS stack (rustls + ring, Windows trust store) and
//! client builders with the app's defaults.
use std::time::Duration;

/// Installs the process-wide rustls crypto provider. Call once at startup (idempotent).
pub fn init_tls() {
    // An Err only means a provider is already installed, which is what we want.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Client builder with the app defaults: no system proxy, no redirects, bounded timeouts.
///
/// WHY no system proxy: in soft mode the app itself sets the user's proxy environment; our own
/// requests must not loop through it unless a caller routes them explicitly.
pub fn client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    init_tls();
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds_with_the_ring_provider() {
        assert!(client_builder(Duration::from_secs(5)).build().is_ok());
    }
}
