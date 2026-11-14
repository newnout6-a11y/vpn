//! Review live2-b3: a start whose exit proof got nothing back cannot tell a dead server from a
//! dead network (a captive portal, an outage, Wi-Fi still joining after a resume). The same echo
//! services the proof asks, asked straight from this process (no system proxy, never through a
//! tunnel), tell the two apart.
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::select_ok;

/// The echo services of the runtime's exit proof (`tunnel::runtime::engines::ECHO_URLS`).
const ECHO_URLS: [&str; 2] = ["https://api.ipify.org", "https://ifconfig.me/ip"];
/// Long enough for a slow but working line; a dead one gets no answer at all.
const BUDGET: Duration = Duration::from_secs(6);

/// Whether this PC reaches the internet without our tunnel.
#[async_trait]
pub trait DirectCheck: Send + Sync {
    /// `true` when an echo service answered (any HTTP answer: the line carries traffic).
    async fn online(&self) -> bool;
}

/// Both echo services at once, straight.
pub struct EchoDirect;

#[async_trait]
impl DirectCheck for EchoDirect {
    async fn online(&self) -> bool {
        let Ok(client) =
            vpnte_base::http::offline(vpnte_base::http::client_builder(BUDGET)).build()
        else {
            return false;
        };
        let asks = ECHO_URLS.map(|url| Box::pin(client.get(url).send()));
        let answered = select_ok(asks).await.is_ok();
        tracing::info!(answered, "direct echo after a silent exit proof");
        answered
    }
}
