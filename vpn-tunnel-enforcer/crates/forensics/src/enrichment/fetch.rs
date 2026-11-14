//! One vetted lookup: every hop's host must resolve to public addresses only, the direct route is
//! pinned to them (F-177), at most four redirects, only an HTML 2xx answer is scanned.
use std::net::{IpAddr, SocketAddr};

use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION, USER_AGENT};
use url::Url;
use vpnte_base::AppError;
use vpnte_core::net::{self, Route};
use vpnte_core::resolve::{self, How};

use super::page::{PageMeta, scan_head};
use super::{LOOKUP_TIMEOUT, allowed_url};

const MAX_REDIRECTS: usize = 4;
/// The head of a page is at its start; the rest is never read.
const MAX_BODY: usize = 512 * 1024;
const UA: &str = "VPN Tunnel Enforcer Domain Intelligence/1.0";

/// Why a lookup gave no metadata (logged at debug; the entry becomes `unavailable`).
#[derive(Debug, thiserror::Error)]
pub(super) enum LookupError {
    #[error("URL or host refused")]
    Refused,
    #[error("the name has no addresses, or one of them is not public")]
    NotPublic,
    #[error("HTTP client setup failed")]
    Client(#[source] AppError),
    #[error("request failed")]
    Http(#[source] reqwest::Error),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("not an HTML page")]
    NotHtml,
    #[error("more than {MAX_REDIRECTS} redirects")]
    Redirects,
}

/// Resolves `host` and returns its addresses when every one of them is public (a single private
/// answer refuses the name: rebinding guard).
pub(super) async fn vetted(host: &str) -> Result<Vec<IpAddr>, LookupError> {
    let ips = resolve::resolve_host(host, How::System, |_| true)
        .await
        .map_err(|_| LookupError::NotPublic)?;
    if !all_public(&ips) {
        return Err(LookupError::NotPublic);
    }
    Ok(ips)
}

/// The safe-domain rule: at least one address and every address public.
pub(super) fn all_public(ips: &[IpAddr]) -> bool {
    !ips.is_empty() && ips.iter().all(|ip| net::is_public_ip(*ip))
}

/// Loads the main document of `https://<domain>/`, following at most four redirects, each hop
/// re-checked, and scans its head.
pub(super) async fn inspect(domain: &str, route: &Route) -> Result<(PageMeta, Url), LookupError> {
    let mut url = Url::parse(&format!("https://{domain}/")).map_err(|_| LookupError::Refused)?;
    for _ in 0..=MAX_REDIRECTS {
        if !allowed_url(&url) {
            return Err(LookupError::Refused);
        }
        let host = url.host_str().ok_or(LookupError::Refused)?.to_owned();
        let ips = vetted(&host).await?;
        let mut builder = net::builder_for(route, LOOKUP_TIMEOUT).map_err(LookupError::Client)?;
        if *route == Route::Direct {
            let pinned: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, 443)).collect();
            builder = builder.resolve_to_addrs(&host, &pinned);
        }
        let client = builder.build().map_err(LookupError::Http)?;
        let mut resp = client
            .get(url.clone())
            .header(USER_AGENT, UA)
            .header(ACCEPT, "text/html,application/xhtml+xml;q=0.9")
            .send()
            .await
            .map_err(LookupError::Http)?;
        let status = resp.status();
        if status.is_redirection() {
            url = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|location| url.join(location).ok())
                .ok_or(LookupError::Refused)?;
            continue;
        }
        if !status.is_success() {
            return Err(LookupError::Status(status.as_u16()));
        }
        let html = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase)
            .is_some_and(|t| t.starts_with("text/html") || t.starts_with("application/xhtml+xml"));
        if !html {
            return Err(LookupError::NotHtml);
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(LookupError::Http)? {
            let room = MAX_BODY - body.len();
            body.extend_from_slice(&chunk[..chunk.len().min(room)]);
            if body.len() >= MAX_BODY {
                break;
            }
        }
        return Ok((scan_head(&String::from_utf8_lossy(&body), &url), url));
    }
    Err(LookupError::Redirects)
}
