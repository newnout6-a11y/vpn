//! Remote-profile links of other clients, each carrying one subscription URL:
//! `sing-box://import-remote-profile?url=<encoded>#<name>` (sing-box docs, "Import remote
//! profile"), `clash://install-config?url=<encoded>&name=<name>` (Clash for Windows / Verge) and
//! `hiddify://import/<url>#<name>` plus its older `install-config` / `install-sub` forms with a
//! `url` parameter (hiddify-app `LinkParser.deep`). The name is dropped: the provider's
//! `profile-title` names the group, and a name chosen by whoever sent the link must not win.
use super::{DeepLinkError, Hosts, add_payload, pct_decode, shown_host, starts_http, target};

/// A client whose links hand over a remote profile.
struct RemoteApp {
    scheme: &'static str,
    /// Hosts whose `url` query parameter is the subscription URL.
    url_hosts: &'static [&'static str],
    /// Host whose path is the payload, as an add link's (`hiddify://import/<url>`).
    path_host: Option<&'static str>,
}

const REMOTE: [RemoteApp; 3] = [
    RemoteApp {
        scheme: "sing-box",
        url_hosts: &["import-remote-profile"],
        path_host: None,
    },
    RemoteApp {
        scheme: "clash",
        url_hosts: &["install-config"],
        path_host: None,
    },
    RemoteApp {
        scheme: "hiddify",
        url_hosts: &["install-config", "install-sub"],
        path_host: Some("import"),
    },
];

/// `None` when `scheme` is not a remote-profile client; otherwise what its link carries.
/// `after` is the text after `scheme://`.
pub(super) fn unwrap(
    scheme: &str,
    after: &str,
    hosts: Hosts,
) -> Option<Result<String, DeepLinkError>> {
    let app = REMOTE
        .iter()
        .find(|a| scheme.eq_ignore_ascii_case(a.scheme))?;
    // The outer link's fragment is the profile name, never part of the carried URL.
    let link = after.split_once('#').map_or(after, |(link, _)| link);
    let end = link.find(['/', '?']).unwrap_or(link.len());
    let (host, tail) = link.split_at(end);
    let host = host.to_ascii_lowercase();
    if app.path_host == Some(host.as_str()) {
        let path = tail.strip_prefix('/').unwrap_or(tail);
        // Hiddify itself prefers a `url` parameter over the path.
        if let Some(url) = query_url(path) {
            return Some(http_target(&url, hosts));
        }
        return Some(add_payload(path, hosts));
    }
    if app.url_hosts.contains(&host.as_str()) {
        let target = query_url(tail).ok_or(DeepLinkError::AddPayloadUnrecognised);
        return Some(target.and_then(|url| http_target(&url, hosts)));
    }
    Some(Err(DeepLinkError::UnknownHost(format!(
        "{}://{}",
        app.scheme,
        shown_host(&host)
    ))))
}

/// The percent-decoded `url` parameter of the query in `tail` (`…?a=b&url=…`). `+` stays `+`:
/// a URL never holds a raw space, and unencoded subscription tokens do carry `+`.
fn query_url(tail: &str) -> Option<String> {
    let (_, query) = tail.split_once('?')?;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("url="))
        .map(|value| pct_decode(value).trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// A remote profile is fetched: only an http(s) URL qualifies (of an internet host, unless the
/// caller judges the host itself).
fn http_target(url: &str, hosts: Hosts) -> Result<String, DeepLinkError> {
    if starts_http(url) {
        target::carried_url(url, hosts)
    } else {
        Err(DeepLinkError::AddPayloadUnrecognised)
    }
}
