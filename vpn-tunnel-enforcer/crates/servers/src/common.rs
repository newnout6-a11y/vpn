//! URL rules shared by the work packages: which text is a subscription URL and its canonical form
//! (the group key). One copy, so import, legacy migration, group lookup and redirects agree.
use url::Url;
use vpnte_profiles::deeplink;

/// `text` starts with `<scheme>://` and something after it (scheme in any case).
pub(crate) fn has_scheme(text: &str, scheme: &str) -> bool {
    text.len() > scheme.len() + 3
        && text.is_char_boundary(scheme.len())
        && text[..scheme.len()].eq_ignore_ascii_case(scheme)
        && text[scheme.len()..].starts_with("://")
}

/// `text` starts with `http://` or `https://` (a feed URL, not a key).
pub(crate) fn is_http_url(text: &str) -> bool {
    has_scheme(text, "http") || has_scheme(text, "https")
}

/// `text` as an `http`/`https` URL with a host (fragment dropped: it never reaches the server).
pub(crate) fn http_url(text: &str) -> Option<Url> {
    if !is_http_url(text) || text.contains(char::is_whitespace) {
        return None;
    }
    let mut url = Url::parse(text).ok()?;
    if url.host_str().is_none_or(str::is_empty) {
        return None;
    }
    url.set_fragment(None);
    Some(url)
}

/// The canonical `http(s)` URL behind `input`: the URL itself, or the one an app deep link carries
/// (`happ://add/…` plain, percent-encoded or base64, `mantaray://…`), without its fragment. The one
/// canonicaliser of import, legacy migration, group lookup and redirects (servers §3.1, S-20), so
/// the same subscription pasted in any of these forms lands in one group.
pub fn canonical_source(input: &str) -> Option<Url> {
    let input = input.trim();
    if input.is_empty() || input.contains(['\r', '\n']) {
        return None;
    }
    match deeplink::unwrap_deeplink(input) {
        Ok(Some(inner)) => http_url(inner.trim()),
        Ok(None) => http_url(input),
        Err(_) => None,
    }
}
