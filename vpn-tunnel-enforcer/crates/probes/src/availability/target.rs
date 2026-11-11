//! The one URL normalisation of the availability check (B-UA-1, B-UA-5, B-UA-6): the page, every
//! probe stage and the history all see the same canonical URL.
use std::sync::LazyLock;

use regex::Regex;
use url::{Host, Url};
use vpnte_base::{AppError, AppResult, Msg};

/// A link the user asked about, normalised once and used by every stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    url: Url,
    host: Host<String>,
    port: u16,
}

/// `scheme://` at the start of the input (any case), as the old app detected it.
static EXPLICIT_SCHEME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^([a-z][a-z0-9+.-]*)://").expect("static regex"));

impl ProbeTarget {
    /// Normalises user input: trimmed, `https://` added when no scheme is typed, only http(s),
    /// userinfo and fragment removed, host lowercased / IDNA-encoded by the URL parser.
    /// Idempotent: parsing [`ProbeTarget::as_str`] again yields the same target.
    pub fn parse(input: &str) -> AppResult<ProbeTarget> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(invalid());
        }
        let text = match EXPLICIT_SCHEME.captures(trimmed).and_then(|c| c.get(1)) {
            Some(scheme)
                if scheme.as_str().eq_ignore_ascii_case("http")
                    || scheme.as_str().eq_ignore_ascii_case("https") =>
            {
                trimmed.to_owned()
            }
            Some(_) => {
                return Err(AppError::validation(Msg::new(
                    "probes.availability.unsupportedScheme",
                )));
            }
            None => format!("https://{trimmed}"),
        };
        let mut url = Url::parse(&text).map_err(|_| invalid())?;
        // A URL with a host always accepts an empty userinfo.
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_fragment(None);
        let host = url.host().map(|h| h.to_owned()).ok_or_else(invalid)?;
        if let Host::Domain(name) = &host {
            // WHATWG allows hosts such as `a$b.com` that no resolver accepts: refuse them here
            // instead of reporting a misleading DNS failure later.
            vpnte_core::net::Host::parse(name).map_err(|_| invalid())?;
        }
        let port = url.port_or_known_default().ok_or_else(invalid)?;
        if port == 0 {
            return Err(invalid());
        }
        Ok(ProbeTarget { url, host, port })
    }

    /// The canonical URL every stage requests.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The canonical URL as text.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Host: a lowercase (punycode) name or an IP literal (IPv6 without brackets).
    pub fn host(&self) -> &Host<String> {
        &self.host
    }

    /// Port, the scheme's default when none was typed.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `true` for `https`.
    pub fn https(&self) -> bool {
        self.url.scheme() == "https"
    }

    /// What the history keeps: `scheme://host[:port]/path`, query and fragment dropped (B-UA-5).
    pub fn history_url(&self) -> String {
        let mut url = self.url.clone();
        url.set_query(None);
        url.into()
    }

    /// Host as text for log lines (never the path or the query).
    pub fn log_host(&self) -> String {
        self.host.to_string()
    }
}

fn invalid() -> AppError {
    AppError::validation(Msg::new("probes.availability.invalidUrl"))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use vpnte_base::ErrorKind;

    use super::*;

    fn parse(s: &str) -> ProbeTarget {
        ProbeTarget::parse(s).unwrap()
    }

    /// AT-07-004: a bare host gets `https://`, and the result is idempotent.
    #[test]
    fn bare_host_gets_https() {
        let t = parse("  youtube.com ");
        assert_eq!(t.as_str(), "https://youtube.com/");
        assert_eq!(t.port(), 443);
        assert!(t.https());
        assert_eq!(parse(t.as_str()), t);
    }

    /// AT-07-004 / B-UA-5: userinfo and fragment go, the query stays for probing only.
    #[test]
    fn userinfo_and_fragment_are_removed() {
        let t = parse("HTTPS://User:Pw@Example.COM:443/p?q=1#f");
        assert_eq!(t.as_str(), "https://example.com/p?q=1");
        assert_eq!(t.history_url(), "https://example.com/p");
        assert_eq!(t.host(), &Host::Domain("example.com".to_owned()));
        assert_eq!(parse(t.as_str()), t);
    }

    /// AT-07-004: other schemes are a validation error.
    #[test]
    fn other_schemes_are_refused() {
        for input in ["ftp://example.test", "file:///C:/x", "ws://example.test"] {
            let err = ProbeTarget::parse(input).unwrap_err();
            assert_eq!(err.kind, ErrorKind::Validation, "{input}");
            assert_eq!(err.user_msg().key, "probes.availability.unsupportedScheme");
        }
        for input in ["", "   ", "https://", "http://a$b.com/", "https://x.com:0/"] {
            let err = ProbeTarget::parse(input).unwrap_err();
            assert_eq!(
                err.user_msg().key,
                "probes.availability.invalidUrl",
                "{input}"
            );
        }
    }

    /// AT-07-004 / B-UA-6: a bracketed IPv6 literal becomes an address, not a name.
    #[test]
    fn ipv6_literal_is_an_address() {
        let t = parse("http://[::1]:8080/x");
        assert_eq!(t.host(), &Host::<String>::Ipv6(Ipv6Addr::LOCALHOST));
        assert_eq!(t.port(), 8080);
        assert!(!t.https());
        assert_eq!(t.history_url(), "http://[::1]:8080/x");
        assert_eq!(parse(t.as_str()), t);
    }

    #[test]
    fn idna_and_default_ports() {
        let t = parse("http://Пример.рф");
        assert_eq!(t.as_str(), "http://xn--e1afmkfd.xn--p1ai/");
        assert_eq!(t.port(), 80);
        assert_eq!(parse("example.com:8443/a").port(), 8443);
        assert_eq!(
            parse("https://example.com:443/").as_str(),
            "https://example.com/"
        );
    }
}
