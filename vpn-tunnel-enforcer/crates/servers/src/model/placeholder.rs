//! Provider placeholders: entries a panel puts into a subscription instead of servers («Приложение
//! не поддерживается», "Update the app", an expired plan's notes). Remnawave serves them as fake
//! hosts at `0.0.0.0:1` to a client it refuses (13.11.2026: such an answer replaced the owner's 14
//! servers). A placeholder is never stored, selected, checked or connected (p-live-fix).
use std::net::IpAddr;

use vpnte_profiles::model::Profile;

use super::{Origin, ServerRow};

/// Name fragments (lower case) a panel uses to refuse the client.
const REFUSAL_WORDS: [&str; 5] = [
    "не поддерживается",
    "обновите приложение",
    "not supported",
    "unsupported",
    "update the app",
];

/// How much of the provider's text a group keeps: three names, one line.
const SAID_NAMES: usize = 3;
const SAID_MAX_CHARS: usize = 160;

/// An entry that points nowhere (`0.0.0.0`, `::`, loopback, no address, port 0 or 1) or whose
/// name tells the client it is refused or must be updated.
pub fn is_placeholder(name: &str, host: &str, port: u16) -> bool {
    port <= 1 || points_nowhere(host) || refuses(name)
}

/// [`is_placeholder`] of a parsed profile.
pub fn is_placeholder_profile(profile: &Profile) -> bool {
    is_placeholder(&profile.name, &profile.server.to_string(), profile.port)
}

impl ServerRow {
    /// A provider placeholder stored by an older build: a feed row that is no server. The user's
    /// own keys are never judged (a local proxy on 127.0.0.1 is a real key there).
    pub fn is_placeholder(&self) -> bool {
        self.origin == Origin::Feed && is_placeholder(&self.name, &self.server, self.port)
    }
}

fn points_nowhere(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_unspecified() || ip.is_loopback(),
        Err(_) => host.is_empty(),
    }
}

fn refuses(name: &str) -> bool {
    let name = name.to_lowercase();
    REFUSAL_WORDS.iter().any(|w| name.contains(w))
}

/// The provider's words in `names` (the placeholders' names): the distinct non-empty ones, at
/// most three, joined into one line of at most 160 characters. `None` when they say nothing.
pub fn provider_words<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut picked: Vec<String> = Vec::new();
    for name in names {
        let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
        if !name.is_empty() && !picked.contains(&name) {
            picked.push(name);
        }
        if picked.len() == SAID_NAMES {
            break;
        }
    }
    let line = picked.join(" · ");
    let mut chars = line.chars();
    let cut: String = chars.by_ref().take(SAID_MAX_CHARS).collect();
    match (cut.is_empty(), chars.next().is_some()) {
        (true, _) => None,
        (false, true) => Some(format!("{}…", cut.trim_end())),
        (false, false) => Some(cut),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// p-live-fix 1a: what the owner's panel sent, and the other shapes panels use.
    #[test]
    fn placeholders_are_told_apart_from_servers() {
        assert!(is_placeholder("Приложение не поддерживается", "0.0.0.0", 1));
        for host in [
            "0.0.0.0",
            "::",
            "[::]",
            "127.0.0.1",
            "127.8.9.10",
            "::1",
            "",
            " ",
        ] {
            assert!(is_placeholder("DE 1", host, 443), "{host:?}");
        }
        assert!(is_placeholder("DE 1", "de1.example.com", 0));
        assert!(is_placeholder("DE 1", "de1.example.com", 1));
        for name in [
            "⚠️ Приложение не поддерживается",
            "Обновите приложение до последней версии",
            "App not supported",
            "Unsupported client",
            "Please update the app",
        ] {
            assert!(is_placeholder(name, "203.0.113.7", 443), "{name}");
        }
        for (name, host, port) in [
            ("DE 1", "de1.example.com", 443),
            ("NL", "203.0.113.7", 8443),
            ("US", "2001:db8::7", 2),
            ("Поддержка 24/7", "198.51.100.1", 443),
        ] {
            assert!(!is_placeholder(name, host, port), "{name}");
        }
    }

    #[test]
    fn the_provider_words_fit_one_line() {
        assert_eq!(
            provider_words(["Приложение не поддерживается"]).as_deref(),
            Some("Приложение не поддерживается")
        );
        assert_eq!(
            provider_words(["  A  b ", "A b", "", "C", "D", "E"]).as_deref(),
            Some("A b · C · D")
        );
        assert_eq!(provider_words(["", "  "]), None);
        let long = "я".repeat(200);
        let said = provider_words([long.as_str()]).unwrap();
        assert_eq!(said.chars().count(), SAID_MAX_CHARS + 1);
        assert!(said.ends_with('…'));
    }
}
