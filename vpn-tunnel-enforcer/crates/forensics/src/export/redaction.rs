//! Redaction policies of one archive, on top of the app's one policy (`vpnte_core::redact`).
//!
//! - `Config` (settings, engine configs): secret keys (incl. `server`, `address`, `id`) masked,
//!   free-text secrets masked.
//! - `Data` (snapshots, system diagnostics, recovery state, system info): only secret-named keys
//!   and secret-shaped text; addresses stay, support needs them (B-19).
//! - `Log`: what the logger already applies (secrets, public IPs as pseudonyms).
//! - `Forensics`: `Log` plus per-archive host pseudonyms (`<subK>.<domain-N>.<public suffix>`), so
//!   the DNS → flow → reset chain stays readable without the names (FR, §3.8).
//!
//! Every policy also masks the Windows user name: `\Users\<name>` segments in any path form (NT
//! device paths included, B-18) and the literal current user name.
use std::collections::HashMap;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::Value;
use vpnte_core::redact::{self, REDACTED};

/// How a piece of the archive is redacted (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Policy {
    Config,
    Data,
    Log,
    Forensics,
}

fn re(pattern: &str) -> Regex {
    // Constant patterns, exercised by the tests.
    Regex::new(pattern).expect("export redaction pattern compiles")
}

/// Host names, ASCII or Unicode (FR:72 was ASCII-only, B-18); the TLD is letters only.
static HOST: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\b(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+\p{L}{2,24}\b")
});
/// File names that look like hosts (FR:88 without `md`: `.md` is Moldova's ccTLD).
static NOT_A_HOST: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\.(?:json|ndjson|jsonl|txt|xml|etl|pcapng|log|exe|dll|sys|ps1|tmp|manifest|csv|xsd|zip)$",
    )
});
/// A path segment under a profile folder, whatever the path form (`\Device\HarddiskVolume3\Users\x`,
/// UNC, JSON-escaped): the segment is the user name.
static USERS_SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?i)([\\/]+(?:users|documents and settings)[\\/]+)([^\\/\r\n"'<>]+)"#));
const HOST_ALLOWLIST: [&str; 2] = ["localhost", "localhost.localdomain"];
/// Replacement for a user name.
pub(super) const USER: &str = "<user>";

/// One redactor per archive: host tokens are stable across all its files and live only in
/// memory (never shared between exports).
pub(super) struct Redactor {
    hosts: HashMap<String, u32>,
    user: Option<Regex>,
}

impl Redactor {
    /// `user`: the current Windows user name (masked literally when it has at least 3 chars).
    pub(super) fn new(user: Option<&str>) -> Self {
        let user = user
            .map(str::trim)
            .filter(|u| u.chars().count() >= 3)
            .map(|u| {
                let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
                let lead = if word(u.chars().next()) { r"\b" } else { "" };
                let tail = if word(u.chars().next_back()) {
                    r"\b"
                } else {
                    ""
                };
                re(&format!("(?i){lead}{}{tail}", regex::escape(u)))
            });
        Self {
            hosts: HashMap::new(),
            user,
        }
    }

    /// Distinct host names replaced so far.
    pub(super) fn hosts_replaced(&self) -> usize {
        self.hosts.len()
    }

    /// Redacts free text.
    pub(super) fn text(&mut self, s: &str, policy: Policy) -> String {
        let base = match policy {
            Policy::Config | Policy::Data => redact::text(s),
            Policy::Log | Policy::Forensics => redact::for_log(s),
        };
        let mut out = base.into_owned();
        // The literal name first: a segment pass that already wrote `<user>` would otherwise be
        // matched again for an account literally named "user".
        if let Some(user) = &self.user {
            out = user.replace_all(&out, USER).into_owned();
        }
        out = USERS_SEGMENT
            .replace_all(&out, |c: &Captures| format!("{}{USER}", &c[1]))
            .into_owned();
        if policy == Policy::Forensics {
            out = self.hosts_in(&out);
        }
        out
    }

    /// Redacts a JSON document in place: keys are never changed; values under secret keys become
    /// `<redacted>` (the full key rule for `Config`, secret-named keys otherwise).
    pub(super) fn json(&mut self, v: &mut Value, policy: Policy) {
        match v {
            Value::String(s) => {
                let r = self.text(s, policy);
                if r != *s {
                    *s = r;
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|x| self.json(x, policy)),
            Value::Object(map) => {
                for (key, value) in map.iter_mut() {
                    let secret = match policy {
                        Policy::Config => redact::is_secret_key(key),
                        _ => redact::is_secret_field(key),
                    };
                    if secret {
                        *value = Value::String(REDACTED.to_owned());
                    } else {
                        self.json(value, policy);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// One NDJSON line: JSON is walked and re-serialized compactly, anything else (a truncated
    /// last line too) is redacted as text, never passed through (FR:245-249).
    pub(super) fn ndjson_line(&mut self, line: &str, policy: Policy) -> String {
        match serde_json::from_str::<Value>(line) {
            Ok(mut v) if v.is_object() || v.is_array() => {
                self.json(&mut v, policy);
                serde_json::to_string(&v).unwrap_or_else(|_| self.text(line, policy))
            }
            _ => self.text(line, policy),
        }
    }

    fn hosts_in(&mut self, s: &str) -> String {
        HOST.replace_all(s, |c: &Captures| {
            let host = &c[0];
            if NOT_A_HOST.is_match(host) || HOST_ALLOWLIST.contains(&host.to_lowercase().as_str()) {
                host.to_string()
            } else {
                self.pseudonym(host)
            }
        })
        .into_owned()
    }
}

impl Redactor {
    /// `<subK>.<domain-N>.<public suffix as written>`; `<host-N>` when the host is itself a public
    /// suffix (`co.uk`) or not a valid name. Tokens are keyed by the registrable domain, so
    /// `a.example.com` and `b.example.com` share `<domain-N>` (FR:177-197).
    fn pseudonym(&mut self, host: &str) -> String {
        let labels: Vec<&str> = host.split('.').collect();
        let ascii = match url::Host::parse(host) {
            Ok(url::Host::Domain(d)) if d.split('.').count() == labels.len() => Some(d),
            _ => None,
        };
        let suffix_labels = ascii.as_deref().and_then(icann_suffix_labels);
        match (ascii, suffix_labels) {
            (Some(ascii), Some(n)) if n < labels.len() => {
                let skip = ascii.split('.').count() - n - 1;
                let key = ascii.split('.').skip(skip).collect::<Vec<_>>().join(".");
                let id = self.token(key);
                let suffix = labels[labels.len() - n..].join(".");
                if skip == 0 {
                    format!("<domain-{id}>.{suffix}")
                } else {
                    format!("<sub{skip}>.<domain-{id}>.{suffix}")
                }
            }
            (ascii, _) => {
                let key = ascii.unwrap_or_else(|| host.to_lowercase());
                format!("<host-{}>", self.token(key))
            }
        }
    }

    fn token(&mut self, key: String) -> u32 {
        let next = self.hosts.len() as u32 + 1;
        *self.hosts.entry(key).or_insert(next)
    }
}

/// Labels of the ICANN public suffix of an ASCII host. The old redactor used tldts with
/// `allowPrivateDomains: false`; `psl` also matches private rules (`s3.amazonaws.com` would be a
/// suffix), so a private match is discarded and the rest of the name looked up again. An unknown
/// TLD is a one-label suffix (the PSL default `*` rule): `printer.corp` → suffix `corp`.
fn icann_suffix_labels(host: &str) -> Option<usize> {
    let mut name = host;
    loop {
        let suffix = psl::suffix(name.as_bytes())?;
        let text = name.get(name.len().checked_sub(suffix.as_bytes().len())?..)?;
        match suffix.typ() {
            Some(psl::Type::Private) => name = text.split_once('.')?.1,
            _ => return Some(text.split('.').count()),
        }
    }
}
