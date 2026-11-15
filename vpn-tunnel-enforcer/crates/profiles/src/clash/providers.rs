//! Mihomo `proxy-providers` of `type: http`: lists a Clash document points at instead of (or
//! besides) carrying them in `proxies`. Panels serve the servers that way, so the subscription
//! fetcher downloads each one like the subscription itself and merges what it finds.
use std::fmt;

use super::yaml::{self, Node};

/// Providers taken from one document.
pub const MAX_PROVIDERS: usize = 16;
/// Longest provider name kept (it is shown in the import report).
const MAX_NAME_CHARS: usize = 64;

/// One `type: http` provider. Its URL usually carries the same access token as the
/// subscription: `Debug` hides it.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpProvider {
    /// The provider's key in `proxy-providers` (control characters dropped).
    pub name: String,
    /// `http(s)` URL of the provider's list.
    pub url: String,
}

impl fmt::Debug for HttpProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProvider")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The `type: http` providers of a Clash document, in document order, without repeated URLs, at
/// most [`MAX_PROVIDERS`]. Anything else (`file`, `inline`, broken YAML) yields nothing.
pub fn http_providers(text: &str) -> Vec<HttpProvider> {
    // Cheap guard: most bodies are not Clash documents with providers.
    if !text.contains("proxy-providers") {
        return Vec::new();
    }
    let Ok(Some(Node::Map(entries))) = yaml::read_root(text, "proxy-providers") else {
        return Vec::new();
    };
    let mut out: Vec<HttpProvider> = Vec::new();
    for (name, node) in entries {
        if out.len() == MAX_PROVIDERS {
            break;
        }
        if let Some(found) = provider(&name, &node)
            && !out.iter().any(|p| p.url == found.url)
        {
            out.push(found);
        }
    }
    out
}

fn provider(name: &str, node: &Node) -> Option<HttpProvider> {
    let Node::Map(pairs) = node else {
        return None;
    };
    let field = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                Node::Scalar { text, .. } => Some(text.trim()),
                _ => None,
            })
    };
    if !field("type")?.eq_ignore_ascii_case("http") {
        return None;
    }
    let url = url::Url::parse(field("url")?).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    let name: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_CHARS)
        .collect();
    let name = name.trim();
    (!name.is_empty()).then(|| HttpProvider {
        name: name.to_owned(),
        url: url.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ru-2026 item 1: a Mihomo document whose servers live in providers (fake URLs).
    #[test]
    fn http_providers_in_document_order() {
        let doc = r#"
mixed-port: 7890
x-common: &common
  interval: 3600
  health-check: { enable: true, url: "https://www.gstatic.com/generate_204" }
proxy-providers:
  Main:
    <<: *common
    type: http
    url: "https://panel.example/sub/TOKEN?flag=clash"
    path: ./providers/main.yaml
  Local:
    type: file
    path: ./local.yaml
  Inline:
    type: inline
    payload: []
  Mirror:
    type: HTTP
    url: https://mirror.example/sub/TOKEN
  Again:
    type: http
    url: "https://panel.example/sub/TOKEN?flag=clash"
  Ftp:
    type: http
    url: ftp://files.example/list
proxies: []
"#;
        let got = http_providers(doc);
        let names: Vec<&str> = got.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["Main", "Mirror"]);
        assert_eq!(got[0].url, "https://panel.example/sub/TOKEN?flag=clash");
        assert!(!format!("{got:?}").contains("TOKEN"));
    }

    #[test]
    fn nothing_without_http_providers() {
        assert!(http_providers("proxies:\n  - {name: a, type: ss}\n").is_empty());
        assert!(http_providers("proxy-providers: [1, 2]\n").is_empty());
        assert!(http_providers("proxy-providers:\n  a: {type: http, url: [x]}\n").is_empty());
        assert!(http_providers("vless://x#proxy-providers").is_empty());
        let many: String = (0..40)
            .map(|i| format!("  p{i}:\n    type: http\n    url: https://p{i}.example/s\n"))
            .collect();
        let got = http_providers(&format!("proxy-providers:\n{many}"));
        assert_eq!(got.len(), MAX_PROVIDERS);
    }
}
