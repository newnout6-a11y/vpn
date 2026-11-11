//! Pieces of a share link: percent-encoding, authority, name fragment, TLS and transport
//! parameters. Each writer mirrors what the `uri` importer reads back; `None` means "a link
//! cannot carry this value exactly", which turns the whole link down.
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

use crate::common::fields::{XHTTP_MODES, parse_host};
use crate::model::{Host, Tls, Transport};

/// RFC 3986 unreserved characters stay, everything else is encoded (`+` -> `%2B`, space ->
/// `%20`, `,` -> `%2C`): the importer reads `+` literally and decodes exactly once.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encodes a userinfo part, query value or fragment.
pub(super) fn pct(text: &str) -> String {
    utf8_percent_encode(text, COMPONENT).to_string()
}

/// `host:port` with IPv6 in brackets; `None` for port 0 or a name the importer reads otherwise.
pub(super) fn server(host: &Host, port: u16) -> Option<String> {
    let readable = match host {
        Host::Ip(_) => true,
        Host::Domain(name) => parse_host(name).as_ref() == Some(host),
    };
    (readable && port != 0).then(|| match host {
        Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
        _ => format!("{host}:{port}"),
    })
}

/// `#<name>`, with Happ's `?serverDescription=<base64>` suffix when the profile has a description.
pub(super) fn fragment(name: &str, description: Option<&str>) -> String {
    match description {
        Some(text) => format!(
            "#{}",
            pct(&format!(
                "{name}?serverDescription={}",
                STANDARD.encode(text)
            ))
        ),
        None => format!("#{}", pct(name)),
    }
}

/// Query parameters in writing order. No `Debug`: values are credentials.
#[derive(Default)]
pub(super) struct Query(Vec<(&'static str, String)>);

impl Query {
    pub(super) fn set(&mut self, key: &'static str, value: impl Into<String>) {
        self.0.push((key, value.into()));
    }

    /// Writes a present value; `Some("")` cannot be written (the importer skips empty values).
    pub(super) fn opt(&mut self, key: &'static str, value: Option<&str>) -> Option<()> {
        match value {
            None => {}
            Some("") => return None,
            Some(value) => self.set(key, value),
        }
        Some(())
    }

    /// Writes a value unless it is empty (the importer's default for an absent parameter).
    pub(super) fn text(&mut self, key: &'static str, value: &str) {
        if !value.is_empty() {
            self.set(key, value);
        }
    }

    pub(super) fn flag(&mut self, key: &'static str, on: bool) {
        if on {
            self.set(key, "1");
        }
    }

    /// A positive number (the importer reads zero as absent); `Some(0)` cannot be written.
    pub(super) fn positive(
        &mut self,
        key: &'static str,
        value: Option<u32>,
        unit: &str,
    ) -> Option<()> {
        match value {
            None => {}
            Some(0) => return None,
            Some(n) => self.set(key, format!("{n}{unit}")),
        }
        Some(())
    }

    /// A comma-separated list the importer splits back into the same items.
    pub(super) fn list(&mut self, key: &'static str, items: &[String]) -> Option<()> {
        if items.is_empty() {
            return Some(());
        }
        csv(items).map(|joined| self.set(key, joined))
    }

    fn has(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| *k == key)
    }

    /// `?k=v&…`, or nothing when there are no parameters.
    pub(super) fn render(&self) -> String {
        let pairs: Vec<String> = self
            .0
            .iter()
            .map(|(k, v)| format!("{k}={}", pct(v)))
            .collect();
        if pairs.is_empty() {
            String::new()
        } else {
            format!("?{}", pairs.join("&"))
        }
    }
}

/// Items joined with `,`; `None` when an item is empty, has outer spaces or a comma (the
/// importer trims items and drops empty ones).
pub(super) fn csv(items: &[String]) -> Option<String> {
    let exact = items
        .iter()
        .all(|i| !i.is_empty() && !i.contains(',') && i.trim() == i);
    exact.then(|| items.join(","))
}

/// How the importer of a scheme treats TLS (mirrors `uri::stream::TlsMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TlsMode {
    /// Off unless `security=tls|reality` (VLESS).
    Optional,
    /// On unless `security=none` (Trojan).
    DefaultOn,
    /// Always on, REALITY possible (AnyTLS).
    Always,
    /// Always on, never REALITY (Hysteria2, TUIC, Naive, HTTPS proxy).
    AlwaysNoReality,
}

/// TLS parameters, then the transport. A transport `host` doubles as the SNI on re-import, so
/// a TLS profile without its own SNI cannot carry one.
pub(super) fn stream(
    q: &mut Query,
    tls: Option<&Tls>,
    transport: Option<&Transport>,
    mode: TlsMode,
    insecure_key: &'static str,
) -> Option<()> {
    tls_params(q, tls, mode, insecure_key)?;
    transport_params(q, transport)?;
    let host_as_sni = tls.is_some_and(|t| t.server_name.is_none()) && q.has("host");
    (!host_as_sni).then_some(())
}

/// `security` and the TLS parameters; `insecure_key` is the name the scheme's clients use.
fn tls_params(
    q: &mut Query,
    tls: Option<&Tls>,
    mode: TlsMode,
    insecure_key: &'static str,
) -> Option<()> {
    let Some(t) = tls else {
        return match mode {
            TlsMode::Optional => Some(()),
            // Written explicitly: without it the importer turns TLS on (the old exporter's P-37).
            TlsMode::DefaultOn => {
                q.set("security", "none");
                Some(())
            }
            // These protocols always run over TLS: the importer cannot read "no TLS".
            TlsMode::Always | TlsMode::AlwaysNoReality => None,
        };
    };
    // Certificates, SPKI pins and version bounds have no share-link parameter.
    let unlinkable = t.certificate_pem.is_some()
        || !t.spki_pin_sha256.is_empty()
        || t.min_version.is_some()
        || t.max_version.is_some()
        || t.fingerprint
            .as_deref()
            .is_some_and(|fp| fp.eq_ignore_ascii_case("none"));
    if unlinkable {
        return None;
    }
    match (&t.reality, mode) {
        (Some(_), TlsMode::AlwaysNoReality) => return None,
        (Some(_), _) => q.set("security", "reality"),
        (None, TlsMode::AlwaysNoReality) => {}
        (None, _) => q.set("security", "tls"),
    }
    q.opt("sni", t.server_name.as_deref())?;
    q.flag("disable_sni", t.disable_sni);
    q.list("alpn", &t.alpn)?;
    q.flag(insecure_key, t.insecure);
    q.opt("fp", t.fingerprint.as_deref())?;
    if let Some(reality) = &t.reality {
        q.opt("pbk", Some(&reality.public_key))?;
        q.text("sid", &reality.short_id);
        q.opt("spx", reality.spider_x.as_deref())?;
    }
    if let Some(ech) = &t.ech {
        q.set("ech", "1");
        q.list("echConfig", &ech.config_lines)?;
        q.opt("echQueryServerName", ech.query_server_name.as_deref())?;
    }
    if let Some(pin) = &t.cert_pin_sha256 {
        // The importer accepts 64 hex digits and stores them in lower case.
        let canonical =
            pin.len() == 64 && pin.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !canonical {
            return None;
        }
        q.set("pinSHA256", pin.as_str());
    }
    Some(())
}

/// `type` and the transport parameters; nothing for plain TCP.
fn transport_params(q: &mut Query, transport: Option<&Transport>) -> Option<()> {
    let Some(transport) = transport else {
        return Some(());
    };
    match transport {
        Transport::Ws {
            path,
            host,
            max_early_data,
            early_data_header,
        } => {
            q.set("type", "ws");
            q.opt("host", host.as_deref())?;
            path_param(q, path)?;
            q.positive("ed", *max_early_data, "")?;
            q.opt("eh", early_data_header.as_deref())?;
        }
        Transport::Grpc {
            service_name,
            multi_mode,
        } => {
            q.set("type", "grpc");
            q.text("serviceName", service_name);
            if let Some(multi) = multi_mode {
                q.set("mode", if *multi { "multi" } else { "gun" });
            }
        }
        Transport::Http { hosts, path } => {
            q.set("type", "http");
            q.list("host", hosts)?;
            path_param(q, path)?;
        }
        Transport::HttpUpgrade { host, path } => {
            q.set("type", "httpupgrade");
            q.text("host", host);
            path_param(q, path)?;
        }
        // The importer refuses `type=quic`: no engine runs QUIC transport from a link.
        Transport::Quic => return None,
        Transport::Xhttp {
            host,
            path,
            mode,
            extra,
        } => {
            q.set("type", "xhttp");
            q.text("host", host);
            path_param(q, path)?;
            match mode.as_deref() {
                None => {}
                Some(mode) if XHTTP_MODES.contains(&mode) => q.set("mode", mode),
                Some(_) => return None,
            }
            if let Some(extra) = extra {
                q.set("extra", Value::Object(extra.clone()).to_string());
            }
        }
        Transport::TcpHttpHeader { host, path } => {
            q.set("type", "tcp");
            q.set("headerType", "http");
            q.list("host", host)?;
            q.list("path", path)?;
        }
    }
    Some(())
}

/// The importer gives every path a leading `/` and reads an absent path as `/`.
pub(super) fn path_param(q: &mut Query, path: &str) -> Option<()> {
    if !path.starts_with('/') {
        return None;
    }
    if path != "/" {
        q.set("path", path);
    }
    Some(())
}
