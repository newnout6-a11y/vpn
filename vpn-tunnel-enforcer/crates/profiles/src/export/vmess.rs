//! VMess share link in the v2rayN form: `vmess://` + base64 of a JSON object. Most clients
//! read only this form; it has no fields for ECH, certificate pins or WebSocket early data, so
//! such profiles are shared as JSON instead.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};

use super::link::{csv, server};
use crate::common::fields::XHTTP_MODES;
use crate::model::{Kind, Profile, Tls, Transport};

type Object = Map<String, Value>;

pub(super) fn link(p: &Profile) -> Option<String> {
    let Kind::Vmess {
        uuid,
        security,
        global_padding,
        authenticated_length,
    } = &p.kind
    else {
        return None;
    };
    if *global_padding || *authenticated_length {
        return None;
    }
    // Validates the address the way the importer will.
    server(&p.server, p.port)?;
    let mut o = Object::new();
    put(&mut o, "v", "2");
    put(&mut o, "ps", p.name.as_str());
    if let Some(text) = &p.description {
        put(&mut o, "serverDescription", STANDARD.encode(text));
    }
    put(&mut o, "add", p.server.to_string());
    put(&mut o, "port", p.port);
    put(&mut o, "id", exact(uuid)?);
    // alterId is always 0 in the model (AEAD); a provider value was normalised on import.
    put(&mut o, "aid", 0);
    put(&mut o, "scy", exact(security)?);
    transport(&mut o, p.transport.as_ref())?;
    tls(&mut o, p.tls.as_ref())?;
    // The importer reads `host` as the SNI when `sni` is absent.
    if p.tls.as_ref().is_some_and(|t| t.server_name.is_none()) && o.contains_key("host") {
        return None;
    }
    Some(format!(
        "vmess://{}",
        STANDARD.encode(Value::Object(o).to_string())
    ))
}

fn put(o: &mut Object, key: &str, value: impl Into<Value>) {
    o.insert(key.to_owned(), value.into());
}

/// A JSON text field the importer reads back unchanged: it trims values and drops empty ones.
fn exact(text: &str) -> Option<&str> {
    (!text.is_empty() && text.trim() == text).then_some(text)
}

/// A path with the leading `/` the importer would add.
fn path(o: &mut Object, path: &str) -> Option<()> {
    put(o, "path", exact(path).filter(|p| p.starts_with('/'))?);
    Some(())
}

fn transport(o: &mut Object, transport: Option<&Transport>) -> Option<()> {
    let (net, header) = match transport {
        None => ("tcp", "none"),
        Some(Transport::Ws {
            path: p,
            host,
            max_early_data,
            early_data_header,
        }) => {
            if max_early_data.is_some() || early_data_header.is_some() {
                return None;
            }
            if let Some(host) = host {
                put(o, "host", exact(host)?);
            }
            path(o, p)?;
            ("ws", "none")
        }
        Some(Transport::Grpc {
            service_name,
            multi_mode,
        }) => {
            // v2rayN keeps the gRPC service name in `path`.
            if !service_name.is_empty() {
                put(o, "path", exact(service_name)?);
            }
            if let Some(multi) = multi_mode {
                put(o, "mode", if *multi { "multi" } else { "gun" });
            }
            ("grpc", "none")
        }
        Some(Transport::Http { hosts, path: p }) => {
            if !hosts.is_empty() {
                put(o, "host", csv(hosts)?);
            }
            path(o, p)?;
            ("h2", "none")
        }
        Some(Transport::HttpUpgrade { host, path: p }) => {
            if !host.is_empty() {
                put(o, "host", exact(host)?);
            }
            path(o, p)?;
            ("httpupgrade", "none")
        }
        Some(Transport::Quic) => return None,
        Some(Transport::Xhttp {
            host,
            path: p,
            mode,
            extra,
        }) => {
            if !host.is_empty() {
                put(o, "host", exact(host)?);
            }
            path(o, p)?;
            if let Some(mode) = mode {
                put(
                    o,
                    "mode",
                    *XHTTP_MODES.iter().find(|m| **m == mode.as_str())?,
                );
            }
            if let Some(extra) = extra {
                put(o, "extra", Value::Object(extra.clone()));
            }
            ("xhttp", "none")
        }
        Some(Transport::TcpHttpHeader { host, path }) => {
            if !host.is_empty() {
                put(o, "host", csv(host)?);
            }
            if !path.is_empty() {
                put(o, "path", csv(path)?);
            }
            ("tcp", "http")
        }
    };
    put(o, "net", net);
    put(o, "type", header);
    Some(())
}

fn tls(o: &mut Object, tls: Option<&Tls>) -> Option<()> {
    let Some(t) = tls else {
        put(o, "tls", "");
        return Some(());
    };
    let unlinkable = t.disable_sni
        || t.ech.is_some()
        || t.cert_pin_sha256.is_some()
        || t.certificate_pem.is_some()
        || !t.spki_pin_sha256.is_empty()
        || t.min_version.is_some()
        || t.max_version.is_some();
    if unlinkable {
        return None;
    }
    put(
        o,
        "tls",
        if t.reality.is_some() {
            "reality"
        } else {
            "tls"
        },
    );
    if let Some(sni) = &t.server_name {
        put(o, "sni", exact(sni)?);
    }
    if !t.alpn.is_empty() {
        put(o, "alpn", csv(&t.alpn)?);
    }
    if let Some(fp) = &t.fingerprint {
        put(
            o,
            "fp",
            exact(fp).filter(|fp| !fp.eq_ignore_ascii_case("none"))?,
        );
    }
    if t.insecure {
        put(o, "allowInsecure", true);
    }
    // v2rayN's VMess JSON has `vcn`; it has no `pqv`, so such a REALITY key needs a link form.
    if let Some(names) = t.cert_names() {
        put(o, "vcn", names);
    }
    if let Some(reality) = &t.reality {
        if reality.mldsa65_key().is_some() {
            return None;
        }
        put(o, "pbk", exact(&reality.public_key)?);
        if !reality.short_id.is_empty() {
            put(o, "sid", exact(&reality.short_id)?);
        }
        if let Some(spx) = &reality.spider_x {
            put(o, "spx", exact(spx)?);
        }
    }
    Some(())
}
