//! A list of outbound-like objects -> profiles: a provider Xray document (one profile), else the
//! sing-box outbounds, else the Xray outbounds.
use serde_json::{Map, Value};

use super::scan::Origin;
use super::singbox::{self, Input, SUPPORTED};
use super::values::text;
use super::xray::{self, Doc};
use super::{EXCERPT_CHARS, Out};
use crate::common::fields::{clean_name, display_name};
use crate::model::SkipReason;

/// Tags that say nothing about the server; the document's remarks name the profile instead.
const GENERIC_TAGS: &[&str] = &[
    "proxy",
    "proxy-out",
    "node",
    "server",
    "default",
    "sing-box",
];

/// Imports `cands`; `ctx` is the document they came from (for Xray provider graphs).
pub(super) fn candidates(
    cands: &[&Value],
    remarks: Option<&str>,
    ctx: Option<&Value>,
    out: &mut Out,
) -> bool {
    let before = out.len();
    if let Some(doc) = ctx
        && provider_document(doc, remarks, out)
    {
        return true;
    }
    let typed: Vec<(&Map<String, Value>, &'static str)> = cands
        .iter()
        .filter_map(|c| c.as_object())
        .filter_map(|o| singbox_type(o).map(|t| (o, t)))
        .collect();
    if !typed.is_empty() {
        singbox_list(&typed, remarks, out);
        if out.len() > before {
            return true;
        }
    }
    for o in cands.iter().filter_map(|c| c.as_object()) {
        if !o.get("settings").is_some_and(Value::is_object) {
            continue;
        }
        if xray::protocol(o).is_none() {
            // A proxy protocol this app does not import gets a reason instead of vanishing.
            if let Some(name) = xray::unknown_proxy(o) {
                out.push(Err(SkipReason::UnknownScheme(name)), || excerpt(o));
            }
            continue;
        }
        let name = xray_name(o, remarks);
        for result in xray::profiles(
            o,
            &name,
            Doc {
                value: ctx,
                entry: None,
            },
        ) {
            out.push(result, || excerpt(o));
        }
    }
    out.len() > before
}

/// The supported sing-box type of `o`, if it looks like a client outbound (inbounds carry
/// `listen` / `users`; objects without an address are header or rule fragments).
fn singbox_type(o: &Map<String, Value>) -> Option<&'static str> {
    let kind = text(o, &["type"])?.trim().to_ascii_lowercase();
    let kind = *SUPPORTED.iter().find(|s| **s == kind)?;
    let inbound = o.contains_key("listen") || o.get("users").is_some_and(Value::is_array);
    let addressed = o.contains_key("server") || (kind == "wireguard" && o.contains_key("peers"));
    let chained_ss = kind == "shadowsocks" && o.contains_key("detour");
    (!inbound && (addressed || chained_ss)).then_some(kind)
}

/// sing-box outbounds of one list; a Shadowsocks outbound whose `detour` names a ShadowTLS
/// outbound of the same list becomes one chained profile.
fn singbox_list(
    typed: &[(&Map<String, Value>, &'static str)],
    remarks: Option<&str>,
    out: &mut Out,
) {
    let layers: Vec<(&str, &Map<String, Value>)> = typed
        .iter()
        .filter(|(_, t)| *t == "shadowtls")
        .filter_map(|(o, _)| Some((text(o, &["tag"])?, *o)))
        .collect();
    let mut used = Vec::new();
    for (o, kind) in typed.iter().filter(|(_, t)| *t != "shadowtls") {
        let layer = text(o, &["detour"]).and_then(|d| layers.iter().find(|(tag, _)| *tag == d));
        if let Some((tag, _)) = layer {
            used.push(*tag);
            if *kind != "shadowsocks" {
                let reason = SkipReason::Invalid {
                    scheme: (*kind).to_owned(),
                    detail: "only Shadowsocks can run over ShadowTLS".into(),
                };
                out.push(Err(reason), || excerpt(o));
                continue;
            }
        }
        let name = outbound_name(o, kind, remarks, layer.map(|(_, l)| *l));
        let input = Input {
            obj: o,
            kind,
            name,
            origin: Origin::Json,
            shadowtls: layer.map(|(_, l)| *l),
        };
        out.push(singbox::import(input), || excerpt(o));
    }
    for (o, _) in typed.iter().filter(|(_, t)| *t == "shadowtls") {
        if !text(o, &["tag"]).is_some_and(|tag| used.contains(&tag)) {
            out.push(Err(SkipReason::ShadowTlsNeedsInner), || excerpt(o));
        }
    }
}

/// `remarks|ps|name`, else the tag unless it is generic, else the document remarks, else the
/// protocol's display name.
fn outbound_name(
    o: &Map<String, Value>,
    kind: &str,
    remarks: Option<&str>,
    layer: Option<&Map<String, Value>>,
) -> String {
    let tag = text(o, &["tag"]).or_else(|| layer.and_then(|l| text(l, &["tag"])));
    let own = text(o, &["remarks", "ps", "name"]);
    let chosen = own.or_else(|| {
        if is_generic(tag, o, kind) {
            remarks.or(tag)
        } else {
            tag.or(remarks)
        }
    });
    chosen
        .map(clean_name)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| display_name(kind).to_owned())
}

fn xray_name(o: &Map<String, Value>, remarks: Option<&str>) -> String {
    outbound_name(o, xray::protocol(o).unwrap_or("vless"), remarks, None)
}

/// A tag that says nothing about the server: empty, a stock name, or the protocol itself (as
/// written, e.g. Xray `ss`, or normalised).
fn is_generic(tag: Option<&str>, o: &Map<String, Value>, kind: &str) -> bool {
    let Some(tag) = tag.map(|t| t.trim().to_ascii_lowercase()) else {
        return true;
    };
    let written = text(o, &["type", "protocol"]).map(|p| p.trim().to_ascii_lowercase());
    tag.is_empty()
        || GENERIC_TAGS.contains(&tag.as_str())
        || tag == kind
        || written.as_deref() == Some(tag.as_str())
}

/// `type tag @ host` of an outbound: enough to find it, never a credential.
fn excerpt(o: &Map<String, Value>) -> String {
    let settings = o.get("settings");
    let first = |key: &str| {
        settings?
            .get(key)?
            .as_array()?
            .first()?
            .get("address")?
            .as_str()
    };
    let address = text(o, &["server"])
        .or_else(|| first("vnext"))
        .or_else(|| first("servers"))
        .or_else(|| settings?.get("address")?.as_str())
        .or_else(|| settings?.pointer("/peers/0/endpoint")?.as_str());
    let mut s = text(o, &["type", "protocol"])
        .unwrap_or("outbound")
        .to_owned();
    if let Some(tag) = text(o, &["tag"]) {
        s.push(' ');
        s.push_str(tag);
    }
    if let Some(address) = address {
        s.push_str(" @ ");
        s.push_str(address);
    }
    clean_name(&s).chars().take(EXCERPT_CHARS).collect()
}

/// A provider Xray document (its last routing rule sends everything to one outbound or balancer)
/// is ONE profile carrying the whole reachable graph (profiles spec K4). A rejected graph skips
/// this document only.
fn provider_document(doc: &Value, remarks: Option<&str>, out: &mut Out) -> bool {
    let Some(entry) = crate::xray_native::document_entry(doc) else {
        return false;
    };
    let Some(selected) =
        crate::xray_native::document_selected(doc, &entry).and_then(Value::as_object)
    else {
        return false;
    };
    let name = remarks
        .map(clean_name)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| xray_name(selected, None));
    let doc = Doc {
        value: Some(doc),
        entry: Some(&entry),
    };
    match xray::profiles(selected, &name, doc).into_iter().next() {
        Some(first) => {
            out.push(first, || excerpt(selected));
            true
        }
        None => false,
    }
}
