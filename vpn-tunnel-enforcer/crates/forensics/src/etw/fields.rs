//! Metadata extraction from a parsed ETW event (5-tuple, query name, resolver): property names
//! verbatim from the old sidecar (RS:255-321). Payloads are never parsed.
use std::net::IpAddr;

use ferrisetw::parser::Parser;
use serde_json::{Map, Value};

use super::classify::{first_ip, le_uint, parse_sockaddr, port_value, truncate_chars};

/// Characters of `QueryResults` kept in a row.
const QUERY_RESULTS_MAX: usize = 500;

/// Adds the fields of one event to `fields` (keys as in the old `events.ndjson`).
pub fn extract(parser: &Parser, category: &str, fields: &mut Map<String, Value>) {
    if category == "dns" {
        extract_dns(parser, fields);
        return;
    }
    let remote = resolve_addr(
        parser,
        &[
            "RemoteAddress",
            "DestinationAddress",
            "DestAddress",
            "Address",
        ],
    );
    if let Some((addr, port)) = remote {
        fields.insert("remoteAddress".into(), addr.to_string().into());
        if let Some(p) = port {
            fields.insert("remotePort".into(), p.into());
        }
    }
    if let Some((addr, port)) =
        resolve_addr(parser, &["LocalAddress", "SourceAddress", "SourceAddr"])
    {
        fields.insert("localAddress".into(), addr.to_string().into());
        if let Some(p) = port {
            fields.insert("localPort".into(), p.into());
        }
    }
    if !fields.contains_key("remotePort")
        && let Some(p) = first_port(parser, &["RemotePort", "DestinationPort", "DestPort"])
    {
        fields.insert("remotePort".into(), p.into());
    }
    if !fields.contains_key("localPort")
        && let Some(p) = first_port(parser, &["LocalPort", "SourcePort"])
    {
        fields.insert("localPort".into(), p.into());
    }
    if category == "tcp" {
        fields.insert("protocol".into(), "tcp".into());
    }
}

fn extract_dns(parser: &Parser, fields: &mut Map<String, Value>) {
    if let Some(q) = try_string(parser, "QueryName") {
        fields.insert("queryName".into(), q.into());
    }
    if let Some(results) = try_string(parser, "QueryResults") {
        if let Some(ip) = first_ip(&results) {
            fields.insert("remoteAddress".into(), ip.to_string().into());
        }
        fields.insert(
            "queryResults".into(),
            truncate_chars(&results, QUERY_RESULTS_MAX).into(),
        );
    }
    for name in ["DnsServerIpAddress", "DnsServer", "ServerList", "Address"] {
        let resolver = try_ip(parser, name).map(|ip| ip.to_string()).or_else(|| {
            try_string(parser, name).map(|s| first_ip(&s).map_or(s, |ip| ip.to_string()))
        });
        if let Some(resolver) = resolver.filter(|r| !r.is_empty()) {
            fields.insert("resolver".into(), resolver.into());
            break;
        }
    }
    if let Some(status) = try_bytes(parser, "QueryStatus").and_then(|b| le_uint(&b)) {
        fields.insert("queryStatus".into(), status.into());
    }
}

/// Address (and port) from the first property that is a typed IP, a sockaddr / IN_ADDR blob or
/// a string containing an IP.
fn resolve_addr(parser: &Parser, names: &[&str]) -> Option<(IpAddr, Option<u16>)> {
    names.iter().find_map(|name| {
        try_ip(parser, name)
            .map(|ip| (ip, None))
            .or_else(|| try_bytes(parser, name).and_then(|b| parse_sockaddr(&b)))
            .or_else(|| {
                try_string(parser, name)
                    .and_then(|s| first_ip(&s))
                    .map(|ip| (ip, None))
            })
    })
}

fn first_port(parser: &Parser, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| try_bytes(parser, name).and_then(|b| port_value(&b)))
}

fn try_bytes(parser: &Parser, name: &str) -> Option<Vec<u8>> {
    parser
        .try_parse::<Vec<u8>>(name)
        .ok()
        .filter(|b| !b.is_empty())
}

fn try_string(parser: &Parser, name: &str) -> Option<String> {
    parser
        .try_parse::<String>(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn try_ip(parser: &Parser, name: &str) -> Option<IpAddr> {
    parser.try_parse::<IpAddr>(name).ok()
}
