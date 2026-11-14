//! Identity of a server key (the engine choice is `vpnte_engine::select_engine`'s alone).
//!
//! The identity hashes what makes two keys the same server account (protocol, address,
//! credential, SNI, REALITY key, transport path, port-hopping ranges, Shadowsocks method,
//! provider graph) and never the display name, notes, mux, dial options or uTLS fingerprint:
//! a provider renaming a node or tuning client options must not turn it into a new server on
//! refresh, and the same key pasted twice under two names is one server.
use sha2::{Digest, Sha256};

use crate::model::{Host, Kind, NativeXray, Profile, Tls, Transport};

/// Bumped only together with a migration of stored identities.
const IDENTITY_VERSION: &str = "v1";

impl Profile {
    /// Stable 128-bit identity of the key: the first 16 bytes of a SHA-256 over its defining fields.
    pub fn identity(&self) -> [u8; 16] {
        let mut h = Fields(Sha256::new());
        h.put(IDENTITY_VERSION);
        h.put(self.kind.label());
        let host = host_key(&self.server);
        h.put(&host);
        h.put(&self.port.to_string());
        credential(&self.kind, &mut h);
        let (mode, sni, pbk) = tls_key(self.tls.as_ref(), &host);
        h.put(mode);
        h.put(&sni);
        h.put(pbk);
        let (transport, path) = transport_key(self);
        h.put(transport);
        h.put(&path);
        h.put(&match &self.kind {
            Kind::Hysteria2 { ports, .. } => port_ranges(ports),
            _ => String::new(),
        });
        h.put(&match &self.kind {
            Kind::Shadowsocks { method, .. } => method.to_ascii_lowercase(),
            _ => String::new(),
        });
        h.put_bytes(&graph_digest(self.native_xray.as_ref()));
        let digest = h.0.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }
}

/// Hash input with length-prefixed fields, so `("ab", "c")` and `("a", "bc")` never collide.
struct Fields(Sha256);

impl Fields {
    fn put(&mut self, field: &str) {
        self.put_bytes(field.as_bytes());
    }

    fn put_bytes(&mut self, field: &[u8]) {
        self.0.update((field.len() as u64).to_le_bytes());
        self.0.update(field);
    }
}

/// Host names compare case-insensitively and without the root dot; IPs in canonical form.
fn host_key(host: &Host) -> String {
    match host {
        Host::Ip(ip) => ip.to_string(),
        Host::Domain(name) => name_key(name),
    }
}

fn name_key(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_lowercase()
}

/// A UUID in any accepted spelling (case, braces, no hyphens) is one id; Xray custom ids
/// (non-UUID strings) are hashed by Xray itself, so they stay case-sensitive.
fn uuid_key(id: &str) -> String {
    uuid::Uuid::try_parse(id.trim()).map_or_else(|_| id.to_owned(), |u| u.hyphenated().to_string())
}

fn credential(kind: &Kind, h: &mut Fields) {
    match kind {
        Kind::Vless {
            uuid, encryption, ..
        } => {
            h.put(&uuid_key(uuid));
            // VLESS Encryption carries the server's public key: a different key is another account.
            h.put(
                encryption
                    .as_deref()
                    .filter(|_| vless_encryption(kind))
                    .unwrap_or_default(),
            );
        }
        Kind::Vmess { uuid, .. } => h.put(&uuid_key(uuid)),
        Kind::Trojan { password }
        | Kind::Hysteria2 { password, .. }
        | Kind::Anytls { password, .. } => h.put(password),
        Kind::Shadowsocks {
            password,
            shadowtls,
            ..
        } => {
            h.put(password);
            h.put(shadowtls.as_ref().map_or("", |s| s.password.as_str()));
        }
        Kind::Tuic { uuid, password, .. } => {
            h.put(&uuid_key(uuid));
            h.put(password);
        }
        Kind::Naive {
            username, password, ..
        } => {
            h.put(username);
            h.put(password);
        }
        // AmneziaWG hashes like WireGuard under its own label: rotated obfuscation values keep
        // the row (a refresh updates them), as rotated TLS fingerprints do elsewhere.
        Kind::Wireguard(wg) | Kind::Amneziawg { wg, .. } => {
            h.put(&wg.private_key);
            h.put(&wg.peers.len().to_string());
            for peer in &wg.peers {
                h.put(&host_key(&peer.host));
                h.put(&peer.port.to_string());
                h.put(&peer.public_key);
            }
        }
        Kind::Socks { username, password } | Kind::Http { username, password } => {
            h.put(username.as_deref().unwrap_or_default());
            h.put(password.as_deref().unwrap_or_default());
        }
    }
}

/// TLS mode, SNI (case-insensitive) and REALITY public key. Without an SNI both engines send the
/// server address (sing-box `common/tls`), so an absent SNI and the host itself are one key.
fn tls_key<'a>(tls: Option<&'a Tls>, host: &str) -> (&'static str, String, &'a str) {
    let Some(t) = tls else {
        return ("none", String::new(), "");
    };
    let sni = t
        .server_name
        .as_deref()
        .map_or_else(|| host.to_owned(), name_key);
    match &t.reality {
        Some(r) => ("reality", sni, r.public_key.as_str()),
        None => ("tls", sni, ""),
    }
}

/// SHA-256 of the provider graph with sorted object keys: the workspace builds serde_json with
/// `preserve_order`, and a panel that reorders keys must not turn its servers into new ones.
fn graph_digest(graph: Option<&NativeXray>) -> Vec<u8> {
    // Serialising string-keyed data does not fail; if it did, the graph would hash as absent.
    let Some(mut value) = graph.and_then(|g| serde_json::to_value(g).ok()) else {
        return Vec::new();
    };
    value.sort_all_objects();
    Sha256::digest(value.to_string()).to_vec()
}

/// Transport kind with its path or gRPC service name; Naive over QUIC is a transport of its own.
fn transport_key(p: &Profile) -> (&'static str, String) {
    match &p.transport {
        None if matches!(p.kind, Kind::Naive { quic: true, .. }) => ("quic", String::new()),
        None => ("tcp", String::new()),
        Some(Transport::Ws { path, .. }) => ("ws", path.clone()),
        Some(Transport::Grpc { service_name, .. }) => ("grpc", service_name.clone()),
        Some(Transport::Http { path, .. }) => ("http", path.clone()),
        Some(Transport::HttpUpgrade { path, .. }) => ("httpupgrade", path.clone()),
        Some(Transport::Quic) => ("quic", String::new()),
        Some(Transport::Xhttp { path, .. }) => ("xhttp", path.clone()),
        Some(Transport::TcpHttpHeader { path, .. }) => ("tcp-http-header", path.join(",")),
    }
}

/// Port-hopping ranges as `a-b,c-d`.
fn port_ranges(ports: &[(u16, u16)]) -> String {
    let items: Vec<String> = ports.iter().map(|(a, b)| format!("{a}-{b}")).collect();
    items.join(",")
}

/// VLESS Encryption is on: `encryption` set and not `none`.
fn vless_encryption(kind: &Kind) -> bool {
    matches!(kind, Kind::Vless { encryption: Some(e), .. } if !e.is_empty() && !e.eq_ignore_ascii_case("none"))
}

#[cfg(test)]
mod tests;
