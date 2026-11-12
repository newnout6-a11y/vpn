//! `Debug` for the model types that hold credentials: UUIDs, passwords, private and pre-shared
//! keys, the imported share line and provider graphs print as `<hidden>` (CONTRACT §4.9: an
//! accidental `?profile` in a log must not leak a key). Verbatim provider option maps (pasted
//! sing-box keys, XHTTP `extra`) print only their keys: their values may be a TLS client key or
//! HTTP header credentials. Everything else prints as derived.
use std::fmt;

use serde_json::{Map, Value};

use super::{
    Hy2Obfs, Kind, NativeXray, Profile, ShadowTlsLayer, Source, Transport, WgPeer, WireGuard,
};

/// Stands in for a secret.
struct Hidden;

impl fmt::Debug for Hidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<hidden>")
    }
}

/// `Some(<hidden>)` / `None`: whether an optional secret is set is not itself a secret.
fn hidden_opt<T>(value: &Option<T>) -> Option<Hidden> {
    value.as_ref().map(|_| Hidden)
}

/// The keys of a verbatim option map, without their values.
struct Keys<'a>(&'a Map<String, Value>);

impl fmt::Debug for Keys<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Destructured so that a new field cannot be forgotten here.
        let Profile {
            name,
            description,
            server,
            port,
            kind,
            tls,
            transport,
            mux,
            dial,
            native_xray,
            singbox_extra,
            source,
            notes,
        } = self;
        f.debug_struct("Profile")
            .field("name", name)
            .field("description", description)
            .field("server", server)
            .field("port", port)
            .field("kind", kind)
            .field("tls", tls)
            .field("transport", transport)
            .field("mux", mux)
            .field("dial", dial)
            .field("native_xray", native_xray)
            .field("singbox_extra", &Keys(singbox_extra))
            .field("source", source)
            .field("notes", notes)
            .finish()
    }
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Ws {
                path,
                host,
                max_early_data,
                early_data_header,
            } => f
                .debug_struct("Ws")
                .field("path", path)
                .field("host", host)
                .field("max_early_data", max_early_data)
                .field("early_data_header", early_data_header)
                .finish(),
            Transport::Grpc {
                service_name,
                multi_mode,
            } => f
                .debug_struct("Grpc")
                .field("service_name", service_name)
                .field("multi_mode", multi_mode)
                .finish(),
            Transport::Http { hosts, path } => f
                .debug_struct("Http")
                .field("hosts", hosts)
                .field("path", path)
                .finish(),
            Transport::HttpUpgrade { host, path } => f
                .debug_struct("HttpUpgrade")
                .field("host", host)
                .field("path", path)
                .finish(),
            Transport::Quic => f.write_str("Quic"),
            Transport::Xhttp {
                host,
                path,
                mode,
                extra,
            } => f
                .debug_struct("Xhttp")
                .field("host", host)
                .field("path", path)
                .field("mode", mode)
                .field("extra", &extra.as_ref().map(Keys))
                .finish(),
            Transport::TcpHttpHeader { host, path } => f
                .debug_struct("TcpHttpHeader")
                .field("host", host)
                .field("path", path)
                .finish(),
        }
    }
}

impl fmt::Debug for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct(self.label());
        match self {
            Kind::Vless {
                flow,
                packet_encoding,
                encryption,
                ..
            } => s
                .field("uuid", &Hidden)
                .field("flow", flow)
                .field("packet_encoding", packet_encoding)
                .field("encryption", encryption),
            Kind::Vmess {
                security,
                global_padding,
                authenticated_length,
                ..
            } => s
                .field("uuid", &Hidden)
                .field("security", security)
                .field("global_padding", global_padding)
                .field("authenticated_length", authenticated_length),
            Kind::Trojan { .. } => s.field("password", &Hidden),
            Kind::Shadowsocks {
                method,
                plugin,
                shadowtls,
                uot,
                ..
            } => s
                .field("method", method)
                .field("password", &Hidden)
                .field("plugin", plugin)
                .field("shadowtls", shadowtls)
                .field("uot", uot),
            Kind::Hysteria2 {
                obfs,
                ports,
                hop_interval_s,
                hop_interval_max_s,
                up_mbps,
                down_mbps,
                bbr_profile,
                ..
            } => s
                .field("password", &Hidden)
                .field("obfs", obfs)
                .field("ports", ports)
                .field("hop_interval_s", hop_interval_s)
                .field("hop_interval_max_s", hop_interval_max_s)
                .field("up_mbps", up_mbps)
                .field("down_mbps", down_mbps)
                .field("bbr_profile", bbr_profile),
            Kind::Tuic {
                congestion,
                udp_relay_mode,
                zero_rtt,
                heartbeat_s,
                ..
            } => s
                .field("uuid", &Hidden)
                .field("password", &Hidden)
                .field("congestion", congestion)
                .field("udp_relay_mode", udp_relay_mode)
                .field("zero_rtt", zero_rtt)
                .field("heartbeat_s", heartbeat_s),
            Kind::Naive {
                quic,
                extra_headers,
                insecure_concurrency,
                ..
            } => s
                .field("username", &Hidden)
                .field("password", &Hidden)
                .field("quic", quic)
                .field("extra_headers", &extra_headers.len())
                .field("insecure_concurrency", insecure_concurrency),
            Kind::Anytls {
                idle_check_s,
                idle_timeout_s,
                min_idle,
                ..
            } => s
                .field("password", &Hidden)
                .field("idle_check_s", idle_check_s)
                .field("idle_timeout_s", idle_timeout_s)
                .field("min_idle", min_idle),
            Kind::Wireguard(wg) => s.field("config", wg),
            Kind::Amneziawg { wg, awg } => s.field("config", wg).field("awg", awg),
            Kind::Socks { username, password } | Kind::Http { username, password } => s
                .field("username", &hidden_opt(username))
                .field("password", &hidden_opt(password)),
        };
        s.finish()
    }
}

impl fmt::Debug for ShadowTlsLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowTlsLayer")
            .field("version", &self.version)
            .field("password", &Hidden)
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl fmt::Debug for Hy2Obfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hy2Obfs")
            .field("kind", &self.kind)
            .field("password", &Hidden)
            .finish()
    }
}

impl fmt::Debug for WireGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuard")
            .field("private_key", &Hidden)
            .field("local_address", &self.local_address)
            .field("mtu", &self.mtu)
            .field("dns", &self.dns)
            .field("peers", &self.peers)
            .finish()
    }
}

impl fmt::Debug for WgPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgPeer")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("public_key", &self.public_key)
            .field("pre_shared_key", &hidden_opt(&self.pre_shared_key))
            .field("allowed_ips", &self.allowed_ips)
            .field("keepalive_s", &self.keepalive_s)
            .field("reserved", &self.reserved)
            .finish()
    }
}

impl fmt::Debug for NativeXray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeXray")
            .field("version", &self.version)
            .field("selected_tag", &self.selected_tag)
            .field("entry", &self.entry)
            .field("outbounds", &self.outbounds.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The imported line carries the credentials; its scheme says enough.
            Source::Uri(line) => {
                let scheme = line.split_once("://").map_or("?", |(scheme, _)| scheme);
                f.debug_tuple("Uri")
                    .field(&format_args!("{scheme}://<hidden>"))
                    .finish()
            }
            Source::Json => f.write_str("Json"),
            Source::Clash => f.write_str("Clash"),
            Source::WgIni => f.write_str("WgIni"),
            Source::Legacy => f.write_str("Legacy"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    fn profile(kind: Kind, source: Source) -> Profile {
        Profile {
            name: "Node".into(),
            description: None,
            server: Host::Domain("h.example".into()),
            port: 443,
            kind,
            tls: None,
            transport: None,
            mux: None,
            dial: DialPrefs::default(),
            native_xray: None,
            singbox_extra: Map::new(),
            source,
            notes: Vec::new(),
        }
    }

    /// `{:?}` of a profile never shows a credential, the imported line or a provider graph.
    #[test]
    fn debug_hides_credentials() {
        let peer = WgPeer {
            host: Host::Domain("wg.example".into()),
            port: 51820,
            public_key: "PUBLIC-KEY".into(),
            pre_shared_key: Some("SECRET-PSK".into()),
            allowed_ips: Vec::new(),
            keepalive_s: None,
            reserved: None,
        };
        let kinds = [
            Kind::Vless {
                uuid: "SECRET-UUID".into(),
                flow: Some("xtls-rprx-vision".into()),
                packet_encoding: None,
                encryption: None,
            },
            Kind::Shadowsocks {
                method: "aes-128-gcm".into(),
                password: "SECRET-PASS".into(),
                plugin: None,
                shadowtls: Some(ShadowTlsLayer {
                    version: 3,
                    password: "SECRET-LAYER".into(),
                    server_name: "cover.example".into(),
                }),
                uot: None,
            },
            Kind::Naive {
                username: "SECRET-USER".into(),
                password: "SECRET-PASS".into(),
                quic: false,
                extra_headers: vec![("X-Token".into(), "SECRET-HEADER".into())],
                insecure_concurrency: None,
            },
            Kind::Wireguard(WireGuard {
                private_key: "SECRET-PRIVATE".into(),
                local_address: Vec::new(),
                mtu: None,
                dns: Vec::new(),
                peers: vec![peer],
            }),
            Kind::Socks {
                username: Some("SECRET-USER".into()),
                password: Some("SECRET-PASS".into()),
            },
        ];
        for kind in kinds {
            let mut p = profile(
                kind,
                Source::Uri("vless://SECRET-UUID@h.example:443#Node".into()),
            );
            p.native_xray = Some(NativeXray {
                version: 1,
                selected_tag: "proxy".into(),
                entry: NativeEntry::default(),
                outbounds: vec![serde_json::json!({"settings": {"id": "SECRET-GRAPH"}})],
                routing: None,
                observatory: None,
                burst_observatory: None,
                policy: None,
            });
            let text = format!("{p:?}");
            assert!(!text.contains("SECRET"), "{text}");
            assert!(
                text.contains("<hidden>") && text.contains("vless://<hidden>"),
                "{text}"
            );
        }
        let text = format!(
            "{:?}",
            profile(
                Kind::Trojan {
                    password: "SECRET".into()
                },
                Source::Json
            )
        );
        assert!(
            text.contains("trojan { password: <hidden> }") && text.contains("source: Json"),
            "{text}"
        );
    }

    /// Pasted sing-box options and XHTTP `extra` print their keys only: a TLS client key or a
    /// header token in them stays out of logs.
    #[test]
    fn debug_shows_only_the_keys_of_verbatim_options() {
        let mut p = profile(
            Kind::Trojan {
                password: "SECRET".into(),
            },
            Source::Json,
        );
        p.singbox_extra.insert(
            "tls.client_key".into(),
            serde_json::json!("SECRET-CLIENT-KEY"),
        );
        p.singbox_extra
            .insert("multiplex".into(), serde_json::json!({"min_streams": 4}));
        let mut extra = Map::new();
        extra.insert(
            "headers".into(),
            serde_json::json!({"Authorization": "SECRET-TOKEN"}),
        );
        p.transport = Some(Transport::Xhttp {
            host: "cdn.example".into(),
            path: "/x".into(),
            mode: Some("auto".into()),
            extra: Some(extra),
        });
        let text = format!("{p:?}");
        assert!(!text.contains("SECRET"), "{text}");
        assert!(
            text.contains(r#"singbox_extra: {"tls.client_key", "multiplex"}"#)
                && text.contains(r#"extra: Some({"headers"})"#)
                && text.contains(r#"path: "/x""#),
            "{text}"
        );
    }
}
