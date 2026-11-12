//! Pinning of a native upstream's server names: pure tests on emitted fragments (fake keys,
//! documentation names and addresses), then the runtime with the fake resolver.
use std::collections::HashMap;
use std::net::IpAddr;

use serde_json::{Value, json};
use vpnte_base::types::EnginePref;
use vpnte_engine::singbox_config::Upstream;
use vpnte_profiles::emit_singbox::{EmitPolicy, SingBoxFragment};

use super::{dialed_names, pin};

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const PINNED: &str = "203.0.113.10";

/// The `proxy-out` fragment the runtime would emit for a fake key.
fn fragment(uri: &str) -> SingBoxFragment {
    let p = vpnte_profiles::uri::parse_uri(uri).expect("fake key parses");
    match Upstream::native(&p, &EmitPolicy::default()).expect("emits") {
        Upstream::Native { fragment, .. } => fragment,
        other => panic!("not native: {other:?}"),
    }
}

fn vless(host_port: &str, query: &str) -> SingBoxFragment {
    fragment(&format!("vless://{UUID}@{host_port}?{query}#Fake"))
}

fn addrs(pairs: &[(&str, &str)]) -> HashMap<String, IpAddr> {
    pairs
        .iter()
        .map(|(name, ip)| ((*name).to_owned(), ip.parse().unwrap()))
        .collect()
}

/// The single outbound (the tagged one) of a fragment.
fn out(f: &SingBoxFragment) -> &Value {
    &f.outbounds()[0]
}

/// TLS without a server name: the address is dialed, the name becomes the server name and the
/// bootstrap resolver goes (the config then has no `dns-bootstrap` server).
#[test]
fn tls_server_name_keeps_the_name() {
    let mut f = fragment("trojan://fake-password@vpn.example:443?security=tls#Fake");
    assert_eq!(dialed_names(&f), ["vpn.example"]);
    assert!(out(&f).get("domain_resolver").is_some());
    assert!(pin(&mut f, &addrs(&[("vpn.example", PINNED)])));
    assert_eq!(out(&f)["server"], PINNED);
    assert_eq!(out(&f)["tls"]["server_name"], "vpn.example");
    assert!(out(&f).get("domain_resolver").is_none());
    assert!(!f.needs_bootstrap_dns());
    assert_eq!(f.endpoint_ips(), [PINNED.parse::<IpAddr>().unwrap()]);

    // A provider SNI is kept as it is.
    let mut f = fragment("trojan://fake-password@vpn.example:443?security=tls&sni=front.example#F");
    assert!(pin(&mut f, &addrs(&[("vpn.example", PINNED)])));
    assert_eq!(out(&f)["tls"]["server_name"], "front.example");
}

/// The HTTP host each transport sent before (sing-box 1.14 derives it from the dialed address
/// when unset) is written out; a provider host stays.
#[test]
fn transports_keep_the_host_they_sent() {
    let pinned = addrs(&[("cdn.example", PINNED)]);
    let mut ws = vless("cdn.example:443", "type=ws&path=%2Fws&security=tls");
    assert!(pin(&mut ws, &pinned));
    assert_eq!(out(&ws)["transport"]["headers"]["Host"], "cdn.example:443");
    assert_eq!(out(&ws)["tls"]["server_name"], "cdn.example");

    let mut fronted = vless(
        "cdn.example:443",
        "type=ws&path=%2Fws&host=front.example&security=tls",
    );
    let before = out(&fronted)["transport"].clone();
    assert!(pin(&mut fronted, &pinned));
    assert_eq!(out(&fronted)["transport"], before);

    let mut upgrade = vless(
        "cdn.example:8080",
        "type=httpupgrade&path=%2Fu&security=none",
    );
    assert!(pin(&mut upgrade, &pinned));
    assert_eq!(out(&upgrade)["transport"]["host"], "cdn.example:8080");
    let mut upgrade_tls = vless("cdn.example:443", "type=httpupgrade&path=%2Fu&security=tls");
    assert!(pin(&mut upgrade_tls, &pinned));
    assert!(out(&upgrade_tls)["transport"].get("host").is_none());
    assert_eq!(out(&upgrade_tls)["tls"]["server_name"], "cdn.example");

    let mut h1 = vless("cdn.example:80", "type=http&path=%2Fh&security=none");
    assert!(pin(&mut h1, &pinned));
    assert_eq!(out(&h1)["transport"]["host"], json!(["cdn.example"]));
    // HTTP/2 over TLS sends a fixed placeholder host, not the server's name.
    let mut h2 = vless("cdn.example:443", "type=http&path=%2Fh&security=tls");
    assert!(pin(&mut h2, &pinned));
    assert!(out(&h2)["transport"].get("host").is_none());

    let mut grpc = vless("cdn.example:443", "type=grpc&serviceName=svc&security=tls");
    assert!(pin(&mut grpc, &pinned));
    assert_eq!(out(&grpc)["tls"]["server_name"], "cdn.example");
}

/// gRPC without TLS would show the address as its authority: that name is not pinned.
#[test]
fn plain_grpc_keeps_the_name() {
    let mut f = vless("cdn.example:443", "type=grpc&serviceName=svc&security=none");
    let before = f.clone();
    assert!(!pin(&mut f, &addrs(&[("cdn.example", PINNED)])));
    assert_eq!(f, before);
}

/// Shadowsocks' v2ray-plugin over TLS takes its server name from `host`, else from the dialed
/// address: without `host` the name stays; other plugin setups are pinned.
#[test]
fn v2ray_plugin_over_tls_needs_its_host() {
    let ss = |opts: &str| {
        SingBoxFragment::Outbound(json!({
            "type": "shadowsocks", "tag": "proxy-out", "server": "ss.example", "server_port": 443,
            "method": "aes-128-gcm", "password": "fake-password", "plugin": "v2ray-plugin",
            "plugin_opts": opts,
            "domain_resolver": { "server": "dns-bootstrap", "strategy": "ipv4_only" },
        }))
    };
    let pinned = addrs(&[("ss.example", PINNED)]);
    let mut bare_tls = ss("tls;path=/ws");
    let before = bare_tls.clone();
    assert!(!pin(&mut bare_tls, &pinned));
    assert_eq!(bare_tls, before);
    for opts in [
        "tls;host=front.example;path=/ws",
        "path=/ws",
        "mode=websocket",
    ] {
        let mut f = ss(opts);
        assert!(pin(&mut f, &pinned), "{opts}");
        assert_eq!(out(&f)["server"], PINNED, "{opts}");
        assert_eq!(out(&f)["plugin_opts"], opts);
    }
}
/// WireGuard peers given by name are pinned one by one; the resolver goes with the last name.
#[test]
fn wireguard_peers_and_the_shadowtls_chain() {
    let resolver = json!({ "server": "dns-bootstrap", "strategy": "ipv4_only" });
    let mut wg = SingBoxFragment::Endpoint(json!({
        "type": "wireguard", "tag": "proxy-out", "domain_resolver": resolver,
        "peers": [{ "address": "wg.example", "port": 51820 }, { "address": "192.0.2.7", "port": 51820 }],
    }));
    assert_eq!(dialed_names(&wg), ["wg.example"]);
    assert!(!pin(&mut wg, &addrs(&[])), "no address: the name stays");
    assert!(pin(&mut wg, &addrs(&[("wg.example", PINNED)])));
    let e = &wg.endpoints()[0];
    assert_eq!(e["peers"][0]["address"], PINNED);
    assert_eq!(e["peers"][1]["address"], "192.0.2.7");
    assert!(e.get("domain_resolver").is_none());

    // Shadowsocks over ShadowTLS: only the ShadowTLS dialer connects; its SNI is the camouflage.
    let mut chain = SingBoxFragment::Chain(vec![
        json!({ "type": "shadowsocks", "tag": "proxy-out", "server": "ss.example",
                "server_port": 443, "detour": "proxy-out-shadowtls" }),
        json!({ "type": "shadowtls", "tag": "proxy-out-shadowtls", "server": "ss.example",
                "server_port": 443, "domain_resolver": resolver,
                "tls": { "enabled": true, "server_name": "camouflage.example" } }),
    ]);
    assert_eq!(dialed_names(&chain), ["ss.example"]);
    assert!(pin(&mut chain, &addrs(&[("ss.example", PINNED)])));
    let list = chain.outbounds();
    assert_eq!(list[0]["server"], "ss.example");
    assert_eq!(list[1]["server"], PINNED);
    assert_eq!(list[1]["tls"]["server_name"], "camouflage.example");
}

/// Only an address the entry's resolver strategy would dial is pinned (IPv4 only by default);
/// a literal server needs nothing.
#[test]
fn strategy_and_literals() {
    let v6 = addrs(&[("vpn.example", "2001:db8::10")]);
    let mut f = fragment("trojan://fake-password@vpn.example:443?security=tls#Fake");
    let before = f.clone();
    assert!(!pin(&mut f, &v6));
    assert_eq!(f, before);
    let SingBoxFragment::Outbound(o) = &mut f else {
        panic!("one outbound")
    };
    o["domain_resolver"]["strategy"] = json!("prefer_ipv6");
    assert!(pin(&mut f, &v6));
    assert_eq!(out(&f)["server"], "2001:db8::10");

    let literal =
        fragment("trojan://fake-password@203.0.113.12:443?security=tls&sni=example.com#L");
    assert!(dialed_names(&literal).is_empty());
}

/// The runtime with the fake resolver (every name -> 203.0.113.10) and the recorded configs.
mod runtime {
    use tokio_util::sync::CancellationToken;
    use vpnte_base::Msg;
    use vpnte_engine::xray_config::{ResolveFault, ResolvePath};

    use super::*;
    use crate::api::{Runtime, StopOptions};
    use crate::runtime::TunnelHandle;
    use crate::runtime::tests::{World, deps, vpn_req};

    const NATIVE_BY_NAME: &str = "trojan://fake-password@vpn.example:443?security=tls#Fake%20N";
    const XRAY_BY_NAME: &str = "vless://00000000-0000-4000-8000-000000000003@xray.example:443?security=tls&sni=example.com&type=tcp#Fake%20X";
    const NOT_PRE_RESOLVED: &str = "tunnel.runtime.serverNotPreResolved";
    const LAST_KNOWN: &str = "core.net.resolveLastKnown";

    /// Starts `uri` on `engine`; the warnings' keys and the generated config.
    async fn start(
        w: &std::sync::Arc<World>,
        uri: &str,
        engine: EnginePref,
    ) -> (Vec<String>, Value) {
        let h = TunnelHandle::spawn(deps(w));
        let receipt = h
            .start(vpn_req(uri, engine), CancellationToken::new())
            .await
            .expect("start");
        let _ = h.stop(StopOptions::default()).await;
        let keys = receipt.warnings.iter().map(|m| m.key.to_string()).collect();
        (keys, w.configs.lock()[0].clone())
    }

    fn proxy_out(config: &Value) -> &Value {
        let list = config["outbounds"].as_array().unwrap();
        list.iter().find(|o| o["tag"] == "proxy-out").unwrap()
    }

    fn has_dns_server(config: &Value, tag: &str) -> bool {
        let servers = config["dns"]["servers"].as_array().unwrap();
        servers.iter().any(|s| s["tag"] == tag)
    }

    /// The name is resolved directly and sing-box dials the address with the TLS name kept;
    /// the config needs no bootstrap DNS any more.
    #[tokio::test]
    async fn native_start_dials_the_pinned_address() {
        let w = World::new();
        let (warnings, config) = start(&w, NATIVE_BY_NAME, EnginePref::SingBox).await;
        assert!(
            !warnings.iter().any(|k| k == NOT_PRE_RESOLVED),
            "{warnings:?}"
        );
        assert_eq!(*w.resolve_paths.lock(), [ResolvePath::Direct]);
        let out = proxy_out(&config);
        assert_eq!(out["server"], PINNED);
        assert_eq!(out["tls"]["server_name"], "vpn.example");
        assert!(out.get("domain_resolver").is_none());
        assert!(!has_dns_server(&config, "dns-bootstrap"));
    }

    /// No address (forged answers, no last known one): sing-box keeps its own lookup, and the
    /// user is told; a last-known address is used and reported.
    #[tokio::test]
    async fn native_start_reports_what_it_could_not_resolve() {
        let w = World::new();
        *w.resolve_answer.lock() = Err(ResolveFault::Poisoned);
        let (warnings, config) = start(&w, NATIVE_BY_NAME, EnginePref::SingBox).await;
        assert!(
            warnings.iter().any(|k| k == NOT_PRE_RESOLVED),
            "{warnings:?}"
        );
        let out = proxy_out(&config);
        assert_eq!(out["server"], "vpn.example");
        assert_eq!(out["domain_resolver"]["server"], "dns-bootstrap");
        assert!(has_dns_server(&config, "dns-bootstrap"));

        let w = World::new();
        *w.resolve_answer.lock() = Ok(Some(Msg::new(LAST_KNOWN)));
        let (warnings, config) = start(&w, NATIVE_BY_NAME, EnginePref::SingBox).await;
        assert!(warnings.iter().any(|k| k == LAST_KNOWN), "{warnings:?}");
        assert_eq!(proxy_out(&config)["server"], PINNED);
    }

    /// Xray's cold start resolves directly (no UDP retry any more), reports a last-known
    /// address, and fails on forged answers with their own message.
    #[tokio::test]
    async fn xray_cold_start_resolves_directly() {
        let w = World::new();
        *w.resolve_answer.lock() = Ok(Some(Msg::new(LAST_KNOWN)));
        let (warnings, _) = start(&w, XRAY_BY_NAME, EnginePref::Xray).await;
        assert!(warnings.iter().any(|k| k == LAST_KNOWN), "{warnings:?}");
        assert_eq!(*w.resolve_paths.lock(), [ResolvePath::Direct]);

        let w = World::new();
        *w.resolve_answer.lock() = Err(ResolveFault::Poisoned);
        let h = TunnelHandle::spawn(deps(&w));
        let req = vpn_req(XRAY_BY_NAME, EnginePref::Xray);
        let err = h.start(req, CancellationToken::new()).await.unwrap_err();
        assert_eq!(err.error.user_msg().key, "engine.xray.resolve.poisoned");
        assert!(w.configs.lock().is_empty());
    }
}

/// A provider `Host` header, in any case and in sing-box's list form too, is the server's and
/// stays as it is.
#[test]
fn provider_host_headers_stay() {
    for headers in [
        json!({ "host": "front.example" }),
        json!({ "Host": ["front.example"] }),
    ] {
        let mut f = SingBoxFragment::Outbound(json!({
            "type": "vless", "tag": "proxy-out", "server": "cdn.example", "server_port": 443,
            "uuid": UUID, "tls": { "enabled": true, "server_name": "front.example" },
            "transport": { "type": "ws", "path": "/ws", "headers": headers.clone() },
        }));
        assert!(pin(&mut f, &addrs(&[("cdn.example", PINNED)])));
        assert_eq!(out(&f)["transport"]["headers"], headers);
        assert_eq!(out(&f)["server"], PINNED);
    }
}
