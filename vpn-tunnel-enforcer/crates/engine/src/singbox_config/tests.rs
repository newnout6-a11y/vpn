//! Config vectors of tunnel-core §7.3-7.12 (outbound normalisation itself is tested in
//! `vpnte_profiles::emit_singbox`) and the review fixes E-D1..E-D4.
use std::net::{IpAddr, Ipv4Addr};

use serde_json::{Map, Value, json};
use vpnte_base::types::{AdaptiveMode, Creds, Loopback, ProxyKind};
use vpnte_base::{AppError, ErrorKind};
use vpnte_core::net::HostPort;
use vpnte_profiles::emit_singbox::EmitPolicy;
use vpnte_profiles::model::{
    DialPrefs, Host, Kind, Profile, Reality, Source, Tls, WgPeer, WireGuard,
};

use super::*;
use crate::tags::*;

// ---- fixtures (obvious fakes only) ----

pub(super) fn creds(tag: &str) -> Creds {
    Creds {
        user: format!("{tag}-user"),
        pass: format!("{tag}-SYNTHETIC"),
    }
}

pub(super) fn lb(port: u16, tag: &str) -> Loopback {
    Loopback {
        port,
        creds: Some(creds(tag)),
    }
}

pub(super) fn ep(port: u16, tag: &str) -> SlotEndpoint {
    SlotEndpoint::new(port, creds(tag)).unwrap()
}

pub(super) fn tun(ipv6: bool, dns_hijack: bool) -> TunParams {
    TunParams {
        alias: "Ethernet 5".into(),
        mtu: 1380,
        ipv6,
        dns_hijack,
        stack: TunStack::Mixed,
    }
}

/// The TUN parameters of TUN-capture inputs.
pub(super) fn tun_of(i: &mut ConfigInputs) -> &mut TunParams {
    match &mut i.capture {
        Capture::Tun(t) => t,
        Capture::Proxy { .. } => panic!("not a TUN capture"),
    }
}

pub(super) fn inputs(upstream: Upstream) -> ConfigInputs {
    ConfigInputs {
        upstream,
        capture: Capture::Tun(tun(false, true)),
        listeners: Listeners {
            clash_port: 25553,
            clash_secret: "0123456789abcdef0123456789abcdef".into(),
            direct: lb(25554, "direct"),
            probe: Some(lb(25555, "probe")),
            dns_bootstrap: None,
        },
        routing: RoutingParts::default(),
        phys_dns: Vec::new(),
    }
}

pub(super) fn profile(server: &str, kind: Kind, tls: Option<Tls>) -> Profile {
    Profile {
        name: "fixture".into(),
        description: None,
        server: match server.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(server.into()),
        },
        port: 443,
        kind,
        tls,
        transport: None,
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: Map::new(),
        source: Source::Json,
        notes: Vec::new(),
    }
}

pub(super) fn vless(server: &str, packet_encoding: Option<&str>) -> Profile {
    let kind = Kind::Vless {
        uuid: "00000000-0000-4000-8000-000000000001".into(),
        flow: None,
        packet_encoding: packet_encoding.map(str::to_owned),
        encryption: None,
    };
    let tls = Tls {
        server_name: Some("sni.example.com".into()),
        ..Tls::default()
    };
    profile(server, kind, Some(tls))
}

pub(super) fn reality(server: &str) -> Profile {
    let mut p = vless(server, None);
    if let Some(tls) = p.tls.as_mut() {
        tls.fingerprint = Some("chrome".into());
        tls.reality = Some(Reality {
            // A syntactically valid X25519 public key (32 zero bytes), not a real server key.
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            short_id: "0123abcd".into(),
            spider_x: None,
            ..Reality::default()
        });
    }
    p
}

pub(super) fn hysteria2(server: &str) -> Profile {
    let kind = Kind::Hysteria2 {
        password: "SYNTHETIC-hy2".into(),
        obfs: None,
        ports: Vec::new(),
        hop_interval_s: None,
        hop_interval_max_s: None,
        up_mbps: None,
        down_mbps: None,
        bbr_profile: None,
    };
    let tls = Tls {
        server_name: Some("sni.example.com".into()),
        ..Tls::default()
    };
    profile(server, kind, Some(tls))
}

pub(super) fn shadowsocks(server: &str) -> Profile {
    let kind = Kind::Shadowsocks {
        method: "2022-blake3-aes-128-gcm".into(),
        password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
        plugin: None,
        shadowtls: None,
        uot: None,
    };
    profile(server, kind, None)
}

/// WireGuard with fake but well-formed keys (32 zero / 32 0x01 bytes in base64).
pub(super) fn wireguard(peer_host: &str) -> Profile {
    let host = match peer_host.parse::<IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(peer_host.into()),
    };
    let wg = WireGuard {
        private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        local_address: vec!["10.0.0.2/32".parse().unwrap()],
        mtu: Some(1280),
        dns: Vec::new(),
        peers: vec![WgPeer {
            host,
            port: 51820,
            public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            pre_shared_key: None,
            allowed_ips: Vec::new(),
            keepalive_s: None,
            reserved: None,
        }],
    };
    let mut p = profile(peer_host, Kind::Wireguard(wg), None);
    p.port = 51820;
    p
}

pub(super) fn native(p: &Profile) -> Upstream {
    Upstream::native(p, &EmitPolicy::default()).unwrap()
}

pub(super) fn slots(udp: UdpPolicy) -> Upstream {
    Upstream::XraySlots {
        slots: [ep(25551, "fixture-a"), ep(25552, "fixture-b")],
        active: Slot::A,
        udp,
    }
}

pub(super) fn local_socks() -> Upstream {
    Upstream::LocalProxy {
        addr: HostPort::parse("127.0.0.1:10808").unwrap(),
        kind: ProxyKind::Socks5,
        creds: None,
    }
}

pub(super) fn rules(config: &Value) -> &Vec<Value> {
    config["route"]["rules"].as_array().unwrap()
}

pub(super) fn index_of(config: &Value, rule: &Value) -> Option<usize> {
    rules(config).iter().position(|r| r == rule)
}

pub(super) fn dns_server<'a>(config: &'a Value, tag: &str) -> Option<&'a Value> {
    config["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["tag"] == tag)
}

fn tun_in(config: &Value) -> &Value {
    &config["inbounds"][0]
}

// ---- §7.3 log / TUN basics, review E-D3 / E-D4 ----

/// AT-02-002: log level and timestamps, no log file; one TUN with the decided fields.
#[test]
fn log_and_tun_basics() {
    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    assert_eq!(c["log"], json!({ "level": "info", "timestamp": true }));
    let tun = tun_in(&c);
    assert_eq!(tun["type"], "tun");
    assert_eq!(tun["tag"], TUN_IN);
    assert_eq!(tun["interface_name"], "Ethernet 5");
    assert_eq!(tun["udp_timeout"], "30s");
    assert_eq!(tun["strict_route"], true);
    assert_eq!(tun["auto_route"], true);
    assert_eq!(tun["stack"], "mixed");
    assert_eq!(tun["mtu"], 1380);
    let tuns = c["inbounds"].as_array().unwrap();
    assert_eq!(tuns.iter().filter(|i| i["type"] == "tun").count(), 1);
    assert!(c.get("experimental").unwrap().get("cache_file").is_none());
}

/// E-D4: the IPv4-only TUN has no IPv6 address, routes, excludes or IPv6 reject rule.
#[test]
fn ipv4_only_tun() {
    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    let tun = tun_in(&c);
    assert_eq!(tun["address"], json!(["192.168.250.253/30"]));
    assert_eq!(tun["route_address"], json!(["0.0.0.0/1", "128.0.0.0/1"]));
    let excluded = tun["route_exclude_address"].as_array().unwrap();
    assert!(!excluded.contains(&json!("fe80::/10")));
    assert!(!excluded.contains(&json!("ff00::/8")));
    assert!(!c.to_string().contains("ip_version"));
}

/// E-D4 (session guarded by the WFP layer, e.g. kill switch Standard with leak protection off):
/// dual-stack TUN, IPv6 routes and excludes, and the IPv6 reject rule.
#[test]
fn dual_stack_tun() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    i.capture = Capture::Tun(tun(true, false));
    let c = build(&i).unwrap();
    let tun = tun_in(&c);
    assert_eq!(
        tun["address"],
        json!(["192.168.250.253/30", "fd8b:3f2a:91c4::1/126"])
    );
    assert_eq!(
        tun["route_address"],
        json!(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"])
    );
    let excluded = tun["route_exclude_address"].as_array().unwrap();
    assert!(excluded.contains(&json!("fe80::/10")));
    assert!(excluded.contains(&json!("ff00::/8")));
    assert!(index_of(&c, &ipv6_reject_rule()).is_some());
}

/// E-D3: `dns_mode` follows the caller: `hijack` only when no WFP DNS block is engaged.
#[test]
fn dns_mode_is_an_input() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    assert_eq!(tun_in(&build(&i).unwrap())["dns_mode"], "hijack");
    i.capture = Capture::Tun(tun(true, false));
    assert_eq!(tun_in(&build(&i).unwrap())["dns_mode"], "native");
}

/// R-E1 / winnet-wfp D4: the TCP stack follows the caller (gvisor when inbound is blocked).
#[test]
fn stack_is_an_input() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    tun_of(&mut i).stack = TunStack::Gvisor;
    assert_eq!(tun_in(&build(&i).unwrap())["stack"], "gvisor");
    assert_eq!(TunStack::default(), TunStack::Mixed);
}

#[test]
fn tun_parameters_are_checked() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    tun_of(&mut i).alias = "  ".into();
    assert!(matches!(build(&i), Err(ConfigError::InvalidTun(_))));
    tun_of(&mut i).alias = "Ethernet 5".into();
    tun_of(&mut i).mtu = 1200;
    assert!(matches!(build(&i), Err(ConfigError::InvalidTun(_))));
    // IPv4-only (no WFP guard) with `native` DNS: nothing would block port 53 outside the TUN.
    i.capture = Capture::Tun(tun(false, false));
    assert!(matches!(build(&i), Err(ConfigError::InvalidTun(_))));
}

// ---- §7.4 MTU ----

/// AT-02-002 (networkCompatibility.test.ts): MTU selection.
#[test]
fn mtu_selection() {
    use AdaptiveMode::*;
    assert_eq!(select_mtu(false, Baseline, false), 1500);
    assert_eq!(select_mtu(false, Baseline, true), 1380);
    assert_eq!(select_mtu(true, Baseline, true), 1280);
    assert_eq!(select_mtu(true, Baseline, false), 1280);
    assert_eq!(select_mtu(false, TlsCompatibility, false), 1500);
    assert_eq!(select_mtu(false, MtuCompatibility, false), 1280);
    assert_eq!(select_mtu(false, MtuCompatibility, true), 1280);
}

pub(super) fn ipv6_reject_rule() -> Value {
    json!({
        "type": "logical",
        "mode": "and",
        "rules": [{ "ip_version": 6 }, { "ip_is_private": true, "invert": true }],
        "action": "reject",
        "method": "default",
        "no_drop": true,
    })
}

// ---- §7.5 DNS ----

/// AT-02-002: a hostname endpoint brings `dns-bootstrap` and resolves through it; an IP
/// endpoint does not; `final` is `dns-remote`. ru-2026 Ф9: the bootstrap is direct DoH to an
/// IP literal (no SNI), never plain UDP, whatever the physical resolvers are.
#[test]
fn bootstrap_dns_only_for_hostname_endpoints() {
    let mut i = inputs(native(&vless("sub.example.com", None)));
    i.phys_dns = vec![
        Ipv4Addr::new(192, 168, 250, 254),
        Ipv4Addr::new(77, 88, 8, 8),
    ];
    let c = build(&i).unwrap();
    let bootstrap = dns_server(&c, DNS_BOOTSTRAP).unwrap();
    assert_eq!(
        bootstrap,
        &json!({ "type": "https", "tag": "dns-bootstrap", "server": "1.1.1.1", "path": "/dns-query" })
    );
    assert_eq!(
        c["outbounds"][0]["domain_resolver"]["server"],
        DNS_BOOTSTRAP
    );
    assert_eq!(c["dns"]["final"], DNS_REMOTE);
    assert_eq!(c["dns"]["strategy"], "ipv4_only");
    // The rest of the bootstrap order serves only `dns-bootstrap-in` (slot mode).
    assert!(c["dns"].get("rules").is_none());
    assert_eq!(c["dns"]["servers"].as_array().unwrap().len(), 2);

    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    assert!(dns_server(&c, DNS_BOOTSTRAP).is_none());
    assert_eq!(c["dns"]["final"], DNS_REMOTE);
}

/// The TUN's own /30, loopback and unspecified resolvers are never used direct (routing reports
/// the missing one); sing-box's DoH bootstrap does not depend on them.
#[test]
fn unusable_physical_resolvers_are_skipped() {
    let none = [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(192, 168, 250, 254),
    ];
    assert_eq!(usable_physical_dns(&none), None);
    let phys = [Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 168, 1, 1)];
    assert_eq!(
        usable_physical_dns(&phys),
        Some(Ipv4Addr::new(192, 168, 1, 1))
    );
    let mut i = inputs(native(&vless("sub.example.com", None)));
    i.phys_dns = none.to_vec();
    let c = build(&i).unwrap();
    assert_eq!(dns_server(&c, DNS_BOOTSTRAP).unwrap()["type"], "https");
}

/// AT-02-002: no DNS profile -> Cloudflare DoH through the tunnel; no `dns-backup`.
#[test]
fn default_remote_dns() {
    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    assert_eq!(
        dns_server(&c, DNS_REMOTE).unwrap(),
        &json!({
            "type": "https", "tag": "dns-remote", "server": "1.1.1.1", "path": "/dns-query",
            "detour": "proxy-out", "tls": { "server_name": "cloudflare-dns.com" },
        })
    );
    assert!(dns_server(&c, "dns-backup").is_none());
    assert!(dns_server(&c, DNS_RESOLVER).is_none());
    assert!(c["dns"].get("rules").is_none());
    assert_eq!(c["route"]["final"], PROXY_OUT);
    assert_eq!(c["route"]["default_domain_resolver"], DNS_REMOTE);
}

/// AT-02-002: routing's servers are used as given (plain profile as TCP through the tunnel).
#[test]
fn routing_dns_servers_are_kept() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    let plain =
        json!({ "type": "tcp", "tag": "dns-remote", "server": "9.9.9.9", "detour": "proxy-out" });
    let direct = json!({ "type": "udp", "tag": "dns-direct", "server": "77.88.8.7" });
    i.routing.dns_servers = vec![plain.clone(), direct.clone()];
    let c = build(&i).unwrap();
    assert_eq!(c["dns"]["servers"], json!([plain, direct]));
}

/// AT-02-002: a hostname DoH server gets `domain_resolver: dns-resolver` and that server is
/// added (a WireGuard upstream would otherwise resolve the name on `dns-remote` itself).
#[test]
fn hostname_remote_dns_gets_a_resolver() {
    let mut i = inputs(native(&wireguard("203.0.113.5")));
    i.routing.dns_servers = vec![json!({
        "type": "https", "tag": "dns-remote", "server": "custom-dns.example.com",
        "path": "/dns-query", "detour": "proxy-out",
        "tls": { "server_name": "custom-dns.example.com" },
    })];
    let c = build(&i).unwrap();
    let remote = dns_server(&c, DNS_REMOTE).unwrap();
    assert_eq!(remote["domain_resolver"], DNS_RESOLVER);
    let resolver = dns_server(&c, DNS_RESOLVER).unwrap();
    assert_eq!(resolver["server"], "1.1.1.1");
    assert_eq!(resolver["detour"], PROXY_OUT);
    assert!(resolver.get("domain_resolver").is_none());
}

/// Every server that `dns-remote*` tunnels goes through `proxy-out` (AT-00-007 slot vector).
#[test]
fn remote_dns_is_tunnelled_in_slot_mode() {
    let c = build(&inputs(slots(UdpPolicy {
        udp: true,
        block_quic: false,
    })))
    .unwrap();
    for s in c["dns"]["servers"].as_array().unwrap() {
        if s["tag"].as_str().unwrap().starts_with("dns-remote") {
            assert_eq!(s["detour"], PROXY_OUT);
        }
    }
}

#[test]
fn malformed_routing_dns_is_refused() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    i.routing.dns_servers = vec![json!({ "type": "udp", "server": "1.1.1.1" })];
    assert!(matches!(build(&i), Err(ConfigError::BadRouting(_))));
    let s = json!({ "type": "udp", "tag": "dns-direct", "server": "1.1.1.1" });
    i.routing.dns_servers = vec![s.clone(), s];
    assert!(matches!(build(&i), Err(ConfigError::BadRouting(_))));
    i.routing.dns_servers = Vec::new();
    i.routing.dns_rules = vec![json!("dns-direct")];
    assert!(matches!(build(&i), Err(ConfigError::BadRouting(_))));
    // `dns-resolver` and the bootstrap servers belong to the builder.
    i.routing.dns_rules = Vec::new();
    for tag in [
        DNS_RESOLVER,
        DNS_BOOTSTRAP,
        "dns-bootstrap-tcp",
        "dns-bootstrap-isp",
    ] {
        i.routing.dns_servers = vec![json!({ "type": "udp", "tag": tag, "server": "1.1.1.1" })];
        assert!(matches!(build(&i), Err(ConfigError::BadRouting(_))));
    }
}

/// Secrets never reach `Debug` output (logs): controller secret, profile keys, credentials.
#[test]
fn debug_hides_secrets() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    let text = format!("{i:?}");
    assert!(text.contains("Native") && text.contains("clash_port"));
    for secret in ["0123456789abcdef", "00000000-0000-4000-8000", "SYNTHETIC"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    let local = Upstream::LocalProxy {
        addr: HostPort::parse("127.0.0.1:10808").unwrap(),
        kind: ProxyKind::Socks5,
        creds: Some(creds("local")),
    };
    for upstream in [
        slots(UdpPolicy {
            udp: true,
            block_quic: true,
        }),
        local,
    ] {
        i.upstream = upstream;
        assert!(!format!("{i:?}").contains("SYNTHETIC"));
    }
}

// ---- §7.8 UDP / QUIC ----

fn quic_reject() -> Value {
    json!({ "network": "udp", "port": 443, "action": "reject", "method": "default", "no_drop": true })
}

fn udp_drop() -> Value {
    json!({ "network": "udp", "action": "reject", "method": "drop" })
}

fn hijack_dns() -> Value {
    json!({ "protocol": "dns", "action": "hijack-dns" })
}

/// The STUN pins (routing-dns B-X-1): sniffed protocol first, then the STUN / TURN ports.
pub(super) fn stun_pins() -> [Value; 2] {
    [
        json!({ "protocol": "stun", "outbound": PROXY_OUT }),
        json!({
            "network": "udp", "port": [3478, 3479, 5349], "port_range": ["19302:19309"],
            "outbound": PROXY_OUT,
        }),
    ]
}

/// B-X-1: WebRTC to any port reaches STUN servers through the tunnel, never through
/// direct-out; both pins sit right after the private-destination rule, before routing's rules.
#[test]
fn stun_is_pinned_by_protocol_and_ports() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    i.routing.domain_rules = smart_ru_parts("C:/rt").domain_rules;
    let c = build(&i).unwrap();
    let private = index_of(
        &c,
        &json!({ "ip_is_private": true, "outbound": DIRECT_OUT }),
    );
    let [sniffed, ports] = stun_pins();
    let at = (index_of(&c, &sniffed), index_of(&c, &ports));
    assert_eq!(at, (private.map(|p| p + 1), private.map(|p| p + 2)));
    assert!(index_of(&c, &json!({ "action": "sniff" })) < at.0);
    assert_eq!(rules(&c)[private.unwrap() + 3], i.routing.domain_rules[0]);
}

/// AT-02-008 / AT-06-001: the UDP policy of the profile as the emitter sees it.
#[test]
fn udp_policy_of_profiles() {
    let vless_default = UdpPolicy::of(&vless("1.2.3.4", None));
    assert_eq!(
        vless_default,
        UdpPolicy {
            udp: true,
            block_quic: true
        }
    );
    let vless_xudp = UdpPolicy::of(&vless("1.2.3.4", Some("xudp")));
    assert_eq!(
        vless_xudp,
        UdpPolicy {
            udp: true,
            block_quic: false
        }
    );
    let hy2 = UdpPolicy::of(&hysteria2("1.2.3.4"));
    assert_eq!(
        hy2,
        UdpPolicy {
            udp: true,
            block_quic: false
        }
    );
    let wg = UdpPolicy::of(&wireguard("203.0.113.5"));
    assert_eq!(
        wg,
        UdpPolicy {
            udp: true,
            block_quic: false
        }
    );
}

/// AT-02-008: generated UDP rules (QUIC reject with `no_drop`, E-D2; all-UDP drop after the
/// DNS hijack) for each policy and upstream kind.
#[test]
fn generated_udp_rules() {
    let tcp_only = Upstream::Native {
        fragment: native_fragment(&reality("1.2.3.4")),
        udp: UdpPolicy {
            udp: false,
            block_quic: true,
        },
    };
    let c = build(&inputs(tcp_only)).unwrap();
    let quic = index_of(&c, &quic_reject()).unwrap();
    let drop = index_of(&c, &udp_drop()).unwrap();
    let hijack = index_of(&c, &hijack_dns()).unwrap();
    assert!(quic < hijack && hijack < drop);
    assert_eq!(c["route"]["final"], PROXY_OUT);

    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    assert!(index_of(&c, &quic_reject()).is_some());
    assert!(index_of(&c, &udp_drop()).is_none());

    for p in [hysteria2("1.2.3.4"), vless("1.2.3.4", Some("xudp"))] {
        let c = build(&inputs(native(&p))).unwrap();
        assert!(index_of(&c, &quic_reject()).is_none());
        assert!(index_of(&c, &udp_drop()).is_none());
    }

    // A local proxy (socks or http) always rejects QUIC and never drops all UDP.
    let c = build(&inputs(local_socks())).unwrap();
    assert!(index_of(&c, &quic_reject()).is_some());
    assert!(index_of(&c, &udp_drop()).is_none());
    let http = Upstream::LocalProxy {
        addr: HostPort::parse("127.0.0.1:10809").unwrap(),
        kind: ProxyKind::Http,
        creds: None,
    };
    let c = build(&inputs(http)).unwrap();
    assert!(index_of(&c, &quic_reject()).is_some());
    assert!(index_of(&c, &udp_drop()).is_none());
}

/// B-34: in slot mode the UDP rules follow the slot's policy (Xray carries UDP over XUDP),
/// not the sing-box `network` field of the remote profile.
#[test]
fn slot_udp_policy() {
    let c = build(&inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    })))
    .unwrap();
    assert!(index_of(&c, &quic_reject()).is_some());
    assert!(index_of(&c, &udp_drop()).is_none());
    let c = build(&inputs(slots(UdpPolicy {
        udp: true,
        block_quic: false,
    })))
    .unwrap();
    assert!(index_of(&c, &quic_reject()).is_none());
}

pub(super) fn native_fragment(p: &Profile) -> vpnte_profiles::emit_singbox::SingBoxFragment {
    match native(p) {
        Upstream::Native { fragment, .. } => fragment,
        _ => unreachable!(),
    }
}

// ---- §7.9 rule order, exclusions, process rules ----

/// AT-02-002: loopback inbound rules; private ranges stay in the TUN; hijack before private.
#[test]
fn inbound_rules_and_exclusions() {
    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    let direct = json!({ "inbound": DIRECT_IN, "outbound": DIRECT_OUT });
    let probe = json!({ "inbound": PROBE_IN, "outbound": PROXY_OUT });
    assert_eq!(index_of(&c, &direct), Some(0));
    assert_eq!(index_of(&c, &probe), Some(1));
    let excluded = tun_in(&c)["route_exclude_address"].as_array().unwrap();
    assert!(excluded.contains(&json!("127.0.0.0/8")));
    for private in ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"] {
        assert!(!excluded.contains(&json!(private)));
    }
    let private = json!({ "ip_is_private": true, "outbound": DIRECT_OUT });
    assert!(index_of(&c, &hijack_dns()).unwrap() < index_of(&c, &private).unwrap());
    let [stun, _] = stun_pins();
    assert!(index_of(&c, &private).unwrap() < index_of(&c, &stun).unwrap());
}

/// AT-02-007: no probe listener (local-proxy mode) -> no `live-check-in` inbound or rule.
#[test]
fn no_probe_listener_without_probe() {
    let mut i = inputs(local_socks());
    i.listeners.probe = None;
    let c = build(&i).unwrap();
    assert!(!c.to_string().contains(PROBE_IN));
}

/// AT-02-002: dialed IP literals leave the TUN routes; hostnames and slots add nothing.
#[test]
fn endpoint_exclusion() {
    let c = build(&inputs(native(&vless("91.224.75.185", None)))).unwrap();
    let excluded = tun_in(&c)["route_exclude_address"].as_array().unwrap();
    assert!(excluded.contains(&json!("91.224.75.185/32")));

    let c = build(&inputs(native(&vless("sub.example.com", None)))).unwrap();
    assert_eq!(
        tun_in(&c)["route_exclude_address"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    // Slot mode excludes no endpoint: routing's P1 rule sends the Xray process direct by path.
    let mut i = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    let xray = json!({
        "process_path_regex": [r"(?i)^C:\\Program Files\\VPN Tunnel Enforcer\\resources\\xray\.exe$"],
        "outbound": DIRECT_OUT,
    });
    i.routing.process_rules = vec![xray.clone()];
    let c = build(&i).unwrap();
    assert_eq!(
        tun_in(&c)["route_exclude_address"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(rules(&c)[2], xray);

    // An IPv6 endpoint is excluded only from a dual-stack TUN.
    let v6 = native(&vless("2001:db8::7", None));
    let c = build(&inputs(v6.clone())).unwrap();
    assert!(!c.to_string().contains("2001:db8::7/128"));
    let mut i = inputs(v6);
    i.capture = Capture::Tun(tun(true, false));
    let c = build(&i).unwrap();
    let excluded = tun_in(&c)["route_exclude_address"].as_array().unwrap();
    assert!(excluded.contains(&json!("2001:db8::7/128")));
}

/// AT-02-002: routing's domain rules land after the DNS hijack and the STUN pin; without them
/// no domain keys appear; routing's process rules come right after the loopback inbound rules,
/// before the QUIC reject. AT-06-008 (regexes, one rule per class) is tested in `routing`.
#[test]
fn routing_rules_placement() {
    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    let text = c.to_string();
    for key in ["\"domain\"", "domain_suffix", "domain_keyword", "rule_set"] {
        assert!(!text.contains(key), "{key}");
    }

    let mut i = inputs(native(&vless("1.2.3.4", None)));
    let domain = json!({ "action": "reject", "method": "default", "no_drop": true, "domain_keyword": ["telegram"] });
    let direct_app =
        json!({ "process_path_regex": [r"(?i)(?:^|\\)MyApp\.exe$"], "outbound": DIRECT_OUT });
    let vpn_app =
        json!({ "process_path_regex": [r"(?i)^C:\\Apps\\chat\.exe$"], "outbound": PROXY_OUT });
    i.routing.domain_rules = vec![domain.clone()];
    i.routing.process_rules = vec![direct_app.clone(), vpn_app.clone()];
    let c = build(&i).unwrap();
    let [_, stun] = stun_pins();
    assert_eq!(
        index_of(&c, &domain),
        Some(index_of(&c, &stun).unwrap() + 1)
    );
    assert_eq!(rules(&c).last(), Some(&domain));
    // 0: mixed-direct-in, 1: live-check-in.
    assert_eq!(index_of(&c, &direct_app), Some(2));
    assert_eq!(index_of(&c, &vpn_app), Some(3));
    assert!(index_of(&c, &vpn_app).unwrap() < index_of(&c, &quic_reject()).unwrap());
}

/// E-D1: the IPv6 reject is a pre-match rule (before `sniff`) and spares private IPv6.
#[test]
fn ipv6_reject_sits_before_sniff() {
    let mut i = inputs(native(&vless("1.2.3.4", None)));
    i.capture = Capture::Tun(tun(true, false));
    let c = build(&i).unwrap();
    let reject = index_of(&c, &ipv6_reject_rule()).unwrap();
    let sniff = index_of(&c, &json!({ "action": "sniff" })).unwrap();
    assert_eq!(reject + 1, sniff);
    assert!(index_of(&c, &quic_reject()).unwrap() < reject);
}

// ---- §7.11 selector / slots ----

/// AT-00-007 / AT-02-002: the selector and both authenticated slot outbounds.
#[test]
fn selector_and_slots() {
    let c = build(&inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    })))
    .unwrap();
    assert_eq!(
        c["outbounds"][0],
        json!({
            "type": "selector", "tag": "proxy-out",
            "outbounds": ["vpnte-upstream-a", "vpnte-upstream-b"],
            "default": "vpnte-upstream-a", "interrupt_exist_connections": true,
        })
    );
    for (n, port, tag) in [(1, 25551, "fixture-a"), (2, 25552, "fixture-b")] {
        let slot = &c["outbounds"][n];
        assert_eq!(slot["type"], "socks");
        assert_eq!(slot["tag"], SLOT_TAGS[n - 1]);
        assert_eq!(slot["version"], "5");
        assert_eq!(slot["server"], "127.0.0.1");
        assert_eq!(slot["server_port"], port);
        assert_eq!(slot["username"], format!("{tag}-user"));
        assert_eq!(slot["password"], format!("{tag}-SYNTHETIC"));
        assert_eq!(slot["udp_fragment"], true);
    }
    assert_eq!(
        c["outbounds"][3],
        json!({ "type": "direct", "tag": "direct-out" })
    );
    assert_eq!(c["route"]["auto_detect_interface"], true);
    assert_eq!(c["route"]["final"], PROXY_OUT);

    let mut i = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    if let Upstream::XraySlots { active, .. } = &mut i.upstream {
        *active = Slot::B;
    }
    assert_eq!(
        build(&i).unwrap()["outbounds"][0]["default"],
        "vpnte-upstream-b"
    );
}

/// AT-00-007: invalid slots are refused (`Invalid authenticated Xray upstream slots`). Missing
/// or oversized credentials and port 0 cannot be built at all (`slot::SlotEndpoint::new`).
#[test]
fn invalid_slots() {
    let mut i = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    if let Upstream::XraySlots { slots, .. } = &mut i.upstream {
        slots[1] = ep(slots[0].port(), "other");
    }
    assert!(matches!(build(&i), Err(ConfigError::InvalidSlots(_))));
    let max = SlotEndpoint::new(
        25552,
        Creds {
            user: "u".into(),
            pass: "p".repeat(255),
        },
    )
    .unwrap();
    if let Upstream::XraySlots { slots, .. } = &mut i.upstream {
        slots[1] = max;
    }
    assert!(build(&i).is_ok());
}

/// AT-02-007: a local SOCKS proxy upstream; credentials are passed when the user set them.
#[test]
fn local_proxy_outbound() {
    let c = build(&inputs(local_socks())).unwrap();
    assert_eq!(
        c["outbounds"][0],
        json!({
            "type": "socks", "tag": "proxy-out", "version": "5", "server": "127.0.0.1",
            "server_port": 10808, "udp_fragment": true,
        })
    );
    let http = Upstream::LocalProxy {
        addr: HostPort::parse("[::1]:1080").unwrap(),
        kind: ProxyKind::Http,
        creds: Some(creds("local")),
    };
    let c = build(&inputs(http)).unwrap();
    assert_eq!(
        c["outbounds"][0],
        json!({
            "type": "http", "tag": "proxy-out", "server": "::1", "server_port": 1080,
            "username": "local-user", "password": "local-SYNTHETIC",
        })
    );
    // A named proxy host resolves directly, never through the proxy it names.
    let named = Upstream::LocalProxy {
        addr: HostPort::parse("proxy.home.arpa:10808").unwrap(),
        kind: ProxyKind::Socks5,
        creds: None,
    };
    let c = build(&inputs(named)).unwrap();
    assert_eq!(
        c["outbounds"][0]["domain_resolver"]["server"],
        DNS_BOOTSTRAP
    );
    assert!(dns_server(&c, DNS_BOOTSTRAP).is_some());
    // `localhost` is this machine: no DNS query a public resolver may not answer.
    let local = Upstream::LocalProxy {
        addr: HostPort::parse("localhost:10808").unwrap(),
        kind: ProxyKind::Http,
        creds: None,
    };
    let c = build(&inputs(local)).unwrap();
    assert_eq!(c["outbounds"][0]["server"], "127.0.0.1");
    assert!(c["outbounds"][0].get("domain_resolver").is_none());
    assert!(dns_server(&c, DNS_BOOTSTRAP).is_none());
}

// ---- §7.12 WireGuard and other native fragments ----

/// AT-04-002 / F-047: WireGuard is an endpoint tagged `proxy-out`; outbounds hold only
/// `direct-out`; a hostname peer resolves through `dns-bootstrap`.
#[test]
fn wireguard_endpoint_config() {
    let c = build(&inputs(native(&wireguard("203.0.113.5")))).unwrap();
    let types: Vec<&str> = c["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["direct"]);
    let ep = &c["endpoints"][0];
    assert_eq!(ep["type"], "wireguard");
    assert_eq!(ep["tag"], PROXY_OUT);
    assert_eq!(ep["address"], json!(["10.0.0.2/32"]));
    assert_eq!(ep["mtu"], 1280);
    assert!(dns_server(&c, DNS_BOOTSTRAP).is_none());
    let excluded = tun_in(&c)["route_exclude_address"].as_array().unwrap();
    assert!(excluded.contains(&json!("203.0.113.5/32")));

    let c = build(&inputs(native(&wireguard("wg.example.com")))).unwrap();
    assert_eq!(
        c["endpoints"][0]["domain_resolver"]["server"],
        DNS_BOOTSTRAP
    );
    assert!(dns_server(&c, DNS_BOOTSTRAP).is_some());
}

/// AT-04-002: a shadowsocks profile is an outbound; no `endpoints` key.
#[test]
fn shadowsocks_has_no_endpoints() {
    let c = build(&inputs(native(&shadowsocks("1.2.3.4")))).unwrap();
    assert!(c.get("endpoints").is_none());
    assert_eq!(c["outbounds"][0]["type"], "shadowsocks");
    assert_eq!(c["outbounds"][0]["tag"], PROXY_OUT);
}

/// A fragment emitted under another tag, or with a hostname server but no bootstrap
/// resolver, would never connect: refused instead of generated.
#[test]
fn unusable_fragments_are_refused() {
    let p = vless("sub.example.com", None);
    let policy = EmitPolicy::default();
    let wrong_tag = vpnte_profiles::emit_singbox::emit_singbox(&p, "proxy", &policy).unwrap();
    let udp = UdpPolicy::of(&p);
    let i = inputs(Upstream::Native {
        fragment: wrong_tag,
        udp,
    });
    assert!(matches!(build(&i), Err(ConfigError::BadUpstream(_))));
    let no_resolver = vpnte_profiles::emit_singbox::emit_singbox(&p, PROXY_OUT, &policy).unwrap();
    let i = inputs(Upstream::Native {
        fragment: no_resolver,
        udp,
    });
    assert!(matches!(build(&i), Err(ConfigError::BadUpstream(_))));
}

// ---- §7.2 listeners, D-8 loopback DNS ----

/// AT-02-002: authenticated loopback inbounds with exactly one user each; the controller.
#[test]
fn loopback_listeners() {
    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    let inbounds = c["inbounds"].as_array().unwrap();
    for (tag, port) in [(DIRECT_IN, 25554), (PROBE_IN, 25555)] {
        let ib = inbounds.iter().find(|i| i["tag"] == tag).unwrap();
        assert_eq!(ib["type"], "mixed");
        assert_eq!(ib["listen"], "127.0.0.1");
        assert_eq!(ib["listen_port"], port);
        assert_eq!(ib["users"].as_array().unwrap().len(), 1);
    }
    assert_eq!(
        c["experimental"],
        json!({ "clash_api": {
            "external_controller": "127.0.0.1:25553",
            "secret": "0123456789abcdef0123456789abcdef",
            "default_mode": "rule",
        } })
    );
}

#[test]
fn listener_ports_and_credentials_are_checked() {
    let base = || {
        inputs(slots(UdpPolicy {
            udp: true,
            block_quic: true,
        }))
    };
    let mut i = base();
    i.listeners.clash_port = 25554;
    assert!(matches!(build(&i), Err(ConfigError::InvalidListeners(_))));
    let mut i = base();
    i.listeners.dns_bootstrap = Some(25551);
    assert!(matches!(build(&i), Err(ConfigError::InvalidListeners(_))));
    let mut i = base();
    i.listeners.direct.creds = None;
    assert!(matches!(build(&i), Err(ConfigError::InvalidListeners(_))));
    let mut i = base();
    i.listeners.probe = Some(Loopback {
        port: 25560,
        creds: Some(Creds {
            user: "u".into(),
            pass: String::new(),
        }),
    });
    assert!(matches!(build(&i), Err(ConfigError::InvalidListeners(_))));
    let mut i = base();
    i.listeners.clash_secret = String::new();
    assert!(matches!(build(&i), Err(ConfigError::InvalidListeners(_))));
    let mut i = base();
    i.listeners.direct.port = 0;
    assert!(matches!(build(&i), Err(ConfigError::InvalidListeners(_))));
}

/// D-8: the loopback DNS inbound for Xray answers through the bootstrap order (DoH by IP
/// literal, TCP, the physical resolver last; ru-2026 Ф9), first in the DNS rules; the inbound
/// rule is first in the route rules.
#[test]
fn dns_bootstrap_inbound() {
    let mut i = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    i.listeners.dns_bootstrap = Some(25556);
    i.phys_dns = vec![Ipv4Addr::new(77, 88, 8, 8)];
    i.routing.dns_rules = vec![json!({ "domain_suffix": [".ru"], "server": "dns-direct" })];
    i.routing.dns_servers =
        vec![json!({ "type": "udp", "tag": "dns-direct", "server": "77.88.8.8" })];
    let c = build(&i).unwrap();
    let ib = c["inbounds"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(
        ib,
        json!({ "type": "direct", "tag": "dns-bootstrap-in", "listen": "127.0.0.1", "listen_port": 25556 })
    );
    assert_eq!(
        rules(&c)[0],
        json!({ "inbound": "dns-bootstrap-in", "action": "hijack-dns" })
    );
    let dns_rules = c["dns"]["rules"].as_array().unwrap();
    assert!(
        dns_rules[..dns_rules.len() - 1]
            .iter()
            .all(|r| r["inbound"] == json!(["dns-bootstrap-in"]))
    );
    assert_eq!(
        dns_rules[0],
        json!({ "inbound": ["dns-bootstrap-in"], "action": "evaluate", "server": "dns-bootstrap", "timeout": "1000ms" })
    );
    assert_eq!(dns_rules.last().unwrap()["server"], "dns-direct");
    assert_eq!(dns_server(&c, DNS_BOOTSTRAP).unwrap()["type"], "https");
    assert_eq!(
        dns_server(&c, "dns-bootstrap-isp").unwrap(),
        &json!({ "type": "udp", "tag": "dns-bootstrap-isp", "server": "77.88.8.8" })
    );
}

// ---- §7.10 Smart RU fragments as placed by the builder ----

/// AT-07-002: rule sets and DNS rules appear only when routing produced them, and routing's
/// rule order is kept verbatim.
#[test]
fn smart_ru_fragments_placement() {
    let c = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    assert!(c["route"].get("rule_set").is_none());
    assert!(c["dns"].get("rules").is_none());
    assert!(dns_server(&c, DNS_DIRECT).is_none());

    let mut i = inputs(native(&vless("1.2.3.4", None)));
    i.routing = smart_ru_parts("C:/rt");
    let c = build(&i).unwrap();
    let sets = c["route"]["rule_set"].as_array().unwrap();
    assert_eq!(sets.len(), 2);
    for s in sets {
        assert_eq!(s["type"], "local");
        assert!(s.get("url").is_none() && s.get("download_detour").is_none());
        assert!(s["path"].as_str().unwrap().ends_with(".srs"));
    }
    // The order inside the fragment (owner order: Smart RU gov rule set above user rules) is
    // routing's; the builder keeps it verbatim, right after the STUN pins.
    let [_, stun] = stun_pins();
    let after_stun = &rules(&c)[index_of(&c, &stun).unwrap() + 1..];
    assert_eq!(after_stun, smart_ru_parts("C:/rt").domain_rules.as_slice());
    assert!(
        index_of(
            &c,
            &json!({ "rule_set": ["geoip-ru"], "outbound": DIRECT_OUT })
        )
        .is_some()
    );
    assert_eq!(dns_server(&c, DNS_DIRECT).unwrap()["server"], "77.88.8.7");
    let dns_rules = c["dns"]["rules"].as_array().unwrap();
    assert!(
        dns_rules
            .iter()
            .any(|r| r.get("rule_set").is_some() && r["server"] == DNS_DIRECT)
    );
}

/// Representative Smart RU fragments (the real ones come from `routing`).
pub(super) fn smart_ru_parts(dir: &str) -> RoutingParts {
    RoutingParts {
        process_rules: Vec::new(),
        domain_rules: vec![
            json!({ "domain": ["2ip.ru"], "domain_suffix": [".2ip.ru"], "outbound": PROXY_OUT }),
            json!({ "rule_set": ["geosite-category-gov-ru"], "outbound": DIRECT_OUT }),
            json!({ "domain_suffix": [".2gis.com", ".2gis.ru"], "outbound": DIRECT_OUT }),
            json!({ "domain": ["bank.example"], "domain_suffix": [".bank.example"], "outbound": DIRECT_OUT }),
            json!({ "rule_set": ["geoip-ru"], "outbound": DIRECT_OUT }),
        ],
        rule_sets: vec![
            json!({ "type": "local", "tag": "geoip-ru", "format": "binary", "path": format!("{dir}/geoip-ru.srs") }),
            json!({ "type": "local", "tag": "geosite-category-gov-ru", "format": "binary", "path": format!("{dir}/geosite-category-gov-ru.srs") }),
        ],
        dns_servers: vec![json!({ "type": "udp", "tag": "dns-direct", "server": "77.88.8.7" })],
        dns_rules: vec![
            json!({ "domain": ["2ip.ru"], "domain_suffix": [".2ip.ru"], "server": DNS_REMOTE }),
            json!({ "rule_set": ["geosite-category-gov-ru"], "server": DNS_DIRECT }),
            json!({ "domain_suffix": [".ru", ".su", ".xn--p1ai"], "server": DNS_DIRECT }),
        ],
        listed_only: None,
        proxy_bypass: Vec::new(),
    }
}

// ---- §3.19 compatibility key ----

/// AT-02-011: the key ignores ports, secrets, slot identity and the alias, and changes with
/// every setting that changes the JSON.
#[test]
fn compat_key_scope() {
    let base = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    let key = compat_key(&base);
    assert_eq!(key, compat_key(&base.clone()));

    let mut same = base.clone();
    same.listeners.clash_port = 30000;
    same.listeners.clash_secret = "ffffffffffffffffffffffffffffffff".into();
    same.listeners.direct = lb(30001, "other");
    tun_of(&mut same).alias = "Ethernet 9".into();
    same.upstream = Upstream::XraySlots {
        slots: [ep(31000, "x"), ep(31001, "y")],
        active: Slot::B,
        udp: UdpPolicy {
            udp: true,
            block_quic: true,
        },
    };
    assert_eq!(compat_key(&same), key);

    let changes: [fn(&mut ConfigInputs); 14] = [
        |i| tun_of(i).mtu = 1280,
        |i| tun_of(i).ipv6 = true,
        |i| tun_of(i).dns_hijack = false,
        |i| tun_of(i).stack = TunStack::Gvisor,
        |i| {
            let curl = json!({ "process_path_regex": [r"(?i)(?:^|\\)curl\.exe$"], "outbound": DIRECT_OUT });
            i.routing.process_rules.push(curl);
        },
        |i| i.routing = smart_ru_parts("C:/rt"),
        |i| i.phys_dns.push(Ipv4Addr::new(77, 88, 8, 8)),
        |i| i.listeners.probe = None,
        |i| i.listeners.dns_bootstrap = Some(26000),
        |i| {
            i.upstream = slots(UdpPolicy {
                udp: true,
                block_quic: false,
            })
        },
        |i| i.upstream = local_socks(),
        |i| i.upstream = native(&vless("1.2.3.4", None)),
        // speed3 S3-10: the apps page's scope and «Не через прокси» count too.
        |i| i.routing.listed_only = Some(vec![r"(?i)(?:^|\\)browser\.exe$".into()]),
        |i| {
            let rule = json!({ "domain_suffix": ["example.org"], "outbound": DIRECT_OUT });
            i.routing.proxy_bypass.push(rule);
        },
    ];
    for (n, change) in changes.iter().enumerate() {
        let mut i = base.clone();
        change(&mut i);
        assert_ne!(compat_key(&i), key, "change #{n}");
    }
}

/// speed3 S3-10 (security review), both ways: the key and the full render decide alike. Under
/// both captures every routing input that changes the JSON changes the key (none is left out, as
/// the apps page's scope and «Не через прокси» once were); what only names the upstream or the
/// app's own ports changes the JSON but never the key.
#[test]
fn the_key_and_the_render_decide_alike() {
    let up = || {
        slots(UdpPolicy {
            udp: true,
            block_quic: true,
        })
    };
    let rule = || json!({ "domain_suffix": ["example.org"], "outbound": DIRECT_OUT });
    let routing: [fn(&mut RoutingParts, Value); 7] = [
        |r, v| r.process_rules.push(v),
        |r, v| r.domain_rules.push(v),
        |r, _| r.rule_sets = smart_ru_parts("C:/rt").rule_sets,
        |r, _| r.dns_servers = vec![json!({ "type": "local", "tag": "dns-local" })],
        |r, _| r.dns_rules = vec![json!({ "domain_suffix": [".example"], "server": DNS_DIRECT })],
        |r, _| r.listed_only = Some(vec!["own".into()]),
        |r, v| r.proxy_bypass.push(v),
    ];
    for base in [inputs(up()), super::proxy_tests::proxied(inputs(up()))] {
        let (json, key) = (build(&base).expect("base"), compat_key(&base));
        let mut rendered = 0;
        for (n, change) in routing.iter().enumerate() {
            let mut i = base.clone();
            change(&mut i.routing, rule());
            if build(&i).is_ok_and(|changed| changed != json) {
                rendered += 1;
                assert_ne!(compat_key(&i), key, "routing change #{n} shapes the JSON");
            }
        }
        assert!(rendered >= 6, "{rendered} of the changes shaped the JSON");
        let mut identity = base.clone();
        identity.upstream = Upstream::XraySlots {
            slots: [ep(31000, "x"), ep(31001, "y")],
            active: Slot::B,
            udp: UdpPolicy {
                udp: true,
                block_quic: true,
            },
        };
        identity.listeners.clash_port = 30000;
        assert_ne!(build(&identity).expect("identity"), json);
        assert_eq!(
            compat_key(&identity),
            key,
            "identity and ports do not count"
        );
    }
}

// ---- errors (locale fragments: `crate::test_locales`) ----

#[test]
fn config_error_is_internal_with_a_message() {
    let e = AppError::from(ConfigError::InvalidSlots("slot port 0"));
    assert_eq!(e.kind, ErrorKind::Internal);
    assert_eq!(e.user_msg().key, "engine.config.invalid");
}
