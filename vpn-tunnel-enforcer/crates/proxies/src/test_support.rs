//! Test fixtures shared by the packages' tests: profiles with fake credentials and a healthy
//! slot status.
use serde_json::Map;
use vpnte_base::types::UnixMs;
use vpnte_profiles::model::{DialPrefs, Host, Kind, Profile, Source, Tls, WgPeer, WireGuard};

use crate::model::{Health, InstanceStatus, Lifecycle};
use crate::slot::{Slot, loopback_url};

/// A profile with nothing but its endpoint and protocol.
pub(crate) fn profile(server: Host, port: u16, kind: Kind) -> Profile {
    Profile {
        name: "test".into(),
        description: None,
        server,
        port,
        kind,
        tls: None,
        transport: None,
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: Map::new(),
        source: Source::Json,
        notes: Vec::new(),
    }
}

/// The old fixture profile (spec §7): VLESS + TLS on port 443 to `server` (an IP or a host
/// name). Fake UUID.
pub(crate) fn vless(server: &str) -> Profile {
    let host = server
        .parse()
        .map_or_else(|_| Host::Domain(server.into()), Host::Ip);
    let kind = Kind::Vless {
        uuid: "00000000-0000-4000-8000-000000000001".into(),
        flow: None,
        packet_encoding: None,
        encryption: None,
    };
    Profile {
        tls: Some(Tls::default()),
        ..profile(host, 443, kind)
    }
}

/// WireGuard to `203.0.113.20:51820` with one peer at `peer` and fake all-zero keys.
pub(crate) fn wireguard(peer: Host) -> Profile {
    let zero_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
    let wg = WireGuard {
        private_key: zero_key.clone(),
        local_address: vec!["10.66.0.2/32".parse().unwrap()],
        mtu: None,
        dns: Vec::new(),
        peers: vec![WgPeer {
            host: peer,
            port: 51820,
            public_key: zero_key,
            pre_shared_key: None,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            keepalive_s: None,
            reserved: None,
        }],
    };
    let server = Host::Ip("203.0.113.20".parse().unwrap());
    profile(server, 51820, Kind::Wireguard(wg))
}

/// A running, freshly probed, healthy slot exiting through `ip`.
pub(crate) fn healthy_instance(slot: u64, ip: &str, now: UnixMs) -> InstanceStatus {
    let slot = Slot::new(slot).unwrap();
    let port = slot.default_port();
    InstanceStatus {
        process_running: true,
        health: Health::Healthy,
        state: Lifecycle::Ready,
        generation: 1,
        egress_ip: Some(ip.parse().unwrap()),
        latency_ms: Some(123),
        last_checked_at: Some(now - 1_000),
        last_success_at: Some(now - 1_000),
        egress_checked_at: Some(now - 1_000),
        port: Some(port),
        proxy_url: Some(loopback_url(port)),
        profile_id: Some(format!("profile-{slot}")),
        pid: Some(1000 + u32::from(slot.get())),
        ..InstanceStatus::stopped(slot)
    }
}

/// A provider's sing-box outbound with a TLS spoof (audit item 18; fake values, documentation
/// address).
pub(crate) fn spoofed() -> Profile {
    let doc = serde_json::json!({ "outbounds": [{
        "type": "trojan", "tag": "Spoofed", "server": "203.0.113.12", "server_port": 443,
        "password": "fake-password",
        "tls": { "enabled": true, "server_name": "example.com",
                 "spoof": "decoy.example", "spoof_method": "wrong-sequence" }
    }]});
    let report = vpnte_profiles::json::parse_json(&doc);
    report.profiles.into_iter().next().expect("one profile")
}
