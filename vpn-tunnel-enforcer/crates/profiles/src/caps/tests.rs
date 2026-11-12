use serde_json::{Map, json};

use super::*;
use crate::model::{DialPrefs, Ech, Host, Hy2Obfs, Reality, ShadowTlsLayer, Source, SsPlugin, Tls};

fn profile(kind: Kind, tls: Option<Tls>) -> Profile {
    Profile {
        name: "test".into(),
        description: None,
        server: Host::Domain("h.example".into()),
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

fn tls(server_name: &str) -> Tls {
    Tls {
        server_name: Some(server_name.into()),
        ..Tls::default()
    }
}

fn naive() -> Kind {
    Kind::Naive {
        username: "user".into(),
        password: "pass".into(),
        quic: false,
        extra_headers: vec![],
        insecure_concurrency: None,
    }
}

fn hy2(obfs: Option<Hy2Obfs>) -> Kind {
    Kind::Hysteria2 {
        password: "secret".into(),
        obfs,
        ports: vec![],
        hop_interval_s: None,
        hop_interval_max_s: None,
        up_mbps: None,
        down_mbps: None,
        bbr_profile: None,
    }
}

fn vless() -> Kind {
    Kind::Vless {
        uuid: "00000000-0000-4000-8000-000000000000".into(),
        flow: None,
        packet_encoding: None,
        encryption: None,
    }
}

fn keys(c: &Capabilities) -> Vec<&str> {
    c.notes.iter().map(|m| m.key.as_ref()).collect()
}

/// §7.1 "caps naive-ech": `{protocol: naive, stealthPreset: naive-ech, tlsConfigured: true,
/// echConfigured: true, warnings: []}`; the Rust preset is `Ech`.
#[test]
fn naive_with_ech() {
    let ech = Ech {
        config_lines: vec!["abc".into()],
        query_server_name: None,
    };
    let c = capabilities(&profile(
        naive(),
        Some(Tls {
            ech: Some(ech),
            ..tls("front.example.com")
        }),
    ));
    assert_eq!(
        (c.protocol, c.stealth, c.tls, c.ech),
        ("naive", Stealth::Ech, true, true)
    );
    assert!(c.notes.is_empty());
    let plain_naive = capabilities(&profile(naive(), Some(tls("front.example.com"))));
    assert_eq!(
        (plain_naive.stealth, plain_naive.ech),
        (Stealth::Naive, false)
    );
}

/// §7.1 "caps HY2 tcp": obfs preset and the tcp-only warning. CHANGED: `tls` is true (old:
/// `tlsConfigured false`): the outbound has no `tls` block, but sing-box refuses Hysteria2
/// without TLS and the emitter adds it.
#[test]
fn hysteria2_obfs_on_tcp_only_routing() {
    // Older imports saved `network: tcp` on Hysteria2; the emitter drops it, so no hint.
    let mut p = profile(
        hy2(Some(Hy2Obfs {
            kind: "salamander".into(),
            password: "pepper".into(),
        })),
        None,
    );
    p.singbox_extra.insert("network".into(), json!("tcp"));
    let c = capabilities(&p);
    assert_eq!(
        (c.protocol, c.stealth, c.tls),
        ("hysteria2", Stealth::Obfs, true)
    );
    assert!(keys(&c).is_empty(), "{:?}", keys(&c));
    // TUIC keeps the key: the hint stays.
    let mut tuic = profile(
        Kind::Tuic {
            uuid: "00000000-0000-4000-8000-000000000000".into(),
            password: "pass".into(),
            congestion: None,
            udp_relay_mode: None,
            zero_rtt: false,
            heartbeat_s: None,
        },
        Some(tls("t.example")),
    );
    tuic.singbox_extra.insert("network".into(), json!("tcp"));
    assert_eq!(keys(&capabilities(&tuic)), ["profiles.caps.udpOnTcpOnly"]);
}

/// Pasted or legacy outbounds without a `tls` block: the summary describes the TLS the emitter
/// adds, not "no camouflage", and AnyTLS is not called unencrypted.
#[test]
fn tls_mandatory_protocols_without_a_tls_block() {
    let tuic = Kind::Tuic {
        uuid: "00000000-0000-4000-8000-000000000000".into(),
        password: "p".into(),
        congestion: None,
        udp_relay_mode: None,
        zero_rtt: false,
        heartbeat_s: None,
    };
    let c = capabilities(&profile(tuic, None));
    assert_eq!((c.stealth, c.tls), (Stealth::Tls, true));
    assert!(c.notes.is_empty());
    assert_eq!(
        capabilities(&profile(hy2(None), None)).stealth,
        Stealth::Tls
    );
    let anytls = Kind::Anytls {
        password: "p".into(),
        idle_check_s: None,
        idle_timeout_s: None,
        min_idle: None,
    };
    let c = capabilities(&profile(anytls, None));
    assert_eq!((c.stealth, c.tls), (Stealth::Utls, true));
    assert_eq!(keys(&c), ["profiles.caps.defaultFingerprint"]);
    let trojan = Kind::Trojan {
        password: "p".into(),
    };
    let c = capabilities(&profile(trojan, None));
    assert_eq!((c.stealth, c.tls), (Stealth::Plain, false));
    assert_eq!(keys(&c), ["profiles.caps.note.unencrypted"]);
}

/// P-01 / P-03: QUIC gets plain TLS (provider fingerprint dropped), a pin is not enforced.
#[test]
fn hysteria2_tls_pin_and_fingerprint() {
    let t = Tls {
        insecure: true,
        fingerprint: Some("chrome".into()),
        cert_pin_sha256: Some("ab".repeat(32)),
        alpn: vec!["h3".into()],
        ..tls("s.example")
    };
    let c = capabilities(&profile(hy2(None), Some(t)));
    assert_eq!((c.stealth, c.tls), (Stealth::Tls, true));
    assert_eq!(
        keys(&c),
        [
            "profiles.caps.insecure",
            "profiles.caps.note.certPinNotEnforced",
            "profiles.caps.note.fingerprintDroppedOnQuic"
        ]
    );
}

#[test]
fn reality_and_tcp_tls_use_a_fingerprint() {
    let reality = Tls {
        reality: Some(Reality {
            public_key: "pbk".into(),
            short_id: "1234".into(),
            spider_x: None,
        }),
        ..tls("www.example.com")
    };
    let c = capabilities(&profile(vless(), Some(reality.clone())));
    assert_eq!(
        (c.stealth, keys(&c)),
        (Stealth::Reality, vec!["profiles.caps.defaultFingerprint"])
    );
    let own = Tls {
        fingerprint: Some("firefox".into()),
        ..reality
    };
    assert!(
        capabilities(&profile(vless(), Some(own.clone())))
            .notes
            .is_empty()
    );
    // REALITY verifies by key: an `allowInsecure` in the link changes nothing, so no warning.
    let insecure = Tls {
        insecure: true,
        ..own
    };
    assert!(
        capabilities(&profile(vless(), Some(insecure)))
            .notes
            .is_empty()
    );

    let trojan = Kind::Trojan {
        password: "p".into(),
    };
    let c = capabilities(&profile(
        trojan,
        Some(Tls {
            insecure: true,
            ..tls("x.example")
        }),
    ));
    assert_eq!(c.stealth, Stealth::Utls);
    assert_eq!(
        keys(&c),
        ["profiles.caps.insecure", "profiles.caps.defaultFingerprint"]
    );

    let mut quic_transport = profile(vless(), Some(tls("x.example")));
    quic_transport.transport = Some(Transport::Quic);
    assert_eq!(capabilities(&quic_transport).stealth, Stealth::Tls);
}

/// Naive never gets `insecure` from the emitter: the note says so instead of a false warning.
#[test]
fn naive_insecure_is_explained_not_warned() {
    let mut p = profile(
        naive(),
        Some(Tls {
            insecure: true,
            ..tls("front.example.com")
        }),
    );
    p.notes.push(Note::NaiveInsecureIgnored);
    assert_eq!(
        keys(&capabilities(&p)),
        ["profiles.caps.note.naiveInsecureIgnored"]
    );
    p.notes.clear();
    assert_eq!(
        keys(&capabilities(&p)),
        ["profiles.caps.note.naiveInsecureIgnored"]
    );
}

#[test]
fn unencrypted_and_obfuscated_shadowsocks() {
    let socks = capabilities(&profile(
        Kind::Socks {
            username: None,
            password: None,
        },
        None,
    ));
    assert_eq!(
        (socks.stealth, keys(&socks)),
        (Stealth::Plain, vec!["profiles.caps.note.unencrypted"])
    );
    let mut vless_plain = profile(vless(), None);
    vless_plain.notes.push(Note::Unencrypted);
    assert_eq!(
        keys(&capabilities(&vless_plain)),
        ["profiles.caps.note.unencrypted"]
    );

    let ss = |plugin, shadowtls| Kind::Shadowsocks {
        method: "aes-256-gcm".into(),
        password: "p".into(),
        plugin,
        shadowtls,
        uot: None,
    };
    let plugin = SsPlugin {
        name: "obfs-local".into(),
        opts: "obfs=http".into(),
    };
    assert_eq!(
        capabilities(&profile(ss(Some(plugin), None), None)).stealth,
        Stealth::Obfs
    );
    let layer = ShadowTlsLayer {
        version: 3,
        password: "p".into(),
        server_name: "front.example.com".into(),
    };
    let c = capabilities(&profile(ss(None, Some(layer)), None));
    assert_eq!(
        (c.stealth, c.tls, keys(&c)),
        (
            Stealth::Utls,
            true,
            vec!["profiles.caps.defaultFingerprint"]
        )
    );
    assert!(
        capabilities(&profile(ss(None, None), None))
            .notes
            .is_empty()
    );
}

#[test]
fn note_messages() {
    let m = note_msg(&Note::AlterIdNormalized(64));
    assert_eq!(
        (m.key.as_ref(), m.args[0].1.as_str()),
        ("profiles.caps.note.alterIdNormalized", "64")
    );
    let m = note_msg(&Note::UnsupportedField("tls.fragment".into()));
    assert_eq!(m.args[0], ("field".into(), "tls.fragment".to_owned()));
    assert_eq!(
        note_msg(&Note::Other("profiles.caps.insecure".into())).key,
        "profiles.caps.insecure"
    );
}

/// Every key this module returns is localized and the `profiles-text` fragment holds nothing else.
#[test]
fn locale_fragments_cover_every_key() {
    let stealth = [
        Stealth::Reality,
        Stealth::Ech,
        Stealth::Naive,
        Stealth::Obfs,
        Stealth::Utls,
        Stealth::Tls,
        Stealth::Plain,
    ];
    let notes = [
        Note::NaiveInsecureIgnored,
        Note::CertPinNotEnforced,
        Note::AlterIdNormalized(1),
        Note::ProviderFpDroppedOnQuic,
        Note::UnsupportedField("f".into()),
        Note::FileReferenceDropped("f".into()),
        Note::DialFieldDropped("f".into()),
        Note::Unencrypted,
        Note::MuxSingBoxOnly,
    ];
    let used: Vec<String> = stealth
        .iter()
        .map(|s| s.msg())
        .chain(notes.iter().map(note_msg))
        .chain(skip_reasons().iter().map(skip_msg))
        .map(|m| m.key.into_owned())
        .chain(
            [
                "profiles.caps.insecure",
                "profiles.caps.udpOnTcpOnly",
                "profiles.caps.defaultFingerprint",
            ]
            .map(String::from),
        )
        .collect();
    for key in &used {
        crate::test_locales::assert_localized(key);
    }
    let used: std::collections::BTreeSet<String> = used.into_iter().collect();
    assert_eq!(used, crate::test_locales::package_keys("profiles-text"));
}

fn skip_reasons() -> Vec<SkipReason> {
    vec![
        SkipReason::UnknownScheme(String::new()),
        SkipReason::UnknownScheme("ssr".into()),
        SkipReason::Invalid {
            scheme: "vless".into(),
            detail: "invalid port".into(),
        },
        SkipReason::MissingCredential,
        SkipReason::ShadowTlsNeedsInner,
        SkipReason::UnsupportedPlugin("kcptun".into()),
        SkipReason::UnsupportedTransport("kcp".into()),
        SkipReason::Duplicate,
        SkipReason::NativeGraphRejected("cyclic outbound chain".into()),
    ]
}

/// Skipped entries map to i18n keys; the scheme, detail and names travel as arguments.
#[test]
fn skip_reasons_have_messages() {
    let msgs: Vec<Msg> = skip_reasons().iter().map(skip_msg).collect();
    assert_eq!(msgs[0].key, "profiles.caps.skip.notAKey");
    assert_eq!(msgs[1].key, "profiles.caps.skip.unknownScheme");
    assert_eq!(msgs[1].args, [("scheme".into(), "ssr".to_owned())]);
    assert_eq!(msgs[2].args.len(), 2);
    assert_eq!(
        msgs[8].args,
        [("reason".into(), "cyclic outbound chain".to_owned())]
    );
}

/// AmneziaWG: obfuscated, no TLS, and the summary says first that no bundled engine runs it;
/// parameters that cannot work are listed too. Its skip reasons have messages of their own.
#[test]
fn amneziawg_capabilities() {
    use crate::model::{Awg, AwgGeneration, WireGuard};
    let wg = WireGuard {
        private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
        local_address: vec!["10.8.1.2/32".parse().expect("net")],
        mtu: None,
        dns: vec![],
        peers: vec![],
    };
    let mut awg = Awg {
        generation: AwgGeneration::V2_0,
        jc: Some(4),
        ..Awg::default()
    };
    let kind = |awg: &Awg| Kind::Amneziawg {
        wg: wg.clone(),
        awg: Box::new(awg.clone()),
    };
    let c = capabilities(&profile(kind(&awg), None));
    assert_eq!(
        (c.protocol, c.stealth, c.tls),
        ("amneziawg", Stealth::Obfs, false)
    );
    assert_eq!(keys(&c), ["profiles.awg.noEngine"]);
    assert_eq!(c.notes[0].args, [("generation".into(), "2.0".to_owned())]);
    awg.jc = Some(500);
    let c = capabilities(&profile(kind(&awg), None));
    assert_eq!(keys(&c), ["profiles.awg.noEngine", "profiles.awg.invalid"]);
    assert_eq!(c.notes[1].args, [("fields".into(), "Jc".to_owned())]);

    let unsupported = skip_msg(&SkipReason::UnsupportedProtocol("OpenVPN".into()));
    assert_eq!(
        unsupported.args,
        [("protocol".into(), "OpenVPN".to_owned())]
    );
    for key in [&unsupported.key, &c.notes[0].key, &c.notes[1].key] {
        crate::test_locales::assert_localized(key);
    }
}
