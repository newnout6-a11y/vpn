//! `parse_text` / `parse_body` against the profiles spec §7 vectors that run through the whole
//! text pipeline. Values are synthetic.
use base64::Engine as _;
use std::collections::HashSet;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use vpnte_profiles::model::{Host, Kind, ParseReport, SkipReason, Transport};

use super::*;

const VLESS: &str =
    "vless://00000000-0000-4000-8000-000000000000@vless.example.com:443?security=tls#VLESS";
const TUIC: &str = "tuic://550e8400-e29b-41d4-a716-446655440000:secret@tuic.example.com:443?sni=front.example.com&congestion_control=bbr&udp_relay_mode=native#TUIC";
const NAIVE: &str = "naive://user:pass@naive.example.com:443?sni=front.example.com#Naive%20Node";

fn parse(input: &str) -> ParseReport {
    parse_text(input).expect("within the size limit")
}

fn names(report: &ParseReport) -> Vec<&str> {
    report.profiles.iter().map(|p| p.name.as_str()).collect()
}

fn reasons(report: &ParseReport) -> Vec<&SkipReason> {
    report.skipped.iter().map(|s| &s.reason).collect()
}

/// §7.1 "mixed lines": protocols in document order.
#[test]
fn mixed_lines_keep_their_order() {
    let report = parse(&format!("{VLESS}\n{TUIC}\n{NAIVE}"));
    let labels: Vec<_> = report.profiles.iter().map(|p| p.kind.label()).collect();
    assert_eq!(labels, ["vless", "tuic", "naive"]);
    assert!(report.skipped.is_empty());
}

/// §7.1 "WG in prose": links inside a chat message, one per protocol alias.
#[test]
fn links_in_prose() {
    let report = parse(
        "Check out: wireguard://cGFzc3dvcmQxMjM=@wg.example.com:51820?publicKey=cHVibGljS2V5MTIz&ip=10.0.0.2#MyWG \
         and wg://cGFzc3dvcmQxMjM=@wg2.example.com:51820?publicKey=cHVibGljS2V5MTIz&ip=10.0.0.3#WG2",
    );
    assert_eq!(names(&report), ["MyWG", "WG2"]);
    assert!(report.profiles.iter().all(|p| p.port == 51820));
}

/// §7.1 "passwordless": nothing imported, each line reported with its reason.
#[test]
fn passwordless_links_are_reported() {
    for line in [
        "trojan://@trojan.example.com:443?sni=front.example.com#Trojan",
        "hy2://hy2.example.com:443?sni=front.example.com#HY2",
        "anytls://any.example.com:443?sni=front.example.com#AnyTLS",
    ] {
        let report = parse(line);
        assert!(report.profiles.is_empty(), "{line}");
        assert_eq!(reasons(&report), [&SkipReason::MissingCredential], "{line}");
    }
    let report =
        parse("shadowtls://shadow.example.com:443?version=3&sni=front.example.com#ShadowTLS");
    assert!(report.profiles.is_empty());
    assert_eq!(reasons(&report), [&SkipReason::ShadowTlsNeedsInner]);
}

/// P-24 / P-25: a key without a credential is reported; a raw space in a name stays a name.
#[test]
fn missing_credential_and_raw_space_name() {
    let report = parse("vless://@h.example:443?security=tls");
    assert!(report.profiles.is_empty());
    assert_eq!(reasons(&report), [&SkipReason::MissingCredential]);
    assert_eq!(report.skipped[0].excerpt, "vless://h.example:443");

    let report = parse(
        "vless://00000000-0000-4000-8000-000000000000@h.example:443?security=tls#Germany (1)",
    );
    assert_eq!(names(&report), ["Germany (1)"]);
    assert!(report.skipped.is_empty());
}

/// §7.3 identity/dedup: the same key twice under two names is one server.
#[test]
fn same_key_twice_is_one_profile() {
    let a = "vless://00000000-0000-4000-8000-000000000000@h.example:443?security=tls#First";
    let b = "vless://00000000-0000-4000-8000-000000000000@h.example:443?security=tls#Second";
    let report = parse(&format!("{a}\n{b}"));
    assert_eq!(names(&report), ["First"]);
    assert_eq!(reasons(&report), [&SkipReason::Duplicate]);
    assert_eq!(report.skipped[0].excerpt, "vless://h.example:443");
}

/// P-15: a CRLF body with a blank line keeps every key (the old header split cut it).
#[test]
fn crlf_body_with_blank_lines() {
    let body = "vless://00000000-0000-4000-8000-000000000001@a.example:443?security=tls#A\r\n\r\n\
                vless://00000000-0000-4000-8000-000000000002@b.example:443?security=tls#B\r\n";
    let report = parse_body(body.as_bytes()).expect("small body");
    assert_eq!(names(&report), ["A", "B"]);
}

/// AT-04-003 / P-14: `base64(base64(<3 URI lines>))` gives the same 3 profiles as the lines.
#[test]
fn nested_base64_reaches_the_list() {
    let lines = format!("{VLESS}\n{TUIC}\n{NAIVE}");
    let plain = parse(&lines);
    assert_eq!(plain.profiles.len(), 3);
    let twice = STANDARD.encode(STANDARD.encode(&lines));
    assert_eq!(parse(&twice).profiles, plain.profiles);
    let wrapped = URL_SAFE_NO_PAD.encode(&lines);
    assert_eq!(parse(&wrapped).profiles, plain.profiles);
}

/// A Happ body: metadata lines, then a base64 list; metadata inside the decoded layer counts too,
/// the outer lines win.
#[test]
fn body_metadata_outer_and_inner() {
    let inner = format!("#profile-title: Inner\n#support-url: https://help.example\n{VLESS}\n");
    let body = format!(
        "#profile-title: Provider\r\n#profile-update-interval: 6\r\n{}\r\n",
        STANDARD.encode(inner)
    );
    let report = parse_body(body.as_bytes()).expect("small body");
    assert_eq!(names(&report), ["VLESS"]);
    assert_eq!(report.meta.title.as_deref(), Some("Provider"));
    assert_eq!(report.meta.refresh_hours, Some(6));
    assert_eq!(
        report.meta.support_url.as_deref(),
        Some("https://help.example/")
    );
}

/// Nothing recognisable: an empty report that still carries the metadata.
#[test]
fn nothing_recognisable() {
    let report = parse("#profile-title: Empty\nhello world\n");
    assert!(report.profiles.is_empty() && report.skipped.is_empty());
    assert_eq!(report.meta.title.as_deref(), Some("Empty"));
    assert_eq!(
        no_profiles(&report).user_msg().key,
        "servers.parse.nothingFound"
    );
}

/// AT-04-005 / §7.2 "happ add list": the deep link carries a base64 list; its first key is taken.
#[test]
fn happ_add_with_a_list() {
    let list = "vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One\n\
                # comment\n\
                trojan://secret@two.example.com:443?sni=front.example.com#Two";
    let report = parse(&format!("happ://add/{}", URL_SAFE_NO_PAD.encode(list)));
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(
        report.profiles[0].server,
        Host::Domain("one.example.com".into())
    );
}

/// AT-04-005 / §7.2 "happ unwrap" through the pipeline: a carried key is parsed; a carried
/// subscription URL and links that cannot be unwrapped come back as one skipped entry that never
/// shows the payload.
#[test]
fn deep_links() {
    let report = parse(
        "happ://add/vless%3A%2F%2F00000000-0000-4000-8000-000000000000%40h.example%3A443%3Fsecurity%3Dtls%23Key",
    );
    assert_eq!(names(&report), ["Key"]);

    for (link, excerpt) in [
        (
            "happ://add/https%3A%2F%2Fsosa.example%2Fsub%2Fabc123",
            "happ://add/…",
        ),
        ("happ://add/https://example.com/sub/xyz", "happ://add/…"),
        (
            "happ://add/aHR0cHM6Ly9leGFtcGxlLmNvbS9zdWIvYWJjMTIz",
            "happ://add/…",
        ),
        // P-22: `{"url": …}` payload.
        (
            "happ://add/eyJ1cmwiOiJodHRwczovL3N1Yi5leGFtcGxlLmNvbS9zIn0",
            "happ://add/…",
        ),
        ("happ://crypt3/AAAA", "happ://crypt3/…"),
        ("happ://crypt5/AAAA", "happ://crypt5/…"),
        ("happ://routing/onadd/AAAA", "happ://routing/…"),
        ("happ://weird/something", "happ://weird/…"),
        ("happ://add/not-a-key-at-all", "happ://add/…"),
        (
            "MANTARAY://crypt/super-secret-payload",
            "mantaray://crypt/…",
        ),
    ] {
        let report = parse(link);
        assert!(report.profiles.is_empty(), "{link}");
        let [skipped] = report.skipped.as_slice() else {
            panic!("{link}: {:?}", report.skipped)
        };
        assert_eq!(skipped.excerpt, excerpt, "{link}");
        let SkipReason::Invalid { scheme, detail } = &skipped.reason else {
            panic!("{link}: {:?}", skipped.reason)
        };
        assert!(
            link.to_ascii_lowercase().starts_with(scheme.as_str()),
            "{link}"
        );
        for secret in [
            "sosa",
            "abc123",
            "xyz",
            "sub.example",
            "AAAA",
            "something",
            "super-secret",
        ] {
            assert!(!detail.contains(secret), "{link}: {detail}");
        }
    }
}

/// AT-04-001 / P-04: unbalanced brackets cost one pass; a document behind garbage is still found.
#[test]
fn bracket_bombs_are_linear() {
    for bomb in ["{".repeat(80_000), "[".repeat(80_000)] {
        let started = std::time::Instant::now();
        let report = parse(&bomb);
        assert!(report.profiles.is_empty());
        // Generous for an unoptimised test build; the old scanner needed close to a minute.
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }
    let report = parse(
        r#"garbage { x {"type":"trojan","server":"192.0.2.1","server_port":443,"password":"p"}"#,
    );
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].kind.label(), "trojan");
}

/// P-14: a sing-box document followed by a share link yields both.
#[test]
fn json_document_then_link() {
    let doc = r#"{"outbounds":[{"type":"trojan","tag":"T","server":"192.0.2.1","server_port":443,"password":"p"}]}"#;
    let report = parse(&format!("{doc}\n{VLESS}\n"));
    let labels: Vec<_> = report.profiles.iter().map(|p| p.kind.label()).collect();
    assert_eq!(labels, ["trojan", "vless"]);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
}

/// §7.2 smoke: links inside a JSON wrapper and inside a sentence.
#[test]
fn links_in_json_and_sentences() {
    let trojan = "trojan://secret@two.example.com:443?sni=front.example.com#Two";
    let report = parse(&format!(r#"{{"ok":true,"links":["{VLESS}","{trojan}"]}}"#));
    assert_eq!(names(&report), ["VLESS", "Two"]);
    let report = parse(&format!("prefix <{VLESS}>, suffix"));
    assert_eq!(names(&report), ["VLESS"]);
}

/// AT-04-006 / §2.7 endpoints (verifier): a sing-box WireGuard endpoint is a real `wireguard`
/// profile.
#[test]
fn singbox_wireguard_endpoint() {
    let doc = r#"{"outbounds":[{"type":"direct","tag":"direct"}],
        "endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],
        "private_key":"cGFzc3dvcmQxMjM=","peers":[{"address":"wg.example","port":51820,
        "public_key":"cHVibGljS2V5MTIz","allowed_ips":["0.0.0.0/0"]}]}]}"#;
    let report = parse(doc);
    assert_eq!(report.profiles.len(), 1, "{:?}", report.skipped);
    assert_eq!(report.profiles[0].kind.label(), "wireguard");
}

/// P-23 (verifier): a column-0 Clash list; trojan is always TLS with the server as SNI.
#[test]
fn clash_column_zero() {
    let report = parse(
        "proxies:\n- name: c0\n  type: trojan\n  server: t.example\n  port: 443\n  password: p\n",
    );
    assert_eq!(names(&report), ["c0"]);
    let tls = report.profiles[0].tls.as_ref().expect("trojan is TLS");
    assert_eq!(tls.server_name.as_deref(), Some("t.example"));
}

/// §7.2 smoke: a Clash VLESS REALITY block inside a whole mihomo config, next to a share link.
#[test]
fn clash_reality_block_and_link() {
    let yaml = format!(
        "mixed-port: 7890\nproxies:\n  - name: \"R\"\n    type: vless\n    server: r.example.com\n    port: 443\n    \
         uuid: 00000000-0000-4000-8000-000000000003\n    network: tcp\n    tls: true\n    \
         servername: www.example.com\n    flow: xtls-rprx-vision\n    client-fingerprint: chrome\n    \
         reality-opts:\n      public-key: SYNTHETIC_PUBLIC_KEY_0000000000000000000000\n      short-id: \"0123\"\n\
         proxy-groups:\n  - name: auto\n    type: select\n    proxies: [R]\n{VLESS}\n"
    );
    let report = parse(&yaml);
    assert_eq!(names(&report), ["R", "VLESS"], "{:?}", report.skipped);
    let reality = report.profiles[0]
        .tls
        .as_ref()
        .and_then(|t| t.reality.as_ref());
    assert_eq!(reality.map(|r| r.short_id.as_str()), Some("0123"));
}

/// A WireGuard `.conf` as written by the WireGuard apps.
#[test]
fn wireguard_conf() {
    let conf = "[Interface]\nPrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\n\
                [Peer]\nPublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = wg.example.com:51820\n";
    let report = parse(conf);
    assert_eq!(report.profiles.len(), 1, "{:?}", report.skipped);
    let Kind::Wireguard(wg) = &report.profiles[0].kind else {
        panic!("not WireGuard")
    };
    assert_eq!(wg.peers[0].port, 51820);
}

/// One sing-box VLESS outbound as a JSON object with the given tag and server.
fn vless_outbound(tag: &str, server: &str) -> String {
    format!(
        r#"{{"type":"vless","tag":"{tag}","server":"{server}","server_port":443,"uuid":"00000000-0000-4000-8000-000000000009","tls":{{"enabled":true,"server_name":"{server}"}},"transport":{{"type":"ws","path":"/ws"}}}}"#
    )
}

/// §7.2 "independent outbounds" through the pipeline: every outbound is a profile, the
/// transport survives, and a repeated outbound (same identity, other tag) is a duplicate.
#[test]
fn json_outbounds_and_duplicates() {
    let outbounds: Vec<String> = (0..100)
        .map(|i| vless_outbound(&format!("node-{i}"), &format!("n{i}.example")))
        .chain([vless_outbound("again", "n0.example")])
        .collect();
    let report = parse(&format!(r#"{{"outbounds":[{}]}}"#, outbounds.join(",")));
    assert_eq!(report.profiles.len(), 100);
    assert_eq!(report.profiles[0].name, "node-0");
    assert!(matches!(
        report.profiles[0].transport,
        Some(Transport::Ws { .. })
    ));
    assert_eq!(reasons(&report), [&SkipReason::Duplicate]);
    assert_eq!(report.skipped[0].excerpt, "again (vless)");
}

/// §6.5 #7: every format of a layer is read; a broken entry never hides the others.
#[test]
fn all_formats_in_one_text() {
    let doc = vless_outbound("json-node", "j.example");
    let text = format!(
        "{doc}\nproxies:\n- name: clash-node\n  type: trojan\n  server: c.example\n  port: 443\n  password: p\n\
         {TUIC}\nvless://broken\nssr://c3NyLmV4YW1wbGU6NDQz\n"
    );
    let report = parse(&text);
    assert_eq!(names(&report), ["json-node", "clash-node", "TUIC"]);
    assert_eq!(report.skipped.len(), 2, "{:?}", report.skipped);
    assert!(matches!(
        report.skipped[0].reason,
        SkipReason::Invalid { .. }
    ));
    assert_eq!(
        report.skipped[1].reason,
        SkipReason::UnknownScheme("ssr".into())
    );
}

/// One synthetic Xray provider document: two REALITY hops behind a balancer.
fn provider_doc(remarks: &str, host: &str) -> serde_json::Value {
    let hop = |tag: &str, address: String| {
        serde_json::json!({ "tag": tag, "protocol": "vless",
            "settings": { "vnext": [{ "address": address, "port": 443,
                "users": [{ "id": "00000000-0000-4000-8000-000000000001", "flow": "xtls-rprx-vision" }] }] },
            "streamSettings": { "network": "tcp", "security": "reality",
                "realitySettings": { "serverName": "front.example.com", "publicKey": "PBK-FAKE",
                                     "shortId": "1234", "fingerprint": "firefox" } } })
    };
    serde_json::json!({ "remarks": remarks,
        "outbounds": [hop("proxy-1", host.to_owned()), hop("proxy-2", format!("b.{host}")),
                      { "tag": "direct", "protocol": "freedom" }, { "tag": "block", "protocol": "blackhole" }],
        "routing": { "balancers": [{ "tag": "l1", "selector": ["proxy-"], "strategy": { "type": "leastPing" } }],
                     "rules": [{ "type": "field", "network": "tcp,udp", "balancerTag": "l1" }] } })
}

/// §7.3 P-14 isolation (verifier): an unsafe provider document rejects only itself; pretty-printed
/// JSON with a share link after it.
#[test]
fn unsafe_provider_document_is_isolated() {
    let mut unsafe_doc = provider_doc("Unsafe", "u.example");
    unsafe_doc["routing"]["balancers"][0]["fallbackTag"] = serde_json::json!("direct");
    let docs = serde_json::json!([provider_doc("Norway", "no.example"), unsafe_doc]);
    let text = format!(
        "{}\n{VLESS}\n",
        serde_json::to_string_pretty(&docs).unwrap()
    );
    let report = parse(&text);
    assert_eq!(names(&report), ["Norway", "VLESS"]);
    assert!(report.profiles[0].native_xray.is_some());
    assert!(matches!(
        reasons(&report)[..],
        [SkipReason::NativeGraphRejected(_)]
    ));
}

/// §6.5 #12: pasted text over 1 MiB and bodies over 16 MiB are refused; surrounding whitespace
/// and a BOM do not count.
#[test]
fn size_limits() {
    let mut big = "a".repeat(text::MAX_INPUT_BYTES);
    assert!(parse_text(&format!("\u{feff}  {big}\n\n")).is_ok());
    big.push('a');
    assert_eq!(parse_text(&big), Err(TooLarge));
    assert!(parse_body(big.as_bytes()).is_ok());
    let huge = vec![b'a'; text::MAX_BODY_BYTES + 1];
    assert_eq!(parse_body(&huge), Err(TooLarge));

    let err = too_large(text::MAX_INPUT_BYTES);
    assert_eq!(err.kind, vpnte_base::ErrorKind::Validation);
    assert_eq!(
        err.user_msg(),
        Msg::new("servers.parse.tooLarge").arg("mib", 1)
    );
    assert_eq!(too_large(text::MAX_BODY_BYTES).user_msg().args[0].1, "16");
}

/// §6.5 #12: at most 5000 profiles; the first key past the limit marks the list as cut.
#[test]
fn profile_limit_marks_the_list_as_cut() {
    let lines: Vec<String> = (0..=MAX_PROFILES)
        .map(|i| {
            format!(
                "vless://00000000-0000-4000-8000-000000000000@h{i}.example:443?security=tls#N{i}"
            )
        })
        .collect();
    let report = parse(&lines.join("\n"));
    assert_eq!(report.profiles.len(), MAX_PROFILES);
    let [cut] = report.skipped.as_slice() else {
        panic!("{:?}", report.skipped)
    };
    assert_eq!(cut.excerpt, "vless://h5000.example:443");
    assert!(
        matches!(&cut.reason, SkipReason::Invalid { scheme, detail } if scheme == "vless" && detail.contains("5000"))
    );
}

/// Skipped entries are bounded; problems past the bound leave one entry with their number, while
/// surplus duplicates (which lose nothing) are simply not listed.
#[test]
fn skipped_entries_are_bounded() {
    let broken: Vec<String> = (0..MAX_SKIPPED + 3)
        .map(|i| format!("vless://b{i}"))
        .collect();
    let report = parse(&broken.join("\n"));
    assert_eq!(report.skipped.len(), MAX_SKIPPED + 1);
    let last = report.skipped.last().unwrap();
    assert!(
        matches!(&last.reason, SkipReason::Invalid { detail, .. } if detail.starts_with("3 more"))
    );

    let copies = vec![VLESS; MAX_SKIPPED + 5].join("\n");
    let report = parse(&copies);
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.skipped.len(), MAX_SKIPPED);
    assert!(
        report
            .skipped
            .iter()
            .all(|s| s.reason == SkipReason::Duplicate)
    );
}

/// §6.5 #12: at most 64 JSON documents; a valid one past the limit is reported, while a flow-style
/// Clash list (one brace span per entry, none of them JSON) raises no false alarm.
#[test]
fn json_document_limit() {
    let docs: Vec<String> = (0..=text::MAX_JSON_SPANS)
        .map(|i| {
            format!(
                r#"{{"outbounds":[{}]}}"#,
                vless_outbound(&format!("d{i}"), &format!("d{i}.example"))
            )
        })
        .collect();
    let report = parse(&docs.join("\n"));
    assert_eq!(report.profiles.len(), text::MAX_JSON_SPANS);
    assert!(matches!(
        &reasons(&report)[..],
        [SkipReason::Invalid { scheme, .. }] if scheme == "json"
    ));

    let entries: Vec<String> = (0..80)
        .map(|i| {
            format!(
                "  - {{name: n{i}, type: trojan, server: t{i}.example, port: 443, password: p}}"
            )
        })
        .collect();
    let report = parse(&format!("proxies:\n{}\n", entries.join("\n")));
    assert_eq!(report.profiles.len(), 80);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
}

/// A UTF-16 body with BOM (Windows "Unicode" text) and a pasted BOM are decoded before parsing.
#[test]
fn utf16_body_and_bom() {
    let utf16: Vec<u8> = format!("\u{feff}{VLESS}\r\n")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(names(&parse_body(&utf16).expect("small body")), ["VLESS"]);
    assert_eq!(names(&parse(&format!("\u{feff}{VLESS}"))), ["VLESS"]);
}

/// The error for an import that found no key: a lone entry explains itself, several are counted.
#[test]
fn no_profiles_messages() {
    let one = parse("vless://@h.example:443?security=tls");
    assert_eq!(
        no_profiles(&one).user_msg().key,
        "profiles.caps.skip.missingCredential"
    );
    let two = parse("vless://@h.example:443?security=tls\nssr://c3NyLmV4YW1wbGU6NDQz");
    let err = no_profiles(&two);
    assert_eq!(err.kind, vpnte_base::ErrorKind::Validation);
    assert_eq!(
        err.user_msg(),
        Msg::new("servers.parse.allSkipped").arg("count", 2)
    );
}

/// AT-04-003: damaged base64 (truncated, binary, or a damaged inner layer) is reported with a
/// reason instead of reading as "nothing found"; prose and short words are not blobs.
#[test]
fn damaged_base64_is_reported() {
    let list = format!("{VLESS}\n{TUIC}\n{NAIVE}");
    let once = STANDARD.encode(&list);
    let truncated = &once[..once.len() - 3];
    let inner_damaged = STANDARD.encode(&once[..once.len() - 3]);
    let binary = STANDARD.encode([
        0xff_u8, 0xfe, 0x00, 0x41, 0x10, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
    ]);
    let wrapped: String = truncated
        .as_bytes()
        .chunks(76)
        .map(|c| format!("{}\r\n", std::str::from_utf8(c).unwrap()))
        .collect();
    for blob in [truncated, &inner_damaged, &binary, &wrapped] {
        let report = parse(blob);
        assert!(report.profiles.is_empty(), "{blob}");
        assert!(
            matches!(&reasons(&report)[..], [SkipReason::Invalid { scheme, .. }] if scheme == "base64"),
            "{blob}: {:?}",
            report.skipped
        );
        assert_eq!(
            no_profiles(&report).user_msg().key,
            "servers.parse.damagedBase64"
        );
    }
    for prose in [
        "hello",
        "nothing to see in this long sentence here",
        "ABCDEFGHIJKLMNO",
    ] {
        assert!(parse(prose).skipped.is_empty(), "{prose}");
    }
}

/// §7.2 "doc + URI": a JSON array holding a provider document and a share link string.
#[test]
fn json_array_with_a_document_and_a_link() {
    let simple = "vless://00000000-0000-4000-8000-000000000002@s.example:443?security=tls#Simple";
    let docs = serde_json::json!([provider_doc("Norway", "no.example"), simple]);
    assert_eq!(names(&parse(&docs.to_string())), ["Norway", "Simple"]);
}

/// One Clash proxy in JSON syntax, as Sub-Store writes them (`produceProxyListOutput`).
fn clash_json_entry(i: usize) -> String {
    format!(
        r#"{{"name":"n{i}","type":"vless","server":"v{i}.example","port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":true,"servername":"v{i}.example"}}"#
    )
}

/// Review R1: Clash entries written in JSON syntax (Sub-Store's default output, also as a flow
/// list) are the YAML reader's, not sing-box outbounds with a missing `server_port`, past the
/// 64-document limit too; a JSON document starting its own line next to them is still JSON.
#[test]
fn clash_entries_in_json_syntax() {
    let entries: Vec<String> = (0..100)
        .map(|i| format!("  - {}\n", clash_json_entry(i)))
        .collect();
    let report = parse(&format!("proxies:\n{}", entries.concat()));
    assert_eq!(report.profiles.len(), 100, "{:?}", report.skipped);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);

    let flow = format!(
        "proxies: [{}, {}]",
        clash_json_entry(0),
        clash_json_entry(1)
    );
    let doc = vless_outbound("json-node", "j.example");
    let report = parse(&format!("{doc}\n{flow}\n"));
    assert_eq!(
        names(&report),
        ["json-node", "n0", "n1"],
        "{:?}",
        report.skipped
    );
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
}

/// Report invariants every input must keep.
fn assert_invariants(input: &str, report: &ParseReport) {
    assert!(report.profiles.len() <= MAX_PROFILES, "{input:?}");
    assert!(report.skipped.len() <= MAX_SKIPPED + 1, "{input:?}");
    let ids: HashSet<[u8; 16]> = report.profiles.iter().map(Profile::identity).collect();
    assert_eq!(
        ids.len(),
        report.profiles.len(),
        "duplicates kept: {input:?}"
    );
    for p in &report.profiles {
        assert!(
            !p.name.trim().is_empty() && p.name.chars().count() <= 256,
            "{input:?}"
        );
    }
    for s in &report.skipped {
        assert!(s.excerpt.chars().count() <= 80, "{input:?}: {s:?}");
        assert!(!s.excerpt.contains("secret"), "{input:?}: {s:?}");
        if let SkipReason::Invalid { detail, .. } = &s.reason {
            assert!(!detail.contains("secret"), "{input:?}: {s:?}");
        }
    }
}

/// AT-04-001 (seeded, lite): random mixtures of keys, JSON / YAML / INI fragments, deep links,
/// metadata, brackets, base64 and odd characters never panic and keep the report invariants;
/// a credential never reaches an excerpt or a reason.
#[test]
fn random_mixtures_keep_the_invariants() {
    let pieces = [
        VLESS,
        TUIC,
        NAIVE,
        "trojan://secret@t.example:443#T",
        "hy2://secret@h.example:443,20000-30000/?sni=x#H",
        "vmess://",
        "ss://",
        "ssr://x",
        "{",
        "}",
        "[",
        "]",
        "\"",
        "proxies:\n",
        "- name: a\n  type: trojan\n  server: t.example\n  port: 443\n  password: secret\n",
        "  - {name: b, type: ss, server: s.example, port: 8388, cipher: aes-256-gcm, password: secret}\n",
        "  - {\"name\":\"j\",\"type\":\"trojan\",\"server\":\"j.example\",\"port\":443,\"password\":\"secret\"}\n",
        "[Interface]\nPrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\n",
        "[Peer]\nPublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\nEndpoint = w.example:51820\n",
        "#profile-title: T\n",
        "happ://add/",
        "happ://crypt4/secret",
        r#"{"type":"trojan","server":"192.0.2.1","server_port":443,"password":"secret"}"#,
        r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[]}}]}"#,
        "\n",
        "\r\n",
        " ",
        "%",
        "#",
        "?",
        "@",
        ":",
        "/",
        "=",
        "QUxMIFZQTg==",
        "\u{feff}",
        "é",
        "😀",
        "\0",
    ];
    let mut rng = fastrand::Rng::with_seed(0x5eed_0001);
    for _ in 0..3000 {
        let mut input = String::new();
        for _ in 0..rng.usize(1..24) {
            input.push_str(pieces[rng.usize(..pieces.len())]);
        }
        if rng.u8(..4) == 0 {
            input = STANDARD.encode(&input);
        }
        let report = parse(&input);
        assert_invariants(&input, &report);
    }
}

/// Excerpts of links show `scheme://host:port` only (fuzzing found broken lines whose tail after a
/// stray `@` carried a password); IPv6 and percent zone ids stay readable.
#[test]
fn link_excerpts_hide_paths_and_garbage() {
    for (line, want) in [
        (
            "ssr://x@% [happ://crypt4/secret{ password: secret}",
            "ssr://%…",
        ),
        (
            r#"ssr://x@{"type":"trojan","password":"secret"}"#,
            "ssr://…",
        ),
        (
            "vless://u@h.example:443/SECRET-PATH?type=ws#n",
            "vless://h.example:443…",
        ),
        (
            "vless://u@[2001:db8::1%eth0]:443?security=tls#n",
            "vless://[2001:db8::1%eth0]:443",
        ),
        ("vmess://eyJhZGQiOiJoLmV4YW1wbGUifQ==", "vmess://…"),
    ] {
        assert_eq!(link_excerpt(line), want, "{line}");
    }
    let report = parse("ssr://x@h.example:1/secret-token");
    assert_eq!(report.skipped[0].excerpt, "ssr://h.example:1…");
}
