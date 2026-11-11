//! Unit tests of the engine-child layer (no engine process involved).
use super::*;

fn output(scrub: Scrubber) -> Output {
    Output {
        ring: Mutex::default(),
        log: None,
        log_failed: AtomicBool::new(false),
        scrub,
        lines: broadcast::channel(4).0,
        marker: Some("sing-box started ("),
        ready: watch::channel(false).0,
    }
}

#[test]
fn ring_keeps_the_last_500_lines_and_256_kib() {
    let out = output(Scrubber::default());
    for i in 0..600 {
        out.on_line(format!("line {i}\n"));
    }
    let ring = out.ring.lock();
    assert_eq!(ring.lines.len(), RING_LINES);
    assert_eq!(&*ring.lines[0].1, "line 100");
    drop(ring);
    for _ in 0..100 {
        out.on_line("x".repeat(20_000));
    }
    let ring = out.ring.lock();
    assert!(ring.bytes <= RING_BYTES, "{}", ring.bytes);
    assert!(ring.lines.iter().all(|(_, l)| l.len() <= MAX_LINE_BYTES));
}

#[test]
fn empty_lines_are_dropped_and_the_marker_sets_ready() {
    let out = output(Scrubber::default());
    let ready = out.ready.subscribe();
    out.on_line("\r\n".into());
    out.on_line("   \n".into());
    assert!(out.ring.lock().lines.is_empty());
    out.on_line("+0300 2026-09-02 10:54:30 INFO sing-box started (0.40s)\r\n".into());
    assert!(*ready.borrow());
    assert_eq!(out.ring.lock().lines.len(), 1);
}

/// tunnel-core 2.10: exit tail = last 6 non-empty lines, at most 800 chars, redacted.
#[test]
fn exit_info_tail_and_bind_evidence() {
    let out = output(Scrubber::new(br#"{"password":"hunter2-secret"}"#, &[]));
    for i in 0..10 {
        out.on_line(format!("INFO line {i}"));
    }
    out.on_line("FATAL start inbound/mixed[mixed-in]: listen tcp 127.0.0.1:34567: bind: Only one usage of each socket address is normally permitted.".into());
    out.on_line("ERROR auth hunter2-secret uuid 0b6e3a0c-9a43-4c1e-8f2a-0123456789ab".into());
    let info = out.exit_info(SystemTime::now(), Some(1), false);
    let lines: Vec<&str> = info.stderr_tail.lines().collect();
    assert_eq!(lines.len(), 6);
    assert_eq!(lines[0], "INFO line 6");
    assert!(!info.stderr_tail.contains("hunter2-secret"));
    assert!(!info.stderr_tail.contains("0b6e3a0c-9a43"));
    assert!(info.binds_any(&[34567]) && !info.binds_any(&[34568]));
    out.on_line("y".repeat(1000));
    assert_eq!(
        out.exit_info(SystemTime::now(), None, true)
            .stderr_tail
            .chars()
            .count(),
        800
    );
}

/// tunnel-core B-17: the port is read from Go's `listen … bind:` prefix, whatever language
/// Windows wrote the reason in; the English WSAEACCES text without an address also counts.
#[test]
fn bind_failures_in_any_language() {
    let (ports, denied) = bind_evidence(
        [
            "FATAL[0000] start service: start inbound/mixed[mixed-in]: listen tcp 127.0.0.1:20001: bind: Сделана попытка доступа к сокету методом, запрещенным правами доступа.",
            "listen udp 127.0.0.1:20002: bind: An attempt was made to access a socket in a way forbidden by its access permissions.",
            "listen tcp4 127.0.0.1:20001: bind: again",
            "INFO inbound/mixed[mixed-in]: tcp server started at 127.0.0.1:20003",
        ]
        .into_iter(),
    );
    assert_eq!(ports, vec![20001, 20002]);
    assert!(!denied);
    let (ports, denied) = bind_evidence(
        ["dial: WSAEACCES: An attempt was made to access a socket in a way forbidden"].into_iter(),
    );
    assert!(ports.is_empty() && denied);
}

#[test]
fn scrubber_takes_secrets_from_the_config() {
    let config = br#"{
        "inbounds": [{"tag": "mixed-in", "listen": "127.0.0.1",
                      "users": [{"username": "0123456789abcdef0123456789abcdef", "password": "fedcba9876543210fedcba9876543210"}]}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "vpn.example.com",
            "users": [{"id": "6f1c7e0a-52b8-4d55-9c36-2a8fd1d3c001"}]}]},
            "streamSettings": {"realitySettings": {"publicKey": "pbk-0123456789-ABCDEFGHIJ", "shortId": "a1b2c3d4", "serverName": "www.example.org"}}},
            {"type": "direct", "tag": "direct-out", "server": "10.0.0.1"}],
        "dns": {"servers": [{"tag": "dns-remote", "server": "1.1.1.1", "short_id": "ab"}],
                "rules": [{"inbound": ["tun-in"], "server": "dns-remote"}]}
    }"#;
    let scrub = Scrubber::new(config, &["slot-pass-123456"]);
    for secret in [
        "0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210",
        "vpn.example.com",
        "pbk-0123456789-ABCDEFGHIJ",
        "a1b2c3d4",
        "1.1.1.1",
        "slot-pass-123456",
    ] {
        assert!(
            scrub.secrets.iter().any(|s| s == secret),
            "{secret} not collected"
        );
        assert_eq!(scrub.exact(&format!("x {secret} y")), "x <redacted> y");
    }
    // Private addresses, plain names, short values and tag references stay readable.
    for kept in [
        "127.0.0.1",
        "10.0.0.1",
        "direct-out",
        "www.example.org",
        "ab",
        "dns-remote",
    ] {
        assert!(!scrub.secrets.iter().any(|s| s == kept), "{kept} collected");
    }
    let line = "invalid \"password\": fedcba9876543210fedcba9876543210 for 6f1c7e0a-52b8-4d55-9c36-2a8fd1d3c001";
    let clean = scrub.clean(line);
    assert!(
        !clean.contains("fedcba98") && !clean.contains("6f1c7e0a"),
        "{clean}"
    );
}
