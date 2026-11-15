//! AT-04-001, local deterministic part: truncated or mutated links never panic; every refusal
//! is a typed `SkipReason` (the nightly 100k-input fuzz run is not part of the unit tests).
use super::*;

fn seeds() -> Vec<String> {
    let vmess = b64(r#"{"add":"h.example","port":443,"id":"a","net":"ws","tls":"tls"}"#);
    let pin = "a".repeat(64);
    vec![
        "vless://00000000-0000-4000-8000-000000000000@reality.example.com:443?security=reality&pbk=Synthetic&sid=1234&spx=%2Fp&type=grpc&serviceName=s&mode=multi#R".into(),
        format!("vmess://{vmess}#V"),
        "trojan://p%2525ss@[2001:db8::1]:443?type=xhttp&mode=auto&extra=%7B%7D#T".into(),
        "ss://YWVzLTI1Ni1nY206cGFzcw%3D%3D@h.example:8388/?plugin=obfs-local%3Bobfs%3Dhttp#S".into(),
        "ss://YWVzLTEyOC1nY206cGFzc0BleGFtcGxlLm5ldDo4Mzg4#legacy".into(),
        format!("hy2://user:pass@h.example:443,20000-30000/?obfs=salamander&obfs-password=p&pinSHA256={pin}&hop_interval=1m30s&up=30%20Mbps#H"),
        "tuic://u:p@h.example:443?heartbeat=10s&congestion_control=new-reno#T".into(),
        "naive+quic://u:p@h.example?ech=a.example+https%3A%2F%2F1.1.1.1%2Fdns-query&extra-headers=A%3A1#N".into(),
        "anytls://p@h.example?idle_session_check_interval_ms=1500&idle-timeout=1m#A".into(),
        "wg://priv:pub@[2001:db8::1]:51820?reserved=AQID&address=10.0.0.2,fd00::2&dns=1.1.1.1#W?serverDescription=SGVsbG8=".into(),
        "socks://dXNlcjpwYXNzQDEuMi4zLjQ6MTA4MA==#S".into(),
        "http://user:pa%3Ass@proxy.example.com:8080".into(),
    ]
}

const NOISE: &[char] = &[
    '@', ':', '/', '?', '#', '%', '[', ']', '=', '&', ',', '+', ' ', 'é', '\0',
];

#[test]
fn truncated_and_mutated_links_never_panic() {
    let mut attempts = 0usize;
    for seed in seeds() {
        assert!(parse_uri(&seed).is_ok(), "seed must import: {seed}");
        let chars: Vec<char> = seed.chars().collect();
        for cut in 0..chars.len() {
            let _ = parse_uri(&chars[..cut].iter().collect::<String>());
            for noise in NOISE {
                let mut mutated = chars.clone();
                mutated[cut] = *noise;
                let _ = parse_uri(&mutated.iter().collect::<String>());
            }
            attempts += 1 + NOISE.len();
        }
    }
    assert!(attempts > 10_000, "{attempts}");
}

/// Skipped-entry excerpts never carry the credential part of a link, a path (an access token)
/// or the tail of a broken line after a stray `@` (the servers fuzzing found passwords there).
#[test]
fn excerpts_are_redacted() {
    use crate::uri::excerpt;
    for (line, want) in [
        (
            "vless://SECRET-UUID@h.example:443?security=tls#Name",
            "vless://h.example:443",
        ),
        ("vmess://eyJhZGQiOiJoLmV4YW1wbGUifQ==#Node", "vmess://…"),
        ("ss://bWV0aG9kOnBhc3M@1.2.3.4:8388/#n", "ss://1.2.3.4:8388…"),
        (
            "trojan://p@h.example:443/SECRET-PATH?type=ws",
            "trojan://h.example:443…",
        ),
        (r#"ssr://x@{"password":"SECRET"}"#, "ssr://…"),
        ("ssr://x@% [happ://SECRET{ password: SECRET}", "ssr://%…"),
        (
            "vless://u@[2001:db8::1%eth0]:443?security=tls",
            "vless://[2001:db8::1%eth0]:443",
        ),
        ("garbage", "…"),
    ] {
        assert_eq!(excerpt(line), want, "{line}");
    }
}
