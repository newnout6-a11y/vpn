use super::*;
use crate::test_support::TempDir;

/// Tiny deterministic generator for the seeded property cases of the old suite.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn ok(s: &str) -> bool {
    parse_ip_or_cidr(s).is_ok()
}

/// AT-03-009 (F-042/F-147): "accepts plain IPv4", "accepts IPv4 CIDR", "accepts IPv6 and IPv6
/// CIDR", "trims surrounding whitespace before validating".
#[test]
fn accepts_addresses_and_cidrs() {
    for s in [
        "203.0.113.4",
        "10.0.0.1",
        "255.255.255.255",
        "203.0.113.0/24",
        "10.0.0.0/8",
        "192.168.1.1/32",
        "2001:db8::1",
        "2001:db8::/32",
        "::1",
        "  10.0.0.1  ",
    ] {
        assert!(ok(s), "{s:?} must be accepted");
    }
}

/// AT-03-009: wildcards, unspecified addresses, garbage and injection attempts are rejected.
#[test]
fn rejects_wildcards_garbage_and_injection() {
    for s in [
        "0.0.0.0",
        "0.0.0.0/0",
        "203.0.113.0/0",
        "::",
        "::/0",
        "2001:db8::/0",
        "256.0.0.1",
        "999.999.999.999",
        "10.0.0.0/33",
        "2001:db8::/129",
        "10.0.0.0/-1",
        "example.com",
        "10.0.0.1-10.0.0.5",
        "",
        "   ",
        "10.0.0.0/24/8",
        "10.0.0.1'; Remove-NetFirewallRule -All; '",
        "10.0.0.1 | Out-Null",
        "$(whoami)",
        "10.0.0.1`n",
        "fe80::1%3",
        "0::0",
        "::ffff:0.0.0.0",
    ] {
        assert!(!ok(s), "{s:?} must be rejected");
    }
}

/// AT-03-009: "rejects non-decimal CIDR prefix" for both families.
#[test]
fn rejects_non_decimal_prefixes() {
    for p in [
        "+24", "24.0", "0x10", "0b10", "0o10", "1e1", " 24", "\t24", "", "Infinity", "NaN",
    ] {
        assert!(!ok(&format!("192.0.2.1/{p}")), "v4 prefix {p:?}");
        assert!(!ok(&format!("2001:db8::1/{p}")), "v6 prefix {p:?}");
    }
    assert_eq!(
        parse_ip_or_cidr("192.0.2.1/024").unwrap(),
        parse_ip_or_cidr("192.0.2.1/24").unwrap()
    );
}

/// AT-03-009, seeds 30009 / 30010 / 30011: any non-zero address with an in-range prefix is
/// accepted; coerced prefix spellings are rejected.
#[test]
fn seeded_properties() {
    let mut g = XorShift(30009);
    for _ in 0..500 {
        let a = std::net::Ipv4Addr::from((g.next() as u32).max(1));
        let p = 1 + g.below(32);
        assert!(ok(&format!("{a}/{p}")), "{a}/{p}");
    }
    let mut g = XorShift(30010);
    for _ in 0..500 {
        let a = std::net::Ipv6Addr::from(((g.next() as u128) << 64 | g.next() as u128).max(1));
        if a.to_ipv4_mapped().is_some_and(|m| m.is_unspecified()) {
            continue;
        }
        let p = 1 + g.below(128);
        assert!(ok(&format!("{a}/{p}")), "{a}/{p}");
    }
    let mut g = XorShift(30011);
    for _ in 0..200 {
        let p = 1 + g.below(32);
        for bad in [
            format!("+{p}"),
            format!("{p}.0"),
            format!("{p}e0"),
            format!("0x{p:x}"),
            format!(" {p}"),
        ] {
            assert!(!ok(&format!("198.51.100.7/{bad}")), "{bad:?}");
        }
    }
}

/// AT-03-009 (Rust additions): canonical text is lower-case and compressed; a host-length
/// prefix reads as the bare address; host bits are kept in the stored value.
#[test]
fn canonical_values() {
    let ip = |s: &str| ExceptionTarget::Ip(parse_ip_or_cidr(s).unwrap());
    assert_eq!(ip("192.0.2.1").value(), "192.0.2.1");
    assert_eq!(ip("10.0.0.0/8").value(), "10.0.0.0/8");
    assert_eq!(ip("2001:DB8:0::/32").value(), "2001:db8::/32");
    assert_eq!(ip("2001:0db8::1").value(), "2001:db8::1");
    assert_eq!(ip("192.0.2.1/24").value(), "192.0.2.1/24");
    assert_eq!(ip("192.0.2.1/32").value(), "192.0.2.1");
    let broad = |s: &str| broad_warning(&ip(s)).is_some();
    assert!(broad("1.0.0.0/1") && broad("2001::/15"));
    assert!(!broad("10.0.0.0/8") && !broad("2001:db8::/16"));
}

/// AT-03-008/009: accepted IP values come back as entered; invalid ones are rejected with the
/// IP/CIDR message before any store write or WFP change.
#[test]
fn ip_exceptions() {
    for v in ["192.0.2.1", "10.0.0.0/8", "2001:db8::/32", "2001:db8::1"] {
        let (target, label) = validate_exception(ExceptionKind::Ip, v, " Office ").unwrap();
        assert_eq!((target.value().as_str(), label.as_str()), (v, "Office"));
    }
    for v in [
        "0.0.0.0/0",
        "::/0",
        "999.1.1.1",
        "10.0.0.1/33",
        "2001:db8::/129",
        "host.example",
        "10.0.0.0/x",
        "192.0.2.1/0x10",
        "192.0.2.1/+24",
        "2001:db8::1/1e1",
        "2001:db8::1/64.0",
    ] {
        let got = validate_exception(ExceptionKind::Ip, v, "x");
        assert_eq!(got, Err(ValidationError::InvalidIp), "{v}");
    }
}

/// AT-03-008, seed 30012: label `''` / 201 chars and value `''` / 2049 chars are rejected.
#[test]
fn input_bounds() {
    let long = |n: usize| "x".repeat(n);
    let ip = |label: &str| validate_exception(ExceptionKind::Ip, "192.0.2.1", label);
    assert_eq!(ip(""), Err(ValidationError::LabelLength));
    assert_eq!(ip(&long(201)), Err(ValidationError::LabelLength));
    assert!(ip(&long(200)).is_ok());
    let value = |kind, v: &str| validate_exception(kind, v, "x");
    assert_eq!(
        value(ExceptionKind::Ip, "  "),
        Err(ValidationError::ValueLength)
    );
    assert_eq!(
        value(ExceptionKind::App, &long(2049)),
        Err(ValidationError::ValueLength)
    );
}

fn exception(id: &str, kind: ExceptionKind, value: &str) -> KillSwitchException {
    let (target, label) = validate_exception(kind, value, "label").unwrap();
    KillSwitchException {
        id: id.into(),
        target,
        label,
    }
}

/// AT-03-008, seeds 30014 / 30015: dotted spellings resolve to the real path and labels are
/// trimmed; control characters, relative / UNC / stream / `..` paths, non-exe files,
/// directories and missing files are rejected.
#[test]
fn app_exceptions() {
    let dir = TempDir::new("apps");
    let exe = dir.file("allowed.exe");
    for k in 0..=5 {
        let raw = format!("{}/{}allowed.exe", dir.path().display(), "./".repeat(k));
        let label = format!(" {} ", "x".repeat(1 + 39 * k));
        let (target, got) = validate_exception(ExceptionKind::App, &raw, &label).unwrap();
        assert_eq!(target, ExceptionTarget::App(exe.clone()), "{raw}");
        assert_eq!(got, label.trim());
    }
    dir.file("x.txt");
    std::fs::create_dir_all(dir.path().join("directory.exe")).unwrap();
    let d = dir.path().display();
    for c in 0u8..32 {
        let raw = format!(r"{d}\a{}b.exe", c as char);
        assert_eq!(
            canonical_exe(&raw),
            Err(ValidationError::NotExecutable),
            "control {c}"
        );
    }
    assert_eq!(
        canonical_exe(&format!("{d}/x.txt")),
        Err(ValidationError::NotExecutable)
    );
    for raw in [
        r"relative/x.exe",
        r"C:\fixture\..\x.exe",
        r"\\server\share\x.exe",
        r"C:\fixture\x:stream.exe",
    ] {
        assert_eq!(
            canonical_exe(raw),
            Err(ValidationError::NotLocalPath),
            "{raw}"
        );
    }
    let dir_exe = format!(r"{d}\directory.exe");
    assert_eq!(canonical_exe(&dir_exe), Err(ValidationError::Unreadable));
    let missing = format!(r"{d}\missing.exe");
    assert_eq!(canonical_exe(&missing), Err(ValidationError::Unreadable));
}

/// AT-03-008, seed 30013: padded / zero-prefixed spellings of an existing CIDR and the 8.3
/// alias of an added path are "equivalent"; more than 256 entries are refused at add time.
#[test]
fn duplicates_and_limit() {
    let existing = exception("a", ExceptionKind::Ip, "192.0.2.1/24");
    for pad in ["", " ", "\t", "\r\n"] {
        for k in 0..=4 {
            let raw = format!("{pad}192.0.2.1/{}24{pad}", "0".repeat(k));
            let list = [existing.clone(), exception("b", ExceptionKind::Ip, &raw)];
            assert_eq!(
                check_list(&list),
                Err(ValidationError::Duplicate),
                "{raw:?}"
            );
        }
    }
    let same_net = [existing, exception("b", ExceptionKind::Ip, "192.0.2.0/24")];
    assert_eq!(check_list(&same_net), Err(ValidationError::Duplicate));
    let case = [
        exception("a", ExceptionKind::Ip, "2001:DB8::1"),
        exception("b", ExceptionKind::Ip, "2001:0db8::1"),
    ];
    assert_eq!(check_list(&case), Err(ValidationError::Duplicate));

    let dir = TempDir::new("short");
    let long = dir.file("a long executable name.exe");
    let long_text = long.to_str().unwrap();
    // 8.3 names may be disabled on the volume; then there is no alias to test.
    if let Some(short) = crate::wfp::filters::tests::short_name(&long) {
        let list = [
            exception("a", ExceptionKind::App, long_text),
            exception("b", ExceptionKind::App, short.to_str().unwrap()),
        ];
        assert_eq!(check_list(&list), Err(ValidationError::Duplicate));
    }

    let many: Vec<_> = (0..=MAX_EXCEPTIONS as u32)
        .map(|i| {
            let addr = std::net::Ipv4Addr::from(0x0a00_0001 + i).to_string();
            exception(&i.to_string(), ExceptionKind::Ip, &addr)
        })
        .collect();
    assert_eq!(check_list(&many[..MAX_EXCEPTIONS]), Ok(()));
    assert_eq!(check_list(&many), Err(ValidationError::TooMany));
}
