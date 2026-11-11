use super::*;

fn p(s: &str) -> DomainPattern {
    DomainPattern::parse(s).unwrap()
}

fn rule(pattern: &str, action: DomainAction) -> DomainRule {
    DomainRule::new(p(pattern), action)
}

/// AT-06-003 (matchDomain): apex + subdomains, wildcard = subdomains only, case and padding
/// ignored, a stored URL means its host, first rule in list order wins (blocks first).
#[test]
fn match_domain_vectors() {
    assert!(first_match(&[], "example.com").is_none());
    let exact = [rule("example.com", DomainAction::Vpn)];
    assert!(first_match(&exact, "").is_none());
    for host in [
        "example.com",
        "www.example.com",
        "a.b.example.com",
        "  example.com  ",
    ] {
        assert!(first_match(&exact, host).is_some(), "{host}");
    }
    assert!(first_match(&exact, "notexample.com").is_none());
    assert!(p("https://2ip.ru/").matches("2ip.ru"));
    assert!(p("Example.COM").matches("example.com"));
    let wild = p("*.example.com");
    assert!(wild.matches("sub.example.com") && wild.matches("a.b.c.example.com"));
    assert!(!wild.matches("example.com"));
    let rules = [
        rule("sub.example.com", DomainAction::Vpn),
        rule("*.example.com", DomainAction::Direct),
    ];
    assert_eq!(
        first_match(&rules, "sub.example.com").unwrap().action,
        DomainAction::Vpn
    );
    let rules = [
        rule("*.google.com", DomainAction::Vpn),
        rule("facebook.com", DomainAction::Vpn),
    ];
    assert!(first_match(&rules, "twitter.com").is_none());
    // Block rules decide first wherever they sit in the list (owner order, as generated).
    let rules = [
        rule("example.com", DomainAction::Vpn),
        rule("ads.example.com", DomainAction::Block),
    ];
    assert_eq!(
        first_match(&rules, "ads.example.com").unwrap().action,
        DomainAction::Block
    );
    assert_eq!(
        first_match(&rules, "www.example.com").unwrap().action,
        DomainAction::Vpn
    );
}

/// Normalisation of user input (domainRouting.ts:58-72) plus the Rust grammar (B-DR-1/3/4).
#[test]
fn parse_normalises_and_validates() {
    assert_eq!(p("https://2ip.ru/"), DomainPattern::Exact("2ip.ru".into()));
    assert_eq!(
        p("  Example.COM./path?q#f "),
        DomainPattern::Exact("example.com".into())
    );
    assert_eq!(
        p("*.Example.com/x"),
        DomainPattern::Subdomains("example.com".into())
    );
    assert_eq!(p("*.ru"), DomainPattern::Subdomains("ru".into()));
    assert_eq!(p("~Telegram"), DomainPattern::Keyword("telegram".into()));
    assert_eq!(
        p("пример.рф"),
        DomainPattern::Exact("xn--e1afmkfd.xn--p1ai".into())
    );
    assert_eq!(
        p("https://ПРИМЕР.рф/a"),
        DomainPattern::Exact("xn--e1afmkfd.xn--p1ai".into())
    );
    assert_eq!(
        p("_dmarc.example.com"),
        DomainPattern::Exact("_dmarc.example.com".into())
    );
    let err = |s: &str| DomainPattern::parse(s).unwrap_err();
    assert_eq!(err("x.com:443"), PatternError::Invalid);
    assert_eq!(err("a..b"), PatternError::Invalid);
    assert_eq!(err("a*b.com"), PatternError::Invalid);
    assert_eq!(err("has space.com"), PatternError::Invalid);
    assert_eq!(err("1.2.3.4"), PatternError::IpLiteral);
    assert_eq!(err("https://[2001:db8::1]/"), PatternError::IpLiteral);
    assert_eq!(err("ru"), PatternError::NeedsDot);
    assert_eq!(err("telegram"), PatternError::NeedsDot);
    assert_eq!(
        err(&format!("{}.com", "a".repeat(64))),
        PatternError::Invalid
    );
    let long = format!("{}.com", vec!["a".repeat(60); 5].join("."));
    assert_eq!(err(&long), PatternError::TooLong);
}

/// B-DR-9: inputs that normalised to "" became `domain_keyword: [""]` (match-all) in the old
/// app; every one of them is refused now, and so is an empty or punctuation-only keyword.
#[test]
fn match_all_patterns_are_refused() {
    for raw in [
        "", "   ", "/", ".", "...", "#x", "?q", "*.", "*", "~", "~ ", "~.", "~-_.",
    ] {
        assert!(
            DomainPattern::parse(raw).is_err(),
            "{raw:?} must be refused"
        );
    }
    assert_eq!(p("~ru").to_string(), "~ru");
}

/// Display is the persisted form and parses back to the same pattern.
#[test]
fn display_round_trips() {
    for raw in [
        "example.com",
        "*.example.com",
        "~kw",
        "xn--e1afmkfd.xn--p1ai",
    ] {
        assert_eq!(p(raw).to_string(), raw);
        assert_eq!(p(&p(raw).to_string()), p(raw));
    }
    let json = serde_json::to_string(&rule("*.x.com", DomainAction::Block)).unwrap();
    assert!(
        json.contains(r#""pattern":"*.x.com","action":"block""#),
        "{json}"
    );
    let back: DomainRule = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pattern, p("*.x.com"));
    assert!(serde_json::from_str::<DomainRule>(&json.replace("*.x.com", "/")).is_err());
}

/// Old dotless patterns keep their (keyword) meaning, now spelled `~word`.
#[test]
fn legacy_dotless_patterns_become_keywords() {
    assert_eq!(
        DomainPattern::parse_legacy("Telegram").unwrap(),
        DomainPattern::Keyword("telegram".into())
    );
    assert_eq!(DomainPattern::parse_legacy("x.com").unwrap(), p("x.com"));
    assert!(DomainPattern::parse_legacy("/").is_err());
    assert!(DomainPattern::parse_legacy("*.").is_err());
}

/// parseDomainList vectors (domainRouting.test.ts) + BOM, comments and dedup (B-DR-5).
#[test]
fn parse_list_vectors() {
    assert_eq!(parse_list(""), ListImport::default());
    assert_eq!(parse_list("example.com").patterns, vec![p("example.com")]);
    let three = parse_list("example.com\ngoogle.com\n*.facebook.com");
    assert_eq!(
        three.patterns,
        vec![p("example.com"), p("google.com"), p("*.facebook.com")]
    );
    assert_eq!(
        parse_list("example.com\n\n\ngoogle.com\n").patterns.len(),
        2
    );
    assert_eq!(
        parse_list("  example.com  \n\tgoogle.com\t").patterns,
        vec![p("example.com"), p("google.com")]
    );
    assert_eq!(parse_list("https://2ip.ru/").patterns, vec![p("2ip.ru")]);
    assert_eq!(parse_list("a.com\r\nb.com\r\n").patterns.len(), 2);
    assert_eq!(parse_list("a.com\n   \n\t\nb.com").patterns.len(), 2);
    // The old app stored `x.com ` and re-trimmed it on use: a trailing comment still works.
    assert_eq!(
        parse_list("x.com # note\n*.y.com. #\nz.com/path ").patterns,
        vec![p("x.com"), p("*.y.com"), p("z.com")]
    );
    let bom = parse_list("\u{feff}first.com\nsecond.com");
    assert_eq!(bom.patterns, vec![p("first.com"), p("second.com")]);
    let mixed = parse_list("# comment\na.com\nA.COM\nru\nx.com:443\nb.com");
    assert_eq!(mixed.patterns, vec![p("a.com"), p("b.com")]);
    assert_eq!((mixed.invalid, mixed.duplicates), (2, 1));
}

/// AT-01-003 / AT-01-004 (domainRoutingImportSecurity.test.ts, capability tokens dropped):
/// a directory and a file over 4 MiB are refused before parsing; a BOM file imports its
/// first line.
#[test]
fn list_file_limits() {
    let tmp = crate::test_support::TempDir::new("list");
    let dir = tmp.path();
    let key = |r: AppResult<String>| r.unwrap_err().user_msg().key.into_owned();
    assert_eq!(key(read_list_file(dir)), "engine.routing.domain.importFile");
    let big = dir.join("big.txt");
    std::fs::write(&big, vec![b'a'; MAX_LIST_BYTES as usize + 1]).unwrap();
    assert_eq!(
        key(read_list_file(&big)),
        "engine.routing.domain.importFile"
    );
    let ok = dir.join("list.txt");
    std::fs::write(&ok, b"\xef\xbb\xbffirst.com\r\nsecond.com\r\n\xff\n").unwrap();
    let parsed = parse_list(&read_list_file(&ok).unwrap());
    assert_eq!(parsed.patterns, vec![p("first.com"), p("second.com")]);
    assert_eq!(parsed.invalid, 1);
    assert!(read_list_file(&dir.join("missing.txt")).is_err());
}
