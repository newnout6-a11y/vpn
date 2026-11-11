use super::*;

fn titled(key: &str, value: &str) -> Option<String> {
    let mut meta = SubscriptionMeta::default();
    apply_meta(&mut meta, key, value);
    meta.title
}

/// `subscriptionBridgeDedupe.test.ts`: every title encoding panels use.
#[test]
fn profile_title_encodings() {
    let all_vpn = Some("ALL VPN".to_owned());
    assert_eq!(titled("profile-title", "base64:QUxMIFZQTg=="), all_vpn);
    assert_eq!(titled("profile-title", "\"base64:QUxMIFZQTg==\""), all_vpn);
    assert_eq!(titled("profile-title", "BASE64:QUxMIFZQTg=="), all_vpn);
    assert_eq!(titled("profile-title", "base64:\"QUxMIFZQTg==\""), all_vpn);
    assert_eq!(titled("Profile-Title", "base64:QUxMIFZQTg=="), all_vpn);
    assert_eq!(
        titled("profile-title", "My Provider VPN").as_deref(),
        Some("My Provider VPN")
    );
    let darwin = Some("Дарвин ВПН".to_owned());
    let encoded = "%D0%94%D0%B0%D1%80%D0%B2%D0%B8%D0%BD%20%D0%92%D0%9F%D0%9D";
    assert_eq!(
        titled("profile-title", &format!("UTF-8''{encoded}")),
        darwin
    );
    assert_eq!(titled("profile-title", encoded), darwin);
}

#[test]
fn undecodable_titles_stay_raw_and_blank_ones_are_dropped() {
    assert_eq!(
        titled("profile-title", "100% fast").as_deref(),
        Some("100% fast")
    );
    assert_eq!(
        titled("profile-title", "%E0%A4%A").as_deref(),
        Some("%E0%A4%A")
    );
    assert_eq!(
        titled("profile-title", "base64:@@@").as_deref(),
        Some("base64:@@@")
    );
    assert_eq!(titled("profile-title", "  \"\"  "), None);
    assert_eq!(titled("profile-title", "a\u{7}b"), Some("a b".to_owned()));
    assert_eq!(
        titled("profile-title", &"x".repeat(1000)).map(|t| t.len()),
        Some(MAX_TITLE_CHARS)
    );
}

/// servers §7 #16 and the userinfo rules of §2.12.
#[test]
fn userinfo_amounts_and_expiry() {
    let mut meta = SubscriptionMeta::default();
    apply_meta(
        &mut meta,
        "subscription-userinfo",
        "upload=0; download=2153701362; total=0; expire=1790951622",
    );
    assert_eq!(
        (meta.upload, meta.download, meta.total),
        (Some(0), Some(2_153_701_362), Some(0))
    );
    assert_eq!(meta.expires_at, Some(1_790_951_622_000));

    let mut meta = SubscriptionMeta::default();
    apply_meta(
        &mut meta,
        "SUBSCRIPTION-USERINFO",
        " Upload = 1.5e3 ;download=-5; total=abc; expire=0; junk ",
    );
    assert_eq!(
        (meta.upload, meta.download, meta.total, meta.expires_at),
        (Some(1500), None, None, None)
    );
}

/// P-21: the interval is in hours, positive decimal digits only.
#[test]
fn update_interval_is_hours() {
    let hours = |v: &str| {
        let mut meta = SubscriptionMeta::default();
        apply_meta(&mut meta, "profile-update-interval", v);
        meta.refresh_hours
    };
    assert_eq!(hours(" 12 "), Some(12));
    for bad in ["0", "-1", "+3", "1.5", "abc", "", "99999999999"] {
        assert_eq!(hours(bad), None, "{bad}");
    }
}

#[test]
fn links_must_be_http() {
    let mut meta = SubscriptionMeta::default();
    apply_meta(
        &mut meta,
        "profile-web-page-url",
        "HTTPS://Panel.Example.com/u/1",
    );
    apply_meta(&mut meta, "support-url", "\"https://t.me/support\"");
    assert_eq!(
        meta.web_page_url.as_deref(),
        Some("https://panel.example.com/u/1")
    );
    assert_eq!(meta.support_url.as_deref(), Some("https://t.me/support"));
    for bad in [
        "javascript:alert(1)",
        "/relative",
        "null",
        "ftp://x.example/",
        "",
    ] {
        let mut meta = SubscriptionMeta::default();
        apply_meta(&mut meta, "support-url", bad);
        assert_eq!(meta.support_url, None, "{bad}");
    }
}

#[test]
fn announce_plain_or_base64() {
    let mut meta = SubscriptionMeta::default();
    apply_meta(&mut meta, "announce", "base64:0J/RgNC40LLQtdGC");
    assert_eq!(meta.announce.as_deref(), Some("Привет"));
    apply_meta(&mut meta, "announce", &"y".repeat(500));
    assert_eq!(
        meta.announce.map(|a| a.chars().count()),
        Some(MAX_ANNOUNCE_CHARS)
    );
}

/// Happ body metadata: leading `#key: value` lines, the rest of the body returned for parsing.
#[test]
fn body_lines_before_the_configs() {
    let body = "#profile-title: base64:QUxMIFZQTg==\r\n# just a comment\n\n#subscription-userinfo: upload=1; download=2; total=3; expire=0\n#profile-update-interval: 12\n#support-url: https://t.me/x\n#announce: hello\nvless://u@h.example:443#A\n#profile-title: ignored\n";
    let (meta, rest) = body_meta(body);
    assert_eq!(meta.title.as_deref(), Some("ALL VPN"));
    assert_eq!(
        (meta.upload, meta.download, meta.total, meta.expires_at),
        (Some(1), Some(2), Some(3), None)
    );
    assert_eq!(meta.refresh_hours, Some(12));
    assert_eq!(meta.support_url.as_deref(), Some("https://t.me/x"));
    assert_eq!(meta.announce.as_deref(), Some("hello"));
    assert_eq!(rest, "vless://u@h.example:443#A\n#profile-title: ignored\n");

    let (meta, rest) = body_meta("dmxlc3M6Ly8=");
    assert_eq!((meta, rest), (SubscriptionMeta::default(), "dmxlc3M6Ly8="));
    assert_eq!(body_meta("#a: b\n# c").1, "");
}

/// §3.8: headers win field by field, the body fills the gaps, the filename is the last resort.
#[test]
fn headers_win_and_the_body_fills_gaps() {
    let (body, _) = body_meta(
        "#profile-title: Body Title\n#subscription-userinfo: total=5\n#profile-update-interval: 6\nvless://x",
    );
    let meta = header_meta(
        [
            ("Subscription-Userinfo", "upload=1; download=2"),
            ("profile-update-interval", "24"),
            ("content-disposition", "attachment; filename=\"file.txt\""),
        ],
        body,
    );
    assert_eq!(
        (meta.upload, meta.download, meta.total),
        (Some(1), Some(2), Some(5))
    );
    assert_eq!(meta.refresh_hours, Some(24));
    assert_eq!(meta.title.as_deref(), Some("Body Title"));

    let meta = header_meta(
        [("profile-title", "Header"), ("profile-title", "Last")],
        SubscriptionMeta::default(),
    );
    assert_eq!(meta.title.as_deref(), Some("Last"));
}

/// P-20 / P-21: a stray `%` in the filename keeps the raw name; the interval is 12 hours.
#[test]
fn content_disposition_names_the_subscription() {
    let meta = header_meta(
        [
            ("content-disposition", "attachment; filename=\"100%.txt\""),
            ("profile-update-interval", "12"),
        ],
        SubscriptionMeta::default(),
    );
    assert_eq!(meta.title.as_deref(), Some("100%"));
    assert_eq!(meta.refresh_hours, Some(12));
    let name =
        |v: &str| header_meta([("Content-Disposition", v)], SubscriptionMeta::default()).title;
    assert_eq!(
        name("attachment; filename*=UTF-8''%D0%92%D0%9F%D0%9D.yaml").as_deref(),
        Some("ВПН")
    );
    assert_eq!(name("inline; filename=sub.JSON").as_deref(), Some("sub"));
    assert_eq!(name("attachment"), None);
    assert_eq!(name("attachment; filename=\".txt\""), None);
    // RFC 6266: `filename*` (with or without a language tag) wins over the ASCII fallback.
    for value in [
        "attachment; filename=\"VPN.txt\"; filename*=UTF-8''%D0%92%D0%9F%D0%9D.txt",
        "attachment; filename*=utf-8'ru'%D0%92%D0%9F%D0%9D.txt; filename=\"VPN.txt\"",
    ] {
        assert_eq!(name(value).as_deref(), Some("ВПН"), "{value}");
    }
}
