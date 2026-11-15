//! Deep-link vectors (profiles spec §7.2 "happ unwrap", "happ add list", "MantaRay crypt", §7.3 P-22).
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use super::*;

fn ok(input: &str) -> Option<String> {
    unwrap_deeplink(input).unwrap_or_else(|e| panic!("{input}: {e}"))
}

fn err(input: &str) -> DeepLinkError {
    unwrap_deeplink(input).expect_err(input)
}

fn encrypted(app: &'static str, variant: &str) -> DeepLinkError {
    DeepLinkError::Encrypted {
        app,
        variant: variant.into(),
    }
}

/// The old `verify-happ-unwrap` vectors.
#[test]
fn happ_unwrap_vectors() {
    assert_eq!(
        ok("happ://add/https%3A%2F%2Fsosa.example%2Fsub%2Fabc123").as_deref(),
        Some("https://sosa.example/sub/abc123")
    );
    assert_eq!(
        ok("happ://add/https://example.com/sub/xyz").as_deref(),
        Some("https://example.com/sub/xyz")
    );
    assert_eq!(
        ok("happ://add/aHR0cHM6Ly9leGFtcGxlLmNvbS9zdWIvYWJjMTIz").as_deref(),
        Some("https://example.com/sub/abc123")
    );
    assert_eq!(
        ok("happ://add/vless%3A%2F%2Fuuid%40host%3A443").as_deref(),
        Some("vless://uuid@host:443")
    );
    assert_eq!(ok("https://example.com/sub"), None);
    assert_eq!(err("happ://crypt3/AAAA"), encrypted("Happ", "crypt3"));
    assert_eq!(err("happ://crypt5/AAAA"), encrypted("Happ", "crypt5"));
    assert_eq!(
        err("happ://routing/onadd/AAAA"),
        DeepLinkError::RoutingProfile
    );
    assert_eq!(
        err("happ://weird/something"),
        DeepLinkError::UnknownHost("happ://weird".into())
    );
}

/// K17: `happ://add/<base64 list>` yields only the first link.
#[test]
fn happ_add_list_yields_the_first_link() {
    let list = "vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One\n# comment\n\
                trojan://secret@two.example.com:443?sni=front.example.com#Two";
    let link = format!("happ://add/{}", URL_SAFE_NO_PAD.encode(list));
    assert_eq!(
        ok(&link).as_deref(),
        Some("vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One")
    );
}

/// P-22 (owner decision 10.3(A)): a JSON `{"url": …}` payload, `link` as fallback.
#[test]
fn happ_add_json_payload() {
    assert_eq!(
        ok("happ://add/eyJ1cmwiOiJodHRwczovL3N1Yi5leGFtcGxlLmNvbS9zIn0").as_deref(),
        Some("https://sub.example.com/s")
    );
    let link = format!(
        "happ://add/{}",
        STANDARD.encode(r#"{"link":"vless://u@h.example:443?security=tls#L"}"#)
    );
    assert_eq!(
        ok(&link).as_deref(),
        Some("vless://u@h.example:443?security=tls#L")
    );
    let pct = "happ://add/%7B%22url%22%3A%22https%3A%2F%2Fsub.example.com%2Fp%22%7D";
    assert_eq!(ok(pct).as_deref(), Some("https://sub.example.com/p"));
}

/// K18: encrypted links are refused, and nothing user-visible echoes the payload.
#[test]
fn encrypted_links_never_echo_the_payload() {
    let e = err("mantaray://crypt/super-secret-payload");
    assert_eq!(e, encrypted("MantaRay", "crypt"));
    let msg = e.msg();
    assert_eq!(msg.key, "profiles.deeplink.encryptedMantaray");
    let shown = format!("{e} {msg:?}");
    assert!(!shown.contains("super-secret-payload"), "{shown}");
    // New: `crypt` / `crypt2` were "unknown scheme" in the old app.
    assert_eq!(err("happ://crypt/AAAA"), encrypted("Happ", "crypt"));
    assert_eq!(err("happ://crypt2/AAAA"), encrypted("Happ", "crypt2"));
    assert_eq!(err("HAPP://CRYPT4/AAAA"), encrypted("Happ", "crypt4"));
    assert_eq!(err("happ://crypto/AAAA"), encrypted("Happ", "crypto"));
    assert_eq!(err("v2raytun://crypt/AAAA"), encrypted("v2RayTun", "crypt"));
    assert_eq!(
        err("happ://crypt4/AAAA").msg().key,
        "profiles.deeplink.encryptedHapp"
    );
    assert_eq!(
        err("v2raytun://crypt/AAAA").msg().key,
        "profiles.deeplink.encrypted"
    );
    // A payload without a `/` would be the "host": never shown.
    let e = err("happ://eyJ1cmwiOiJodHRwczovL3NlY3JldC5leGFtcGxlL3N1YiJ9");
    assert_eq!(e, DeepLinkError::UnknownHost("happ://…".into()));
}

/// p-subs (research happ-crypt.md, option C): the Happ refusal says where the plain link is (the
/// subscription page in a browser, Remnawave, the account page or bot, the provider) and never
/// talks about decrypting, in both languages.
#[test]
fn the_happ_refusal_points_at_the_plain_link() {
    let texts: Vec<String> = crate::LOCALES
        .iter()
        .flat_map(|(ru, en)| [ru, en])
        .filter_map(|json| {
            let doc: serde_json::Value = serde_json::from_str(json).ok()?;
            let text = doc.pointer("/profiles/deeplink/encryptedHapp")?;
            Some(text.as_str()?.to_lowercase())
        })
        .collect();
    assert_eq!(texts.len(), 2, "ru + en");
    for text in &texts {
        assert!(
            text.contains("remnawave") && text.contains("https"),
            "{text}"
        );
        assert!(
            !text.contains("decrypt") && !text.contains("расшифр"),
            "{text}"
        );
    }
    assert!(
        texts
            .iter()
            .any(|t| t.contains("браузер") && t.contains("бот"))
    );
    assert!(
        texts
            .iter()
            .any(|t| t.contains("browser") && t.contains("bot"))
    );
}

#[test]
fn mantaray_and_plain_wrappers() {
    for host in ["add", "import", "sub", "subscription"] {
        assert_eq!(
            ok(&format!("mantaray://{host}/https%3A%2F%2Fm.example%2Fs")).as_deref(),
            Some("https://m.example/s")
        );
    }
    assert_eq!(
        err("mantaray://other/x"),
        DeepLinkError::UnknownHost("mantaray://other".into())
    );
    assert_eq!(
        err("mantaray://add/"),
        DeepLinkError::AddPayloadUnrecognised
    );
    assert_eq!(
        ok("v2raytun://import/https://v.example/sub").as_deref(),
        Some("https://v.example/sub")
    );
    let key = "vless://u@h.example:443?security=reality#V";
    assert_eq!(
        ok(&format!("incy://add/{}", STANDARD.encode(key))).as_deref(),
        Some(key)
    );
    assert_eq!(
        ok(&format!("incy://import/{}", STANDARD.encode(key))).as_deref(),
        Some(key)
    );
    assert_eq!(err("incy://crypt/x"), encrypted("INCY", "crypt"));
}

#[test]
fn payload_forms() {
    // Percent-encoded base64 padding.
    let b64 = STANDARD.encode("https://example.com/s?x=1");
    assert!(b64.ends_with('='));
    assert_eq!(
        ok(&format!("happ://add/{}", b64.replace('=', "%3D"))).as_deref(),
        Some("https://example.com/s?x=1")
    );
    // A whole key line keeps a name with spaces; a key inside text loses glued punctuation.
    let line = "vless://u@h.example:443?security=tls#Germany (1)";
    let encoded: String =
        percent_encoding::utf8_percent_encode(line, percent_encoding::NON_ALPHANUMERIC).collect();
    assert_eq!(ok(&format!("happ://add/{encoded}")).as_deref(), Some(line));
    let text = STANDARD.encode("Ваш ключ (vless://u@h.example:443#N).");
    assert_eq!(
        ok(&format!("happ://add/{text}")).as_deref(),
        Some("vless://u@h.example:443#N")
    );
    let naive = "naive+https://user:pass@n.example:443#N";
    assert_eq!(
        ok(&format!("happ://add/{}", STANDARD.encode(naive))).as_deref(),
        Some(naive)
    );
    // A URL never carries what follows its first whitespace.
    let two = STANDARD.encode("https://a.example/s\nhttps://b.example/s");
    assert_eq!(
        ok(&format!("happ://add/{two}")).as_deref(),
        Some("https://a.example/s")
    );
    // Case-insensitive scheme and host; surrounding whitespace and BOM ignored.
    assert_eq!(
        ok("\u{feff}  HAPP://ADD/https%3A%2F%2Fa.example%2Fs \n").as_deref(),
        Some("https://a.example/s")
    );
    // A malformed escape leaves the text as is (decodeURIComponent semantics).
    assert_eq!(
        ok("happ://add/https://a.example/%E0%A4%A").as_deref(),
        Some("https://a.example/%E0%A4%A")
    );
}

#[test]
fn unrecognised_payloads_are_explicit_errors() {
    assert_eq!(err("happ://add"), DeepLinkError::AddPayloadUnrecognised);
    assert_eq!(err("happ://add/"), DeepLinkError::AddPayloadUnrecognised);
    assert_eq!(
        err("happ://add/hello%20world"),
        DeepLinkError::AddPayloadUnrecognised
    );
    assert_eq!(
        err("happ://add/AAAA"),
        DeepLinkError::AddPayloadUnrecognised
    );
    assert_eq!(
        err(r#"happ://add/{"url":"ftp://x.example/s"}"#),
        DeepLinkError::AddPayloadUnrecognised
    );
}

#[test]
fn other_input_is_not_a_deep_link() {
    for input in [
        "",
        "   ",
        "vless://u@h.example:443#N",
        "https://example.com/sub",
        "happ:///x",
        "happ://add/https%3A%2F%2Fa.example\nvless://u@h.example:443",
        "hiddify-next://import/https://x.example/s",
        "not a link",
    ] {
        assert_eq!(ok(input), None, "{input:?}");
    }
}

/// RU-2026 item 4: the remote-profile links of sing-box, Clash and Hiddify carry one
/// subscription URL (forms recorded in `crates/profiles/progress/w7-phones.md`).
#[test]
fn remote_profile_links_carry_their_url() {
    let sub = Some("https://sub.example/s/abc?t=1");
    // sing-box docs: `sing-box://import-remote-profile?url=urlEncodedURL#urlEncodedName`.
    let encoded = "https%3A%2F%2Fsub.example%2Fs%2Fabc%3Ft%3D1";
    assert_eq!(
        ok(&format!(
            "sing-box://import-remote-profile?url={encoded}#My%20VPN"
        ))
        .as_deref(),
        sub
    );
    assert_eq!(
        ok(&format!("SING-BOX://Import-Remote-Profile?url={encoded}")).as_deref(),
        sub
    );
    // Clash for Windows / Verge: `clash://install-config?url=…&name=…`, any parameter order.
    assert_eq!(
        ok(&format!("clash://install-config?name=X&url={encoded}")).as_deref(),
        sub
    );
    assert_eq!(
        ok("clash://install-config?url=https://sub.example/c.yaml&name=Y").as_deref(),
        Some("https://sub.example/c.yaml")
    );
    // Hiddify: the path after `import/` (query kept, fragment = name), or a `url` parameter.
    assert_eq!(
        ok("hiddify://import/https://sub.example/s/abc?t=1#Name").as_deref(),
        sub
    );
    assert_eq!(ok(&format!("hiddify://import/{encoded}")).as_deref(), sub);
    assert_eq!(
        ok(&format!("hiddify://install-config?url={encoded}#N")).as_deref(),
        sub
    );
    assert_eq!(
        ok(&format!("hiddify://install-sub?url={encoded}")).as_deref(),
        sub
    );
    // A key handed over by Hiddify's import link is a key, as with the other add links.
    assert_eq!(
        ok("hiddify://import/vless%3A%2F%2Fu%40h.example%3A443").as_deref(),
        Some("vless://u@h.example:443")
    );
}

#[test]
fn remote_profile_links_without_a_url_are_explicit_errors() {
    for input in [
        "sing-box://import-remote-profile",
        "sing-box://import-remote-profile?name=x",
        "sing-box://import-remote-profile?url=",
        "sing-box://import-remote-profile?url=ftp%3A%2F%2Fx.example%2Fs",
        "clash://install-config?url=vless%3A%2F%2Fu%40h.example%3A443",
        "hiddify://install-config",
        "hiddify://import/",
    ] {
        assert_eq!(err(input), DeepLinkError::AddPayloadUnrecognised, "{input}");
    }
    assert_eq!(
        err("sing-box://add-profile?url=https%3A%2F%2Fx.example"),
        DeepLinkError::UnknownHost("sing-box://add-profile".into())
    );
    assert_eq!(
        err("clash://https%3A%2F%2Fx.example%2Fs"),
        DeepLinkError::UnknownHost("clash://…".into())
    );
}

/// Every error key exists in both languages and `profiles.deeplink` holds nothing else.
#[test]
fn locale_fragments_cover_every_message() {
    let deeplink = [
        DeepLinkError::Encrypted {
            app: "Happ",
            variant: "crypt4".into(),
        },
        DeepLinkError::Encrypted {
            app: "MantaRay",
            variant: "crypt".into(),
        },
        DeepLinkError::Encrypted {
            app: "v2RayTun",
            variant: "crypt".into(),
        },
        DeepLinkError::RoutingProfile,
        DeepLinkError::AddPayloadUnrecognised,
        DeepLinkError::UnknownHost("happ://weird".into()),
        DeepLinkError::LocalTarget,
    ];
    let used: std::collections::BTreeSet<String> =
        deeplink.iter().map(|e| e.msg().key.into_owned()).collect();
    for key in &used {
        crate::test_locales::assert_localized(key);
    }
    let own: std::collections::BTreeSet<String> =
        crate::test_locales::package_keys("profiles-native")
            .into_iter()
            .filter(|k| k.starts_with("profiles.deeplink."))
            .collect();
    assert_eq!(used, own, "unused locale keys");
}

/// phones-a11: a link from a web page or a chat never makes the app request the user's own
/// network: loopback, LAN, link-local and local names are refused before any request, in every
/// notation the fetcher's URL parser accepts; internet hosts pass.
#[test]
fn links_into_a_local_network_are_refused() {
    let local = [
        "http://127.0.0.1:9090/configs?x",
        "http://0x7f.1/s",
        "http://2130706433/s",
        "http://[::1]/s",
        "http://[::ffff:127.0.0.1]/s",
        "https://192.168.1.1/sub",
        "http://10.0.0.1/s",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/s",
        "http://[fe80::1]/s",
        "http://[fd00::1]/s",
        "http://localhost:2017/s",
        "http://api.localhost/s",
        "http://router/s",
        "http://nas.local/s",
        "http://box.lan/s",
        "http://hub.home.arpa/s",
    ];
    for url in local {
        let encoded =
            percent_encoding::utf8_percent_encode(url, percent_encoding::NON_ALPHANUMERIC);
        let links = [
            format!("sing-box://import-remote-profile?url={encoded}#Name"),
            format!("clash://install-config?url={encoded}"),
            format!("hiddify://import/{url}"),
            format!("v2raytun://import/{url}"),
            format!("happ://add/{url}"),
        ];
        for link in links {
            assert_eq!(
                unwrap_deeplink(&link),
                Err(DeepLinkError::LocalTarget),
                "{link}"
            );
            // A redirect's Location carries it on: the fetcher's hop policy judges it by the
            // redirect's origin and the resolved addresses.
            assert_eq!(
                unwrap_redirect(&link).ok().flatten().as_deref(),
                Some(url),
                "{link}"
            );
        }
    }
    for url in [
        "https://sub.example.com/s/t",
        "http://8.8.8.8/s",
        "https://[2001:4860::8888]/s",
    ] {
        let link = format!("hiddify://import/{url}");
        assert_eq!(
            unwrap_deeplink(&link).unwrap().as_deref(),
            Some(url),
            "{link}"
        );
    }
}
