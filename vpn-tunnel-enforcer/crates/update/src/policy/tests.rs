use super::*;

/// The compiled ranges replace "1.14.x only": sing-box from the bundled 1.14.4 inside 1.14,
/// Xray from the bundled 26.11.9 on; unknown engines are never allowed.
#[test]
fn engine_ranges_start_at_the_bundled_versions() {
    assert!(
        engine_allowed(SINGBOX, Version(1, 14, 4)) && engine_allowed(SINGBOX, Version(1, 14, 9))
    );
    assert!(
        !engine_allowed(SINGBOX, Version(1, 14, 3)) && !engine_allowed(SINGBOX, Version(1, 15, 0))
    );
    assert!(engine_allowed(XRAY, Version(26, 11, 9)) && engine_allowed(XRAY, Version(27, 1, 0)));
    assert!(!engine_allowed(XRAY, Version(26, 11, 8)));
    assert!(!engine_allowed("mihomo", Version(1, 19, 34)));
    assert_eq!(
        engine_range(SINGBOX).and_then(|r| r.minimum()),
        Some(Version(1, 14, 4))
    );
}

/// The keys are placeholders until the owner creates them: nothing verifies, nothing is checked.
#[test]
fn placeholder_keys_mean_no_channel() {
    assert_eq!(keys_ready(), !trusted_keys().is_empty());
    assert!(CURRENT_KEY.is_empty() || PublicKey::from_base64(CURRENT_KEY).is_ok());
    assert_eq!(app_version().to_string(), env!("CARGO_PKG_VERSION"));
}

/// Feed mirrors are https and never the rate-limited API host.
#[test]
fn feed_bases_avoid_the_api_host() {
    for base in FEED_BASES {
        assert!(
            base.starts_with("https://") && base.ends_with('/'),
            "{base}"
        );
        assert!(!base.contains("api.github.com"), "{base}");
    }
}

/// The bundled versions come from the compiled manifest and lie inside the ranges (read, not
/// hard-coded: an engine bump by engines-watch keeps this valid).
#[test]
fn bundled_versions_come_from_the_manifest() {
    let singbox = bundled_version(SINGBOX).unwrap();
    assert_eq!(
        (singbox.0, singbox.1),
        (1, 14),
        "the generated config is for sing-box 1.14"
    );
    assert!(bundled_version(XRAY).is_some());
    assert_eq!(bundled_version("nope"), None);
    for id in [SINGBOX, XRAY] {
        let bundled = bundled_version(id).unwrap();
        assert!(engine_allowed(id, bundled), "{id}");
        let minimum = engine_range(id).and_then(|r| r.minimum());
        assert!(minimum.is_some_and(|m| m <= bundled), "{id}");
    }
}
