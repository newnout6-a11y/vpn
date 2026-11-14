use super::*;

/// Read-only: the settings of this machine are readable unelevated and stable between two reads.
/// Nothing is written (the machine's own network depends on its proxy settings).
#[test]
fn the_current_settings_read_unelevated() {
    let first = read().unwrap();
    assert_eq!(read().unwrap(), first);
}

/// The journal stores the config as JSON: camelCase, missing fields default.
#[test]
fn the_config_is_camel_case_with_defaults() {
    let config = ProxyConfig {
        use_proxy: true,
        server: "127.0.0.1:10808".into(),
        bypass: "localhost;127.*;<local>".into(),
        ..ProxyConfig::default()
    };
    let json = serde_json::to_value(&config).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"useProxy": true, "server": "127.0.0.1:10808",
            "bypass": "localhost;127.*;<local>", "usePac": false, "pacUrl": "", "autoDetect": false})
    );
    let partial: ProxyConfig = serde_json::from_str(r#"{"useProxy": true}"#).unwrap();
    assert_eq!(
        partial,
        ProxyConfig {
            use_proxy: true,
            ..ProxyConfig::default()
        }
    );
}

/// Writes a test proxy, reads it back, and puts back exactly what was there.
#[test]
#[ignore = "changes system state"]
fn system_write_reads_back_and_restores() {
    let original = read().unwrap();
    let test = ProxyConfig {
        use_proxy: true,
        server: "127.0.0.1:9".into(),
        bypass: "localhost;127.*;[::1];<local>".into(),
        use_pac: false,
        pac_url: String::new(),
        auto_detect: false,
    };
    let written = write(&test);
    let back = read();
    let restored = write(&original);
    written.unwrap();
    restored.unwrap();
    assert_eq!(back.unwrap(), test);
    assert_eq!(read().unwrap(), original);
}
