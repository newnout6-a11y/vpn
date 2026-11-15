//! Item 18 at the level of the started config: the whole sing-box config a tunnel start builds
//! (TUN and proxy form, the EmitPolicy the tunnel derives from stealth / TLS compatibility)
//! carries a key's tricks on `proxy-out`, the stealth default for keys without their own, none
//! on REALITY, and passes `sing-box check` (skipped quietly without the binary).
use serde_json::{Value, json};
use vpnte_profiles::emit_singbox::EmitPolicy;
use vpnte_profiles::model::{Profile, TlsTricks};
use vpnte_profiles::uri::parse_uri;

use super::tests::inputs;
use super::{Capture, Upstream, build};
use crate::test_support::singbox_check;

const ID: &str = "00000000-0000-4000-8000-000000000001";
/// Public sample key from the sing-box docs (not a credential).
const PBK: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";

/// `record_fragment`, `fragment`, `fragment_fallback_delay` of `proxy-out` in both forms of the
/// started config, after `sing-box check` accepted each.
fn started(p: &Profile, stealth: bool) -> [Option<Value>; 3] {
    // runtime::start: `tls_compat: req.stealth || req.adaptive == TlsCompatibility`.
    let policy = EmitPolicy {
        tls_compat: stealth,
        ..EmitPolicy::default()
    };
    let upstream = || Upstream::native(p, &policy).expect("emits");
    let tun = inputs(upstream());
    let mut proxy = inputs(upstream());
    proxy.capture = Capture::Proxy { port: 25560 };
    let mut seen = Vec::new();
    for i in [tun, proxy] {
        let config = build(&i).expect("builds");
        if let Err(e) = singbox_check(&config) {
            panic!("sing-box refused the started config: {e}");
        }
        let outbounds = config["outbounds"].as_array().expect("outbounds");
        let out = outbounds.iter().find(|o| o["tag"] == "proxy-out");
        let tls = &out.expect("proxy-out")["tls"];
        let keys = ["record_fragment", "fragment", "fragment_fallback_delay"];
        seen.push(keys.map(|k| tls.get(k).cloned()));
    }
    assert_eq!(seen[0], seen[1], "TUN and proxy form differ");
    seen.swap_remove(0)
}

#[test]
fn started_config_carries_the_tricks() {
    let link = |query: &str| {
        let line = format!("vless://{ID}@nl.example:443?security=tls&sni=nl.example{query}#T");
        parse_uri(&line).expect("link")
    };
    let both = [Some(json!(true)), Some(json!(true)), Some(json!("20ms"))];
    let record = [Some(json!(true)), None, None];
    let none = [None, None, None];
    // The key's own value, whatever the stealth switch says.
    let own = link("&fragment=tlshello,100-200,10-20");
    assert_eq!(started(&own, false), both);
    let own_record = link("&fragment=tlshello,100-200,0");
    assert_eq!(started(&own_record, true), record);
    // No value of its own: the stealth default (both), or nothing.
    let plain = link("");
    assert_eq!(started(&plain, true), both);
    assert_eq!(started(&plain, false), none);
    let mut off = link("");
    off.tls.as_mut().expect("tls").tricks = Some(TlsTricks::Off);
    assert_eq!(started(&off, true), none);
    // REALITY never on sing-box (it would run on Xray under Auto anyway).
    let reality = parse_uri(&format!(
        "vless://{ID}@nl.example:443?security=reality&pbk={PBK}&sid=1234&sni=www.example.com&fragment=tlshello,100-200,10-20#R"
    ))
    .expect("link");
    assert_eq!(started(&reality, true), none);
}
