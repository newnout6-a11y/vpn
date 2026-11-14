//! `tls.spoof` / `tls.spoof_method` (sing-box 1.14: a decoy ClientHello with another SNI sent
//! before the real one) need administrator rights on Windows (raw packets; ru-2026 §6). A
//! provider's sing-box JSON may carry them (kept as `singbox_extra`, re-emitted by
//! `emit_singbox`). A process without those rights must never start a config that needs them:
//! unelevated they are dropped (the caller tells the user), elevated they stay.
use serde_json::Value;
use vpnte_profiles::emit_singbox::SingBoxFragment;

/// The TLS keys that need an elevated sing-box.
pub const SPOOF_KEYS: [&str; 2] = ["spoof", "spoof_method"];

/// Removes [`SPOOF_KEYS`] from the `tls` of every entry of `fragment` unless `elevated`; `true`
/// when something was removed (show the caller's notice).
pub fn gate_spoof(fragment: &mut SingBoxFragment, elevated: bool) -> bool {
    if elevated {
        return false;
    }
    let entries: &mut [Value] = match fragment {
        SingBoxFragment::Outbound(o) | SingBoxFragment::Endpoint(o) => std::slice::from_mut(o),
        SingBoxFragment::Chain(list) => list,
    };
    let mut dropped = false;
    for entry in entries {
        if let Some(tls) = entry.get_mut("tls").and_then(Value::as_object_mut) {
            for key in SPOOF_KEYS {
                dropped |= tls.remove(key).is_some();
            }
        }
    }
    dropped
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vpnte_profiles::emit_singbox::{EmitPolicy, emit_singbox};

    use super::*;

    /// A provider's sing-box outbound with a TLS spoof (fake values, documentation address).
    fn spoofed() -> SingBoxFragment {
        let doc = json!({ "outbounds": [{
            "type": "trojan", "tag": "p", "server": "203.0.113.12", "server_port": 443,
            "password": "fake-password",
            "tls": { "enabled": true, "server_name": "example.com",
                     "spoof": "decoy.example", "spoof_method": "wrong-sequence" }
        }]});
        let report = vpnte_profiles::json::parse_json(&doc);
        let p = report.profiles.into_iter().next().expect("one profile");
        emit_singbox(&p, "proxy-out", &EmitPolicy::default()).expect("emits")
    }

    /// Audit item 18: unelevated, the spoof keys are dropped (reported); elevated, kept as given;
    /// a config without them is untouched either way.
    #[test]
    fn spoof_needs_elevation() {
        let original = spoofed();
        let tls = |f: &SingBoxFragment| f.outbounds()[0]["tls"].clone();
        assert_eq!(
            tls(&original)["spoof"],
            "decoy.example",
            "re-emitted as given"
        );

        let mut elevated = original.clone();
        assert!(!gate_spoof(&mut elevated, true));
        assert_eq!(elevated, original);

        let mut unelevated = original.clone();
        assert!(gate_spoof(&mut unelevated, false));
        let kept = tls(&unelevated);
        assert!(kept.get("spoof").is_none() && kept.get("spoof_method").is_none());
        assert_eq!(kept["server_name"], "example.com", "the rest of tls stays");
        assert!(!gate_spoof(&mut unelevated, false), "nothing left to drop");
    }

    /// The gated config passes the real `sing-box check` (skipped without the binary).
    #[test]
    fn gated_outbound_passes_sing_box_check() {
        let mut fragment = spoofed();
        gate_spoof(&mut fragment, false);
        let mut outbound = fragment.outbounds()[0].clone();
        outbound["tag"] = json!("proxy-out");
        let config = json!({ "outbounds": [outbound], "route": { "final": "proxy-out" } });
        crate::test_support::singbox_check(&config).unwrap();
    }
}
