//! Audit item 18: a provider's `tls.spoof` reaches sing-box only from an elevated process;
//! unelevated it is dropped from the started config with a notice naming the server.
use tokio_util::sync::CancellationToken;
use vpnte_base::types::EnginePref;

use super::*;
use crate::api::{Mode, Runtime, VpnProfile};
use crate::runtime::TunnelHandle;

fn spoofed_req() -> StartRequest {
    let doc = serde_json::json!({ "outbounds": [{
        "type": "trojan", "tag": "Spoofed", "server": "203.0.113.12", "server_port": 443,
        "password": "fake-password",
        "tls": { "enabled": true, "server_name": "example.com",
                 "spoof": "decoy.example", "spoof_method": "wrong-sequence" }
    }]});
    let profile = vpnte_profiles::json::parse_json(&doc)
        .profiles
        .into_iter()
        .next()
        .expect("one profile");
    StartRequest {
        mode: Mode::DirectVpn {
            profile: VpnProfile {
                id: "spoofed".into(),
                profile: Arc::new(profile),
                device: None,
                engine: EnginePref::Auto,
            },
        },
        engine: EnginePref::SingBox,
        ..local_req()
    }
}

/// The started config carries the spoof exactly when this process is elevated (CI runs both:
/// the workstation unelevated, the CI job elevated); unelevated the receipt says it was dropped.
#[tokio::test]
async fn tls_spoof_follows_the_process_rights() {
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    let receipt = h
        .start(spoofed_req(), CancellationToken::new())
        .await
        .expect("start");
    let config = w.configs.lock()[0].clone();
    let outbounds = config["outbounds"].as_array().expect("outbounds");
    let proxy = outbounds
        .iter()
        .find(|o| o["tag"] == "proxy-out")
        .expect("proxy-out");
    let notice = receipt
        .warnings
        .iter()
        .any(|m| m.key == "tunnel.runtime.spoofDropped");
    if vpnte_winnet::elevation::is_elevated() {
        assert_eq!(proxy["tls"]["spoof"], "decoy.example");
        assert!(!notice);
    } else {
        assert!(proxy["tls"].get("spoof").is_none(), "{proxy}");
        assert!(proxy["tls"].get("spoof_method").is_none());
        assert!(notice, "{:?}", receipt.warnings);
    }
}
