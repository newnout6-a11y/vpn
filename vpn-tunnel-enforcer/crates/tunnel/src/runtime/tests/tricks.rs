//! Item 18: stealth's TLS tricks reach both engines. sing-box gets them from its emitter; Xray's
//! `proxy_graph` has no stealth input, so the runtime resolves the default into the profile
//! before the start and the switch, and the "stealth does not apply" warning goes away.
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::EnginePref;

use super::*;
use crate::api::Runtime;
use crate::runtime::TunnelHandle;

fn spawn(world: &Arc<World>) -> TunnelHandle {
    TunnelHandle::spawn(deps(world))
}

fn stealthy(key: &str, engine: EnginePref) -> StartRequest {
    StartRequest {
        stealth: true,
        ..vpn_req(key, engine)
    }
}

/// The finalmask of the Xray slot config's proxy outbound.
fn finalmask(config: &Value) -> &Value {
    &config["outbounds"][0]["streamSettings"]["finalmask"]
}

fn strong_mask() -> Value {
    json!({ "tcp": [{ "type": "fragment",
        "settings": { "packets": "tlshello", "length": "100-200", "delay": "10-20" } }] })
}

#[tokio::test]
async fn stealth_tricks_reach_sing_box() {
    let w = World::new();
    let h = spawn(&w);
    h.start(
        stealthy(TLS_KEY, EnginePref::SingBox),
        CancellationToken::new(),
    )
    .await
    .expect("start");
    let config = w.configs.lock()[0].clone();
    let outbounds = config["outbounds"].as_array().expect("outbounds");
    let proxy = outbounds
        .iter()
        .find(|o| o["tag"] == "proxy-out")
        .expect("proxy-out");
    let tls = &proxy["tls"];
    assert_eq!(tls["record_fragment"], true, "{proxy}");
    assert_eq!(tls["fragment"], true, "{proxy}");
    assert_eq!(tls["fragment_fallback_delay"], "20ms", "{proxy}");
}

#[tokio::test]
async fn stealth_tricks_reach_xray_on_start_and_switch() {
    let w = World::new();
    let h = spawn(&w);
    let receipt = h
        .start(
            stealthy(XRAY_KEY, EnginePref::Xray),
            CancellationToken::new(),
        )
        .await
        .expect("slot start");
    let stealth = "engine.xray.warn.stealth";
    assert!(
        !receipt.warnings.iter().any(|m| m.key == stealth),
        "{:?}",
        receipt.warnings
    );
    assert_eq!(finalmask(&w.xray_configs.lock()[0]), &strong_mask());
    let owner: crate::api::OwnerCheck = Arc::new(|| true);
    let sw = h
        .switch_upstream(
            stealthy(XRAY_KEY_2, EnginePref::Xray),
            CancellationToken::new(),
            owner,
        )
        .await
        .expect("in place");
    assert!(sw.verified(), "{sw:?}");
    assert!(!sw.warnings.iter().any(|m| m.key == stealth), "{sw:?}");
    let configs = w.xray_configs.lock().clone();
    assert_eq!(configs.len(), 2);
    assert_eq!(finalmask(&configs[1]), &strong_mask());
}

/// Without stealth the key runs as it is: no tricks of its own, none added.
#[tokio::test]
async fn no_stealth_no_xray_tricks() {
    let w = World::new();
    let h = spawn(&w);
    h.start(
        vpn_req(XRAY_KEY, EnginePref::Xray),
        CancellationToken::new(),
    )
    .await
    .expect("slot start");
    assert_eq!(finalmask(&w.xray_configs.lock()[0]), &Value::Null);
}
