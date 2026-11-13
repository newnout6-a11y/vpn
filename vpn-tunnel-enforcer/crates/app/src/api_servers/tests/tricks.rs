//! Item 18: the detail editor's TLS tricks over a real list — what it shows, what a pick
//! stores, that the run profile (tunnel, helper service) carries it, and where there is none.
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::{HelloSplit, Span, TlsTricks};
use vpnte_servers::model::{ProfileId, RowTricks};
use vpnte_ui::servers::{AddTarget, ServersApi, SubscriptionRequest, TricksChoice, TricksSplit};

use super::super::ServersBackend;
use super::backend::Env;
use super::locales;

const ID: &str = "00000000-0000-4000-8000-000000000001";
const PBK: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";

/// Pastes `keys` and answers the new rows' ids in list order.
async fn pasted(env: &Env, api: &ServersBackend, keys: &str) -> Vec<ProfileId> {
    let target = AddTarget::Auto;
    api.add(
        keys.to_owned(),
        target,
        ClientDevice::Pc,
        SubscriptionRequest::default(),
    )
    .await
    .expect("added");
    env.backend
        .servers
        .view()
        .servers
        .iter()
        .map(|s| s.id.clone())
        .collect()
}

#[tokio::test]
async fn tricks_editor_over_a_real_list() {
    locales();
    let env = Env::new("tricks");
    let api = ServersBackend::start(env.backend.clone());
    let keys = [
        format!("vless://{ID}@plain.example:443?security=tls&sni=plain.example#plain"),
        format!(
            "vless://{ID}@own.example:443?security=tls&sni=own.example&fragment=1,40-60,30-50#own"
        ),
        format!(
            "vless://{ID}@r.example:443?security=reality&sni=www.example.com&pbk={PBK}&sid=ab#reality"
        ),
        "hy2://secret@hy2.example:443?sni=hy2.example#quic".to_owned(),
    ];
    let ids = pasted(&env, &api, &keys.join("\n")).await;
    let id = |name: &str| {
        let servers = env.backend.servers.view().servers;
        let row = servers.iter().find(|s| s.name == name).expect("row");
        assert!(ids.contains(&row.id));
        row.id.to_string()
    };
    let (plain, own) = (id("plain"), id("own"));
    // REALITY and QUIC: no editor.
    assert_eq!(api.tls_tricks(&id("reality")).await.expect("read"), None);
    assert_eq!(api.tls_tricks(&id("quic")).await.expect("read"), None);

    let view = api.tls_tricks(&plain).await.expect("read").expect("editor");
    assert_eq!(view.choice, TricksChoice::Default);
    assert!(!view.default_strong);
    api.set_tls_tricks(&plain, TricksChoice::Strong)
        .await
        .expect("set");
    let row = env
        .backend
        .servers
        .get(&plain.as_str().into())
        .expect("row");
    assert_eq!(row.tls_tricks, Some(RowTricks::Set(TlsTricks::STRONG)));
    let view = api.tls_tricks(&plain).await.expect("read").expect("editor");
    assert_eq!(view.choice, TricksChoice::Strong);
    // Back to the default: nothing stored, the key follows the settings again.
    api.set_tls_tricks(&plain, TricksChoice::Default)
        .await
        .expect("set");
    let row = env
        .backend
        .servers
        .get(&plain.as_str().into())
        .expect("row");
    assert_eq!(row.tls_tricks, None);

    // The provider's split shows as its own option; «As in settings» overrides it (review a7).
    let provider = TricksChoice::Custom {
        record: false,
        split: TricksSplit {
            len: (40, 60),
            interval_ms: (30, 50),
        },
    };
    let view = api.tls_tricks(&own).await.expect("read").expect("editor");
    assert_eq!(view.choice, provider);
    api.set_tls_tricks(&own, TricksChoice::Default)
        .await
        .expect("set");
    let row = env.backend.servers.get(&own.as_str().into()).expect("row");
    assert_eq!(row.tls_tricks, Some(RowTricks::Default));
    let view = api.tls_tricks(&own).await.expect("read").expect("editor");
    assert_eq!(view.choice, TricksChoice::Default);
    // What the tunnel and the helper service get: the app default, not the link's split.
    let fingerprints = Default::default();
    let run = crate::svc_tunnel::vpn_profile(row, &fingerprints).expect("runs");
    assert_eq!(run.profile.own_tls_tricks(), None);
    assert_eq!(run.profile.tls_tricks_for(true), TlsTricks::STRONG);
    // Picking the provider's option again stores nothing: refreshes are followed.
    api.set_tls_tricks(&own, provider).await.expect("set");
    let row = env.backend.servers.get(&own.as_str().into()).expect("row");
    assert_eq!(row.tls_tricks, None);
    let run = crate::svc_tunnel::vpn_profile(row, &fingerprints).expect("runs");
    let split = HelloSplit {
        len: Span::new(40, 60),
        interval_ms: Span::new(30, 50),
    };
    assert_eq!(run.profile.tls_tricks_for(true), TlsTricks::Hello(split));

    // The adaptive bypass's TLS compatibility makes the default «Сильно» too (review a7).
    env.tunnel.connect_to(&id("quic"));
    env.tunnel.session.send_modify(|s| {
        if let Some(s) = s.as_mut() {
            s.adaptive = vpnte_base::types::AdaptiveMode::TlsCompatibility;
        }
    });
    let view = api.tls_tricks(&plain).await.expect("read").expect("editor");
    assert!(view.default_strong);
    env.tunnel.session.send_replace(None);
    let view = api.tls_tricks(&plain).await.expect("read").expect("editor");
    assert!(!view.default_strong);

    // Stealth on: the default line says «Сильно».
    env.backend
        .settings
        .update(|s| s.stealth_mode = true)
        .expect("stealth");
    let view = api.tls_tricks(&plain).await.expect("read").expect("editor");
    assert!(view.default_strong);
    assert!(api.tls_tricks("missing").await.is_err());
}

/// The merged profile (the user's choice over a link's own split) passes the bundled engines:
/// `sing-box check` on its stealth outbound and `xray run -test` on its slot config. Skipped
/// quietly where the engines are not fetched.
#[tokio::test]
async fn merged_profiles_pass_the_real_engines() {
    use serde_json::json;
    use vpnte_base::types::Creds;
    use vpnte_engine::slot::SlotEndpoint;
    use vpnte_engine::xray_config::{build_config, proxy_graph};
    use vpnte_profiles::emit_singbox::{EmitPolicy, emit_singbox};
    use vpnte_servers::model::{Origin, ServerRow};

    let resources =
        std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    let (singbox, xray) = (resources.join("sing-box.exe"), resources.join("xray.exe"));
    if !singbox.exists() || !xray.exists() {
        return;
    }
    let link = format!(
        "vless://{ID}@own.example:443?security=tls&sni=own.example&type=ws&path=%2Fws&fragment=1,40-60,30-50#own"
    );
    let profile = vpnte_profiles::uri::parse_uri(&link).expect("parses");
    let split = HelloSplit {
        len: Span::new(10, 30),
        interval_ms: Span::new(5, 10),
    };
    let choices = [
        RowTricks::Set(TlsTricks::STRONG),
        RowTricks::Set(TlsTricks::Record),
        RowTricks::Set(TlsTricks::Both(split)),
        RowTricks::Set(TlsTricks::Off),
        RowTricks::Default,
    ];
    let policy = EmitPolicy {
        tls_compat: true,
        ..EmitPolicy::default()
    };
    let creds = Creds {
        user: "slot-user".into(),
        pass: "slot-password".into(),
    };
    let ep = SlotEndpoint::new(20190, creds).expect("endpoint");
    for choice in choices {
        let mut row =
            ServerRow::new(&profile, "g".into(), Origin::Manual, ClientDevice::Pc, 0).expect("row");
        row.tls_tricks = Some(choice);
        let run = crate::svc_tunnel::vpn_profile(row, &Default::default()).expect("runs");
        let fragment = emit_singbox(&run.profile, "proxy-out", &policy).expect("emits");
        let mut outbounds = fragment.outbounds().to_vec();
        outbounds.push(json!({ "type": "direct", "tag": "direct-out" }));
        let config = json!({ "log": { "level": "error" }, "outbounds": outbounds,
                             "route": { "final": "proxy-out" } });
        let config = config.to_string();
        let checked = vpnte_engine::singbox_process::check_config(&singbox, config.as_bytes());
        checked
            .await
            .unwrap_or_else(|e| panic!("{choice:?}: sing-box: {e:?}"));
        let graph = proxy_graph(&run.profile, ClientDevice::Pc).expect("graph");
        let slot = build_config(&graph, &ep).to_string();
        let checked = vpnte_engine::xray_process::check_config(&xray, slot.as_bytes());
        checked
            .await
            .unwrap_or_else(|e| panic!("{choice:?}: xray: {e:?}"));
    }
}
