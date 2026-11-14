//! A refresh commits what the answer says about the subscription itself (ru-2026 items 2, 3,
//! 22): the provider's controls, a sealed fallback URL that later refreshes use, and a permanent
//! move with its note. Loopback panels, fake URLs.
use std::sync::Arc;

use parking_lot::Mutex;
use vpnte_base::types::Owner;
use vpnte_core::secret::Secret;
use vpnte_profiles::text::AutoconnectPick;

use super::tests::env;
use crate::model::GroupKind;
use crate::subscription::tests::{KEY_A, KEY_B, Server, closed_port, reply};

fn list() -> Vec<u8> {
    format!("{KEY_A}\n{KEY_B}\n").into_bytes()
}

/// Controls and the fallback URL are kept; a permanent move re-points the group with a note,
/// and the rows and the selection stay.
#[tokio::test]
async fn controls_fallback_and_move_are_committed() {
    let answer = Arc::new(Mutex::new("plain"));
    let mode = answer.clone();
    let server = Server::start_tls(move |seen| {
        let host = seen.header("host").unwrap_or_default().to_owned();
        let next = format!("https://{host}/moved/token");
        let mirror = format!("https://{host}/mirror/token");
        match (*mode.lock(), seen.path.as_str()) {
            ("controls", _) => {
                let body = format!(
                    "#hide-settings: 1\n#subscription-autoconnect: 1\n#subscription-autoconnect-type: lastused\n//routing: happ://routing/add/e30=\n{KEY_A}\n{KEY_B}\n"
                );
                reply("200 OK", &[("fallback-url", mirror.as_str())], body.as_bytes())
            }
            ("move", "/feed/token") => reply("200 OK", &[("new-url", next.as_str())], &list()),
            _ => reply("200 OK", &[], &list()),
        }
    })
    .await;
    let e = env();
    let id = e.import(&server.url("/feed/token")).await;
    let rows = e.rows();

    *answer.lock() = "controls";
    e.refresh(&id, Owner::Manual).await.unwrap();
    let group = e.group(&id);
    assert!(group.hides_settings());
    assert_eq!(group.controls.autoconnect, Some(true));
    assert_eq!(
        group.controls.autoconnect_pick,
        Some(AutoconnectPick::LastUsed)
    );
    assert_eq!(
        group.controls.routing.as_deref(),
        Some("happ://routing/add/e30=")
    );
    let fallback = group.fallback.as_ref().and_then(Secret::expose);
    assert_eq!(fallback, Some(server.url("/mirror/token").as_str()));
    let summary = e
        .servers
        .view()
        .groups
        .into_iter()
        .find(|g| g.id == id)
        .unwrap();
    assert!(summary.controls.hides_settings());

    *answer.lock() = "move";
    e.refresh(&id, Owner::Manual).await.unwrap();
    let group = e.group(&id);
    assert_eq!(group.url(), Some(server.url("/moved/token")));
    assert!(group.moved_at.is_some());
    assert_eq!(e.rows().len(), rows.len());
    assert_eq!(group.device(), Some(vpnte_base::types::ClientDevice::Pc));
}

/// The stored fallback URL serves a refresh whose URL is dead; the URL stays as it was.
#[tokio::test]
async fn stored_fallback_serves_a_dead_url() {
    let mirror = Server::start_tls(|_| reply("200 OK", &[], &list())).await;
    let e = env();
    let id = e.import(&mirror.url("/feed/token")).await;
    let dead = format!("https://127.0.0.1:{}/feed/token", closed_port().await);
    e.servers
        .update(|doc| {
            let group = doc.group_mut(&id).unwrap();
            group.kind = GroupKind::Subscription {
                url: Secret::new(&dead),
                device: vpnte_base::types::ClientDevice::Pc,
            };
            group.fallback = Some(Secret::new(mirror.url("/mirror/token").as_str()));
            Ok(())
        })
        .unwrap();
    let report = e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!(report.updated, 2);
    let group = e.group(&id);
    assert_eq!(group.url().map(String::from), Some(dead));
    assert_eq!(group.moved_at, None);
    assert_eq!(mirror.seen().last().unwrap().path, "/mirror/token");
}

/// A first answer that moves the subscription creates the group at the new address with the
/// note; a later move onto an address another group of the device has is not applied.
#[tokio::test]
async fn moves_at_import_and_onto_a_known_subscription() {
    let moving = Arc::new(Mutex::new(false));
    let flag = moving.clone();
    let server = Server::start_tls(move |seen| {
        let host = seen.header("host").unwrap_or_default().to_owned();
        let to_b = format!("https://{host}/b");
        match seen.path.as_str() {
            "/old" => reply("200 OK", &[("new-url", to_b.as_str())], &list()),
            "/a" if *flag.lock() => reply("200 OK", &[("new-url", to_b.as_str())], &list()),
            _ => reply("200 OK", &[], &list()),
        }
    })
    .await;
    let e = env();
    let first = e.import(&server.url("/old")).await;
    assert_eq!(e.group(&first).url(), Some(server.url("/b")));
    assert!(e.group(&first).moved_at.is_some());

    let a = e.import(&server.url("/a")).await;
    assert_ne!(a, first);
    *moving.lock() = true;
    e.refresh(&a, Owner::Manual).await.unwrap();
    assert_eq!(
        e.group(&a).url(),
        Some(server.url("/a")),
        "taken: not moved"
    );
    assert_eq!(e.group(&a).moved_at, None);
}

/// subs-b1: a plain `http` panel's move and fallback hints are not committed, at import or at a
/// refresh: anyone on the path could have written them, and the group would follow for good.
#[tokio::test]
async fn cleartext_hints_are_not_committed() {
    let server = Server::start(|seen| {
        let host = seen.header("host").unwrap_or_default().to_owned();
        let next = format!("https://{host}/moved/token");
        let hints = [("new-url", next.as_str()), ("fallback-url", next.as_str())];
        reply("200 OK", &hints, &list())
    })
    .await;
    let e = env();
    let url = server.url("/feed/token");
    let id = e.import(&url).await;
    e.refresh(&id, Owner::Manual).await.unwrap();
    let group = e.group(&id);
    assert_eq!(group.url(), Some(url));
    assert_eq!(group.moved_at, None);
    assert_eq!(group.fallback, None);
}

/// subs-a4 / subs-b9: a subscription that hides its configs, fetched into another group (the
/// manual keys here), brings its new keys in hidden: no copy, save or export from there either.
/// A key the user already had there stays as it was.
#[tokio::test]
async fn hidden_keys_fetched_into_another_group_stay_hidden() {
    use tokio_util::sync::CancellationToken;
    use vpnte_base::types::ClientDevice;

    use crate::refresh::AddOutcome;

    let server = Server::start(|_| reply("200 OK", &[("hide-settings", "1")], &list())).await;
    let e = env();
    let add = |input: String, into| {
        let e = &e;
        async move {
            let cancel = CancellationToken::new();
            let ctx = &e.ctx;
            match e
                .servers
                .add_from_input(ctx, &input, into, ClientDevice::Pc, cancel)
                .await
                .unwrap()
            {
                AddOutcome::Added { report, .. } => report,
                other => panic!("expected keys added, got {other:?}"),
            }
        }
    };
    let own = add(KEY_A.to_owned(), None).await;
    let manual = own.group.clone();
    let fetched = add(server.url("/feed/token").to_string(), Some(manual.clone())).await;
    assert_eq!((fetched.group.clone(), fetched.added.len()), (manual, 1));
    let refused = e.servers.shareable_profile(&fetched.added[0]).unwrap_err();
    assert_eq!(refused.user_msg().key, "servers.hidden.refused");
    assert!(e.servers.shareable_profile(&own.added[0]).is_ok());
    let hidden = e.servers.hidden_rows();
    assert!(hidden.contains(&fetched.added[0]) && !hidden.contains(&own.added[0]));
}
