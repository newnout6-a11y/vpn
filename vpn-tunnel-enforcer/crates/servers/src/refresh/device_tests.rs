//! p-subs at the list level: an import that came from outside stays out of the local network
//! (phones-a11), a subscription's own device ID is sent, shown and undone, and a refused device
//! is recorded for the group. Loopback panels, fake keys.
use std::sync::Arc;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, Owner};
use vpnte_profiles::device::is_valid_hwid;

use super::tests::env;
use super::{AddOptions, AddOutcome};
use crate::model::{FetchOutcome, GroupId, GroupStatus};
use crate::subscription::tests::{KEY_A, Server, reply};

/// The x-hwid of every request, in order.
type Ids = Arc<Mutex<Vec<Option<String>>>>;

async fn panel() -> (Server, Ids) {
    let ids: Ids = Arc::default();
    let log = ids.clone();
    let server = Server::start(move |seen| {
        log.lock().push(seen.header("x-hwid").map(str::to_owned));
        reply("200 OK", &[], KEY_A.as_bytes())
    })
    .await;
    (server, ids)
}

fn options(send_hwid: bool, from_link: bool) -> AddOptions {
    AddOptions {
        send_hwid,
        from_link,
        ..AddOptions::new(None, ClientDevice::Pc)
    }
}

/// phones-a11: the same loopback subscription is refused when it came from a link or a QR code
/// (nothing is sent) and added when the user typed it.
#[tokio::test]
async fn an_import_from_outside_stays_out_of_the_lan() {
    let e = env();
    let (server, ids) = panel().await;
    let url = server.url("/sub/token").to_string();
    let err = e
        .servers
        .add_from_input_with(&e.ctx, &url, options(false, true), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "profiles.deeplink.localTarget");
    assert!(ids.lock().is_empty(), "nothing was sent");
    let added = e
        .servers
        .add_from_input_with(
            &e.ctx,
            &url,
            options(false, false),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(matches!(added, AddOutcome::Added { .. }));
}

/// A reset gives the subscription its own valid ID (sent, and shown in the summary); undo goes
/// back to this PC's ID; deleting the group forgets it; the manual group has no request.
#[tokio::test]
async fn a_reset_device_id_is_sent_and_can_be_undone() {
    let e = env();
    let (server, ids) = panel().await;
    let url = server.url("/sub/token").to_string();
    e.servers
        .add_from_input_with(&e.ctx, &url, options(true, false), CancellationToken::new())
        .await
        .unwrap();
    let id = subscription_id(&e.servers);
    let machine = ids.lock()[0].clone().expect("the HWID is on");
    e.servers.set_own_device_id(&id, true).unwrap();
    e.refresh(&id, Owner::Manual).await.unwrap();
    let own = ids.lock().last().cloned().flatten().unwrap();
    assert!(is_valid_hwid(&own) && own != machine, "{own}");
    let shown = e
        .servers
        .view()
        .groups
        .into_iter()
        .find(|g| g.id == id)
        .unwrap();
    assert_eq!(shown.own_hwid.as_deref(), Some(own.as_str()));
    e.servers.set_own_device_id(&id, false).unwrap();
    e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!(ids.lock().last().cloned().flatten(), Some(machine));
    e.servers.set_own_device_id(&id, true).unwrap();
    e.servers.delete_group(&id, true).unwrap();
    assert!(e.servers.read(|doc| doc.device_ids.is_empty()));
    let manual = e
        .servers
        .read(|doc| doc.manual_group().map(|g| g.id.clone()));
    if let Some(manual) = manual {
        let err = e.servers.set_own_device_id(&manual, true).unwrap_err();
        assert_eq!(err.user_msg().key, "servers.group.manualNoRequest");
    }
}

/// A refresh the panel refuses for the device keeps the rows and records the typed reason.
#[tokio::test]
async fn a_refused_device_is_recorded_for_the_group() {
    let e = env();
    let refuse = Arc::new(Mutex::new(false));
    let flag = refuse.clone();
    let server = Server::start(move |_| match *flag.lock() {
        true => reply("404 Not Found", &[("x-hwid-not-supported", "true")], b""),
        false => reply("200 OK", &[], KEY_A.as_bytes()),
    })
    .await;
    let url = server.url("/sub/token").to_string();
    e.servers
        .add_from_input_with(
            &e.ctx,
            &url,
            options(false, false),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let id = subscription_id(&e.servers);
    *refuse.lock() = true;
    let err = e.refresh(&id, Owner::Manual).await.unwrap_err();
    assert_eq!(err.user_msg().key, "servers.fetch.hwidRequired");
    let group = e.group(&id);
    assert_eq!(group.fetch.last_outcome, Some(FetchOutcome::HwidRequired));
    assert_eq!(group.status(0), GroupStatus::Failed);
    assert_eq!(e.rows().len(), 1, "the keys stay");
}

fn subscription_id(servers: &crate::store::Servers) -> GroupId {
    servers
        .read(|doc| {
            doc.groups
                .iter()
                .find(|g| !g.is_manual())
                .map(|g| g.id.clone())
        })
        .expect("a subscription group")
}

/// fix-ks b2: a group that came from a link keeps that mark, so its refreshes stay out of the
/// local network as its add did (the loopback panel sees nothing); deleting the group forgets
/// the mark.
#[tokio::test]
async fn a_linked_group_refreshes_out_of_the_lan() {
    let e = env();
    let (server, ids) = panel().await;
    let url = server.url("/sub/token").to_string();
    e.servers
        .add_from_input_with(
            &e.ctx,
            &url,
            options(false, false),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let id = subscription_id(&e.servers);
    let (_, typed) = e.servers.refresh_request(&id).unwrap();
    assert!(!typed.from_link, "typed by hand");
    e.servers.mark_linked(&id).unwrap();
    let (_, linked) = e.servers.refresh_request(&id).unwrap();
    assert!(linked.from_link);
    let sent = ids.lock().len();
    let _ = e.refresh(&id, Owner::Manual).await;
    assert_eq!(ids.lock().len(), sent, "nothing was sent into the LAN");
    e.servers.delete_group(&id, true).unwrap();
    assert!(!e.servers.read(|doc| doc.linked(&id)));
}
