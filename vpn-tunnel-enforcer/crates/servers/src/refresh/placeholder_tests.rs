//! p-live-fix 1d: a loopback panel that answers by User-Agent the way Remnawave does — its
//! placeholders («Приложение не поддерживается» at 0.0.0.0:1) to clients it refuses, a real list to
//! the client it supports, an encrypted list to Happ. Fake keys only.
use std::sync::Arc;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Owner;
use vpnte_profiles::device::agent_family;

use super::tests::{Env, env};
use crate::model::{FetchOutcome, GroupId, GroupStatus};
use crate::subscription::tests::{KEY_A, KEY_B, Server, reply};

const SAID: &str = "Приложение не поддерживается";

/// What the panel serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Panel {
    /// A real list to this User-Agent family, Happ's list encrypted, placeholders to the rest.
    Supports(&'static str),
    /// Placeholders to every client (a rule that answers with remarks).
    RefusesAll,
    /// Remnawave with its HWID check on: placeholders and its headers without `x-hwid`.
    WantsHwid,
    /// Happ gets its encrypted list, everyone else a 404.
    OnlyHapp,
}

/// The panel, its mode (switchable) and the User-Agent family of every request.
struct Fake {
    server: Server,
    mode: Arc<Mutex<Panel>>,
    agents: Arc<Mutex<Vec<String>>>,
}

fn percent(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn placeholder() -> String {
    format!(
        "vless://00000000-0000-4000-8000-000000000000@0.0.0.0:1?security=none&type=tcp#{}",
        percent(SAID)
    )
}

async fn fake(mode: Panel) -> Fake {
    let mode = Arc::new(Mutex::new(mode));
    let agents: Arc<Mutex<Vec<String>>> = Arc::default();
    let (now, log) = (mode.clone(), agents.clone());
    let server = Server::start(move |seen| {
        let ua = seen.header("user-agent").unwrap_or_default().to_owned();
        let family = agent_family(&ua).to_owned();
        log.lock().push(family.clone());
        let list = format!("{KEY_A}\n{KEY_B}\n");
        let stub = placeholder();
        match *now.lock() {
            Panel::Supports(ours) if family == ours => reply("200 OK", &[], list.as_bytes()),
            Panel::Supports(_) | Panel::OnlyHapp if family == "Happ" => reply(
                "200 OK",
                &[],
                b"happ://crypt5/QUJDREVGR0hJSktMTU5PUFFSU1RVVldY",
            ),
            Panel::OnlyHapp => reply("404 Not Found", &[], b""),
            Panel::WantsHwid if seen.header("x-hwid").is_some() => {
                reply("200 OK", &[("x-hwid-active", "true")], list.as_bytes())
            }
            Panel::WantsHwid => reply(
                "200 OK",
                &[
                    ("x-hwid-active", "true"),
                    ("x-hwid-not-supported", "true"),
                    ("x-hwid-limit", "true"),
                ],
                stub.as_bytes(),
            ),
            Panel::Supports(_) | Panel::RefusesAll => reply("200 OK", &[], stub.as_bytes()),
        }
    })
    .await;
    Fake {
        server,
        mode,
        agents,
    }
}

impl Fake {
    fn seen(&self) -> Vec<String> {
        std::mem::take(&mut *self.agents.lock())
    }
}

fn live(e: &Env, id: &GroupId) -> usize {
    e.servers.read(|doc| {
        doc.profiles
            .iter()
            .filter(|r| &r.group_id == id && r.archived.is_none() && r.missing_since.is_none())
            .count()
    })
}

/// The rotation passes Happ (encrypted: not read) and v2rayN (placeholders) and takes the list
/// of the client the panel supports; no placeholder is stored; the client is remembered.
#[tokio::test]
async fn the_rotation_reaches_the_supported_client() {
    let e = env();
    let panel = fake(Panel::Supports("clash-verge")).await;
    let id = e.import(&panel.server.url("/sub/token")).await;
    assert_eq!(panel.seen(), ["Happ", "v2rayN", "clash-verge"]);
    assert_eq!(live(&e, &id), 2);
    e.servers.read(|doc| {
        assert!(doc.profiles.iter().all(|r| !r.is_placeholder()));
        let note = doc.fetch_note(&id).unwrap();
        assert_eq!(note.agent.as_deref(), Some("clash-verge"));
    });
}

/// The remembered client goes first: one request when it still works.
#[tokio::test]
async fn the_sticky_identity_goes_first() {
    let e = env();
    let panel = fake(Panel::Supports("sing-box")).await;
    let id = e.import(&panel.server.url("/sub/token")).await;
    assert_eq!(panel.seen().last().map(String::as_str), Some("sing-box"));
    e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!(panel.seen(), ["sing-box"]);
    // The panel changes its mind: the rotation runs again from the remembered client.
    *panel.mode.lock() = Panel::Supports("v2rayN");
    e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!(panel.seen(), ["sing-box", "Happ", "v2rayN"]);
    let agent = e
        .servers
        .read(|doc| doc.fetch_note(&id).unwrap().agent.clone());
    assert_eq!(agent.as_deref(), Some("v2rayN"));
}

/// The owner's case: a refresh that gets placeholders from every client keeps the servers,
/// records the outcome and the provider's words, and says them in one line.
#[tokio::test]
async fn a_placeholder_never_replaces_the_list() {
    let e = env();
    let panel = fake(Panel::Supports("v2rayN")).await;
    let id = e.import(&panel.server.url("/sub/token")).await;
    *panel.mode.lock() = Panel::RefusesAll;
    for _ in 0..2 {
        let err = e.refresh(&id, Owner::Schedule).await.unwrap_err();
        assert_eq!(err.user_msg().key, "servers.fetch.said");
        assert!(
            err.user_msg()
                .args
                .iter()
                .any(|(k, v)| k == "said" && v == SAID)
        );
    }
    assert_eq!(live(&e, &id), 2, "the servers stay as they were");
    let group = e.group(&id);
    assert_eq!(group.fetch.last_outcome, Some(FetchOutcome::Placeholder));
    assert_eq!(group.status(0), GroupStatus::Failed);
    let view = e.servers.view();
    let summary = view.groups.iter().find(|g| g.id == id).unwrap();
    assert_eq!(summary.said.as_deref(), Some(SAID));
    assert!(view.servers.iter().all(|s| !s.name.contains(SAID)));
    // A real list again clears the words.
    *panel.mode.lock() = Panel::Supports("v2rayN");
    e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!(e.servers.view().groups[0].said, None);
}

/// Remnawave without the HWID: placeholders with `x-hwid-not-supported` (and `x-hwid-limit`) are
/// the panel asking for the HWID, not a full device limit; the words are kept for the group.
#[tokio::test]
async fn a_missing_hwid_is_asked_for_not_a_device_limit() {
    let e = env();
    let panel = fake(Panel::Supports("v2rayN")).await;
    let id = e.import(&panel.server.url("/sub/token")).await;
    *panel.mode.lock() = Panel::WantsHwid;
    let err = e.refresh(&id, Owner::Manual).await.unwrap_err();
    assert_eq!(err.user_msg().key, "servers.fetch.hwidRequired");
    assert_eq!(
        e.group(&id).fetch.last_outcome,
        Some(FetchOutcome::HwidRequired)
    );
    assert_eq!(live(&e, &id), 2);
    let said = e
        .servers
        .read(|doc| doc.fetch_note(&id).unwrap().said.clone());
    assert_eq!(said.as_deref(), Some(SAID));
    // With the HWID switched on, the same panel serves the list.
    e.servers.set_group_send_hwid(&id, true).unwrap();
    e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!(
        e.group(&id).fetch.last_outcome,
        Some(FetchOutcome::Ok { partial: false })
    );
}

/// Only Happ gets a list, and only encrypted: one line says so, nothing is stored.
#[tokio::test]
async fn an_encrypted_list_only_is_said_in_one_line() {
    let e = env();
    let panel = fake(Panel::OnlyHapp).await;
    let err = e
        .servers
        .add_from_input(
            &e.ctx,
            panel.server.url("/sub/token").as_str(),
            None,
            vpnte_base::types::ClientDevice::Pc,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "servers.fetch.body.encrypted");
    assert!(e.servers.read(|doc| doc.groups.is_empty()));
}
