//! RU-2026 item 4 over a real backend: the QR export goes through `shareable_profile` (a key its
//! provider hides is refused, the others carry their share link), a handed-over link is taken
//! once (that the add dialog then imports nothing by itself is the UI's test,
//! `vpnte_ui::servers::tests::a_handed_over_link_starts_from_the_new_group_defaults`), and the
//! scheme panel works on a throw-away registry key.
use tokio::sync::watch;
use vpnte_base::AppError;
use vpnte_base::types::ClientDevice;
use vpnte_servers::model::ProfileId;
use vpnte_ui::servers::{AddTarget, LinkSchemes, SchemeOwner, ServersApi, SubscriptionRequest};
use vpnte_winnet::registry::{self, Hive, View};
use vpnte_winnet::url_scheme::Registrar;

use super::super::{ServersBackend, export, qr};
use super::backend::Env;
use super::locales;
use super::reports::PASTE;

fn key(err: AppError) -> String {
    err.user_msg().key.into_owned()
}

#[tokio::test]
async fn the_qr_export_refuses_hidden_keys_and_carries_the_share_link() {
    locales();
    let env = Env::new("phones-qr");
    let hidden = super::relays::add_hidden(&env);
    let api = ServersBackend::start(env.backend.clone());
    let refused = api.key_qr(&hidden.added[0].to_string()).await.unwrap_err();
    assert_eq!(key(refused), "servers.hidden.refused");

    let target = AddTarget::Auto;
    let request = SubscriptionRequest::default();
    let report = api.add(PASTE.to_owned(), target, ClientDevice::Pc, request);
    assert_eq!(report.await.unwrap().added, 2);
    let shown = api
        .state()
        .borrow()
        .servers
        .iter()
        .find(|s| !s.config_hidden)
        .cloned();
    let id = shown.expect("a key of the manual group").id;
    let profile = env
        .backend
        .servers
        .shareable_profile(&ProfileId::from(id.as_str()))
        .unwrap();
    let link = export::share(&profile).unwrap().text();
    let code = api.key_qr(&id).await.unwrap();
    let (side, luma) = qr::tests::draw(&code, 4, false);
    let side = u32::try_from(side).unwrap();
    let picture = image::GrayImage::from_raw(side, side, luma).unwrap();
    assert_eq!(qr::decode_gray(picture).unwrap(), [link]);
}

#[tokio::test]
async fn a_handed_over_link_is_taken_once() {
    locales();
    let env = Env::new("phones-link");
    let api = ServersBackend::start(env.backend.clone());
    let mut arrivals: watch::Receiver<u64> = api.link_arrivals();
    assert_eq!(api.take_link(), None);
    let link = "hiddify://import/https://sub.example.net/s/fake#Name";
    api.links.offer(link.to_owned());
    arrivals.changed().await.unwrap();
    assert_eq!(*arrivals.borrow_and_update(), 1);
    assert_eq!(api.take_link().as_deref(), Some(link));
    assert_eq!(api.take_link(), None, "taken once");
}

/// A throw-away `HKCU\Software\VPNTE-Test-*` root, deleted on drop.
struct TestRoot(String);

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = registry::delete_tree(Hive::CurrentUser, &self.0, View::Native);
    }
}

#[tokio::test]
async fn the_scheme_panel_takes_and_gives_back_links() {
    locales();
    let env = Env::new("phones-schemes");
    let root = TestRoot(format!(
        r"Software\VPNTE-Test-phones-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let api = ServersBackend::start_with(env.backend.clone(), Registrar::under(&root.0));
    let schemes = api.link_schemes().await.unwrap();
    assert_eq!(schemes.list.len(), vpnte_winnet::url_scheme::SCHEMES.len());
    assert!(schemes.list.iter().all(|s| s.owner == SchemeOwner::Free));
    assert!(schemes.portable, "a test exe is no installed copy");
    let owner = |schemes: &LinkSchemes, name: &str| {
        schemes
            .list
            .iter()
            .find(|s| s.scheme == name)
            .map(|s| s.owner.clone())
    };
    let schemes = api.set_link_scheme("vless".into(), true).await.unwrap();
    assert_eq!(owner(&schemes, "vless"), Some(SchemeOwner::Ours));
    let schemes = api.set_link_scheme("vless".into(), false).await.unwrap();
    assert_eq!(owner(&schemes, "vless"), Some(SchemeOwner::Free));
    let refused = api.set_link_scheme("http".into(), true).await.unwrap_err();
    assert_eq!(key(refused), "app.phones.schemes.failed");
}

/// phones-b7: a portable copy registers links only on the user's «open links here»: then every
/// free scheme opens it.
#[tokio::test]
async fn a_portable_copy_adopts_links_on_request() {
    locales();
    let env = Env::new("phones-adopt");
    let root = TestRoot(format!(
        r"Software\VPNTE-Test-phones-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let registrar = Registrar::under(&root.0);
    let api = ServersBackend::start_with(env.backend.clone(), registrar.clone());
    assert!(
        !registrar.initialized().unwrap(),
        "nothing registered by itself"
    );
    let schemes = api.adopt_link_schemes().await.unwrap();
    assert!(schemes.list.iter().all(|s| s.owner == SchemeOwner::Ours));
    assert!(registrar.initialized().unwrap());
}

/// The fragment pairs up and holds exactly the keys this package's code uses.
#[test]
fn phones_locale_keys_match_the_code() {
    let flat = |json: &str| {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut out = Vec::new();
        let mut stack = vec![(String::new(), &value)];
        while let Some((prefix, value)) = stack.pop() {
            match value.as_object() {
                Some(map) => stack.extend(map.iter().map(|(k, v)| (format!("{prefix}{k}."), v))),
                None => out.push(prefix.trim_end_matches('.').to_owned()),
            }
        }
        out.sort();
        out
    };
    let ru = flat(include_str!("../../../locales/w7-phones.ru.json"));
    let en = flat(include_str!("../../../locales/w7-phones.en.json"));
    assert_eq!(ru, en);
    let code = [
        include_str!("../phones.rs"),
        include_str!("../qr/mod.rs"),
        include_str!("../qr/screen.rs"),
        include_str!("../../boot/mod.rs"),
    ]
    .concat();
    let mut used: Vec<String> = code
        .split('"')
        .filter(|part| part.starts_with("app.phones."))
        .map(str::to_owned)
        .collect();
    used.sort();
    used.dedup();
    assert_eq!(used, ru);
}
