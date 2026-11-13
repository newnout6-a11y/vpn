//! The helper line in every service state (p-noadmin-ui): the calm line and the install action
//! only where installing helps, nothing while a feature works, nothing without a backend.
use std::rc::Rc;

use vpnte_base::i18n::Lang;

use super::demo::{DemoHelper, HelperScene};
use super::*;
use crate::test_locales::text as lookup;
use crate::test_support::{Shown, shown};

const FEATURES: [Feature; 4] = [
    Feature::Tunnel,
    Feature::KillSwitch,
    Feature::Policies,
    Feature::Capture,
];

#[component]
fn Root(feature: Feature) -> Element {
    rsx! {
        HelperLine { feature }
    }
}

async fn line(helper: Option<Rc<DemoHelper>>, feature: Feature) -> (VirtualDom, Shown) {
    let mut dom = VirtualDom::new_with_props(Root, RootProps { feature });
    if let Some(helper) = helper {
        let api: Rc<dyn HelperApi> = helper;
        dom = dom.with_root_context(api);
    }
    let seen = shown(&mut dom).await;
    (dom, seen)
}

fn text(dom: &VirtualDom, key: &str) -> String {
    let key = format!("ui.helper.{key}");
    dom.in_runtime(|| crate::lang::translate_now(&key, &[]))
}

/// What each scene shows for each feature: (line key or none, install offered).
fn expected(scene: HelperScene, feature: Feature) -> (Option<&'static str>, bool) {
    use Feature::*;
    use HelperScene::*;
    match (scene, feature) {
        (Missing, Tunnel) => (Some("tunnel"), true),
        (Missing, KillSwitch) => (Some("killSwitch"), true),
        (Older, Tunnel) => (Some("older.appScope"), false),
        (_, Capture) | (Missing | Installed | Older, Policies) => (Some("notInVersion"), false),
        _ => (None, false),
    }
}

#[tokio::test]
async fn each_state_shows_one_calm_line_where_it_applies() {
    crate::test_locales::init_locales();
    for scene in [
        HelperScene::Installed,
        HelperScene::Missing,
        HelperScene::Older,
        HelperScene::Elevated,
    ] {
        for feature in FEATURES {
            let helper = Rc::new(DemoHelper::new(scene));
            let (dom, seen) = line(Some(helper), feature).await;
            let (key, install) = expected(scene, feature);
            let case = format!("{scene:?} / {feature:?}: {:?}", seen.texts);
            assert_eq!(
                seen.has("data-helper", feature.id()),
                key.is_some(),
                "{case}"
            );
            if let Some(key) = key {
                assert!(seen.shows(&text(&dom, key)), "{case}");
            }
            assert_eq!(seen.shows(&text(&dom, "install")), install, "{case}");
        }
    }
}

#[tokio::test]
async fn without_a_backend_nothing_is_shown() {
    crate::test_locales::init_locales();
    for feature in FEATURES {
        let (_, seen) = line(None, feature).await;
        assert!(
            seen.texts.is_empty() && seen.attrs.is_empty(),
            "{feature:?}"
        );
    }
}

/// «Установить службу-помощник» approved: the view says so before the call returns, and the
/// line is gone for every feature the service carries.
#[tokio::test]
async fn an_install_turns_the_line_off() {
    crate::test_locales::init_locales();
    let helper = Rc::new(DemoHelper::new(HelperScene::Missing));
    assert!(helper.install_service().await.expect("installed"));
    assert_eq!(
        *helper.capability().borrow(),
        HelperScene::Installed.capability()
    );
    for feature in [Feature::Tunnel, Feature::KillSwitch] {
        let (_, seen) = line(Some(helper.clone()), feature).await;
        assert!(!seen.has("data-helper", feature.id()), "{feature:?}");
    }
}

#[component]
fn StripRoot(tunnel_mode: bool) -> Element {
    rsx! {
        TunnelStrip { tunnel_mode }
    }
}

/// The start page's strip: only for a saved Tunnel mode while the service is missing.
#[tokio::test]
async fn the_strip_shows_only_for_a_saved_tunnel_mode_without_the_service() {
    crate::test_locales::init_locales();
    for (tunnel_mode, scene, expected) in [
        (true, HelperScene::Missing, true),
        (false, HelperScene::Missing, false),
        (true, HelperScene::Installed, false),
        (true, HelperScene::Elevated, false),
    ] {
        let api: Rc<dyn HelperApi> = Rc::new(DemoHelper::new(scene));
        let mut dom = VirtualDom::new_with_props(StripRoot, StripRootProps { tunnel_mode })
            .with_root_context(api);
        let seen = shown(&mut dom).await;
        let body = text(&dom, "strip.body");
        assert_eq!(seen.shows(&body), expected, "{tunnel_mode} {scene:?}");
        assert_eq!(seen.shows(&text(&dom, "install")), expected);
    }
}

#[test]
fn every_helper_text_exists_in_both_languages_and_is_calm() {
    let keys = [
        "tunnel",
        "killSwitch",
        "viaService",
        "notInVersion",
        "install",
        "older.appScope",
        "strip.title",
        "strip.body",
    ];
    for key in keys {
        for lang in [Lang::Ru, Lang::En] {
            let key = format!("ui.helper.{key}");
            let text = lookup(lang, &key).unwrap_or_else(|| panic!("{lang:?} {key}"));
            assert!(!text.contains('!'), "calm copy: {text}");
        }
    }
    assert_eq!(
        lookup(Lang::Ru, "ui.helper.install").as_deref(),
        Some("Установить службу-помощник")
    );
}

#[test]
fn abilities_say_what_works() {
    assert!(Ability::Service.works() && Ability::InProcess.works());
    assert!(!Ability::NeedsService.works() && !Ability::NotInVersion.works());
    let older = HelperScene::Older.capability();
    assert_eq!(older.lacks(), &[Lack::AppScope]);
    assert!(HelperScene::Installed.capability().lacks().is_empty());
    assert_eq!(older.ability(Feature::Tunnel), Ability::Service);
}
