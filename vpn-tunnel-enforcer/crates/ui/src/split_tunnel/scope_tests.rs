//! Re-check item 16: the scope switch of the Apps page — its hint for the list as it is, the
//! older service's line, both catalogs, and the page rendered over the demo.
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::i18n::Lang;

use super::demo::DemoSplitTunnel;
use super::*;
use crate::test_locales::text as lookup;
use crate::widgets::{Load, Toasts};

fn app(rule: AppRule) -> SplitApp {
    SplitApp {
        id: "a".into(),
        name: "Browser".into(),
        path: r"C:\Browser\browser.exe".into(),
        icon: None,
        rule,
        kind: AppKind::App,
    }
}

/// Every app: one hint; only the listed ones: the hint says what goes direct, or, with nothing
/// listed yet, that everything does; a list still loading is not called empty.
#[test]
fn the_hint_follows_the_scope_and_the_list() {
    let listed = Load::Ready(vec![app(AppRule::Direct), app(AppRule::Vpn)]);
    let unlisted = Load::Ready(vec![app(AppRule::Direct), app(AppRule::None)]);
    let key = |scope, apps: &Load<Vec<SplitApp>>| scope_hint_key(scope, apps);
    assert_eq!(
        key(AppScope::All, &unlisted),
        "splitTunneling.scope.hintAll"
    );
    assert_eq!(key(AppScope::All, &listed), "splitTunneling.scope.hintAll");
    let only = AppScope::OnlyListed;
    assert_eq!(key(only, &listed), "splitTunneling.scope.hintListed");
    assert_eq!(key(only, &unlisted), "splitTunneling.scope.hintEmpty");
    assert_eq!(
        key(only, &Load::Ready(Vec::new())),
        "splitTunneling.scope.hintEmpty"
    );
    assert_eq!(key(only, &Load::Loading), "splitTunneling.scope.hintListed");
}

#[test]
fn every_scope_text_exists_in_both_languages() {
    for name in [
        "label",
        "hintAll",
        "hintListed",
        "hintEmpty",
        "olderService",
        "failed",
    ] {
        for lang in [Lang::Ru, Lang::En] {
            let key = format!("splitTunneling.scope.{name}");
            let text = lookup(lang, &key).unwrap_or_else(|| panic!("{lang:?} {key}"));
            assert!(!text.contains('!'), "calm copy: {text}");
        }
    }
    assert_eq!(
        lookup(Lang::Ru, "splitTunneling.scope.label").as_deref(),
        Some("Только выбранные приложения")
    );
}

/// What the renderer was asked to show: the dynamic texts.
#[derive(Default)]
struct Seen(Vec<String>);

impl Seen {
    fn shows(&self, text: &str) -> bool {
        self.0.iter().any(|t| t == text)
    }
}

impl dioxus::core::WriteMutations for Seen {
    fn append_children(&mut self, _: dioxus::core::ElementId, _: usize) {}
    fn assign_node_id(&mut self, _: &'static [u8], _: dioxus::core::ElementId) {}
    fn create_placeholder(&mut self, _: dioxus::core::ElementId) {}
    fn create_text_node(&mut self, value: &str, _: dioxus::core::ElementId) {
        self.0.push(value.to_owned());
    }
    fn load_template(&mut self, _: dioxus::core::Template, _: usize, _: dioxus::core::ElementId) {}
    fn replace_node_with(&mut self, _: dioxus::core::ElementId, _: usize) {}
    fn replace_placeholder_with_nodes(&mut self, _: &'static [u8], _: usize) {}
    fn insert_nodes_after(&mut self, _: dioxus::core::ElementId, _: usize) {}
    fn insert_nodes_before(&mut self, _: dioxus::core::ElementId, _: usize) {}
    fn set_attribute(
        &mut self,
        _: &'static str,
        _: Option<&'static str>,
        _: &dioxus::core::AttributeValue,
        _: dioxus::core::ElementId,
    ) {
    }
    fn set_node_text(&mut self, value: &str, _: dioxus::core::ElementId) {
        self.0.push(value.to_owned());
    }
    fn create_event_listener(&mut self, _: &'static str, _: dioxus::core::ElementId) {}
    fn remove_event_listener(&mut self, _: &'static str, _: dioxus::core::ElementId) {}
    fn remove_node(&mut self, _: dioxus::core::ElementId) {}
    fn push_root(&mut self, _: dioxus::core::ElementId) {}
}

/// Renders whatever work is due, a few rounds, into a fresh record.
async fn render(dom: &mut VirtualDom) -> Seen {
    let mut seen = Seen::default();
    for _ in 0..6 {
        tokio::select! {
            () = dom.wait_for_work() => {}
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        dom.render_immediate(&mut seen);
    }
    seen
}

/// The catalog text of `splitTunneling.scope.<key>` in the page's language.
fn text(dom: &VirtualDom, key: &str) -> String {
    let key = format!("splitTunneling.scope.{key}");
    dom.in_runtime(|| crate::lang::translate_now(&key, &[]))
}

fn root() -> Element {
    Toasts::use_provider();
    rsx! {
        SplitTunnelPage {}
    }
}

/// The page over the demo shows the switch with the line for each scene, the older service's
/// line only where it applies, and follows a scope saved meanwhile (the snapshot it pushes).
#[tokio::test]
async fn the_page_shows_the_switch_with_its_line() {
    crate::test_locales::init_locales();
    let scenes = [
        ("full", "hintAll", false),
        ("only", "hintListed", false),
        ("only-empty", "hintEmpty", false),
        ("old-service", "hintListed", true),
    ];
    for (scene, hint, older) in scenes {
        let demo = Rc::new(DemoSplitTunnel::new(scene).instant());
        let api: Rc<dyn SplitTunnelApi> = demo.clone();
        let mut dom = VirtualDom::new(root).with_root_context(api);
        // The first build writes the page whole: its texts are recorded too.
        let mut seen = Seen::default();
        dom.rebuild(&mut seen);
        seen.0.extend(render(&mut dom).await.0);

        assert!(seen.shows(&text(&dom, "label")), "{scene}: {:?}", seen.0);
        assert!(seen.shows(&text(&dom, hint)), "{scene}: {:?}", seen.0);
        assert_eq!(seen.shows(&text(&dom, "olderService")), older, "{scene}");
        if scene == "full" {
            demo.set_scope(AppScope::OnlyListed).await.expect("saved");
            let after = render(&mut dom).await;
            assert!(after.shows(&text(&dom, "hintListed")), "{:?}", after.0);
        }
    }
}
