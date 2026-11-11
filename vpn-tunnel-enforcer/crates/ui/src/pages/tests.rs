use vpnte_base::i18n::Lang;

use super::*;
use crate::test_locales::text;

/// `/mihomo|amnezia|browser.box|process.monitor/i` of the old test.
fn names_planned_feature(label: &str) -> bool {
    let label = label.to_lowercase();
    let gap = |a: &str, b: &str| {
        label.match_indices(a).any(|(at, _)| {
            let rest = &label[at + a.len()..];
            rest.chars()
                .next()
                .is_some_and(|c| rest[c.len_utf8()..].starts_with(b))
        })
    };
    label.contains("mihomo")
        || label.contains("amnezia")
        || gap("browser", "box")
        || gap("process", "monitor")
}

#[test]
fn pages_keep_the_old_ids_and_sidebar_order() {
    let ids: Vec<&str> = Page::ALL.iter().map(|page| page.id()).collect();
    assert_eq!(
        ids,
        [
            "dashboard",
            "apps",
            "servers",
            "speedtest",
            "availability",
            "trafficHistory",
            "schedule",
            "logs",
            "settings",
            "maintenance"
        ]
    );
    for (i, page) in Page::ALL.into_iter().enumerate() {
        assert_eq!(Page::from_id(page.id()), Some(page));
        assert_eq!(page.index(), i);
    }
    assert_eq!(Page::from_id("Dashboard"), None);
    assert_eq!(Page::SpeedTest.label_key(), "sidebar.speedTest");
    assert_eq!(nav_number(0), "01");
    assert_eq!(nav_number(9), "10");
}

/// AT-00-009 / AT-12-002: production navigation has no planned-feature entries; 9 buttons in
/// basic mode, 10 in advanced mode (Maintenance last).
#[test]
fn navigation_hides_planned_features() {
    let basic: Vec<Page> = Page::nav(false).collect();
    let advanced: Vec<Page> = Page::nav(true).collect();
    assert_eq!(basic.len(), 9);
    assert!(!basic.contains(&Page::Maintenance));
    assert_eq!(advanced.len(), 10);
    assert_eq!(advanced.last(), Some(&Page::Maintenance));
    for lang in [Lang::Ru, Lang::En] {
        for page in Page::ALL {
            let label = text(lang, page.label_key()).expect("label exists");
            assert!(!names_planned_feature(&label), "{lang:?}: {label}");
        }
    }
    assert!(names_planned_feature("Browser-Box"));
    assert!(names_planned_feature("process monitor"));
}

#[test]
fn every_label_exists_in_both_languages() {
    for page in Page::ALL {
        let key = page.label_key();
        for lang in [Lang::Ru, Lang::En] {
            assert!(
                text(lang, key).is_some_and(|s| !s.is_empty()),
                "{lang:?} {key}"
            );
        }
    }
    let ru = |key| text(Lang::Ru, key);
    assert_eq!(ru("sidebar.availability").as_deref(), Some("Доступность"));
    assert_eq!(ru("sidebar.maintenance").as_deref(), Some("Починка"));
    assert_eq!(ru("sidebar.speedTest").as_deref(), Some("Тест скорости"));
    assert_eq!(
        text(Lang::En, "sidebar.platform").as_deref(),
        Some("win-x64")
    );
}

/// Advanced-mode guard: Maintenance is not reachable while advanced mode is off.
#[test]
fn advanced_only_pages_redirect_to_the_start_page() {
    assert_eq!(Page::Maintenance.allowed(false), Page::Dashboard);
    assert_eq!(Page::Maintenance.allowed(true), Page::Maintenance);
    assert_eq!(Page::Logs.allowed(false), Page::Logs);

    let mut nav = NavState::new(Page::Servers);
    assert!(nav.go(Page::Maintenance, false));
    assert_eq!(nav.current, Page::Dashboard);
    assert!(!nav.go(Page::Dashboard, false));
}

/// D-26: switching advanced mode off leaves Maintenance and forgets it, so it is not mounted
/// (hidden) again when the mode comes back, and its next visit slides in like a first one.
#[test]
fn advanced_mode_off_forgets_advanced_only_pages() {
    let mut nav = NavState::new(Page::Dashboard);
    nav.go(Page::Maintenance, true);
    nav.go(Page::Servers, true);
    assert_eq!(
        nav.mounted(),
        [Page::Dashboard, Page::Maintenance, Page::Servers]
    );
    nav.leave_advanced();
    assert_eq!(nav.current, Page::Servers);
    assert_eq!(nav.mounted(), [Page::Dashboard, Page::Servers]);

    nav.go(Page::Maintenance, true);
    assert_eq!(nav.entry(Page::Maintenance), Entry::Slide);
    // switched off while on Maintenance: back to the start page
    nav.leave_advanced();
    assert_eq!(nav.current, Page::Dashboard);
    assert_eq!(nav.mounted(), [Page::Dashboard, Page::Servers]);
    assert_eq!(nav.entry(Page::Dashboard), Entry::Fade);
}

/// Source pin (`AppSource.test.ts`): the start page is the only initially visited page;
/// `trafficHistory` / `logs` are mounted only while current, other visited pages stay.
#[test]
fn visited_pages_stay_mounted_except_active_only_ones() {
    let mut nav = NavState::new(Page::Dashboard);
    assert_eq!(nav.mounted(), [Page::Dashboard]);
    nav.go(Page::Logs, false);
    assert_eq!(nav.mounted(), [Page::Dashboard, Page::Logs]);
    nav.go(Page::Servers, false);
    assert_eq!(nav.mounted(), [Page::Dashboard, Page::Servers]);
    nav.go(Page::TrafficHistory, false);
    assert_eq!(
        nav.mounted(),
        [Page::Dashboard, Page::Servers, Page::TrafficHistory]
    );
    nav.go(Page::Logs, false);
    // first-visit order, as the old `Set` of visited pages kept it
    assert_eq!(nav.mounted(), [Page::Dashboard, Page::Logs, Page::Servers]);
    assert!(!nav.go(Page::Logs, false));
}

/// Page switch motion: the start page does not move at launch, a first visit slides, a
/// revisit fades, an active-only page slides every time (it is mounted afresh).
#[test]
fn entries_follow_the_old_page_motion() {
    let mut nav = NavState::new(Page::Dashboard);
    assert_eq!(nav.entry(Page::Dashboard), Entry::Still);
    nav.go(Page::Servers, false);
    assert_eq!(nav.entry(Page::Servers), Entry::Slide);
    nav.go(Page::Dashboard, false);
    assert_eq!(nav.entry(Page::Dashboard), Entry::Fade);
    nav.go(Page::Servers, false);
    assert_eq!(nav.entry(Page::Servers), Entry::Fade);
    nav.go(Page::Logs, false);
    assert_eq!(nav.entry(Page::Logs), Entry::Slide);
    nav.go(Page::Servers, false);
    nav.go(Page::Logs, false);
    assert_eq!(nav.entry(Page::Logs), Entry::Slide);

    let nav = NavState::new(Page::Logs);
    assert_eq!(nav.entry(Page::Logs), Entry::Still);
    assert_eq!(Entry::Still.class(), "");
    assert_eq!(Entry::Slide.class(), "page-enter");
    assert_eq!(Entry::Fade.class(), "page-fade");
}

/// `usePageActive` (`hooks/PageActivity.test.tsx`): active = the page is current AND the
/// window is visible; outside a page only the window decides.
#[test]
fn page_activity_needs_the_current_page_and_a_visible_window() {
    let (a, b) = (Some(Page::Settings), Some(Page::Servers));
    assert!(is_active(a, a, true));
    assert!(!is_active(a, b, true));
    assert!(!is_active(a, a, false));
    assert!(is_active(None, b, true));
    assert!(is_active(a, None, true));
    assert!(!is_active(None, None, false));
}

// different bodies: identical functions may share one address
fn first() -> Element {
    rsx! { "first" }
}

fn second() -> Element {
    rsx! { "second" }
}

#[test]
fn registry_maps_pages_to_components() {
    let mut registry = PageRegistry::new();
    assert!(Page::ALL.iter().all(|&page| registry.get(page).is_none()));
    let empty = registry;
    registry
        .register(Page::Servers, first)
        .register(Page::Logs, first);
    assert!(
        registry
            .get(Page::Servers)
            .is_some_and(|f| std::ptr::fn_addr_eq(f, first as fn() -> Element))
    );
    assert!(registry.get(Page::Dashboard).is_none());
    assert_ne!(registry, empty);
    let copy = registry;
    assert_eq!(copy, registry);
    registry.register(Page::Logs, second);
    assert!(
        registry
            .get(Page::Logs)
            .is_some_and(|f| std::ptr::fn_addr_eq(f, second as fn() -> Element))
    );
    assert_ne!(copy, registry);
}
