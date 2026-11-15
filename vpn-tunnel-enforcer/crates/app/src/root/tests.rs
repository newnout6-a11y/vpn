//! Tests of the root's pure parts: the page registry of this build and the WebView2 folder.
use std::path::PathBuf;

use super::*;

/// Speed test and Availability (`app-tools`) join the wired pages, and so does Maintenance (the
/// shell offers it only in advanced mode).
#[test]
fn the_tools_pages_join_the_wired_pages() {
    let registry = registry();
    for page in [
        Page::Dashboard,
        Page::Servers,
        Page::SpeedTest,
        Page::Availability,
        Page::Logs,
        Page::Settings,
    ] {
        assert!(registry.get(page).is_some(), "{page:?} is not registered");
    }
    assert!(registry.get(Page::Maintenance).is_some());
}

/// Apps, Traffic history and Schedule (`app-lists`) join the wired pages, and so does
/// Maintenance.
#[test]
fn the_list_pages_join_the_wired_pages() {
    let registry = registry();
    for page in [
        Page::Dashboard,
        Page::Apps,
        Page::Servers,
        Page::TrafficHistory,
        Page::Schedule,
        Page::Logs,
        Page::Settings,
    ] {
        assert!(registry.get(page).is_some(), "{page:?} is not registered");
    }
    assert!(registry.get(Page::Maintenance).is_some());
}

#[test]
fn webview_folder_follows_the_data_dir_override_and_elevation() {
    let dirs = DataDirs::new(
        PathBuf::from(r"C:\t\data"),
        PathBuf::from(r"C:\t\legacy"),
        PathBuf::from(r"C:\t\res"),
    );
    let default = PathBuf::from(r"C:\Users\u\AppData\Local\VPN Tunnel Enforcer\WebView2");
    assert_eq!(webview_dir(&dirs, false, false, default.clone()), default);
    assert_eq!(
        webview_dir(&dirs, true, false, default.clone()),
        PathBuf::from(r"C:\t\data\cache\WebView2")
    );
    assert_eq!(
        webview_dir(&dirs, false, true, default),
        PathBuf::from(r"C:\Users\u\AppData\Local\VPN Tunnel Enforcer\WebView2.elevated")
    );
}

/// A context of a listed type is provided to every window (the same handle); one of an unlisted
/// type to the first window only.
#[test]
fn listed_contexts_are_provided_again() {
    let links = api_servers::LinkInbox::default();
    let context = reusable(Box::new(links));
    assert!(context.reusable());
    for _ in 0..2 {
        let value = context.provide().expect("provided again");
        assert!(value.downcast::<api_servers::LinkInbox>().is_ok());
    }
    let unlisted = reusable(Box::new(7_u8));
    assert!(!unlisted.reusable());
    assert!(unlisted.provide().is_some());
    assert!(unlisted.provide().is_none());
}
