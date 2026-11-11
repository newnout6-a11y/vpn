//! Tests of the root's pure parts: the page registry of this build and the WebView2 folder.
use std::path::PathBuf;

use super::*;

/// Scope of this build: the four wired pages are registered, every other page is left to the
/// shell's placeholder.
#[cfg(not(feature = "app-tools"))]
#[cfg(not(feature = "app-maintenance"))]
#[cfg(not(feature = "app-lists"))]
#[test]
fn only_the_wired_pages_are_registered() {
    let registry = registry();
    let registered: Vec<Page> = Page::ALL
        .into_iter()
        .filter(|page| registry.get(*page).is_some())
        .collect();
    assert_eq!(
        registered,
        [Page::Dashboard, Page::Servers, Page::Logs, Page::Settings]
    );
}

/// With the Maintenance page built in (`app-maintenance`), it joins the wired pages; the shell
/// offers it only in advanced mode.
#[cfg(not(feature = "app-tools"))]
#[cfg(feature = "app-maintenance")]
#[cfg(not(feature = "app-lists"))]
#[test]
fn the_maintenance_page_joins_the_wired_pages() {
    let registry = registry();
    let registered: Vec<Page> = Page::ALL
        .into_iter()
        .filter(|page| registry.get(*page).is_some())
        .collect();
    assert_eq!(
        registered,
        [
            Page::Dashboard,
            Page::Servers,
            Page::Logs,
            Page::Settings,
            Page::Maintenance
        ]
    );
}

/// With the Tools pages built in (`app-tools`), Speed test and Availability join the wired pages
/// (other page packages of the same build may add theirs).
#[cfg(feature = "app-tools")]
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
    assert_eq!(
        registry.get(Page::Maintenance).is_some(),
        cfg!(feature = "app-maintenance")
    );
}

/// With the list pages built in (`app-lists`), Apps, Traffic history and Schedule join the
/// wired pages (other page packages of the same build may add theirs).
#[cfg(feature = "app-lists")]
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
    assert_eq!(
        registry.get(Page::Maintenance).is_some(),
        cfg!(feature = "app-maintenance")
    );
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
