//! Tests of the root's pure parts: the page registry of this build and the WebView2 folder.
use std::path::PathBuf;

use super::*;

/// Scope of this build: the four wired pages are registered, every other page is left to the
/// shell's placeholder.
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
