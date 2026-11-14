//! View models, the [`SplitTunnelApi`] and the pure logic of the Apps page: search, the path
//! shown for an app, its icon.
use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::AppResult;

use super::routing::{RoutingImported, RoutingOffer, RoutingPreview, RoutingSource};
use crate::widgets::Load;

/// What the page needs from the split-tunnel service (routing). Every mutation publishes the
/// new [`SplitSnapshot`] before it returns; the page never patches its list by itself.
#[async_trait(?Send)]
pub trait SplitTunnelApi: 'static {
    /// The app list, pushed on every change (the first read of an empty store runs discovery).
    fn state(&self) -> watch::Receiver<SplitSnapshot>;
    /// Reads the list again after a failed read (the result arrives through `state`).
    async fn reload(&self) -> AppResult<()>;
    /// Re-scans the installed apps (merge by path, rules kept, removed apps stay removed);
    /// returns how many new apps were found.
    async fn refresh(&self) -> AppResult<usize>;
    /// Shows the open dialog (`.exe`) and adds the chosen program with rule «Нет» (an existing
    /// path returns its entry); `None` when the dialog was dismissed.
    async fn add_app(&self) -> AppResult<Option<SplitApp>>;
    /// Adds a bare process name that bypasses the VPN (normalised by the service: quotes
    /// stripped, the leaf of a pasted path, `.exe` appended, lower case) or flips an existing
    /// one to «Напрямую». A bad name is a `Validation` error whose message the page shows.
    async fn add_process(&self, name: String) -> AppResult<SplitApp>;
    /// Sets the rule of app `id`.
    async fn set_rule(&self, id: String, rule: AppRule) -> AppResult<()>;
    /// Saves which apps use the VPN; the running session takes it at its next start, like the
    /// list itself.
    async fn set_scope(&self, scope: AppScope) -> AppResult<()>;
    /// Removes app `id` (a later rescan does not bring it back).
    async fn remove(&self, id: String) -> AppResult<()>;
    /// Reads a Happ routing profile and says what importing it would do; nothing changes yet.
    /// A value that is not a profile is a `Validation` error whose message the page shows.
    async fn preview_routing(&self, source: RoutingSource) -> AppResult<RoutingPreview>;
    /// Adds the previewed profile (`RoutingPreview::token`) to the user's own rules; a token
    /// that is no longer the latest preview is a `Conflict` (preview again).
    async fn import_routing(&self, token: u64) -> AppResult<RoutingImported>;
}

/// Pushed state of the page.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitSnapshot {
    pub apps: Load<Vec<SplitApp>>,
    /// Subscriptions whose provider sent a Happ routing profile.
    pub offers: Vec<RoutingOffer>,
    pub scope: AppScope,
    /// A session runs with the other scope than the saved one: the switch applies from the next
    /// connection (appsplit-b5).
    pub pending: bool,
    /// Proxy mode (the running session's, else the saved one): only programs that use the
    /// system proxy reach the VPN (appsplit-b6, NOADMIN.md section 2).
    pub proxy: bool,
    /// Tunnel mode runs in a helper service too old for [`AppScope::OnlyListed`]: there every
    /// app still uses the VPN until the service is updated.
    pub older_service: bool,
}

impl Default for SplitSnapshot {
    fn default() -> Self {
        Self {
            apps: Load::Loading,
            offers: Vec::new(),
            scope: AppScope::All,
            pending: false,
            proxy: false,
            older_service: false,
        }
    }
}

/// Which apps use the VPN: the switch at the top of the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AppScope {
    /// Every app; the rules decide per site.
    #[default]
    All,
    /// «VPN только для выбранных приложений»: the apps set to «Через VPN»; every other app
    /// connects directly.
    OnlyListed,
}

/// Catalog key of the switch's hint for the list as it is: with only the listed apps and none
/// listed yet, it says what still uses the VPN (a list still loading reads as listed); in Proxy
/// mode it says that only programs using the system proxy reach the VPN.
pub fn scope_hint_key(scope: AppScope, apps: &Load<Vec<SplitApp>>, proxy: bool) -> &'static str {
    let none_listed =
        matches!(apps, Load::Ready(list) if list.iter().all(|a| a.rule != AppRule::Vpn));
    match scope {
        AppScope::All if proxy => "splitTunneling.scope.hintAllProxy",
        AppScope::All => "splitTunneling.scope.hintAll",
        AppScope::OnlyListed if none_listed => "splitTunneling.scope.hintEmpty",
        AppScope::OnlyListed if proxy => "splitTunneling.scope.hintListedProxy",
        AppScope::OnlyListed => "splitTunneling.scope.hintListed",
    }
}

/// Where an app's traffic goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AppRule {
    Vpn,
    Direct,
    #[default]
    None,
}

impl AppRule {
    pub const ALL: [AppRule; 3] = [AppRule::Vpn, AppRule::Direct, AppRule::None];

    /// Catalog key of the button text («VPN», «Напрямую», «Нет»).
    pub const fn label_key(self) -> &'static str {
        match self {
            AppRule::Vpn => "splitTunneling.ruleVpn",
            AppRule::Direct => "splitTunneling.ruleDirect",
            AppRule::None => "splitTunneling.ruleNone",
        }
    }

    /// Catalog key of the button's hover text («Через VPN», «Мимо VPN», «Без правила»).
    pub const fn title_key(self) -> &'static str {
        match self {
            AppRule::Vpn => "splitTunneling.ruleVpnTitle",
            AppRule::Direct => "splitTunneling.ruleDirectTitle",
            AppRule::None => "splitTunneling.ruleNoneTitle",
        }
    }
}

/// A program chosen by path, or a bare process name matched wherever it runs from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AppKind {
    #[default]
    App,
    Process,
}

/// One row of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitApp {
    pub id: String,
    pub name: String,
    /// Full path of a program; the process name (`curl.exe`) of a process entry.
    pub path: String,
    /// Base64 PNG (with or without the `data:image/png;base64,` prefix).
    pub icon: Option<String>,
    pub rule: AppRule,
    pub kind: AppKind,
}

/// The search of the old page, with the query trimmed: case-insensitive, on the name or the
/// path (which covers the file name: «codex» finds `…\OpenAI\Codex\bin\codex.exe`).
pub fn matches(app: &SplitApp, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    query.is_empty()
        || app.name.to_lowercase().contains(&query)
        || app.path.to_lowercase().contains(&query)
}

/// The path shown under an app's name (display only; the stored path is never changed).
/// Paths read through UTF-16 Win32 calls are shown verbatim, CJK and Hangul included (U-26);
/// only segments with U+FFFD — rows imported from the old app, decoded with a wrong code page
/// — are rebuilt from the app name (the old sanitiser, ui-pages §3.14).
pub fn display_path(app: &SplitApp) -> String {
    let path = &app.path;
    if app.kind == AppKind::Process || !path.contains('\u{FFFD}') {
        return path.clone();
    }
    let sep = if path.contains('\\') { "\\" } else { "/" };
    let parts: Vec<&str> = path.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
    let last = parts.len().saturating_sub(1);
    let fixed: Vec<String> = parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            if part.contains('\u{FFFD}') {
                clean_segment(part, &app.name, i == last)
            } else {
                (*part).to_owned()
            }
        })
        .collect();
    let joined = fixed.join(sep);
    // Keep a leading separator (`\\server\share`, `/opt/…`) that the split dropped.
    match path.find(|c: char| c != '\\' && c != '/') {
        Some(0) | None => joined,
        Some(n) => format!("{}{joined}", &path[..n]),
    }
}

/// U+FFFD runs and characters Windows forbids in names become spaces; whitespace collapsed.
fn scrub(text: &str) -> String {
    let spaced: String = text
        .chars()
        .map(|c| {
            if c == '\u{FFFD}' || "<>:\"/\\|?*".contains(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn clean_segment(segment: &str, name: &str, leaf: bool) -> String {
    let ext = if leaf { extension(segment) } else { "" };
    let stem = scrub(&segment[..segment.len() - ext.len()]);
    let stem = if stem.chars().count() >= 2 && stem.chars().any(char::is_alphanumeric) {
        stem
    } else {
        match scrub(name) {
            n if n.is_empty() => "app".to_owned(),
            n => n,
        }
    };
    let ext = if ext.is_empty() && leaf { ".exe" } else { ext };
    format!("{stem}{ext}")
}

/// `.exe` of `name.exe`: a dot and 1–8 ASCII letters or digits at the end.
fn extension(segment: &str) -> &str {
    match segment.rfind('.') {
        Some(dot) => {
            let ext = &segment[dot + 1..];
            if (1..=8).contains(&ext.len()) && ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
                &segment[dot..]
            } else {
                ""
            }
        }
        None => "",
    }
}

/// `src` of an app icon: a `data:` URL of a base64 PNG, or `None` when the value is not plain
/// base64 (then the first letter is shown).
pub fn icon_src(icon: &str) -> Option<String> {
    let data = icon.strip_prefix("data:image/png;base64,").unwrap_or(icon);
    let base64 = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=');
    (!data.is_empty() && data.bytes().all(base64)).then(|| format!("data:image/png;base64,{data}"))
}

/// The letter shown when an app has no icon.
pub fn initial(name: &str) -> String {
    name.chars()
        .find(|c| c.is_alphanumeric())
        .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect())
}
