//! First-run wizard: a six-step overlay in «Пломба» over the shell (language, how to connect,
//! routing mode, Smart RU, optional protection, summary). Nothing is applied before the last step; «Завершить»
//! hands every choice to the backend in one call, «Пропустить» saves only the language.
//!
//! The overlay is a `role=dialog aria-modal=true` layer below the title strip (the caption buttons
//! stay usable); `assets/js/wizard.js` keeps the keyboard inside it, so nothing underneath — the
//! power button included — can be reached while it is open.
use std::fmt;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{KillSwitchLevel, ProxyKind};

mod demo;
#[cfg(test)]
mod helper_tests;
mod model;
mod steps;
#[cfg(test)]
mod tests;
mod view;

pub use demo::{DemoScene, DemoWizardApi};
pub use view::Wizard;

/// Where the tunnel gets its upstream from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Connection {
    /// Our own servers from a key or subscription (settings: connection mode `DirectVpn`).
    Key,
    /// Another VPN client's local proxy, e.g. Happ (settings: connection mode `LocalProxy`).
    #[default]
    LocalProxy,
}

/// How traffic reaches the tunnel; both work with either [`Connection`] (NOADMIN §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Routing {
    /// «Туннель»: TUN capture of every program; needs the helper service (or the app started as
    /// administrator).
    Hard,
    /// «Прокси»: the engine behind a loopback proxy and the per-user system proxy pointed at it;
    /// programs that ignore the system proxy go direct. The first-run default without
    /// administrator rights (NOADMIN §0).
    #[default]
    Soft,
}

/// The current settings the wizard starts from, so a second run changes only what the user
/// changes (and a first run starts from the defaults: kill switch off, owner decision D-15).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WizardDefaults {
    pub connection: Connection,
    pub routing: Routing,
    /// Smart RU (Russian sites directly). The app preselects it on for a first run (owner answer
    /// 18) and shows the stored choice on a re-run.
    pub smart_ru: bool,
    pub kill_switch: KillSwitchLevel,
    /// Autostart as Windows reports it now (the checkbox shows it; finishing applies a change).
    pub autostart: bool,
    /// Servers already in the list (a key is optional then, and the screen says so).
    pub servers: usize,
}

/// Pushed state of the wizard.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WizardState {
    /// Show the wizard: onboarding not completed, or Settings asked for it again. The app sets it
    /// to `false` after a successful finish or skip; a later `true` opens a fresh wizard.
    pub open: bool,
    /// Read each time the wizard opens.
    pub current: WizardDefaults,
}

/// A local proxy of another VPN client found on this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProxy {
    pub host: String,
    pub port: u16,
    pub kind: ProxyKind,
}

/// What the backend recognised in a pasted key or subscription link; nothing is imported yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyCheck {
    /// Servers found; `0` means the text is not a usable key.
    pub servers: usize,
    /// The text was a subscription link (fetched to count its servers).
    pub subscription: bool,
}

/// Pasted key or subscription text. It carries credentials, so `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyText(pub String);

impl fmt::Debug for KeyText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyText(..)")
    }
}

/// Everything «Завершить» applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardChoices {
    pub lang: Lang,
    pub connection: Connection,
    pub routing: Routing,
    /// The Smart RU setting.
    pub smart_ru: bool,
    /// The checked key (trimmed), only with [`Connection::Key`] and only after the backend found
    /// servers in exactly this text; to be imported like the Servers page «Добавить».
    pub key: Option<KeyText>,
    /// The key's subscription sends the device HWID: the user pressed «Включить HWID и
    /// добавить» for exactly this text (its check already sent it).
    pub send_hwid: bool,
    pub kill_switch: KillSwitchLevel,
    pub autostart: bool,
}

/// Backend of the wizard, handed to it as `Rc<dyn WizardApi>` context.
#[async_trait(?Send)]
pub trait WizardApi: 'static {
    /// Whether to show the wizard and the settings it starts from.
    fn state(&self) -> watch::Receiver<WizardState>;
    /// Looks for another VPN client's local proxy; `None` = nothing found. Runs once per wizard
    /// session and again on «Искать снова».
    async fn detect_proxy(&self) -> AppResult<Option<LocalProxy>>;
    /// Parses a key or subscription link without importing or saving anything; a subscription
    /// is fetched with the device HWID only when `send_hwid` (the user's click). An edit of the
    /// text cancels the check (`cancel`, and the future is dropped).
    async fn check_key(
        &self,
        text: String,
        send_hwid: bool,
        cancel: CancellationToken,
    ) -> AppResult<KeyCheck>;
    /// Applies the choices all-or-nothing: import the key, autostart and kill switch when they
    /// change (undone if a later step fails), then one settings write with `first_run_complete`.
    /// On failure the wizard stays open and shows the error's message.
    async fn finish(&self, choices: WizardChoices) -> AppResult<()>;
    /// «Пропустить»: saves the language shown now and `first_run_complete`, nothing else.
    async fn skip(&self, lang: Lang) -> AppResult<()>;
}
