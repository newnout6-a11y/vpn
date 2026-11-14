//! `autopick.json`: the user's connect-at-launch choice, and the rule that applies while the user
//! never made one.
use serde::{Deserialize, Serialize};
use vpnte_core::store::Document;

/// What the user picked for the start of the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchChoice {
    Off,
    LastUsed,
    LowestDelay,
}

/// Which server a launch connect takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchPick {
    LastUsed,
    LowestDelay,
    /// A provider's `subscription-autoconnect-type: random` (never offered to the user).
    Random,
}

/// A provider's `subscription-autoconnect` for its group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderWord {
    Off,
    On(LaunchPick),
}

/// Who decided what a launch does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchSource {
    User,
    Provider,
    /// Nobody: off.
    Default,
}

/// Who decides under [`launch_pick`]'s rule.
pub fn launch_source(choice: Option<LaunchChoice>, provider: Option<ProviderWord>) -> LaunchSource {
    match (choice, provider) {
        (Some(_), _) => LaunchSource::User,
        (None, Some(_)) => LaunchSource::Provider,
        (None, None) => LaunchSource::Default,
    }
}

/// The `autopick.json` document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AutoPickConfig {
    /// `None` until the user picks: the default rule of [`launch_pick`] applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch: Option<LaunchChoice>,
}

impl Document for AutoPickConfig {
    const FILE: &'static str = "autopick.json";
    const VERSION: u32 = 1;
}

/// What a launch connects to, if anything: the user's own choice wins (an explicit Off too);
/// without one, the provider's word for the group of the last-used server
/// (`subscription-autoconnect`, picking by its `-type`); otherwise nothing: off by default. An
/// install migrated from the old version starts off as well: its `autoPilotEnabled` was on by
/// default, never a choice, and never connected server-list users at launch.
pub fn launch_pick(
    choice: Option<LaunchChoice>,
    provider: Option<ProviderWord>,
) -> Option<LaunchPick> {
    match (choice, provider) {
        (Some(LaunchChoice::Off), _) | (None, Some(ProviderWord::Off) | None) => None,
        (Some(LaunchChoice::LastUsed), _) => Some(LaunchPick::LastUsed),
        (Some(LaunchChoice::LowestDelay), _) => Some(LaunchPick::LowestDelay),
        (None, Some(ProviderWord::On(pick))) => Some(pick),
    }
}
