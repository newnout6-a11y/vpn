//! Nested preference objects of `settings.json`: notification switches and persistent UI state.
use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use super::{NotifyMethod, take};

/// Notification switches. They govern OS toasts only: protection notices always reach the in-app
/// list (owner decision D-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPrefs {
    pub vpn_connect: bool,
    pub vpn_disconnect: bool,
    pub leak_detected: bool,
    pub profile_rotation: bool,
    pub schedule_triggered: bool,
    pub connection_error: bool,
    pub method: NotifyMethod,
    /// Sound of Windows notifications.
    pub sound: bool,
    /// Keys written by a newer version, kept as they are.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for NotificationPrefs {
    fn default() -> Self {
        Self {
            vpn_connect: true,
            vpn_disconnect: true,
            leak_detected: true,
            profile_rotation: true,
            schedule_triggered: true,
            connection_error: true,
            method: NotifyMethod::System,
            sound: true,
            extra: Map::new(),
        }
    }
}

impl NotificationPrefs {
    /// Maps the old `notification-prefs.json` (`{"notificationPrefs": {…}}` or the inner object); the
    /// old store could be partial, so every key falls back on its own.
    pub fn from_legacy(legacy: &Value) -> Self {
        let inner = legacy.get("notificationPrefs").unwrap_or(legacy);
        let mut prefs = Self::default();
        if let Some(obj) = inner.as_object() {
            prefs.merge(obj.clone());
        }
        prefs.extra.clear();
        prefs
    }

    pub(super) fn merge(&mut self, mut obj: Map<String, Value>) {
        take(&mut obj, "vpnConnect", &mut self.vpn_connect);
        take(&mut obj, "vpnDisconnect", &mut self.vpn_disconnect);
        take(&mut obj, "leakDetected", &mut self.leak_detected);
        take(&mut obj, "profileRotation", &mut self.profile_rotation);
        take(&mut obj, "scheduleTriggered", &mut self.schedule_triggered);
        take(&mut obj, "connectionError", &mut self.connection_error);
        take(&mut obj, "method", &mut self.method);
        take(&mut obj, "sound", &mut self.sound);
        self.extra.extend(obj);
    }
}

impl<'de> Deserialize<'de> for NotificationPrefs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut prefs = Self::default();
        prefs.merge(Map::deserialize(deserializer)?);
        Ok(prefs)
    }
}

/// Small UI state that should survive a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiPrefs {
    /// Server groups expanded in the server list.
    pub expanded_groups: Vec<String>,
    /// Tips the user has closed.
    pub dismissed_tips: BTreeSet<String>,
    /// Debug-level logging (raised at runtime through the logger's reload handle).
    pub debug_log: bool,
    /// Keys written by a newer version, kept as they are.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl UiPrefs {
    pub(super) fn merge(&mut self, mut obj: Map<String, Value>) {
        take(&mut obj, "expandedGroups", &mut self.expanded_groups);
        take(&mut obj, "dismissedTips", &mut self.dismissed_tips);
        take(&mut obj, "debugLog", &mut self.debug_log);
        self.extra.extend(obj);
    }
}

impl<'de> Deserialize<'de> for UiPrefs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut prefs = Self::default();
        prefs.merge(Map::deserialize(deserializer)?);
        Ok(prefs)
    }
}
