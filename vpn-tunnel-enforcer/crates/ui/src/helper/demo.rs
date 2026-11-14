//! The fake helper backend of the demos and the tests: the three service states, plus an app
//! started as administrator without the service.
use std::time::Duration;

use tokio::sync::watch;
use vpnte_base::AppResult;

use super::{Ability, Capability, HelperApi, Lack, Service};

/// The situation a demo starts in: the part after `+` of its `--scene` (see [`split_scene`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperScene {
    /// The service is installed and as new as the app.
    Installed,
    /// No service (the prompt was declined): proxy mode, the install is offered.
    Missing,
    /// An older service: Tunnel mode routes every app until it updates itself.
    Older,
    /// No service, the app runs elevated (development, CI): privileged parts run in-process.
    Elevated,
}

impl HelperScene {
    /// `installed`, `missing`, `older`, `elevated`.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "installed" => Self::Installed,
            "missing" => Self::Missing,
            "older" => Self::Older,
            "elevated" => Self::Elevated,
            _ => return None,
        })
    }

    /// The view the app pushes in this situation (this build: the service carries Tunnel mode
    /// and the kill switch; browser policies run elevated only; packet capture is not built).
    pub fn capability(self) -> Capability {
        let (service, elevated, privileged) = match self {
            Self::Installed => (Service::Installed, false, Ability::Service),
            Self::Missing => (Service::Missing, false, Ability::NeedsService),
            Self::Older => (
                Service::Older {
                    lacks: vec![Lack::AppScope],
                },
                false,
                Ability::Service,
            ),
            Self::Elevated => (Service::Missing, true, Ability::InProcess),
        };
        Capability {
            service,
            elevated,
            tunnel: privileged,
            kill_switch: privileged,
            policies: if elevated {
                Ability::InProcess
            } else {
                Ability::NotInVersion
            },
            capture: Ability::NotInVersion,
        }
    }
}

/// Splits a demo's `--scene` into the page's own scene and the helper's: `fresh+older`,
/// `+missing` (the page's default scene); without `+` the service is installed, as after the
/// installer. An unknown helper name is logged and taken as installed: a demo always starts.
pub fn split_scene(scene: &str) -> (&str, HelperScene) {
    let Some((page, helper)) = scene.split_once('+') else {
        return (scene, HelperScene::Installed);
    };
    let helper = HelperScene::from_name(helper).unwrap_or_else(|| {
        tracing::warn!(helper, "unknown helper scene; installed");
        HelperScene::Installed
    });
    (page, helper)
}

/// [`HelperApi`] over a scene; «Установить службу-помощник» succeeds after a short pause.
pub struct DemoHelper {
    state: watch::Sender<Capability>,
}

impl DemoHelper {
    pub fn new(scene: HelperScene) -> Self {
        Self {
            state: watch::channel(scene.capability()).0,
        }
    }

    /// Switches the scene (tests).
    pub fn set(&self, scene: HelperScene) {
        self.state.send_replace(scene.capability());
    }
}

#[async_trait::async_trait(?Send)]
impl HelperApi for DemoHelper {
    fn capability(&self) -> watch::Receiver<Capability> {
        self.state.subscribe()
    }

    async fn install_service(&self) -> AppResult<bool> {
        tokio::time::sleep(Duration::from_millis(600)).await;
        self.set(HelperScene::Installed);
        Ok(true)
    }
}
