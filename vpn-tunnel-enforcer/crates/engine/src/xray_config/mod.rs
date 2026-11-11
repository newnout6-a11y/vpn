//! Xray JSON: engine selection, typed profile -> Xray outbound, and the runtime config of one
//! Xray instance (authenticated loopback SOCKS inbound -> the profile's outbound or a compiled
//! provider graph). The only producer of Xray JSON (CONTRACT §3.3); pure code, no I/O, except
//! the async pre-resolution of server names ([`resolve_hosts`]).
//!
//! Flow of a start: [`select_engine`] says Xray -> [`proxy_graph`] (translate or compile) and
//! [`warnings`] for the user -> [`resolve_hosts`] for [`ProxyGraph::hosts`] and
//! [`ProxyGraph::substitute`] (Xray never resolves a server name itself) -> [`build_config`]
//! for a [`crate::slot::SlotEndpoint`] -> the process launcher writes the JSON to
//! `xray run -config stdin:`.
use vpnte_base::error::AppError;
use vpnte_base::msg::Msg;
use vpnte_profiles::xray_native::NativeError;

mod config;
mod ech;
mod endpoints;
mod fingerprint;
mod hysteria;
mod resolve;
mod select;
mod stream;
mod translate;
mod warnings;
mod wireguard;

pub use config::{ProxyGraph, build_config, proxy_graph};
pub use resolve::{ResolveFault, ResolvePath, Resolved, resolve_hosts};
pub use select::{Decision, Reject, SelectReason, SingBoxOnly, select_engine};
pub use translate::translate;
pub use warnings::warnings;

/// Tag of the profile's outbound (translated, or the compiled graph's selected outbound).
const PROXY_TAG: &str = "proxy";
const DIRECT_TAG: &str = "direct";
const BLOCK_TAG: &str = "block";
/// Tag of the loopback SOCKS inbound sing-box (or a probe) talks to.
const INBOUND_TAG: &str = "in";

/// Why no Xray config could be produced for a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum XrayConfigError {
    /// Xray has no outbound for the protocol (selection keeps such profiles on sing-box).
    #[error("Xray has no outbound for the {0} protocol")]
    Protocol(&'static str),
    /// The profile uses something Xray refuses or cannot honour.
    #[error("Xray cannot honour a profile feature: {0:?}")]
    Feature(SingBoxOnly),
    /// A profile setting Xray would refuse when dialling (ECH config, Hysteria2 obfuscation).
    #[error("the profile's {0} setting is not valid for Xray")]
    Invalid(&'static str),
    /// The provider graph failed its checks.
    #[error(transparent)]
    Native(#[from] NativeError),
}

impl From<XrayConfigError> for AppError {
    fn from(err: XrayConfigError) -> Self {
        match err {
            XrayConfigError::Protocol(protocol) => AppError::validation(
                Msg::new("engine.xray.config.protocol").arg("protocol", protocol),
            )
            .with_source(err),
            XrayConfigError::Feature(feature) => {
                AppError::validation(Reject::SingBoxOnly(feature).msg()).with_source(err)
            }
            XrayConfigError::Invalid(setting) => {
                AppError::validation(Msg::new("engine.xray.config.invalid").arg("setting", setting))
                    .with_source(err)
            }
            XrayConfigError::Native(native) => native.into(),
        }
    }
}

#[cfg(test)]
mod tests;
