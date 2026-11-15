//! How the service checks a new engine before it switches to it: the version the file reports
//! must be the feed's, and the engine's own check must accept the shape of config Tunnel mode
//! builds (TUN capture over the Xray slots; for Xray the slot config of a stand-in VLESS server).
//! The trial (three failed starts in a row go back) covers what a shape check cannot.
use std::io;
use std::path::Path;

use async_trait::async_trait;
use vpnte_base::types::{ClientDevice, Loopback};
use vpnte_engine::singbox_config::{
    self, Capture, ConfigInputs, Listeners, RoutingParts, TunParams, TunStack, UdpPolicy, Upstream,
};
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::{ports, singbox_process, xray_config, xray_process};
use vpnte_update::policy::{SINGBOX, XRAY};
use vpnte_update::store::EngineCheck;
use vpnte_update::version::Version;

/// A stand-in server for the Xray check (documentation address, fake id).
const SAMPLE_XRAY: &str = "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp&sni=example.com#sample";

/// The checks of a new engine (object-safe: the real engines here, fakes in tests).
#[async_trait]
pub trait Checks: Send + Sync {
    /// The version `exe` reports.
    async fn version(&self, id: &str, exe: &Path) -> io::Result<Version>;
    /// `Err` = the first refusal of our configs by `exe`.
    async fn configs(&self, id: &str, exe: &Path) -> Result<(), String>;
}

/// [`EngineCheck`] for the store over a [`Checks`] object.
pub(super) struct Dyn<'a>(pub &'a dyn Checks);

impl EngineCheck for Dyn<'_> {
    async fn version(&self, id: &str, exe: &Path) -> io::Result<Version> {
        self.0.version(id, exe).await
    }

    async fn check_configs(&self, id: &str, exe: &Path) -> Result<(), String> {
        self.0.configs(id, exe).await
    }
}

/// [`Checks`] over the real engine binaries.
pub struct EngineChecks;

#[async_trait]
impl Checks for EngineChecks {
    async fn version(&self, id: &str, exe: &Path) -> io::Result<Version> {
        let triple = match id {
            SINGBOX => singbox_process::engine_version(exe).await?,
            XRAY => xray_process::engine_version(exe).await?,
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        Ok(Version::from_triple(triple))
    }

    async fn configs(&self, id: &str, exe: &Path) -> Result<(), String> {
        match id {
            SINGBOX => {
                let config = tun_config()?;
                singbox_process::check_config(exe, &config)
                    .await
                    .map_err(|e| match e {
                        singbox_process::CheckError::Rejected(why) => why,
                        singbox_process::CheckError::Run(err) => err.to_string(),
                    })
            }
            XRAY => {
                let config = xray_slot_config()?;
                xray_process::check_config(exe, &config)
                    .await
                    .map_err(|e| e.to_string())
            }
            _ => Err(format!("unknown engine {id}")),
        }
    }
}

/// A TUN session over the Xray slots, with the listeners the runtime opens (ports picked but
/// never bound here: `check` builds the inbounds without listening).
fn tun_config() -> Result<Vec<u8>, String> {
    let mut taken = Vec::new();
    let mut port = || -> Result<u16, String> {
        let p = ports::alloc_port(false, &taken).map_err(|_| NO_PORT.to_owned())?;
        taken.push(p);
        Ok(p)
    };
    let (clash, direct, probe, bootstrap) = (port()?, port()?, port()?, port()?);
    let a = SlotEndpoint::allocate(&[clash, direct, probe, bootstrap]).map_err(|_| NO_PORT)?;
    let b = SlotEndpoint::allocate(&[clash, direct, probe, bootstrap, a.port()])
        .map_err(|_| NO_PORT)?;
    let inputs = ConfigInputs {
        upstream: Upstream::XraySlots {
            slots: [a, b],
            active: Slot::A,
            udp: UdpPolicy {
                udp: true,
                block_quic: false,
            },
        },
        capture: Capture::Tun(TunParams {
            alias: "VPN Tunnel Enforcer".into(),
            mtu: 1500,
            ipv6: false,
            dns_hijack: true,
            stack: TunStack::Mixed,
        }),
        listeners: Listeners {
            clash_port: clash,
            clash_secret: ports::secret(),
            direct: Loopback {
                port: direct,
                creds: Some(ports::creds()),
            },
            probe: Some(Loopback {
                port: probe,
                creds: Some(ports::creds()),
            }),
            dns_bootstrap: Some(bootstrap),
        },
        routing: RoutingParts::default(),
        phys_dns: Vec::new(),
    };
    let config = singbox_config::build(&inputs).map_err(|e| format!("{e:?}"))?;
    serde_json::to_vec(&config).map_err(|e| e.to_string())
}

fn xray_slot_config() -> Result<Vec<u8>, String> {
    let profile = vpnte_profiles::uri::parse_uri(SAMPLE_XRAY).map_err(|e| format!("{e:?}"))?;
    let graph = xray_config::proxy_graph(&profile, ClientDevice::default())
        .map_err(|e| format!("{e:?}"))?;
    let endpoint = SlotEndpoint::allocate(&[]).map_err(|_| NO_PORT.to_owned())?;
    serde_json::to_vec(&xray_config::build_config(&graph, &endpoint)).map_err(|e| e.to_string())
}

const NO_PORT: &str = "no free loopback port";

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

    /// The bundled engines (from `cargo xtask engines`) accept the configs the check builds and
    /// report their bundled versions; skipped quietly when the binaries are not there.
    #[tokio::test]
    async fn the_bundled_engines_pass_the_service_checks() {
        let dir = Path::new(RESOURCES);
        for (id, exe) in [(SINGBOX, "sing-box.exe"), (XRAY, "xray.exe")] {
            let exe = dir.join(exe);
            if !exe.is_file() {
                continue;
            }
            let version = EngineChecks.version(id, &exe).await.expect("version");
            assert_eq!(
                Some(version),
                vpnte_update::policy::bundled_version(id),
                "{id}"
            );
            EngineChecks.configs(id, &exe).await.expect(id);
        }
    }
}
