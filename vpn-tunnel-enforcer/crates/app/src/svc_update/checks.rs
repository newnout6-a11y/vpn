//! The engine store's checks of a new engine (research §4.7 step 3): it must report the feed's
//! version, and accept every config the app would build now for the user's current server and
//! settings — Proxy and TUN capture, native and Xray-slot upstreams, Smart RU, the user's rules —
//! through its own `check` (sing-box) / `run -test` (Xray). Any refusal = not installed.
use std::io;
use std::path::Path;
use std::sync::Arc;

use vpnte_base::types::{ClientDevice, Engine, Loopback};
use vpnte_core::settings::RuleSetMode;
use vpnte_engine::routing::process::probe_fs;
use vpnte_engine::routing::smart_ru::SmartRu;
use vpnte_engine::routing::{self, RoutingInputs};
use vpnte_engine::singbox_config::{
    self, Capture, ConfigInputs, Listeners, TunParams, TunStack, UdpPolicy, Upstream,
};
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::xray_config::{self, Decision};
use vpnte_engine::{ports, singbox_process, xray_process};
use vpnte_profiles::emit_singbox::EmitPolicy;
use vpnte_profiles::model::Profile;
use vpnte_update::policy::{SINGBOX, XRAY};
use vpnte_update::store::EngineCheck;
use vpnte_update::version::Version;

use crate::services::Backend;

/// A stand-in Xray server when the current one does not run on Xray: the generator's output for
/// a common VLESS form still has to pass the new engine (documentation address, fake id).
const SAMPLE_XRAY: &str = "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp&sni=example.com#sample";

/// [`EngineCheck`] over the backend's stores and the real engines.
pub(crate) struct AppCheck(pub Arc<Backend>);

impl EngineCheck for AppCheck {
    async fn version(&self, id: &str, exe: &Path) -> io::Result<Version> {
        let triple = match id {
            SINGBOX => singbox_process::engine_version(exe).await?,
            XRAY => xray_process::engine_version(exe).await?,
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        Ok(Version::from_triple(triple))
    }

    async fn check_configs(&self, id: &str, exe: &Path) -> Result<(), String> {
        match id {
            SINGBOX => {
                for config in self.singbox_configs().await? {
                    singbox_process::check_config(exe, &config)
                        .await
                        .map_err(|e| match e {
                            singbox_process::CheckError::Rejected(why) => why,
                            singbox_process::CheckError::Run(err) => err.to_string(),
                        })?;
                }
                Ok(())
            }
            XRAY => {
                let config = self.xray_config()?;
                xray_process::check_config(exe, &config).await.map_err(|e| {
                    vpnte_base::AppError::from(e)
                        .user_msg()
                        .render(self.0.lang())
                })
            }
            _ => Err(format!("unknown engine {id}")),
        }
    }
}

impl AppCheck {
    /// The user's server (when it reads) and its engine choice.
    fn current(&self) -> Option<(Profile, ClientDevice, Engine)> {
        let row = self.0.servers.active()?.row;
        let profile = row.profile().ok()?;
        let setting = self.0.settings.read(|s| s.proxy_engine);
        let pref = xray_config::server_pref(setting, row.engine);
        let engine = match xray_config::select_engine(&profile, pref) {
            Decision::Selected { engine, .. } => engine,
            Decision::Rejected(_) => return None,
        };
        Some((profile, row.device, engine))
    }

    /// Proxy and TUN capture, each with the native upstream of the current server (when it runs
    /// on sing-box) and with the Xray slots.
    async fn singbox_configs(&self) -> Result<Vec<Vec<u8>>, String> {
        let routing = self.routing().await?;
        let mut upstreams = Vec::new();
        if let Some((profile, device, Engine::SingBox)) = self.current() {
            let policy = EmitPolicy {
                device: Some(device),
                ..Default::default()
            };
            upstreams.push(Upstream::native(&profile, &policy).map_err(|e| e.to_string())?);
        }
        let mut ports = Ports::default();
        upstreams.push(Upstream::XraySlots {
            slots: [ports.slot()?, ports.slot()?],
            active: Slot::A,
            udp: UdpPolicy {
                udp: true,
                block_quic: false,
            },
        });
        let tun = TunParams {
            alias: "VPN Tunnel Enforcer".into(),
            mtu: 1500,
            ipv6: false,
            dns_hijack: true,
            stack: TunStack::Mixed,
        };
        let mut out = Vec::new();
        for upstream in upstreams {
            let slots = matches!(upstream, Upstream::XraySlots { .. });
            let proxy = Capture::Proxy {
                port: ports.next()?,
            };
            for capture in [proxy, Capture::Tun(tun.clone())] {
                let inputs = ConfigInputs {
                    upstream: upstream.clone(),
                    capture,
                    listeners: ports.listeners(slots)?,
                    routing: routing.clone(),
                    phys_dns: Vec::new(),
                };
                let config = singbox_config::build(&inputs).map_err(|e| format!("{e:?}"))?;
                out.push(serde_json::to_vec(&config).map_err(|e| e.to_string())?);
            }
        }
        Ok(out)
    }

    /// The Xray slot config of the current server, or of the stand-in VLESS server.
    fn xray_config(&self) -> Result<Vec<u8>, String> {
        let (profile, device) = match self.current() {
            Some((profile, device, Engine::Xray)) => (profile, device),
            _ => (
                vpnte_profiles::uri::parse_uri(SAMPLE_XRAY).map_err(|e| format!("{e:?}"))?,
                ClientDevice::default(),
            ),
        };
        let graph = xray_config::proxy_graph(&profile, device).map_err(|e| format!("{e:?}"))?;
        let endpoint = Ports::default().slot()?;
        serde_json::to_vec(&xray_config::build_config(&graph, &endpoint)).map_err(|e| e.to_string())
    }

    /// The user's routing: Smart RU with the active rule sets, domain rules, split tunnelling,
    /// the chosen DNS (file probes and the rule-set lookup are blocking).
    async fn routing(&self) -> Result<singbox_config::RoutingParts, String> {
        let backend = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let s = backend.settings.snapshot();
            let doc = backend.rules.snapshot();
            let managed = s.smart_ru_rule_set_mode == RuleSetMode::Managed;
            let dir = s
                .smart_ru_split
                .then(|| backend.rule_sets.active(managed).map(|(_, dir)| dir))
                .flatten();
            let split = doc.resolve_split(probe_fs);
            let dns = doc.active_dns().map(|p| p.primary);
            let fragments = routing::build(&RoutingInputs {
                smart: SmartRu {
                    enabled: s.smart_ru_split,
                    maps_direct: s.smart_ru_maps_direct,
                },
                rule_set_dir: dir.as_deref(),
                domain_rules: &doc.domain_rules,
                split: &split,
                engine_paths: &[],
                third_party_cores: false,
                dns: dns.as_ref(),
                physical_dns: &[],
                endpoint_is_hostname: false,
            });
            fragments.parts
        })
        .await
        .map_err(|e| e.to_string())
    }
}

/// Distinct loopback ports for one config (never bound here: `check` builds the inbounds
/// without listening).
#[derive(Default)]
struct Ports(Vec<u16>);

impl Ports {
    fn next(&mut self) -> Result<u16, String> {
        let port = ports::alloc_port(false, &self.0).map_err(|_| NO_PORT.to_owned())?;
        self.0.push(port);
        Ok(port)
    }

    fn slot(&mut self) -> Result<SlotEndpoint, String> {
        let slot = SlotEndpoint::allocate(&self.0).map_err(|_| NO_PORT.to_owned())?;
        self.0.push(slot.port());
        Ok(slot)
    }

    fn listeners(&mut self, slots: bool) -> Result<Listeners, String> {
        Ok(Listeners {
            clash_port: self.next()?,
            clash_secret: ports::secret(),
            direct: Loopback {
                port: self.next()?,
                creds: Some(ports::creds()),
            },
            probe: Some(Loopback {
                port: self.next()?,
                creds: Some(ports::creds()),
            }),
            dns_bootstrap: if slots { Some(self.next()?) } else { None },
        })
    }
}

const NO_PORT: &str = "no free loopback port";
