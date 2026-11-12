//! The helper service `vpnte-service` (LocalSystem): hosts the privileged half of the tunnel —
//! the runtime with the TUN capture, the pinned engines and the WFP kill switch — behind one named
//! pipe that the unelevated app drives. Library parts: the pipe protocol ([`proto`], used by the
//! app too), the pipe server and the app's client ([`pipe`], [`pipe::client`]), request
//! validation ([`validate`]), security descriptors ([`sddl`]), the session host ([`host`]), the
//! users list ([`users`]), engine confinement ([`sandbox`]), the Service Control Manager glue
//! ([`scm`]), folders ([`paths`]), install / uninstall ([`install`]), the service body
//! ([`service`]) and the signed-update check ([`update`]). The binary is `src/main.rs`.

#[cfg(test)]
mod test_locales;

/// This crate's locale fragments as `(ru_json, en_json)`, one per work package.
pub const LOCALES: &[(&str, &str)] = &[(
    include_str!("../locales/svc-core.ru.json"),
    include_str!("../locales/svc-core.en.json"),
)];

pub mod host;
pub mod install;
pub mod paths;
pub mod pipe;
pub mod proto;
pub mod sandbox;
pub mod scm;
pub mod sddl;
pub mod service;
pub mod update;
pub mod users;
pub mod validate;
