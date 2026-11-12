//! The helper service as the app finds it (owner decision 12.11.2026): installed (the SCM knows
//! it; the pipe's server is checked against its exe at every connect) or not, and the one
//! elevated step the app may ask Windows for — the service's own install verb, from Settings.
use std::path::PathBuf;

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_service::per_user::{self, Elevated};
use vpnte_service::scm::manage;

/// The service exe next to the app's (the installer and the portable archive ship it there).
const SERVICE_EXE: &str = "vpnte-service.exe";

/// The service is registered with the SCM.
pub fn installed() -> bool {
    match manage::installed_binary() {
        Ok(found) => found.is_some(),
        Err(err) => {
            tracing::warn!(error = %err, "service registration unreadable");
            false
        }
    }
}

fn service_exe() -> AppResult<PathBuf> {
    let exe = std::env::current_exe().map_err(AppError::internal)?;
    let path = exe.with_file_name(SERVICE_EXE);
    if path.is_file() {
        Ok(path)
    } else {
        Err(AppError::msg(
            ErrorKind::Validation,
            Msg::new("app.service.notShipped"),
        ))
    }
}

/// Asks Windows to run `vpnte-service.exe install` elevated (its prompt; the app itself never
/// elevates) and waits. `Ok(true)` installed, `Ok(false)` nobody approved the prompt: nothing
/// else happens, proxy mode goes on. Blocking.
pub fn request_install() -> AppResult<bool> {
    let exe = service_exe()?;
    let elevated = per_user::request_install(&exe, None).map_err(|e| {
        AppError::msg(ErrorKind::Internal, Msg::new("app.service.installFailed")).with_source(e)
    })?;
    match elevated {
        Elevated::Exited(0) => Ok(installed()),
        Elevated::Declined => Ok(false),
        Elevated::Exited(code) => Err(AppError::msg(
            ErrorKind::Internal,
            Msg::new("app.service.installFailed"),
        )
        .with_source(std::io::Error::other(format!("install exited with {code}")))),
    }
}
