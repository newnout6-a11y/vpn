//! The service's pipe: server listener and the app's client end.
//!
//! Server: the name and DACL of [`crate::sddl`], `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first
//! instance (creating the pipe fails if anyone else already did: no squatting under our name),
//! `PIPE_REJECT_REMOTE_CLIENTS`, byte mode with the length-prefixed frames of
//! [`crate::proto::frame`]. Waiting in `ConnectNamedPipe` is an overlapped I/O on the runtime's
//! completion port: an idle service never wakes up.
use std::io;
use std::sync::Arc;

use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};

use crate::sddl::{self, SecurityDescriptor};

pub mod client;
pub mod ident;

#[cfg(test)]
mod tests;

pub use ident::ClientInfo;

/// Decides whether an identified client may use the service (the DACL already admitted it).
pub type ClientCheck = Arc<dyn Fn(&ClientInfo) -> bool + Send + Sync>;

/// The default check: every client the DACL admitted (interactive users, administrators,
/// SYSTEM). The security boundary is the typed protocol, not the caller's image.
pub fn admit_all() -> ClientCheck {
    Arc::new(|_| true)
}

/// Pipe name and DACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeConfig {
    pub name: String,
    pub sddl: String,
}

impl PipeConfig {
    /// The service's pipe ([`sddl::PIPE_NAME`], [`sddl::PIPE_SDDL`]).
    pub fn production() -> Self {
        Self {
            name: sddl::PIPE_NAME.to_owned(),
            sddl: sddl::PIPE_SDDL.to_owned(),
        }
    }
}

/// Accepts connections; always holds one instance waiting for the next client.
pub struct Listener {
    name: String,
    sd: SecurityDescriptor,
    next: NamedPipeServer,
}

impl Listener {
    /// Creates the first instance (fails when the pipe already exists).
    pub fn bind(config: &PipeConfig) -> io::Result<Self> {
        let sd = SecurityDescriptor::from_sddl(&config.sddl).map_err(io::Error::other)?;
        let next = instance(&config.name, &sd, true)?;
        Ok(Self {
            name: config.name.clone(),
            sd,
            next,
        })
    }

    /// Waits for a client; returns its connected end and readies the next instance.
    pub async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        self.next.connect().await?;
        let fresh = instance(&self.name, &self.sd, false)?;
        Ok(std::mem::replace(&mut self.next, fresh))
    }
}

fn instance(name: &str, sd: &SecurityDescriptor, first: bool) -> io::Result<NamedPipeServer> {
    let mut attributes = sd.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte);
    // SAFETY: `attributes` points at `sd`, which outlives the call.
    unsafe { options.create_with_security_attributes_raw(name, (&raw mut attributes).cast()) }
}
