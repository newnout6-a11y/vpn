//! Child processes and process observation: the kill-on-close Job Object every child lives in,
//! the hidden-spawn helper for engines and tools, the graceful CTRL_BREAK stop, image paths by
//! PID, owners of local sockets, and the startup sweep of orphaned engines under our own
//! directories.
//!
//! New engines are owned by handle (spawned by us, inside a kill-on-close job), so no ownership
//! proof by enumeration is needed for them: a signalled process handle is the exit proof. The
//! enumeration here only serves the one-time sweep of leftovers from older builds.

mod ctrl;
mod image;
mod job;
mod sockets;
mod sweep;

pub use ctrl::{ctrl_break, detach_console};
pub use image::{ImageError, image_path};
pub use job::{Job, app_job, spawn_hidden};
pub use sockets::{ListenerOwner, SocketRow, TcpState, Transport, listener_owner, socket_table};
pub use sweep::{
    OwnedProc, ProcessScan, SweepError, SweepReport, UnknownProc, UnknownReason, find_under,
    sweep_orphans,
};
