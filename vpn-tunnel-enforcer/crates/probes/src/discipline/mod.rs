//! Probe discipline for Russian networks (Nov 2026): a shared handshake budget per server
//! endpoint, a transfer check that proves more than the ~16 KB freeze threshold, a reach probe
//! (ICMP + plain TCP to the server's own port) and the classifier that turns what the checks saw
//! into a verdict with a suggested reaction.
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::Loopback;

mod budget;
mod classify;
#[cfg(test)]
pub(crate) mod far_side;
mod reach;
#[cfg(test)]
mod tests;
mod transfer;

pub use budget::{
    BudgetError, Endpoint, FREEZE_BACKOFF, HandshakeBudget, MAX_PER_WINDOW, MIN_GAP, WINDOW, budget,
};
pub use classify::{
    Classification, Observations, Reaction, Seen, Verdict, classify, real_certificate,
};
pub use reach::{Reach, TCP_LIMIT, reach};
pub(crate) use transfer::check as transfer_check;
pub use transfer::{
    FREEZE_BAND, Limits, TRANSFER_BYTES, TRANSFER_HOST, Trace, Transfer, TransferReport,
};

/// A transfer check through an engine that already runs (the tunnel's probe inbound after
/// connect, or any loopback SOCKS that dials the server): one budgeted handshake to `endpoint`
/// (`None`: a loopback server, not budgeted), the trace, then [`TRANSFER_BYTES`]. Waits up to
/// `max_wait` for a slot, else `Deferred` ([`BudgetError`] as `AppError`); a freeze holds the
/// endpoint for [`FREEZE_BACKOFF`]. `Err` also on cancellation.
pub async fn transfer_through(
    proxy: &Loopback,
    endpoint: Option<&Endpoint>,
    max_wait: Duration,
    cancel: &CancellationToken,
) -> AppResult<TransferReport> {
    if let Some(endpoint) = endpoint {
        budget().acquire(endpoint, max_wait, cancel).await?;
    }
    let wire = crate::live::wire::Wire::verified().map_err(vpnte_base::AppError::internal)?;
    let report = transfer_check(&wire, proxy, true, Limits::STANDARD, cancel).await?;
    if let Some(endpoint) = endpoint
        && report.transfer.frozen()
    {
        budget().hold(endpoint, FREEZE_BACKOFF);
    }
    Ok(report)
}
