//! Probe discipline for Russian networks (Nov 2026): a shared handshake budget per server
//! endpoint, a transfer check that proves more than the ~16 KB freeze threshold, a reach probe
//! (ICMP + plain TCP to the server's own port) and the classifier that turns what the checks saw
//! into a verdict with a suggested reaction.
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
