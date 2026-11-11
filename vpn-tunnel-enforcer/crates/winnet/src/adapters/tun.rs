//! Our TUN adapter: find it after sing-box starts, re-check its identity, wait for it to go away.
//!
//! sing-box creates the Wintun adapter under the alias we chose and assigns our /30. Alias plus the
//! exact address identifies it before its LUID is known; afterwards the LUID does.
use std::net::IpAddr;
use std::time::Duration;

use ipnet::{Ipv4Net, Ipv6Net};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, ErrorKind, Msg};
use windows::core::GUID;

use super::ffi::{self, GaaRow};
use super::is_own_tun_address;

const OPER_UP: i32 = 1;
const OPER_NOT_PRESENT: i32 = 6;
/// The adapter appears a few hundred ms after sing-box starts. Each poll is one GAA read on the
/// blocking pool (~7 ms on a machine with dozens of NDIS filter interfaces).
const FIND_POLL: Duration = Duration::from_millis(50);
const RELEASE_POLL: Duration = Duration::from_millis(25);

/// Our verified TUN adapter; other code excludes it by LUID, never by alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTun {
    pub alias: String,
    pub luid: u64,
    pub guid: GUID,
    pub if_index: u32,
    /// The /30 it was verified with.
    pub v4: Ipv4Net,
    /// Present when the TUN is dual-stack.
    pub v6: Option<Ipv6Net>,
}

/// Why [`wait_owned_tun`] gave up.
#[derive(Debug, thiserror::Error)]
pub enum TunAdapterError {
    #[error("TUN adapter {alias:?} with {v4} did not come up within {waited:?}")]
    Timeout {
        alias: String,
        v4: Ipv4Net,
        waited: Duration,
        /// The last adapter read failed (otherwise the adapter simply never matched).
        #[source]
        last_error: Option<windows::core::Error>,
    },
    #[error("cancelled while waiting for the TUN adapter")]
    Cancelled,
}

impl From<TunAdapterError> for AppError {
    fn from(err: TunAdapterError) -> Self {
        match err {
            TunAdapterError::Cancelled => AppError::cancelled(),
            TunAdapterError::Timeout { .. } => {
                AppError::msg(ErrorKind::Timeout, Msg::new("winnet.adapters.tunTimeout"))
                    .with_source(err)
            }
        }
    }
}

/// Outcome of [`wait_released`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Release {
    /// None of the given aliases carries one of our addresses any more.
    Released,
    Cancelled,
    /// Still present at the deadline, or the read failed: release is not proven.
    Unverified,
}

/// Case-insensitive like Windows connection names; `to_lowercase` also folds Cyrillic aliases.
fn same_alias(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

/// Up, exactly the `alias`, the exact `v4` (address and prefix) and, if given, the exact `v6`.
fn holds_identity(row: &GaaRow, alias: &str, v4: Ipv4Net, v6: Option<Ipv6Net>) -> bool {
    let has = |ip: IpAddr, len: u8| {
        row.addresses
            .iter()
            .any(|a| a.ip == ip && a.prefix_len == len && a.usable())
    };
    row.oper_status == OPER_UP
        && same_alias(&row.alias, alias)
        && has(IpAddr::V4(v4.addr()), v4.prefix_len())
        && v6.is_none_or(|v6| has(IpAddr::V6(v6.addr()), v6.prefix_len()))
}

/// Exactly one adapter carries `alias` and it holds the identity. Two adapters with one alias would
/// mean the name is not ours to trust, so that never matches.
fn find_owned(rows: &[GaaRow], alias: &str, v4: Ipv4Net, v6: Option<Ipv6Net>) -> Option<OwnedTun> {
    let mut named = rows.iter().filter(|r| same_alias(&r.alias, alias));
    let row = named.next()?;
    if named.next().is_some() || !holds_identity(row, alias, v4, v6) || row.if_index == 0 {
        return None;
    }
    Some(OwnedTun {
        alias: row.alias.clone(),
        luid: row.luid,
        guid: row.guid?,
        if_index: row.if_index,
        v4,
        v6,
    })
}

/// Waits until sing-box's adapter `alias` is up with exactly `v4` (and `v6` when the TUN is
/// dual-stack), then returns its LUID / GUID / index. Nothing is published as running before this.
pub async fn wait_owned_tun(
    alias: &str,
    v4: Ipv4Net,
    v6: Option<Ipv6Net>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<OwnedTun, TunAdapterError> {
    wait_owned_with(ffi::adapters_async, alias, v4, v6, timeout, cancel).await
}

async fn wait_owned_with<F: Future<Output = windows::core::Result<Vec<GaaRow>>>>(
    mut read: impl FnMut() -> F,
    alias: &str,
    v4: Ipv4Net,
    v6: Option<Ipv6Net>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<OwnedTun, TunAdapterError> {
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.is_cancelled() {
            return Err(TunAdapterError::Cancelled);
        }
        let last_error = match read().await {
            Ok(rows) => match find_owned(&rows, alias, v4, v6) {
                Some(tun) => return Ok(tun),
                None => None,
            },
            Err(err) => Some(err),
        };
        let now = Instant::now();
        if now >= deadline {
            return Err(TunAdapterError::Timeout {
                alias: alias.to_owned(),
                v4,
                waited: timeout,
                last_error,
            });
        }
        tokio::select! {
            () = cancel.cancelled() => return Err(TunAdapterError::Cancelled),
            () = tokio::time::sleep(FIND_POLL.min(deadline - now)) => {}
        }
    }
}

/// Waits until none of `aliases` carries one of our TUN addresses (current or legacy IPv4 prefix,
/// or `v6` when the old TUN was dual-stack). The caller has already proven the engine exited; this
/// only waits for Windows to tear the adapter down before the next one is created.
pub async fn wait_released(
    aliases: &[String],
    v6: Option<Ipv6Net>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Release {
    wait_released_with(ffi::adapters_async, aliases, v6, timeout, cancel).await
}

async fn wait_released_with<F: Future<Output = windows::core::Result<Vec<GaaRow>>>>(
    mut read: impl FnMut() -> F,
    aliases: &[String],
    v6: Option<Ipv6Net>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Release {
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.is_cancelled() {
            return Release::Cancelled;
        }
        match read().await {
            Ok(rows) if !owned_present(&rows, aliases, v6) => return Release::Released,
            Ok(_) => {}
            // A failed read is not proof of release.
            Err(_) => return Release::Unverified,
        }
        let now = Instant::now();
        if now >= deadline {
            return Release::Unverified;
        }
        tokio::select! {
            () = cancel.cancelled() => return Release::Cancelled,
            () = tokio::time::sleep(RELEASE_POLL.min(deadline - now)) => {}
        }
    }
}

fn owned_present(rows: &[GaaRow], aliases: &[String], v6: Option<Ipv6Net>) -> bool {
    rows.iter()
        .filter(|r| aliases.iter().any(|a| same_alias(&r.alias, a)))
        .any(|r| {
            r.addresses.iter().any(|a| {
                is_own_tun_address(a.ip) || v6.is_some_and(|v6| a.ip == IpAddr::V6(v6.addr()))
            })
        })
}

/// Whether the interface still exists (`GetIfEntry2`); a "not present" ghost counts as gone.
pub fn adapter_present(luid: u64) -> windows::core::Result<bool> {
    Ok(ffi::if_row(luid)?.is_some_and(|row| row.oper_status != OPER_NOT_PRESENT))
}

/// The adapter with this LUID is still ours: same GUID, alias and addresses, and up.
pub(super) fn identity_holds(tun: &OwnedTun) -> windows::core::Result<bool> {
    Ok(identity_in(&ffi::adapters()?, tun))
}

fn identity_in(rows: &[GaaRow], tun: &OwnedTun) -> bool {
    rows.iter().find(|r| r.luid == tun.luid).is_some_and(|row| {
        row.guid == Some(tun.guid)
            && row.if_index == tun.if_index
            && holds_identity(row, &tun.alias, tun.v4, tun.v6)
    })
}

#[cfg(test)]
mod tests;
