//! Network-change events. `NotifyIpInterfaceChange` + `NotifyUnicastIpAddressChange` wake a task
//! that lets the burst settle (one Wi-Fi reconnect fires a dozen notifications), recomputes the
//! address signature and reports only real changes, so consumers never see no-op callbacks.
use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    NotifyIpInterfaceChange, NotifyUnicastIpAddressChange,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

use super::ffi::{self, GaaRow};

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const OPER_UP: i32 = 1;

/// A settled change of the machine's addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetChange {
    /// Address rows (one per address of every up, non-loopback interface) before the change.
    pub before: usize,
    /// Address rows after the change.
    pub after: usize,
}

/// What a [`NetChange`] most likely was (labels the live session's network transition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetChangeKind {
    AdapterRemoved,
    AdapterAdded,
    AddressChanged,
}

impl NetChange {
    /// Fewer rows: an adapter went away; more: one appeared; as many: an address changed.
    pub fn kind(&self) -> NetChangeKind {
        match self.after.cmp(&self.before) {
            std::cmp::Ordering::Less => NetChangeKind::AdapterRemoved,
            std::cmp::Ordering::Greater => NetChangeKind::AdapterAdded,
            std::cmp::Ordering::Equal => NetChangeKind::AddressChanged,
        }
    }
}

/// `alias|family|address|prefix` of every address of every up, non-loopback interface, sorted.
/// Includes TUNs and virtual adapters on purpose: any of them changing is a network change.
fn signature(rows: &[GaaRow]) -> Vec<String> {
    let mut sig: Vec<String> = rows
        .iter()
        .filter(|r| r.oper_status == OPER_UP && r.if_type != IF_TYPE_SOFTWARE_LOOPBACK)
        .flat_map(|r| {
            r.addresses
                .iter()
                .filter(|a| !a.ip.is_loopback())
                .map(move |a| {
                    let family = if a.ip.is_ipv4() { "IPv4" } else { "IPv6" };
                    format!("{}|{family}|{}|{}", r.alias, a.ip, a.prefix_len)
                })
        })
        .collect();
    sig.sort();
    sig
}

/// Both registrations. Dropping cancels them — `CancelMibChangeNotify2` waits for a callback in
/// progress — and only then frees the callback context.
struct Registrations {
    iface: HANDLE,
    addr: HANDLE,
    ctx: *const Notify,
}

// SAFETY: notification handles and the shared `Notify` are not bound to the registering thread.
unsafe impl Send for Registrations {}

impl Drop for Registrations {
    fn drop(&mut self) {
        for handle in [self.iface, self.addr] {
            if !handle.is_invalid() {
                // SAFETY: a handle from a successful registration, cancelled once, never from a callback.
                let _ = unsafe { CancelMibChangeNotify2(handle) };
            }
        }
        // SAFETY: `ctx` came from `Arc::into_raw` and no callback can run after the cancels above.
        drop(unsafe { Arc::from_raw(self.ctx) });
    }
}

unsafe extern "system" fn on_interface(
    ctx: *const c_void,
    _: *const MIB_IPINTERFACE_ROW,
    _: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: `ctx` is the `Notify` that `Registrations` keeps alive until both are cancelled.
    unsafe { &*ctx.cast::<Notify>() }.notify_one();
}

unsafe extern "system" fn on_address(
    ctx: *const c_void,
    _: *const MIB_UNICASTIPADDRESS_ROW,
    _: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: as in `on_interface`.
    unsafe { &*ctx.cast::<Notify>() }.notify_one();
}

fn register(notify: &Arc<Notify>) -> windows::core::Result<Registrations> {
    let mut regs = Registrations {
        iface: HANDLE::default(),
        addr: HANDLE::default(),
        ctx: Arc::into_raw(Arc::clone(notify)),
    };
    let ctx = regs.ctx.cast::<c_void>();
    // SAFETY: callback and context stay valid until `regs` drops, which cancels first.
    unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            Some(on_interface),
            Some(ctx),
            false,
            &mut regs.iface,
        )
    }
    .ok()?;
    // SAFETY: as above.
    unsafe {
        NotifyUnicastIpAddressChange(
            AF_UNSPEC,
            Some(on_address),
            Some(ctx),
            false,
            &mut regs.addr,
        )
    }
    .ok()?;
    Ok(regs)
}

/// Watches interface and address changes on the current tokio runtime. A [`NetChange`] is sent once
/// notifications have been quiet for `settle` and the address signature differs from the last one.
/// The watch ends, and deregisters, on `cancel` or when the receiver is dropped. The baseline is
/// read before this returns (one blocking adapter read); later reads run on the blocking pool.
pub fn watch_network(
    settle: Duration,
    cancel: CancellationToken,
) -> windows::core::Result<mpsc::Receiver<NetChange>> {
    let notify = Arc::new(Notify::new());
    let registrations = register(&notify)?;
    let last = signature(&ffi::adapters()?);
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let _registrations = registrations;
        watch_loop(ffi::adapters_async, &notify, last, &tx, settle, &cancel).await;
    });
    Ok(rx)
}

/// The watch task: waits for a burst, lets it settle, re-reads and sends real changes. Returns on
/// `cancel` or when the receiver is gone.
async fn watch_loop<F: Future<Output = windows::core::Result<Vec<GaaRow>>>>(
    mut read: impl FnMut() -> F,
    notify: &Notify,
    mut last: Vec<String>,
    tx: &mpsc::Sender<NetChange>,
    settle: Duration,
    cancel: &CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tx.closed() => return,
            () = notify.notified() => {}
        }
        // Every new notification restarts the quiet period.
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(settle) => break,
                () = notify.notified() => {}
            }
        }
        match read().await {
            Ok(rows) => {
                let now = signature(&rows);
                if now != last {
                    let change = NetChange {
                        before: last.len(),
                        after: now.len(),
                    };
                    last = now;
                    // A consumer that stops reading must not keep the watch alive past cancel.
                    tokio::select! {
                        () = cancel.cancelled() => return,
                        sent = tx.send(change) => if sent.is_err() { return },
                    }
                }
            }
            Err(err) => tracing::debug!("network change: adapter read failed: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::adapters::UnicastAddress;

    fn row(alias: &str, oper_status: i32, if_type: u32, addrs: &[(&str, u8)]) -> GaaRow {
        GaaRow {
            if_index: 1,
            luid: 1,
            guid: None,
            alias: alias.into(),
            description: String::new(),
            mac: Vec::new(),
            ipv4_enabled: true,
            ipv6_enabled: true,
            if_type,
            oper_status,
            link_speed_bps: 0,
            addresses: addrs
                .iter()
                .map(|(ip, len)| UnicastAddress {
                    ip: ip.parse().unwrap(),
                    prefix_len: *len,
                    dad_state: 4,
                    temporary: false,
                })
                .collect(),
            gateways: Vec::new(),
            dns: Vec::new(),
        }
    }

    /// AT-07-002: the signature covers every address of every up, non-loopback interface (TUNs
    /// included), sorted; down interfaces and loopback do not count.
    #[test]
    fn signature_rows() {
        let rows = [
            row(
                "Wi-Fi",
                OPER_UP,
                71,
                &[("192.168.1.5", 24), ("fe80::1", 64)],
            ),
            row("happ-xray", OPER_UP, 53, &[("172.19.0.1", 30)]),
            row("Ethernet", 2, 6, &[("10.0.0.2", 8)]),
            row(
                "Loopback Pseudo-Interface 1",
                OPER_UP,
                24,
                &[("127.0.0.1", 8)],
            ),
        ];
        assert_eq!(
            signature(&rows),
            [
                "Wi-Fi|IPv4|192.168.1.5|24",
                "Wi-Fi|IPv6|fe80::1|64",
                "happ-xray|IPv4|172.19.0.1|30"
            ]
        );
    }

    /// The history label of a change: fewer rows / more rows / same count.
    #[test]
    fn change_kind() {
        assert_eq!(
            NetChange {
                before: 3,
                after: 2
            }
            .kind(),
            NetChangeKind::AdapterRemoved
        );
        assert_eq!(
            NetChange {
                before: 2,
                after: 3
            }
            .kind(),
            NetChangeKind::AdapterAdded
        );
        assert_eq!(
            NetChange {
                before: 3,
                after: 3
            }
            .kind(),
            NetChangeKind::AddressChanged
        );
    }

    /// Live: registering, cancelling and deregistering works and ends the stream promptly.
    #[tokio::test]
    async fn live_watch_stops_on_cancel() {
        let cancel = CancellationToken::new();
        let mut rx = watch_network(Duration::from_millis(200), cancel.clone()).expect("register");
        cancel.cancel();
        let end = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("watch task ended");
        assert_eq!(end, None);
    }

    /// A consumer that stopped reading leaves the task waiting in `send`; cancel must still end it
    /// (and so drop the OS registrations). Every fake read reports a new address.
    #[tokio::test]
    async fn a_stalled_consumer_does_not_outlive_cancel() {
        let notify = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn({
            let (notify, cancel, reads) = (notify.clone(), cancel.clone(), reads.clone());
            async move {
                let read = || {
                    let ip = format!("10.0.0.{}", reads.fetch_add(1, Ordering::SeqCst) + 1);
                    std::future::ready(Ok(vec![row("Wi-Fi", OPER_UP, 71, &[(&ip, 24)])]))
                };
                let settle = Duration::from_millis(1);
                watch_loop(read, &notify, Vec::new(), &tx, settle, &cancel).await;
            }
        });
        // Two settled bursts: the first change fills the channel, the second waits in `send`.
        for burst in 1..=2 {
            while reads.load(Ordering::SeqCst) < burst {
                notify.notify_one();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "blocked in send while nobody reads");

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cancel ends a task blocked in send")
            .expect("task did not panic");
        let first = NetChange {
            before: 0,
            after: 1,
        };
        assert_eq!(rx.try_recv(), Ok(first));
        assert!(rx.try_recv().is_err(), "the second change was never sent");
    }
}
