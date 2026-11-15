//! Lab L11-4: a lookup made ahead of the click is shared while it runs. Whoever needs the same
//! name meanwhile (a switch's stage in this process, a second lookup ahead) joins it instead of
//! asking the resolvers again. Per Windows user, as every answer of this module.
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;

use parking_lot::Mutex;
use tokio::sync::watch;

use super::ResolveError;

/// An ahead lookup as its joiners see it: `None` while it runs, then its addresses
/// (`Some(None)`: it found none).
type Outcome = Option<Option<Vec<IpAddr>>>;

/// The lookups in flight, by owner and name.
type Flight = HashMap<(String, String), watch::Receiver<Outcome>>;

static FLIGHT: Mutex<Option<Flight>> = Mutex::new(None);

/// Runs `lookup` of `name` for `owner` as the one shared lookup of it, or joins the one in
/// flight. No owner (a service request nobody named): it runs on its own, unshared.
pub(super) async fn shared<F>(
    owner: Option<String>,
    name: &str,
    lookup: F,
) -> Result<Vec<IpAddr>, ResolveError>
where
    F: Future<Output = Result<Vec<IpAddr>, ResolveError>>,
{
    let Some(owner) = owner else {
        return lookup.await;
    };
    let key = (owner, name.to_owned());
    let turn = {
        let mut flight = FLIGHT.lock();
        let map = flight.get_or_insert_default();
        if let Some(running) = map.get(&key) {
            Turn::Join(running.clone())
        } else {
            let (tx, rx) = watch::channel(None);
            map.insert(key.clone(), rx);
            Turn::Ask(tx)
        }
    };
    let tx = match turn {
        Turn::Ask(tx) => tx,
        Turn::Join(running) => return outcome(running).await.ok_or(ResolveError::Failed),
    };
    // Gone with the lookup, also when its caller drops it halfway: joiners then ask themselves.
    let _gone = Landed(key);
    let found = lookup.await;
    tx.send_replace(Some(found.as_ref().ok().cloned()));
    found
}

/// Whether a lookup asks the resolvers or joins the one in flight.
enum Turn {
    Ask(watch::Sender<Outcome>),
    Join(watch::Receiver<Outcome>),
}

/// The addresses `owner`'s ahead lookup of `name` in flight brings, once it lands (`None`: none
/// runs, it found nothing, or it was dropped).
pub(super) async fn join(owner: Option<&str>, name: &str) -> Option<Vec<IpAddr>> {
    let key = (owner?.to_owned(), name.to_owned());
    let running = FLIGHT.lock().as_ref()?.get(&key)?.clone();
    outcome(running).await
}

async fn outcome(mut running: watch::Receiver<Outcome>) -> Option<Vec<IpAddr>> {
    let landed = running.wait_for(Option::is_some).await.ok()?;
    landed.clone().flatten()
}

/// Removes its lookup from [`FLIGHT`] when dropped.
struct Landed((String, String));

impl Drop for Landed {
    fn drop(&mut self) {
        if let Some(map) = FLIGHT.lock().as_mut() {
            map.remove(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    /// A lookup that answers `addrs` after `ms` and counts how often it ran.
    async fn lookup(
        ms: u64,
        addrs: Vec<IpAddr>,
        runs: &std::sync::atomic::AtomicUsize,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(ms)).await;
        Ok(addrs)
    }

    /// L11-4: a second asker of a name in flight gets the first lookup's answer when it lands;
    /// the resolvers are asked once. Another user's asker joins nothing.
    #[tokio::test(start_paused = true)]
    async fn a_name_in_flight_is_joined_not_asked_again() {
        let runs = std::sync::atomic::AtomicUsize::new(0);
        let owner = Some("S-1-5-21-ahead".to_owned());
        let first = shared(
            owner.clone(),
            "join.example",
            lookup(300, vec![ip(7)], &runs),
        );
        let second = shared(
            owner.clone(),
            "join.example",
            lookup(10, vec![ip(8)], &runs),
        );
        let joined = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            join(owner.as_deref(), "join.example").await
        };
        let other = join(Some("S-1-5-21-other"), "join.example");
        let (a, b, c, d) = tokio::join!(first, second, joined, other);
        assert_eq!((a.unwrap(), b.unwrap()), (vec![ip(7)], vec![ip(7)]));
        assert_eq!((c, d), (Some(vec![ip(7)]), None));
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(join(owner.as_deref(), "join.example").await, None, "landed");
    }

    /// A dropped lookup leaves its joiners nothing to wait for.
    #[tokio::test(start_paused = true)]
    async fn a_dropped_lookup_releases_its_joiners() {
        let runs = std::sync::atomic::AtomicUsize::new(0);
        let owner = Some("S-1-5-21-drop".to_owned());
        let dropped = tokio::time::timeout(
            Duration::from_millis(100),
            shared(
                owner.clone(),
                "drop.example",
                lookup(5_000, vec![ip(9)], &runs),
            ),
        );
        let joined = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            join(owner.as_deref(), "drop.example").await
        };
        let (gone, seen) = tokio::join!(dropped, joined);
        assert!(gone.is_err());
        assert_eq!(seen, None);
    }
}
