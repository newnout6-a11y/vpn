//! TUN alias choice. The alias mimics the auto-numbered names Windows gives additional NICs
//! ("Ethernet 5") so anti-VPN software scanning adapter names sees nothing unusual. A name that
//! is already taken is never reused: a duplicate connection name is either refused at adapter
//! creation or taken over from its holder by renaming it — a user's NIC must never be renamed.
use vpnte_base::{AppError, Msg};

use super::tun::same_alias;
use super::{ffi, reg};

/// Candidates in order of preference.
pub const CANDIDATES: [&str; 8] = [
    "Ethernet 5",
    "Ethernet 6",
    "Ethernet 7",
    "Ethernet 8",
    "Ethernet 9",
    "Ethernet 10",
    "Ethernet 11",
    "Ethernet 12",
];
/// Used only when every candidate is taken.
pub const FALLBACK: &str = "VPNTE-TUN";

/// Every alias [`choose`] ever returns: the candidates and the fallback (release waits and
/// stale-state checks look at all of them).
pub fn all_aliases() -> Vec<String> {
    CANDIDATES
        .iter()
        .chain([&FALLBACK])
        .map(|s| (*s).to_owned())
        .collect()
}

/// No free alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AliasError {
    #[error("every TUN alias candidate is taken by another network connection")]
    Exhausted,
}

impl From<AliasError> for AppError {
    fn from(err: AliasError) -> Self {
        AppError::conflict(Msg::new("winnet.adapters.aliasExhausted")).with_source(err)
    }
}

/// Names of every network connection Windows knows: the registry `Connection\Name` of each
/// adapter (disabled, hidden and currently absent ones too) plus the alias of every live NDIS
/// interface.
pub fn connection_names() -> windows::core::Result<Vec<String>> {
    let mut names = reg::connection_names()?;
    names.extend(ffi::if_rows()?.into_iter().map(|row| row.alias));
    Ok(names)
}

/// The first candidate not in `taken` (case-insensitive), else [`FALLBACK`], else an error.
pub fn choose(taken: &[String]) -> Result<String, AliasError> {
    CANDIDATES
        .iter()
        .chain([&FALLBACK])
        .find(|candidate| !taken.iter().any(|name| same_alias(name, candidate)))
        .map(|candidate| (*candidate).to_owned())
        .ok_or(AliasError::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// AT-02-002 / AT-02-004: alias vectors (tunnel-core §7.14).
    #[test]
    fn first_free_candidate() {
        assert_eq!(
            choose(&names(&[
                "Wi-Fi",
                "Ethernet",
                "Loopback Pseudo-Interface 1"
            ]))
            .unwrap(),
            "Ethernet 5"
        );
        assert_eq!(
            choose(&names(&["Ethernet", "Ethernet 5", "Wi-Fi"])).unwrap(),
            "Ethernet 6"
        );
        assert_eq!(
            choose(&names(&["Ethernet 5", "Ethernet 6", "Ethernet 7"])).unwrap(),
            "Ethernet 8"
        );
        assert_eq!(choose(&names(&["ethernet 5"])).unwrap(), "Ethernet 6");
        assert_eq!(choose(&[]).unwrap(), "Ethernet 5");
    }

    /// AT-02-004: all candidates taken → fallback; fallback taken too → a clear error, never reuse.
    #[test]
    fn fallback_then_error() {
        let mut taken = names(&CANDIDATES);
        assert_eq!(choose(&taken).unwrap(), FALLBACK);
        taken.push("vpnte-tun".to_owned());
        assert_eq!(choose(&taken), Err(AliasError::Exhausted));
        let err = AppError::from(AliasError::Exhausted);
        assert_eq!(err.kind, vpnte_base::ErrorKind::Conflict);
        assert_eq!(err.user_msg().key, "winnet.adapters.aliasExhausted");
    }

    #[test]
    fn all_aliases_cover_choices() {
        let all = all_aliases();
        assert_eq!(all.len(), 9);
        assert_eq!(all.last().map(String::as_str), Some(FALLBACK));
    }

    /// Live read on this machine: the registry and the interface table both answer, and the
    /// choice never collides with an existing name.
    #[test]
    fn live_connection_names() {
        let names = connection_names().expect("connection names");
        assert!(!names.is_empty());
        let chosen = choose(&names).expect("a free alias");
        assert!(
            !names.iter().any(|n| n.eq_ignore_ascii_case(&chosen)),
            "{chosen} is taken"
        );
        println!("{} connection names; chosen alias {chosen:?}", names.len());
    }
}
