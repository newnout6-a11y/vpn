//! The two Xray upstream slots behind sing-box's `proxy-out` selector: which slot, and where its
//! authenticated SOCKS listener is. One vocabulary for the sing-box config, the Xray config and
//! the Xray supervisor.
use vpnte_base::AppError;
use vpnte_base::types::{Creds, Loopback};

use crate::tags::SLOT_TAGS;

/// One of the two upstream slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Slot {
    #[default]
    A,
    B,
}

impl Slot {
    /// Both slots, in selector order.
    pub const BOTH: [Slot; 2] = [Slot::A, Slot::B];

    /// The standby slot when `self` is active, and vice versa.
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    /// Position in [`SLOT_TAGS`] and in `singbox_config::Upstream::XraySlots::slots`.
    pub fn index(self) -> usize {
        match self {
            Slot::A => 0,
            Slot::B => 1,
        }
    }

    /// Tag of the slot's SOCKS outbound in the sing-box config (a `proxy-out` member).
    pub fn tag(self) -> &'static str {
        SLOT_TAGS[self.index()]
    }

    /// Engine log stem: `xray-a.log` / `xray-b.log`.
    pub fn log_stem(self) -> &'static str {
        match self {
            Slot::A => "xray-a",
            Slot::B => "xray-b",
        }
    }
}

/// The authenticated SOCKS5 listener of one Xray instance on 127.0.0.1 (a runtime slot or a
/// probe instance). Valid by construction (port non-zero, user and password 1..=255 bytes as
/// RFC 1929 requires), so neither the Xray config nor the supervisor can get a bad one. `Debug`
/// hides the credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotEndpoint {
    port: u16,
    creds: Creds,
}

/// Why a slot endpoint was refused: the app generates ports and credentials itself, so this is
/// always a bug ([`vpnte_base::ErrorKind::Internal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidEndpoint {
    #[error("invalid loopback SOCKS port 0")]
    Port,
    #[error("invalid loopback SOCKS authentication (user and password must be 1..=255 bytes)")]
    Authentication,
}

impl From<InvalidEndpoint> for AppError {
    fn from(err: InvalidEndpoint) -> Self {
        AppError::internal(err)
    }
}

impl SlotEndpoint {
    /// Checks the port and the credentials.
    pub fn new(port: u16, creds: Creds) -> Result<Self, InvalidEndpoint> {
        if port == 0 {
            return Err(InvalidEndpoint::Port);
        }
        let ok = |s: &str| (1..=255).contains(&s.len());
        if !ok(&creds.user) || !ok(&creds.pass) {
            return Err(InvalidEndpoint::Authentication);
        }
        Ok(Self { port, creds })
    }

    /// A fresh endpoint: a free loopback TCP port outside `taken` and new random credentials.
    pub fn allocate(taken: &[u16]) -> Result<Self, crate::ports::PortsExhausted> {
        Ok(Self {
            port: crate::ports::alloc_port(false, taken)?,
            creds: crate::ports::creds(),
        })
    }

    /// Loopback port of the SOCKS listener.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Credentials sing-box (or a probe) must present.
    pub fn creds(&self) -> &Creds {
        &self.creds
    }

    /// The same listener as the shared base type (`singbox_config::Upstream::XraySlots`).
    pub fn loopback(&self) -> Loopback {
        Loopback {
            port: self.port,
            creds: Some(self.creds.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(user: &str, pass: &str) -> Creds {
        Creds {
            user: user.into(),
            pass: pass.into(),
        }
    }

    /// Slot credentials must fit RFC 1929 (1..=255 bytes each); checked before anything runs.
    #[test]
    fn endpoint_validation() {
        for bad in [creds("", "secret"), creds("user", &"я".repeat(128))] {
            let err = SlotEndpoint::new(20000, bad).expect_err("refused");
            assert_eq!(err, InvalidEndpoint::Authentication);
            assert!(err.to_string().contains("authentication"));
        }
        assert_eq!(
            SlotEndpoint::new(0, creds("u", "p")),
            Err(InvalidEndpoint::Port)
        );
        let max = SlotEndpoint::new(65535, creds(&"u".repeat(255), "p")).expect("255 bytes");
        assert_eq!((max.port(), max.creds().user.len()), (65535, 255));
        assert_eq!(max.loopback().creds, Some(creds(&"u".repeat(255), "p")));
        // Debug output never shows the credentials.
        assert!(!format!("{max:?}").contains("uuu"));
        let err = AppError::from(InvalidEndpoint::Port);
        assert_eq!(err.kind, vpnte_base::ErrorKind::Internal);
    }

    #[test]
    fn allocated_endpoints_are_valid() {
        let fresh = SlotEndpoint::allocate(&[]).unwrap();
        assert_eq!(fresh.creds().user.len(), 32);
        assert!(SlotEndpoint::new(fresh.port(), fresh.creds().clone()).is_ok());
    }

    #[test]
    fn slots() {
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::BOTH.map(Slot::tag), SLOT_TAGS);
        assert_eq!(
            (Slot::A.log_stem(), Slot::B.log_stem()),
            ("xray-a", "xray-b")
        );
        assert_eq!(Slot::default(), Slot::A);
    }
}
