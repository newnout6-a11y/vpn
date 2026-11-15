//! The demo's links and QR codes: a fake clipboard, key file and QR scans (fixed fake keys), a
//! fake QR pattern (not scannable on purpose: it encodes nothing) and an in-memory scheme panel.
use std::cell::RefCell;

use tokio::sync::watch;
use vpnte_base::AppResult;

use super::delay;
use crate::servers::links_model::{LinkScheme, LinkSchemes, QrCode, SchemeOwner};

/// A remote-profile link as a browser hands it over (`--scene link`).
pub(super) const FAKE_LINK: &str =
    "sing-box://import-remote-profile?url=https%3A%2F%2Fsub.example.com%2Fdemo%2Ftoken#Demo";

/// An obvious fake key (RFC 2606 host, all-zero UUID).
pub(super) const FAKE_KEY: &str = "vless://00000000-0000-4000-8000-000000000000@demo.example.com:443?security=reality&sni=www.example.com&fp=chrome&pbk=AAAA&type=tcp#Demo%20phone";

const SCHEMES: [&str; 12] = [
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
    "hy2",
    "tuic",
    "anytls",
    "sing-box",
    "clash",
    "v2raytun",
    "hiddify",
];

pub(super) struct DemoLinks {
    arrivals: watch::Sender<u64>,
    pending: RefCell<Option<String>>,
    schemes: RefCell<Vec<LinkScheme>>,
}

impl DemoLinks {
    pub(super) fn new() -> Self {
        let schemes = SCHEMES
            .iter()
            .map(|&scheme| LinkScheme {
                scheme: scheme.to_owned(),
                owner: match scheme {
                    "hiddify" => SchemeOwner::Other(Some("Hiddify".into())),
                    "clash" => SchemeOwner::Other(None),
                    "v2raytun" => SchemeOwner::Chosen("v2RayTun".into()),
                    "hy2" => SchemeOwner::Free,
                    _ => SchemeOwner::Ours,
                },
            })
            .collect();
        Self {
            arrivals: watch::Sender::new(0),
            pending: RefCell::new(None),
            schemes: RefCell::new(schemes),
        }
    }

    /// As if Windows handed the app `link`.
    pub(super) fn offer(&self, link: &str) {
        *self.pending.borrow_mut() = Some(link.to_owned());
        self.arrivals.send_modify(|n| *n += 1);
    }

    pub(super) fn arrivals(&self) -> watch::Receiver<u64> {
        self.arrivals.subscribe()
    }

    pub(super) fn take(&self) -> Option<String> {
        self.pending.borrow_mut().take()
    }

    pub(super) async fn scan(&self) -> AppResult<String> {
        delay(700).await;
        Ok(FAKE_KEY.to_owned())
    }

    /// The demo runs as a portable copy, so the panel shows its «open links here».
    pub(super) fn schemes(&self) -> LinkSchemes {
        LinkSchemes {
            list: self.schemes.borrow().clone(),
            portable: true,
        }
    }

    pub(super) async fn set(&self, scheme: &str, on: bool) -> LinkSchemes {
        delay(250).await;
        if let Some(entry) = self
            .schemes
            .borrow_mut()
            .iter_mut()
            .find(|s| s.scheme == scheme)
        {
            entry.owner = match (&entry.owner, on) {
                // The user's Windows choice stays (the real registrar writes nothing then).
                (SchemeOwner::Chosen(_), _) => entry.owner.clone(),
                (_, true) => SchemeOwner::Ours,
                // Hiddify's key was kept aside when the demo took it over: it comes back.
                (_, false) if scheme == "hiddify" => SchemeOwner::Other(Some("Hiddify".into())),
                (_, false) => SchemeOwner::Free,
            };
        }
        self.schemes()
    }

    /// Every free scheme opens this copy now.
    pub(super) async fn adopt(&self) -> LinkSchemes {
        delay(250).await;
        for entry in self.schemes.borrow_mut().iter_mut() {
            if entry.owner == SchemeOwner::Free {
                entry.owner = SchemeOwner::Ours;
            }
        }
        self.schemes()
    }
}

/// A QR-looking pattern: the three finder squares and pseudo-random modules (seeded by `id`).
pub(super) fn fake_qr(id: &str) -> QrCode {
    const SIZE: usize = 29;
    let mut rng = fastrand::Rng::with_seed(id.bytes().map(u64::from).sum());
    // A finder square at (cx, cy): dark outer ring, light ring, dark 3×3 core, light border.
    let finder = |x: usize, y: usize| {
        let at = |cx: usize, cy: usize| {
            let (fx, fy) = (x.wrapping_sub(cx), y.wrapping_sub(cy));
            (fx < 8 && fy < 8).then(|| {
                let ring = fx.abs_diff(3).max(fy.abs_diff(3));
                ring != 2 && ring <= 3
            })
        };
        at(0, 0)
            .or_else(|| at(SIZE - 7, 0))
            .or_else(|| at(0, SIZE - 7))
    };
    let dark = (0..SIZE * SIZE)
        .map(|i| finder(i % SIZE, i / SIZE).unwrap_or_else(|| rng.bool()))
        .collect();
    QrCode {
        size: SIZE as u32,
        dark,
    }
}
