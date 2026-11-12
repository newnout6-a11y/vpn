//! What the pinned mihomo cannot express of an AmneziaWG profile (AT-12-004): a profile that
//! uses any of it is refused with the exact list before anything runs. Nothing is dropped or
//! approximated on the way into mihomo's config.
use serde::Serialize;
use vpnte_base::AppError;
use vpnte_base::msg::Msg;
use vpnte_profiles::awg;
use vpnte_profiles::model::{Kind, Profile};

/// One thing the lab engine cannot run, named as the key the user sees in their config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Gap {
    /// Not an AmneziaWG profile: the lab engine runs nothing else.
    NotAmneziawg,
    /// TLS, a transport, mux or a provider Xray graph on the profile (sing-box / Xray forms).
    Layer(&'static str),
    /// Pasted sing-box options (dotted paths) or dial preferences mihomo has no key for.
    Option(String),
    /// No local address (mihomo refuses the entry: "missing local address").
    NoAddress,
    /// More than one local address of one family (mihomo keeps one `ip` and one `ipv6`).
    SecondAddress,
    /// No peer.
    NoPeer,
    /// Peers with different keepalives (mihomo keeps one per entry).
    KeepalivePerPeer,
    /// An AmneziaWG 3.x keepalive range: mihomo has one fixed value, and a fixed interval is
    /// exactly the timing pattern the range hides.
    KeepaliveRange,
    /// WARP `reserved` bytes: mihomo writes them over bytes 1-3 of every packet, which AmneziaWG
    /// uses for its own message headers.
    Reserved,
}

impl Gap {
    /// The name shown in the refusal (config key names are not translated).
    pub fn name(&self) -> String {
        match self {
            Gap::NotAmneziawg => "protocol".into(),
            Gap::Layer(layer) => (*layer).into(),
            Gap::Option(key) => key.clone(),
            Gap::NoAddress => "Address".into(),
            Gap::SecondAddress => "Address (second of one family)".into(),
            Gap::NoPeer => "[Peer]".into(),
            Gap::KeepalivePerPeer => "PersistentKeepalive (per peer)".into(),
            Gap::KeepaliveRange => "PersistentKeepalive (range)".into(),
            Gap::Reserved => "Reserved".into(),
        }
    }
}

/// Why the lab engine refuses a profile before any start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreflightError {
    /// AmneziaWG parameters out of bounds (`vpnte_profiles::awg::validate`, AT-12-003 step 1).
    #[error("invalid AmneziaWG parameters: {}", .0.names())]
    Invalid(awg::AwgInvalid),
    /// Things mihomo cannot express, every one of them, in profile order.
    #[error("mihomo cannot run: {}", names(.0))]
    Unsupported(Vec<Gap>),
}

fn names(gaps: &[Gap]) -> String {
    gaps.iter().map(Gap::name).collect::<Vec<_>>().join(", ")
}

impl PreflightError {
    /// User-facing text: the invalid fields, or the exact unsupported list.
    pub fn msg(&self) -> Msg {
        match self {
            PreflightError::Invalid(invalid) => invalid.msg(),
            PreflightError::Unsupported(gaps) => {
                Msg::new("engine.lab.preflight.unsupported").arg("items", names(gaps))
            }
        }
    }
}

impl From<PreflightError> for AppError {
    fn from(err: PreflightError) -> Self {
        AppError::validation(err.msg()).with_source(err)
    }
}

/// Checks `p` against what mihomo's `wireguard` proxy with `amnezia-wg-option` expresses.
pub fn preflight(p: &Profile) -> Result<(), PreflightError> {
    let Kind::Amneziawg { wg, awg } = &p.kind else {
        return Err(PreflightError::Unsupported(vec![Gap::NotAmneziawg]));
    };
    awg::validate(awg).map_err(PreflightError::Invalid)?;
    let mut gaps = Vec::new();
    for (present, layer) in [
        (p.tls.is_some(), "tls"),
        (p.transport.is_some(), "transport"),
        (p.mux.is_some(), "mux"),
        (p.native_xray.is_some(), "xray"),
    ] {
        if present {
            gaps.push(Gap::Layer(layer));
        }
    }
    if !p.dial.is_default() {
        gaps.push(Gap::Option("dial".into()));
    }
    gaps.extend(p.singbox_extra.keys().map(|k| Gap::Option(k.clone())));
    let v4 = wg
        .local_address
        .iter()
        .filter(|a| a.addr().is_ipv4())
        .count();
    let v6 = wg.local_address.len() - v4;
    if wg.local_address.is_empty() {
        gaps.push(Gap::NoAddress);
    } else if v4 > 1 || v6 > 1 {
        gaps.push(Gap::SecondAddress);
    }
    match wg.peers.first() {
        None => gaps.push(Gap::NoPeer),
        Some(first) if wg.peers.iter().any(|x| x.keepalive_s != first.keepalive_s) => {
            gaps.push(Gap::KeepalivePerPeer);
        }
        Some(_) => {}
    }
    if awg.keepalive_range.is_some_and(|r| r.is_range()) {
        gaps.push(Gap::KeepaliveRange);
    }
    if wg.peers.iter().any(|peer| peer.reserved.is_some()) {
        gaps.push(Gap::Reserved);
    }
    if gaps.is_empty() {
        Ok(())
    } else {
        Err(PreflightError::Unsupported(gaps))
    }
}
