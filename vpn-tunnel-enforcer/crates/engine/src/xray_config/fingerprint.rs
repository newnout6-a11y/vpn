//! uTLS fingerprint of a TCP TLS / REALITY outbound and the warnings about it (ru-2026-plan §2).
use vpnte_base::msg::Msg;
use vpnte_base::types::ClientDevice;
use vpnte_profiles::device::utls_fingerprint;
use vpnte_profiles::model::Tls;

/// uTLS presets the bundled Xray accepts (case-insensitive); other provider names fall back to
/// the default instead of failing the build with `unknown "fingerprint"`.
const XRAY_FINGERPRINTS: [&str; 12] = [
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
    "randomizednoalpn",
    "unsafe",
];
/// The ClientHellos Xray REALITY servers >= 26.9.8 accept: the presets with an X25519MLKEM768
/// key share. edge / ios / qq / random(ized) are refused there.
const ACCEPTED: [&str; 3] = ["chrome", "firefox", "safari"];
/// Presets that fail against servers of every kind in RU field reports (November 2026).
const BROKEN: [&str; 2] = ["android", "360"];

/// The provider's fingerprint when Xray knows it (REALITY: not `unsafe`, it needs uTLS), else
/// the device default when servers accept it, else `chrome`. Android / iOS device defaults are
/// replaced: their presets are refused or broken.
pub(super) fn fingerprint(tls: &Tls, device: ClientDevice) -> &'static str {
    if let Some(known) = provider(tls).and_then(|fp| known(fp, tls.reality.is_some())) {
        return known;
    }
    let default = utls_fingerprint(device);
    if ACCEPTED.contains(&default) {
        default
    } else {
        "chrome"
    }
}

/// What the user should know about the provider's fingerprint: unknown to Xray (replaced),
/// refused by REALITY servers, or broken everywhere. The choice itself is kept.
pub(super) fn warning(tls: &Tls) -> Option<Msg> {
    let raw = provider(tls)?;
    let reality = tls.reality.is_some();
    let key = match known(raw, reality) {
        None => "engine.xray.warn.fingerprintUnknown",
        Some(fp) if reality && !ACCEPTED.contains(&fp) => "engine.xray.warn.fingerprintRejected",
        Some(fp) if BROKEN.contains(&fp) => "engine.xray.warn.fingerprintBroken",
        Some(_) => return None,
    };
    Some(Msg::new(key).arg("fingerprint", raw))
}

fn provider(tls: &Tls) -> Option<&str> {
    tls.fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty())
}

fn known(raw: &str, reality: bool) -> Option<&'static str> {
    XRAY_FINGERPRINTS
        .iter()
        .copied()
        .find(|k| k.eq_ignore_ascii_case(raw) && !(reality && *k == "unsafe"))
}
