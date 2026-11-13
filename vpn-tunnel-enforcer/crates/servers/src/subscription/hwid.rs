//! What a panel says about the device ID when it serves no servers: Remnawave's open HWID scheme
//! (response headers since panel v2.7.5; Happ, v2RayTun, Koala Clash and others follow it) and the
//! 403 "Device fingerprint required" answer of panels that gate the same way. The reason becomes
//! a typed outcome, so the page can say it in one line and offer the HWID switch.
use crate::model::FetchOutcome;

/// Body prefix of a 403 that is searched for the fingerprint sentence.
pub(super) const BODY_PREFIX: usize = 4 * 1024;

/// The refusal reason of an answer that gave no servers: `status` with its headers (lower-case
/// names, as `http::get` reads them), for a 403 the start of its body, and whether the request
/// carried the HWID. Remnawave sends `x-hwid-active` with every answer of a device-limited panel,
/// so a 404 that has only it is about the device only when no HWID was sent (with one, the
/// subscription itself is gone).
pub(super) fn refusal(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    sent_hwid: bool,
) -> Option<FetchOutcome> {
    let set = |name: &str| {
        headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case(name)
                && (v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
        })
    };
    if set("x-hwid-max-devices-reached") {
        return Some(FetchOutcome::DeviceLimit);
    }
    if set("x-hwid-not-supported") || (status == 404 && !sent_hwid && set("x-hwid-active")) {
        return Some(FetchOutcome::HwidRequired);
    }
    // `x-hwid-limit` is the same fact for v2RayTun's sake, but Remnawave sets it on every refusal
    // of its HWID check, "no HWID sent" included (13.11.2026: the owner's answer read as a full
    // device limit): a device limit only when nothing above named another reason.
    if set("x-hwid-limit") {
        return Some(FetchOutcome::DeviceLimit);
    }
    let head = String::from_utf8_lossy(&body[..body.len().min(BODY_PREFIX)]).to_ascii_lowercase();
    (status == 403 && head.contains("device fingerprint required"))
        .then_some(FetchOutcome::HwidRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// Recorded Remnawave answers (panel 2.7.5+) and the 403 of fingerprint-gated panels.
    #[test]
    fn panel_answers_name_the_reason() {
        let (none, off, on) = (headers(&[]), false, true);
        let not_sent = headers(&[("x-hwid-active", "true"), ("x-hwid-not-supported", "true")]);
        assert_eq!(
            refusal(404, &not_sent, b"", off),
            Some(FetchOutcome::HwidRequired)
        );
        let active = headers(&[("x-hwid-active", "true")]);
        assert_eq!(
            refusal(404, &active, b"", off),
            Some(FetchOutcome::HwidRequired)
        );
        // With the HWID sent, a 404 of an HWID panel is the subscription being gone.
        assert_eq!(refusal(404, &active, b"", on), None);
        // Active alone says nothing about another status (an expired plan on an HWID panel).
        assert_eq!(refusal(200, &active, b"", off), None);
        assert_eq!(refusal(410, &active, b"", off), None);
        let full = headers(&[
            ("x-hwid-active", "true"),
            ("x-hwid-max-devices-reached", "true"),
            ("x-hwid-limit", "true"),
        ]);
        assert_eq!(
            refusal(404, &full, b"", on),
            Some(FetchOutcome::DeviceLimit)
        );
        let v2raytun = headers(&[("X-HWID-Limit", "1")]);
        assert_eq!(
            refusal(404, &v2raytun, b"", on),
            Some(FetchOutcome::DeviceLimit)
        );
        let json = br#"{"message":"Device fingerprint required","statusCode":403}"#;
        assert_eq!(
            refusal(403, &none, json, off),
            Some(FetchOutcome::HwidRequired)
        );
        assert_eq!(
            refusal(403, &none, b"DEVICE FINGERPRINT REQUIRED", off),
            Some(FetchOutcome::HwidRequired)
        );
        // A CDN's 403, a plain 404 and switched-off headers are not about the device.
        assert_eq!(refusal(403, &none, b"<html>Forbidden</html>", off), None);
        assert_eq!(refusal(404, &none, b"Not Found", off), None);
        let no = headers(&[("x-hwid-not-supported", "false"), ("x-hwid-limit", "0")]);
        assert_eq!(refusal(404, &no, b"", off), None);
        // The sentence counts only within the prefix and only on a 403.
        let mut late = vec![b' '; BODY_PREFIX];
        late.extend_from_slice(b"device fingerprint required");
        assert_eq!(refusal(403, &none, &late, off), None);
        assert_eq!(refusal(401, &none, json, off), None);
    }

    /// p-live-fix: Remnawave (main, 14.11.2026) answers a request without the HWID with 200, its
    /// placeholders and `x-hwid-limit` next to `x-hwid-not-supported`: the HWID is what it wants.
    #[test]
    fn a_missing_hwid_is_not_a_device_limit() {
        let not_sent = headers(&[
            ("x-hwid-active", "true"),
            ("x-hwid-not-supported", "true"),
            ("x-hwid-limit", "true"),
        ]);
        for status in [200, 404] {
            assert_eq!(
                refusal(status, &not_sent, b"", false),
                Some(FetchOutcome::HwidRequired)
            );
        }
        let full = headers(&[
            ("x-hwid-limit", "true"),
            ("x-hwid-max-devices-reached", "true"),
        ]);
        assert_eq!(
            refusal(200, &full, b"", true),
            Some(FetchOutcome::DeviceLimit)
        );
    }
}
