//! ECH for Xray: a static config becomes `tlsSettings.echConfigList`.
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use vpnte_profiles::model::Ech;

use super::XrayConfigError;

/// The ECHConfigList of `ech` as standard padded base64: Xray decodes `echConfigList` with Go's
/// `StdEncoding` when it dials (`run -test` does not look at it), while share links carry URL-safe
/// unpadded text and sing-box JSON a PEM block. `None` without config lines (a DNS lookup, which
/// selection keeps on sing-box).
pub(super) fn config_list(ech: &Ech) -> Result<Option<String>, XrayConfigError> {
    let body: String = ech
        .config_lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.starts_with("-----"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    if body.is_empty() {
        return Ok(None);
    }
    let bytes = STANDARD_NO_PAD
        .decode(body)
        .map_err(|_| XrayConfigError::Invalid("ech"))?;
    // An ECHConfigList is a u16 length prefix and exactly that many bytes of configs.
    let declared = match bytes.as_slice() {
        [hi, lo, ..] => usize::from(u16::from_be_bytes([*hi, *lo])),
        _ => return Err(XrayConfigError::Invalid("ech")),
    };
    if declared == 0 || declared + 2 != bytes.len() {
        return Err(XrayConfigError::Invalid("ech"));
    }
    Ok(Some(STANDARD.encode(bytes)))
}
