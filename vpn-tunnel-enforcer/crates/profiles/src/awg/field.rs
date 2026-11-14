//! Names of the AmneziaWG parameters and the refusal that lists the invalid ones.
use vpnte_base::{AppError, Msg};

/// One AmneziaWG parameter, in the order the refusal lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AwgField {
    Jc,
    Jmin,
    Jmax,
    S1,
    S2,
    S3,
    S4,
    H1,
    H2,
    H3,
    H4,
    I1,
    I2,
    I3,
    I4,
    I5,
    J1,
    J2,
    J3,
    Itime,
    HeaderProtectionKey,
    ContentPaddingAddition,
    RekeyAfterTime,
    RekeyTimeout,
    RejectAfterTime,
    KeepaliveTimeout,
    MaxHandshakeAttempts,
    PersistentKeepalive,
    RandomTrailers,
    DisableCookies,
    /// mihomo's `version` (3 selects the 3.x implementation).
    Version,
}

use AwgField::*;

impl AwgField {
    /// `S1`-`S4` in index order (`Awg::s`).
    pub const S: [AwgField; 4] = [S1, S2, S3, S4];
    /// `H1`-`H4` (`Awg::h`).
    pub const H: [AwgField; 4] = [H1, H2, H3, H4];
    /// `I1`-`I5` (`Awg::i`).
    pub const I: [AwgField; 5] = [I1, I2, I3, I4, I5];
    /// `J1`-`J3` (`Awg::j`).
    pub const J: [AwgField; 3] = [J1, J2, J3];
    /// The 3.x timers (`Awg::timers`).
    pub const TIMERS: [AwgField; 5] = [
        RekeyAfterTime,
        RekeyTimeout,
        RejectAfterTime,
        KeepaliveTimeout,
        MaxHandshakeAttempts,
    ];
    const ALL: [AwgField; 31] = [
        Jc,
        Jmin,
        Jmax,
        S1,
        S2,
        S3,
        S4,
        H1,
        H2,
        H3,
        H4,
        I1,
        I2,
        I3,
        I4,
        I5,
        J1,
        J2,
        J3,
        Itime,
        HeaderProtectionKey,
        ContentPaddingAddition,
        RekeyAfterTime,
        RekeyTimeout,
        RejectAfterTime,
        KeepaliveTimeout,
        MaxHandshakeAttempts,
        PersistentKeepalive,
        RandomTrailers,
        DisableCookies,
        Version,
    ];

    /// The name in an AmneziaWG `.conf` (`HeaderProtectionKey`), also shown to the user.
    pub fn conf_name(self) -> &'static str {
        match self {
            Jc => "Jc",
            Jmin => "Jmin",
            Jmax => "Jmax",
            S1 => "S1",
            S2 => "S2",
            S3 => "S3",
            S4 => "S4",
            H1 => "H1",
            H2 => "H2",
            H3 => "H3",
            H4 => "H4",
            I1 => "I1",
            I2 => "I2",
            I3 => "I3",
            I4 => "I4",
            I5 => "I5",
            J1 => "J1",
            J2 => "J2",
            J3 => "J3",
            Itime => "Itime",
            HeaderProtectionKey => "HeaderProtectionKey",
            ContentPaddingAddition => "ContentPaddingAddition",
            RekeyAfterTime => "RekeyAfterTime",
            RekeyTimeout => "RekeyTimeout",
            RejectAfterTime => "RejectAfterTime",
            KeepaliveTimeout => "KeepaliveTimeout",
            MaxHandshakeAttempts => "MaxHandshakeAttempts",
            PersistentKeepalive => "PersistentKeepalive",
            RandomTrailers => "RandomTrailers",
            DisableCookies => "DisableCookies",
            Version => "Version",
        }
    }

    /// The key in mihomo's `amnezia-wg-option` (`header-protection-key`).
    pub fn yaml_name(self) -> String {
        let mut out = String::new();
        let mut lower_before = false;
        for c in self.conf_name().chars() {
            if c.is_ascii_uppercase() && lower_before {
                out.push('-');
            }
            lower_before = c.is_ascii_lowercase();
            out.push(c.to_ascii_lowercase());
        }
        out
    }

    /// The parameter a `.conf` key, a mihomo key or a link parameter names, in any case and
    /// with or without `-` / `_` (`HeaderProtectionKey`, `header-protection-key`,
    /// `header_protection_key`). `PersistentKeepalive` and `Version` belong to WireGuard and
    /// mihomo: their readers handle them.
    pub fn from_key(key: &str) -> Option<AwgField> {
        let wanted: String = key
            .chars()
            .filter(|c| !matches!(c, '-' | '_'))
            .map(|c| c.to_ascii_lowercase())
            .collect();
        Self::ALL
            .into_iter()
            .filter(|f| !matches!(f, PersistentKeepalive | Version))
            .find(|f| f.conf_name().eq_ignore_ascii_case(&wanted))
    }
}

/// AmneziaWG parameters that cannot work, every one named: refused before import and before
/// any start (AT-12-003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwgInvalid {
    /// In [`AwgField`] order, each once.
    pub fields: Vec<AwgField>,
}

impl AwgInvalid {
    /// `None` when nothing is invalid.
    pub(crate) fn of(mut fields: Vec<AwgField>) -> Option<Self> {
        fields.sort_unstable();
        fields.dedup();
        (!fields.is_empty()).then_some(Self { fields })
    }

    /// The field names as shown to the user: `Jmin, Jmax, H2`.
    pub fn names(&self) -> String {
        let names: Vec<_> = self.fields.iter().map(|f| f.conf_name()).collect();
        names.join(", ")
    }

    /// `profiles.awg.invalid` with the field names.
    pub fn msg(&self) -> Msg {
        Msg::new("profiles.awg.invalid").arg("fields", self.names())
    }
}

impl From<AwgInvalid> for AppError {
    fn from(invalid: AwgInvalid) -> Self {
        AppError::validation(invalid.msg())
    }
}
