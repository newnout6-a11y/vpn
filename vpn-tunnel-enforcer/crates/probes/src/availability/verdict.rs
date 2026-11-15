//! The verdict of a check from its two path reports (old `deriveVerdict`, with B-UA-3 / B-UA-4
//! fixed: an unmeasured side is "unknown", never "blocked"; 401 / 403 do not confirm access).
use serde::{Deserialize, Serialize};
use vpnte_base::Msg;

use super::report::PathReport;

/// What the check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AvailabilityVerdict {
    WorksBoth,
    WorksOnlyWithVpn,
    WorksOnlyWithoutVpn,
    BlockedEverywhere,
    /// The origin answers but refuses (401 / 403): availability not confirmed.
    AuthRequired,
    #[default]
    Unknown,
}

impl AvailabilityVerdict {
    /// Short label of the verdict.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            AvailabilityVerdict::WorksBoth => "probes.availability.verdict.worksBoth",
            AvailabilityVerdict::WorksOnlyWithVpn => "probes.availability.verdict.worksOnlyWithVpn",
            AvailabilityVerdict::WorksOnlyWithoutVpn => {
                "probes.availability.verdict.worksOnlyWithoutVpn"
            }
            AvailabilityVerdict::BlockedEverywhere => {
                "probes.availability.verdict.blockedEverywhere"
            }
            AvailabilityVerdict::AuthRequired => "probes.availability.verdict.authRequired",
            AvailabilityVerdict::Unknown => "probes.availability.verdict.unknown",
        })
    }
}

/// The advice shown with a verdict (`probes.availability.rec.*`), stored typed so the history
/// re-renders in the current language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Recommendation {
    /// Only the direct path was measured and it works.
    ReachableWithoutVpn,
    /// Only the direct path was measured and it refuses access (F-210).
    RefusedVpnNotMeasured,
    /// Only the direct path was measured and it failed.
    DirectFailedVpnNotMeasured,
    /// One side could not be measured (B-UA-3).
    PathNotMeasured,
    /// The site itself refuses the user's region; it opens through the VPN.
    GeoBlockedLocally,
    /// The site also refuses the VPN server's country.
    GeoBlockedVpnCountry,
    /// The site refuses access without the VPN (protected 2xx/3xx, direct 401 / 403).
    RefusedWithoutVpn,
    /// The site refuses the VPN exit (protected 401 / 403, direct 2xx/3xx).
    RefusedThroughVpn,
    /// The site refuses access on every measured path.
    AuthRequired,
    /// Both paths reach the site.
    ReachableBoth,
    /// The direct path fails in the network (DNS / TCP / TLS): the provider blocks it.
    ProviderBlocks,
    /// The direct path reaches no usable answer, the protected one does.
    OnlyWithVpn,
    /// Typical of Russian services: works only without the VPN.
    OnlyWithoutVpn,
    /// Neither path works.
    BlockedEverywhere,
    /// The check did not complete.
    #[default]
    Incomplete,
}

impl Recommendation {
    /// User text of the advice.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            Recommendation::ReachableWithoutVpn => "probes.availability.rec.reachableWithoutVpn",
            Recommendation::RefusedVpnNotMeasured => {
                "probes.availability.rec.refusedVpnNotMeasured"
            }
            Recommendation::DirectFailedVpnNotMeasured => {
                "probes.availability.rec.directFailedVpnNotMeasured"
            }
            Recommendation::PathNotMeasured => "probes.availability.rec.pathNotMeasured",
            Recommendation::GeoBlockedLocally => "probes.availability.rec.geoBlockedLocally",
            Recommendation::GeoBlockedVpnCountry => "probes.availability.rec.geoBlockedVpnCountry",
            Recommendation::RefusedWithoutVpn => "probes.availability.rec.refusedWithoutVpn",
            Recommendation::RefusedThroughVpn => "probes.availability.rec.refusedThroughVpn",
            Recommendation::AuthRequired => "probes.availability.rec.authRequired",
            Recommendation::ReachableBoth => "probes.availability.rec.reachableBoth",
            Recommendation::ProviderBlocks => "probes.availability.rec.providerBlocks",
            Recommendation::OnlyWithVpn => "probes.availability.rec.onlyWithVpn",
            Recommendation::OnlyWithoutVpn => "probes.availability.rec.onlyWithoutVpn",
            Recommendation::BlockedEverywhere => "probes.availability.rec.blockedEverywhere",
            Recommendation::Incomplete => "probes.availability.rec.incomplete",
        })
    }

    /// A plausible advice for a stored verdict whose old advice text is not kept (legacy import).
    pub fn for_verdict(verdict: AvailabilityVerdict) -> Recommendation {
        match verdict {
            AvailabilityVerdict::WorksBoth => Recommendation::ReachableBoth,
            AvailabilityVerdict::WorksOnlyWithVpn => Recommendation::OnlyWithVpn,
            AvailabilityVerdict::WorksOnlyWithoutVpn => Recommendation::OnlyWithoutVpn,
            AvailabilityVerdict::BlockedEverywhere => Recommendation::BlockedEverywhere,
            AvailabilityVerdict::AuthRequired => Recommendation::AuthRequired,
            AvailabilityVerdict::Unknown => Recommendation::Incomplete,
        }
    }
}

/// Verdict and advice from the protected ("с защитой") and the direct ("без VPN") reports.
/// `protected` is `None` when the tunnel was off (then `direct` is the native measurement).
pub fn derive_verdict(
    protected: Option<&PathReport>,
    direct: Option<&PathReport>,
) -> (AvailabilityVerdict, Recommendation) {
    use AvailabilityVerdict as V;
    use Recommendation as R;
    match (protected, direct) {
        (None, Some(d)) => match () {
            _ if !d.measured => (V::Unknown, R::Incomplete),
            _ if d.refused() => (V::AuthRequired, R::RefusedVpnNotMeasured),
            _ if d.available => (V::WorksBoth, R::ReachableWithoutVpn),
            _ => (V::Unknown, R::DirectFailedVpnNotMeasured),
        },
        (Some(p), Some(d)) => both(p, d),
        _ => (V::Unknown, R::Incomplete),
    }
}

fn both(p: &PathReport, d: &PathReport) -> (AvailabilityVerdict, Recommendation) {
    use AvailabilityVerdict as V;
    use Recommendation as R;
    if !p.measured || !d.measured {
        return (V::Unknown, R::PathNotMeasured);
    }
    if p.works() && d.geo_blocked {
        return (V::WorksOnlyWithVpn, R::GeoBlockedLocally);
    }
    if p.geo_blocked {
        let verdict = if d.available && !d.geo_blocked {
            V::WorksOnlyWithoutVpn
        } else {
            V::BlockedEverywhere
        };
        return (verdict, R::GeoBlockedVpnCountry);
    }
    match (p.works(), p.refused(), d.works(), d.refused()) {
        (true, _, true, _) => (V::WorksBoth, R::ReachableBoth),
        (true, _, _, true) => (V::WorksOnlyWithVpn, R::RefusedWithoutVpn),
        (_, true, true, _) => (V::WorksOnlyWithoutVpn, R::RefusedThroughVpn),
        (true, _, false, false) if d.failed_in_network() => {
            (V::WorksOnlyWithVpn, R::ProviderBlocks)
        }
        (true, _, false, false) => (V::WorksOnlyWithVpn, R::OnlyWithVpn),
        (false, false, true, _) => (V::WorksOnlyWithoutVpn, R::OnlyWithoutVpn),
        (_, true, _, _) | (_, _, _, true) => (V::AuthRequired, R::AuthRequired),
        _ => (V::BlockedEverywhere, R::BlockedEverywhere),
    }
}

#[cfg(test)]
mod tests {
    use super::super::report::{ErrorCode, HttpStage, PathSource, Stage};
    use super::*;
    use crate::availability::tests::ru;

    fn ok(status: u16) -> PathReport {
        PathReport {
            available: true,
            total_ms: Some(100),
            http: Some(HttpStage {
                status: Some(status),
                ms: Some(100),
                server: None,
            }),
            ..PathReport::new(PathSource::Native)
        }
    }

    fn down(stage: Stage, error: ErrorCode) -> PathReport {
        PathReport {
            error_stage: Some(stage),
            error: Some(error),
            ..PathReport::new(PathSource::Native)
        }
    }

    fn geo_blocked() -> PathReport {
        PathReport {
            available: false,
            geo_blocked: true,
            error_stage: Some(Stage::Http),
            ..ok(200)
        }
    }

    fn check(p: Option<&PathReport>, d: Option<&PathReport>) -> (AvailabilityVerdict, String) {
        let (verdict, rec) = derive_verdict(p, d);
        (verdict, ru(&rec.msg().key))
    }

    /// urlAvailabilityVerdict.test.ts (AT-07-003): geo blocks on either side.
    #[test]
    fn geo_blocks() {
        let (v, text) = check(Some(&ok(200)), Some(&geo_blocked()));
        assert_eq!(v, AvailabilityVerdict::WorksOnlyWithVpn);
        assert!(text.contains("регион"), "{text}");
        let (v, text) = check(Some(&geo_blocked()), Some(&ok(200)));
        assert_eq!(v, AvailabilityVerdict::WorksOnlyWithoutVpn);
        assert!(text.contains("сервер"), "{text}");
        let unavailable = down(Stage::Tcp, ErrorCode::TimedOut);
        let (v, _) = check(Some(&geo_blocked()), Some(&unavailable));
        assert_eq!(v, AvailabilityVerdict::BlockedEverywhere);
    }

    /// urlAvailabilityVerdict.test.ts: plain cases, F-210 and the 403 differential.
    #[test]
    fn plain_cases() {
        let (v, _) = check(Some(&ok(200)), Some(&ok(200)));
        assert_eq!(v, AvailabilityVerdict::WorksBoth);
        for status in [401, 403] {
            // F-210, superseded by B-UA-4: a refusal without a VPN measurement is not "works".
            let (v, text) = check(None, Some(&ok(status)));
            assert_eq!(v, AvailabilityVerdict::AuthRequired);
            assert!(text.contains("VPN"), "{text}");
        }
        let (v, _) = check(Some(&ok(200)), Some(&ok(403)));
        assert_eq!(v, AvailabilityVerdict::WorksOnlyWithVpn);
        let (v, _) = check(None, Some(&ok(200)));
        assert_eq!(v, AvailabilityVerdict::WorksBoth);
        let (v, _) = check(None, Some(&down(Stage::Dns, ErrorCode::NameNotFound)));
        assert_eq!(v, AvailabilityVerdict::Unknown);
    }

    /// B-UA-3 / B-UA-4 (new vectors): unmeasured side, 404 and the provider-blame rule.
    #[test]
    fn honesty_rules() {
        let unmeasured = PathReport::unmeasured(PathSource::DirectInbound, ErrorCode::ProxyFailed);
        let (v, text) = check(Some(&ok(200)), Some(&unmeasured));
        assert_eq!(v, AvailabilityVerdict::Unknown);
        assert!(text.contains("не измерен"), "{text}");
        let not_found = ok(404);
        let (v, _) = check(Some(&ok(200)), Some(&not_found));
        assert_eq!(v, AvailabilityVerdict::WorksBoth);
        assert_eq!(
            not_found.http_class(),
            Some(super::super::report::HttpClass::NotFound)
        );
        let reset = PathReport {
            source: PathSource::DirectInbound,
            ..down(Stage::Http, ErrorCode::ConnReset)
        };
        assert_eq!(
            derive_verdict(Some(&ok(200)), Some(&reset)),
            (
                AvailabilityVerdict::WorksOnlyWithVpn,
                Recommendation::ProviderBlocks
            )
        );
        let server_error = PathReport {
            available: false,
            error_stage: Some(Stage::Http),
            ..ok(502)
        };
        assert_eq!(
            derive_verdict(Some(&ok(200)), Some(&server_error)),
            (
                AvailabilityVerdict::WorksOnlyWithVpn,
                Recommendation::OnlyWithVpn
            )
        );
        let (v, _) = check(Some(&ok(403)), Some(&ok(200)));
        assert_eq!(v, AvailabilityVerdict::WorksOnlyWithoutVpn);
        let (v, _) = check(Some(&ok(403)), Some(&ok(401)));
        assert_eq!(v, AvailabilityVerdict::AuthRequired);
        let (v, _) = check(
            Some(&down(Stage::Tls, ErrorCode::ConnReset)),
            Some(&ok(200)),
        );
        assert_eq!(v, AvailabilityVerdict::WorksOnlyWithoutVpn);
        let (v, _) = check(
            Some(&down(Stage::Tls, ErrorCode::ConnReset)),
            Some(&server_error),
        );
        assert_eq!(v, AvailabilityVerdict::BlockedEverywhere);
        assert_eq!(derive_verdict(None, None).0, AvailabilityVerdict::Unknown);
    }
}
