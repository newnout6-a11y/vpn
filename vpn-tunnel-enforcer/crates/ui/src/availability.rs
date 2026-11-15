//! Availability page («Доступность»): "is this site blocked for me, or does it need the VPN?".
//! A URL is checked through the tunnel and directly side by side (stages, verdict,
//! recommendation, saved history), and a routing self-test compares the egress seen through
//! the VPN with the real one (ui-pages §3.10, monitoring §3.6 / §3.9).
//!
//! The page talks to the backend only through [`AvailabilityApi`], handed down as
//! `Rc<dyn AvailabilityApi>` in context; [`demo::DemoAvailability`] is the fake used by
//! `demo_tools` and the tests.
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;

mod ctl;
pub mod demo;
mod format;
mod model;
mod page;

pub use format::{
    HISTORY_ROWS, Mark, StageRow, format_age, path_status, routing_look, stage_rows, verdict_look,
};
pub(crate) use format::{text, text_with};
pub use model::{
    AvailabilityState, DnsStage, GeoInfo, HttpStage, PathReport, PathSource, RoutingReport,
    RoutingVerdict, TcpStage, TlsStage, UrlCheck, UrlVerdict,
};
pub use page::AvailabilityPage;

/// What the Availability page needs from the backend (implemented by the app over the probes).
#[async_trait::async_trait(?Send)]
pub trait AvailabilityApi: 'static {
    /// Tunnel state and the saved history, pushed on every change.
    fn state(&self) -> watch::Receiver<AvailabilityState>;
    /// Checks one link through the tunnel and directly; the backend normalises the input (adds
    /// `https://`) and saves the result to the history before returning. An unusable link is
    /// `ErrorKind::Validation`; cancelling `cancel` ends the check with `ErrorKind::Cancelled`.
    async fn check_url(&self, input: String, cancel: CancellationToken) -> AppResult<UrlCheck>;
    /// The routing self-test (VPN egress versus the real one, plus the Smart RU echo).
    async fn routing_test(&self, cancel: CancellationToken) -> AppResult<RoutingReport>;
    /// Forgets the saved checks.
    async fn clear_history(&self) -> AppResult<()>;
}

#[cfg(test)]
mod tests {
    //! i18n gate of the package (ui-pages §7.12): every key the code names resolves (the fragment
    //! rules are checked crate-wide).
    use super::{PathReport, RoutingVerdict, UrlVerdict, path_status, routing_look, verdict_look};
    use crate::speedtest::{Egress, SpeedPhase, egress_look, phase_key};

    const SOURCES: [&str; 11] = [
        include_str!("availability.rs"),
        include_str!("availability/ctl.rs"),
        include_str!("availability/demo.rs"),
        include_str!("availability/format.rs"),
        include_str!("availability/page.rs"),
        include_str!("speedtest.rs"),
        include_str!("speedtest/ctl.rs"),
        include_str!("speedtest/demo.rs"),
        include_str!("speedtest/format.rs"),
        include_str!("speedtest/page.rs"),
        include_str!("bin/demo_tools.rs"),
    ];

    /// Every quoted key in the package's sources and every key reached through an enum resolves
    /// in both languages (the fragments plus the old app's strings the pages reuse).
    #[test]
    fn every_key_the_code_names_resolves() {
        let prefixes = [
            "ui.availability.",
            "ui.speedTest.",
            "ui.tools.",
            "speedTest.",
            "sidebar.",
            "common.",
        ];
        let mut keys: Vec<String> = Vec::new();
        for source in SOURCES {
            for (i, chunk) in source.split('"').enumerate() {
                let plain = chunk.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
                    && !chunk.ends_with('.');
                if i % 2 == 1 && plain && prefixes.iter().any(|p| chunk.starts_with(p)) {
                    keys.push(chunk.to_owned());
                }
            }
        }
        keys.extend(
            UrlVerdict::ALL
                .iter()
                .map(|v| verdict_look(*v).0.to_owned()),
        );
        keys.extend(
            RoutingVerdict::ALL
                .iter()
                .map(|v| routing_look(*v).0.to_owned()),
        );
        for (available, geo_blocked, measured) in [
            (true, false, true),
            (false, true, true),
            (false, false, false),
            (false, false, true),
        ] {
            let path = PathReport {
                available,
                geo_blocked,
                measured,
                ..PathReport::default()
            };
            keys.push(path_status(&path).0.to_owned());
        }
        for phase in [
            SpeedPhase::Latency,
            SpeedPhase::Download,
            SpeedPhase::Upload,
            SpeedPhase::Complete,
        ] {
            keys.push(phase_key(phase).to_owned());
        }
        let ip = std::net::IpAddr::from([198, 51, 100, 1]);
        for egress in [
            Egress::Changed { seen: None },
            Egress::Direct { seen: ip },
            Egress::NotChecked,
        ] {
            let (sentence, mark, _) = egress_look(egress).expect("a look");
            keys.extend([sentence.to_owned(), mark.to_owned()]);
        }
        assert!(
            keys.len() > 100,
            "the scanner found only {} keys",
            keys.len()
        );
        crate::test_locales::assert_resolve(
            &crate::test_locales::catalogs(&[]),
            keys.iter().map(String::as_str),
        );
    }
}
