//! Leak checks.
//!
//! - [`self_test`]: "does the kill switch ACTUALLY block?" — reaches for the Internet from every
//!   physical adapter address the way an ordinary leaking app would (a `curl.exe` child bound
//!   to the address), plus a default-route read and an IP-service cross-check.
//! - [`watch`]: background scheduling of the self-test (periodic, event-triggered, suppressed
//!   around transitions, gated on "protection expected").
//! - [`check`]: the on-demand leak check card (public IPv4 / IPv6 against the IP monitor
//!   evidence, foreign tunnels, DNS, engine log health, unexplained direct-out traffic) and its
//!   summary; missing evidence is "not checked", never "no leaks found".
//!
//! Field case behind it all: with the kill switch on and the TUN up, a browser still showed
//! the user's ISP address while the app's own read (through the TUN) showed the VPN exit.
pub mod check;
pub mod probe;
pub mod self_test;
pub mod watch;

pub use check::{
    CheckInput, CheckItem, CheckReport, CheckStatus, ConnRecord, DirectAudit, Mode, audit_direct,
    leak_check, summarize,
};
pub use probe::{CurlOutcome, Reach, Why};
pub use self_test::{
    AddrProbe, Disagreement, LeakEnv, PhysicalAddr, SelfTestReport, SelfTestResult,
    SelfTestVerdict, SelfTester, SystemEnv, report, run_self_test, verdict,
};
pub use watch::{LeakEvent, LeakWatch, WatchConfig};
