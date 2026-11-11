//! One `curl.exe` probe: its arguments, and what its outcome proves (the launcher and the
//! reason for curl are in [`crate::curl`]).
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;

pub use crate::curl::CurlOutcome;
pub(crate) use crate::curl::run_curl;
use crate::public_ip::Family;

/// Grace on top of curl's own `--max-time` before the process is killed.
const PROCESS_GRACE: Duration = Duration::from_secs(2);

/// Why a probe proved nothing either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Why {
    /// `curl.exe` missing or not startable.
    Launch,
    /// Killed after curl's own deadline plus grace.
    ProcessTimeout,
    /// curl 45: the local address could not be bound (gone, or mid-change).
    Bind,
    /// curl 6: name resolution failed.
    Dns,
    /// curl 35 / 60: TLS failed.
    Tls,
    /// Finished but printed no address of the family.
    BadAnswer,
    /// Any other curl failure.
    Curl,
}

impl Why {
    /// User-facing reason.
    pub fn label(self) -> Msg {
        Msg::new(match self {
            Why::Launch => "probes.leak.why.launch",
            Why::ProcessTimeout => "probes.leak.why.processTimeout",
            Why::Bind => "probes.leak.why.bind",
            Why::Dns => "probes.leak.why.dns",
            Why::Tls => "probes.leak.why.tls",
            Why::BadAnswer => "probes.leak.why.badAnswer",
            Why::Curl => "probes.leak.why.curl",
        })
    }
}

/// What a probe from one local address proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Reach {
    /// An answer came back: this address reaches the Internet outside the tunnel.
    #[serde(rename_all = "camelCase")]
    Reached { ip: IpAddr },
    /// curl measured no connection: 7 (connect failed) or 28 (timed out). Neither proves a
    /// firewall rule, but a dropped SYN to a public anycast address is the usual signature of
    /// one; treating 28 as unknown would make "no leak" unreachable on many networks (B-LT-6).
    #[serde(rename_all = "camelCase")]
    NotReached { curl_exit: i32 },
    /// DNS / TLS / launch / bind / garbage: nothing established about egress.
    #[serde(rename_all = "camelCase")]
    Inconclusive { curl_exit: Option<i32>, why: Why },
}

/// The address a probe printed: the `ip=` line of a Cloudflare trace, else the whole trimmed
/// output; it must be an address of `family`.
pub fn parse_probe_ip(stdout: &str, family: Family) -> Option<IpAddr> {
    let text = stdout.trim();
    let candidate = text
        .lines()
        .find_map(|line| line.strip_prefix("ip="))
        .unwrap_or(text)
        .trim();
    let ip: IpAddr = candidate.parse().ok()?;
    let right_family = matches!(
        (ip, family),
        (IpAddr::V4(_), Family::V4) | (IpAddr::V6(_), Family::V6)
    );
    right_family.then_some(ip)
}

/// Evidence of one run. Positive evidence wins: an address printed before a late failure
/// (exit 28 after the answer) still means the Internet was reached.
pub fn classify(outcome: &CurlOutcome, family: Family) -> Reach {
    if let Some(ip) = parse_probe_ip(&outcome.stdout, family) {
        return Reach::Reached { ip };
    }
    let why = match outcome.exit {
        Some(code @ (7 | 28)) => return Reach::NotReached { curl_exit: code },
        _ if !outcome.launched => Why::Launch,
        None => Why::ProcessTimeout,
        Some(45) => Why::Bind,
        Some(6) => Why::Dns,
        Some(35 | 60) => Why::Tls,
        Some(0) => Why::BadAnswer,
        Some(_) => Why::Curl,
    };
    Reach::Inconclusive {
        curl_exit: outcome.exit,
        why,
    }
}

/// Arguments of one probe: no curlrc (`-q` must come first), no proxy, no URL globbing (IPv6
/// literals), silent with errors, one deadline for connect and transfer.
pub(crate) fn curl_args(
    family: Family,
    bind: Option<IpAddr>,
    max_time_s: u64,
    url: &str,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-q".into(),
        match family {
            Family::V4 => "-4".into(),
            Family::V6 => "-6".into(),
        },
    ];
    if let Some(ip) = bind {
        args.extend(["--interface".into(), ip.to_string()]);
    }
    let secs = max_time_s.to_string();
    args.extend(
        ["--noproxy", "*", "--globoff", "-sS", "--max-time"]
            .into_iter()
            .map(String::from),
    );
    args.push(secs.clone());
    args.extend(["--connect-timeout".into(), secs, url.into()]);
    args
}

/// Process deadline for a probe with curl's `--max-time` of `max_time_s`.
pub(crate) fn process_timeout(max_time_s: u64) -> Duration {
    Duration::from_secs(max_time_s) + PROCESS_GRACE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curl::{STDERR_TAIL, curl_path};

    fn out(exit: Option<i32>, stdout: &str) -> CurlOutcome {
        CurlOutcome {
            exit,
            stdout: stdout.into(),
            stderr: String::new(),
            launched: true,
        }
    }

    /// AT-00-008: adapter evidence — address printed → reached; 7 / 28 → not reached; anything
    /// else (no code, -1, 0 without address, 6, 35, 60, 45, launch failure) → inconclusive.
    #[test]
    fn outcomes_classify() {
        let reached = classify(&out(Some(0), "fl=1\nip=5.6.7.8\nts=2"), Family::V4);
        assert_eq!(
            reached,
            Reach::Reached {
                ip: "5.6.7.8".parse().unwrap()
            }
        );
        assert_eq!(
            classify(&out(Some(28), "1.2.3.4"), Family::V4),
            Reach::Reached {
                ip: "1.2.3.4".parse().unwrap()
            }
        );
        for code in [7, 28] {
            assert_eq!(
                classify(&out(Some(code), ""), Family::V4),
                Reach::NotReached { curl_exit: code }
            );
        }
        let why = |o: &CurlOutcome| match classify(o, Family::V4) {
            Reach::Inconclusive { why, .. } => Some(why),
            _ => None,
        };
        assert_eq!(why(&out(None, "")), Some(Why::ProcessTimeout));
        assert_eq!(why(&out(Some(-1), "")), Some(Why::Curl));
        assert_eq!(
            why(&out(Some(0), "invalid IP response")),
            Some(Why::BadAnswer)
        );
        assert_eq!(why(&out(Some(6), "")), Some(Why::Dns));
        assert_eq!(why(&out(Some(35), "")), Some(Why::Tls));
        assert_eq!(why(&out(Some(60), "")), Some(Why::Tls));
        assert_eq!(why(&out(Some(45), "")), Some(Why::Bind));
        assert_eq!(why(&CurlOutcome::not_launched()), Some(Why::Launch));
        assert_eq!(why(&out(Some(0), "999.1.2.3")), Some(Why::BadAnswer));
        assert_eq!(
            why(&out(Some(0), "2001:db8::1")),
            Some(Why::BadAnswer),
            "IPv6 answer to an IPv4 probe"
        );
        let v6 = classify(&out(Some(0), "ip=2606:4700::1\n"), Family::V6);
        assert_eq!(
            v6,
            Reach::Reached {
                ip: "2606:4700::1".parse().unwrap()
            }
        );
    }

    #[test]
    fn stderr_tail_keeps_the_last_200_chars() {
        let mut o = out(Some(7), "");
        assert_eq!(o.stderr_tail(), None);
        o.stderr = format!("{}{}", "a".repeat(300), "Z\r\n");
        let tail = o.stderr_tail().unwrap();
        assert_eq!(tail.chars().count(), STDERR_TAIL);
        assert!(tail.ends_with('Z'));
    }

    #[test]
    fn arguments_and_binary() {
        let args = curl_args(
            Family::V6,
            Some("2001:db8::5".parse().unwrap()),
            4,
            "https://[2606:4700:4700::1111]/cdn-cgi/trace",
        );
        assert_eq!(args[0], "-q", "curlrc must not be read");
        assert_eq!(
            args[1..],
            [
                "-6",
                "--interface",
                "2001:db8::5",
                "--noproxy",
                "*",
                "--globoff",
                "-sS",
                "--max-time",
                "4",
                "--connect-timeout",
                "4",
                "https://[2606:4700:4700::1111]/cdn-cgi/trace"
            ]
        );
        assert_eq!(process_timeout(4), Duration::from_secs(6));
        let exe = curl_path().unwrap();
        assert!(exe.is_absolute() && exe.ends_with("curl.exe"));
    }

    /// The real binary on this machine answers a local-only invocation (`--version`).
    #[tokio::test]
    async fn system_curl_runs_hidden() {
        let outcome = run_curl(
            vec!["-q".into(), "--version".into()],
            Duration::from_secs(10),
        )
        .await;
        assert!(outcome.launched);
        assert_eq!(outcome.exit, Some(0));
        assert!(outcome.stdout.starts_with("curl "));
    }
}
