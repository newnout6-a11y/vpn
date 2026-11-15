//! The engines' routine per-connection lines (owner logs O-4, 15.11.2026): sing-box and Xray
//! name every connection's destination and DNS answer at info, the level both must keep (the
//! sing-box ready line and Xray's dial and handshake failures are info lines the start and the
//! fault classification read from the pipe). Their log files leave these lines out: on disk they
//! were a second browsing history of every user (10 MB in 4 h) and helped no diagnosis.

/// Words of a line that reports something going wrong: such a line stays in the file.
const TROUBLE: [&str; 9] = [
    "fail",
    "error",
    "timeout",
    "timed out",
    "refused",
    "reset",
    "unreachable",
    "denied",
    "reject",
];

/// An info line about one connection or one DNS answer that reports no failure: sing-box
/// `INFO [<id> <ms>] …` and `INFO dns: …`, Xray `[Info] [<id>] …`. Start-up and state lines carry
/// no connection id and stay, as does every warning and error.
pub(crate) fn is_routine_flow(line: &str) -> bool {
    let rest = if let Some(at) = line.find(" INFO ") {
        &line[at + " INFO ".len()..]
    } else if let Some(at) = line.find("[Info] ") {
        &line[at + "[Info] ".len()..]
    } else {
        return false;
    };
    let per_connection = connection_id(rest) || rest.starts_with("dns: ");
    per_connection && !trouble(rest)
}

/// `[<digits>` opens the line's rest: the engine's connection context.
fn connection_id(rest: &str) -> bool {
    rest.strip_prefix('[')
        .is_some_and(|id| id.starts_with(|c: char| c.is_ascii_digit()))
}

fn trouble(rest: &str) -> bool {
    let lower = rest.to_ascii_lowercase();
    TROUBLE.iter().any(|word| lower.contains(word))
}

#[cfg(test)]
mod tests {
    use super::is_routine_flow;

    /// O-4: the line kinds of the owner's engine logs (destinations replaced by fakes).
    #[test]
    fn routine_connection_lines_are_told_apart_from_the_rest() {
        let routine = [
            "+0300 2026-11-14 21:22:50 INFO [3360712370 0ms] inbound/tun[tun-in]: inbound connection to 192.0.2.7:443",
            "+0300 2026-11-14 21:22:50 INFO [3360712370 2ms] outbound/socks[vpnte-upstream-a]: outbound connection to example.com:443",
            "+0300 2026-11-14 21:22:50 INFO [1 0ms] router: found process path: C:\\Windows\\System32\\svchost.exe",
            "+0300 2026-11-14 21:22:50 INFO [2 0ms] dns: exchanged A example.com. 300 IN A 192.0.2.7",
            "+0300 2026-11-14 21:22:50 INFO dns: refreshed A example.com. 300 IN A 192.0.2.7",
            "2026/11/14 21:22:50.123456 [Info] [1234567] proxy/socks: TCP Connect request to tcp:example.com:443",
            "2026/11/14 21:22:50.123456 [Info] [1234567] app/dispatcher: sniffed domain: example.com",
            "2026/11/14 21:22:50.123456 [Info] [1234567] proxy/vless/outbound: tunneling request to tcp:example.com:443 via 192.0.2.9:443",
        ];
        for line in routine {
            assert!(is_routine_flow(line), "{line}");
        }
        let kept = [
            "+0300 2026-11-14 21:22:47 INFO sing-box started (0.40s)",
            "+0300 2026-11-14 21:22:47 INFO network: updated default interface Ethernet, index 12",
            "+0300 2026-11-14 21:22:47 INFO inbound/tun[tun-in]: started at tun0",
            "+0300 2026-11-14 21:30:01 ERROR [5 5s] connection: open connection to 192.0.2.7:443 using outbound/direct[direct-out]: dial tcp 192.0.2.7:443: i/o timeout",
            "+0300 2026-11-14 21:30:01 WARN [6 0ms] inbound/tun[tun-in]: something odd",
            "+0300 2026-11-14 21:30:01 INFO [7 3s] dns: exchange failed for example.com: timeout",
            "2026/11/14 21:22:47.000001 [Warning] core: Xray 26.11.9 started",
            "2026/11/14 21:22:47.000001 [Info] infra/conf/serial: Reading config: &{Name:stdin: Format:json}",
            "2026/11/14 21:40:00.000001 [Info] [42] app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: connection ends",
            "2026/11/14 21:40:00.000001 [Info] [43] transport/internet/splithttp: failed to send upload > bad status code:500 Internal Server Error",
            "protocol error: received DATA after END_STREAM",
        ];
        for line in kept {
            assert!(!is_routine_flow(line), "{line}");
        }
    }

    /// O-4: an engine log file keeps its start-up and failure lines and no routine connection;
    /// any other log keeps every line.
    #[test]
    fn engine_log_files_leave_routine_connections_out() {
        use crate::logging::RotatingFile;
        let tmp = crate::test_support::TempDir::new("flows");
        let engine = RotatingFile::engine(tmp.path(), "sing-box").expect("engine log");
        let routine = "+0300 2026-11-14 21:22:50 INFO [1 0ms] dns: exchanged A example.com. 300 IN A 192.0.2.7";
        let failed =
            "+0300 2026-11-14 21:30:01 ERROR [5 5s] connection: open connection: i/o timeout";
        for line in [
            "+0300 2026-11-14 21:22:47 INFO sing-box started (0.40s)",
            routine,
            failed,
        ] {
            engine.write_line(line).expect("written");
        }
        let text = std::fs::read_to_string(tmp.path().join("sing-box.log")).expect("read");
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(!text.contains("exchanged"), "{text}");
        let other = RotatingFile::open(tmp.path(), "other", 1 << 20, 0).expect("open");
        other.write_line(routine).expect("written");
        let text = std::fs::read_to_string(tmp.path().join("other.log")).expect("read");
        assert!(text.contains("exchanged"), "{text}");
    }
}
