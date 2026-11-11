//! Internet reachability as an ordinary app sees it: Windows' own `curl.exe` ([`crate::curl`]:
//! absolute System32 path, proxies off). The kill switch permits our own exe, not curl, so an
//! in-process client would get through where the user's apps are blocked and report a lie
//! (B-SD-5).
use std::net::IpAddr;
use std::time::Duration;

use vpnte_base::Msg;
use vpnte_base::types::Verdict;

use super::{Category, CheckItem};

/// `(id, label key, url)` of the endpoints, checked in parallel.
pub const ENDPOINTS: [(&str, &str, &str); 5] = [
    (
        "endpoint-ipv4",
        "probes.diag.endpoint.ipv4",
        "https://api.ipify.org",
    ),
    (
        "endpoint-cloudflare",
        "probes.diag.endpoint.cloudflare",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ),
    (
        "endpoint-google",
        "probes.diag.endpoint.google",
        "https://www.google.com/generate_204",
    ),
    (
        "endpoint-msft",
        "probes.diag.endpoint.msft",
        "http://www.msftconnecttest.com/connecttest.txt",
    ),
    (
        "endpoint-store",
        "probes.diag.endpoint.store",
        "https://storeedgefd.dsx.mp.microsoft.com",
    ),
];

/// curl's own limit per request; the process gets a little longer.
const CURL_MAX_TIME_S: u32 = 12;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);

/// What one curl run reported through its `--write-out` line.
#[derive(Debug, Clone, PartialEq)]
pub struct WriteOut {
    pub exit: Option<i32>,
    pub http_code: u16,
    pub remote_ip: Option<IpAddr>,
    pub time_s: Option<f64>,
    pub error: String,
}

/// Parses `-w "%{http_code}|%{remote_ip}|%{time_total}|%{errormsg}"`.
pub fn parse_write_out(exit: Option<i32>, stdout: &str) -> WriteOut {
    let mut parts = stdout.trim().splitn(4, '|');
    let mut next = || parts.next().unwrap_or_default().trim().to_owned();
    let (code, ip, time, error) = (next(), next(), next(), next());
    WriteOut {
        exit,
        http_code: code.parse().unwrap_or(0),
        remote_ip: ip.parse().ok(),
        time_s: time.parse().ok(),
        error,
    }
}

/// The item of one endpoint. curl runs without `-f`, so any HTTP answer exits 0: reachable is
/// `Ok` (a 5xx is a warning); a non-zero exit (DNS, connect, TLS, timeout) is `Fail`.
pub fn endpoint_item(
    id: &str,
    label: &'static str,
    url: &str,
    outcome: Result<WriteOut, String>,
) -> CheckItem {
    let o = match outcome {
        Ok(o) => o,
        Err(e) => {
            return CheckItem::new(
                id,
                Category::Internet,
                label,
                Some(Verdict::NotChecked),
                Msg::new("probes.diag.endpoint.notRun"),
            )
            .details(vec![format!("url={url}"), e], 2);
        }
    };
    let reachable = o.exit == Some(0) && (o.http_code > 0 || o.remote_ip.is_some());
    let mut rows = vec![format!("url={url}")];
    rows.extend(o.time_s.map(|t| format!("time={t:.3}s")));
    let (verdict, value) = if reachable {
        let ip = o.remote_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let verdict = if o.http_code >= 500 {
            Verdict::Warn
        } else {
            Verdict::Ok
        };
        (
            verdict,
            Msg::new("probes.diag.endpoint.http")
                .arg("code", o.http_code)
                .arg("ip", ip),
        )
    } else {
        rows.push(format!(
            "curl exit={} {}",
            o.exit.map_or("?".to_owned(), |c| c.to_string()),
            o.error
        ));
        (Verdict::Fail, Msg::new("probes.diag.endpoint.noConnection"))
    };
    CheckItem::new(id, Category::Internet, label, Some(verdict), value).details(rows, 4)
}

/// Runs curl once for `url`; `Err` when it could not be started or did not finish in time.
pub async fn run_curl(url: &str) -> Result<WriteOut, String> {
    let max_time = CURL_MAX_TIME_S.to_string();
    let args = [
        "-q",
        "--noproxy",
        "*",
        "-L",
        "-sS",
        "-o",
        "NUL",
        "--max-time",
        &max_time,
        "-w",
        "%{http_code}|%{remote_ip}|%{time_total}|%{errormsg}",
        url,
    ];
    let out = crate::curl::run_curl(args.map(str::to_owned).to_vec(), PROCESS_TIMEOUT).await;
    match out.exit {
        _ if !out.launched => Err("curl.exe not started".to_owned()),
        None => Err("curl did not finish in time".to_owned()),
        exit => Ok(parse_write_out(exit, &out.stdout)),
    }
}

/// All endpoint items, in parallel.
pub async fn endpoint_items() -> Vec<CheckItem> {
    let runs = ENDPOINTS
        .map(|(id, label, url)| async move { endpoint_item(id, label, url, run_curl(url).await) });
    futures_util::future::join_all(runs).await
}
