# vpnte-probes — API for dependent crates

Measurements: public IP monitor and leak checks, system diagnostics and the routing plan, local
upstream-proxy detection, URL availability, speed test, server pings, country / ASN lookups, egress
IP and SOCKS latency, key health (temporary probe engine), the stages of the live server check and
the live check runner. Depends on `vpnte-base`, `vpnte-core`, `vpnte-winnet`, `vpnte-profiles`,
`vpnte-engine`. No cargo features.

```toml
vpnte-probes.workspace = true
```

| module | what |
| --- | --- |
| `ping` | server latency ladder (direct-out SOCKS / physical-bound TCP + ICMP / unbound), `ping_all` stream |
| `geo` | `Geo`: country of an IP (3 providers, vote, 429 back-off, cache), exit / entry verification, ASN |
| `egress` | SOCKS connect latency, public egress IPv4 through a loopback SOCKS endpoint |
| `key_health` | `check_profile[_verdict]` / `check_many[_verdicts]`: temporary probe engine, one budgeted transfer, verdict + `HealthReason` + classification |
| `discipline` | RU discipline: per-endpoint handshake budget, 64 KiB transfer check (freeze), reach probe (ICMP + TCP), classifier |
| `public_ip` | `IpReader`: provider race per family through a route (TUN-bound, loopback proxy, direct) |
| `ip_monitor` | `IpMonitor`: evidence store + periodic task, baseline adoption, verdicts, auto-verify |
| `leak` | adapter-bound leak self-test (curl.exe), `LeakWatch` scheduler, leak check card, direct-out audit |
| `diagnostics` | system report (checklist), routing plan (decision table), routing self-test, snapshots |
| `local_proxy` | detect + protocol-verify a local upstream proxy (Happ and other clients), single flight |
| `availability` | URL check tunnel vs direct (DNS / TCP / TLS / HTTP stages), verdict, geo-block scoring, history |
| `speedtest` | multi-stream download / upload / latency, progress, egress check, history |
| `live_stages` | the live check's measurement stages and its stored row vocabulary |
| `live` | live check runner: FIFO jobs (single / batch ≤ 12), engine probe, findings, diff, history |
| `curl` | the one `curl.exe` launcher (System32 path, hidden, app job, proxies off) of `leak` and `diagnostics` |
| `LOCALES` | the crate's locale fragments, `&[(ru_json, en_json)]` |

**Elevation: nothing here needs it.** ICMP echo (`vpnte_winnet::icmp`: `IcmpSendEcho2Ex` /
`Icmp6SendEcho2`), `IP_UNICAST_IF` binding, IP Helper / SCM / registry reads, curl.exe and the
loopback probe engines all work unelevated, and the unelevated reads are complete (process names
come from a Toolhelp snapshot, services from SCM query rights). Nothing self-elevates, no call
answers "needs elevation" (an `ErrorKind::Permission` here is a plain access-denied I/O error, e.g.
a history file), nothing changes system state (the system proxy is only read); the diagnostics
report and snapshots just record `elevated=<bool>`. No `elevated_*` tests.
**Network paths:** requests never use the system proxy implicitly. Callers choose the route: the
TUN (bind to its address), the engine's `mixed-direct-in` (`Loopback` with its credentials), a
physical adapter, or plain OS routing. Probes that must not leave through another VPN take the
physical path (`ping`, `live_stages::ProbePath::Physical`, `key_health` binding).
**Blocking vs async:** async functions need a tokio runtime; the functions marked "blocking"
below (registry / IP Helper / socket-table / process reads, snapshot collection, `physical_uplink`)
go on `spawn_blocking`.
**Secrets:** keys never appear in logs, errors, histories or events. Probe-engine output is the
engine crate's redacted tail; `Loopback` credentials print redacted.

## Wiring (app)

```rust
use std::sync::Arc;
use vpnte_probes::{diagnostics::snapshot::Snapshotter, geo::Geo, ip_monitor::IpMonitor,
    leak::{LeakWatch, SelfTester, SystemEnv, WatchConfig}, live::{self, LiveHistory}, live_stages::GeoCache,
    local_proxy::{LocalProxyDetector, ScanOptions}, public_ip::IpReader};

let geo = Geo::new(!settings.disable_geo_lookup);            // keep in step: geo.set_enabled(..)
let reader = Arc::new(IpReader::new());                       // shared: keeps the 429 back-off
let monitor = IpMonitor::new(reader.clone());                 // Clone; subscribe() -> watch<IpEvidence>
let tester = Arc::new(SelfTester::new(Arc::new(SystemEnv)));  // single-flight leak self-test
let watch = LeakWatch::spawn(tester.clone(), WatchConfig::default(), gate, kill_switch_level,
                             Some(net_changes));              // vpnte_winnet::adapters NetChange receiver
let detector = LocalProxyDetector::new(ScanOptions { skip_ports: own_ports, skip_pids: engine_pids });
let snapshots = Snapshotter::new(&dirs.root, version.into(), app_state);  // start_periodic() at boot
let live_geo = GeoCache::new()?;                              // ASN cache of the live check, one per app
let url_checks = Arc::new(Store::<availability::UrlChecks>::open(&dirs.root));
let speed_tests = Arc::new(Store::<speedtest::SpeedTests>::open(&dirs.root));
let live_history = Arc::new(live::HistoryStore::open(&dirs.root));   // then prune(&live_profile_ids)
let live = live::LiveCheckService::new(Arc::new(AppLiveEnv { .. }), live_history.clone())?;  // shutdown().await on exit
// locales: [.., vpnte_probes::LOCALES, ..].concat()
// legacy: UrlChecks::from_legacy(&v) / SpeedTests::from_legacy(&v) for `url-availability` / `speed-test`,
//         live_history.store().replace(LiveHistory::from_legacy(&v)) for the old live-check history
```

Typical calls: connect → `reader.wave(&IpRoute::Direct, Family::V4, ..)` → `monitor.set_real_ip(..)`;
after start `monitor.start(conn, IpRoute::Tun { v4, v6 }, interval)` and, once routes are proven,
`monitor.adopt_baseline(conn, None, ..)`; server list «Ping» → `ping_all`; «Check keys» →
`key_health::check_many` (commit with `Servers::record_health`); diagnostics page →
`diagnostics::report::system_report`; start gate → `diagnostics::plan::plan_now(..).gate()`.

## ping (`vpnte_probes::ping`)

```rust
pub const TCP_TIMEOUT /*1800 ms*/, ICMP_TIMEOUT /*1500 ms*/, RESOLVE_TIMEOUT /*2500 ms*/: Duration;
pub const SAMPLES: usize /*3*/;  pub const PING_ALL_WINDOW: usize /*6*/;
#[derive(Default)] pub struct NetPath { pub tun_direct: Option<Loopback> }  // Some = our TUN runs (mixed-direct-in)
impl NetPath { pub fn tunnel_running(&self) -> bool }
pub enum PingPath { DirectOutSocks, Tcp, Icmp }                // serde kebab-case
pub struct PingSample { pub ms: u32, pub path: PingPath }
pub struct PingTarget { pub host: String, pub port: u16, pub udp_only: bool }
impl PingTarget { pub fn of(p: &Profile) -> Self }             // udp_only = UDP transports (no TCP rung)
pub fn is_loopback_host(host: &str) -> bool;
pub fn median(samples: &[Option<u32>]) -> Option<u32>;  pub fn plausible(ms: u32, loopback: bool) -> bool; // > 3 ms
pub async fn ping(target: &PingTarget, net: &NetPath, cancel: &CancellationToken) -> Option<PingSample>;
pub fn ping_all<K: Send + 'static>(targets: Vec<(K, PingTarget)>, net: NetPath, cancel: CancellationToken)
    -> impl Stream<Item = (K, Option<PingSample>)> + Send;   // 6 at a time, results as they finish
```
Ladder (DPI-safe): TUN up → direct-out SOCKS (TCP protocols), then physical-source TCP + ICMP, never
an unbound socket; TUN down → physical sources, then unbound TCP, then unbound ICMP. Results are
memory-only: the app records them (`Servers::record_ping`).

## geo (`vpnte_probes::geo`)

```rust
pub fn geo_routes(settings: &Settings, tunnel_running: bool) -> Vec<Route>;   // TUN + auto → [Direct]
pub trait LookupOwner: Send + Sync { fn is_current(&self) -> bool;
    fn switching(&self) -> bool { false } fn has_active(&self) -> bool { true } }
pub enum VerifyReject { GeoDisabled, InvalidIp, Superseded, SwitchInProgress, NoActiveProfile,
                        ResolveFailed, LookupFailed }      // msg() -> probes.geo.reject.*; serde kebab-case
pub struct AsnInfo { pub asn: Option<String> /*"AS13335"*/, pub org, pub network, pub country: Option<String> }
#[derive(Clone)] pub struct Geo;
impl Geo {
    pub fn new(enabled: bool) -> Self;  pub fn set_enabled(&self, on: bool);  pub fn enabled(&self) -> bool;
    pub async fn country(&self, ip: IpAddr, routes: Vec<Route>, owner: Arc<dyn LookupOwner>) -> Option<Iso2>;
    pub async fn verify_exit(&self, ip: IpAddr, routes: Vec<Route>, owner: Arc<dyn LookupOwner>) -> Result<Iso2, VerifyReject>;
    pub async fn verify_entry(&self, host: &str, routes: Vec<Route>, cancel: &CancellationToken) -> Result<(Iso2, IpAddr), VerifyReject>;
    pub async fn asn(&self, ip: IpAddr, routes: &[Route], cancel: &CancellationToken) -> Option<AsnInfo>;
}
```
geojs + ipinfo.io + ipwho.is in parallel, vote (priority geojs), 6 s read deadline, per-provider 429
back-off (`Retry-After` honoured, ≤ 1 h), cache 256 entries 5 min (empty results 5 s), non-public IPs
refused without a request, disabled → zero requests. The app implements `LookupOwner` (generation /
active id / tunnel session snapshot) and records countries with `Servers::record_country`.

## egress (`vpnte_probes::egress`)

```rust
pub const EGRESS_DEADLINE: Duration;                         // 4 s for the whole provider race
pub enum EgressError { Validation, Cancelled, Timeout, Network }   // Copy; From for AppError (probes.egress.*)
pub async fn socks_connect_latency(proxy: &Loopback, host: &str, port: u16, limit: Duration) -> Option<u32>;
pub async fn reliable_socks_latency(proxy: &Loopback, host: &str, port: u16, limit: Duration, attempts: usize) -> Option<u32>;
pub async fn probe_egress_ipv4(ep: &Loopback, cancel: &CancellationToken) -> Result<Ipv4Addr, EgressError>;
```
Latency = socket creation to the full CONNECT reply, `max(1, round(ms))`. Egress: 4 providers
(Cloudflare trace, ipify, icanhazip, myip) over SOCKS domain CONNECT :443 + rustls, public IPv4 only.

## key_health (`vpnte_probes::key_health`)

```rust
pub const CONCURRENCY: usize /*5*/;  pub const BATCH_DEADLINE: Duration /*600 s*/;  pub const KEY_WAIT: Duration /*65 s*/;
pub const PROXY_TAG /*"proxy-out"*/, DIRECT_TAG /*"probe-direct-out"*/, INBOUND_TAG /*"probe-in"*/: &str;
pub enum HealthReason { NoOutbound, ConfigFailed, TlsFailed, AuthFailed, Timeout, HandshakeFailed,
    Hy2ConfigFailed, Hy2AuthFailed, Hy2UdpBlocked, Hy2TlsFailed, Hy2HandshakeFailed }   // kebab-case; msg()
pub struct ProbeCtx { pub singbox_exe: PathBuf, pub xray_exe: PathBuf, pub engine_pref: EnginePref,
    pub device: ClientDevice, pub net: NetPath, pub dns_bootstrap_in: Option<SocketAddr> }
pub struct KeyHealth { pub online: bool, pub at: UnixMs, pub rtt_ms: Option<u32>, pub reason: Option<HealthReason>,
    pub egress_ip: Option<IpAddr>, pub country: Option<Iso2>, pub engine: Option<Engine> }   // camelCase
impl KeyHealth { pub fn offline(reason: HealthReason, engine: Option<Engine>) -> Self }
pub struct KeyCheck { pub health: KeyHealth, pub verdict: discipline::Classification }
pub enum Uplink { Detour(Loopback), Bind(Option<String>) }   // how the probe engine leaves this PC
pub fn probe_config(p: &Profile, listen: &Loopback, device: ClientDevice, route: &Uplink) -> Result<Value, EmitError>;
pub fn classify_failure(hysteria2: bool, log: &str, err: &str) -> HealthReason;
pub fn parse_trace(text: &str) -> (Option<IpAddr>, Option<Iso2>);
pub struct ProbeEngine;   // socks() -> &Loopback, engine() -> Engine, output() -> String, async stop(self); drop kills
pub enum Started { Ready(ProbeEngine), Offline(KeyHealth) }
pub async fn start_probe_engine(p: &Profile, ctx: &ProbeCtx, cancel: &CancellationToken) -> AppResult<Started>;
pub async fn check_profile(p: &Profile, ctx: &ProbeCtx, cancel: &CancellationToken) -> AppResult<KeyHealth>;
pub async fn check_profile_verdict(p: &Profile, ctx: &ProbeCtx, cancel: &CancellationToken) -> AppResult<KeyCheck>;
pub enum HealthError { GroupNotFoundOrEmpty, Cancelled, Timeout, Setup(AppError) }   // From for AppError
pub async fn check_many<K: Send>(items: Vec<(K, Option<Profile>)>, ctx: &ProbeCtx, cancel: &CancellationToken)
    -> Result<Vec<(K, KeyHealth)>, HealthError>;   // None profile = unreadable → no-outbound
pub async fn check_many_verdicts<K: Send>(items: Vec<(K, Option<Profile>)>, ctx: &ProbeCtx,
    cancel: &CancellationToken) -> Result<Vec<(K, KeyCheck)>, HealthError>;
```
One check = one budgeted handshake (`discipline::budget`, wait ≤ `KEY_WAIT`, else `Err`
`probes.discipline.deferred`: not checked, no result in a batch), the probe engine, then ONE
connection through it: the Cloudflare trace (exit IP / country) and a 64 KiB transfer
(`discipline::TRANSFER_BYTES`). `online` = the whole transfer arrived, or an HTTP status came back
through the tunnel (volume then unproven: verdict `not-verified`); a stall = `online: false`,
reason `timeout`, verdict `frozen` (12–24 KiB) or `stalled`, and a freeze holds the endpoint for
`FREEZE_BACKOFF`. A failed dial adds the reach probe (ICMP + TCP to the key's port) for the
classifier. `rtt_ms` = start of the transfer check to the first response head. `Err` only for
setup failures (engine missing, ports exhausted), deferral and cancellation; an engine that
rejects the profile, exits or never serves its port is an offline verdict. `HealthReason` mirrors
`vpnte_servers::model::HealthReason` (same wire names): map 1:1 into `HealthRecord`, commit with
`Servers::record_health(HealthUpdate { identity: row.identity() taken before the probe, .. })`, and
the verdict with `Servers::record_verdicts`.
`classify_failure` (also used by `live`): over lowercased `log + "\n" + err`, first match of config →
auth → tls → timeout → handshake (auth before tls on purpose); Hysteria2 has its own ladder (empty
text → `hy2-handshake-failed`). Probe engine log level stays `debug` (the patterns need it).

## public_ip (`vpnte_probes::public_ip`)

```rust
pub const WAVE_BUDGET: Duration;                               // 2 s ceiling of one wave
pub enum Family { V4, V6 }                                     // Family::of(IpAddr) (mapped v4 = V4)
pub struct Provider { pub v4: &'static str, pub v6: Option<&'static str> }   // url(family)
pub const PROVIDERS: [Provider; 4];          // Cloudflare trace, ipify, icanhazip, myip (v4 only)
pub enum IpRoute { Tun { v4: Ipv4Addr, v6: Option<Ipv6Addr> }, Loopback(Loopback), Direct }   // is_tun()
pub struct IpSample { pub ip: IpAddr, pub provider: u8, pub at: UnixMs }   // camelCase
pub fn parse_provider_body(body: &str) -> Option<IpAddr>;
pub struct IpReader;                                           // Default; share one via Arc (429 back-off)
impl IpReader { pub fn new() -> Self;
    pub async fn wave(&self, route: &IpRoute, family: Family, budget: Duration, cancel: &CancellationToken) -> Option<IpSample>; }
```

## ip_monitor (`vpnte_probes::ip_monitor`)

```rust
pub type ConnId = u64;
pub const DEFAULT_INTERVAL /*30 s*/, MIN_INTERVAL /*5 s*/, MAX_INTERVAL /*300 s*/: Duration;
pub enum IpVerdict { Passed, Indeterminate, NotChecked /*default*/, Failed }   // verdict() -> Verdict; label() -> Msg
pub fn verdict(sample: IpAddr, baseline: Option<IpAddr>, real_ip: Option<IpAddr>) -> IpVerdict;
pub struct IpEvidence { pub baseline: Option<IpAddr>, pub real_ip: Option<IpAddr>, pub last: Option<IpSample>,
                        pub fresh: bool, pub verdict: IpVerdict }
pub trait Sampler: Send + Sync + 'static { fn sample<'a>(&'a self, route: &'a IpRoute, family: Family,
    cancel: &'a CancellationToken) -> BoxFuture<'a, Option<IpSample>>; }      // impl for IpReader
pub enum AdoptError { NoSample, Mismatch { seen: IpAddr }, RealIp, Cancelled, Stale }   // From for AppError
#[derive(Clone)] pub struct IpMonitor;
impl IpMonitor {
    pub fn new(sampler: Arc<dyn Sampler>) -> Self;
    pub fn start(&self, conn: ConnId, route: IpRoute, every: Duration);   // spawns; first read after one period
    pub fn stop(&self);  pub fn set_interval(&self, every: Duration) -> bool;   // clamped; true = rescheduled
    pub async fn refresh(&self, conn: ConnId) -> IpEvidence;              // UI refresh, never adopts
    pub async fn adopt_baseline(&self, conn: ConnId, expected: Option<IpAddr>, cancel: &CancellationToken) -> Result<IpAddr, AdoptError>;
    pub async fn adopt_after_transition(&self, conn: ConnId, routes_active: impl Fn() -> bool, cancel: &CancellationToken) -> Result<IpAddr, AdoptError>;
    pub async fn auto_verify(&self, conn: ConnId, env: &dyn VerifyEnv, cancel: &CancellationToken) -> VerifyOutcome;
    pub fn set_real_ip(&self, ip: Option<IpAddr>);  pub fn invalidate_baseline(&self);
    pub fn suspend(&self) -> SuspendGuard;  pub fn is_suspended(&self) -> bool;   // guards nest; Drop resumes
    pub fn evidence(&self) -> IpEvidence;   pub fn subscribe(&self) -> watch::Receiver<IpEvidence>;
    pub fn last_alive(&self) -> Option<Instant>;   // TUN-bound read showed the baseline (watchdog liveness)
}
pub trait VerifyEnv: Send + Sync { fn is_current(&self, conn: ConnId) -> bool; fn routes_active(&self) -> bool;
                                   fn self_test(&self) -> BoxFuture<'_, SelfTestResult>; }
pub enum VerifyOutcome { Adopted(IpAddr), Busy, NotNeeded, RoutesInactive, SafetyGate(SelfTestVerdict), Rejected, Stale, Cancelled }
```
An unknown result is never "passed": no sample → `NotChecked`; a different exit stays
`Indeterminate` until `auto_verify` adopts it behind a clean leak self-test. Lifecycle: profile swap /
stop → hold `suspend()`; server swap → `invalidate_baseline()`, restart, `adopt_after_transition`.

## leak (`vpnte_probes::leak`, items re-exported from `probe`, `self_test`, `watch`, `check`)

```rust
// probe: one curl.exe run bound to a local address (CurlOutcome is crate::curl::CurlOutcome, re-exported)
pub struct CurlOutcome { pub exit: Option<i32>, pub stdout: String, pub stderr: String, pub launched: bool }
pub enum Reach { Reached { ip: IpAddr }, NotReached { curl_exit: i32 }, Inconclusive { curl_exit: Option<i32>, why: Why } }
pub enum Why { Launch, ProcessTimeout, Bind, Dns, Tls, BadAnswer, Curl }        // label() -> Msg
// self_test
pub struct SelfTestResult { pub at: UnixMs, pub kill_switch: KillSwitchLevel, pub default_v4: Option<Ipv4Addr>,
    pub probes: Vec<AddrProbe>, pub inspection_complete: bool, pub services_disagree: Option<Disagreement>, pub cancelled: bool }
pub enum SelfTestVerdict { Leak, PossibleLeak, Ok, Inconclusive }               // verdict() -> Verdict
pub fn verdict(r: &SelfTestResult) -> SelfTestVerdict;
pub fn report(r: &SelfTestResult) -> SelfTestReport;   // { verdict, headline: Msg, details: Vec<Msg> }
pub trait LeakEnv: Send + Sync + 'static {             // SystemEnv = System32\curl.exe + winnet physical adapters
    fn curl(&self, args: Vec<String>, timeout: Duration) -> BoxFuture<'static, CurlOutcome>;
    fn physical_addresses(&self) -> BoxFuture<'static, Result<Vec<PhysicalAddr>, ()>>; }
pub async fn run_self_test(env: &dyn LeakEnv, kill_switch: KillSwitchLevel, cancel: &CancellationToken) -> SelfTestResult;
pub struct SelfTester;   // new(env), async run(kill_switch, cancel) (shared single flight), stop_all()
// watch: background runs (period 30 s, net-change coalescing 5 s)
pub struct WatchConfig { pub every: Duration, pub coalesce: Duration }        // Default
pub struct LeakEvent { pub reason: &'static str, pub verdict: SelfTestVerdict, pub result: SelfTestResult }
pub struct LeakWatch;    // spawn(..) (see Wiring), subscribe() -> broadcast<LeakEvent>, trigger(reason),
                         // suppress(duration); Drop stops it
// check: the leak check card
pub enum CheckStatus { Ok, Warn, Fail, Info, NotChecked }                       // verdict() -> Option<Verdict>
pub struct CheckItem { pub id: &'static str, pub label: Msg, pub status: CheckStatus, pub value: Msg, pub details: Vec<Msg> }
pub struct CheckReport { pub ran_at: UnixMs, pub summary: CheckStatus, pub headline: Msg, pub items: Vec<CheckItem> }
pub enum Mode { DirectVpn, LocalProxy { upstream: Option<HostPort> } }
pub struct CheckInput { pub mode: Mode, pub tunnel_up: bool, pub evidence: IpEvidence, pub self_test: Option<SelfTestResult>,
                        pub engine_log: Option<Vec<String>>, pub direct: Option<DirectAudit> }
pub async fn leak_check(reader: &IpReader, input: CheckInput, cancel: &CancellationToken) -> CheckReport;   // ≤ 15 s
pub struct ConnRecord { pub chains: Vec<String>, pub rule: String, pub host: Option<String>,
                        pub destination_ip: Option<IpAddr>, pub process_path: Option<String> }   // Clash /connections row
pub fn audit_direct(conns: &[ConnRecord], smart_ru: bool, is_core_process: &dyn Fn(&str) -> bool) -> DirectAudit;
```
With the kill switch Off every background self-test is `PossibleLeak`: gate background runs on
"protection expected". Manual runs call `SelfTester::run` directly (no gate, no alarm). The probes
reach the Internet from each physical adapter (that is the test).

## curl (`vpnte_probes::curl`)

```rust
pub struct CurlOutcome { pub exit: Option<i32> /* None = killed / not waited */, pub stdout: String,
                         pub stderr: String, pub launched: bool }   // not_launched(), stderr_tail() (200 chars)
pub fn curl_path() -> Option<PathBuf>;                              // GetSystemDirectoryW + curl.exe, never PATH
pub async fn run_curl(args: Vec<String>, timeout: Duration) -> CurlOutcome;   // dropping the future kills curl
```
curl, not our sockets, because the kill switch permits our own exe: curl measures what any app sees.
Hidden child in the app's kill-on-close job, proxy variables removed (callers also pass `--noproxy *`).
Used by the leak self-test (adapter-bound probes) and the diagnostics endpoint items.

## diagnostics (`vpnte_probes::diagnostics`, submodules `plan`, `report`, `routing`, `snapshot` public)

```rust
// report model (diagnostics::*)
pub enum Category { App, Tun, Proxy, Network, Internet, Windows, Logs, Routing, Profile }   // is_critical(), msg()
pub struct CheckItem { pub id: String, pub category: Category, pub label: Msg,
    pub verdict: Option<Verdict> /* None = informational */, pub value: Msg, pub details: Vec<String>, pub notes: Vec<Msg> }
pub struct SystemReport { pub ran_at: UnixMs, pub summary: Verdict, pub items: Vec<CheckItem> }
pub fn summarize(items: &[CheckItem]) -> Verdict;
impl From<&leak::CheckItem> for CheckItem;   // leak card row → ReportInputs::routing (Info → None, details → notes)
// report: the system report (native reads + curl endpoint checks + `sing-box version`)
pub struct ReportInputs { pub app_version: String, pub dirs: DataDirs, pub settings: Settings, pub tunnel: TunnelFacts,
    pub proxy: Option<LocalProxy>, pub engine_log: Vec<String>, pub profile: Option<ProfileFacts>,
    pub routing: Vec<CheckItem> /* leak-check items, become "routing-<id>" */, pub extra: Vec<CheckItem>, pub own_pids: Vec<u32> }
pub struct TunnelFacts { pub running: bool, pub upstream: Option<String>, pub luid: Option<u64> }
pub struct ProfileFacts { pub name: String, pub protocol: String, pub stealth: String, pub tls: bool, pub ech: bool,
    pub hy2: Option<Hy2Facts>, pub warnings: Vec<Msg> }        // fill from vpnte_profiles caps
pub async fn system_report(inputs: ReportInputs, cancel: CancellationToken) -> AppResult<SystemReport>;
// plan: may the tunnel start, and in which mode
pub enum PlanStatus { Ready, Protected, Blocked, Broken }   pub enum RecommendedMode { Hard, External, Off }
pub struct RoutingPlan { pub ran_at: UnixMs, pub status: PlanStatus, pub recommended_mode: RecommendedMode, pub title: Msg,
    pub note: Option<Msg>, pub explanation: Msg, pub before: Msg, pub after: Msg, pub can_start_hard: bool,
    pub proxy: Option<LocalProxy>, pub tunnels: Vec<TunnelInfo>, pub tunnels_verified: bool,
    pub listeners: Vec<ListenerInfo>, pub blockers: Vec<Msg>, pub steps: Vec<PlanStep> }
impl RoutingPlan { pub fn gate(&self) -> AppResult<()> }    // Conflict + probes.plan.<kind>.gate
pub fn routing_plan(inputs: &PlanInputs) -> RoutingPlan;    // pure decision table
pub struct PlanContext<'a> { pub tun_running: bool, pub tun_luid: Option<u64>, pub tun_alias: Option<String>, pub direct_vpn: bool,
    pub active_profile: Option<String>, pub proxy_override: Option<(String, u16, ProxyKind)>,
    pub detector: &'a LocalProxyDetector, pub skip_pids: Vec<u32> }
pub async fn plan_now(ctx: PlanContext<'_>) -> RoutingPlan; // reads foreign tunnels + listeners, then routing_plan
// routing: is traffic split as configured (echo services through the TUN and mixed-direct-in)
pub enum RoutingVerdict { Ok, Partial, Leak, TunnelOff, Inconclusive }
pub struct RoutingInputs { pub tunnel_active: bool, pub direct: Option<Loopback>, pub tun_source: Option<IpAddr>,
                           pub smart_ru: bool, pub disable_geo_lookup: bool }
pub async fn routing_test(inputs: RoutingInputs, cancel: CancellationToken) -> AppResult<RoutingResult>;
pub async fn direct_egress_ip(direct: &Loopback) -> Option<IpAddr>;   // the real ISP IP (IpMonitor::set_real_ip)
// snapshot: JSON system snapshots under <data root>\snapshots (60 kept, public IPs pseudonymised)
pub enum SnapshotReason { AppStart, TunPreStart, TunPostStart, TunStartFailed, TunPostStop, Periodic, Manual, LeakDetected }
pub type AppState = Arc<dyn Fn() -> Map<String, Value> + Send + Sync>;   // protection status, engines, monitor
pub struct Snapshotter;   // new(&root, version, app_state) -> Arc<Self>; async capture(reason) -> Option<PathBuf>;
                          // start_periodic() (5 min, spawns) / stop_periodic(); dir()
pub fn snapshot::dir(data_root: &Path) -> PathBuf;   // maintenance «clear diagnostics»
// sysinfo (re-exported, blocking): processes(), service(name) -> ServiceRow, os_info() -> OsInfo
```
`system_report` items (in order): `runtime-app`, `runtime-settings`, `runtime-tun-status`, `binaries`,
`proxy-current`, `adapters`, `ip-config`, `routes`, `dns-resolve`, `proxy-listeners`,
`proxy-processes`, `endpoint-{ipv4,cloudflare,google,msft,store}`, `services-core`, `services`,
`app-log`, `tun-log`, `routing-*`, `active-profile-capabilities`, then `extra` (rule sets, capture).

## local_proxy (`vpnte_probes::local_proxy`)

```rust
pub struct LocalProxy { pub addr: SocketAddr, pub kind: ProxyKind, pub source: Source,
    pub verified: bool /* an IP echo answered through it */, pub public_ip: Option<IpAddr> }   // label()
pub enum Source { Config(String), System(String), Listener(String), TypicalPort, Manual }
pub struct ScanOptions { pub skip_ports: Vec<u16>, pub skip_pids: Vec<u32> }   // our own inbounds / engines
pub struct LocalProxyDetector;
impl LocalProxyDetector {
    pub fn new(options: ScanOptions) -> Self;
    pub async fn detect(&self) -> Option<LocalProxy>;          // single flight; cache 8 s (hit) / 500 ms (miss)
    pub async fn recheck(&self, known: &LocalProxy) -> bool;   // cheap local re-handshake
}
pub async fn scan(options: ScanOptions) -> Option<LocalProxy>;                       // ≤ 6 s
pub async fn probe_manual(host: &str, port: u16, kind: ProxyKind) -> Option<LocalProxy>;   // settings override
pub struct SystemProxy { pub wininet: Option<WinInet>, pub winhttp: Option<Option<String>>, pub env: Vec<(String, String)> }
impl SystemProxy { pub fn read() -> Self /* blocking */; pub fn candidates(&self) -> Vec<Candidate> }
```
Candidates: client config files (14 dirs), WinINet / WinHTTP / env proxy, loopback listeners (minus
system processes, ports < 1024 except 443, excluded ports and our own `ScanOptions`), 20 typical ports;
each is protocol-verified (SOCKS5 greeting / HTTP CONNECT) before it counts. Building blocks (`config_candidates`, `listener_candidates`, `attempt`, `verify`,
`pick`, …) are public for tests and the routing plan. `scan` dials the typical ports on loopback.

## availability (`vpnte_probes::availability`)

```rust
pub struct ProbeTarget;    // the one URL normalisation
impl ProbeTarget { pub fn parse(input: &str) -> AppResult<ProbeTarget>;   // probes.availability.{invalidUrl,unsupportedScheme}
    pub fn url(&self) -> &Url; pub fn host(&self) -> &url::Host<String>; pub fn port(&self) -> u16; pub fn https(&self) -> bool;
    pub fn history_url(&self) -> String /* no userinfo / query / fragment */; }
pub enum Paths { Direct, Tunnel { tun_v4: Option<Ipv4Addr>, tun_v6: Option<Ipv6Addr>, direct_inbound: Option<Loopback> } }
pub trait GeoLookup: Send + Sync { fn lookup(&self, ip: IpAddr) -> BoxFuture<'_, Option<GeoInfo>>; }   // app: over geo::Geo
#[derive(Clone)] pub struct CheckEnv { pub paths: Paths, pub geo: Option<Arc<dyn GeoLookup>> }       // None = geo disabled
pub struct AvailabilityResult { pub id: String, pub url: String, pub tested_at: UnixMs, pub tunnel_active: bool,
    pub protected: Option<PathReport>, pub direct: Option<PathReport>,
    pub verdict: AvailabilityVerdict, pub recommendation: Recommendation }   // camelCase; stored as is
pub enum AvailabilityVerdict { WorksBoth, WorksOnlyWithVpn, WorksOnlyWithoutVpn, BlockedEverywhere, AuthRequired, Unknown } // msg()
pub const CHECK_BUDGET: Duration /*30 s*/;  pub const PATH_BUDGET: Duration /*15 s*/;
pub async fn check_url(env: &CheckEnv, target: &ProbeTarget, cancel: &CancellationToken) -> AppResult<AvailabilityResult>;
pub async fn run_check(ops: &OperationRegistry, history: Arc<Store<UrlChecks>>, env: CheckEnv, input: &str,
                       opts: RunOpts) -> AppResult<AvailabilityResult>;   // operation "availability-check:<uuid>", commits
pub struct UrlChecks { pub history: Vec<AvailabilityResult> }   // history/url-checks.json, 50 newest first
impl UrlChecks { pub fn push(&mut self, r: AvailabilityResult); pub fn clear(&mut self); pub fn from_legacy(v: &Value) -> UrlChecks; }
```
`PathReport` holds the DNS / TCP / TLS / HTTP stages, `ErrorCode` (msg()), the geo info and the
geo-block reasons; an unmeasured path is `Unknown`, never "blocked". Geo-block scoring
(`score_single_page`, `compare_renders`, `html_to_signal`) is pure and public.

## speedtest (`vpnte_probes::speedtest`)

```rust
pub enum SpeedPhase { Latency, Download, Upload, Complete, Error }   // msg()
pub struct SpeedProgress { pub percent: u8, pub phase: SpeedPhase }  // latency 0, download 5..=50, upload 50..=100
pub struct SpeedResult { pub id: String, pub timestamp: UnixMs, pub download_mbps: f64, pub upload_mbps: Option<f64>,
    pub latency_ms: u32, pub server_name: String, pub profile_used: Option<String>, pub egress: Egress,
    pub transport_warning: Option<TransportWarning> }                // camelCase
pub enum Egress { Match, Changed { seen: Option<IpAddr> }, Direct { seen: IpAddr }, NotChecked }   // msg()
pub struct EgressRef { pub baseline: Option<IpAddr>, pub real_ip: Option<IpAddr> }
pub trait EgressSource: Send + Sync { fn reference(&self) -> EgressRef;
    fn sample(&self, family: IpFamily) -> BoxFuture<'_, Option<IpAddr>>; }   // app: over IpMonitor / IpReader
pub struct Connection { pub tun_v4: Option<Ipv4Addr>, pub profile: Option<String> }
#[derive(Clone)] pub struct SpeedEnv { pub connection: Option<Connection>, pub egress: Option<Arc<dyn EgressSource>>, pub plan: Plan }
pub async fn measure(connection: &Connection, egress: Option<&dyn EgressSource>, plan: &Plan,
    progress: &watch::Sender<SpeedProgress>, cancel: &CancellationToken) -> AppResult<SpeedResult>;   // stores nothing
pub async fn run(ops: &OperationRegistry, history: Arc<Store<SpeedTests>>, env: SpeedEnv,
    switched: impl Future<Output = ()> + Send + 'static, progress: watch::Sender<SpeedProgress>,
    opts: RunOpts) -> AppResult<SpeedResult>;   // single flight; `switched` fires on a server change
pub struct SpeedTests { pub history: Vec<SpeedResult> }   // history/speed-tests.json, 50; push / clear / from_legacy
```
Errors: `Conflict` `probes.speed.{notConnected,serverChanged}` (and `core.ops.busy`), `Network`
`probes.speed.{latencyFailed,downloadFailed}`, `Cancelled`, `Timeout`. `Plan::standard()` is the
production plan (time-boxed rounds, Cloudflare / OVH / Tele2 / thinkbroadband targets).

## live_stages (`vpnte_probes::live_stages`)

The live check's stages as independent async functions; their result types are the stored row
format of `live-server-checks.json` (old camelCase names, unknown legacy fields ignored on read).
```rust
pub enum Text { Msg(Msg), Legacy(String) }             // new rows store a Msg, imported rows a string
pub enum TimedStatus { Ok, Error, Skipped, NotChecked } // legacy "unavailable" reads as NotChecked
pub enum NotCheckedReason { UdpTransport, Reality, BasicMode, TunnelTransition, GeoDisabled } // msg(); serde kebab-case
pub struct Timed { pub status: TimedStatus, pub duration_ms: u64, pub error: Option<String>,
                   pub reason: Option<NotCheckedReason>, pub route: Option<ProbeRoute> }   // not_checked(r), cancelled()
pub enum ProbeRoute { Os, Physical }                   // which way a stage's packets went (stored)
pub enum ProbePath { Os, Physical { if_index: u32, luid: u64, src_v4: Option<Ipv4Addr>, src_v6: Option<Ipv6Addr> } }
pub fn physical_uplink() -> windows::core::Result<(ProbePath, String /* alias */)>;   // blocking
// target
pub fn normalize_host_port(raw_host: &str, port: Option<u16>) -> NormalizedTarget;
pub fn require_host(raw_host: &str) -> Result<(), AppError>;
pub enum TargetClass { Refused, Private, Public }  pub fn classify_target(ip: IpAddr) -> TargetClass;  // Refused: no socket
// stages
pub async fn probe_dns<B: DnsBackend>(backend: &B, host: &str, extended: bool, cancel: &CancellationToken)
    -> (DnsDiagnostics, Vec<String> /* reverseDns */);     // SystemDns::new()? = DnsQuery_W + DoH comparison
pub async fn sample_latency(addr: SocketAddr, extended: bool, path: &ProbePath, cancel: &CancellationToken)
    -> (Reachability, Option<LatencyStats>);
pub async fn scan_ports(ip: IpAddr, known: u16, extended: bool, path: &ProbePath, cancel: &CancellationToken) -> Vec<PortItem>;
pub async fn inspect_tls(addr: SocketAddr, identity: &str, path: &ProbePath, cancel: &CancellationToken) -> TlsInfo;
pub async fn probe_http(addr: SocketAddr, is_tls: bool, authority: &str, sni: Option<&str>, path: &ProbePath,
                        cancel: &CancellationToken) -> HttpInfo;
pub async fn trace_route(dst: IpAddr, path: &ProbePath, cancel: &CancellationToken) -> RouteTrace;   // ICMP TTL 1..=8
pub async fn probe_pmtu(dst: IpAddr, path: &ProbePath, iface: Option<(u64, &str)>, cancel: &CancellationToken) -> Pmtu;
pub fn path_info(dst: IpAddr, tun_luid: Option<u64>) -> PathInfo;
pub struct GeoCache;   // new()? — one per app; ipapi.co → ipwho.is fallback, 10 min cache
pub async fn lookup_asn(cache: &GeoCache, ip: IpAddr, cancel: &CancellationToken) -> Result<AsnInfo, String>;
pub async fn infrastructure(geo: Option<&GeoCache> /* None = geo off */, ip: Option<IpAddr>, host: &str,
    known_country: Option<String>, others: &[OtherProfile], cancel: &CancellationToken) -> Infrastructure;
```
Gating of stages (UDP transports, REALITY, basic mode, tunnel transitions), findings, the diff
(`ChangesFromPrevious` is defined here, filled by `live`) and row assembly belong to `live`.

## discipline (`vpnte_probes::discipline`)

RU network discipline (Nov 2026): more than ~3 TLS handshakes to one server name in a minute
freeze that server for the client for ~120 s; TCP to many foreign data centres freezes without
RST after ~16–20 KB; a banned IP answers ICMP while TCP and UDP are dropped; mobile networks cut
UDP. Every check that makes an engine dial a server takes a slot of one shared budget.
```rust
pub const WINDOW: Duration /*60 s*/;  pub const MAX_PER_WINDOW: usize /*3*/;  pub const MIN_GAP: Duration /*400 ms*/;
pub const FREEZE_BACKOFF: Duration /*130 s: quiet time after a freeze verdict*/;
pub struct Endpoint;   // budget key: "sni:<tls server name>" (else the server's domain), or "host:port"
impl Endpoint { pub fn of(p: &Profile) -> Option<Endpoint> /* None: loopback server */;
    pub fn server_name(&str) -> Self; pub fn host_port(&str, u16) -> Self; pub fn as_str(&self) -> &str }
pub enum BudgetError { Deferred { retry_after: Duration }, Cancelled }   // -> AppError Conflict probes.discipline.deferred {{seconds}}
pub fn budget() -> &'static HandshakeBudget;                    // the one process-wide budget
impl HandshakeBudget {
    pub async fn acquire(&self, e: &Endpoint, max_wait: Duration, cancel: &CancellationToken) -> Result<(), BudgetError>;
    pub fn hold(&self, e: &Endpoint, quiet: Duration);   // after a freeze: no handshake before `quiet` passed
    pub fn wait_for(&self, e: &Endpoint) -> Duration;    // zero = a slot is free now
}
// transfer check (one connection = one handshake): GET /cdn-cgi/trace (keep-alive), then
// GET /__down?bytes=65536 on https://speed.cloudflare.com (exact byte count, no per-client cap)
pub const TRANSFER_HOST: &str; pub const TRANSFER_BYTES: u64 /*64 KiB*/; pub const FREEZE_BAND: RangeInclusive<u64> /*12..=24 KiB raw*/;
pub struct Limits { pub first_byte, pub gap, pub deadline: Duration }   // Limits::STANDARD = 10 s / 5 s / 20 s
pub enum Transfer { Complete { bytes, ms }, Stalled { bytes }, NoData, Failed { bytes, error: String } }
impl Transfer { pub fn frozen(&self) -> bool /* stall inside FREEZE_BAND */; pub fn complete(&self) -> bool }
pub struct TransferReport { pub transfer: Transfer, pub trace: Option<Trace>, pub answer_ms: Option<u32> }
pub type Trace = (Option<IpAddr>, Option<Iso2>);
pub async fn transfer_through(proxy: &Loopback, endpoint: Option<&Endpoint>, max_wait: Duration,
    cancel: &CancellationToken) -> AppResult<TransferReport>;   // through an engine that already runs
// reach probe (not budgeted): ICMP echo + one TCP connect to the server's own port, physical source
pub enum Seen { NotRun, Answered, Refused, Silent }
pub struct Reach { pub icmp: Seen, pub tcp: Seen }
pub async fn reach(host: &str, port: u16, udp_only: bool, net: &NetPath, cancel: &CancellationToken) -> Reach;
// classifier
pub struct Observations { pub udp_transport: bool, pub deferred: bool, pub transfer: Option<Transfer>,
    pub failure: Option<HealthReason>, pub real_certificate: bool, pub icmp: Seen, pub tcp: Seen }
pub enum Verdict { Healthy, Frozen, Stalled, HandshakeFailed, KeyRejected, IpBanned, UdpBlocked, Offline,
    Deferred, NotVerified }                                   // kebab-case; msg() -> probes.verdict.*
pub enum Reaction { None, SwitchServer, TryAnotherFingerprint, PreferTcpTransport, RetryLater }  // msg() -> probes.reaction.*
pub struct Classification { pub verdict: Verdict, pub reaction: Reaction }   // camelCase
pub fn classify(o: &Observations) -> Classification;
pub fn real_certificate(engine_log: &str) -> bool;            // "received real certificate", REALITY verification
```
Bytes are counted below the inner TLS (what the proxy delivered), the closest observable to what
the server sent; a stall = first bytes, then `gap` of silence (no FIN / RST). Classifier order:
deferred → an observed transfer (complete = healthy, stall in band = frozen / switch server, other
stall = stalled / retry later, an HTTP error after data = not-verified) → the engine failure
(auth = key-rejected, config = not-verified) → a real certificate (handshake-failed / try another
fingerprint) → reach: UDP transport with a TLS failure inside QUIC = handshake-failed (the
datagrams passed), with TCP answering (a reset counts) = udp-blocked / prefer TCP;
TCP silent + ICMP answering = ip-banned / switch server (changing port or transport will not help);
both silent or the port refused = offline; TCP connects + TLS failure = handshake-failed / try
another fingerprint, + a hang = handshake-failed / retry later (changing the fingerprint inside a
freeze is reported to extend it); no evidence = not-verified. `Verdict` / `Reaction` share their
wire names with `vpnte_servers::model::{ServerVerdict, ServerReaction}`: store them with
`Servers::record_verdicts` (map 1:1 like `HealthReason`).
Not wired by this crate (no dependency): the tunnel's post-connect egress probe
(`vpnte_tunnel` `egress_via`) and the automation; the app should route the former through
`transfer_through` or `budget().acquire` and feed `Classification` to the latter.

## live (`vpnte_probes::live`)

One FIFO runner, one job at a time (a batch is one job, its checks sequential: probe engines and
throughput share the uplink). A check = target + DNS, the direct stages concurrently, the engine
stage, split-tunnel snapshot, diff with the baseline, findings, sanitising, history write.
Engine stage and the handshake budget: every request through the engine is a new handshake to
the server, so a check of a non-loopback server dials one at a time through
`discipline::budget()` in order trace → throughput samples (when asked) → ipify → first media
host → ipify6 → second media host, none later than 8 s before the check's deadline; what the
budget refuses is left out of the rows and named in the handshake note
(`probes.discipline.liveDeferred`); nothing dialled → handshake / media `skipped`, never failed.
In practice a check gets three dials per minute per server name (the rest of a basic check is
left out; a second check within the minute is mostly left out).
```rust
pub const MAX_BATCH: usize /*12*/;  pub const HISTORY_PER_TARGET: usize /*20*/;
pub const BASIC_DEADLINE /*25 s*/, EXTENDED_DEADLINE /*60 s*/: Duration;   // throughput → extended budget in any mode
pub enum CheckMode { Basic /*default*/, Extended }              // serde lowercase; extended() -> bool
pub enum CheckTarget { Profile(String), Endpoint { host: String, port: Option<u16> } }   // endpoint: direct stages only
pub struct CheckRequest { pub target: CheckTarget, pub mode: CheckMode, pub throughput: bool /* 3 × 4 MiB */ }
pub enum JobRequest { Single(CheckRequest), Batch { profiles: Vec<String> /* 1..=12, dups dropped */, mode: CheckMode, throughput: bool } }
// implemented by the app (probes cannot depend on servers / tunnel / routing)
pub trait LiveEnv: Send + Sync + 'static {
    fn profile(&self, id: &str) -> Option<ProfileTarget>;
    fn tunnel(&self) -> TunnelView;
    fn other_profiles(&self, except_id: Option<&str>) -> Vec<OtherProfile>;   // shared-/24 hint
    fn split_tunnel(&self) -> Result<SplitTunnelRules, String>;
    fn engine_setup(&self) -> EngineSetup;
    fn geo_enabled(&self) -> bool;                                            // !settings.disable_geo_lookup
}
pub struct ProfileTarget { pub id: String, pub profile: Profile, pub country: Option<String>,
                           pub device: ClientDevice, pub eligible: bool /* enabled && !removed */ }
pub enum TunnelState { Down, Up, Transition }                   // serde kebab-case
pub struct TunnelView { pub state: TunnelState, pub active_profile_id: Option<String>,
    pub live_check_in: Option<Loopback> /* direct-VPN self-probe inbound */, pub mixed_direct_in: Option<Loopback>,
    pub tun_luid: Option<u64> }                                 // TunnelView::down()
pub struct EngineSetup { pub singbox_exe: PathBuf, pub xray_exe: PathBuf, pub engine_pref: EnginePref,
                         pub dns_bootstrap_in: Option<SocketAddr> }
pub struct SplitTunnelRules { pub enabled: bool, pub direct_names: Vec<String>, pub direct_paths: Vec<String>, pub vpn_names: Vec<String> }
// OtherProfile = live_stages::geo::OtherProfile { name: String, server: String, resolved_ip: Option<IpAddr> }
// the service (one per app, inside a tokio runtime)
pub struct LiveCheckService<B: DnsBackend + Send + 'static = SystemDns>;
impl LiveCheckService { pub fn new(env: Arc<dyn LiveEnv>, history: Arc<HistoryStore>) -> AppResult<Self>; }
impl<B> LiveCheckService<B> {
    pub fn submit(&self, request: JobRequest) -> AppResult<JobHandle>;   // FIFO; bad batch size -> Validation
    pub fn history(&self) -> &Arc<HistoryStore>;
    pub async fn shutdown(&self);          // cancels all, waits for the runner; later submit -> Conflict
}
pub struct JobHandle { pub id: JobId, pub cancel: CancellationToken,
    pub progress: watch::Receiver<ProgressSnapshot>, pub done: oneshot::Receiver<JobOutcome> }   // drop ≠ cancel
pub enum JobOutcome { Single(AppResult<Box<LiveCheck>>), Batch(BatchResult) }
pub struct BatchResult { pub mode: CheckMode, pub started_at: UnixMs, pub finished_at: UnixMs, pub cancelled: bool,
                         pub results: Vec<LiveCheck>, pub errors: Vec<BatchError /* { profile_id, error: Msg } */> }
pub struct ProgressSnapshot { pub state: JobState /* Queued|Running|Done */, pub items: Vec<ItemProgress>, pub current: Option<usize> }
pub struct ItemProgress { pub profile_id: Option<String>, pub state: ItemState /* Pending|Running|Completed|Failed|Cancelled */,
    pub stages: [Option<ProgressStatus>; 13] /* index = StageId as usize */, pub completed: u8,
    pub elapsed_ms: u64, pub median_mbps: Option<f64>, pub error: Option<Msg> }
pub enum StageId { Dns, Reachability, Tls, Http, Ports, Route, Infrastructure, Handshake, Egress, MediaStream,
                   Throughput, Path, Pmtu }                     // StageId::ALL
pub enum ProgressStatus { Running, Completed, Failed, Skipped }
// history: <data root>\history\live-checks.json {schemaVersion 1, targets: {"profile:<id>"|"host:<h>": [row…]}}
pub struct LiveHistory { pub targets: BTreeMap<String, Vec<LiveCheck>> }   // Document; from_legacy(&Value)
pub struct HistoryStore;
impl HistoryStore {
    pub fn open(root: &Path) -> Self;  pub fn store(&self) -> &Store<LiveHistory>;   // subscribe / replace / notice
    pub fn add(&self, check: LiveCheck) -> AppResult<()>;   // sanitises; blocking I/O; caps 20 / 180 d / 500
    pub fn list(&self, profile_id: Option<&str>, host: Option<&str>) -> Vec<LiveCheck>;   // newest first, copies
    pub fn baseline(&self, profile_id: Option<&str>, host: &str, port: u16) -> Option<LiveCheck>;
    pub fn clear(&self) -> AppResult<()>;  pub fn export_json(&self) -> String;
    pub fn prune(&self, live_profiles: &HashSet<String>) -> AppResult<usize>;       // at startup
}
pub fn target_key(profile_id: Option<&str>, host: &str) -> String;
// pure
pub fn evaluate_findings(cur: &LiveCheck, prev: Option<&LiveCheck>) -> Vec<Finding>;
pub fn diff(cur: &LiveCheck, prev: &LiveCheck) -> HistoryDiff;      // flags() -> live_stages::ChangesFromPrevious
pub fn is_baseline(row: &LiveCheck, port: Option<u16>) -> bool;
pub fn sanitize(check: &mut LiveCheck);
pub fn summarize_split_tunnel(rules: &SplitTunnelRules) -> SplitTunnel;
pub fn summarize_throughput(samples: Vec<ThroughputSample>, endpoint: &str, duration_ms: u64, error: Option<String>) -> Throughput;
```
`LiveCheck` (stored row, camelCase, old enum strings + `not_checked`): `id` (`lc_<32 hex>`),
`profile_id`, `host`, `port`, `mode`, `started_at` / `finished_at` (`UnixMs`), `duration_ms`,
`cancelled`, `tunnel: Option<TunnelContext>`, the `live_stages` sections (`dns`, `reverse_dns`, `asn`,
`reachability`, `latency`, `tls`, `http`, `open_ports`, `route`, `infrastructure`, `path_diagnostics`,
`pmtu`), the engine sections `handshake` / `egress` / `media_stream` / `throughput` (each with a
status enum; handshake `ok` only after an answer came back through the tunnel), `split_tunnel` and
`findings: Vec<Finding { code: FindingCode, severity: Severity /* Info|Warning|Error */, title: Text,
detail: Text, evidence }>` (UI shows them in order). `EngineRoute`: `physical-direct` (tunnel down,
temporary engine bound to the uplink), `active-tunnel-direct-detour` (temporary engine through
`mixed_direct_in`), `active-tunnel` (checked profile is the active one: self-probe via
`live_check_in`, never a second engine).
Rules: cancelled / timed-out checks are never stored; a started history write completes; the final
snapshot of a cancelled job marks the items the cancel cut short `Cancelled`. Tunnel
`Transition` → every network stage `not_checked` (`tunnel-transition`), the row is still produced.
UDP transports skip TCP / TLS / HTTP / ports; TLS / HTTP only in extended mode and never for REALITY;
loopback-class targets are refused after DNS. TLS through the tunnel (reflectors Cloudflare / ipify,
Twitch media hosts, speed.cloudflare.com) is verified against the Windows store. The failure class
of a handshake comes from `key_health::classify_failure`.
UI flow: `submit` → pump `progress` into a signal → await `done`; tie `cancel` to the component
(`cancel.drop_guard()`); the history page reads `history().list(..)` and subscribes to
`history().store()`.

## Errors and i18n keys

User-facing text is `Msg` with keys under `probes.` (fragments `locales/<package>.{ru,en}.json`,
registered through `LOCALES`): `probes.egress.*`, `probes.geo.reject.*`,
`probes.keyHealth.{groupEmpty,reason.*}` (servers package); `probes.ip.{verdict,adopt}.*`,
`probes.leak.{why,probe,selfTest,check}.*`; `probes.diag.*`, `probes.routing.*`, `probes.plan.*`;
`probes.availability.*`, `probes.speed.*`; `probes.liveStages.*`; `probes.live.{profileNotFound,
shuttingDown,batch,history,engine,egress,media,throughput,split,finding}.*` (findings:
`probes.live.finding.<rule>.{title,detail}`); `probes.discipline.{deferred,liveDeferred}`,
`probes.verdict.*`, `probes.reaction.*` (probe-discipline). Technical stage errors in stored
rows stay English strings (`ECONNREFUSED`, `ETIMEDOUT`, …). Errors are `AppError` (`Validation`,
`Conflict`, `Network`, `Timeout`, `Cancelled`) or the module enums listed above, each with
`From<_> for AppError`.
Push channels: `IpMonitor::subscribe` (`watch<IpEvidence>`), `LeakWatch::subscribe`
(`broadcast<LeakEvent>`), `ping_all` (stream), speed test progress (`watch<SpeedProgress>` the caller
owns), live jobs (`JobHandle::progress` `watch<ProgressSnapshot>`, `JobHandle::done` oneshot).
Histories: `Store<UrlChecks>`, `Store<SpeedTests>`, `HistoryStore::store()` (`Store<LiveHistory>`),
change notification from the store.

## Not implemented / not run

- Two ASN lookups on purpose (different specs, routes and stored shapes): `geo::Geo::asn`
  (geojs / ipinfo / ipwho vote over the bootstrap routes; `geo::AsnInfo` with optional fields, server
  details) and `live_stages::lookup_asn` (ipapi.co → ipwho.is over the OS route; `live_stages::AsnInfo`
  is the persisted live-check row shape with `countryCode`). Two endpoint tables of IP echo services
  likewise: `public_ip::PROVIDERS` (family-pinned endpoints, direct / bound / loopback routes) and
  `egress`'s (domain names CONNECTed through SOCKS, IPv4 only).
- `live`: no engine queue (one runner serialises the probe engines), so the spec's `queued-timeout`
  / `engine-busy` reasons do not exist; no request ids / IPC admission caps (no IPC).
- Not in this crate (never assigned to a package): `server_info` (servers §2.11, the server detail
  probe; the app composes it from `ping` + `geo`) and `tunnel_http_probe` /
  `recent_tunnel_confirmation` (servers §6; the tunnel's `Confirmations` takes outside evidence, the
  app answers it with `IpMonitor::last_alive`).
- Dropped by decision: the diagnostics event-log items, `runtime-acl` / `runtime-paths` /
  `tun-prev-log` / boot-recovery items (no ACL staging or boot task in this design), smart-route
  rule-set and forensics items (they arrive through `ReportInputs::extra`); the leak card's DNS
  server list; per-provider stage timings of `public_ip`; a snapshot on a manually found leak (the
  caller captures `SnapshotReason::LeakDetected`); tracert / PowerShell paths of the live stages
  (native ICMP instead).
- Not run here (tests use loopback fakes, the bundled engines on loopback and `sing-box check`):
  real geo / ASN / egress / public-IP providers, key probes of real servers, remote pings, real
  speed-test transfers and sites, physical-adapter binding while our TUN is up, `local_proxy::scan`
  against this machine (it would dial the user's running client), `SystemEnv` curl probes, the
  routing self-test through a real `mixed-direct-in`; for `live`: real reflectors / Twitch hosts /
  speed.cloudflare.com, Xray probe engines, the `mixed_direct_in` detour and the self-probe through
  a real running tunnel (the engine stage ran against a fake SOCKS server and one real sing-box).
  Ignored tests (`--ignored`) cover the live public-IP wave, live DNS, live key (env
  `VPNTE_LIVE_KEY`) and the real system report.
- Xray probes with our TUN down are not interface-bound (`vpnte_engine::xray_config` has no
  `sockopt.interface` option yet). The tunnel must list the Xray executable in the engine's
  `RoutingInputs::engine_paths` in every mode, else Xray probes made while connected go through
  `proxy-out`.
- probe-discipline, not run here: the real transfer endpoint (`speed.cloudflare.com`), a real
  frozen / banned / UDP-blocked server, ICMP / TCP reach of real servers (tests use loopback,
  where `reach` reports `NotRun` by design). Mobile white-list detection is the
  `ru-network-matrix` package's; the budget does not count the tunnel's own reconnects (engine
  crate) nor the tunnel's post-connect egress probe (tunnel crate) until the app routes them
  through `discipline`.
