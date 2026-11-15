# vpnte-proxies — API map

External loopback proxies: numbered **slots**, each an unauthenticated `mixed` (HTTP + SOCKS5) listener
on `127.0.0.1:<port>` backed by its own sing-box child (plus an Xray child for profiles that run on Xray),
probed through its data plane and rotated between servers; plus the local **control API** (HTTP on
`127.0.0.1:17873`, token-guarded) and its console client `vpnte_proxy.exe`.
Depends on `base`, `core`, `profiles`, `engine`.

```rust
pub const LOCALES: &[(&str, &str)];   // (ru_json, en_json) per fragment, file-name order:
                                      // proxies-control, proxies-manager, proxies-model
```

## Wiring (app)

```rust
use std::sync::Arc;
use vpnte_proxies::control::{ControlConfig, ControlServer};
use vpnte_proxies::manager::{EngineChoice, ProfileSource, ProxyManager, ProxyProfile};
use vpnte_proxies::model::{GroupHealth, ProxyOps, StopReason};

struct Servers { /* the app's server list, settings, probes */ }

#[async_trait::async_trait]
impl ProfileSource for Servers {
    fn profiles(&self) -> Vec<ProxyProfile> { /* every server, list order */ }
    fn active_vpn_profile_id(&self) -> Option<String> { /* the main tunnel's server */ }
    fn engine_choice(&self) -> EngineChoice { /* settings: EnginePref + default ClientDevice; a */
        /* ProxyProfile's own `engine` / `device` win: EngineChoice::for_profile */ }
    async fn check_group_health(&self, group_id: &str) -> vpnte_base::AppResult<GroupHealth> { /* probes */ }
}

// inside the tokio runtime
let manager = ProxyManager::new(Arc::new(servers), &dirs.resources);
let ops: Arc<dyn ProxyOps> = Arc::new(manager.clone());
match ControlServer::start(ops.clone(), ControlConfig::from_env(&dirs.root), shutdown.child_token()).await {
    Ok(server) => { /* serves until the token fires; `server.join().await` after cancelling */ }
    Err(e) => { /* already logged; optional notice: AppError::from(e) */ }
}
let mut rx = manager.snapshot();               // UI state (watch), see `ProxySnapshot`
ops.add("profile-id".into()).await?;           // UI "+": lowest free slot
ops.rotate(slot, None).await?;                 // UI rotate button
ops.stop_all(StopReason::VpnStop).await;      // main VPN disconnected: every slot stops
manager.shutdown().await;                      // app exit: every slot stopped, later starts refused
```

Every `ProxyOps` error is a `ProxyError`; `AppError::from(err)` gives the UI message.

## `slot`

```rust
pub const CONTROL_HOST: &str = "127.0.0.1";  pub const CONTROL_PORT: u16 = 17873;
pub const BASE_PROXY_PORT: u16 = 17990;      pub const MAX_SLOT: u16 = 47546;   // slot N -> 17990 + N - 1
pub struct Slot(u16);   // Copy + Ord + Hash + Display; serde = plain number; From<Slot> for u16; TryFrom<u64>
impl Slot {
    pub const DEFAULT: Slot;                               // slot 1 (what "no slot" means)
    pub fn new(n: u64) -> Result<Slot, ProxyError>;        // 400 "external proxy slot must be between 1 and 47546"
    pub fn parse(raw: &str) -> Result<Slot, ProxyError>;   // JS Number(): " 2 ", "2.0", "1e1"
    pub fn get(self) -> u16;  pub fn default_port(self) -> u16;  pub fn all() -> impl Iterator<Item = Slot>;
}
pub fn parse_port(raw: &str) -> Result<u16, ProxyError>;  // 1..=65535, else 400 "invalid port"
pub fn loopback_url(port: u16) -> String;                 // "http://127.0.0.1:<port>" (slot and control URLs)
```

## `model` — states, wire DTOs, requests, `ProxyError`, `ProxyOps`

```rust
pub enum Health { Stopped /*default*/, Starting, Healthy, Degraded, Rotating, Quarantined, Failed } // lowercase
pub enum Lifecycle { Stopped /*default*/, Starting, Ready, Degraded, Rotating, Quarantined, Failed } // lowercase
pub enum Degradation { ProcessFailed, HealthFailureBudgetExhausted, EgressIpChangedWithoutRotation,
    RotationDidNotChangeEgressIp, DuplicateEgressIp, EgressProbeFailed } // kebab
pub enum Action { Start /*default*/, Rotate, Connect }  impl Action { pub fn parse(&str) -> Option<Action> } // "trigger" = Connect
pub struct StartRequest { pub slot: Option<Slot> /* None = 1 */, pub country: Option<String> /* sticky */,
    pub profile_id: Option<String>, pub port: Option<u16> /* None = keep / default */, pub action: Action,
    pub idempotency_key: Option<String> /* rotate */, pub rotate_reason: Option<String> }   // Default
pub enum StopReason { Api, Ui, VpnStop }  impl StopReason { pub fn as_str(self) -> &'static str } // app exit = shutdown()
pub fn prewarm_count(count: u64) -> Result<u16, ProxyError>;   // 1..=47546, else 400
pub const FRESH_WINDOW_MS: UnixMs = 60_000;
pub fn derive_readiness(instances: &mut [InstanceStatus], now: UnixMs);  // sets `ready` + `running`
```

`ProxyError` (`Clone + Eq + Error`; the `String` is the English wire `detail`, never a secret):

```rust
pub enum ProxyError { BadRequest(String) /*400*/, NotFound(String) /*404*/, Conflict(String) /*409*/,
    Unavailable(String) /*503: shutting down*/, Upstream(u16, String) /*status*/, Engine(String) /*500*/,
    Refused(Msg) /*422: the engine setting cannot run the profile; wire detail fixed English*/ }
impl ProxyError {
    pub fn http_status(&self) -> u16;  pub fn code(&self) -> &'static str; // "conflict" | "forbidden" (403 of a
                                                                           // group check) | "external-proxy-error"
    pub fn detail(&self) -> &str;
    pub fn group_health(kind: ErrorKind) -> Self;   // old /profiles/healthcheck mapping, generic Russian wire texts
}
impl From<ProxyError> for AppError;   // Msg `proxies.error.<kind>` {detail} (Refused: its own engine Msg);
                                      // kind 400/403/404/422 Validation,
                                      // 409/503 Conflict, 502 Network, 504 Timeout, else Internal
```

Wire DTOs (serde, camelCase, field-for-field the old control API JSON; `lastCheckedAt` / `lastSuccessAt`
are epoch ms, every other timestamp an ISO string via `model::iso_ms`):

```rust
pub struct InstanceStatus { pub slot: Slot, pub running: bool /* process_running && ready */,
    pub process_running: bool, pub ready: bool /* healthy, fresh, unique egress */, pub health: Health,
    pub state: Lifecycle, pub generation: u64, pub egress_ip: Option<IpAddr>, pub latency_ms: Option<u32>,
    pub last_checked_at, pub last_success_at, pub egress_checked_at, pub updated_at: Option<UnixMs>,
    pub last_error: Option<String>, pub last_error_at: Option<UnixMs>, pub degradation_reason: Option<Degradation>,
    pub consecutive_failures: u32, pub next_check_at: Option<UnixMs>, pub last_rotate_reason: Option<String>,
    pub auto_disabled: bool, pub host: String, pub port: Option<u16>, pub proxy_url: Option<String>,
    pub profile_id, pub profile_name, pub country: Option<String>, pub pid: Option<u32>, pub started_at: Option<UnixMs>,
    pub engine: Option<Engine> /* while running: Xray when the slot has an Xray child, else sing-box;
                                  JSON "engine": "sing-box" | "xray", omitted when None */,
    pub notice: Option<Msg> /* what the running engine goes without (proxies.slot.spoofDropped);
                               UI only: #[serde(skip)], the control API JSON is unchanged */ }
impl InstanceStatus { pub fn stopped(slot: Slot) -> Self }   // a never-started slot (no 404 for unknown slots)
pub struct Aggregate { pub total, running, ready, healthy, unique_egress, duplicate_egress, starting,
    degraded, quarantined: u32 }
impl Aggregate { pub fn of(&[InstanceStatus], now: UnixMs) -> Self /* derive readiness first */;
                 pub fn covers(&self, count: u32) -> bool /* prewarm `ready` */ }
pub struct ProxyStatus { #[serde(flatten)] pub instance: InstanceStatus, pub control_host: String,
    pub control_port: Option<u16>, pub control_url: Option<String>, pub max_instances: Unlimited /* null */,
    pub instances: Vec<InstanceStatus>, pub aggregate: Aggregate }      // GET /status, start / stop results
pub struct Instances { pub max_instances: Unlimited, pub instances, pub aggregate, pub control_url }  // GET /instances
pub struct InstancesBatch { pub instances: Vec<InstanceStatus>, pub aggregate: Aggregate }
pub enum ServerStatus { Online, Offline, Unknown /*default*/ }
pub struct ProfileRow { pub id, pub name: String, pub country: Option<String>, pub protocol: String,
    pub server: String, pub port: u16, pub group_id: Option<String>, pub status: ServerStatus,
    pub ping_ms, pub health_latency_ms: Option<u32>, pub health_reason: Option<String>,
    pub last_checked_at: Option<UnixMs>, pub selected_for_vpn: bool, pub active: bool, pub active_slots: Vec<Slot> }
pub struct ProfileList { pub profiles: Vec<ProfileRow> }                                   // GET /list
pub enum BatchSkipReason { ActiveVpn, Unavailable }                                         // kebab
pub struct BatchSkip { pub profile_id: String, pub reason: BatchSkipReason }
pub struct BatchFailure { pub profile_id: String, pub error: String /* detail */ }
pub struct BatchStartResult { pub requested: u32, pub started: Vec<InstanceStatus>,
    pub already_running_profile_ids: Vec<String>, pub skipped: Vec<BatchSkip>, pub failed: Vec<BatchFailure> }
pub struct PrewarmResult { pub requested: u32, pub started, pub instances: Vec<InstanceStatus>,
    pub aggregate: Aggregate, pub ready: bool }
pub struct KeyHealth { pub profile_id: String, pub online: bool, pub latency_ms: Option<u32>,
    pub reason: Option<String>, pub egress_ip: Option<IpAddr>, pub country: Option<String> } // None omitted
pub struct GroupHealth { pub ok: bool, pub results: Vec<KeyHealth> }  impl GroupHealth { pub fn alive(&self) -> usize }
pub struct ControlError { pub ok: bool /* false */, pub error: String, pub detail: String }
impl ControlError { pub fn new(error, detail) -> Self }  impl From<&ProxyError> for ControlError;
pub struct Unlimited;                                                                       // serializes as null
pub mod iso_ms {   // serde `with` module: Option<UnixMs> <-> "2026-11-11T05:19:00.123Z" (reads any RFC 3339 offset)
    pub fn format(ms: UnixMs) -> Option<String>;                 // None outside the calendar range
    pub fn serialize<S: Serializer>(value: &Option<UnixMs>, s: S) -> Result<S::Ok, S::Error>;  // None = null
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<UnixMs>, D::Error>;
}
```

`ProxyOps` — one method per control endpoint plus the UI's actions (statuses are derived at call time).
The manager implements it; the control server holds `Arc<dyn ProxyOps>`.

```rust
#[async_trait::async_trait]
pub trait ProxyOps: Send + Sync {
    fn set_control_port(&self, port: u16);                                  // control server, once after bind
    async fn status(&self, slot: Slot) -> ProxyStatus;                      // GET /status, GET /
    async fn instances(&self) -> Instances;     // GET /instances; also queues probes of slots unchecked >= 60 s
    async fn status_batch(&self, slots: Option<Vec<Slot>>) -> InstancesBatch;
    async fn check_health(&self, slot: Slot) -> InstanceStatus;            // probe now (or join the one in flight)
    async fn list(&self, country: Option<String>) -> Vec<ProfileRow>;       // usable profiles, country-filtered
    async fn check_group_health(&self, group_id: String) -> Result<GroupHealth, ProxyError>;
    async fn start(&self, req: StartRequest) -> Result<ProxyStatus, ProxyError>;  // start / rotate / connect
    async fn rotate(&self, slot: Slot, reason: Option<String>) -> Result<ProxyStatus, ProxyError>; // provided
    async fn add(&self, profile_id: String) -> Result<ProxyStatus, ProxyError>;   // UI "+", a subscription
                                                                                  // fetch's spare route
    async fn start_profiles(&self, profile_ids: Vec<String>) -> BatchStartResult; // Servers page, never the VPN's
    async fn prewarm(&self, count: u64, country: Option<String>) -> Result<PrewarmResult, ProxyError>;
    async fn stop(&self, slot: Slot, reason: StopReason) -> Result<ProxyStatus, ProxyError>;
    async fn stop_all(&self, reason: StopReason) -> ProxyStatus;                  // every slot; slot 1's status
}
```

Rules worth knowing: a `start` of a configured running slot returns it unchanged; `connect`
without a profile is 400; a failed start leaves the slot `failed` and configured until an explicit stop;
an explicit stop clears the profile, the sticky country and the rotation keys. A rotate answers after its first
probe; a repeated `idempotency_key` (per slot, last 64 keys, 10 min) returns the current status without rotating.
A start's port must not be the control API's or another slot's and must be bindable on 127.0.0.1 (else 409). A
stop asks the engines to end (CTRL_BREAK; sing-box and the Xray child at once), kills them after 3 s and waits
up to 3 s more; an exit that is still not confirmed fails with 500 "engine did not exit": the slot stays `failed` with its
port reserved, a plain `start` of it is then the idempotent no-op, and `stop` or `rotate` retries (B-18).

## `config` — sing-box config of one slot

```rust
pub const INBOUND_TAG: &str = "external-mixed-in";  pub const PROXY_OUT_TAG: &str = "proxy-out";
pub const DIRECT_TAG: &str = "direct-out";
pub fn build(upstream: &SingBoxFragment, port: u16) -> Result<Value, ProxyError>; // mixed inbound + upstream,
    // localhost / private -> direct, rest rejected; no `dns` block (names are pinned instead)
pub fn xray_bridge(xray_port: u16, creds: &Creds) -> Result<SingBoxFragment, ProxyError>; // SOCKS5 to the slot's Xray
pub fn hostnames(upstream: &SingBoxFragment) -> Vec<String>;      // names the engine would resolve
pub fn pin(upstream: &mut SingBoxFragment, host: &str, ip: IpAddr); // dial the IP, keep SNI / ws Host / host
pub fn preferred_address(addrs: &[IpAddr]) -> Option<IpAddr>;    // first IPv4, else first
```

## `probe` — data-plane probe through a slot listener

```rust
pub const REQUEST_TIMEOUT: Duration;  /* 10 s */   pub const PROBE_BUDGET: Duration;  /* 20 s */
pub enum Answer { Trace /* "ip=" line */, Json /* {"ip": …} */ }
pub struct Target { pub url: String, pub answer: Answer }
pub struct ProbeConfig { pub targets: Vec<Target>, pub request_timeout: Duration, pub budget: Duration }
impl Default for ProbeConfig;   // Cloudflare trace, ipify, myip (HTTPS, through the slot's HTTP proxy)
pub struct ProbeOk { pub egress_ip: IpAddr, pub latency_ms: u32 }
pub enum ProbeError { LocalInbound(String) /* our listener refused */, Transport(String) /* nothing answered: counts */,
    Service(String) /* the route answered without a usable IP: does not count */ }  // Display = the English text (slot `lastError`)
pub async fn probe(port: u16, config: &ProbeConfig) -> Result<ProbeOk, ProbeError>;
pub fn egress_ip_from(answer: Answer, body: &str) -> Option<IpAddr>;
```

Classification of one request (B-5, refined by the manager review): a refused connection to the slot's own
listener is `LocalInbound` (the probe stops); a request error or timeout is `Transport`; an HTTP error status or an
answer without an address is `Service`, except a 5xx over plain HTTP, where the proxy answers for the service (its
own "bad gateway"), which is `Transport`. Through the HTTPS tunnel (all three default services) a refused CONNECT
is already a request error, so any status there came from the service over a working route. The first valid IP
wins; otherwise the probe is `Transport` only when no service answered at all, else `Service`.

## `health` — per-slot health state machine (pure: no I/O, no clock)

```rust
pub const FAILURE_BUDGET: u32 = 4;
pub struct Timing { pub first_probe, pub first_stagger, pub success, pub success_stagger,
    pub cooldowns: [Duration; 3], pub recheck, pub hint_delay, pub hint_spacing: Duration }
impl Default for Timing;   // 0 ms + slot%5*100 ms; 45 s + slot%5*250 ms; 15/30/60 s; 60 s; 15 s; 30 s
impl Timing { pub fn first(&self, Slot) -> Duration; pub fn after_success(&self, Slot) -> Duration;
              pub fn cooldown(&self, failures: u32) -> Duration }
pub enum Next { In(Duration), Park, Disable, Kill }
pub fn is_transport_hint(line: &str) -> bool;
pub struct Route { pub lifecycle: Lifecycle, pub health: Health, pub egress_ip: Option<IpAddr>,
    pub latency_ms: Option<u32>, pub last_checked_at, pub last_success_at: Option<UnixMs>,
    pub last_error: Option<String>, pub last_error_at: Option<UnixMs>, pub degradation: Option<Degradation>,
    pub consecutive_failures: u32, pub next_check_at: Option<UnixMs>, pub rotation_prev_egress: Option<IpAddr>,
    pub last_hint_at: Option<UnixMs> }
impl Route {
    pub fn begin(&mut self, rotating: bool);  pub fn stopped(now: UnixMs) -> Self;
    pub fn is_healthy(&self, running: bool, now: UnixMs) -> bool;
    pub fn succeeded(&mut self, ok: ProbeOk, now: UnixMs) -> bool;        // false = drift / rotation kept IP
    pub fn failed(&mut self, err: &ProbeError, now: UnixMs, timing: &Timing) -> Next;
    pub fn degrade(&mut self, reason: Degradation, message: String, quarantined: bool, now: UnixMs);
    pub fn process_failed(&mut self, message: String, now: UnixMs);
    pub fn disabled(&mut self, now: UnixMs);
    pub fn hint(&mut self, line: &str, now: UnixMs, timing: &Timing) -> Option<Duration>;
}
pub fn ms(d: Duration) -> UnixMs;
```

## `manager` — `ProxyManager` (implements `ProxyOps`)

```rust
pub struct ProxyProfile { pub id: String, pub name: String, pub country: Option<String> /* ISO, name or flag */,
    pub group_id: Option<String>, pub profile: vpnte_profiles::model::Profile,
    pub device: Option<ClientDevice> /* own; None = EngineChoice::device */,
    pub engine: EnginePref /* own; Auto = EngineChoice::pref */,
    pub status: ServerStatus /* healthStatus, else ping status */, pub ping_ms: Option<u32>,
    pub health_latency_ms: Option<u32>, pub health_reason: Option<String>, pub last_checked_at: Option<UnixMs>,
    pub enabled: bool, pub removed: bool /* gone from its subscription */ }
impl ProxyProfile { pub fn usable(&self) -> bool }                 // enabled && !removed
pub struct EngineChoice { pub pref: EnginePref, pub device: ClientDevice }   // Default
impl EngineChoice { pub fn for_profile(self, p: &ProxyProfile) -> EngineChoice }  // the server's own win
#[async_trait::async_trait]
pub trait ProfileSource: Send + Sync {
    fn profiles(&self) -> Vec<ProxyProfile>;
    fn active_vpn_profile_id(&self) -> Option<String>;
    fn engine_choice(&self) -> EngineChoice;
    async fn check_group_health(&self, group_id: &str) -> AppResult<GroupHealth>; // error kind -> HTTP status
}
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProxySnapshot { pub instances: Vec<InstanceStatus>, pub aggregate: Aggregate,
    pub control_url: Option<String>, pub at: UnixMs }
impl ProxySnapshot { pub fn refreshed(&self, now: UnixMs) -> ProxySnapshot }  // readiness re-derived at `now`
#[derive(Clone)] pub struct ProxyManager;              // cheap clone (Arc inside); Debug shows no internals
impl ProxyManager {
    pub fn new(source: Arc<dyn ProfileSource>, resources: &Path) -> Self; // `resources` = DataDirs::resources
    pub fn snapshot(&self) -> watch::Receiver<ProxySnapshot>;
    pub async fn shutdown(&self);              // every slot stopped; later starts are 503
}
pub fn degradation_msg(reason: Degradation) -> Msg;   // proxies.degradation.<camelCase>  (row tooltip)
```

Behaviour: one sing-box per slot, config over stdin, ready when the slot port accepts within 5 s (no
`sing-box check`); every upstream host name is resolved by the app with
`vpnte_core::resolve::resolve_server` (direct DoH / TCP chain, then the OS resolver, then the name's last
known address, which is logged and not cached; IPv4 first, block-page answers refused, live answers cached
5 min) and pinned; profiles the main tunnel would run on Xray get a per-slot
Xray child behind a SOCKS5 bridge (either child exiting fails the slot); engine selection =
`vpnte_engine::xray_config::select_engine(profile, pref)` like the main tunnel. Probes: first right after
readiness (+ slot%5 × 100 ms), then every ~45 s; `Transport` failures retry after 15/30/60 s and the 4th
auto-disables the slot (re-checked under the slot guard, so a forced probe that healed the route in between
keeps it); a `Service` failure does not
count, resets the counter and re-probes after 60 s; a refused listener kills the engine; drift, a rotation that
kept its exit, or a duplicate exit (the lowest other slot on that IP keeps it) park the slot until a start,
rotate or forced probe. Results that land after a stop or restart of the slot are dropped. At most 3 probes run at once.
Engine exits are not restarted. Auto-picks: country by ISO code / alias / name (whole words, never
substrings); among the matches the first in list order of the best rank, ranked by: not used by another slot,
then not the main VPN's server, then online < unknown < offline (so the main VPN's server still beats a server
another slot already runs); rotation moves round-robin to the next profile of the best rank (with no other
profile it restarts the current one).
Engine output is logged redacted, at most one warning per slot per 30 s; no engine log files.

## `control` — local control API

```rust
pub const ENV_CONTROL_PORT: &str = "VPNTE_CONTROL_PORT";   // server side; set = that port, no fallback
pub const TOKEN_HEADER: &str = "x-vpnte-control-token";    // or `Authorization: Bearer <token>`
pub const TOKEN_FILE: &str = "external-proxy-control-token";              // "<64 hex>\n"
pub const ENDPOINT_FILE: &str = "external-proxy-control-endpoint.json";   // `Endpoint`, pretty + "\n"
pub struct ControlConfig { pub dir: PathBuf /* data root */, pub port: u16, pub fallback: bool }
impl ControlConfig { pub fn from_env(dir: impl Into<PathBuf>) -> Self }   // 17873 + ephemeral fallback
pub enum ServeError { Token(io::Error), Bind { port: u16, source: io::Error } }   // thiserror
impl From<ServeError> for AppError;          // Internal; proxies.control.tokenFailed | bindFailed {port}
pub struct ControlServer;
impl ControlServer {
    pub async fn start(ops: Arc<dyn ProxyOps>, config: ControlConfig, cancel: CancellationToken)
        -> Result<ControlServer, ServeError>;   // token file, exclusive bind, ops.set_control_port, endpoint file
    pub fn port(&self) -> u16;  pub fn url(&self) -> String;
    pub fn token_file(&self) -> &Path;  pub fn endpoint_file(&self) -> Option<&Path>;
    pub async fn join(self);                    // after `cancel` fired
}
pub struct ControlToken;   // Clone + Eq; Debug hides the value
impl ControlToken { pub fn generate() -> io::Result<Self>; pub fn as_str(&self) -> &str;
                    pub fn matches(&self, provided: &str) -> bool }      // constant time; "" never matches
pub struct Endpoint { pub host: String, pub port: u16, pub url: String, pub token_file: PathBuf, pub updated_at: UnixMs }
impl Endpoint { pub fn new(dir: &Path, port: u16) -> Self }
pub fn read_token(path: &Path) -> Option<String>;              // trimmed; None when missing / blank
pub fn is_mutation_path(path: &str) -> bool;                   // the 10 POST-only paths
pub fn is_trusted_host(host: Option<&str>, port: u16) -> bool; // "127.0.0.1:<p>" | "localhost:<p>"
```

Endpoints (optional prefix `/api/external-proxy`; `?format=text` or `?text=1` = plain-text answers): GET
`/status` `/` `/instances` `/list`; POST `/start` `/rotate` `/connect` `/trigger` `/stop` `/connect-profiles`
`/healthcheck` `/profiles/healthcheck` `/instances/prewarm` `/instances/status-batch`. The lease endpoints
`/instances/reserve|renew|release` are gone (owner decision of 12.11.2026): like any unknown path they answer
405 to POST and 404 to GET. Pipeline: Host guard (421) → OPTIONS 204 → method (405) → token
(401) → body (≤ 64 KiB, else 413; JSON object or blank) → endpoint; errors are
`{"ok":false,"error":<code>,"detail":<text>}`. A path that is not an endpoint is 405 for any method but GET and
a JSON 404 `not-found` for GET (no token needed: nothing is served there); a malformed request is 400
`bad-request`; a panicking operation is 500. The client gets 10 s to send its request and 10 s to take the
answer; the operation itself has no deadline (a rotate or prewarm takes seconds). One request per connection,
≤ 64 connections at once.

`control::client` (blocking `std::net`, used by the CLI):

```rust
pub const ENV_CONTROL_URL: &str = "VPNTE_CONTROL_URL";  pub const ENV_CONTROL_TOKEN: &str = "VPNTE_CONTROL_TOKEN";
pub struct ControlUrl;   // Display "http://host:port[/prefix]"; only loopback http (127.0.0.1 / localhost)
impl ControlUrl { pub fn local_default() -> Self; pub fn parse(raw: &str) -> Option<Self>; pub fn port(&self) -> u16;
    pub fn request(&self, method: &str, path_and_query: &str, token: Option<&str>, timeout: Duration) -> io::Result<Reply> }
pub fn discover(endpoint_file: &Path) -> Option<ControlUrl>;
pub struct Reply { pub status: u16, pub body: String }
```

CLI `vpnte_proxy` (`src/bin/vpnte_proxy/main.rs`; shipped as `vpnte-proxy.exe`): `vpnte-proxy [ACTION]
[TARGET] [PORT] [SLOT] [-Json]` or named `-Action/-Target/-Port/-Slot/-Json`; actions start, rotate,
connect, trigger, stop, status, instances, list, profiles-health. Exit 0 ok, 1 API / token error, 2 usage.
Finds the API through `VPNTE_CONTROL_URL`, the endpoint file, then 127.0.0.1:17873 (liveness check: `GET
/status` with a 2 s timeout; after a 401 one retry when the token came from the token file, which a restarted
app rewrites; a 401 never starts the app); when the API is down it starts `VPN Tunnel Enforcer.exe` next to
itself (as the current user, with null stdio and without passing the CLI's own standard handles, so a caller
that captures the CLI's output is not held until the app exits) and waits up to 15 s. The request itself has a
60 s timeout.

## Elevation

Nothing in this crate needs elevation: slots and the control API listen on 127.0.0.1, the engines run as the
user, the token / endpoint files go to the data root with a user-only DACL. A provider's `tls.spoof` /
`tls.spoof_method` (sing-box needs administrator rights for them) leave an unelevated slot's config
(`vpnte_engine::singbox_config::gate_spoof`, audit item 18): the slot runs without them and its
`InstanceStatus::notice` says so; an elevated process keeps them. Under the `asInvoker` privilege model
nothing here returns `ErrorKind::Permission` and nothing belongs in the helper service. The CLI never elevates,
starts the app as the current user and never relaunches it on a 401. Tests: none is `#[ignore]`d.

## i18n keys and events

- `proxies.error.{badRequest,notFound,conflict,unavailable,upstream,engine}` `{{detail}}` —
  `AppError::from(ProxyError)`.
- `proxies.control.tokenFailed`, `proxies.control.bindFailed` `{{port}}` — `AppError::from(ServeError)`.
- `proxies.degradation.<camelCase Degradation>` — `degradation_msg` (the UI names `Health` states
  with its own texts).
- `proxies.slot.spoofDropped` `{{name}}` — `InstanceStatus::notice` of a slot that runs without the
  provider's TLS spoof (same words as the main tunnel's `tunnel.runtime.spoofDropped`).
- Register `vpnte_proxies::LOCALES` at start.
- State is pushed only through `ProxyManager::snapshot()` (a `watch`, sent when something visible changed).
  Readiness also expires with the clock: call `ProxySnapshot::refreshed(now)` on a UI timer (≤ 60 s) instead
  of trusting an old `ready`. There are no other events.

## Not implemented / dropped

- PID files, orphan cleanup, staged engine copies, per-exe firewall rules (children run in kill-on-close Jobs,
  configs go over stdin); `sing-box check` before a start; HTTP keep-alive.
- The lease API (`/instances/reserve|renew|release`, "Buyer Search" / "PSR client" leases with their 409
  guards and the lease-only degradation): removed by the owner's decision of 12.11.2026 (owner question 6,
  package p-lease).
- Compatibility copies of the control files in the Electron dir.
- Automatic restart of an exited engine (a manual start or rotate is the recovery).
- Not exercised by tests: a real Xray child as a slot (its config passed `xray run -test`), real public IP
  services and DoH servers (stubs only; the tunnelled-5xx rule is covered by the pure classifier test), the CLI
  against a live app, the fixed port 17873. The CLI's app start (`launch`) has no automated test: it was run
  once by hand against a fake `VPN Tunnel Enforcer.exe` (closing pass, `progress/_close.md`).

Delivery is outside this crate and done: `cargo xtask dist` stages `vpnte_proxy.exe` as `vpnte-proxy.exe` next
to `VPN Tunnel Enforcer.exe`, and the installer ships the `vpnte-proxy.cmd` / `.ps1` compatibility shims
(`installer/shims/`) that forward to it.

## Needs from other crates

- app: implement `ProfileSource` over the server list; build `ProxyManager` and start `ControlServer` at boot
  (see Wiring); `stop_all(StopReason::VpnStop)` when the main VPN disconnects;
  `shutdown()` on exit; register `LOCALES` (today `crates/app/src/svc_core` lists the fragment files itself).
- tunnel (main TUN config): route the bundled `sing-box.exe` / `xray.exe` processes to `direct-out`, else slot
  traffic hops through the main VPN server.
- UI: render `ProxySnapshot`; a "restart" of a failed slot passes its `profile_id` explicitly.
- app (`api_dashboard/proxies.rs` `row()`): show `InstanceStatus::notice` as the row's tooltip when
  there is no error (today the tooltip shows the error or the health word only).
