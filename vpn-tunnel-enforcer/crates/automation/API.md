# vpnte-automation — API map for dependent crates

Scheduler, profile rotation, AutoPilot, adaptive bypass, reversible Soft-mode tweaks and browser /
location hardening. The only consumer is `vpnte-app`: it implements the four host traits over the
tunnel, profiles and probes, spawns the three tasks and wires the lifecycle hooks below.

- **Generic, not `dyn`.** `Coordinator`, `RotationProfiles`, `AdaptiveHost` and `AutoPilotEnv`
  return `impl Future + Send` (RPITIT, no `async-trait`): implement them on concrete app types and
  hold `Arc<AppCoordinator>` etc. Every future must be `Send` (the tasks run under `tokio::spawn`).
- **Three long-running tasks**, each `async fn run(&self, cancel: CancellationToken)`, one runner
  each: `Scheduler::run`, `Rotation::run`, `Adaptive::run`. They own their state; the UI reads
  `watch` snapshots. AutoPilot is a one-shot `run(trigger)`.
- **Tweaks / hardening are blocking cores with async facades** (`apply` / `rollback` / `status`
  run on tokio's blocking pool; `*_blocking` variants for a thread that may block). One
  `tweaks::Journal` per process is shared by Soft mode, browsers and location.
- **No user text is formatted here.** Results and errors carry `Msg` (keys under `automation.`);
  notices go out through `Coordinator::notify(category, Notice)`; `tracing` lines are English and
  never contain profile ids, URLs, credentials or proxy values.
- **Documents** (`vpnte_core::store::Store<T>`, data dir root): `schedules.json` (`Schedules`),
  `rotation.json` (`RotationConfig`), `adaptive.json` (`AdaptiveDoc`, `HOLDS_SECRETS`: DPAPI-sealed
  HMAC key), `tweaks.json` (`TweakDoc`, opened by `Journal::open`), `hardening.json`
  (`HardeningDoc`, legacy marker). Each file has exactly one `Store` in the process.
- **Elevation.** Only browser policies and the machine part of location privacy need it (HKLM):
  unelevated, `Browsers::apply`, `Browsers::rollback` (with journalled values) and
  `Location::apply` return `Err(Permission, "automation.hardening.needsAdmin")` before reading
  anything; `Location::rollback` restores the HKCU value and keeps the HKLM records for a retry.
  Everything else (scheduler, rotation, AutoPilot, adaptive bypass incl. the Win32 network identity,
  Soft mode) runs as the signed-in user. Under CONTRACT §1 the HKLM work belongs in the helper
  service `vpnte-service`; the code is not adapted yet (a `noadmin-*` follow-up): today the app
  calls it in-process and shows "unavailable" on `Permission`.

## Crate root
```rust
pub const LOCALES: &[(&str, &str)];   // (ru_json, en_json) per package, file-name order:
                                      // automation-adaptive, -hardening, -sched, -tweaks
```
Register with the other crates' layers at start, after the UI's base layer:
`vpnte_base::i18n::init(&[ui_layers, .., vpnte_automation::LOCALES, ..].concat())`. Every key is
under `automation.` (`adaptive`, `autopilot`, `coordinator`, `hardening`, `rotation`, `scheduler`,
`tweaks`); a test pins `LOCALES` to the files in `locales/`.

## `coordinator` — the tunnel as automation sees it (the app implements it)
```rust
use vpnte_automation::coordinator::*;

pub struct RuntimeId(pub u64);                         // Copy + Ord + Hash; new on every engine (re)start
pub struct ProxyEndpoint { pub addr: HostPort, pub kind: ProxyKind, pub creds: Option<Creds> }
pub enum ConnectRequest {
    Direct { profile_id: String },
    LocalProxyHard { endpoint: Option<ProxyEndpoint> },  // None: resolve like a manual connect
    Soft { endpoint: Option<ProxyEndpoint> },            // (settings override, else detection)
}
impl ConnectRequest { pub fn kind(&self) -> SessionKind; }
pub enum SessionKind { Direct, LocalProxyHard, Soft }
pub struct SessionInfo { pub kind: SessionKind, pub owner: Owner, pub profile_id: Option<String>,
                         pub runtime_id: RuntimeId, pub mode: AdaptiveMode }
pub enum ConnectOutcome { Connected, AlreadyConnected }
pub enum OpError { Conflict, Cancelled, Timeout, ProfileUnavailable, NoLocalProxy, Failed(AppError) }
impl OpError { pub fn reason(&self) -> Msg; }          // automation.coordinator.* | errors.* | the inner msg
impl From<OpError> for AppError;                       // Conflict/ProfileUnavailable/NoLocalProxy → Conflict
pub enum SwitchError { NotStarted(OpError), Failed { reason: OpError, restored_previous: bool } }
pub enum StopCause { Requested(Owner), Fault, Shutdown }   // Requested(Owner::Manual) = the user
pub enum LifecycleEvent {
    Started { owner: Owner, runtime_id: RuntimeId, kind: SessionKind, profile_id: Option<String>, mode: AdaptiveMode },
    Stopped { owner: Owner, runtime_id: RuntimeId, cause: StopCause },
    Fault { runtime_id: RuntimeId, fault: OutboundFault },
    NetworkChanged,
}
pub enum NoticeCategory { ScheduleTriggered, ProfileRotation, ConnectionError }

pub trait Coordinator: Send + Sync + 'static {
    fn session(&self) -> Option<SessionInfo>;
    fn busy(&self) -> bool;                            // a lifecycle operation is in flight
    fn connect(&self, owner: Owner, req: ConnectRequest) -> impl Future<Output = Result<ConnectOutcome, OpError>> + Send;
    fn disconnect(&self, owner: Owner) -> impl Future<Output = Result<(), OpError>> + Send;
    fn switch_profile(&self, owner: Owner, profile_id: &str) -> impl Future<Output = Result<(), SwitchError>> + Send;
    fn adaptive_restart(&self, owner: Owner, mode: AdaptiveMode, sibling: Option<&str>)
        -> impl Future<Output = Result<RuntimeId, OpError>> + Send;
    fn events(&self) -> broadcast::Receiver<LifecycleEvent>;
    fn notify(&self, category: NoticeCategory, notice: Notice);  // in-app always; toast if the category is on
}
```
The contract automation relies on (implement it exactly):
- Admission by `Owner` order: a strictly higher owner pre-empts a running lower operation; an equal
  or lower one gets `Conflict`. Dropping a returned future cancels the request (finish or roll back
  natively; no half-started engine).
- `connect`: an equal session → `AlreadyConnected` and a higher caller takes the session over; a
  different session is switched only if `owner >= session.owner`. `disconnect` without a session →
  `Ok`; with a higher-owned session → `Conflict`.
- `switch_profile`: protected restart, egress + tunnel proof, selection committed only on success,
  owner kept; failure → previous profile restarted (`Failed { restored_previous: true }`); double
  failure → full stop with protection rolled back (`false`); refused or failed before the tunnel was
  touched → `NotStarted` (previous session intact).
- `adaptive_restart` (`Owner::AdaptiveRetry`): protected restart in `mode`, on `sibling` when given;
  returns the new runtime only after its fresh egress was proven and **after** emitting its
  `Started { runtime_id, mode }`.
- Restarts that continue a session (crash auto-restart, settings restart, adaptive restart, switch)
  keep `SessionInfo::owner`. `Started` fires for every engine (re)start (a switch emits only
  `Started`); `Stopped` means no session afterwards; `Stopped { cause: Fault }` = restarts exhausted.
- `Fault` events come from the engine log classifier; `NetworkChanged` from winnet's
  `watch_network` (physical network changed, debounced). The scheduler and adaptive bypass subscribe
  once each when their task starts; events sent before that are not replayed.
- `notify`: the app honours the user's `notifications.*` toggles per category; the in-app list
  always gets the notice.

## `schedule` — pure weekly-window algebra (jiff; the zone is always passed in)
```rust
pub struct HhMm(u16);                 // Copy + Ord + Hash; minutes since midnight; Display "HH:MM";
                                      // serde: string, read with the lenient rules
impl HhMm {
    pub const fn new(hour: u8, minute: u8) -> Option<Self>;
    pub const fn minutes(self) -> u16;  pub const fn hour(self) -> i8;  pub const fn minute(self) -> i8;
    pub fn parse_lenient(text: &str) -> Option<Self>;   // old parseInt rules: stored / imported values only
}
impl FromStr for HhMm { type Err = InvalidTime; }      // strict UI input ^([01]?\d|2[0-3]):([0-5]\d)$
pub struct InvalidTime;                                // thiserror
pub enum ScheduleMode { Hard, Soft, Direct }           // serde "hard" | "soft" | "direct"
pub struct ScheduleEntry {                             // serde camelCase
    pub id: String, pub name: String, pub enabled: bool,
    pub days: Vec<u8>,                                 // weekday of the window START, 0 = Sunday … 6
    pub start_time: HhMm, pub end_time: HhMm,          // end < start: overnight; end == start: 24 h
    pub profile_id: String,                            // Direct only
    pub mode: ScheduleMode,
}
pub struct Window { pub start: Timestamp, pub stop: Timestamp, pub entry: usize }      // [start, stop)
pub struct Run { pub start: Timestamp, pub stop: Timestamp, pub first: usize, pub last: usize } // merged windows
impl Run { pub fn contains(&self, t: Timestamp) -> bool; }
pub enum NextEvent { Start { at: Timestamp, entry: usize }, Stop { at: Timestamp, entry: usize } }
impl NextEvent { pub fn at(&self) -> Timestamp; }
pub fn windows(e: &ScheduleEntry, idx: usize, tz: &TimeZone, now: Timestamp, days_ahead: i32) -> Vec<Window>;
pub fn is_active(e: &ScheduleEntry, tz: &TimeZone, t: Timestamp) -> bool;
pub fn active_entries(entries: &[ScheduleEntry], tz: &TimeZone, t: Timestamp) -> Vec<usize>;
pub fn active_run(entries: &[ScheduleEntry], tz: &TimeZone, now: Timestamp) -> Option<Run>;
pub fn next_event(entries: &[ScheduleEntry], tz: &TimeZone, now: Timestamp) -> Option<NextEvent>;
```
DST: a local time in a gap moves forward by the gap, a repeated time takes the earlier instant (the
old `Date` behaviour). Runs are merged over −8 … +8 days.

## `scheduler` — `schedules.json` and the reconcile task
```rust
use vpnte_automation::scheduler::*;

pub struct Schedules { pub schedules: Vec<ScheduleEntry>, pub suppressed_at: Option<UnixMs> } // Document v1
impl Schedules { pub fn from_legacy(legacy: &Value) -> (Schedules, Vec<Msg>); } // old scheduler.json;
                                                       // Msg = automation.scheduler.importSkipped {name}
pub struct ScheduleDraft { pub name: String, pub enabled: bool, pub days: Vec<u8>, pub start_time: HhMm,
                           pub end_time: HhMm, pub profile_id: String, pub mode: ScheduleMode }
impl From<ScheduleEntry> for ScheduleDraft;            // edit form prefill
pub enum Wake { Edited, Resume, TimeChanged }
pub enum BoundaryKind { Start, Stop }
pub struct Upcoming { pub kind: BoundaryKind, pub at: UnixMs, pub schedule_id: String }
pub struct SchedulerStatus {                           // Default + Clone + PartialEq (watch snapshot)
    pub ready: bool,                                   // first pass after start done
    pub run: Option<(UnixMs, UnixMs)>,                 // active merged run
    pub suppressed: bool,                              // the user stopped / took over this run by hand
    pub connecting: bool, pub retry_at: Option<UnixMs>, pub next: Option<Upcoming>,
}
pub struct Scheduler<C: Coordinator>;
impl<C: Coordinator> Scheduler<C> {
    pub fn new(store: Arc<Store<Schedules>>, coord: Arc<C>) -> Self;
    pub fn list(&self) -> Vec<ScheduleEntry>;
    pub fn create(&self, draft: ScheduleDraft) -> AppResult<ScheduleEntry>;            // Validation errors
    pub fn update(&self, id: &str, draft: ScheduleDraft) -> AppResult<ScheduleEntry>;  // unknown id: Validation notFound
    pub fn delete(&self, id: &str) -> AppResult<()>;                                   // unknown id: no-op
    pub fn next_event(&self) -> Option<Upcoming>;                                      // system zone, now
    pub fn status(&self) -> watch::Receiver<SchedulerStatus>;
    pub fn wake(&self, reason: Wake);
    pub async fn run(&self, cancel: CancellationToken);                                // the task
}
```
Behaviour the app and UI see:
- Connects as `Owner::Schedule`: `Direct` → `ConnectRequest::Direct`, `Hard` / `Soft` →
  `LocalProxyHard` / `Soft { endpoint: None }` (the profile id is not used). A run whose session is
  held by `Manual` / `Recovery` is left alone; a manual start / stop inside a run suppresses it (also
  across restarts) until it ends. Only its own session is stopped at the run's end.
- Failed connects retry after 60 / 120 / 300 / 600 / 600 … s (`retry_at`); `Conflict` retries quietly.
- Notices: `ScheduleTriggered` Info, title `automation.scheduler.title`, body `.started` / `.stopped`
  {name}; `ConnectionError` Warn on the first failure of a run, title `.connectFailed` /
  `.profileUnavailable` {name}, body = the coordinator's reason.
- Edits through the API wake the task itself; call `wake(Edited)` after an import rewrote the
  file, `wake(Resume)` on winnet `PowerEvent::Resumed` / `SessionUnlocked`, `wake(TimeChanged)` on a
  clock change if the app learns of one (the 60 s re-check covers it otherwise; a zone change
  applies within ≤ 5 min, jiff's system-zone cache).
- `create` / `update` errors (`Validation`): `automation.scheduler.invalidName` (empty or > 200
  chars), `.invalidDays` (a day > 6), `.profileRequired` (Direct without profile), `.notFound`.
  Empty `days` is allowed (never active); days are stored sorted without duplicates.

## `rotation` — `rotation.json`, candidate pick, timer, "rotate now"
```rust
use vpnte_automation::rotation::*;

pub const INTERVAL_MINUTES: (u32, u32) = (5, 1440);
pub fn clamp_interval(minutes: f64) -> u32;            // rounded into the range; NaN / ∞ → 5
pub enum RotationOrder { Sequential, Random }          // serde lowercase, default Sequential
pub struct RotationConfig {                            // Document "rotation.json" v1, serde camelCase
    pub enabled: bool, pub interval_minutes: u32,      // default 30
    pub order: RotationOrder, pub profile_ids: Vec<String>,   // deduplicated, in order
    pub current_index: usize,                          // advances only on success
    pub next_rotation_at: Option<UnixMs>,              // a future value survives restarts
}
impl RotationConfig { pub fn from_legacy(legacy: &Value) -> RotationConfig; }  // old profile-rotation.json
pub struct RotationPatch { pub enabled: Option<bool>, pub interval_minutes: Option<f64>,
                           pub order: Option<RotationOrder>, pub profile_ids: Option<Vec<String>> }
pub fn candidate_order(len: usize, current: usize, order: RotationOrder, rng: &mut fastrand::Rng) -> Vec<usize>;
pub enum ProfileStatus { Unknown, Online, Offline }
pub struct ProfileFacts { pub id: String, pub name: String, pub enabled: bool, pub archived: bool,
                          pub has_outbound: bool, pub status: ProfileStatus, pub checked_at: Option<UnixMs> }
pub trait RotationProfiles: Send + Sync + 'static {   // the app: profile store + offline ping
    fn facts(&self, id: &str) -> Option<ProfileFacts>;
    fn all(&self) -> Vec<ProfileFacts>;                // store order (seeds an empty list)
    fn reachable(&self, id: &str) -> impl Future<Output = bool> + Send;   // offline ICMP / TCP ping
    fn select(&self, id: &str) -> AppResult<()>;      // selection without a session; refuse unusable
}
pub enum RotationTrigger { Timer, User }
pub enum RotationOutcome {                             // Clone + PartialEq
    Rotated { profile_id: String }, NothingToRotate, NotDirect, NoProfiles, NoneAvailable,
    NotStarted { reason: Msg }, Aborted { reason: Msg },
    Failed { profile_id: String, reason: Msg, restored_previous: bool },
}
impl RotationOutcome { pub fn message(&self) -> Option<Msg>; }  // UI text after "rotate now"; None = a notice said it
pub struct Rotation<C: Coordinator, P: RotationProfiles>;
impl<C: Coordinator, P: RotationProfiles> Rotation<C, P> {
    pub fn new(store: Arc<Store<RotationConfig>>, coord: Arc<C>, profiles: Arc<P>) -> Self;
    pub fn config(&self) -> RotationConfig;
    pub fn subscribe(&self) -> watch::Receiver<u64>;  // store generation: re-read config() (countdown, index)
    pub fn set_config(&self, patch: RotationPatch) -> AppResult<RotationConfig>;  // store write errors only
    pub async fn rotate(&self, trigger: RotationTrigger) -> RotationOutcome;     // single flight
    pub async fn run(&self, cancel: CancellationToken); // the timer task
}
```
- A live rotation moves a **Direct** session through `Coordinator::switch_profile(Owner::Rotation, ..)`
  under a 120 s deadline; Local-proxy / Soft sessions are never converted (`NotDirect`). Without a
  session "rotate now" only calls `RotationProfiles::select` (after an offline `reachable` probe;
  an "online" status younger than 2 min skips the probe).
- A real config change restarts the countdown and cancels a rotation in flight; an unchanged patch is
  a no-op; enabling with an empty list seeds it with every usable profile.
- Notices: success `ProfileRotation` Info, title `automation.rotation.title`, body `.switched`
  {name}; failures `ConnectionError`: `.failedRestored` (Warn), `.failedUnprotected` (Error),
  `.failedNotStarted` (Warn). "Busy" (`NotStarted { reason: .busy }`) is quiet.

## `adaptive` — adaptive bypass (verify every tunnel start, escalate, learn)
```rust
use vpnte_automation::adaptive::*;

pub const MAX_SIBLINGS: usize = 2;
pub struct ProfileView {                               // never logged: the outbound holds credentials
    pub id: String,
    pub outbound: Value,                               // emit_singbox with EmitPolicy::default(); chain = array
    pub client_device: Option<ClientDevice>, pub client_fingerprint: Option<String>, pub engine: Engine,
}
pub struct Sibling { pub profile: ProfileView, pub latency_ms: Option<u32> }
pub struct Capabilities { pub tls: bool, pub mtu: bool, pub external: bool, pub reason: Option<Msg> }
impl Capabilities { pub fn allows(&self, mode: AdaptiveMode) -> bool; }
pub fn capabilities(kind: SessionKind, profile: Option<&ProfileView>) -> Capabilities;
pub fn next_mode(mode: AdaptiveMode, caps: &Capabilities) -> Option<AdaptiveMode>; // Baseline → Tls → Mtu
pub fn family(outbound: &Value) -> String;             // "type/reality-flag/transport"
pub fn order_siblings(active: &ProfileView, candidates: Vec<Sibling>) -> Vec<Sibling>; // other family first
pub enum Phase { Idle, Connecting, Verifying, Adapting, Connected, Failed }   // serde kebab-case
pub struct AdaptiveStatus { pub phase: Phase, pub mode: AdaptiveMode, pub external: bool, pub attempts: u8,
                            pub message: Msg, pub reason: Option<Msg>, pub updated_at: UnixMs } // watch snapshot
impl AdaptiveStatus { pub fn idle(now: UnixMs) -> Self; }
pub trait AdaptiveHost: Send + Sync + 'static {        // the app
    fn profile(&self, id: &str) -> Option<ProfileView>;
    fn siblings(&self, id: &str) -> Vec<Sibling>;      // usable same-group profiles, store order, `id` excluded
    fn probe(&self, cancel: CancellationToken) -> impl Future<Output = Option<Duration>> + Send;
        // one tunnel HTTPS probe through the OS stack (probes crate, cache skipped, 1 retry); prompt on cancel
    fn select(&self, id: &str) -> AppResult<()>;      // commit a verified sibling as the selection
    fn abandon(&self) -> impl Future<Output = ()> + Send;
        // stop the engine, keep the kill switch (tunnel stop with preserve_protection), Stopped { cause: Fault }
    fn network_identity(&self) -> impl Future<Output = Option<NetworkSnapshot>> + Send; // default identity::read()
}
pub struct Adaptive<C: Coordinator, H: AdaptiveHost>;
impl<C: Coordinator, H: AdaptiveHost> Adaptive<C, H> {
    pub fn new(coord: Arc<C>, host: Arc<H>, settings: Arc<Store<Settings>>, store: Arc<Store<AdaptiveDoc>>) -> Self;
    pub fn status(&self) -> watch::Receiver<AdaptiveStatus>;
    pub async fn begin(&self, kind: SessionKind, profile: Option<ProfileView>) -> AdaptiveMode; // start in this mode
    pub fn start_failed(&self, reason: Option<Msg>);  // Some = start error shown; None = cancelled → Idle
    pub fn restart_mode(&self, running: AdaptiveMode) -> AdaptiveMode;  // settings / crash restarts
    pub fn retry(&self) -> bool;                       // UI "retry": re-verify with a fresh budget; false = no tunnel
    pub fn reset_learning(&self) -> AppResult<()>;     // «Сбросить запомненные настройки сети»
    pub async fn run(&self, cancel: CancellationToken);  // the task
}
// adaptive::learning — `adaptive.json`
pub const TTL_MS: i64; pub const MAX_RECORDS: usize;  // 30 days, 24 records
pub struct LearnedRecord { pub mode: AdaptiveMode, pub learned_at: UnixMs, pub last_used_at: UnixMs,
                           pub expires_at: UnixMs }   // serde camelCase
pub struct AdaptiveDoc { pub secret: Option<Secret>, pub learning: BTreeMap<String, LearnedRecord> }
    // Document "adaptive.json" v1, HOLDS_SECRETS; keys "v3:<HMAC(network)>:<HMAC(profile)>"
pub fn compact(learning: &mut BTreeMap<String, LearnedRecord>, now: UnixMs);
pub struct Learning;                                   // used by Adaptive; public for tools / tests
impl Learning { pub fn open(store: Arc<Store<AdaptiveDoc>>) -> Self; pub fn enabled(&self) -> bool;
    pub fn key(&self, network: &NetworkSnapshot, profile: &ProfileView) -> Option<String>;
    pub fn lookup(&self, key: &str, usable: impl Fn(AdaptiveMode) -> bool, now: UnixMs) -> Option<AdaptiveMode>;
    pub fn learn(&self, key: &str, mode: AdaptiveMode, now: UnixMs); pub fn forget(&self, key: &str);
    pub fn clear(&self) -> AppResult<()>; }
// adaptive::identity — the physical network, without names or addresses in clear
pub struct NetworkSnapshot;                            // Debug "NetworkSnapshot(..)"
impl NetworkSnapshot { pub fn from_rows(rows: Vec<IdentityRow>) -> Option<Self>; }
pub struct IdentityRow { pub guid: String, pub mac: String, pub prefixes: Vec<String>, pub gateways: Vec<String> }
pub fn rows(adapters: &[Adapter], gateway_mac: impl Fn(u64, IpAddr) -> Option<String>) -> Vec<IdentityRow>;
pub async fn read() -> Option<NetworkSnapshot>;       // Win32 on the blocking pool, ≤ 3 s, unelevated
```
- Settings read: `adaptive_bypass` (off → `Baseline`, no learning, no escalation),
  `adaptive_bypass_server_fallback` (siblings), `stealth_mode` (seeds the first mode).
- Per tunnel start (Direct and local-proxy Hard; Soft is never verified): 20 s settle, then 2 of 3
  probes; on failure TLS compatibility → MTU 1280 (≤ 2 mode restarts) → up to 2 siblings; what
  worked is learned per (network, profile) for 30 days. A terminal failure is status `Failed` plus
  one `ConnectionError` Warn notice; the tunnel stays up unless a provisional sibling failed (then
  `abandon`). A `Started` the task did not ask for (user, switch, crash restart) supersedes the run.
- The learning key is DPAPI-sealed; when DPAPI, the store or the RNG fails, learning is off for the
  run and the connect still proceeds.

## `autopilot` — the launch-time planner (local-proxy Hard)
```rust
use vpnte_automation::autopilot::*;

pub enum AutoPilotTrigger { AppLaunch, UserRequest }  // UserRequest ignores the `autopilot` switch
pub enum AutoPilotMode { Off, External, Hard, Soft }   // serde lowercase
pub enum StepStatus { Ok, Warn, Fail, Info }           // serde lowercase
pub struct AutoPilotStep { pub label: Msg, pub before: Msg, pub after: Msg, pub status: StepStatus }
pub struct AutoPilotResult { pub ran_at: UnixMs, pub summary: StepStatus, pub mode: AutoPilotMode,
    pub title: Msg, pub message: Msg, pub changed: bool /* a tunnel was started */, pub steps: Vec<AutoPilotStep> }
pub struct Listener { pub host: String, pub port: u16, pub process: String }
pub trait AutoPilotEnv: Send + Sync + 'static {        // the app
    fn listeners(&self) -> Vec<Listener>;              // the monitoring listener table (loopback / wildcard)
    fn detect(&self) -> impl Future<Output = Option<ProxyEndpoint>> + Send;   // the probes local-proxy detection
    fn foreign_tunnels(&self) -> impl Future<Output = AppResult<Vec<String>>> + Send; // default: winnet foreign_tun
}
pub fn normalize_host(host: &str) -> &str;             // "::" | "::1" | "0.0.0.0" | "" → "127.0.0.1"
pub fn score(port: u16, process: &str) -> i32;         // well-known port +10, proxy-core name +5
pub fn rank_listeners(listeners: &[Listener]) -> Vec<(HostPort, &Listener)>;  // best first, deduplicated
pub struct Timing { pub tcp: Duration, pub handshake: Duration }   // Default 1200 / 3000 ms
pub struct AutoPilot<C: Coordinator, E: AutoPilotEnv>;
impl<C: Coordinator, E: AutoPilotEnv> AutoPilot<C, E> {
    pub fn new(coord: Arc<C>, env: Arc<E>, settings: Arc<Store<Settings>>,
               schedule: Option<watch::Receiver<SchedulerStatus>>) -> Self;
    pub fn with_timing(coord: Arc<C>, env: Arc<E>, settings: Arc<Store<Settings>>,
               schedule: Option<watch::Receiver<SchedulerStatus>>, timing: Timing) -> Self;
    pub async fn run(&self, trigger: AutoPilotTrigger) -> Option<AutoPilotResult>;  // None = skipped silently
}
```
- Runs only when `routing_mode == Hard && connection_mode == LocalProxy` (and, for `AppLaunch`, the
  `autopilot` switch is on); an `AppLaunch` run waits for the scheduler's `ready` and is skipped
  while a schedule run is active or connecting. It never stops a session, never writes settings.
- Decision order: a second concurrent run → "busy"; an existing session or a busy coordinator →
  "already active"; adapter list unreadable → Warn, no start; a foreign tunnel → `External`
  (observe only); endpoint = `proxy_override` (with `proxy_type`) → `detect()` → ranked
  listeners, each verified by a SOCKS5 / HTTP CONNECT handshake; then
  `connect(Owner::Autopilot, LocalProxyHard { endpoint: Some(..) })`.
- The app shows `title` / `message` once (toast + log) and logs each step as
  `AutoPilot: <label> → <after>`; every text is an `automation.autopilot.*` key.

## `tweaks` — the shared journal and Soft mode (per-user, no elevation)
```rust
use vpnte_automation::tweaks::{self, *};   // root re-exports: Backend, Feature, Journal, Record,
    // RollbackReport, Target, TweakError, TweakState, Val, DevTargets, Soft, SoftReport, SoftStatus, SoftSystem

// journal — one per process, shared by Soft, browsers and location; blocking, serialised by a mutex
pub enum Feature { SoftEnv, DevGit, DevGradle, DevStudio, BrowserWebRtc, LocationPrivacy } // serde kebab-case
pub fn tool_name(feature: Feature) -> &'static str;   // "Git", "Gradle", "Android Studio", …
pub enum EnvVar { HttpProxy, HttpsProxy, AllProxy, NoProxy }   // ALL; name() -> "HTTP_PROXY" …
pub enum GitKey { HttpProxy, HttpsProxy }                       // ALL; name() -> "http.proxy" …
pub enum BlockKind { Gradle, VmOptions }                        // file_name()
pub enum StudioOption { UseHttpProxy, ProxyHost, ProxyPort, ProxyTypeIsSocks } // ALL; name()
pub enum RegHive { Hkcu, Hklm }
pub enum Target {                                      // serde tag "t"
    Env { var: EnvVar }, Git { key: GitKey }, Block { kind: BlockKind, path: PathBuf },
    StudioOpt { path: PathBuf, option: StudioOption }, Lines { path: PathBuf, lines: Vec<String> },
    Reg { hive: RegHive, key: String, name: String },
}
impl Target { pub fn label(&self) -> String; }         // log-safe: file name only, never a value
pub enum Val { Absent, Sz(String), ExpandSz(String), Dword(u32), Text(String) }  // serde tag "t", content "v"
pub struct Record { pub feature: Feature, pub target: Target, pub baseline: Val, pub applied: Val, pub created: bool }
pub type RegAdmit = fn(RegHive, &str, &str, &Val) -> bool;      // load-time allow-list for Reg records
pub fn no_registry(_: RegHive, _: &str, _: &str, _: &Val) -> bool;  // admits none
pub struct TweakDoc { pub records: Vec<Record>, pub legacy_imported: bool }   // Document "tweaks.json" v1
pub trait Backend: Send + Sync {
    fn read(&self, target: &Target) -> io::Result<Val>;              // Err = cannot tell
    fn write(&self, target: &Target, value: &Val) -> io::Result<bool>;  // Absent removes; true = created container
    fn prune(&self, target: &Target) -> io::Result<()>;              // remove a container we created, if empty
    fn changed(&self, _targets: &[Target]) {}                        // once per batch (env broadcast)
}
pub enum TweakError { Unreadable(String, io::Error), Write(String, io::Error), NotVerified(String),
                      Journal(AppError), NotDetected(Feature), OtherUser }   // thiserror
impl TweakError { pub fn describe(&self) -> (ErrorKind, Msg); }     // automation.tweaks.* {target | tool}
impl From<TweakError> for AppError;
pub enum TweakState { Off, On, Drifted, Unknown }      // serde kebab-case; Unknown = not checked
pub struct RollbackReport { pub restored: Vec<Target>, pub kept_user_value: Vec<Target>, pub failed: Vec<Target> }
impl RollbackReport { pub fn is_complete(&self) -> bool; pub fn merge(&mut self, other: RollbackReport);
    pub fn failure_msg(&self) -> Option<Msg>; pub fn kept_msg(&self) -> Option<Msg>; }
pub struct Journal;
impl Journal {
    pub fn open(root: &Path, admit_reg: RegAdmit) -> Self;   // pass hardening::admit (see below)
    pub fn notice(&self) -> Option<Msg>;               // journalCorrupt (moved aside) / store read-only
    pub fn records(&self, feature: Feature) -> Vec<Record>;  pub fn is_applied(&self, feature: Feature) -> bool;
    pub fn apply(&self, backend: &dyn Backend, plan: &[(Feature, Target, Val)]) -> Result<(), TweakError>;
    pub fn rollback(&self, backend: &dyn Backend, features: &[Feature]) -> RollbackReport;
    pub fn status(&self, backend: &dyn Backend, feature: Feature) -> TweakState;
    pub fn legacy_imported(&self) -> bool;  pub fn adopt_legacy(&self, records: Vec<Record>) -> AppResult<usize>;
}

// soft — the Soft session: env variables + the opted-in dev targets, applied / rolled back together
pub const SOFT_FEATURES: [Feature; 4];                 // SoftEnv, DevGit, DevGradle, DevStudio
pub struct SoftSystem { pub env: UserEnv, pub git: Option<GitCli>, pub gradle_home: Option<PathBuf>,
    pub studio_root: Option<PathBuf>, pub broadcast: bool, pub check_user: bool }   // impl Backend
impl SoftSystem { pub fn current_user() -> Self; }    // HKCU\Environment, Git, GRADLE_USER_HOME|~\.gradle, %APPDATA%\Google
pub struct DevTargets { pub git: bool, pub gradle: bool, pub android_studio: bool }
    // serde camelCase + default: {"git","gradle","androidStudio"}; all off by default
pub struct SoftReport { pub applied: Vec<Feature>, pub not_detected: Vec<Feature>, pub dropped: RollbackReport }
pub struct SoftStatus { pub env: TweakState, pub git: TweakState, pub gradle: TweakState,
                        pub android_studio: TweakState }   // serde camelCase
#[derive(Clone)] pub struct Soft;
impl Soft {
    pub fn new(journal: Arc<Journal>, sys: SoftSystem) -> Self;
    pub async fn apply(&self, addr: HostPort, kind: ProxyKind, dev: DevTargets) -> AppResult<SoftReport>;
    pub async fn rollback(&self) -> AppResult<RollbackReport>;   // Err only if the blocking task panicked
    pub async fn status(&self) -> AppResult<SoftStatus>;
    pub fn is_applied(&self) -> bool;
    // blocking twins: apply_blocking(&HostPort, ProxyKind, DevTargets), rollback_blocking() -> RollbackReport,
    // status_blocking() -> SoftStatus
}
pub fn feature_name(feature: Feature) -> Msg;  pub fn feature_warning(feature: Feature) -> Msg;  // opt-in list

// building blocks (soft, legacy and hardening use them; the app normally does not)
endpoint::{proxy_url(&HostPort, ProxyKind) -> String /* socks5h://… | http://…, [v6] */, host_bare(&HostPort) -> String}
env::{NO_PROXY, plan, read, write, os_error(windows::core::Error) -> io::Error /* keeps "access denied" */}
git::{GitCli { pub exe: PathBuf, pub global_file: Option<PathBuf> }, GitCli::find() -> Option<GitCli>, plan}
block::{render, is_block, is_legacy_gradle_line, read, write, prune, read_lines, remove_lines, legacy_gradle_lines}
studio::{newest_install, settings_file, vmoptions_file, plan, read_option, write_option, prune}
user::ensure_session_user() -> Result<(), TweakError>  // E3: process user == session user, else OtherUser
legacy::{LegacySources { receipts_dir, gradle_props, studio_root } + current_user(),
         LegacyReport { adopted: usize, notice: Option<Msg> },
         import(journal: &Journal, backend: &dyn Backend, src: &LegacySources) -> LegacyReport}
```
- Every original value is read before anything is written (unreadable → nothing written); a refresh
  keeps the first baselines; rollback restores a value only while it still holds ours (a later user
  change is kept: `kept_user_value`); failed records stay journalled for the next rollback.
- `Soft::apply` writes `HTTP(S)_PROXY` / `ALL_PROXY` = the proxy URL and `NO_PROXY` to
  `HKCU\Environment` (new processes only; `WM_SETTINGCHANGE` broadcast) and the selected dev targets;
  proxy credentials are never written. A selected but missing tool is skipped (`not_detected`); an
  unreadable or malformed one fails the whole apply with nothing left half-applied. Errors:
  `automation.tweaks.unreadable` / `.writeFailed` / `.notVerified` {target}, `.otherUser`
  (Permission), journal store errors.
- Lifecycle: `apply` on a Soft start / refresh; `rollback` on stop, before a Hard / Direct start,
  at shutdown and in startup recovery when the settings are not Soft (Soft → re-apply = re-verify).
  Append `report.failure_msg()` to the stop result; show `report.kept_msg()` as info.

## `hardening` — browser policies and location privacy (registry, journalled)
```rust
use vpnte_automation::hardening::{self, *};

pub fn admit(hive: RegHive, key: &str, name: &str, value: &Val) -> bool;   // the journal's RegAdmit

// system — where values are read / written (blocking)
pub trait System: Backend {                            // tweaks::Backend for Target::Reg
    fn dir_exists(&self, path: &Path) -> bool;
    fn elevated(&self) -> bool;
    fn check_user(&self) -> Result<(), TweakError>;    // E3 (tweaks::user)
}
#[derive(Debug, Clone, Default)] pub struct WinSystem;   // vpnte_winnet::registry
impl WinSystem { pub fn new() -> Self; pub fn under(root: impl Into<String>) -> Self; } // under = HKCU sandbox (tests)

// browser — HKLM policies of the verified Chromium browsers
pub const WEBRTC_POLICY: (&str, &str);   // ("WebRtcIPHandlingPolicy", "disable_non_proxied_udp")
pub const DOH_POLICY: (&str, &str);      // ("DnsOverHttpsMode", "off")
pub enum Browser { Chrome, Edge, Brave, Yandex, Chromium, Vivaldi, Opera, Firefox }   // serde kebab-case
impl Browser { pub const ALL: [Browser; 8]; pub fn name(self) -> &'static str; pub fn verified(self) -> bool; }
pub struct BrowserDirs { pub local: Option<PathBuf>, pub roaming: Option<PathBuf> }   // Default
impl BrowserDirs { pub fn current_user() -> Self; }
pub fn plan(browser: Browser) -> Vec<(Feature, Target, Val)>;   // empty for unverified browsers
pub enum BrowserState { NotInstalled, NotVerified, Off, Protected, Drifted, Unknown, Failed { reason: Msg } }
    // serde tag "state", kebab-case
pub struct BrowserEntry { pub browser: Browser, pub state: BrowserState }
pub struct BrowserReport { pub browsers: Vec<BrowserEntry>, pub restart_required: bool, pub success: bool,
                           pub message: Option<Msg>, pub notes: Vec<Msg> }
#[derive(Clone)] pub struct Browsers;
impl Browsers {
    pub fn new(journal: Arc<Journal>, sys: Arc<dyn System>, dirs: BrowserDirs) -> Self;
    pub async fn apply(&self) -> AppResult<BrowserReport>;      // needs elevation
    pub async fn rollback(&self) -> AppResult<BrowserReport>;   // needs elevation when something is journalled
    pub async fn status(&self) -> AppResult<BrowserReport>;     // read-only, unelevated
    pub fn is_applied(&self) -> bool;
    // blocking twins: apply_blocking() / rollback_blocking() -> AppResult<BrowserReport>, status_blocking() -> BrowserReport
}

// location — session-scoped Windows location privacy
pub const CONSENT: (RegHive, &str, &str);  // HKCU …\CapabilityAccessManager\ConsentStore\location, "Value"
pub const POLICY_KEY: &str;                // HKLM SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors
pub const POLICY_VALUES: [&str; 2];        // DisableLocation, DisableWindowsLocationProvider
pub fn plan() -> Vec<(Feature, Target, Val)>;   // Sz("Deny"), Dword(1), Dword(1)
pub struct LocationStatus { pub ours: TweakState, pub user_denied: Option<bool>, pub policy_disabled: Option<bool> }
impl LocationStatus { pub fn os_denied(&self) -> Option<bool>; }   // user_denied || policy_disabled
pub fn rollback_failure_msg(report: &RollbackReport) -> Option<Msg>;   // automation.hardening.location.rollbackFailed
#[derive(Clone)] pub struct Location;
impl Location {
    pub fn new(journal: Arc<Journal>, sys: Arc<dyn System>) -> Self;
    pub async fn apply(&self) -> AppResult<LocationStatus>;     // needs elevation (+ E3 check)
    pub async fn rollback(&self) -> AppResult<RollbackReport>;  // no pre-check: unelevated, HKCU is restored
                                                                // and the HKLM records stay for a retry
    pub async fn status(&self) -> AppResult<LocationStatus>;
    pub fn is_applied(&self) -> bool;
    // blocking twins: apply_blocking() -> AppResult<LocationStatus>, rollback_blocking() -> RollbackReport,
    // status_blocking() -> LocationStatus
}

// legacy — one-time adoption of the old app's browser / location leftovers (no system writes)
pub struct HardeningDoc { pub legacy_imported: bool }  // Document "hardening.json" v1 (marker)
pub struct LegacySources { pub browser_manifest: Option<PathBuf>, pub location_manifest: Option<PathBuf> }
impl LegacySources { pub fn new(legacy_dir: &Path) -> Self; }   // <old dir>\browser-hardening\…, %ProgramData%\VPN-Tunnel-Enforcer\…
pub struct LegacyReport { pub adopted: usize, pub notices: Vec<Msg> }
pub fn import(journal: &Journal, root: &Path, sys: &dyn System, src: &LegacySources) -> LegacyReport;
```
- Browsers: Chrome / Edge / Brave / Yandex get `WebRtcIPHandlingPolicy` and `DnsOverHttpsMode` under
  `HKLM\SOFTWARE\Policies\…` (Yandex on both of its roots); Chromium, Vivaldi, Opera, Firefox are
  detected and reported `NotVerified` («Не проверено»), never touched. Each browser is one unit: a
  failure undoes that browser only (`Failed { reason }`). Policies take effect after a full browser
  restart (`restart_required`). Old values outside today's plan are rolled back on the next apply.
- Errors: unelevated apply → `Permission` `automation.hardening.needsAdmin` (before any read);
  location as another account → `Permission` `automation.tweaks.otherUser`; unreadable →
  `automation.hardening.location.unreadable` {hive}; write / read-back failure → `.location.failed`;
  a current value of a type the allow-list cannot hold → `Conflict` `.location.foreignValue`.
- Location is session-scoped: after a successful connect with `settings.location_privacy` →
  `apply()`; on disconnect, shutdown and startup recovery → `if is_applied() { rollback() }`, append
  `rollback_failure_msg(&report)` to the stop result. The setting is never rewritten from a result.

## Wiring in the app
```rust
use vpnte_automation::{adaptive::*, autopilot::*, hardening, rotation::*, scheduler::*, tweaks};

// --- once at start, after DataDirs, settings, logging and the app's coordinator (Arc<AppCoordinator>)
let journal = Arc::new(tweaks::Journal::open(&dirs.root, hardening::admit)); // NOT no_registry: that
notices.extend(journal.notice());                     // would drop (and delete) the hardening records
let soft = tweaks::Soft::new(journal.clone(), tweaks::SoftSystem::current_user());
let sys: Arc<dyn hardening::System> = Arc::new(hardening::WinSystem::new());
let browsers = hardening::Browsers::new(journal.clone(), sys.clone(), hardening::BrowserDirs::current_user());
let location = hardening::Location::new(journal.clone(), sys.clone());

// --- legacy import, before startup recovery; idempotent (own markers); on a blocking thread
let t = tweaks::legacy::import(&journal, &tweaks::SoftSystem::current_user(),
                               &tweaks::legacy::LegacySources::current_user());       // first
let h = hardening::legacy::import(&journal, &dirs.root, &*sys,
                                  &hardening::legacy::LegacySources::new(&dirs.legacy_electron)); // second
notices.extend(t.notice); notices.extend(h.notices);
let schedules = Arc::new(Store::<Schedules>::open(&dirs.root));
let rotation_cfg = Arc::new(Store::<RotationConfig>::open(&dirs.root));
if let Some(old) = open("scheduler") {                // core::legacy opened document (app's import)
    let (doc, warnings) = Schedules::from_legacy(&old); schedules.replace(doc)?; report.extend(warnings);
}
if let Some(old) = open("profile-rotation") { rotation_cfg.replace(RotationConfig::from_legacy(&old))?; }

// --- tasks, after startup recovery; the scheduler before the AutoPilot launch run
let scheduler = Arc::new(Scheduler::new(schedules, coord.clone()));
tokio::spawn({ let (s, c) = (scheduler.clone(), cancel.clone()); async move { s.run(c).await } });
let rotation = Arc::new(Rotation::new(rotation_cfg, coord.clone(), profiles.clone())); // profiles: RotationProfiles
tokio::spawn({ let (r, c) = (rotation.clone(), cancel.clone()); async move { r.run(c).await } });
let adaptive = Arc::new(Adaptive::new(coord.clone(), host, settings.clone(),           // host: AdaptiveHost
    Arc::new(Store::<AdaptiveDoc>::open(&dirs.root))));
tokio::spawn({ let (a, c) = (adaptive.clone(), cancel.clone()); async move { a.run(c).await } });
let pilot = AutoPilot::new(coord.clone(), env, settings.clone(), Some(scheduler.status())); // env: AutoPilotEnv
if let Some(result) = pilot.run(AutoPilotTrigger::AppLaunch).await { /* badge, log lines, one toast */ }

// --- hooks inside the app's connect / restart / stop paths
let mode = adaptive.begin(kind, profile_view).await;  // before a Direct / local-proxy Hard start
// start error → adaptive.start_failed(Some(err.user_msg())); cancelled → adaptive.start_failed(None)
// settings / crash restart → start with adaptive.restart_mode(session.mode)
// Soft start / refresh → soft.apply(ep.addr, ep.kind, dev_targets).await?   (dev_targets: the app's setting)
// stop, Hard / Direct start, shutdown, recovery (settings not Soft) → soft.rollback().await
// connected + settings.location_privacy → location.apply().await; stop / shutdown / recovery →
//   if location.is_applied() { location.rollback().await }
// winnet PowerEvent::Resumed | SessionUnlocked → scheduler.wake(Wake::Resume); config import → wake(Edited)
// shutdown: cancel.cancel() (tasks return; nothing is rolled back by them)
```

## Events, snapshots and texts the app / UI handles
- `Coordinator::notify(category, Notice)`: `ScheduleTriggered` (scheduler start / stop),
  `ProfileRotation` (rotation success), `ConnectionError` (schedule connect failure, rotation
  failures, adaptive terminal failure). Titles and bodies are `Msg`s of this crate or the reason the
  coordinator returned.
- Watch snapshots: `Scheduler::status()` → `SchedulerStatus` (next boundary, retry, suppressed),
  `Adaptive::status()` → `AdaptiveStatus` (`message` = `automation.adaptive.status.*`, `reason` =
  `automation.adaptive.reason.*` or a tunnel reason), `Rotation::subscribe()` → generation (re-read
  `config()` for the countdown). Results: `AutoPilotResult`, `RotationOutcome::message()`,
  `SoftReport`, `BrowserReport`, `LocationStatus`, `RollbackReport::{failure_msg, kept_msg}`.
- UI-only keys (labels the backend never emits): `automation.hardening.browser.state.*` (one per
  `BrowserState`), `automation.tweaks.target.*.{name,warning}` (also via `feature_name` /
  `feature_warning`). The "not checked" states are `TweakState::Unknown`, `BrowserState::Unknown` /
  `NotVerified`, `LocationStatus` fields `None`: show them as «Не проверено», never as protected.

## Not implemented / not verified
- Not run here: anything elevated (real HKLM writes: `cargo test -p vpnte-automation -- --ignored`
  in an elevated shell runs the one sandboxed HKLM test); the real `Coordinator`, `RotationProfiles`,
  `AdaptiveHost`, `AutoPilotEnv` (the app's; only test fakes exercise the contracts); browsers
  obeying the policies; Windows honouring the three location values; a real Android Studio layout;
  the E3 other-user path; the `ResolveIpNetEntry2` (active ARP) path of the identity reader.
- Not adapted to the privilege model yet: browser policies and the location policy run in-process and
  need an elevated process; moving them into `vpnte-service` is a `noadmin-*` follow-up.
- Not in this crate: persistence of the Soft dev-target list (`DevTargets`; `Settings` has no field
  for it), `WM_TIMECHANGE` (winnet has no event; the 60 s re-check covers clock changes), the old
  adaptive-learning import and install-secret migration (dropped), Chromium `Preferences` / Firefox
  `user.js` editing (replaced by the `legacy.browserFiles` notice), process-environment mirroring of
  the proxy variables, NLA network names (the gateway MAC is used instead). Planned WP-12 features
  are not implemented.
