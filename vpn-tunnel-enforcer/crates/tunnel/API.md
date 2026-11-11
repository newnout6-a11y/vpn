# vpnte-tunnel — API map

Connection runtime and lifecycle: the runtime actor that starts / supervises / switches / stops
the engines (`runtime`, `switch`), the lane that decides who may change the tunnel (`lifecycle`),
the pure state machine (`fsm`), session outcomes and the connection history (`outcome`,
`history`), and the shared vocabulary of all of them (`api`). Depends on `vpnte-base`, `-core`,
`-winnet`, `-profiles`, `-engine`. Cargo features (`tunnel-fsm`, `tunnel-history`,
`tunnel-lifecycle`, `tunnel-runtime`) are build scaffolding; the default enables all.

```rust
pub const LOCALES: &[(&str, &str)];   // (ru, en) per fragment, file-name order: fsm, history, lifecycle, runtime
```
The app registers it with `vpnte_base::i18n::init` after the UI's base layer. Every user-facing
text is a `Msg` (render with `vpnte_base`'s lookup or `outcome::render`); English strings in this
crate (`SwitchFailure::message`, `ProtectedRestart::reason`, `reason` arguments) are log text.

Typical app wiring: **`Lifecycle` over `TunnelHandle`**. UI actions, automation and recovery call
the `Lifecycle` only; nobody else calls the `Runtime` (a second caller would bypass admission,
history and notices).

## `api` — shared types, `trait Runtime`
```rust
pub struct VpnProfile { pub id: String, pub profile: Arc<Profile>, pub device: Option<ClientDevice> }
pub enum Mode { LocalProxy { addr: String, kind: ProxyKind }, DirectVpn { profile: VpnProfile } }
impl Mode { pub fn kind(&self) -> ModeKind }
pub enum ModeKind { LocalProxy, DirectVpn }                         // "localProxy" / "directVpn"
pub enum Origin { User, Schedule, Rotation, Adaptive, Recovery }     // all but Recovery reset the crash budget
pub struct StartRequest { pub mode: Mode, pub kill_switch: KillSwitchLevel, pub public_wifi: bool,
    pub stealth: bool, pub adaptive: AdaptiveMode, pub engine: EnginePref, pub origin: Origin }
pub struct StartReceipt { pub generation: u64, pub pid: u32, pub started_at: UnixMs, pub engine: Engine,
    pub warnings: Vec<Msg> }
pub struct StopOptions { pub preserve_protection: bool, pub preserve_last: bool }   // Default = full stop
pub struct StopReceipt { pub operation_id: String /* stop_<32 hex> */, pub ok: bool, pub runtime_stopped: bool,
    pub forced: bool, pub protection_released: Option<bool>, pub baseline_restored: Option<bool>,
    pub adapter_gone: bool, pub warnings: Vec<Msg> }
impl StopReceipt { pub fn confirms_cleanup(&self) -> bool }        // ok && stopped && both Some(true)
pub struct RestartOptions { pub release_timeout: Duration /* 5 s */, pub cancel: CancellationToken } // Default
pub struct ExitInfo { pub at: UnixMs, pub code: Option<i32>, pub stderr_tail: String /* redacted */,
    pub user_initiated: bool }
pub struct TunStatus { pub running: bool, pub mode: Option<ModeKind>, pub proxy_addr: Option<String>,
    pub proxy_type: Option<ProxyKind>, pub profile_name: Option<String>, pub protocol: Option<String>,
    pub pid: Option<u32>, pub warning: Option<Msg>, pub proxy_reachable: bool /* Default true */,
    pub started_at: Option<UnixMs>, pub restart_attempt: u8,
    pub session: Option<SessionEndpoints> /* #[serde(skip)]: secrets never serialized */ }
pub struct SessionEndpoints { pub clash_port: u16, pub clash_secret: String, pub direct: ProxyEndpoint,
    pub probe: Option<ProxyEndpoint>, pub tun_luid: Option<u64>, pub tun_alias: Option<String>,
    pub logs: Vec<PathBuf> }                                         // Debug hides secrets; no serde
pub struct ProxyEndpoint { pub port: u16, pub user: String, pub pass: String }
pub enum TunStatusKind { Stopping, Adapting, Stopped, Running, KillSwitchActive,
    Restarting { attempt: u8, max: u8 }, ProxyDown { reason: Msg }, Error { warning: Msg },
    PostTrialFailover { name: String }, CompetingTun { name: String }, CompetingTunCleared }
                                                                     // Display = old wire string ("restarting:1/3")
pub enum TunWarning { ForeignTunUnverified, ReleaseUnverified, Other(Msg) }  // Other: e.g. engine routing warnings
impl TunWarning { pub fn msg(&self) -> Msg; pub fn from_msg(msg: Msg) -> Self }   // from_msg: typed for the known keys
pub enum TunnelEvent { StartBegan { generation: u64 }, StartFinished { generation: u64, ok: bool },
    StopFinished { generation: u64, preserved: bool, receipt: StopReceipt },
    SwitchBegan { generation: u64 }, SwitchFinished { generation: u64, verified: bool },
    ProtectedRestart { reason: String }, Status(TunStatusKind), Warning(TunWarning) }
pub const TUN_SETUP_KEY_PREFIX: &str = "tunnel.runtime.tunSetup";  // TUN bring-up failures (history: tun-setup-failed)
pub struct TunError { pub error: AppError, pub warnings: Vec<Msg> }  // From<AppError>, Into<AppError>
impl TunError { pub fn new(kind: ErrorKind, msg: Msg) -> Self; pub fn kind(&self) -> ErrorKind;
    pub fn user_msg(&self) -> Msg; pub fn with_warning(self, warning: Msg) -> Self }
pub enum Slot { A, B }  impl Slot { pub fn other(self) -> Slot }
pub enum SwitchOutcome { Success, Cancelled, Failed }
pub enum SwitchPhase { Stage, Probe, Select, Confirm, Commit, Restore, ConfirmPrevious, StopCandidate,
    StopPrevious, Ownership }
pub struct SwitchFailure { pub phase: SwitchPhase, pub message: String }
pub struct SwitchReceipt { pub outcome: SwitchOutcome, pub committed: bool, pub active_slot: Option<Slot>,
    pub previous_preserved: bool, pub candidate_stopped: bool, pub previous_stopped: bool,
    pub ownership_lost: bool, pub failures: Vec<SwitchFailure> }    // Default = "failed"
impl SwitchReceipt { pub fn verified(&self) -> bool }
pub type OwnerCheck = Arc<dyn Fn() -> bool + Send + Sync>;
#[async_trait] pub trait Runtime: Send + Sync {
    async fn start(&self, req: StartRequest, cancel: CancellationToken) -> Result<StartReceipt, TunError>;
        // queued behind the operation in flight; then Cancelled if a stop came after it,
        // Conflict while a tunnel is up (alreadyRunning) or an old exit is unproven (previousNotStopped)
    async fn stop(&self, opts: StopOptions) -> StopReceipt;
    async fn restart_protected(&self, reason: String, next: StartRequest, opts: RestartOptions)
        -> Result<StartReceipt, TunError>;
    async fn restart_with_last(&self, reason: String) -> Result<Option<StartReceipt>, TunError>; // None = idle
    async fn restart_adaptive(&self, mode: AdaptiveMode, reason: String, profile: Option<VpnProfile>)
        -> Result<StartReceipt, TunError>;
    async fn switch_upstream(&self, next: StartRequest, cancel: CancellationToken, is_owner: OwnerCheck)
        -> Option<SwitchReceipt>;                                    // None = not in place: restart_protected
    fn status(&self) -> watch::Receiver<TunStatus>;
    fn subscribe(&self) -> broadcast::Receiver<TunnelEvent>;         // on Lagged: resync from status()
    fn last_exit(&self) -> Option<ExitInfo>;
    fn recent_fault(&self) -> Option<OutboundFault>;
}
```
Event contract (relied on by the lifecycle, checked by `lifecycle/tests/joint.rs`): the status
watch is updated before the matching `Status` event; every event of an operation is sent before
the call returns; native generations strictly increase per start (lane or crash restart), one
`StartFinished` per `StartBegan`, `StopFinished.generation` = the run it ended; the runtime sends
no notices.

## `fsm` — pure connection state machine (no I/O)
```rust
pub enum TunnelState { Disconnected, Connected, Error, Blocked, Unknown }
pub enum Transition { Connecting, Disconnecting, Reconnecting }
pub enum Health { Ok, Degraded }   pub enum TunnelMode { Tun, Soft }   pub enum ProcessState { Running, Stopped }
pub enum ProxyStatus { Running, ProxyDown, Stopped }   pub enum FaultState { Error, Blocked, Unknown }
pub struct TunnelSnapshot { pub version: u8, pub revision: u64, pub state: TunnelState,
    pub transition: Option<Transition>, pub health: Option<Health>, pub mode: Option<TunnelMode>,
    pub process_state: ProcessState, pub proxy_status: ProxyStatus, pub pid: Option<u32>,
    pub started_at: Option<UnixMs>, pub competing_tun: Option<String>, pub cleanup_required: bool,
    pub operation: Option<OpMeta> }                                  // serde camelCase (old wire shape)
pub struct Evidence { pub running: bool, pub pid: Option<u32>, pub soft_applied: bool, pub started_at: Option<UnixMs> }
impl Evidence { pub fn from_status(status: &TunStatus, soft_applied: bool) -> Self }
pub struct Invalid;                                                  // Into<AppError> = Conflict
impl Fsm { new, snapshot, can_start, can_rotate, can_refresh_soft,
    can_confirm_start(Option<Evidence>), can_confirm_stop(Option<Evidence>),
    op_changed(&OpMeta, ..), fault(FaultState, ..), keep_previous(OpId, ..), runtime(&TunStatusKind, ..),
    native_start_began(u64), native_start_finished(u64, bool, ..), upstream_began(u64, ..),
    upstream_finished(u64, bool, ..), native_stop_finished(u64, bool, &StopReceipt, ..) }
                                       // `..` = the current Option<Evidence>; mutators return Result<(), Invalid>
                                       // except `fault` (always accepted)
```
Used inside the lifecycle; others only read `TunnelSnapshot` (`Lifecycle::snapshot()`). A start-up
fault is seeded with `fault(FaultState::Unknown, ..)` on a fresh machine (the lifecycle's `fault`).
`fsm::Evidence` (OS evidence) is unrelated to `outcome::Evidence` (session facts in history).

## `outcome` — why a session ended
```rust
pub const VERBATIM: &str = "tunnel.outcome.verbatim";               // "{{text}}": old / free text as a Msg
pub fn verbatim(text: impl Into<String>) -> Msg;   pub fn verbatim_text(msg: &Msg) -> Option<&str>;
pub fn render(msg: &Msg, lang: Lang) -> String;                     // verbatim text even without catalogs
pub enum OutcomeKind { UserStop, AppQuit, ServerSwitch, Rotation, Schedule, ProxyUnreachable,
    ServerRejectedKey, ServerDown, SingboxCrash, Killswitch, TunSetupFailed, NetworkLost, SystemSleep,
    StartFailed, Unknown }                                           // kebab-case wire names
impl OutcomeKind { pub const ALL: [Self; 15]; pub fn as_str(self) -> &'static str;
    pub fn bucket(self) -> DisconnectReason; pub fn confidence(self) -> Confidence;
    pub fn never_connected(self) -> bool }                          // StartFailed | TunSetupFailed
pub enum DisconnectReason { User, Error, Rotation, Schedule, Crash }   // old coarse buckets
pub enum Confidence { Observed, Inferred, Indeterminate }
impl DisconnectReason { pub fn as_str(self) -> &'static str }   impl Confidence { pub fn as_str(self) -> &'static str }
pub enum AdaptiveContext { Baseline, TlsCompatibility, MtuCompatibility, ExternalManaged }  // From<AdaptiveMode>
pub enum NetworkTransition { AdapterRemoved, AdapterAdded, AddressChanged, Text(String) }
impl NetworkTransition { pub fn as_str(&self) -> &str; pub fn parse(text: &str) -> Self }
pub struct Evidence { pub singbox_exit_code: Option<i64>, pub singbox_stderr_tail: Option<String>,
    pub outbound_fault: Option<OutboundFault>, pub adaptive_mode: Option<AdaptiveContext>,
    pub adaptive_attempts: Option<u32>, pub auto_restart_attempts: Option<u32>,
    pub kill_switch_engaged: Option<bool>, pub leak_detected_during_session: Option<bool>,
    pub network_transition: Option<NetworkTransition>, pub egress_country: Option<String>,
    pub egress_ip: Option<String>, pub proxy_engine: Option<Engine>, pub hint: Option<Msg> }
impl Evidence { pub fn is_empty(&self) -> bool; pub fn normalized(self) -> Self }
pub struct SessionOutcome { pub kind: OutcomeKind, pub headline: Msg, pub evidence: Evidence }
impl SessionOutcome { pub fn new(kind, evidence) -> Self; pub fn with_headline(kind, evidence, headline: Msg) -> Self;
    pub fn start_failure(tun_setup: bool, hint: Option<Msg>, evidence: Evidence) -> Self }
pub fn headline(kind: OutcomeKind, evidence: &Evidence) -> Msg;
pub struct EngineExit { pub since: Duration, pub user_initiated: bool, pub code: Option<i64>,
    pub stderr_tail: Option<String> }
pub struct EndSignals { pub since_resume: Option<Duration>, pub since_network_change: Option<Duration>,
    pub outbound_fault: Option<OutboundFault>, pub kill_switch_active: bool, pub proxy_unreachable: bool,
    pub warning: Option<Msg>, pub restart_attempts: u32, pub engine_exit: Option<EngineExit> }
pub fn classify_end(s: &EndSignals) -> OutcomeKind;  // sleep < 25 s, key rejected, server down,
                                                     // network < 15 s, kill switch, proxy, crash < 30 s, unknown
pub fn unexpected_end(signals: &EndSignals, session: Evidence) -> SessionOutcome;
pub fn node_switch_kind(reason: &str) -> Option<OutcomeKind>;      // "profile rotation to …" / "server switch"
```

## `history` — connection history (`history/connections.json`, ring of 1000, oldest first)
```rust
pub const MAX_ENTRIES: usize = 1000;
pub enum SessionMode { Hard, Soft, Direct }     pub enum Route { Tun, SoftEnv, Unconfirmed }
impl SessionMode { pub fn as_str(self) -> &'static str }   impl Route { pub fn as_str(self) -> &'static str }
pub struct Provenance { pub source: Source, pub owner: Option<Owner> /* "unknown" */, pub route: Route,
    pub confidence: Confidence }
pub struct Entry { pub id: String, pub correlation_id: Option<CorrelationId>, pub provenance: Option<Provenance>,
    pub started_at: UnixMs, pub ended_at: Option<UnixMs>, pub duration_ms: Option<u64>,
    pub profile_name: String, pub profile_id: String, pub mode: SessionMode, pub bytes_down: u64,
    pub bytes_up: u64, pub disconnect_reason: DisconnectReason, pub error_message: Option<Msg>,
    pub outcome: Option<SessionOutcome> }                           // camelCase, Electron field names
impl Entry { pub fn connection_ms(&self) -> u64; pub fn is_valid(&self) -> bool;
    pub fn from_new(new: NewEntry) -> AppResult<Entry> }
pub struct NewEntry { pub correlation_id: Option<CorrelationId>, pub source: Source, pub owner: Option<Owner>,
    pub route: Route, pub started_at: UnixMs, pub ended_at: UnixMs, pub duration_ms: u64,
    pub profile_name: String, pub profile_id: String, pub mode: SessionMode, pub bytes_down: u64,
    pub bytes_up: u64, pub outcome: SessionOutcome }
pub struct ConnectionHistory { pub entries: VecDeque<Entry> }      // core::store::Document, lenient per row
impl ConnectionHistory { pub fn push(&mut self, entry: Entry);
    pub fn from_legacy(legacy: &Value) -> (ConnectionHistory, usize /* dropped */) }
pub struct LegacyImport { pub imported: usize, pub dropped: usize }
impl LegacyImport { pub fn warning(&self) -> Option<Msg> }          // tunnel.history.legacyDropped
pub struct Filter { pub levels: Vec<DisconnectReason>, pub date_from: Option<UnixMs>,
    pub date_to: Option<UnixMs>, pub text: Option<String> }
pub fn filter<'a>(entries: impl IntoIterator<Item = &'a Entry>, f: &Filter, lang: Lang) -> Vec<Entry>;
pub enum Period { Day, Week, Month }  impl Period { pub fn window_ms(self) -> i64 }
pub struct Stats { pub total_time_ms: u64, pub total_bytes_down: u64, pub total_bytes_up: u64, pub entry_count: usize }
pub fn stats<'a>(entries: impl IntoIterator<Item = &'a Entry>, period: Period, now: UnixMs) -> Stats;
pub const CSV_HEADER: &str;                                          // 18 columns
pub fn to_csv<'a>(entries: impl IntoIterator<Item = &'a Entry>, lang: Lang) -> String;   // formula-guarded
pub fn to_json<'a>(entries: impl IntoIterator<Item = &'a Entry>, lang: Lang) -> AppResult<String>;
#[derive(Clone)] pub struct History;                                // Arc<Store<ConnectionHistory>> inside
impl History { pub fn new(store: Arc<Store<ConnectionHistory>>) -> Self; pub fn open(root: &Path) -> Self;
    pub fn store(&self) -> &Arc<Store<ConnectionHistory>>; pub fn subscribe(&self) -> watch::Receiver<u64>;
    pub fn add(&self, new: NewEntry) -> AppResult<Entry>; pub fn list(&self) -> Vec<Entry>;
    pub fn filter(&self, f: &Filter, lang: Lang) -> Vec<Entry>; pub fn stats(&self, period: Period, now: UnixMs) -> Stats;
    pub fn clear(&self) -> AppResult<()>; pub fn export_csv(&self, lang: Lang) -> String;
    pub fn export_json(&self, lang: Lang) -> AppResult<String>;
    pub fn import_legacy(&self, legacy: &Value) -> AppResult<LegacyImport> }
```
Writes are blocking file I/O (`spawn_blocking` in async code). The lifecycle writes every row; the
app reads (`list` / `filter` / `stats` / exports, `subscribe` for changes), clears, and calls
`import_legacy(&decrypted_electron_store)` once during the legacy import.

## `lifecycle` — the lane: who may change the tunnel
```rust
pub const DEFAULT_TIMEOUT: Duration;                                 // 120 s per lane operation
pub use crate::api::TUN_SETUP_KEY_PREFIX;
pub enum ConnectTarget { LocalProxy { addr: String, kind: ProxyKind },
    DirectVpn { profile_id: Option<String> /* None = active server */ }, Soft { addr: String, kind: ProxyKind } }
pub struct ConnectReq { pub target: ConnectTarget, pub owner: Owner, pub source: Source,
    pub correlation: Option<CorrelationId>, pub adaptive: AdaptiveMode, pub timeout: Duration,
    pub cancel: Option<CancellationToken> }
impl ConnectReq { pub fn new(target: ConnectTarget, owner: Owner, source: Source) -> Self }
pub enum StopCause { User, AppQuit, Schedule, Timeout, Cancelled, Preempted, Failed }
pub struct DisconnectReq { pub cause: StopCause, pub owner: Owner, pub source: Source,
    pub correlation: Option<CorrelationId>, pub timeout: Duration }
impl DisconnectReq { pub fn new(cause: StopCause, owner: Owner, source: Source) -> Self }
pub struct SwitchReq { pub profile_id: String, pub owner: Owner, pub source: Source,
    pub correlation: Option<CorrelationId>, pub timeout: Duration, pub cancel: Option<CancellationToken> }
impl SwitchReq { pub fn new(profile_id: impl Into<String>, owner: Owner, source: Source) -> Self }
pub struct Done { pub warnings: Vec<Msg> }
pub enum ConnError { Refused(Msg), NoServer(Msg), Cancelled(Msg), Timeout(Msg), Failed(TunError) }
impl ConnError { pub fn kind(&self) -> ErrorKind /* Refused|NoServer = Conflict */; pub fn user_msg(&self) -> Msg;
    pub fn warnings(&self) -> &[Msg] }                               // From<ConnError> for AppError
pub struct SessionView { pub owner: Owner /* holder */, pub profile_id: String, pub profile_name: String,
    pub mode: SessionMode, pub generation: Option<u64>, pub adaptive: AdaptiveMode, pub started_at: UnixMs }
pub enum SessionEvent { Up(SessionView), Ended { session: SessionView, outcome: OutcomeKind } }
pub struct ShutdownReport { pub engines_stopped: bool, pub soft_restored: bool, pub capture_stopped: bool,
    pub timed_out: bool }
#[derive(Clone)] pub struct Lifecycle;
impl Lifecycle {
    pub fn spawn(deps: LifecycleDeps) -> Self;                       // inside a tokio runtime
    pub async fn connect(&self, req: ConnectReq) -> Result<Done, ConnError>;     // dropping the future cancels
    pub async fn disconnect(&self, req: DisconnectReq) -> Result<Done, ConnError>;
    pub async fn rotate(&self, req: SwitchReq) -> Result<Done, ConnError>;       // history: rotation
    pub async fn switch_upstream(&self, req: SwitchReq) -> Result<Done, ConnError>; // history: server-switch
    pub async fn restart_with_last(&self, reason: impl Into<String>, owner: Owner, source: Source)
        -> Result<Done, ConnError>;                                  // settings changed; idle = no-op success
    pub async fn restart_adaptive(&self, mode: AdaptiveMode, sibling: Option<String>, owner: Owner)
        -> Result<Done, ConnError>;                                  // idle = Refused(lane.notRunning)
    pub fn cancel_pending(&self);                                    // H-04: a start of owner <= Manual / a reconnect
    pub async fn maintenance<T, F, Fut>(&self, f: F) -> Result<T, ConnError>; // F: FnOnce() -> Fut, all Send + 'static;
                                                                     // idle lane, not connected (A-05); past the
                                                                     // 120 s budget: Timeout, state unknown
    pub async fn shutdown(&self, budget: Duration) -> ShutdownReport;  // closes admission, stops as app-quit
    pub async fn reopen(&self) -> bool;
    pub fn snapshot(&self) -> watch::Receiver<TunnelSnapshot>;
    pub fn session(&self) -> watch::Receiver<Option<SessionView>>;
    pub fn events(&self) -> broadcast::Receiver<SessionEvent>;
    pub fn busy(&self) -> bool;
    pub fn fault(&self, state: FaultState);                         // start-up recovery / panic hook: no I/O
    pub fn adopt(&self, owner: Owner);                               // a higher owner takes the session over
    pub fn resumed(&self);  pub fn network_changed(&self, transition: NetworkTransition);  pub fn leak_detected(&self);
}
// collaborators the app implements over the other crates
pub struct ServerChoice { pub server: VpnProfile, pub country: Option<String> }
pub trait ProfileSource: Send + Sync { fn resolve(&self, id: Option<&str>) -> Option<ServerChoice>; }
#[async_trait] pub trait SoftProxy: Send + Sync { fn applied(&self) -> Option<bool>;
    async fn apply(&self, addr: &str, kind: ProxyKind) -> AppResult<()>; async fn rollback(&self) -> AppResult<()>;
    async fn is_configured(&self, addr: &str, kind: ProxyKind) -> AppResult<bool>; }
pub trait Monitor: Send + Sync { fn suppress_leak_tests(&self, span: Duration); fn start(&self, generation: Option<u64>);
    fn stop(&self); fn egress_ip(&self) -> Option<String>; }
#[async_trait] pub trait Forensics: Send + Sync { fn start_session(&self, mode: SessionMode, target: &str);
    async fn stop_session(&self, reason: &str) -> bool; fn session_bytes(&self) -> (u64, u64); }
#[async_trait] pub trait ExternalProxies: Send + Sync { async fn stop_all(&self, reason: &str); }
pub enum NoticeKind { VpnConnect, VpnDisconnect, ConnectionError, ProfileRotation }
pub trait Notifier: Send + Sync { fn notify(&self, notice: Notice, kind: NoticeKind); }
#[derive(Clone)] pub struct LifecycleDeps { pub runtime: Arc<dyn Runtime>, pub profiles: Arc<dyn ProfileSource>,
    pub soft: Arc<dyn SoftProxy>, pub monitor: Arc<dyn Monitor>, pub forensics: Arc<dyn Forensics>,
    pub proxies: Arc<dyn ExternalProxies>, pub notifier: Arc<dyn Notifier>, pub history: History,
    pub settings: Arc<Store<Settings>> }
```
Admission: a strictly higher `Owner` pre-empts a running start; stops coalesce and win over
everything except a strictly higher start; refusals are `Refused` with a `tunnel.lifecycle.lane.*`
message. Engine / kill switch / stealth / public Wi-Fi come from `settings` at start time; the
start origin from the owner. Not enforced here (the app's automation `Coordinator` does it): a
`disconnect` by an owner lower than `SessionView::owner`; restarting the previous server after a
failed `rotate` (on failure: still connected on the old server -> report "not started", else
`connect` the previous server).

## `runtime` — the actor and its seams
```rust
#[derive(Clone)] pub struct TunnelHandle;                           // implements api::Runtime
impl TunnelHandle { pub fn spawn(deps: RuntimeDeps) -> Self }        // inside a tokio runtime
#[derive(Clone)] pub struct RuntimeDeps { pub engines: Arc<dyn Engines>, pub capture: Arc<dyn Capture>,
    pub inputs: Arc<dyn InputsSource>, pub failover: Option<Arc<dyn Failover>>,
    pub confirmations: Option<Arc<dyn Confirmations>>, pub timings: Timings }
pub struct Timings { pub ready, capture_ready, exit, release: Duration, pub backoff: [Duration; 3] /* 2/5/10 s */,
    pub stable /* 30 s */, proxy_watch /* 5 s */, proxy_probe, proxy_listen, egress_watch /* 15 s */,
    evidence_age /* 45 s */, capture_watch /* 15 s */, confirm_candidate, confirm_previous: Duration } // Default
pub const MAX_RESTARTS: u8 = 3;
pub struct UserInputs { pub smart_ru: bool, pub smart_ru_maps_direct: bool, pub rule_set_dir: Option<PathBuf>,
    pub domain_rules: Vec<DomainRule>, pub split_direct: Vec<String>, pub split_vpn: Vec<String>,
    pub split_inactive: Vec<InactiveSplit>, pub dns: Option<DnsAddr>, pub kill_switch: KillSwitchLevel,
    pub public_wifi: bool, pub stealth: bool, pub auto_restart_on_crash: bool }  // serde camelCase, Default
impl UserInputs { pub fn split(&self) -> ResolvedSplit }
pub struct InactiveSplit { pub name: String, pub path: String, pub missing: bool }
#[async_trait] pub trait InputsSource: Send + Sync { async fn snapshot(&self) -> AppResult<UserInputs>; }
#[async_trait] pub trait Failover: Send + Sync {                   // post-trial failover (servers)
    async fn next_live_sibling(&self, cancel: &CancellationToken) -> Option<VpnProfile>;
    fn commit(&self, profile_id: &str); }
pub trait Confirmations: Send + Sync { fn confirmed_within(&self, age: Duration) -> bool; } // monitoring
// how traffic is captured (the only module that knows TUN / WFP / adapters)
#[async_trait] pub trait Capture: Send + Sync {
    async fn prepare(&self, req: &StartRequest, avoid: &[String]) -> AppResult<CapturePlan>;
    fn config(&self, plan: &CapturePlan, parts: &EngineParts) -> Result<(Value, [u8; 32]), ConfigError>;
    async fn begin(&self, plan: &CapturePlan, session_programs: &[PathBuf]) -> AppResult<()>;
    async fn ready(&self, plan: &CapturePlan, timeout: Duration, cancel: &CancellationToken) -> AppResult<CaptureProof>;
    async fn routes_ok(&self, proof: &CaptureProof) -> bool;
    async fn lost(&self) -> AppResult<()>;
    async fn release(&self) -> AppResult<()>;
    async fn wait_gone(&self, plan: &CapturePlan, timeout: Duration, cancel: &CancellationToken) -> bool;
    async fn check(&self, proof: &CaptureProof) -> CaptureCheck; }
pub struct CapturePlan { pub alias: Option<String>, pub form: TunForm, pub stack: TunStack, pub mtu: u16,
    pub guard: KillSwitchLevel /* what the protection enforces */, pub warnings: Vec<Msg> }
pub struct CaptureProof { pub luid: Option<u64>, pub alias: Option<String> }
pub enum CaptureCheck { Clear, Competing(String), Unknown }
pub struct EngineParts { pub upstream: Upstream, pub listeners: Listeners, pub routing: RoutingParts,
    pub phys_dns: Vec<Ipv4Addr> }
pub struct TunForm { pub dual_stack: bool, pub dns_hijack: bool }
pub fn tun_form(level: KillSwitchLevel, leak_protection: bool) -> TunForm;  // WFP guard -> dual stack + native DNS
pub struct TunCapture;  impl TunCapture { pub fn new(protection: Arc<vpnte_winnet::wfp::Protection>) -> Self }
// engines (real: RealEngines over vpnte_engine; tests: fakes in runtime/tests)
#[async_trait] pub trait CoreProc: Send + Sync { fn pid(&self) -> u32;
    async fn wait_ready(&self, timeout: Duration, cancel: &CancellationToken) -> Result<(), StartError>;
    async fn terminate(&self, within: Duration) -> Result<ExitInfo, StopError>;  // engine ExitInfo
    fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>>; fn recent_fault(&self) -> Option<OutboundFault>; }
#[async_trait] pub trait Slots: Send + Sync {                      // engine Slot / SlotEndpoint / XrayError
    async fn start(&mut self, slot: Slot, ep: SlotEndpoint, launch: SlotLaunch, cancel: &CancellationToken)
        -> Result<(), XrayError>;
    async fn restart(&mut self, slot: Slot, cancel: &CancellationToken) -> Result<(), XrayError>;
    async fn stop(&mut self, slot: Slot) -> Result<(), XrayError>; async fn stop_all(&mut self) -> Result<(), XrayError>;
    fn activate(&mut self, slot: Slot) -> Result<(), XrayError>; fn running(&self, slot: Slot) -> bool; }
#[async_trait] pub trait Engines: Send + Sync {
    fn spawn_core(&self, config: &[u8]) -> io::Result<Arc<dyn CoreProc>>;   // config on stdin
    fn slots(&self, events: mpsc::Sender<XrayEvent>) -> Box<dyn Slots>;
    fn xray_exe(&self) -> PathBuf; fn log_files(&self, slots: bool) -> Vec<PathBuf>;
    async fn select(&self, clash: &ClashEndpoint, slot: Slot) -> AppResult<()>;
    async fn upstream_downloads(&self, clash: &ClashEndpoint) -> AppResult<Vec<(String, u64)>>;
    async fn resolve(&self, hosts: &[String], path: ResolvePath, cancel: &CancellationToken)
        -> Result<Resolved, ResolveFault>;
    async fn egress_via(&self, port: u16, creds: &Creds, cancel: &CancellationToken) -> AppResult<IpAddr>;
    async fn egress(&self, timeout: Duration, cancel: &CancellationToken) -> AppResult<IpAddr>;
    async fn local_proxy(&self, addr: &HostPort, limit: Duration) -> AppResult<Option<PathBuf>>;
    async fn physical_dns(&self) -> Vec<Ipv4Addr>; }
pub struct RealEngines;
impl RealEngines { pub fn new(singbox: PathBuf, xray: PathBuf, logs: Option<PathBuf>) -> Self }  // canonical paths
```
Behaviour the caller can rely on: one task serialises every operation (a start waits for the one in
flight); `stop()` cancels a start / switch / restart in flight and waits for its compensation;
concurrent stops share one receipt.
Crash policy: auto-restart (origin `Recovery`, `Restarting{n,3}` first, backoff 2 / 5 / 10 s, budget
reset after 30 s stable), then failover once (when a `Failover` is given), then terminal: kill
switch off -> release + `Stopped`; strict, or standard with auto-restart off -> keep blocking
(`KillSwitchActive`); standard + budget exhausted -> release + `Stopped`. Watchdogs never stop the
tunnel (`ProxyDown` / `Running`). The runtime never calls `Protection::set_level`: the owner of the
settings keeps the level in sync. `TunStatus::session` carries the Clash secret and the loopback
proxy passwords: serde skips it and `Debug` hides them; never format its fields into a log.

## `switch` — protected upstream switch (used by the runtime)
```rust
pub trait SwitchOps {    // stage / probe(slot, &CancellationToken), select / confirm / stop(slot): async;
    fn alive(&self, slot: Slot) -> bool; fn commit(&mut self, slot: Slot) -> Result<(), AppError>;
    fn is_owner(&self) -> bool; }                                    // calls never overlap; generic, no dyn
pub async fn run_protected_switch<O: SwitchOps + Send>(previous: Slot, candidate: Slot, ops: &mut O,
    cancel: &CancellationToken) -> SwitchReceipt;                    // never errs: failures in the receipt
```

## Main flows
```rust
// wiring (app, or the helper service for the runtime half): `protection` = winnet's
// `Arc<wfp::Protection>` after `startup()`; `app` = the app's implementations of the traits.
let runtime = TunnelHandle::spawn(RuntimeDeps {
    engines: Arc::new(RealEngines::new(singbox_exe, xray_exe, Some(logs_dir))),
    capture: Arc::new(TunCapture::new(protection.clone())),
    inputs: app.clone(),                                   // impl InputsSource over the stores
    failover: Some(app.clone()), confirmations: Some(app.clone()),
    timings: Timings::default(),
});
let lifecycle = Lifecycle::spawn(LifecycleDeps {
    runtime: Arc::new(runtime), profiles: app.clone(), soft: app.clone(), monitor: app.clone(),
    forensics: app.clone(), proxies: app.clone(), notifier: app.clone(),
    history: History::open(&data_dir), settings: settings_store.clone(),
});
lifecycle.fault(FaultState::Unknown);                      // only when start-up recovery found leftovers

// UI "connect" / "disconnect" / server change
let target = ConnectTarget::DirectVpn { profile_id: None };            // the active server
let done = lifecycle.connect(ConnectReq::new(target, Owner::Manual, Source::Ui)).await?;  // done.warnings
lifecycle.disconnect(DisconnectReq::new(StopCause::User, Owner::Manual, Source::Ui)).await?;
lifecycle.switch_upstream(SwitchReq::new("srv-b", Owner::Manual, Source::Ui)).await?;
lifecycle.restart_with_last("settings changed", Owner::Manual, Source::Ui).await?;

// state for the UI: snapshot() (TunnelSnapshot), session() (SessionView), events() (Up / Ended);
// runtime details (pid, warning, uptime, endpoints): the runtime's status() watch.
// quit: let report = lifecycle.shutdown(Duration::from_secs(10)).await;
```
Errors: show `ConnError::user_msg()`; `kind() == Cancelled` is quiet; `Timeout` means the lane keeps
cleaning up in the background. `Done::warnings` / `ConnError::warnings` are extra messages.

## What callers must handle
- **Notices** arrive only through `Notifier::notify(notice, kind)` (title / body are `Msg`s under
  `tunnel.lifecycle.notice.<name>`): `connected`, `restored` (runtime reconnect), `disconnected`,
  `stopFailed`, `stopped` (unexpected end; body = outcome headline), `crashRestarting`
  (`attempt`, `max`), `crashBlocked`, `failover` (`name`), `restartFailed` (body = runtime warning),
  `internalError` (a lane effect panicked: the lane is released and the state reads `unknown`,
  A-01). Rotation, schedule and tray toasts are their owners'. The notifier applies the user's
  `NoticeKind` switches; the lifecycle does not.
- **`maintenance`** past the 120 s lane budget: the action is dropped, the caller gets
  `ConnError::Timeout` (`tunnel.lifecycle.lane.maintenanceTimeout`) and the state reads `unknown`
  (its changes are unproven; cleanup is owed, as after `fault(Unknown)`).
- **`SessionEvent`**: `Up` (also for a continued session after a switch / restart / auto-restart),
  `Ended { outcome }` after the row was written; automation maps user-stop / schedule ->
  requested, app-quit -> shutdown, else fault.
- **Inputs to feed**: `resumed()` (resume / unlock), `network_changed(..)`, `leak_detected()`,
  `fault(..)` (recovery report, panic hook), `adopt(owner)` (a higher owner takes the session).
- **Runtime `TunnelEvent`s** are consumed by the lifecycle; others may read `status()` and
  `Status(..)` / `Warning(..)` for display. A lagged receiver resyncs from `status()`.

## i18n keys (fragments in `locales/`, all under `tunnel.`)
| Prefix | Produced by | Args |
| --- | --- | --- |
| `tunnel.warning.{foreignTunUnverified,releaseUnverified}` | `TunWarning::msg` | — |
| `tunnel.runtime.{alreadyRunning,actorGone,notRunning,noLastStart,previousNotStopped,proxyAddressInvalid,proxyNotListening,profileUnusable,egressUnknown,fullStopRan,stopIncomplete,restartStopFailed,restartCancelled,switchUnconfirmed}` | runtime errors / warnings | `addr` (`proxyNotListening`) |
| `tunnel.runtime.tunSetup.{adapter,protection,routes}` | TUN bring-up failures (`TUN_SETUP_KEY_PREFIX`) | — |
| `tunnel.runtime.cleanup.{exitUnproven,xray,protection}` | compensation / stop warnings, `Error{warning}` | — |
| `tunnel.runtime.watchdog.{proxyDown,upstreamDown,slotExited}` | `ProxyDown{reason}` | `addr` / `name` / — |
| `tunnel.lifecycle.lane.*`, `.server.{none,unavailable}`, `.soft.*` | `ConnError` messages | — |
| `tunnel.lifecycle.outcome.*` | lifecycle headlines of ended sessions | — |
| `tunnel.lifecycle.notice.<name>.{title,body}` | notices (above) | per notice |
| `tunnel.outcome.verbatim`, `tunnel.outcome.headline.*` | `SessionOutcome::headline` (plurals on `count`) | `text`, `code`, `count`, … |
| `tunnel.history.{invalidEntry,legacyDropped}` | `History::add`, `LegacyImport::warning` | `count` |

## Elevation and privilege model
Needs nothing: `api`, `fsm`, `outcome`, `history`, `lifecycle`, `switch`; of the runtime the actor,
`RealEngines` (spawning sing-box / Xray, Clash API, IP echo, listener owner lookup) and
`TunCapture::prepare` / `check` (adapter and registry reads). Needs elevation: the TUN capture.
sing-box creates the Wintun adapter (administrators only) and `TunCapture::begin` / `ready` /
`lost` / `release` change winnet's WFP `Protection`. Nothing checks elevation up front (libraries
never self-elevate, CONTRACT §1), so an unelevated start ends like this:
- kill switch `standard` / `strict` or leak protection on: `begin` (`connect_begin`) fails with
  `ErrorKind::Permission` (winnet `AccessDenied`) and the start is refused before any engine runs;
- kill switch `off` and leak protection off: no WFP filter is wanted, nothing refuses the start, and
  it fails when sing-box cannot create its adapter: sing-box's exit (`engine.process.singboxExited`,
  kind `Internal`), not `Permission`. Never run unelevated on this machine; the `noadmin-*`
  packages decide how the app reports TUN as unavailable without service or elevation.

Per CONTRACT §1 the privileged half (`TunnelHandle` + `TunCapture` + `RealEngines`) is meant to run
in the helper service `vpnte-service` or in an elevated process. Inputs come through `RuntimeDeps`
(trait objects the host builds) and `StartRequest`; outputs are plain values (status watch, events,
receipts). Only `UserInputs` is serde today, and `TunStatus` serializes without `session` (the
secrets), so the wire types of that split are still to be written. The split itself (`noadmin-*`)
is not done here.

## Not implemented / not run
- Proxy capture (unprivileged): a second `Capture` with a loopback mixed inbound, and the engine
  builder it needs (`singbox_config::build` always emits the TUN). Follow-up package.
- Local-proxy full-tunnel validation (public IP via the proxy vs direct): a probe before
  `connect`, not in the runtime (it only checks the listener and its owner).
- Routing-plan decision table and bootstrap routes; engine log size rotation; the window focus of
  the crash table (the app's).
- Not enforced here (the app's automation `Coordinator`): holder check on `disconnect`, restoring
  the previous server after a failed `rotate` (see `lifecycle`).
- Not run here: `tests/e2e_tun.rs::elevated_tun_session_end_to_end` (needs elevation; CI runs
  `cargo test -p vpnte-tunnel -- --ignored elevated_`), so `TunCapture` and `RealEngines`' network
  reads run only there. Known leftover: sing-tun's `mixed` stack adds a Windows Firewall rule
  `sing-tun (<engine path>)` nobody removes (cleanup crate's job).
- Not exercised by tests: the lifecycle's session rule "wall-clock end, monotonic duration" under a
  moved system clock (§7.11 calendar correction); the race "stop queued while the crash backoff fires"
  (`select!` picks among ready branches; covered by reasoning and `stop_cancels_a_pending_restart`).
- Open risk, not verified (needs an elevated start / stop / start): winnet's
  `alias::connection_names` counts registry names of absent adapters, so a TUN that leaves its
  `Connection` key behind makes every connect pick the next alias until `aliasExhausted` (fix
  belongs in winnet).
