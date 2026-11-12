# vpnte-winnet — API

Windows system layer (x64 only): adapters / routes / TUN identity, processes and jobs, interface
counters, ICMP, the WFP kill switch and leak protection, registry, user environment, the per-user
system proxy, elevation, autostart (per-user `Run` value), single instance, secret clipboard,
power / session / theme events, toasts and the Start-menu shortcut. Depends only on `vpnte-base`.
Paths: `vpnte_winnet::{adapters, process, counters, icmp, wfp, registry, env, sysproxy, autostart,
clipboard, elevation, single_instance, shell, toast, power, url_scheme}` plus `vpnte_winnet::LOCALES`. Shared types used below come from `vpnte_base`
(`AppError`, `AppResult`, `ErrorKind`, `Msg`, `Notice`, `types::{KillSwitchLevel, UnixMs}`),
`ipnet` (`IpNet`, `Ipv4Net`, `Ipv6Net`), `windows::core::{GUID, Error, Result}`,
`tokio_util::sync::CancellationToken`.

## Conventions
- **Errors.** Raw OS reads return `windows::core::Result<T>` ("not found" is `Ok(None)` /
  `Ok(false)`, never an error); map them yourself (`AppError::internal(e)` or your own `Msg`).
  Domain operations return a typed error that converts with `AppError::from` (key and kind listed
  per module) or `AppResult` directly. User text is only ever a `Msg` key under `winnet.*`.
- **Threads.** Functions marked *blocking* do COM / registry / BFE / process work that can take
  from milliseconds to seconds: call them from `tokio::task::spawn_blocking` (or a plain thread),
  never on the UI thread. IP Helper reads (`counters`, `process::socket_table`, `adapters` route
  lookups) take about 1 ms and may run inline. The `adapters` functions that walk the adapter
  table (`inventory`, `physical_*`, `foreign_tun::detect`, `route_proof`, `alias::connection_names`)
  are *blocking*: 7-20 ms on a machine with dozens of NDIS filter interfaces (measured here); the
  `adapters` async waits already read on the blocking pool. `async fn`s and the functions marked
  *runtime* must run inside a tokio runtime (they spawn or use tokio types).
- **Elevation.** The app runs unelevated (NOADMIN: manifest `asInvoker`, never a UAC prompt of
  its own); a privileged feature is available exactly when `elevation::is_elevated()` is true.
  Unelevated these fail with access denied / `ErrorKind::Permission`: every WFP change and
  enumeration (`wfp::Protection` ops → `ProtectionError::AccessDenied`, `wfp::remove_all`,
  `wfp::Engine`; the app creates no `Protection` unelevated), deleting the 1.x logon task
  (`autostart::delete_task`; `sync` then keeps it and carries on),
  writing the installer's all-users Start-menu link (`toast::ensure_shortcut` under
  `toast::common_programs_dir()`), terminating an elevated orphan in
  `process::sweep_orphans` (reported as `survived`). Everything else works unelevated, including
  `wfp::app_id`, `wfp::outbound_block_profiles`, `wfp::tun_inbound_blocked`, the `wfp`
  validation functions, `Protection::settings` / `session_guarded`, all adapter / route / counter
  reads, `icmp::echo`, `env`, `sysproxy`, `autostart` (the `Run` value), HKCU `registry` access
  and the per-user `toast` paths.
- **No cargo features**: the crate always builds whole.

## Locales
```rust
pub const LOCALES: &[(&str, &str)];   // (ru_json, en_json), one per work package, package order
// app, once, before `vpnte_ui::launch` (later registrations are ignored):
let layers: Vec<(&str, &str)> = [vpnte_view::LOCALES, vpnte_winnet::LOCALES /* , other crates */]
    .concat();
vpnte_ui::lang::init_locales(&layers);
```
| Keys | Arguments | Emitted by |
| --- | --- | --- |
| `winnet.adapters.{tunTimeout,aliasExhausted,foreignTunConflict}` | — | `TunAdapterError`, `AliasError`, `foreign_tun::refuse_on_conflict` |
| `winnet.process.{unsafeDir,listUnreadable}` | — | `SweepError` |
| `winnet.process.sweep.{stopped,survived,unknown}` | `count` | `SweepReport::summary` |
| `winnet.icmp.{invalid,failed}` | — | `IcmpError` |
| `winnet.wfp.exception.{labelLength,valueLength,invalidIp,notExecutable,notLocalPath,unreadable,duplicate,notFound,broad}` | — | `ValidationError::msg`, `broad_warning` |
| `winnet.wfp.exception.tooMany` | `max` | `ValidationError::TooMany` |
| `winnet.wfp.error.{bfeUnavailable,accessDenied,persist,sessionActive,levelUnconfirmed,exceptionsUnconfirmed}` | — | `ProtectionError::msg` |
| `winnet.wfp.error.programMissing` / `winnet.wfp.error.wfp` | `name` (file name) / `code` (`0x8032000e`) | `ProtectionError::msg` |
| `winnet.wfp.notice.{blockedTitle,blockedStrict,blockedStandard,exceptionSkippedTitle,unverifiedTitle,unverified}` | — | `Protection::notices` |
| `winnet.wfp.notice.exceptionSkipped` | `label` | `Protection::notices` |
| `winnet.wfp.status.firewallOutboundBlock` | — | `ProtectionStatus::firewall_warning` |
| `winnet.wfp.status.hypervUnfiltered` | — | `ProtectionStatus::hyperv_warning` |
| `winnet.autostart.{failed,denied,stateUnknown}` | — | `AutostartError` |
| `winnet.autostart.disabledByUser` | — | `AutostartState::hint` |
| `winnet.clipboard.{busy,failed}` | — | `SecretClipboard::copy` |
| `winnet.singleInstance.noAnswer` | — | `single_instance::send` |
| `winnet.shell.{badUrl,noFolder,openFailed}` | — | `shell::*` |
| `winnet.toast.productionAumid` | — | `toast::ensure_shortcut` (debug builds) |

Tests pin that every fragment is valid JSON with equal ru / en keys and placeholders, that every
key literal in the code exists and every fragment key is named by the code, and that `LOCALES`
equals the files.

## `adapters` — inventory, routes, our TUN, foreign tunnels, change watch (read-only, unelevated)
```rust
pub const TUN_V4: Ipv4Net;            // 192.168.250.253/30 (sing-box side; gateway of the TUN)
pub const TUN_RESOLVER_V4: Ipv4Addr;  // 192.168.250.254
pub const TUN_V6: Ipv6Net;            // fd8b:3f2a:91c4::1/126, only when the TUN is dual-stack
#[derive(Copy, Eq, Hash)] pub enum Family { V4, V6 }      // Family::of(ip: IpAddr) -> Family
pub fn is_own_tun_address(ip: IpAddr) -> bool;           // 192.168.250.x | legacy 172.19.0.x (hint only)

// inventory: one predicate "physical" for DNS sources, leak tests, pings and identity
pub struct UnicastAddress { pub ip: IpAddr, pub prefix_len: u8, pub dad_state: i32, pub temporary: bool }
impl UnicastAddress { pub fn usable(&self) -> bool }     // DAD not Invalid / Duplicate
pub enum AdapterStatus { Up, Disconnected, NotPresent, Disabled }
pub struct Adapter { pub if_index: u32, pub luid: u64, pub guid: GUID, pub alias: String,
    pub description: String, pub if_type: u32, pub status: AdapterStatus, pub mac: Vec<u8>,
    pub permanent_mac: Vec<u8>, pub hardware: bool, pub filter: bool, pub hidden: bool,
    pub driver: Option<String> /* ComponentId, lowercase */, pub ipv4_enabled: bool,
    pub ipv6_enabled: bool, pub link_speed_bps: u64, pub addresses: Vec<UnicastAddress>,
    pub gateways: Vec<IpAddr>, pub dns: Vec<IpAddr>, pub dns_static: bool, pub physical: bool }
impl Adapter {
    pub fn is_up(&self) -> bool;  pub fn is_visible(&self) -> bool;   // visible = Get-NetAdapter list
    pub fn source_v4(&self) -> Vec<Ipv4Addr>;   // usable, no 169.254.*
    pub fn global_v6(&self) -> Vec<Ipv6Addr>;   // usable 2000::/3
    pub fn dns_v4(&self) -> Vec<Ipv4Addr>;  pub fn gateways_v4(&self) -> Vec<Ipv4Addr>;
}
pub fn inventory() -> windows::core::Result<Vec<Adapter>>;          // empty / loopback-only = Err
pub fn physical_adapters() -> windows::core::Result<Vec<Adapter>>;  // none = Err (fail closed)
pub fn physical_dns_v4() -> windows::core::Result<Vec<Ipv4Addr>>;   // deduped, TUN /30 removed

// routes
pub struct Route { pub if_index: u32, pub luid: u64, pub destination: IpNet,
    pub next_hop: Option<IpAddr>, pub metric: u32, pub protocol: i32 }
pub struct BestRoute { pub if_index: u32, pub luid: u64, pub destination: IpNet,
    pub next_hop: Option<IpAddr>, pub source: IpAddr }                       // Copy
pub struct DefaultRoute { pub if_index: u32, pub luid: u64, pub alias: String,
    pub next_hop: Option<IpAddr>, pub metric: u32 }
pub fn routes(family: Family) -> windows::core::Result<Vec<Route>>;         // empty IPv4 table = Err
pub fn best_route(dst: IpAddr) -> windows::core::Result<BestRoute>;        // GetBestRoute2, validated
pub fn default_route(family: Family) -> windows::core::Result<Option<DefaultRoute>>; // lowest metric /0
pub fn interface_mtu(luid: u64, family: Family) -> windows::core::Result<Option<u32>>;
pub fn alias_of(luid: u64) -> windows::core::Result<String>;
pub fn route_proof(tun: &OwnedTun) -> windows::core::Result<bool>;         // Err = not proven

// our TUN (sing-box creates it; we only identify it)
pub struct OwnedTun { pub alias: String, pub luid: u64, pub guid: GUID, pub if_index: u32,
    pub v4: Ipv4Net, pub v6: Option<Ipv6Net> }
pub enum TunAdapterError { Timeout { alias: String, v4: Ipv4Net, waited: Duration,
    last_error: Option<windows::core::Error> }, Cancelled }
    // -> AppError: Timeout = ErrorKind::Timeout + winnet.adapters.tunTimeout; Cancelled = AppError::cancelled()
pub enum Release { Released, Cancelled, Unverified }
pub async fn wait_owned_tun(alias: &str, v4: Ipv4Net, v6: Option<Ipv6Net>, timeout: Duration,
    cancel: &CancellationToken) -> Result<OwnedTun, TunAdapterError>;   // polls every 50 ms
pub async fn wait_released(aliases: &[String], v6: Option<Ipv6Net>, timeout: Duration,
    cancel: &CancellationToken) -> Release;                             // 25 ms polls; after the engine exited
pub fn adapter_present(luid: u64) -> windows::core::Result<bool>;      // a "not present" ghost = false

pub mod alias {
    pub const CANDIDATES: [&str; 8];   // "Ethernet 5" … "Ethernet 12" (disguised TUN names)
    pub const FALLBACK: &str;          // "VPNTE-TUN"
    pub fn all_aliases() -> Vec<String>;                                // candidates + fallback
    pub fn connection_names() -> windows::core::Result<Vec<String>>;    // registry ∪ live aliases
    pub fn choose(taken: &[String]) -> Result<String, AliasError>;      // first free, case-insensitive
    pub enum AliasError { Exhausted }  // -> AppError conflict + winnet.adapters.aliasExhausted
}
pub mod foreign_tun {
    pub enum Severity { Warning, Conflict }                             // Ord: Conflict > Warning
    pub struct Foreign { pub name: String, pub description: String, pub luid: u64,
        pub address: IpAddr, pub severity: Severity }                   // label() = "name (ip)"
    pub fn detect(own_luid: Option<u64>, own_aliases: &[&str]) -> windows::core::Result<Vec<Foreign>>;
        // sorted Conflict first; Conflict = it carries a route with prefix length <= 1;
        // hardware-backed NICs are never tunnels, whatever their name
    pub fn refuse_on_conflict(found: &[Foreign]) -> AppResult<()>;    // conflict + winnet.adapters.foreignTunConflict
}

// network changes (runtime)
pub struct NetChange { pub before: usize, pub after: usize }   // kind() -> NetChangeKind
pub enum NetChangeKind { AdapterRemoved, AdapterAdded, AddressChanged }
pub fn watch_network(settle: Duration, cancel: CancellationToken)
    -> windows::core::Result<tokio::sync::mpsc::Receiver<NetChange>>;  // trailing debounce (pass 1.5 s); ends on cancel / drop
    // runtime; reads the baseline inline (one adapter-table walk), later reads on the blocking pool
```
Connect flow (tunnel runtime, inside a fn returning `AppResult`):
```rust
let names = adapters::alias::connection_names().map_err(AppError::internal)?;
let alias = adapters::alias::choose(&names)?;
let own: Vec<String> = adapters::alias::all_aliases();   // our leftover adapter is not "foreign"
let own: Vec<&str> = own.iter().map(String::as_str).collect();
let found = adapters::foreign_tun::detect(None, &own).map_err(AppError::internal)?;
adapters::foreign_tun::refuse_on_conflict(&found)?;
// … wfp.connect_begin(..), spawn sing-box with interface_name = alias …
let tun = adapters::wait_owned_tun(&alias, adapters::TUN_V4, None, Duration::from_secs(20), &cancel).await?;
wfp.tun_up(tun.luid)?;                       // WFP permits address the TUN by this LUID
if !adapters::route_proof(&tun).unwrap_or(false) { /* not proven: abort, never report "secure" */ }
// stop: after the engine exited
adapters::wait_released(&[alias], None, Duration::from_secs(10), &cancel).await;
```
Notes: `physical_dns_v4()` errs when no physical NIC is up; the engine should fall back to its
default resolvers rather than fail the start. Display formatting (link speed, MAC) is the UI's.

## `process` — jobs, hidden children, image paths, sockets, orphan sweep
```rust
pub struct Job;                                    // Send + Sync; drop closes it => members die
impl Job {
    pub fn kill_on_close() -> windows::core::Result<Job>;  // KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION
    pub fn assign(&self, child: &tokio::process::Child) -> windows::core::Result<()>;
    pub fn terminate(&self, exit_code: u32) -> windows::core::Result<()>;
}
pub fn app_job() -> std::io::Result<&'static Job>; // process-wide, never dropped (one-shot tools)
pub fn spawn_hidden(cmd: &mut tokio::process::Command, job: &Job) -> std::io::Result<tokio::process::Child>;
    // runtime. CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP (the child gets its own windowless
    // console and leads its own group, so `ctrl_break` reaches exactly it), stdin/stdout/stderr
    // piped (overrides earlier stdio), kill_on_drop(true), assigned to `job` at once; a failed
    // assign kills the child and errs.
pub fn ctrl_break(pid: u32) -> std::io::Result<()>;
    // blocking (~50 ms, one at a time process-wide). CTRL_BREAK to the console group of a running
    // `spawn_hidden` child: AttachConsole(pid), our own handler swallows C/BREAK, Generate…,
    // 50 ms settle, FreeConsole. Only asks: the caller waits and kills on its own deadline. Go
    // engines (sing-box, Xray) turn it into SIGINT and shut down cleanly. Errs when `pid` has no
    // console or is 0, or when this process has a console of its own (access denied).
pub fn detach_console() -> bool;
    // tests / console tools: FreeConsole of an inherited console so `ctrl_break` works; refuses
    // (false) while stdout / stderr is a terminal. The GUI app and a service have no console.
pub fn image_path(pid: u32) -> Result<PathBuf, ImageError>;
pub enum ImageError { Gone /* no such PID, also 0 */, Denied, Os(windows::core::Error) }

#[serde(rename_all = "lowercase")] pub enum Transport { Tcp, Udp }
#[serde(rename_all = "kebab-case")] pub enum TcpState { Closed, Listen, SynSent, SynReceived,
    Established, FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait, DeleteTcb, Unknown }
pub struct SocketRow { pub transport: Transport, pub local: SocketAddr,
    pub remote: Option<SocketAddr>, pub state: Option<TcpState>, pub pid: u32 }  // Serialize; UDP: None
pub struct ListenerOwner { pub pid: u32, pub local: SocketAddr, pub image: Option<PathBuf> }
pub fn socket_table() -> windows::core::Result<Vec<SocketRow>>;   // all TCP + bound UDP, v4 then v6
pub fn listener_owner(transport: Transport, port: u16, hosts: &[IpAddr])
    -> windows::core::Result<Option<ListenerOwner>>;
    // first host with a listener wins: pass the exact address first, then the wildcards
    // ([127.0.0.1, 0.0.0.0, ::]: a dual-stack `::` socket accepts IPv4 too). TCP: LISTEN only.

pub fn find_under(prefixes: &[PathBuf], names: &[&str]) -> Result<ProcessScan, SweepError>;
pub fn sweep_orphans(prefixes: &[PathBuf], names: &[&str]) -> Result<SweepReport, SweepError>; // blocking ≤ 3 s per name
pub struct ProcessScan { pub owned: Vec<OwnedProc>, pub unknown: Vec<UnknownProc> }
pub struct SweepReport { pub stopped: Vec<OwnedProc>, pub survived: Vec<OwnedProc>, pub unknown: Vec<UnknownProc> }
impl SweepReport { pub fn is_clean(&self) -> bool; pub fn summary(&self) -> Option<Msg> }
pub struct OwnedProc { pub pid: u32, pub path: PathBuf }
pub struct UnknownProc { pub pid: u32, pub name: String, pub reason: UnknownReason }
pub enum UnknownReason { Vanished, OpenFailed, PathUnreadable }
pub enum SweepError { UnsafePrefix(String), Enumeration(windows::core::Error), Inconsistent }
    // -> AppError: UnsafePrefix = Validation + winnet.process.unsafeDir;
    //    others = Internal + winnet.process.listUnreadable
```
Engines: `let job = Job::kill_on_close().map_err(AppError::internal)?;` then
`let mut child = spawn_hidden(&mut cmd, &job)?;` and keep the `Job` as long as the engine should
live; stop = `ctrl_break(pid)` on the blocking pool, wait for the exit with a grace period, then
`job.terminate(code)` (or `child.start_kill()`) and wait again with a timeout (the reaped handle
is the exit proof; keep the handle open while a `ctrl_break` may still target its PID: Windows
never reuses the PID of a process with an open handle). A killed sing-box never calls
`WintunCloseAdapter`, so its TUN interface outlives the session. curl / pktmon / `version`
probes use `app_job()`. Orphan sweep at start (blocking thread): `sweep_orphans(&[engines_dir,
legacy_runtime_dirs…], &["vpnte-sing-box.exe", "vpnte-xray.exe", …])`; names order = stop order;
prefixes are plain long-form `X:\…` directories (8.3 names never match, `\\?\`, UNC, wildcards and
relative paths are refused). Nothing outside the prefixes is touched; our own PID is excluded.

## `counters` — interface counters by LUID
```rust
#[derive(Copy, Serialize)]
pub struct IfCounters { pub luid: u64, pub guid: u128 /* InterfaceGuid: a new value = adapter
    recreated, counters restarted */, pub in_octets: u64, pub out_octets: u64,
    pub in_packets: u64, pub out_packets: u64 /* unicast + non-unicast */, pub in_discards: u64,
    pub in_errors: u64, pub out_discards: u64, pub out_errors: u64, pub up: bool }
pub fn read(luid: u64) -> windows::core::Result<Option<IfCounters>>;   // GetIfEntry2; None = gone (also LUID 0)
```
Address the TUN by `OwnedTun::luid`, never by alias. `guid` equals `OwnedTun::guid.to_u128()`.

## `icmp` — echo with TTL / DF / source (async, `IcmpSendEcho2Ex` / `Icmp6SendEcho2` on the blocking pool)
```rust
pub const MAX_PAYLOAD: u16 = 65_500;
pub const MAX_TIMEOUT: Duration;                 // 30 s
pub struct EchoRequest { pub dst: IpAddr, pub src: Option<IpAddr>, pub ttl: u8 /* >= 1 */,
    pub df: bool /* the IPv4 DF bit */, pub payload: u16, pub timeout: Duration /* 1 ms ..= 30 s */ }
impl EchoRequest { pub fn new(dst: IpAddr) -> Self }
    // TTL 128, no DF, 32 B payload like ping.exe; timeout 1 s (ping.exe waits 4 s)
pub enum EchoStatus { Success, TtlExpired, PacketTooBig, TimedOut, Unreachable, Other(u32) }
pub struct EchoReply { pub status: EchoStatus, pub from: Option<IpAddr>, pub rtt_ms: Option<u32> }
pub enum IcmpError { Invalid(&'static str), Os(windows::core::Error), Join }
    // -> AppError: Invalid = Validation + winnet.icmp.invalid; Os = Network, Join = Internal
    //    (both winnet.icmp.failed)
pub async fn echo(req: EchoRequest) -> Result<EchoReply, IcmpError>;
```
Traceroute: run `echo(EchoRequest { ttl, ..EchoRequest::new(dst) })` for several TTLs in a
`JoinSet`; reached = `status == Success && from == Some(dst)`. PMTU ladder: `df: true`, `payload`
= ladder value (+28 B headers on IPv4, +48 B on IPv6), `src` = a physical address.
`PacketTooBig` carries no MTU (the reply structures do not expose it). IPv6 routers never
fragment; whether `df` also stops the *source* from fragmenting an IPv6 probe above the local MTU
is unverified, so on a link with MTU < 1500 (PPPoE 1492) an IPv6 rung above it may read as accepted.

## `wfp` — kill switch and leak protection (our provider + sublayer; needs elevation)
Items are re-exported at `vpnte_winnet::wfp::*` (submodules `engine`, `fwpolicy`, `model`,
`protection`, `spec`, `validate` are public too). Dynamic session for `standard` / leak protection
(gone when the process dies), persistent filters only for `strict`.
```rust
pub const PROVIDER_KEY: GUID;  pub const SUBLAYER_KEY: GUID;
pub const LEGACY_IPV6_SUBLAYER: GUID;   // old app's sublayer: delete only (cleanup-legacy)
pub const MAX_EXCEPTIONS: usize = 256;
pub const WATCHDOG_PERIOD: Duration;    // 30 s

// settings document part (serde camelCase, missing fields = default; exceptions keep the old
// stored shape {id, type: "app" | "ip", value, label})
#[derive(Default /* Off, leak/wifi/lan true */, Serialize, Deserialize)]
pub struct ProtectionSettings { pub level: KillSwitchLevel, pub leak_protection: bool,
    pub public_wifi_compat: bool, pub allow_lan: bool, pub exceptions: Vec<KillSwitchException> }
impl ProtectionSettings { pub fn toggles(&self) -> Toggles }
pub struct Toggles { pub leak_protection: bool, pub public_wifi_compat: bool, pub allow_lan: bool }
pub struct KillSwitchException { pub id: String /* caller makes new ids */, pub target: ExceptionTarget, pub label: String }
pub enum ExceptionTarget { App(PathBuf), Ip(IpNet) }   // kind() -> ExceptionKind, value() -> String
pub enum ExceptionKind { App, Ip }                      // serde "app" | "ip"
pub struct EnginePaths { pub singbox: PathBuf, pub xray: Option<PathBuf>, pub external_proxy: Option<PathBuf> }
pub enum Conn { Disconnected, Connecting, Up, Dropped }
pub enum KillSwitchState { Off, Armed /* standard, no session */, Engaged, Blocking /* no tunnel */, Failed }
pub struct ProtectionStatus { pub level: KillSwitchLevel, pub conn: Conn,
    pub kill_switch: KillSwitchState, pub last_error: Option<ProtectionError>,
    pub leak_protection_active: bool, pub dynamic_filters: Option<u32>,
    pub persistent_filters: Option<u32> /* None = BFE not readable (unelevated) */,
    pub sublayer_weight: Option<u16>, pub bfe_running: Option<bool>,
    pub last_verified: Option<UnixMs>, pub skipped_exceptions: Vec<String> /* ids */,
    pub windows_firewall_outbound_block: Option<Vec<FwProfileBlock>>,
    pub hyperv_switch_present: Option<bool> /* Hyper-V guests bypass WFP ALE filters */ }
impl ProtectionStatus { pub fn firewall_warning(&self) -> Option<Msg>;
    pub fn hyperv_warning(&self) -> Option<Msg> /* kill switch on + a Hyper-V switch */ }
#[derive(Clone, thiserror::Error)]
pub enum ProtectionError { BfeUnavailable { code: u32 }, AccessDenied, EngineMissing(PathBuf),
    Wfp { op: &'static str, code: u32 }, Validation(ValidationError), Persist(Arc<AppError>),
    SessionActive, Unconfirmed(Unconfirmed /* Level | Exceptions */) }
impl ProtectionError { pub fn kind(&self) -> ErrorKind; pub fn msg(&self) -> Msg }
    // kind: AccessDenied = Permission, Validation = Validation, SessionActive = Conflict,
    // Persist = the store error's kind, others Internal. `AppError::from(e)` carries kind + msg.

// the handle: Send + Sync, share it in an Arc; one mutex serialises every operation (blocking)
pub type Persist<'a> = &'a dyn Fn(&ProtectionSettings) -> AppResult<()>;  // runs under the lock
impl Protection {
    pub fn new(engines: EnginePaths, self_exe: PathBuf, settings: ProtectionSettings) -> Self;
    pub fn notices(&self) -> broadcast::Receiver<Notice>;   // all in category `connectionError`
    pub fn settings(&self) -> ProtectionSettings;
    pub fn session_guarded(&self) -> bool;  // level != Off || leak protection: dual-stack TUN + dns_mode native
    pub fn startup(&self) -> Result<(), ProtectionError>;   // strict set or leftover removal
    pub fn connect_begin(&self, session_programs: &[PathBuf], tun_addresses: &[IpAddr])
        -> Result<(), ProtectionError>;                     // TUN_V4 (+ TUN_V6 when dual-stack)
    pub fn tun_up(&self, luid: u64) -> Result<(), ProtectionError>;
    pub fn tun_lost(&self) -> Result<(), ProtectionError>;  // ignored without a session
    pub fn disconnected(&self) -> Result<(), ProtectionError>;
    pub fn set_level(&self, level: KillSwitchLevel, persist: Persist) -> Result<(), ProtectionError>;
    pub fn set_exceptions(&self, list: Vec<KillSwitchException>, persist: Persist) -> Result<(), ProtectionError>;
    pub fn add_exception(&self, exception: KillSwitchException, persist: Persist) -> Result<(), ProtectionError>;
    pub fn remove_exception(&self, id: &str, persist: Persist) -> Result<(), ProtectionError>;
    pub fn update_settings(&self, toggles: Toggles) -> Result<(), ProtectionError>; // caller saves after Ok
    pub fn status(&self) -> ProtectionStatus;               // fresh enumeration + firewall read
    pub fn watchdog_tick(&self);
    pub async fn run_watchdog(self: Arc<Self>, cancel: CancellationToken);  // ticks on the blocking pool
    pub fn reset(&self, persist: Persist) -> Result<RemoveReport, ProtectionError>; // SessionActive in a session
    pub fn shutdown(&self);                                 // closes the dynamic session; strict stays
}
pub fn remove_all() -> Result<RemoveReport, ProtectionError>;  // `--cleanup` / uninstall
pub struct RemoveReport { pub filters: usize, pub sublayer: bool, pub provider: bool }

// validation (pure, no effects)
pub fn validate_exception(kind: ExceptionKind, value: &str, label: &str)
    -> Result<(ExceptionTarget, String /* trimmed label */), ValidationError>;
pub fn parse_ip_or_cidr(s: &str) -> Result<IpNet, ValidationError>;
pub fn canonical_exe(raw: &str) -> Result<PathBuf, ValidationError>;   // existing local .exe, long form
pub fn check_list(list: &[KillSwitchException]) -> Result<(), ValidationError>; // equivalents + limit
pub fn broad_warning(target: &ExceptionTarget) -> Option<Msg>;          // IPv4 < /8, IPv6 < /16
pub enum ValidationError { LabelLength, ValueLength, InvalidIp, NotExecutable, NotLocalPath,
    Unreadable, Duplicate, TooMany, NotFound }                          // msg(self) -> Msg; Copy
    // -> AppError (also via ProtectionError::Validation): Validation + the field message

// Windows Firewall (read-only COM, unelevated)
pub enum FwProfile { Domain, Private, Public }
pub struct FwProfileBlock { pub profile: FwProfile, pub active: bool }
pub fn outbound_block_profiles() -> windows::core::Result<Vec<FwProfileBlock>>;
pub fn tun_inbound_blocked() -> windows::core::Result<bool>;  // true: the tunnel uses stack "gvisor"

// low level (Protection uses it; cleanup-legacy deletes the old sublayer with it)
pub enum Layer { Connect4, Connect6, Accept4, Accept6, OutboundIpPacket6 }  // Layer::OURS, key(), from_key()
pub enum Action { Permit, Block }
pub struct AppId;                                  // from_bytes(..), as_bytes()
pub enum Cond { AppId(Arc<AppId>), LocalInterface(u64), LocalAddr(IpAddr), Loopback, Protocol(u8),
    LocalPort(u16), RemotePort(u16), RemoteV4(Ipv4Net), RemoteV6(Ipv6Net), IcmpType(u16) }
pub struct FilterSpec { pub name: &'static str, pub layer: Layer, pub action: Action, pub weight: u8, pub conds: Vec<Cond> }
pub fn app_id(exe: &Path) -> Result<AppId, WfpError>;     // canonical path -> FwpmGetAppIdFromFileName0, unelevated
pub struct WfpError { pub op: &'static str, pub code: u32 } // is(hr), is_access_denied(), is_rpc_failure(), engine_lost()
impl Engine {                                               // Drop = FwpmEngineClose0; Send
    pub fn open_dynamic() -> Result<Engine, WfpError>;  pub fn open_persistent() -> Result<Engine, WfpError>;
    pub fn is_dynamic(&self) -> bool;
    pub fn transaction<R>(&self, f: impl FnOnce(&Engine) -> Result<R, WfpError>) -> Result<R, WfpError>;
    pub fn ensure_provider_and_sublayer(&self) -> Result<u16, WfpError>;   // actual sublayer weight
    pub fn add(&self, spec: &FilterSpec) -> Result<u64, WfpError>;          // persistent iff session not dynamic
    pub fn delete(&self, id: u64) -> Result<(), WfpError>;                  // not found = Ok
    pub fn list(&self, q: &ListQuery) -> Result<Vec<FilterInfo>, WfpError>;
    pub fn owned_filters(&self) -> Result<Vec<FilterInfo>, WfpError>;       // our provider, our 4 layers
    pub fn sublayer(&self, key: &GUID) -> Result<Option<SublayerInfo>, WfpError>;
    pub fn delete_sublayer(&self, key: &GUID) -> Result<(), WfpError>;      // absent = Ok
    pub fn delete_provider(&self, key: &GUID) -> Result<(), WfpError>;      // absent = Ok
}
pub struct ListQuery { pub layer: Layer, pub provider: Option<GUID> }
pub struct FilterInfo { pub id: u64, pub key: GUID, pub layer: GUID, pub sublayer: GUID,
    pub provider: Option<GUID>, pub flags: u32, pub action: u32, pub weight: Option<u8>, pub name: String }
    // is_persistent(), flags_valid(boot: bool)
pub struct SublayerInfo { pub key: GUID, pub weight: u16, pub flags: u32, pub provider: Option<GUID>, pub name: String }
```
Wiring:
```rust
let wfp = Arc::new(wfp::Protection::new(engines, std::env::current_exe()?, settings.protection.clone()));
wfp.startup()?;                                   // after settings import + legacy cleanup
tokio::spawn(wfp.clone().run_watchdog(cancel.clone()));        // elevated mode only
let mut notices = wfp.notices();                  // forward to toasts (category connectionError)
// tunnel runtime (TUN mode only; Soft mode never calls these):
let guarded = wfp.session_guarded();              // engine config: dual-stack TUN + dns_mode "native" iff true
let gvisor = wfp::tun_inbound_blocked().unwrap_or(true);       // engine config: stack "gvisor" iff true
let tun_addrs: Vec<IpAddr> = std::iter::once(adapters::TUN_V4.addr().into())
    .chain(guarded.then(|| adapters::TUN_V6.addr().into())).collect();
wfp.connect_begin(&local_proxy_owner_exes, &tun_addrs)?;  // BEFORE spawning engines; Err = refuse the connect
wfp.tun_up(owned_tun.luid)?;                      // Err = abort the connect
wfp.tun_lost()?;                                  // unexpected drop: blocks stay until disconnected()
wfp.disconnected()?;                              // every end of a session
// UI: exceptions
let (target, label) = wfp::validate_exception(kind, &value, &label)?;   // + wfp::broad_warning(&target)
wfp.add_exception(KillSwitchException { id: new_id, target, label }, &|s| store.save_protection(s))?;
wfp.shutdown();                                   // on exit
```
`Persist` callbacks run with the protection lock held: they must not call back into
`Protection`. `set_level` / exception changes persist at the point the fail-closed order needs
(entering strict saves first; a failed save re-applies the previous state). Paths in
`EnginePaths` / `session_programs` must be the image paths the processes run from; `app_id`
canonicalises them (8.3 names, links), so launch engines from their canonical path. A missing
static engine is skipped with a warning, a missing session program refuses `connect_begin`
(`EngineMissing`). From `connect_begin` until `disconnected()` every guarded session blocks DNS
(53 / 853) outside the TUN for everything but engines, our exe, session programs and exceptions,
the Windows DNS client included: engines resolve server names themselves. Notices go out only
when traffic is actually blocked (strict at startup / disconnect, standard drop), for a skipped
app exception (once per id) and when the watchdog cannot confirm protection (once per failure
streak).

## `registry` — typed Reg* access (`windows::core::Result`; blocking but fast)
```rust
pub enum Hive { CurrentUser, LocalMachine, Users /* HKU\<sid>\… */ }
pub enum View { Native /* default */, Bits64, Bits32 }       // KEY_WOW64_64KEY / _32KEY
pub enum Access { Read, ReadWrite }
pub enum Value { Sz(String), ExpandSz(String) /* unexpanded */, MultiSz(Vec<String>), Dword(u32),
    Raw { kind: u32, data: Vec<u8> } }
pub struct Key;                                               // closes on drop; Send
impl Key {
    pub fn open(hive: Hive, path: &str, access: Access, view: View) -> Result<Option<Key>>;  // None = no key
    pub fn create(hive: Hive, path: &str, view: View) -> Result<(Key, bool /* created now */)>;
    pub fn open_subkey(&self, name: &str, access: Access) -> Result<Option<Key>>;          // same view
    pub fn value(&self, name: &str) -> Result<Option<Value>>;                // None = no value
    pub fn string(&self, name: &str) -> Result<Option<String>>;             // Sz | ExpandSz; other type = Err
    pub fn dword(&self, name: &str) -> Result<Option<u32>>;                 // other type = Err
    pub fn multi_string(&self, name: &str) -> Result<Option<Vec<String>>>;  // other type = Err
    pub fn set(&self, name: &str, value: &Value) -> Result<()>;
    pub fn set_string(&self, name: &str, text: &str) -> Result<()>;
    pub fn set_expand_string(&self, name: &str, text: &str) -> Result<()>;
    pub fn set_dword(&self, name: &str, value: u32) -> Result<()>;
    pub fn set_multi_string<S: AsRef<str>>(&self, name: &str, items: &[S]) -> Result<()>;
    pub fn delete_value(&self, name: &str) -> Result<bool>;                 // false = was absent
    pub fn subkey_names(&self) -> Result<Vec<String>>;
    pub fn value_names(&self) -> Result<Vec<String>>;                       // "" = default value
    pub fn is_empty(&self) -> Result<bool>;
}
pub fn delete_key(hive: Hive, path: &str, view: View) -> Result<bool>;     // no subkeys; false = absent
pub fn delete_tree(hive: Hive, path: &str, view: View) -> Result<bool>;    // recursive; "" refused
```
A value of an unexpected type is `Err(ERROR_UNSUPPORTED_TYPE)`, never "absent" (a tweak journal
must abort on it). Names / values with an interior NUL and empty `MultiSz` items are refused
(`E_INVALIDARG`). Tests use throw-away keys `HKCU\Software\VPNTE-Test-*`.

## `env` — persistent user environment (`HKCU\Environment`; the process environment is never touched)
```rust
pub const BROADCAST_TIMEOUT: Duration;                       // 5 s
pub enum EnvValue { Plain(String) /* REG_SZ */, Expandable(String) /* REG_EXPAND_SZ */ }  // text()
pub struct UserEnv;
impl UserEnv {
    pub fn current_user() -> Self;                           // HKCU\Environment
    pub fn under(path: impl Into<String>) -> Self;           // another HKCU key (tests)
    pub fn get(&self, name: &str) -> windows::core::Result<Option<EnvValue>>;  // other type = Err
    pub fn set(&self, name: &str, value: &EnvValue) -> windows::core::Result<()>;
    pub fn remove(&self, name: &str) -> windows::core::Result<bool>;
}
pub fn broadcast_change(timeout: Duration) -> windows::core::Result<()>;  // blocking; WM_SETTINGCHANGE "Environment"
```
Writes do not broadcast: call `broadcast_change(BROADCAST_TIMEOUT)` once per batch on a blocking
thread. Treat any `Err` from `get` as "unreadable → abort, no writes".

## `sysproxy` — the per-user system proxy (WinINet default connection; blocking, unelevated)
```rust
#[derive(Default, PartialEq, Eq, Hash, Serialize, Deserialize)]   // serde camelCase, missing = default
pub struct ProxyConfig { pub use_proxy: bool /* PROXY_TYPE_PROXY */, pub server: String /* "host:port" | "http=…;https=…" */,
    pub bypass: String /* ";"-list, "<local>" */, pub use_pac: bool, pub pac_url: String, pub auto_detect: bool }
pub fn read() -> windows::core::Result<ProxyConfig>;            // FLAGS_UI (FLAGS before IE 8), server, bypass, PAC URL
pub fn write(config: &ProxyConfig) -> windows::core::Result<()>; // FLAGS (+DIRECT) and the three strings, then notify
```
Only the documented `InternetQueryOptionW` / `InternetSetOptionW(INTERNET_OPTION_PER_CONNECTION_OPTION)`
on the default (LAN) connection, so the `DefaultConnectionSettings` blob stays consistent; `write`
then sends `INTERNET_OPTION_SETTINGS_CHANGED` and `INTERNET_OPTION_REFRESH` and stops at the first
failure. Empty strings mean unset. A machine-wide proxy policy (`ProxySettingsPerUser = 0`) makes
`write` fail with access denied. The Soft-mode tweak (`vpnte_automation::tweaks::sysproxy`) is the
only writer; tests never write the real setting (`system_*` test is `#[ignore = "changes system state"]`).

## `autostart` — per-user `Run` value (registry, blocking, unelevated); 1.x task helpers over COM
```rust
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";              // under HKCU
pub const APPROVED_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
pub const RUN_VALUE: &str = "VPN Tunnel Enforcer";    // data: "\"<exe>\" --autostart" (REG_SZ)
pub const TASK_NAME: &str = "VPN Tunnel Enforcer";    // the 1.x logon task (root folder), removed by `sync`
pub const AUTOSTART_ARG: &str = "--autostart";
pub enum AutostartState { Absent, Present { matches_exe: bool },
    DisabledByUser { matches_exe: bool } }            // switched off in Task Manager: never switched on
impl AutostartState { pub fn hint(self) -> Option<Msg>; }   // DisabledByUser -> winnet.autostart.disabledByUser
pub fn set(enabled: bool, exe: &Path) -> windows::core::Result<()>;  // write / delete (absent = Ok)
pub fn state(exe: &Path) -> windows::core::Result<AutostartState>;  // Err = unknown, never Absent
pub trait AutostartOs { fn apply(&self, enabled: bool) -> windows::core::Result<()>;
    fn read(&self) -> windows::core::Result<AutostartState>;
    fn remove_legacy_task(&self) -> windows::core::Result<bool>; }  // Ok(false): absent or not deletable
pub struct RunValue { pub exe: PathBuf }                             // impl AutostartOs (the real value)
pub enum Step { Os(windows::core::Error), Readback { expected: AutostartState, found: AutostartState },
    Persist(Box<AppError>) }
pub enum AutostartError { Unchanged(Step), Unknown { cause: Step, restore: Step } }
    // -> AppError: Unknown = Internal + winnet.autostart.stateUnknown; access denied = Permission +
    //    winnet.autostart.denied; persist failure = its kind + winnet.autostart.failed;
    //    else Internal + winnet.autostart.failed
pub fn set_checked(os: &impl AutostartOs, previous: bool, enabled: bool,
    persist: impl FnOnce(bool) -> AppResult<()>) -> Result<(), AutostartError>;  // apply, read back, persist
pub fn sync(os: &impl AutostartOs, enabled: bool) -> windows::core::Result<bool /* acted */>;
pub struct ExecAction { pub path: String, pub arguments: String }
pub struct TaskInfo { pub user_id: String /* raw: name or SID */, pub enabled: bool, pub exec: Vec<ExecAction>, pub other_actions: usize }
pub fn read_task(path: &str) -> windows::core::Result<Option<TaskInfo>>;   // "Name" or r"\Folder\Name"
pub fn delete_task(path: &str) -> windows::core::Result<bool>;             // false = absent
pub fn delete_task_folder(path: &str) -> windows::core::Result<bool>;      // not empty = Err
```
Matching: the value's command must be this exe (case-insensitive, quotes and slash style ignored)
with exactly `--autostart`; anything else, or a non-string value under our name, is stale.
`StartupApproved\Run\<RUN_VALUE>` is read only: binary data with an odd first byte (03) = switched
off by the user, even (02 / 06) or no value = on. An entry switched off there counts as applied for
`set_checked(.., true, ..)` and `sync(.., true)` (the app's part is done; the switch is the
user's, `AutostartState::hint` says where it is) and is re-pointed when stale but never switched
on; `false` deletes the value. `sync` also deletes the 1.x logon task `TASK_NAME` (access denied =
kept and logged: it was created elevated; the installer's elevated cleanup removes it) and
reports a failure of that only after the value was synced.
Settings toggle: `spawn_blocking(move || autostart::set_checked(&RunValue { exe }, prev, on, |on|
store.update(|s| s.autostart = on)))`, map with `AppError::from`; the UI disables the switch while
pending and shows `autostart::state(&exe)?.hint()` next to it. Startup: `autostart::sync(&RunValue
{ exe }, settings.autostart)` on a blocking thread (log failures, never block startup). Legacy
import: imported `autoStart` true → `set_checked(.., previous = false, true, ..)`; false →
`sync(.., false)`. cleanup-legacy: `read_task` / `delete_task` / `delete_task_folder` for
`\VPNTE\BootRecoveryTask`, `\VPNTE Boot Recovery`, `\VPNTE`.

## `clipboard` — secret copy with privacy formats and auto-clear
```rust
pub const CLEAR_AFTER: Duration;   // 60 s
pub const RETRY_AFTER: Duration;   // 5 s (clipboard busy at clear time)
pub struct SecretClipboard;        // Send + Sync
impl SecretClipboard {
    pub fn start() -> Self;                                 // runtime (panics outside one); own owner window
    pub fn copy(&self, text: &str) -> AppResult<Duration>;  // blocking ≤ ~0.2 s; returns time until clear
        // Err: Conflict + winnet.clipboard.busy | Internal + winnet.clipboard.failed
    pub fn shutdown(&self);                                 // clears now if still ours, stops the task
}                                                           // drop stops the task without clearing
```
The text is written with `ExcludeClipboardContentFromMonitorProcessing`,
`CanIncludeInClipboardHistory = 0` and `CanUploadToCloudClipboard = 0`; it is cleared after 60 s
only if the clipboard still holds our content (sequence number). The clipboard owner is a private
message-only window on its own message-pump thread (not the app window: `EmptyClipboard` sends the
owner a message and waits, so a UI-thread owner could deadlock with a clear). The UI's copy warning
must not claim that Windows history / sync may keep a copy (B18).

## `elevation`, `single_instance` — process start
```rust
pub fn is_elevated() -> bool;                                        // TokenElevation, read once
    // nothing here elevates (NOADMIN §0): privileged features exist exactly while this is true

pub const MUTEX_NAME: &str = r"Local\VpnTunnelEnforcer.Instance";  // per Windows session
pub const PIPE_PREFIX: &str = r"\\.\pipe\VpnTunnelEnforcer";        // + ".<session id>"
pub struct InstanceNames { pub mutex: String, pub pipe: String }     // tests use random names
impl InstanceNames { pub fn production() -> AppResult<Self>; }      // this process's session
pub enum Command { Activate, ShutdownForUpdate, OpenLink(String) }   // Clone; the caller maps its own argv
pub const MAX_LINK: usize = 16 * 1024;                               // OpenLink: one printable line, <= this
pub enum Acquire { Primary(Primary), Secondary }
pub fn acquire(names: &InstanceNames) -> AppResult<Acquire>;        // Err only for unexpected mutex failures
impl Primary {                                                       // drop = stop listener + release mutex
    pub fn take_commands(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<Command>>;  // once
    pub fn is_listening(&self) -> bool;                              // false: the pipe could not be created
}
pub fn send(pipe: &str, cmd: Command, timeout: Duration) -> AppResult<()>;   // blocking
    // errors carry winnet.singleInstance.noAnswer (Timeout | Permission | Internal; Validation for
    // a link that is not one printable line within MAX_LINK); a primary refuses an activation or
    // a link from another session's client ("other-session" reply = error); an OpenLink is
    // written only to a server in this session running this exe (else Permission, nothing sent)
```
`OpenLink` carries a link Windows passed to a later launch (`--open-link "%1"`, see `url_scheme`);
the listener logs only the command name, never the link (it is a key or a subscription URL).
Pipe names share one global namespace, so before writing a link the client checks the server
(`GetNamedPipeServerSessionId`, the image of `GetNamedPipeServerProcessId`). The pipe's descriptor:
owner = the user; SYSTEM and administrators all; the user read / write / attributes (no
FILE_APPEND_DATA); medium label, no write up. So a link launch (always unelevated) reaches a primary
started as administrator, while an elevated primary answers `shutdown-for-update` only to an equally
elevated client ("denied").
Per session (owner decision 12): every signed-in user runs their own copy; the installer's
`--shutdown-for-update` launch runs in the installing user's session and reaches that user's copy.
`main()` (`update` = the app's own `--shutdown-for-update` flag):
```rust
let command = if update { Command::ShutdownForUpdate } else { Command::Activate };
let names = InstanceNames::production()?;
match single_instance::acquire(&names)? {
    Acquire::Secondary => {
        let _ = single_instance::send(&names.pipe, command, Duration::from_secs(5));
        return Ok(());
    }
    Acquire::Primary(mut primary) => {           // keep `primary` alive for the process lifetime
        if command == Command::ShutdownForUpdate { return Ok(()); }
        let commands = primary.take_commands();  // Activate -> show window; ShutdownForUpdate -> quit
        /* … */
    }
}
```

## `url_scheme` — per-user link schemes (`HKCU\Software\Classes`; blocking, unelevated)
```rust
pub const SCHEMES: [&str; 12];        // vless vmess trojan ss hysteria2 hy2 tuic anytls sing-box clash v2raytun hiddify
pub const OPEN_LINK_FLAG: &str = "--open-link";
pub enum Owner { Free, Ours, Other(Option<String> /* program name: "Happ", "Hiddify Protocol" */),
                 Chosen(String) /* UserChoice ProgId: the user's pick in Windows' chooser */ }
pub enum Took { Ours, Chosen(String) }  // take(): Chosen = the Windows choice stays, nothing written
pub struct SchemeState { pub scheme: &'static str, pub owner: Owner }
pub struct Ensured { pub registered: Vec<&'static str>, pub repointed: usize }
pub struct Registrar;                 // Clone
impl Registrar {
    pub fn current_user() -> Self;    // HKCU classes + record; HKLM classes only read
    pub fn under(root: &str) -> Self; // tests: <root>\Classes, <root>\Machine (stands in for HKLM), <root>\Record, <root>\Choices
    pub fn command(exe: &Path) -> String;               // "\"<exe>\" --open-link \"%1\""
    pub fn initialized(&self) -> Result<bool>;          // the record exists (first run done)
    pub fn states(&self, exe: &Path) -> Result<Vec<SchemeState>>;   // SCHEMES order
    pub fn owner(&self, scheme: &str, exe: &Path) -> Result<Owner>;
    pub fn ensure(&self, exe: &Path) -> Result<Ensured>;  // first run = adopt; later: re-point ours only
    pub fn adopt(&self, exe: &Path) -> Result<Ensured>;   // every Free scheme + ours (re)written for exe (a portable copy's «open links here»)
    pub fn take(&self, scheme: &str, exe: &Path) -> Result<Took>;  // user's request: also another program's class key (kept aside)
    pub fn unregister(&self, scheme: &str, exe: &Path) -> Result<bool>;  // ours (recorded or exe's command); puts back the key we replaced
    pub fn unregister_for(&self, exe: &Path) -> Result<Vec<String>>;  // uninstall: what the record lists for exe; record when empty
    pub fn notify_shell(&self);       // SHChangeNotify(SHCNE_ASSOCCHANGED) after a change; nothing for `under`
}
```
Record `HKCU\Software\VPN Tunnel Enforcer\LinkSchemes`: one value per scheme = the exact command we
wrote; `Previous\<scheme>` = another program's per-user key replaced on the user's request (never a
key of ours; replaced only by a newer foreign key; dropped when the class key vanished meanwhile, so
a removed program's handler is never revived). Owner: a `UserChoice` ProgId under
`HKCU\…\Shell\Associations\UrlAssociations\<scheme>` naming another handler wins (`Chosen(prog_id)`;
Windows reaches no class key then, and only the user changes it, in Windows' default apps), else the
per-user key (ours when it carries the recorded command or this exe's), else a machine-wide key
(`Other`), else `Free`. A scheme name outside `SCHEMES` is `E_INVALIDARG` (nothing written);
`unregister_for` also removes a recorded name only a newer version lists (a value that is no scheme
name is just dropped), so an unknown name never stops an uninstall. Tests use `Registrar::under`
with a throw-away `HKCU\Software\VPNTE-Test-*` key; `system_current_user_round_trip` (ignored,
`changes system state`) runs on the real classes.

## `shell` — hand links and folders to Windows (async; `ShellExecuteExW` on the blocking pool)
```rust
pub async fn open_url(url: &str) -> AppResult<()>;              // http(s) only, else Validation + winnet.shell.badUrl
pub async fn open_folder(path: &Path) -> AppResult<()>;         // absolute existing dir, else Validation + winnet.shell.noFolder
pub async fn open_notification_settings() -> AppResult<()>;     // ms-settings:notifications
    // a failed launch = Permission | Internal + winnet.shell.openFailed (no shell error dialog)
```

## `toast` — AUMID, toasts, notification setting, Start-menu shortcut, block reset
```rust
pub const AUMID: &str = "com.vpntunnelenforcer.app";
pub const DEV_AUMID: &str = "com.vpntunnelenforcer.app.dev";
pub fn app_aumid() -> &'static str;                             // DEV_AUMID in debug builds
pub fn set_process_aumid(aumid: &str) -> AppResult<()>;         // before any window exists
pub fn process_aumid() -> Option<String>;
pub struct Toast { pub title: String, pub body: String, pub sound: bool }
pub type OnActivate = Arc<dyn Fn() + Send + Sync>;              // click while the toast is on screen
pub fn show(aumid: &str, toast: &Toast, on_activate: Option<OnActivate>) -> AppResult<()>;  // blocking WinRT
pub enum NotifySetting { Enabled, Unregistered /* no toast seen yet, or no Start-menu link */,
    DisabledForApplication, DisabledForUser, DisabledByGroupPolicy, DisabledByManifest }
    // allows_toasts() = Enabled | Unregistered; treat Unregistered as "unknown": toast + in-app copy
pub fn notification_setting(aumid: &str) -> AppResult<NotifySetting>;
pub fn notifications_enabled(aumid: &str) -> AppResult<bool>;   // = allows_toasts()
pub struct Shortcut { pub aumid: String, pub target: PathBuf, pub args: String, pub description: String }
pub fn user_programs_dir() -> AppResult<PathBuf>;               // FOLDERID_Programs (per user)
pub fn common_programs_dir() -> AppResult<PathBuf>;             // FOLDERID_CommonPrograms (the installer's link)
pub fn ensure_shortcut(path: &Path, shortcut: &Shortcut) -> AppResult<bool>;  // true = written; blocking COM
    // debug builds refuse AUMID: Validation + winnet.toast.productionAumid
pub fn read_shortcut(path: &Path) -> AppResult<Shortcut>;
pub fn remove_shortcut(path: &Path) -> AppResult<bool>;
pub fn remove_hijacking_dev_shortcut(programs_dir: &Path) -> AppResult<bool>;  // <dir>\Electron.lnk of a dev build
pub const LEGACY_AUMIDS: &[&str];                               // the Electron app's ids (reset only)
pub struct ResetReport { pub cleared: Vec<String>, pub errors: Vec<(String, AppError)> }
pub fn reset_os_block(aumids: &[&str]) -> ResetReport;          // deletes Enabled only when == 0
```
Start-up (after the instance check, before the first window): `set_process_aumid(app_aumid())`;
on a blocking thread `remove_hijacking_dev_shortcut(&user_programs_dir()?)` once (the app keeps a
marker in its data dir). Toasts of an unpackaged app need a Start-menu link carrying the AUMID: the
installer creates `common_programs_dir()/"VPN Tunnel Enforcer.lnk"` and its `--setup
stamp-shortcuts` helper stamps it; a release build re-stamps that link when its AUMID is missing
(`let sc = read_shortcut(&link)?; ensure_shortcut(&link, &Shortcut { aumid: AUMID.into(), ..sc })`)
and never creates a per-user link (the uninstaller removes only the all-users one). Debug builds
that want toasts use a distinct `user_programs_dir()?.join("VPN Tunnel Enforcer (dev).lnk")` with
`DEV_AUMID`, never the production name.
The notifier (preferences, coalescing, in-app fallback) is the app's; "unblock notifications" =
`reset_os_block(&[app_aumid(), LEGACY_AUMIDS…])` + `shell::open_notification_settings()`.

## `power` — wake, unlock and theme events
```rust
pub enum PowerEvent { Resumed, SessionUnlocked, ThemeChanged { dark: bool } }   // Copy
pub struct PowerMonitor;                         // own thread + hidden top-level window; drop stops it
impl PowerMonitor {
    pub fn start() -> AppResult<PowerMonitor>;
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<PowerEvent>;
}
pub fn system_prefers_dark() -> bool;            // AppsUseLightTheme == 0
```
One wake is reported once (5 s de-duplication); `ThemeChanged` only on a real light / dark switch;
suspend is only logged. Subscribers: the lifecycle actor (`Resumed` / `SessionUnlocked` →
re-check the tunnel) and the theme service.

## Not implemented here (by decision)
- `wintun_guid` / LUID-from-name derivation: the TUN's LUID comes from the live adapter
  (`wait_owned_tun`). No adapter or route is ever changed: sing-box owns routes and DNS.
- Proxy baseline (firewall-recovery §6.10) and `proxy_baseline_applied`: the app combines it.
- Legacy cleanup steps (§6.6): crate `cleanup` drives them with `wfp::Engine`, `autostart::read_task`
  / `delete_task*`, `process::sweep_orphans`, `registry`.
- automation's `network_identity()` (NLA + HMAC): build it from `adapters::inventory()`.
- 60 s caches of physical snapshots / DNS sources, alias-based counter lookup, PID files,
  PowerShell / CIM fallbacks: dropped (one native adapter read costs about 10 ms here, and a cache
  served stale DNS after network switches).
- A COM toast activator (activation from Action Center after the popup closed).
- The Run-key login item of an unpackaged old dev build.
- Display formatting (link speed, MAC, route protocol names): the UI / diagnostics renderer's.

## Not verified on this machine (needs elevation, internet or a desktop session)
- WFP filter add / transactions / provider + sublayer creation / persistent filters
  (`cargo test -p vpnte-winnet -- --ignored elevated_`, 5 tests, elevated), the §7.10 manual
  checklist, traffic of Hyper-V guests and Mobile Hotspot clients (not local sockets, so ALE
  filters do not see it; only the Hyper-V switch is detected and warned about).
- Writing the real `Run` key (`system_run_value_round_trip`, throw-away value name), the real
  system proxy (`sysproxy::system_write_reads_back_and_restores`) and the real clipboard
  (`clipboard::system_clipboard_round_trip`; skips where `OpenClipboard` is denied, as in this
  sandboxed shell): all `#[ignore = "changes system state"]`, never run here (this machine's
  network depends on its proxy settings); the registry code runs on throw-away keys and
  `sysproxy::read` read-only. Deleting a real 1.x logon task (`RunValue::remove_legacy_task`)
  was never called.
- A real sing-box TUN for `wait_owned_tun` / `route_proof` success paths (unit vectors only);
  `watch_network` with real network changes (its loop is tested with a fake reader).
- `ctrl_break` from the real GUI app (tests detach the test process from its inherited console
  first) and the TUN interface's removal after a graceful sing-box stop (elevated `e2e_tun` in CI).
- The private clipboard owner window used across threads (see the clipboard test above).
- `icmp` TTL-expired / packet-too-big replies: the local VPN answers echo itself, and GitHub-hosted
  runners drop ICMP to the internet, so `ttl_one_expires_at_the_first_hop` is opt-in
  (`VPNTE_ICMP_TESTS=1`); IPv6 `df` on a link with MTU < 1500.
- `UnicastAddress::temporary` (= random suffix, as the old app): current Windows may also report a
  random suffix for the stable SLAAC address; no global IPv6 here (only diagnostics use it).
- Sweeping an elevated orphan from an unelevated process; second launch from another Windows
  session or an elevated primary with an unelevated client; real sleep / unlock / theme events
  (driven with synthetic messages); real `shell` launches (only validation is tested).
- The real toast (1 ignored test, shows UI): green once, not re-run after the `PROPVARIANT` fix
  (the shortcut tests cover that path); toast activation (`on_activate`) was never clicked.
- Known risks, accepted: if Windows keeps stale `Connection\Name` keys of our removed Wintun
  adapters, `alias::choose` walks down the candidates and can end in `AliasError::Exhausted`
  (a Wintun ghost was seen here, none with our names). Any local process can pre-create the
  instance mutex / pipe name: the app then stays a secondary (denial of service only; the client
  connects with identification-level impersonation). Task Manager's `StartupApproved` encoding
  (odd first byte = off) is the observed convention, not a documented format.
  The clipboard sequence number is read right after `CloseClipboard`: a write by another program
  in that instant would be adopted and cleared.
