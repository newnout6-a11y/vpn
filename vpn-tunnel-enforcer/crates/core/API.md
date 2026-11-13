# vpnte-core — API

Foundation services every backend crate builds on: data directories, JSON documents with atomic
write-through, DPAPI-sealed secrets, the settings document, the one redaction policy, the app /
engine logs, strict address parsing and app-request routes, a SOCKS5 client, name resolution
(system / DoH), the feature-operation registry, and read-only primitives for the one-time import
of the old Electron data. Depends on `vpnte-base` only.

Paths: `vpnte_core::{paths, store, secret, settings, redact, logging, net, socks5, resolve, ops,
legacy}` plus `vpnte_core::LOCALES`. Shared types used below come from `vpnte_base`:
`AppError` / `ErrorKind` / `AppResult`, `Msg`, `types::{UnixMs, now_ms, Owner, ProxyKind, Creds,
KillSwitchLevel, EnginePref}`, `i18n::Lang`. The crate has no cargo features.

**Elevation: nothing here needs it** (everything works without administrator rights). DPAPI runs as the
current user; files are written only where the caller points (the app: under the data dir), the
legacy dir is only read, and nothing touches the registry, firewall, routes or services. Tests use
temp dirs only; the one test that needs the internet (`resolve::tests::live_resolvers`) is
ignored.
**Runtime:** `ops`, `socks5`, `resolve` and the `reqwest` clients of `net` need a tokio runtime;
`logging` owns one writer thread; `Store`, `Secret` (DPAPI) and `legacy` (file reads, DPAPI, which
may contact a domain controller) are blocking: call them from `spawn_blocking` on hot async paths
or with large documents.

## Locales (register at startup)
```rust
pub const LOCALES: &[(&str, &str)];      // (ru_json, en_json) per fragment of this crate
// app, before the UI launches (later calls are ignored):
let layers: Vec<(&str, &str)> = [vpnte_core::LOCALES, vpnte_winnet::LOCALES /* , … */].concat();
vpnte_ui::lang::init_locales(&layers);   // UI base layers first, then these
```
Every `Msg` / `AppError::msg` this crate returns has its key here (all under `core.`):

| Keys | Arguments | Returned by |
| --- | --- | --- |
| `core.store.{readOnly,writeFailed,encodeFailed,newerVersion,corruptKept,unreadable}` | `file` | `Store::update/replace/set_aside` errors, `Store::notice` |
| `core.store.corruptSetAside` | `file`, `backup` | `Store::notice` |
| `core.store.dataDirLocked` | — | `DataDirs::lock` (`Conflict`) |
| `core.settings.proxyOverrideInvalid` | — | `ProxyOverride::parse`, `SettingsPatch::set_proxy_override` |
| `core.settings.legacyProxyDropped` | — | warning of `Settings::from_legacy` |
| `core.net.addressInvalid` | — | `From<AddrError> for AppError` |
| `core.net.socks{Unreachable,Malformed,AuthRequired,AuthRejected,InvalidInput}` | — | `From<SocksError>` |
| `core.net.socksUpstreamRejected` | `code` | `From<SocksError>` |
| `core.net.resolve{InvalidName,NotFound,Filtered,Poisoned,Failed}` | — | `From<ResolveError>` |
| `core.net.resolveLastKnown` | — | `ServerAddrs::warning` |
| `core.ops.{busy,closing,invalidTimeout}` | — | `OperationRegistry::run` |
| `core.log.file.{app,appPrevious}` / `core.log.file.{engine,enginePrevious}` | — / `engine` | `LogFile::label` |
| `core.legacy.{keyUnavailable,secretUnreadable,fileNewer,fileInvalid,fileUnreadable}` | — | `From<KeyError / SecretFault / DocError>` |

Cancellation and timeouts use the canonical `AppError::cancelled()` / `AppError::timeout()`
(`errors.*` keys of the base layer). `ErrorKind::Cancelled` is a quiet outcome (no error toast).

## Events
- `Store<T>::subscribe() -> watch::Receiver<u64>`: generation, bumped after every persisted change
  (and by `set_aside`). Re-read with `store.snapshot()` / `store.read(..)`.
- `OperationRegistry::subscribe() -> broadcast::Receiver<OpMeta>`: every operation transition in
  order; on `Lagged` resync with `list()`.
Nothing else in this crate pushes events.

## `paths` — where things live
```rust
pub const APP_DIR_NAME: &str = "VPN Tunnel Enforcer";   pub const LEGACY_DIR_NAME: &str = "vpn-tunnel-enforcer";
pub const ENV_DATA_DIR: &str = "VPNTE_DATA_DIR";         pub const ENV_LEGACY_DIR: &str = "VPNTE_LEGACY_DIR";
pub const ENV_RESOURCES_DIR: &str = "VPNTE_RESOURCES_DIR";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirs {
    pub root: PathBuf,             // %APPDATA%\VPN Tunnel Enforcer (or VPNTE_DATA_DIR): documents, `lock`
    pub logs: PathBuf,             // <root>\logs
    pub history: PathBuf,          // <root>\history
    pub cache: PathBuf,            // <root>\cache
    pub legacy_electron: PathBuf,  // %APPDATA%\vpn-tunnel-enforcer (or VPNTE_LEGACY_DIR): never written
    pub resources: PathBuf,        // VPNTE_RESOURCES_DIR, else <exe dir>\resources (engines, rule sets)
}
impl DataDirs {
    pub fn resolve() -> AppResult<Self>;   // env overrides (empty = unset, relative made absolute), else the
                                           // Roaming AppData known folder; creates nothing. An ELEVATED
                                           // process ignores all three overrides (any program of the user
                                           // can set them in HKCU\Environment): resources = <exe dir>\resources,
                                           // data / legacy = the normal folders
    pub fn new(root: PathBuf, legacy_electron: PathBuf, resources: PathBuf) -> Self; // logs/history/cache under root
    pub fn ensure(&self) -> AppResult<()>;         // create root, logs, history, cache
    pub fn lock(&self) -> AppResult<DataLock>;     // creates root; exclusive <root>\lock; held elsewhere →
                                                   // Conflict core.store.dataDirLocked
}
#[derive(Debug)] pub struct DataLock;   // keep it for the whole process life; the OS releases it on exit / crash
pub fn log_ignored_overrides();       // elevated + an override set: one warn line per process naming it;
                                     // resolve() and logging::init call it (a line with no subscriber
                                     // is lost, so the guard is spent only when it was logged)
```

## `store` — one persistence mechanism for every JSON document
```rust
pub const SCHEMA_KEY: &str = "schemaVersion";
pub trait Document: Serialize + DeserializeOwned + Default + Clone + PartialEq + Send + Sync + 'static {
    const FILE: &'static str;            // "/"-separated path under the data root: "history/connections.json"
    const VERSION: u32;                  // current schemaVersion (all documents start at 1)
    const HOLDS_SECRETS: bool = false;   // corrupt file: true → kept untouched + read-only; false → moved aside
}
pub enum Mode { Writable, ReadOnly(ReadOnlyReason) }              // Debug, Clone, Copy, PartialEq, Eq
pub enum ReadOnlyReason { NewerVersion(u32), Corrupt, Unreadable } // same derives
pub struct Store<T: Document>;          // one per document per process; share it (Arc) between services
impl<T: Document> Store<T> {
    pub fn open(root: &Path) -> Self;   // never fails: missing → Default (no file until the first change);
                                        // problems become a read-only Mode or a notice; removes the
                                        // <name>.<16 hex>.tmp leftovers of a write that crashed before its rename
    pub fn path(&self) -> &Path;
    pub fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R;   // lock held only during f (no update inside f)
    pub fn snapshot(&self) -> T;
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> AppResult<R>; // copy → f → equal? no write :
                                        // write_atomic → swap → notify; f must not call update on the same store
    pub fn replace(&self, next: T) -> AppResult<()>;
    pub fn subscribe(&self) -> watch::Receiver<u64>;
    pub fn mode(&self) -> Mode;
    pub fn notice(&self) -> Option<Msg>;   // banner text: read-only reason, or "moved aside as <backup>"
    pub fn set_aside(&self) -> AppResult<()>; // Maintenance action for Corrupt / Unreadable: rename to
                                        // <stem>.corrupt-<unix ms>.json, continue empty; refused for
                                        // NewerVersion; no-op when writable
}
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()>; // temp + fsync + MoveFileExW(REPLACE |
                                        // WRITE_THROUGH), retried ~0.8 s on sharing violations; parent dir created
```
On disk: pretty JSON (2 spaces) + newline, `"schemaVersion"` first; unknown keys survive only if
the document type keeps them (`#[serde(flatten)] extra: Map<String, Value>`, as `Settings` does).
A missing / non-integer `schemaVersion` loads as current; a UTF-8 BOM is tolerated. Errors:
read-only → `Conflict` `core.store.readOnly`; I/O → kind from the `io::Error` + `core.store.writeFailed`;
a DPAPI refusal while sealing → `Internal` `core.store.encodeFailed` (never written in plaintext).
A file still held after the retries (or access denied) at open is `Unreadable` for this session;
the next start reads it again (or the user sets it aside).

## `secret` — DPAPI-sealed strings
```rust
#[derive(Clone)] pub struct Secret;     // PartialEq/Eq (plaintext, or sealed bytes when locked);
                                        // Debug "Secret(<redacted>|<locked>)", Display "<secret>"
impl Secret {
    pub fn new(plain: impl Into<String>) -> Self;     // sealed lazily, on first serialisation
    pub fn from_json<T: Serialize + ?Sized>(value: &T) -> Result<Self, SecretError>; // whole-object secrets
    pub fn from_stored(stored: String) -> Self;       // "dpapi:v1:<b64>" → open; else locked, kept byte-for-byte
    pub fn expose(&self) -> Option<&str>;             // None when locked
    pub fn expose_json<T: DeserializeOwned>(&self) -> Result<T, SecretError>;
    pub fn is_locked(&self) -> bool;                  // copied from another account / PC, DPAPI key lost
    pub fn sealed(&self) -> Result<&str, SecretError>; // stored form, sealed once and cached
    pub fn verify(&self) -> Result<(), SecretError>;  // seal → open → compare (import read-back rule)
}
pub enum SecretError { Locked, Dpapi(windows::core::Error), RoundTrip, Json(serde_json::Error) } // Debug, thiserror
```
serde: serialises to the stored form (fails closed if DPAPI cannot seal), deserialises any string
(never fails on a bad blob: it becomes locked). An unchanged secret re-serialises to identical
bytes, so `Store::update` never rewrites a file because of it — provided the document is
serialised by reference: `#[serde(into = ..)]` serialises a clone, which seals again on every save
(new DPAPI salt); write a manual `Serialize` instead (as `ProxyOverride` does). Put secrets in
documents as `Secret` / `Option<Secret>` fields; never log `expose()`.

## `settings` — the `settings.json` document
```rust
pub const CHECK_INTERVAL_MS: (u32, u32) = (5_000, 300_000);     // clamp ranges
pub const DEEP_INSPECTION_MAX_MB: (u32, u32) = (128, 2_048);
pub const RULE_SET_UPDATE_HOURS: (u32, u32) = (1, 720);
pub enum ConnectionMode { LocalProxy /*default*/, DirectVpn }   // JSON "localProxy" / "directVpn"
pub enum RoutingMode { Hard /*default*/, Soft }                 // Hard = TUN (needs elevation); Soft = loopback
                                        // proxy + per-user system proxy (no admin); the wizard picks Soft unelevated
pub enum BootstrapRouteMode { Auto /*default*/, Direct, LocalProxy }
pub enum RuleSetMode { Bundled, Managed /*Settings default*/ }
pub enum RuleSetChoice { Default /*default*/, User }  // who set the list source: the wizard keeps a User choice
pub enum AppScope { All /*default*/, OnlyListed }  // "all" / "onlyListed": the apps page's «Только выбранные приложения»
pub enum NotifyMethod { System /*default*/, InApp, Both }       // "system" / "inapp" / "both"

#[derive(Debug, Clone, PartialEq, Serialize)]   // Deserialize = lenient per field (merge_json)
pub struct Settings {                            // JSON camelCase; Document FILE "settings.json", VERSION 2
    pub connection_mode: ConnectionMode,         pub routing_mode: RoutingMode,
    pub proxy_override: Option<ProxyOverride>,   // manual local proxy; None = detect automatically
    pub proxy_type: ProxyKind,                   // Socks5
    pub bootstrap_route_mode: BootstrapRouteMode,
    pub check_interval_ms: u32,                  // 30_000
    pub disable_geo_lookup: bool,                // false
    pub autostart: bool,                         // false; set only after winnet changed the OS task (not in the patch)
    pub autopilot: bool,                         // true
    pub minimize_to_tray: bool,                  // true
    pub location_privacy: bool, pub domain_enrichment: bool, pub auto_network_baseline: bool, // false
    pub kill_switch: KillSwitchLevel,            // Off (replaces the old boolean firewallKillSwitch)
    pub advanced_mode: bool, pub first_run_complete: bool,                                    // false
    pub auto_restart_on_crash: bool, pub desktop_notifications: bool,                         // true
    pub public_wifi_compatibility: bool,         // true (TUN MTU 1380)
    pub deep_inspection: bool,                   // false: packet capture is opt-in
    pub deep_inspection_max_mb: u32,             // 512
    pub stealth_mode: bool,                      // false
    pub adaptive_bypass: bool, pub adaptive_bypass_server_fallback: bool,                     // true
    pub smart_ru_split: bool, pub smart_ru_maps_direct: bool,                                 // false
    pub smart_ru_rule_set_mode: RuleSetMode,
    pub smart_ru_rule_set_auto_update: bool, pub smart_ru_rule_set_use_proxy: bool,           // true
    pub smart_ru_rule_set_update_hours: u32,     // 24
    pub smart_ru_rule_set_choice: RuleSetChoice, // Default; «Автообновлять списки» on the Settings page = User
    pub proxy_engine: EnginePref,                // Auto
    pub app_scope: AppScope,                     // All; OnlyListed = only the apps set to «Через VPN» (re-check 16)
    pub locale: Option<Lang>,                    // None = follow Windows
    pub active_theme_id: String,                 // "builtin-dark" (the design's reference is dark)
    pub notifications: NotificationPrefs,        // every switch on, method System, sound on
    pub ui: UiPrefs,
    pub log_key: Option<Secret>,                 // log pseudonym key (ensure_log_key); never export it
    pub extra: Map<String, Value>,               // keys of a newer version, kept
}
impl Settings {
    pub fn merge_json(&mut self, obj: Map<String, Value>); // lenient per-key apply (load, config import):
                                        // invalid → current value + warning, numbers rounded + clamped,
                                        // unknown keys kept in `extra` (config import: drop them first)
    pub fn clamp(&mut self);
    pub fn apply(&mut self, patch: SettingsPatch);          // assign the Some fields, clamp
    pub fn ensure_log_key(&mut self) -> Option<[u8; 32]>;   // existing key, or a fresh random one when
                                        // missing / locked / malformed; None only if the OS RNG fails
    pub fn from_legacy(legacy: &Value) -> (Settings, Vec<Msg>); // old settings object (or {"settings":{..}});
                                        // warnings for the import report
    pub fn apply_legacy_stores(&mut self, i18n: Option<&Value>, themes: Option<&Value>,
                               notification_prefs: Option<&Value>);
}
#[derive(Debug, Clone, Default, PartialEq)] pub struct SettingsPatch { /* Option<_> per field except autostart
    and log_key; proxy_override: Option<Option<ProxyOverride>>, locale: Option<Option<Lang>> (Some(None) clears) */ }
impl SettingsPatch { pub fn set_proxy_override(&mut self, input: &str) -> AppResult<()>; } // "" clears;
                                        // a scheme in the input also sets proxy_type
pub fn import_kill_switch(level: Option<&str>, legacy_bool: Option<bool>) -> KillSwitchLevel; // D-16:
                                        // "strict" wins, else firewallKillSwitch == true → Standard, else Off

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]   // Serialize: manual, by reference (sealed once)
pub struct ProxyOverride { pub addr: net::HostPort, pub credentials: Option<Secret> } // stored {host, port, credentials?};
                                        // a stored host failing the grammar loads as None (warning)
impl ProxyOverride {
    pub fn parse(input: &str) -> AppResult<(Self, Option<ProxyKind>)>; // [socks5|socks5h|socks|http://][user[:pass]@]
                                        // host:port, [v6]; strict HostPort grammar; https / socks4 / paths / queries /
                                        // whitespace refused; the userinfo is kept as typed (percent-encoded), sealed
    pub fn creds(&self) -> Option<Creds>;              // percent-decoded; None if absent or locked
    pub fn route(&self, kind: ProxyKind) -> net::Route; // app requests through this proxy (kind = proxy_type)
}
pub struct NotificationPrefs { pub vpn_connect: bool, pub vpn_disconnect: bool, pub leak_detected: bool,
    pub profile_rotation: bool, pub schedule_triggered: bool, pub connection_error: bool,
    pub method: NotifyMethod, pub sound: bool, pub extra: Map<String, Value> }
impl NotificationPrefs { pub fn from_legacy(legacy: &Value) -> Self; }  // old notification-prefs.json
pub struct UiPrefs { pub expanded_groups: Vec<String>, pub dismissed_tips: BTreeSet<String>,
    pub debug_log: bool, pub extra: Map<String, Value> }
```
Version 2 (fix-lists, psmart-a3/b4): a file without `smartRuRuleSetChoice` is version 1 and moves
from bundled to managed lists once on load (`Settings::move_to_managed_lists`: the old app saved
its default "bundled" for everyone, so no stored "bundled" is a choice; `from_legacy` does the
same); the wizard turning Smart RU on calls `Settings::default_lists_unless_chosen`.

Use: `let settings = Arc::new(Store::<Settings>::open(&dirs.root));` then
`settings.update(|s| s.apply(patch))?`. Notification switches govern OS toasts only (protection
notices always reach the in-app list). `HOLDS_SECRETS = false`: a corrupt `settings.json` is moved
aside (proxy credentials stay sealed in the copy) and defaults are used. Config export must drop
`logKey` and `proxyOverride.credentials` (sealed for this account only).

## `redact` — the one redaction policy
```rust
pub const REDACTED: &str = "<redacted>";
pub fn text(s: &str) -> Cow<'_, str>;      // secrets in free text → typed masks: <redacted-vpn-uri>, -proxy-url,
                                           // -url, -credential, -key, -token, -host, -user-path, -uuid, -mac
pub fn for_log(s: &str) -> Cow<'_, str>;   // text() then ips(): what every log line gets
pub fn json(v: &mut serde_json::Value);    // values under secret keys → "<redacted>" (any type); strings → text()
pub fn is_secret_key(key: &str) -> bool;   // JSON key rule: exact keys (any case) uuid, password, pass, user,
                                           // username, id, address, server, server_port, private/public_key,
                                           // short_id, client_secret, token, auth_str, directVpnInput,
                                           // vpnInput, subscription(Url), up/down_mbps; `vpnte_xray`; plus
                                           // every name is_secret_field matches
pub fn is_secret_field(name: &str) -> bool; // log field-name rule: contains uuid, password, passwd, passphrase,
                                           // token, secret, private/public/api_key, pre_shared, short_id, auth,
                                           // credential, cookie, headers or hwid; or is pbk / sid / psk
pub fn ip_pseudonym(ip: IpAddr) -> String; // public → "ip_" + 8 hex of HMAC-SHA256(key, octets); private,
                                           // loopback, CGNAT, link-local, ULA, multicast, fake-ip pools verbatim
pub fn ips(s: &str) -> Cow<'_, str>;       // public IPv4 / IPv6 in text → pseudonyms
pub fn set_ip_key(key: &[u8; 32]);         // the persisted per-install key (Settings::ensure_log_key);
                                           // until then a per-process random key
```
Every UUID-shaped token and every 43-char mixed base64 token in free text is masked (fail closed):
put ids that must stay readable into the `profile` / `group` / `op` / `corr` / `slot` log fields.
Diagnostics exports run documents through `json` and free text through `for_log`.

## `logging` — app log, engine logs, log viewer
```rust
pub const APP_LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;   pub const TAIL_MAX_BYTES: usize = 1024 * 1024;
pub const APP_STEM: &str = "app";
pub const ENGINE_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;   pub const ENGINE_TAIL_LINES: usize = 64;
pub fn init(dir: &Path, debug: bool) -> AppResult<LogGuard>; // global subscriber → <dir>\app.log (+ .1.log),
                                           // panic hook (logs the panic, waits ≤ 2 s for the disk);
                                           // Conflict when a global subscriber already exists
#[must_use] pub struct LogGuard;           // keep in main; Drop drains the queue (≤ 5 s) and stops the writer
pub fn set_debug(on: bool);                // ui.debug_log at runtime
pub fn flush();                            // wait (≤ 2 s) until queued lines are on disk
pub fn recent_problems() -> Vec<Problem>;  // last 200 WARN / ERROR events of this run, oldest first
pub struct Problem { pub at: UnixMs, pub level: tracing::Level, pub target: String, pub msg: String }
#[derive(Serialize, Deserialize)]
pub struct LogLine { pub ts: String, pub level: String, pub target: String, pub msg: String,
                     pub fields: Map<String, Value>, pub corr: Option<String> }   // one app.log line
pub struct LogFile { pub stem: String, pub previous: bool }
impl LogFile {
    pub fn app() -> Self;  pub fn engine(stem: impl Into<String>) -> Self;  pub fn previous(self) -> Self;
    pub fn file_name(&self) -> String;     // app.log, sing-box.1.log
    pub fn artifact(&self) -> String;      // app-log, sing-box-previous-log (ClearReport names)
    pub fn label(&self) -> Msg;            // core.log.file.*
}
pub struct LogSnapshot { pub name: String, pub exists: bool, pub size: u64, pub truncated: bool, pub content: String }
pub struct ClearReport { pub cleared: Vec<String>, pub absent: Vec<String>, pub errors: Vec<(String, ErrorKind)> }
pub fn list(dir: &Path) -> io::Result<Vec<LogFile>>;   // app first, then engines; current before previous
pub fn tail(dir: &Path, file: &LogFile, max_bytes: usize) -> io::Result<LogSnapshot>; // whole lines
pub struct TailLine { pub offset: u64, pub text: String }    // p-logs: byte offset = a row key that
pub struct LineTail { pub exists: bool, pub truncated: bool, pub lines: Vec<TailLine> } // survives re-reads
pub fn tail_lines(dir: &Path, file: &LogFile, max_bytes: usize) -> io::Result<LineTail>; // blank lines skipped
pub fn split_lines(start: u64, bytes: &[u8]) -> Vec<TailLine>;   // LF / CRLF
pub fn event_line(event: &tracing::Event<'_>) -> LogLine;  // one event, redacted like app.log (no spans):
                                           // the helper service's own log (p-logs)
pub fn clear(dir: &Path) -> ClearReport;   // truncates current logs (through live writers), deletes .1.log
#[derive(Clone)] pub struct RotatingFile;  // clones share one file; one writer per path per process
impl RotatingFile {
    pub fn open(dir: &Path, stem: &str, max_bytes: u64, tail_lines: usize) -> io::Result<Self>; // stem
                                           // [a-z0-9-]+; a path already open returns that live writer (its cap
                                           // and tail kept), which reopens <stem>.log on its next write
    pub fn engine(dir: &Path, stem: &str) -> io::Result<Self>;   // 10 MiB + .1.log, 64-line tail
    pub fn write_line(&self, line: &str) -> io::Result<()>;      // redact::for_log, then file + tail
    pub fn tail(&self) -> Vec<String>;                           // redacted, oldest first
    pub fn path(&self) -> PathBuf;
}
```
Line format: `{"ts":"2026-11-11T08:00:00.000Z","level":"INFO","target":"vpnte_x::y","msg":"…","fields":{…},"corr":"op_…"}`.
Own targets (`vpnte*`) are written from INFO (DEBUG when toggled), libraries from WARN; TRACE never.
Fields with secret names become `<redacted>`; strings are redacted and cut at 4000 chars; a
`corr` field (or one on an enclosing span) is lifted to the top level. Log lines are English,
never localized. Engines: `RotatingFile::engine(&dirs.logs, "sing-box" | "xray")`, `write_line`
per pipe line; classify faults on the raw line before writing it, use `tail()` as outcome evidence.
Libraries that log through the `log` crate (rustls, reqwest, tao) do not reach the layer: no
`tracing-log` bridge is installed; the app can add `tracing_log::LogTracer` after `init`.

## `net` — addresses, the public-IP predicate, app-request routes
```rust
pub enum AddrError { Empty, MissingPort, BadPort, BadHost }   // Copy; From for AppError (Validation, core.net.addressInvalid)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host { Ip(IpAddr), Name(String) }   // names lowercase, no trailing dot; Display, FromStr
impl Host { pub fn parse(s: &str) -> Result<Host, AddrError>;  // IP literal, [v6] or RFC 1123 name (+ `_`);
            pub fn ip(&self) -> Option<IpAddr>; }              // "999.1.1.1", "127.1", "0x7f.1" and
                                                               // undecodable punycode ("xn--zz") refused
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostPort;                         // Display "host:port" / "[v6]:port"; FromStr; TryFrom<SocketAddr>
impl HostPort {
    pub fn parse(s: &str) -> Result<HostPort, AddrError>;   // strict, trimmed; port 1..=65535 (≤ 5 digits);
                                                             // unbracketed IPv6 and "[v4]:port" refused
    pub fn new(host: &str, port: u16) -> Result<HostPort, AddrError>;
    pub fn host(&self) -> &Host;   pub fn port(&self) -> u16;
    pub fn socket_addr(&self) -> Option<SocketAddr>;        // when the host is an IP literal (mapped kept)
}
pub fn is_public_ip(ip: IpAddr) -> bool;     // the one public-address predicate (special / documentation /
                                             // CGNAT / ULA / Teredo … blocks excluded; mapped, NAT64, 6to4
                                             // judged by the IPv4)
pub fn is_loopback(ip: IpAddr) -> bool;  pub fn is_private(ip: IpAddr) -> bool;
pub fn is_cgnat(ip: IpAddr) -> bool;     pub fn is_link_local(ip: IpAddr) -> bool;
pub fn unmap(ip: IpAddr) -> IpAddr;          // ::ffff:a.b.c.d → a.b.c.d
#[derive(Clone, PartialEq, Eq)]
pub enum Route { Direct, Proxy { url: Url } } // Debug "Route(<label>)", never credentials
impl Route {
    pub fn proxy(kind: ProxyKind, addr: &HostPort, creds: Option<&Creds>) -> Route; // socks5h:// | http://
    pub fn label(&self) -> String;           // "direct" | "socks5h://127.0.0.1:10808": log-safe, dedupe key
                                             // (a scheme's default port is omitted: "http://h")
}
pub fn builder_for(route: &Route, timeout: Duration) -> AppResult<reqwest::ClientBuilder>; // base defaults
                                             // (no implicit system proxy, no redirects) bound to the route
pub fn client_for(route: &Route, timeout: Duration) -> AppResult<reqwest::Client>;
```
Pinned direct request (DoH retry of a subscription): `builder_for(&Route::Direct, t)?.resolve_to_addrs(host, &addrs).build()`.
User proxy: `settings.proxy_override.as_ref().map(|p| p.route(settings.proxy_type))`. Call
`vpnte_base::http::init_tls()` once at startup before building clients.

## `socks5` — SOCKS5 client (RFC 1928 / 1929)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksError { Connect(io::ErrorKind), Io(io::ErrorKind), Closed, AuthRequired, AuthRejected,
                      UpstreamRejected(u8), Malformed, InvalidInput, Timeout, Cancelled } // From for AppError
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, creds: Option<&Creds>) -> Result<(), SocksError>;
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, creds: Option<&Creds>,
                                                          target: &HostPort) -> Result<(), SocksError>;
pub async fn connect(proxy: SocketAddr, creds: Option<&Creds>, target: &HostPort,
                     limit: Duration) -> Result<TcpStream, SocksError>; // one deadline for TCP + handshake
pub async fn wait_ready(port: u16, creds: Option<&Creds>, total: Duration,
                        cancel: &CancellationToken) -> Result<(), SocksError>; // polls 127.0.0.1:port
```
With credentials only user/password (0x02) is offered, without only no-auth (0x00); anything else is
`AuthRequired`. Targets: IPv4 → ATYP 1, IPv6 → ATYP 4, names → ATYP 3 (resolved by the proxy).
`wait_ready` retries every 100 ms (attempt ≤ 250 ms), returns at once on a definite answer
(`AuthRequired` / `AuthRejected` / `Malformed`), else the last error or `Timeout`; cancel wins.
Without credentials an accepted TCP connection counts as ready (no SOCKS greeting is sent).
Port 0 and credentials outside 1..=255 bytes → `InvalidInput` before any I/O.

## `resolve` — app-side name resolution
```rust
pub enum How { System, Doh }                 // OS resolver | the direct chain below (A and AAAA)
pub enum ResolveError { InvalidName, NotFound, Filtered, Poisoned, Failed }  // Copy; From for AppError
pub async fn resolve_host(name: &str, how: How, keep: impl Fn(IpAddr) -> bool)
    -> Result<Vec<IpAddr>, ResolveError>;    // deduplicated, IPv4 first, only addresses `keep` accepts
pub struct ServerAddrs { pub addrs: Vec<IpAddr>, pub last_known: bool }   // Clone, PartialEq
impl ServerAddrs { pub fn warning(&self) -> Option<Msg>; }   // core.net.resolveLastKnown when last_known
pub async fn resolve_server(name: &str, keep: impl Fn(IpAddr) -> bool)
    -> Result<ServerAddrs, ResolveError>;    // VPN server names: chain -> OS (2.5 s) -> last known
pub enum DohByName { Cloudflare, Yandex }    // one DoH-by-name upstream, for the network-mode check
pub async fn resolve_with(name: &str, resolver: DohByName, via: Option<&Loopback>,
    keep: impl Fn(IpAddr) -> bool) -> Result<Vec<IpAddr>, ResolveError>;  // via = loopback SOCKS5 inbound
pub const MEMORY_TTL: Duration;              // 7 days
pub struct ResolverMemoryDoc;                // Document "cache/resolver.json": one DPAPI-sealed payload
pub fn persist(root: &Path, network: Option<String>, cancel: CancellationToken); // load + seed + apply the
                                             // network's winner at start; save on change every 30 s and at cancel
pub fn set_network(key: Option<String>, at: UnixMs);  // moved to network `key` (None = unknown) at `at`
```
`persist` (call once inside the runtime, before the first connect) seeds the last-known server
addresses and the per-network winning upstream from the sealed document (entries older than
`MEMORY_TTL` dropped, at most 32 networks), asks the winner of `network` (the caller's quick read
of the current network) first from the very first lookup, and writes the memory back only when it
changed (a winner keeps the time it won; the same winner again is stamped anew only once a day).
`set_network` credits each chain win to the network that was current when it was won: a win
before `at` stays with the old network, a win since `at` belongs to the new one and is asked first
there; otherwise the new network's remembered winner (for example Yandex DoH on a mobile
whitelist) goes first, and an unknown network uses the production order. `resolve_with` asks exactly one upstream and leaves the shared chain alone.
An IP literal is returned without a lookup (still filtered; `resolve_server` never marks it
`last_known`). `System` has no deadline of its own: wrap it in `tokio::time::timeout`. It is
the honest OS answer (diagnostics rely on it) and cannot see poisoning.

`Doh` = the direct chain against the 2026 Russian DNS blocking (ru-2026 Ф9: DoT cut, DoH cut
by SNI, UDP/53 to public resolvers redirected to the NSDI, which forges NXDOMAIN with AA; TCP/53
untouched): RFC 8484 DoH POST to `1.1.1.1`, `9.9.9.9` (HTTP/2 only), `8.8.8.8`,
`94.140.14.140` (AdGuard unfiltered) by IP literal (no SNI, no DNS of its own), then DoH by
name (`common.dot.dns.yandex.net`, `cloudflare-dns.com`), then DNS over TCP/53 to `8.8.8.8`,
`1.1.1.1`, `77.88.8.8`. In that order; the next upstream also starts after a 0.7 s head start
or at once when one fails; 3 s per upstream; the second record type gets 0.3 s once the first
brought addresses; the upstream that answered last is asked first next time (process-wide).
Poisoned (NXDOMAIN with AA, or only block-page addresses: unspecified, loopback, `0/8`,
link-local, multicast, class E) counts as a failure and moves on; block-page addresses are
dropped next to real ones (private and CGNAT stay). All upstreams missing = the most telling
error (`Filtered` > `NotFound` > `Poisoned` > `Failed`), never an empty success.
`keep = net::is_public_ip` refuses private answers too (subscriptions). Debug log lines name an
upstream by its index in that order (`upstream = 0..8`; the log masks URLs and public IPs) with
the transport's cause chain (`resolver unreachable`) or the verdict (`no usable address`).

`resolve_server` (before an engine dials a server name): the chain, then the OS resolver
(mobile whitelists may leave only the ISP's DNS; a block-page-only OS answer = `Poisoned`; the
chain's verdict stands over an OS `NotFound`, which cannot be told from a forged one), then the
addresses the name had at its last successful lookup (256 names; never older than `MEMORY_TTL`,
however long the process runs): returned with `last_known: true` on `Failed` / `Poisoned` /
`NotFound`, never on `Filtered` (a real answer the caller refuses). Show `warning()` to the user.
Only chain answers are persisted by `persist`; an OS-resolver answer taken while the chain fails
(a stub page, a captive portal) never replaces a chain-verified address and lives for this run
only.

## `ops` — registry of long feature operations
```rust
pub use tokio_util::sync::CancellationToken;   pub use vpnte_base::types::Owner;   // Ord == priority
pub enum Source { Ui, Tray, Lifecycle /*default*/, Runtime, Unknown }   // lowercase ("ipc" read as Ui)
pub struct CorrelationId;                // "op_" + 32 hex (UUID v4 bits); Default/new(), parse(&str) -> Option, as_str, Display
pub struct OpId;                         // process-wide counter; Display "op_<hex>"; OpId::next()
pub enum OpStatus { Running, Success, Cancelled, Error }
pub enum FeatureKind { Refresh, SpeedTest, Import, Export, Rotation, HealthCheck, AvailabilityCheck,
                       RoutingCheck, ServerProbe, LeakCheck, Snapshot }   // kebab-case wire names
impl FeatureKind { pub const ALL: [FeatureKind; 11];
                   pub const fn deadline(self) -> Duration;   // 120 s; SpeedTest / HealthCheck 600 s;
                                                              // Availability / Routing / LeakCheck / Snapshot 60 s; ServerProbe 9 s
                   pub const fn as_str(self) -> &'static str; } // wire name = default resource
pub enum OpKind { Connect, Disconnect, Rotation, /* … every FeatureKind */ }   // From<FeatureKind>
pub struct OpMeta { pub id: OpId, pub correlation: CorrelationId, pub owner: Owner, pub source: Source,
                    pub kind: OpKind, pub started_at: UnixMs, pub deadline: Option<UnixMs>, // None while paused
                    pub status: OpStatus, pub category: Option<ErrorKind> }   // camelCase
pub struct RunOpts { pub owner: Owner, pub source: Source, pub resource: Option<Cow<'static, str>>,
                     pub timeout: Option<Duration>, pub cancel: Option<CancellationToken>,
                     pub correlation: Option<CorrelationId> }   // Default: Manual, Lifecycle, kind's resource,
                                                                // kind's deadline, no token, new correlation
#[derive(Clone)] pub struct OperationRegistry;   // Default; Arc inside: create one, clone it everywhere
impl OperationRegistry {
    pub fn new() -> Self;
    pub async fn run<T, F, Fut>(&self, kind: FeatureKind, opts: RunOpts, f: F) -> AppResult<T>
        where T: Send + 'static, F: FnOnce(Lease) -> Fut, Fut: Future<Output = AppResult<T>> + Send + 'static;
    pub fn cancel(&self, id: OpId) -> bool;               // false: unknown, finished or committing (a cancel
                                                          // during a commit still applies if the commit fails)
    pub fn is_busy(&self, resource: &str) -> bool;
    pub fn list(&self) -> Vec<OpMeta>;                    // oldest first, ≤ 1000, live never evicted
    pub fn subscribe(&self) -> broadcast::Receiver<OpMeta>;
    pub async fn close(&self);                            // refuse + cancel all + wait for drains
    pub fn resume_admission(&self) -> bool;               // after a refused quit; false while old effects drain
}
#[derive(Clone)] pub struct Lease;
impl Lease {
    pub fn id(&self) -> OpId;   pub fn correlation(&self) -> &CorrelationId;   pub fn meta(&self) -> Option<OpMeta>;
    pub fn token(&self) -> &CancellationToken;   // cancelled on abort, own failure, and once settled
    pub fn assert_active(&self) -> AppResult<()>;  // call before publishing anything
    pub fn wait<T: Send + 'static>(&self, fut: impl Future<Output = T> + Send + 'static)
        -> impl Future<Output = AppResult<T>> + Send + 'static;   // tracked effect, aborts promptly
    pub fn wait_for_user<T: Send + 'static>(&self, fut: impl Future<Output = T> + Send + 'static)
        -> impl Future<Output = AppResult<T>> + Send + 'static;   // pauses the work budget meanwhile
    pub fn commit<T>(&self, f: impl FnOnce() -> AppResult<T>) -> AppResult<T>; // final persistence; Ok = success;
                                        // Conflict while a tracked effect is pending; Err or a panic in f =
                                        // failed commit (an abort that landed during f applies then)
    pub fn cancel(&self) -> bool;   pub fn expire(&self) -> bool;  // coordinator: cancelled / timeout
}
```
Semantics: single flight per resource (default = the kind's wire name; pass a dynamic resource such
as `format!("refresh:{group}")` for finer locking). A strictly higher owner cancels a running
predecessor and is admitted after its drain, within its own deadline; an equal / lower owner, or a
predecessor already ending, gets `Conflict` `core.ops.busy` at once. The caller gets the abort error
(cancel, timeout, pre-emption, close) immediately while the resource stays busy until every effect
spawned through the lease settled. Dropping the `run` future cancels the operation. Nothing may
happen after `commit`; a failure returned after a commit reaches the caller, while the history
keeps the committed success.
Errors: `core.ops.busy` / `core.ops.closing` (`Conflict`), `core.ops.invalidTimeout` (`Validation`,
1 ms ..= 2^31-1 ms), canonical `Cancelled` / `Timeout`, an effect's own `AppError` unchanged.
```rust
let n = ops.run(FeatureKind::Export, RunOpts { source: Source::Ui, ..Default::default() }, |lease| async move {
    let doc = lease.wait(build_export()).await?;   // tracked, cancellable
    lease.commit(|| write_file(&doc))               // success is final from here on
}).await?;
```
Lane operations of the tunnel (connect / disconnect / rotation) publish their own `OpMeta` with
`OpKind::{Connect, Disconnect, Rotation}`, ids from `OpId::next()`, `CorrelationId::new()`.
App shutdown: `tokio::time::timeout(budget, ops.close()).await`; after a refused quit
`ops.resume_admission()`. Operations UI: `list()` + `subscribe()` + `cancel(id)`.
Known limits (by design): a user wait opened from another task than the effect body within one
timer tick of the deadline can still time out (in the effect body it is exact); `Lease::wait`
after the operation's own failure returns `Cancelled` at once (nothing may be published then).

## `legacy` — read-only primitives for the one-time Electron import
```rust
pub struct LegacyDir;                       // nothing under it is ever written, renamed or deleted
impl LegacyDir {
    pub fn at(path: impl Into<PathBuf>) -> Self;          // LegacyDir::at(&dirs.legacy_electron)
    pub fn path(&self) -> &Path;
    pub fn stores_present(&self) -> io::Result<Vec<&'static str>>; // known stores with a <store>.json (empty = nothing to import; Err = could not check)
    pub fn plaintext_leftovers(&self) -> Vec<String>;      // names only: settings.json.bak-*, live-server-checks.json.bak / .v0.bak
    pub fn read(&self, store: &str) -> Result<Option<LegacyDoc>, DocError>;        // Ok(None) = no file
    pub fn read_backup(&self, store: &str) -> Result<Option<LegacyDoc>, DocError>; // <store>.json.bak (live checks)
    pub fn chromium_key(&self) -> Result<ChromiumKey, KeyError>;                   // from `Local State`
}
pub const STORES: &[(&str, u64)];  // settings(2), server-picker(2), server-groups, adaptive-bypass, connection-history,
    // dns-profiles, domain-intelligence, domain-routing, external-proxy-leases, granular-kill-switch, i18n,
    // notification-prefs, profile-rotation, scheduler, smart-route-rule-sets, speed-test, split-tunnel, themes,
    // traffic-domains, url-availability (0), live-server-checks(1): name and newest schemaVersion
pub struct LegacyDoc;              // Debug shows store + version only
impl LegacyDoc {
    pub fn parse(store: &str, bytes: &[u8]) -> Result<Self, DocError>;    // lenient JSON (BOM, bad UTF-8, lone surrogates)
    pub fn from_value(store: &str, raw: Value) -> Result<Self, DocError>; // admission like the old store
    pub fn store(&self) -> &'static str;   pub fn version(&self) -> u64;   pub fn raw(&self) -> &Value;
    pub fn open(&self, key: Option<&ChromiumKey>) -> OpenedDoc;
}
pub struct OpenedDoc { pub value: Value,   // every envelope replaced: text | parsed JSON at JSON positions |
                                           // {"__vpnteLocked": true} (key missing) | null (never opens)
                       pub opened: u32, pub locked: Vec<String>,                 // RFC 6901 pointers
                       pub invalid: Vec<(String, SecretFault)> }
pub const LOCKED_MARKER: &str = "__vpnteLocked";   pub fn is_locked(v: &Value) -> bool;
pub enum DocError { Unregistered(String), Io(io::Error), TooLarge, Corrupt, Backup, InvalidVersion,
                    Newer { found: u64, supported: u64 } }   // From for AppError (core.legacy.file*)
impl DocError { pub fn reason(&self) -> &'static str; }      // unregistered|unreadable|too-large|corrupt|backup|invalid|newer
pub struct ChromiumKey;                     // Zeroizing AES-256 key, Debug "ChromiumKey(..)"
pub fn chromium_key(legacy: &Path) -> Result<ChromiumKey, KeyError>;
pub fn open_v10(key: &ChromiumKey, blob: &[u8]) -> Result<String, SecretFault>;
pub fn secret_ref_ciphertext(v: &Value) -> Option<&str>;   pub fn is_encrypted_backup(v: &Value) -> bool;
pub fn legacy_secret(key: Option<&ChromiumKey>, v: Option<&Value>) -> LegacyValue;  // one secret position
pub fn open_ciphertext(key: Option<&ChromiumKey>, text: &str) -> LegacyValue;       // bare ciphertext string
pub enum LegacyValue { Absent, Plain(Value), Opened(String), Locked, Invalid(SecretFault) } // Debug hides secrets
pub enum KeyError { Missing, Io(io::ErrorKind), Malformed, NoKey, Encoding, Header, Dpapi(windows::core::Error),
                    Length(usize) }         // From for AppError (core.legacy.keyUnavailable; Dpapi → Permission)
pub enum SecretFault { TestCipher, Encoding, Format, Auth, Utf8, Json } // From for AppError (core.legacy.secretUnreadable)
```
Each crate maps opened documents into its own types (`Settings::from_legacy`, servers, …); the app
orchestrates the import, the report and the "secrets pending" retry. Re-wrapped secrets: check
`Secret::verify` before committing.

## Main flows
```rust
// app start (before anything else writes)
vpnte_base::http::init_tls();
let dirs = DataDirs::resolve()?;
dirs.ensure()?;
let _lock = dirs.lock()?;                                   // second instance → Conflict
let settings = Arc::new(Store::<Settings>::open(&dirs.root));
let _log = logging::init(&dirs.logs, settings.read(|s| s.ui.debug_log))?;
// a read-only settings.json (newer version / unreadable) must not stop the start (B28): key unsaved
let log_key = settings.update(Settings::ensure_log_key)
    .unwrap_or_else(|_| settings.snapshot().ensure_log_key());
if let Some(key) = log_key { redact::set_ip_key(&key); }
let ops = OperationRegistry::new();

// one-time legacy import (orchestrated by the app; blocking: run it on spawn_blocking)
let legacy = LegacyDir::at(&dirs.legacy_electron);
let key = legacy.chromium_key().ok();                       // Err → secrets stay locked, retry later
let mut open = |store: &str| match legacy.read(store) {    // Ok(None) = no such file
    Ok(doc) => doc.map(|doc| doc.open(key.as_ref()).value),
    Err(e) => { report.skipped(store, e.reason()); None }  // `report`: the app's import report
};
if let Some(old) = open("settings") {
    let (mut imported, warnings) = Settings::from_legacy(&old);   // warnings → import report
    let granular = open("granular-kill-switch");
    let level = granular.as_ref().and_then(|g| g.get("killSwitchLevel")).and_then(Value::as_str);
    let flag = old.pointer("/settings/firewallKillSwitch").and_then(Value::as_bool);
    imported.kill_switch = settings::import_kill_switch(level, flag);
    let (i18n, themes, prefs) = (open("i18n"), open("themes"), open("notification-prefs"));
    imported.apply_legacy_stores(i18n.as_ref(), themes.as_ref(), prefs.as_ref());
    settings.update(move |s| *s = Settings { log_key: s.log_key.take(), ..imported })?;
}
```
`DocError::reason()` feeds the report's "skipped" outcome; `OpenedDoc::locked` counts secrets
waiting for the key; consumers check `legacy::is_locked(v)` at their secret positions.

## Not implemented here (by design)
- Opening folders, autostart, toasts, elevation: `vpnte-winnet`. Changing `Settings::autostart`
  is the app's job after winnet changed the OS task.
- Import orchestration, receipts, `ImportReport`, config export / import (storage §6.7): the app.
- Route lists for subscriptions / geo lookups: callers build them from `Route::Direct` and
  `ProxyOverride::route` (dedupe by `label()`).
- Schema upgrades: every document is at version 1; a newer file opens read-only.
- Old `app.log` is not imported; integrity markers, mojibake repair, journals: dropped (contract §1).
- `log`-crate bridge (`tracing-log`): not in the dependency tree; the app installs one if wanted.
- Redaction gaps left open on purpose (no producer logs such text, B5): triple-escaped JSON,
  percent-encoded or `\/\/`-escaped share links in free text, secrets inside cookies.
- Name lookups through the tunnel's DNS (sing-box UDP path) and SOCKS latency / egress probes:
  engine and probes crates (they use `socks5::connect` / `handshake` and `resolve_host`).
- Persisting the last-known server addresses (`resolve_server` keeps them in memory: no
  document exists for DNS answers); the chain does not bind to the physical adapter, so with
  the TUN up its lookups go through the tunnel like any app request.
