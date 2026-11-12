# vpnte-engine — API for dependent crates

sing-box and Xray: the full sing-box config of a tunnel start, Xray configs and endpoint
resolution, engine processes (spawn / readiness / exit / faults), the Clash API client, the
user's routing document (split tunnelling, DNS profiles, domain rules, hits), Smart RU rule
sets and installed-app discovery. Depends on `vpnte-base`, `vpnte-core`, `vpnte-winnet`,
`vpnte-profiles`.

```toml
vpnte-engine.workspace = true
```

| module | what |
| --- | --- |
| `tags` | every sing-box tag (`PROXY_OUT`, `SLOT_TAGS`, `DNS_REMOTE`, ...) |
| `slot` | `Slot` (A / B) and the validated `SlotEndpoint` (authenticated loopback SOCKS) |
| `ports` | loopback port allocation, random secrets / credentials |
| `singbox_config` | pure builder of the whole sing-box 1.14 config (`build`; TUN or loopback-proxy capture), `select_mtu`, `compat_key` |
| `singbox_process` | one sing-box child: spawn, readiness, exit, faults, version, `check_config` |
| `xray_process` | `XraySupervisor`: the two Xray slots, exit events, faults, `check_config` |
| `clash_api` | Clash API client: version, selector switch with read-back, connections, traffic |
| `xray_config` | engine selection, profile -> Xray JSON, slot config, async name pre-resolution |
| `routing` | `RulesDoc` (`rules.json`), patterns / DNS / split types, fragment generator `build`, hits, Smart RU rule sets |
| `apps` | installed-application discovery for the split-tunnel picker |
| `LOCALES` | `&[(ru_json, en_json)]`: register at start (after the UI base layer) |

**Runtime:** `singbox_process`, `xray_process`, `clash_api`, `xray_config::resolve_hosts` and
`routing::rulesets::RuleSetService::refresh` need a tokio runtime. Everything else is pure or
blocking file / registry I/O (`apps::discover`, `routing::process::probe_fs`,
`routing::domain::read_list_file`, `RuleSetService::prune`: call them from `spawn_blocking`).
**Elevation:** nothing in this crate asks for it, but a `sing-box run` with the TUN inbound of
`singbox_config::build` (`Capture::Tun`) needs an elevated process (Wintun); without it sing-box
exits during start-up (`StartError::Exited`, reason in `ExitInfo::stderr_tail`). The proxy
capture (`Capture::Proxy`, NOADMIN.md §2), `check` / `-test` runs and Xray never need it. Not
executed here: a real TUN start (all engine tests are loopback-only).
**Pinned engines:** in an elevated process every engine run (`run`, `check`, `version`,
`rule-set match`) first verifies the exe — for sing-box also `libcronet.dll` and `wintun.dll`
next to it — against the SHA-256 pins of `resources/engines.toml` (compiled in): the per-user
install folder is user-writable. Verified files stay open without write / delete sharing until
the process ends (the first run hashes them once). A different or relative-path file is refused
before the spawn: `io::ErrorKind::InvalidData`, rendered as `engine.process.notPinned(file)` by
the `From<…> for AppError` impls; a missing one (a missing DLL too: Windows would search `PATH`
for it) as `io::ErrorKind::NotFound`, rendered as `engine.process.fileMissing(file)`. Unelevated
nothing is checked.
**Errors:** every error enum has `From<_> for vpnte_base::AppError` with an `engine.*` message;
callers bubble them with `?` and render `AppError::user_msg()`.
**Children:** every engine runs hidden (CREATE_NO_WINDOW, in its own windowless console and
process group) in its own kill-on-close Job: dropping the owning value kills exactly that
process; a stop asks it to end (CTRL_BREAK) before it kills. Config always goes over stdin.

## `tags`

```rust
pub const PROXY_OUT: &str = "proxy-out";        // final outbound; Clash selector group in slot mode
pub const DIRECT_OUT: &str = "direct-out";
pub const TUN_IN: &str = "tun-in";
pub const PROXY_IN: &str = "proxy-in";          // unauthenticated loopback mixed inbound (proxy capture)
pub const DIRECT_IN: &str = "mixed-direct-in";  // authenticated loopback mixed inbound -> direct
pub const PROBE_IN: &str = "live-check-in";     // authenticated loopback mixed inbound -> proxy-out
pub const DNS_BOOTSTRAP_IN: &str = "dns-bootstrap-in";
pub const SLOT_TAGS: [&str; 2] = ["vpnte-upstream-a", "vpnte-upstream-b"];
pub const DNS_REMOTE: &str = "dns-remote";      // dns.final, through proxy-out
pub const DNS_RESOLVER: &str = "dns-resolver";  // resolves hostname DoH/DoT servers, through proxy-out
pub const DNS_BOOTSTRAP: &str = "dns-bootstrap";// direct, for upstream server names
pub const DNS_BOOTSTRAP_QUAD9, DNS_BOOTSTRAP_GOOGLE, DNS_BOOTSTRAP_TCP, DNS_BOOTSTRAP_ISP: &str;
                                                // the rest of the slot mode's bootstrap order
pub const DNS_DIRECT: &str = "dns-direct";      // direct, for Smart RU / user "direct" domains
```
Clash `chains` of a connection end in `PROXY_OUT` / `DIRECT_OUT` (or a slot tag).

## `slot`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Slot { #[default] A, B }
impl Slot {
    pub const BOTH: [Slot; 2];
    pub fn other(self) -> Slot;
    pub fn index(self) -> usize;              // position in SLOT_TAGS / XraySlots.slots
    pub fn tag(self) -> &'static str;         // SLOT_TAGS[index]
    pub fn log_stem(self) -> &'static str;    // "xray-a" | "xray-b"
}
#[derive(Debug /* hides creds */, Clone, PartialEq, Eq)]
pub struct SlotEndpoint { /* port, creds: private */ }
impl SlotEndpoint {
    pub fn new(port: u16, creds: Creds) -> Result<Self, InvalidEndpoint>;  // port != 0, user/pass 1..=255 bytes
    pub fn allocate(taken: &[u16]) -> Result<Self, PortsExhausted>;      // free TCP port + fresh creds
    pub fn port(&self) -> u16;  pub fn creds(&self) -> &Creds;
    pub fn loopback(&self) -> Loopback;       // vpnte_base form
}
pub enum InvalidEndpoint { Port, Authentication }   // -> AppError Internal (the app made it)
```
One `SlotEndpoint` per slot flows from allocation into `xray_config::build_config`,
`XraySupervisor::start` and `singbox_config::Upstream::XraySlots`.

## `ports`

```rust
pub const PORT_RANGE: Range<u16> = 20000..45000;    // clear of the External Proxy API's 17990..=17999
pub struct PortsExhausted;                          // -> Network, "engine.ports.exhausted"
pub fn alloc_port(udp: bool, taken: &[u16]) -> Result<u16, PortsExhausted>; // 16 random picks;
                                                    // udp: also UDP-tested (dns-bootstrap-in)
pub fn secret() -> String;                          // 16 CSPRNG bytes as 32 lowercase hex
pub fn creds() -> Creds;                            // user + pass, 32 hex each
```
Ports are test-bound (bind then release): allocate right before the engine start.

## `singbox_config` — the config of one tunnel start (pure, deterministic)

```rust
pub struct ConfigInputs { pub upstream: Upstream, pub capture: Capture, pub listeners: Listeners,
    pub routing: RoutingParts, pub phys_dns: Vec<Ipv4Addr> /* physical adapters' resolvers */ }
pub enum Capture {               // NOADMIN.md §2: routing_mode Hard = Tun, Soft = Proxy
    Tun(TunParams),              // `tun-in`; needs an elevated process
    Proxy { port: u16 },         // `tags::PROXY_IN`: mixed (HTTP + SOCKS) on 127.0.0.1:port, no
}                                // users, no set_system_proxy (the app sets the system proxy)
pub enum Upstream {
    LocalProxy { addr: vpnte_core::net::HostPort, kind: ProxyKind, creds: Option<Creds> }, // "hard mode"
    Native { fragment: vpnte_profiles::emit_singbox::SingBoxFragment, udp: UdpPolicy },
    XraySlots { slots: [SlotEndpoint; 2], active: Slot, udp: UdpPolicy },  // selector `proxy-out`
}
impl Upstream {
    // emit_singbox(p, PROXY_OUT, policy) with domain_resolver = dns-bootstrap; udp = UdpPolicy::of(p)
    pub fn native(p: &Profile, policy: &EmitPolicy) -> Result<Upstream, EmitError>;
}
pub struct UdpPolicy { pub udp: bool /* false: drop all UDP */, pub block_quic: bool }
impl UdpPolicy { pub fn of(p: &Profile) -> Self; }   // emit_singbox::{udp_capable, block_quic}
pub struct TunParams { pub alias: String, pub mtu: u16 /* >= 1280 */, pub ipv6: bool,
    pub dns_hijack: bool, pub stack: TunStack }
pub enum TunStack { #[default] Mixed, Gvisor }     // Gvisor when Windows Firewall blocks inbound
pub struct Listeners { pub clash_port: u16, pub clash_secret: String, pub direct: Loopback,
    pub probe: Option<Loopback> /* direct VPN modes only */, pub dns_bootstrap: Option<u16> /* slot mode */ }
#[derive(Default)]
pub struct RoutingParts { pub process_rules: Vec<Value>, pub domain_rules: Vec<Value>,
    pub rule_sets: Vec<Value>, pub dns_servers: Vec<Value>, pub dns_rules: Vec<Value> }  // from routing::build
pub enum ConfigError { InvalidSlots(&'static str), InvalidListeners(&'static str),
    InvalidTun(&'static str), BadUpstream(&'static str), BadRouting(String) }   // -> Internal, "engine.config.invalid"

pub fn build(i: &ConfigInputs) -> Result<serde_json::Value, ConfigError>;
pub fn select_mtu(stealth: bool, adaptive: AdaptiveMode, public_wifi: bool) -> u16; // 1280 | 1380 | 1500
pub fn compat_key(i: &ConfigInputs) -> [u8; 32];   // equal keys: a running config can serve the new
                                                   // upstream (ignores profile, slots, listener ports,
                                                   // secrets, alias; the capture and its proxy port count)
pub fn usable_physical_dns(physical: &[Ipv4Addr]) -> Option<Ipv4Addr>;  // not TUN /30, loopback, 0.0.0.0
```
Rules the caller must keep (review of the WFP / TUN design):
- `tun.ipv6 = !tun.dns_hijack = Protection::session_guarded()` (kill switch != Off or leak
  protection on): dual-stack TUN + IPv6 reject only while the app's own WFP layer guards IPv6/DNS.
- Every app-owned port (controller, direct, probe, bootstrap-in, slots, proxy capture) non-zero
  and distinct; authenticated mixed inbounds (direct, probe) always have user / password
  1..=255 bytes; secret without spaces. Keep the proxy-capture port for the whole session.
- Generated route order: loopback inbounds -> `routing.process_rules` -> QUIC reject (when
  `udp.block_quic`) -> IPv6 reject (dual-stack TUN, always in proxy form) -> sniff -> hijack-dns
  (TUN only) -> private direct -> all-UDP drop (when `!udp.udp`) -> STUN pins (sniffed `stun`,
  then UDP 3478 / 3479 / 5349 / 19302-19309, routing-dns B-X-1) -> `routing.domain_rules`;
  final `proxy-out`; `auto_detect_interface` only with the TUN.
- Proxy form = the TUN form minus the TUN inbound, the DNS hijack rule and
  `auto_detect_interface`; upstreams, selector, DNS, rule sets, sniffing, the UDP / QUIC / IPv6
  policy, process rules, loopback inbounds and the Clash API are the same. Process rules keep
  working: sing-box looks up the owner of every loopback source (`route/process_cache.go`
  `isLocalSource`), on Windows by the client socket's local address in the TCP / UDP tables
  (`winiphlpapi.FindPid`). Programs that ignore the proxy are not captured at all.
- DNS: routing's servers / rules; `dns-remote` defaults to Cloudflare DoH through the tunnel;
  `dns-resolver` is added for hostname tunnelled servers. Upstream server names resolve direct
  in the order of `vpnte_core::resolve` (ru-2026 Ф9), never by plain UDP to a public resolver:
  `dns-bootstrap` = DoH to `1.1.1.1` by IP literal (no SNI, no detour) when the upstream dials
  a name or bootstrap-in exists. An outbound's `domain_resolver` names one server and bypasses
  the DNS rules (sing-box 1.14 `dns/router.go` `Lookup`), so native outbounds get this first
  step only. Queries of `dns-bootstrap-in` (Xray slots) get the whole order, first in
  `dns.rules`: `evaluate` (1.5 s each) `dns-bootstrap` -> `dns-bootstrap-quad9` (DoH 9.9.9.9)
  -> `dns-bootstrap-google` (DoH 8.8.8.8), a step's answer taken (`respond`) when it has an
  address or is NXDOMAIN; then `dns-bootstrap-tcp` (TCP 8.8.8.8:53) and, when
  `usable_physical_dns` gives one, `dns-bootstrap-isp` (UDP to it) last. These tags are
  reserved (routing must not define them). Routing's DNS rules must not use legacy address
  filters (`ip_cidr` / `ip_is_private` without `match_response`): `evaluate` turns legacy DNS
  mode off and sing-box then refuses them. `strategy: ipv4_only`. Clash API on
  `127.0.0.1:clash_port` with `clash_secret`.
- Upstream server IPs are excluded from the TUN routes (Native); slot mode excludes nothing:
  pass the Xray exe in `RoutingInputs::engine_paths` (process rule -> direct) instead.

```rust
// Tunnel start, native sing-box upstream (sketch; errors convert into AppError with `?`).
let clash = ClashEndpoint::allocate(&[])?;            // clash_api: port + 32-hex secret
let direct_port = ports::alloc_port(false, &[clash.port])?;
let routing = routing::build(&routing_inputs);      // see `routing`; show routing.warnings
let inputs = ConfigInputs {
    upstream: Upstream::native(&profile, &EmitPolicy { device, ..Default::default() })?,
    capture: Capture::Tun(TunParams { alias, mtu: select_mtu(stealth, adaptive, public_wifi),
                     ipv6: guarded, dns_hijack: !guarded, stack: TunStack::Mixed }),
    // Soft: Capture::Proxy { port: session_port }  (ports::alloc_port(false, &[..]) once per session)
    listeners: Listeners { clash_port: clash.port, clash_secret: clash.secret.clone(),
                           direct: Loopback { port: direct_port, creds: Some(ports::creds()) },
                           probe: None, dns_bootstrap: None },
    routing: routing.parts,
    phys_dns,                                        // vpnte_winnet::adapters, re-read per start
};
let json = singbox_config::build(&inputs)?;
let sb = SingBoxProcess::spawn(&singbox_exe, json.to_string().as_bytes(), Some(&logs_dir))?;
sb.wait_ready(singbox_process::READY_TIMEOUT, &cancel).await?;  // on Err: sb.terminate(..) / drop
```

## `singbox_process` — one sing-box child

```rust
pub const READY_MARKER: &str = "sing-box started (";  pub const LOG_STEM: &str = "sing-box";
pub const READY_TIMEOUT: Duration = 20 s;  pub const STOP_TIMEOUT: Duration = 3 s;  // wait after the kill
pub const GRACEFUL_STOP: Duration = 3 s;              // wait for the own exit after CTRL_BREAK
pub const KILL_CODE: i32 = 1;                         // exit code of our own kills
pub struct SingBoxProcess;                            // drop = engine killed (its own Job)
impl SingBoxProcess {
    // `run -c stdin --disable-color`, cwd = exe dir; logs: Some(dir) -> <dir>\sing-box.log
    // (the previous run is rotated to sing-box.1.log)
    pub fn spawn(exe: &Path, config: &[u8], logs: Option<&Path>) -> io::Result<Self>;
    pub async fn wait_ready(&self, timeout: Duration, cancel: &CancellationToken) -> Result<(), StartError>;
    pub async fn terminate(&self, within: Duration) -> Result<ExitInfo, StopError>;   // idempotent
        // CTRL_BREAK, up to GRACEFUL_STOP for the own exit, else kill + up to `within`
    pub fn pid(&self) -> u32;
    pub fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>>;   // Some once the exit is proven
    pub fn exit_info(&self) -> Option<ExitInfo>;
    pub fn recent_fault(&self) -> Option<OutboundFault>;             // classify_fault over the ring
    pub fn tail(&self, n: usize) -> Vec<String>;                     // redacted
    pub fn subscribe_lines(&self) -> broadcast::Receiver<Arc<str>>;  // RAW lines: never log them
}
pub struct ExitInfo { pub at: SystemTime, pub code: Option<i32>, pub stderr_tail: String /* 6 lines,
    <= 800 chars, redacted */, pub user_initiated: bool, pub graceful: bool, pub bind_failures: Vec<u16>,
    pub access_denied: bool }
impl ExitInfo { pub fn binds_any(&self, ports: &[u16]) -> bool; }  // died on one of our ports: retry once
pub enum StartError { Exited(ExitInfo), Timeout, Cancelled, Spawn(io::Error) }
pub enum StopError { ExitNotConfirmed }               // retry the stop
pub enum CheckError { Rejected(String /* redacted */), Run(io::Error) }
pub fn classify_fault<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<OutboundFault>;
pub async fn engine_version(exe: &Path) -> io::Result<(u16, u16, u16)>;  // cache once per app run
pub fn parse_version(text: &str) -> Option<(u16, u16, u16)>;
pub fn version_supported(v: (u16, u16, u16)) -> bool;                    // 1.14.x only
pub async fn check_config(exe: &Path, config: &[u8]) -> Result<(), CheckError>;  // `check -c stdin`, 10 s
```
The exit is published after the output pumps drained (tail and bind evidence complete).
**Stop (AT-02-009).** `terminate` asks first: CTRL_BREAK to the engine's own console group
(`vpnte_winnet::process::ctrl_break`), which Go turns into SIGINT; sing-box then closes every
inbound, the TUN's Wintun session and adapter included (`WintunCloseAdapter` removes the adapter
it created), and exits 0 (measured: ~50 ms without TUN). A kill (TerminateJobObject, code
`KILL_CODE`) follows only when it is not gone after `GRACEFUL_STOP` (logged `engine stop
escalated`) or the event could not be delivered (a caller with a console of its own: tests must
call `vpnte_winnet::process::detach_console()` first). `ExitInfo::graceful` = it ended by itself
after our CTRL_BREAK; `user_initiated && !graceful` = we killed it. Worst case of a stop:
`GRACEFUL_STOP + within`. A drop still kills at once (Job closes), as does the app's exit.
Secrets of the config (and slot credentials) are masked in every logged / returned line; our
DNS server tags (`dns-remote`, `dns-resolver`, `dns-direct`, `dns-bootstrap` and its
`-quad9` / `-google` / `-tcp` / `-isp` steps) stay readable.
`StartError` -> `engine.process.singboxExited(code)` / `singboxNotReady` (Timeout) /
`spawnFailed(engine)` (kind Permission when access is denied) / `notPinned(file)` (elevated, an
engine file differs from its pin) / `fileMissing(file)` (elevated, an engine file is missing);
`StopError` -> `stopUnconfirmed`.

## `xray_process` — the two Xray slots

```rust
pub const READY_TIMEOUT: Duration = 3500 ms;  pub const STOP_TIMEOUT: Duration = 1000 ms;  // after the kill
pub const CHECK_TIMEOUT: Duration = 5 s;  pub const EXIT_CONFIG_REJECTED: i32 = 23;
pub const FAULT_MAX_AGE: Duration = 120 s;
pub struct SlotLaunch { pub config: Vec<u8>, pub dial_target: Option<SocketAddr> }  // Debug hides config
pub struct SlotStatus { pub running: bool, pub port: Option<u16>, pub pid: Option<u32>,
    pub started_at: Option<SystemTime>, pub dial_target: Option<SocketAddr> }      // Default = empty slot
pub enum XrayEvent { Exited { slot: Slot, pid: u32, code: Option<i32>, expected: bool, graceful: bool,
    tail: String } }
pub enum XrayError { Spawn(io::Error), ConfigRejected(String), ExitedEarly { code: Option<i32>, tail: String },
    NotReady { port: u16, cause: SocksError }, SlotOccupied, PortOwnedByOtherSlot, NotRunning,
    NotStarted, ExitNotConfirmed, Cancelled }
pub struct XraySupervisor;                             // owned by the tunnel actor (&mut self)
impl XraySupervisor {
    pub fn new(exe: PathBuf, logs: Option<PathBuf>, events: mpsc::Sender<XrayEvent>) -> Self;
                                                       // exe also -> RoutingInputs::engine_paths
    // `run -config stdin:`; ready = authenticated SOCKS handshake raced with exit / cancel;
    // any failure stops the candidate before returning
    pub async fn start(&mut self, slot: Slot, ep: SlotEndpoint, launch: SlotLaunch,
                       cancel: &CancellationToken) -> Result<SlotStatus, XrayError>;
    pub async fn restart(&mut self, slot: Slot, cancel: &CancellationToken) -> Result<SlotStatus, XrayError>;
    pub async fn stop(&mut self, slot: Slot) -> Result<(), XrayError>;   // idempotent
    pub async fn stop_all(&mut self) -> Result<(), XrayError>;
    pub fn activate(&mut self, slot: Slot) -> Result<(), XrayError>;    // after the Clash select
    pub fn active(&self) -> Option<Slot>;
    pub fn status(&self, slot: Slot) -> SlotStatus;
    pub fn endpoint(&self, slot: Slot) -> Option<&SlotEndpoint>;        // diagnostics only, never shown
    pub fn recent_fault(&self, slot: Slot) -> Option<OutboundFault>;    // last 120 s
    pub fn log_tail(&self, slot: Slot) -> String;                       // redacted
}
pub fn classify_xray_fault<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<OutboundFault>;
pub async fn check_config(exe: &Path, config: &[u8]) -> Result<(), XrayError>;  // `run -test -config stdin:`
pub async fn engine_version(exe: &Path) -> io::Result<(u16, u16, u16)>;         // `version`, CHECK_TIMEOUT
```
Events: `XrayEvent::Exited` only for slots that reached readiness; `expected` = we stopped it;
`graceful` = it ended by itself after our CTRL_BREAK. `stop` / `stop_all` / `restart` / a failed
start stop a slot like sing-box: CTRL_BREAK, up to `singbox_process::GRACEFUL_STOP` (Xray exits
0 in ~0.2 s here), else the kill and up to `STOP_TIMEOUT`; `stop_all` stops A then B.
Restart policy / backoff (0.5 / 2 / 5 s, 3 per 60 s) is the tunnel FSM's. Messages:
`engine.process.xray.{exited(code), socksNotReady(port), slotOccupied, portTaken, notRunning,
notStarted}`, `engine.process.{configRejected, stopUnconfirmed, spawnFailed}(engine)`.

## `clash_api` — controller of one sing-box run

```rust
pub const CONTROL_TIMEOUT: Duration = 1 s;  pub const SNAPSHOT_TIMEOUT: Duration = 4 s;
pub const TRAFFIC_TIMEOUT: Duration = 3 s;
pub struct ClashEndpoint { pub port: u16, pub secret: String }   // Debug hides the secret
impl ClashEndpoint { pub fn allocate(taken: &[u16]) -> Result<Self, PortsExhausted>;
                     pub fn is_valid(&self) -> bool; }            // port != 0, 32 hex secret
pub enum ClashError { Invalid, Transport(reqwest::Error), Timeout, Status(u16), Schema, NotConfirmed }
pub struct ClashApi;
impl ClashApi {
    pub fn new(ep: &ClashEndpoint) -> Result<Self, ClashError>;      // no request; never a system proxy
    pub async fn version(&self) -> Result<String, ClashError>;      // "sing-box 1.14.4"
    pub async fn selection(&self, group: &str) -> Result<Selection, ClashError>;
    // PUT + exact read-back within one CONTROL_TIMEOUT; any Err = selection unknown: restore it
    pub async fn select(&self, group: &str, member: &str, members: &[&str]) -> Result<(), ClashError>;
    pub async fn connections(&self) -> Result<Connections, ClashError>;
    pub async fn traffic(&self) -> Result<Traffic, ClashError>;     // one tick of /traffic
}
pub struct Selection { pub kind: String, pub now: String, pub all: Vec<String> }
pub struct Traffic { pub up: u64, pub down: u64 }
pub struct Connections { pub download_total: u64, pub upload_total: u64, pub connections: Vec<Connection> }
pub struct Connection { pub id: String, pub metadata: ConnMeta, pub upload: u64, pub download: u64,
    pub start: String, pub chains: Vec<String>, pub rule: String }
pub struct ConnMeta { pub network: String, pub inbound: String /* JSON "type" */, pub source_ip: String,
    pub source_port: String, pub destination_ip: String, pub destination_port: String,
    pub host: String, pub process_path: String }
pub fn parse_connections(body: &[u8]) -> Result<Connections, ClashError>;
pub fn parse_selection(body: &[u8]) -> Result<Selection, ClashError>;
pub fn confirms(selection: &Selection, member: &str, members: &[&str]) -> bool;
```
Fill `singbox_config::Listeners { clash_port: ep.port, clash_secret: ep.secret.clone(), .. }` from
the same `ClashEndpoint`. Protected slot switch: `api.select(tags::PROXY_OUT, slot.tag(),
&tags::SLOT_TAGS).await?` then `sup.activate(slot)?`. Messages: `engine.clash.{invalid,
unreachable, badAnswer, notConfirmed}`.

## `xray_config` — Xray JSON (the only producer) and name pre-resolution

```rust
pub enum SelectReason { Default, Protocol, Preference, Reality, XrayTransport, NativeXray, CertPin,
    SingBoxOnly(SingBoxOnly) }                                          // Serialize, kebab-case
impl SelectReason { pub fn msg(self) -> Msg; } // engine.xray.reason.*: short caption after the engine name
pub enum SingBoxOnly { H2Transport, QuicTransport, InsecureWithoutPin, SpkiPin, Ech, ShadowsocksPlugin,
    ShadowsocksUdpOverTcp, ShadowsocksMethod, RealityTransport, Plaintext }
pub enum XrayLacks { Client(&'static str) /* TUIC, NaiveProxy, AnyTLS, ShadowTLS */,
    Form(&'static str) /* transport under Hy2 / WG / SOCKS / HTTP, SOCKS over TLS */ }
pub enum Reject { NativeXray, XrayTransport, SingBoxOnly(SingBoxOnly), Conflict(SingBoxOnly),
    XrayLacks(XrayLacks) /* forced Xray: never a silent sing-box */,
    Amneziawg /* any preference, checked first: neither engine runs AmneziaWG (mihomo, a WP-12
                 lab function, does); never started as plain WireGuard. reject.amneziawg */ }
impl Reject { pub fn msg(&self) -> Msg; }      // engine.xray.{reject.*, singBoxOnly.*, conflict.*}; -> Validation
                                               // reject.{noXrayClient,xrayForm}(protocol): offer Auto / sing-box
pub enum Decision { Selected { engine: Engine, reason: SelectReason }, Rejected(Reject) }
impl Decision { pub fn engine(self) -> Result<Engine, Reject>; }
pub fn select_engine(p: &Profile, pref: EnginePref) -> Decision;      // pure
pub fn server_pref(setting: EnginePref, server: EnginePref) -> EnginePref; // a server's own sing-box /
                                    // Xray wins, its Auto follows the setting: apply before select_engine
pub fn translate(p: &Profile, device: ClientDevice) -> Result<Value, XrayConfigError>; // outbound "proxy"
pub fn warnings(p: &Profile, tls_compat: bool) -> Vec<Msg>;           // pure; engine.xray.warn.*
pub enum ProxyGraph { Translated(Value), Native(Box<CompiledGraph>) } // Debug shows only the shape
pub fn proxy_graph(p: &Profile, device: ClientDevice) -> Result<ProxyGraph, XrayConfigError>; // provider
                                                                     // graph validated + compiled, else translate
impl ProxyGraph {
    pub fn hosts(&self) -> Vec<String>;                              // server names to pre-resolve
    pub fn substitute(&mut self, resolved: &HashMap<String, IpAddr>); // address -> IP, derived names pinned
}
pub fn build_config(graph: &ProxyGraph, ep: &SlotEndpoint) -> Value; // infallible
pub enum XrayConfigError { Protocol(&'static str), Feature(SingBoxOnly), Invalid(&'static str),
    Native(NativeError) }                                             // -> Validation
```
**Outbounds** (bundled Xray 26.11.9; each shape passes `xray run -test`): VLESS, VMess, Trojan,
Shadowsocks (9 ciphers; UDP-over-TCP only with 2022 ciphers), Hysteria2 (`hysteria` v2: TLS
always, salamander / gecko in `finalmask.udp`, port hopping, Brutal bandwidth and BBR preset in
`finalmask.quicParams`, certificate pin as `pinnedPeerCertSha256`), WireGuard (user-space, no
adapter, provider DNS as `remoteDNS`), SOCKS (no TLS, no transport), HTTP (TLS allowed, no
transport). TUIC, Naive, AnyTLS and ShadowTLS have no Xray outbound (Auto / forced sing-box:
`SelectReason::Protocol`; forced Xray: `Reject::XrayLacks`).
Static ECH configs go to `echConfigList`; ECH by DNS lookup, over QUIC or with REALITY stays
`SingBoxOnly::Ech`. uTLS: the provider's fingerprint is kept (with a warning when servers refuse
it), otherwise the device default if it is chrome / firefox / safari, else chrome. XHTTP gets
an explicit `extra.xmux` (4-6 connections) unless the provider set one; no typed outbound ever
carries `mux`, and mux.cool is removed from a provider graph's XHTTP outbounds.
**Selection:** Auto picks Xray for provider graphs, Xray-only transports, explicit gRPC gun,
REALITY and (new) any non-REALITY TLS profile with a certificate pin (`CertPin`: sing-box
cannot enforce a DER hash pin); sing-box otherwise. Forced Xray runs every Xray-capable kind and
refuses the rest (no engine is ever switched silently; owner decision 2026-11-11). Show the
engine with `reason.msg()` wherever a run or a planned run is displayed.
**Warnings:** call `warnings(&profile, tls_compat)` whenever Xray runs the profile and show them
(the sing-box options Xray drops: mux, dial, pasted sing-box options, `disable_sni`, stealth /
TLS compatibility, ws early data; refused / broken / unknown fingerprints; an unknown BBR preset;
mux.cool removed from a provider XHTTP outbound). `tls_compat` = stealth or adaptive TLS mode.

```rust
// async: names are resolved by the app, never by Xray (its lookup would loop through the TUN)
pub enum ResolvePath { Direct, ViaSingBox(SocketAddr) }
pub struct Resolved { pub addrs: HashMap<String, IpAddr>,
    pub warning: Option<Msg> }                                       // core.net.resolveLastKnown: show it
pub enum ResolveFault { Failed, Sinkhole, Poisoned, Cancelled }     // -> Network / Cancelled
pub async fn resolve_hosts(hosts: &[String], path: ResolvePath, cancel: &CancellationToken)
    -> Result<Resolved, ResolveFault>;
```
Config shape: SOCKS inbound `in` on `127.0.0.1:ep.port()` with password auth, UDP, route-only
sniffing (tls / http / quic); outbounds proxy (graph), `direct`, `block`; private CIDRs direct;
log `info` to stdout, access log off; never dns / api / stats. Reject texts are complete
sentences (render `reject.msg()`). `hosts()` / `substitute()` also cover WireGuard
`peers[].endpoint` (`host:port`). `resolve_hosts`: `Direct` (TUN down) =
`vpnte_core::resolve::resolve_server` per name: the direct DoH / TCP chain against the Russian
DNS blocking, the OS resolver (2.5 s), then the address the name had last time in this process
(`warning` set; it is never silent); no plain UDP to any resolver; bounded by `resolve_server`
itself (worst case about 11 s, typically under 1 s). `ViaSingBox(addr)` = UDP DNS to the
running sing-box's loopback `dns-bootstrap-in` (TUN up; the socket binds loopback, so a
non-loopback address fails as `Failed` without sending), A, else
AAAA, 4 s per name. IP literals are answered in place. <= 4 lookups in flight; the first
failure fails the plan (no partial map); block-page answers (loopback, 0.0.0.0/8, link-local,
multicast, broadcast) -> `Sinkhole`; forged answers with no trustworthy resolver (NXDOMAIN with
AA, block-page-only) -> `Poisoned` (`engine.xray.resolve.poisoned`); private / CGNAT servers
are accepted. The tunnel also pins a native profile's server name with `Direct` (tunnel
`runtime::pin`).

```rust
// Xray upstream in slot A (cold start, TUN down) — sketch.
let engine = select_engine(&profile, settings.engine_pref).engine()?;   // Engine::Xray here
let mut graph = proxy_graph(&profile, device)?;
notify_all(warnings(&profile, stealth || adaptive == AdaptiveMode::TlsCompatibility));
let resolved = resolve_hosts(&graph.hosts(), ResolvePath::Direct, &cancel).await?;
if let Some(msg) = resolved.warning.clone() { notify(msg) }
graph.substitute(&resolved.addrs);
let (ep_a, ep_b) = (SlotEndpoint::allocate(&taken)?, SlotEndpoint::allocate(&taken_plus_a)?);
let launch = SlotLaunch { config: build_config(&graph, &ep_a).to_string().into_bytes(),
                          dial_target: resolved.addrs.values().next().map(|ip| (*ip, profile.port).into()) };
sup.start(Slot::A, ep_a.clone(), launch, &cancel).await?;
// sing-box: Upstream::XraySlots { slots: [ep_a, ep_b], active: Slot::A, udp: UdpPolicy::of(&profile) },
// listeners.dns_bootstrap = Some(port), RoutingInputs::engine_paths = [the Xray exe].
```

## `routing` — the user's rules and the route / DNS fragments

Re-exports: `routing::{RulesDoc, RoutingFragments, RoutingInputs, RoutingWarning, build}`.

```rust
// routing::domain — patterns and rules (list order = priority)
pub const MAX_PATTERN_LEN: usize = 253;  pub const MAX_RULES: usize = 10_000;  pub const MAX_LIST_BYTES: u64 = 4 MiB;
pub enum DomainAction { Vpn, Direct, Block }                       // serde "vpn" | "direct" | "block"
pub enum DomainPattern { Exact(String), Subdomains(String), Keyword(String) } // "x.com" | "*.x.com" | "~kw"
impl DomainPattern { pub fn parse(raw: &str) -> Result<Self, PatternError>;  // URL -> host, IDNA -> punycode
                     pub fn parse_legacy(raw: &str) -> Result<Self, PatternError>; // old dotless -> ~kw
                     pub fn matches(&self, host: &str) -> bool; }  // + Display / FromStr / serde (string)
pub enum PatternError { Empty, TooLong, IpLiteral, NeedsDot, Invalid } // .msg(); -> Validation
pub struct DomainRule { pub id: Uuid, pub pattern: DomainPattern, pub action: DomainAction }
impl DomainRule { pub fn new(pattern: DomainPattern, action: DomainAction) -> Self; }
pub fn first_match<'a>(rules: &'a [DomainRule], host: &str) -> Option<&'a DomainRule>;
pub struct ListImport { pub patterns: Vec<DomainPattern>, pub invalid: usize, pub duplicates: usize }
pub fn read_list_file(path: &Path) -> AppResult<String>;          // blocking; regular file <= 4 MiB
pub fn parse_list(text: &str) -> ListImport;                       // BOM, blanks, '#' comments, dedup

// routing::dns — resolver addresses and profiles
pub enum DnsHost { Ip(IpAddr), Name(String) }
pub enum DnsAddr { Plain(IpAddr), Doh { host: DnsHost, port: Option<u16>, path: Option<String> },
                   Dot { host: DnsHost, port: Option<u16> } }      // FromStr / Display / serde (string)
pub enum DnsAddrError { Required, TooLong, Scheme, Invalid, DohHost, DotHost, Port, Path, UnusableIp } // .msg()
pub struct DnsProfile { pub id: String, pub name: String, pub primary: DnsAddr, pub secondary: Option<DnsAddr> }
impl DnsProfile { pub fn is_builtin(&self) -> bool; }
pub const BUILTIN_PREFIX: &str = "builtin-";  pub const MAX_NAME_LEN: usize = 120;  pub const MAX_ADDR_LEN: usize = 2048;
pub fn builtin_profiles() -> [DnsProfile; 4];
pub fn find_profile(custom: &[DnsProfile], id: &str) -> Option<DnsProfile>;

// routing::process — split tunnelling (always `process_path_regex`, case-insensitive)
pub struct ProcessName;  impl ProcessName { pub fn parse(raw: &str) -> Result<Self, SplitError>;
    pub fn as_str(&self) -> &str; pub fn regex(&self) -> String; }    // `.exe` appended when missing
pub struct AppPath;      impl AppPath { pub fn parse(raw: &str) -> Result<Self, SplitError>;
    pub fn as_str(&self) -> &str; pub fn as_path(&self) -> &Path; pub fn regex(&self) -> String; }
pub enum SplitTarget { App(AppPath), Command(ProcessName) }  impl SplitTarget { pub fn parse(raw: &str) -> Result<Self, SplitError>; }
pub enum AppRule { Vpn, Direct, #[default] None }
pub struct SplitApp { pub id: Uuid, pub name: String, pub target: SplitTarget, pub rule: AppRule }
pub enum SplitError { BadName, BadPath }                           // .msg(); -> Validation
pub enum Probe { File { canonical: Option<AppPath> }, Missing, NotAFile }
pub fn probe_fs(path: &AppPath) -> Probe;                          // blocking
pub fn long_spelling(path: &AppPath, resolved: &str) -> Option<AppPath>;
pub struct ResolvedSplit { pub direct: Vec<String>, pub vpn: Vec<String>, pub inactive: Vec<InactiveApp> }
pub struct InactiveApp { pub name: String, pub path: String, pub reason: InactiveReason }
pub enum InactiveReason { FileMissing, NotAFile }
pub fn resolve_split(apps: &[SplitApp], probe: impl Fn(&AppPath) -> Probe) -> ResolvedSplit;
pub const THIRD_PARTY_CORES: &[&str];  pub fn third_party_core_regexes() -> Vec<String>;
pub const MAX_INPUT_LEN: usize = 4096;

// routing::smart_ru — verbatim lists
pub const GEOIP_RU: &str;  pub const GOV_RU: &str;  pub const RULE_SETS: [(&str /*tag*/, &str /*file*/, &str /*url*/); 2];
pub const RU_TLD_SUFFIXES, RU_COMMERCIAL_SERVICE_SUFFIXES, MAPS_DOMAIN_SUFFIXES, GOOGLE_AND_GEMINI_PINNED_SUFFIXES,
          KIMI_MOONSHOT_DOMAIN_SUFFIXES, VPN_PINNED_MEDIA_SUFFIXES, IP_CHECKER_SUFFIXES: &[&str];
pub struct SmartRu { pub enabled: bool, pub maps_direct: bool }

// routing::plan — the one generator (pure, deterministic, owner order ТЗ-06 §10.4)
pub struct RoutingInputs<'a> { pub smart: SmartRu, pub rule_set_dir: Option<&'a Path>,
    pub domain_rules: &'a [DomainRule], pub split: &'a ResolvedSplit,
    pub engine_paths: &'a [AppPath] /* our Xray / external proxy exe; never the app's own exe */,
    pub third_party_cores: bool /* local-proxy mode */, pub dns: Option<&'a DnsAddr> /* None = auto DoH */,
    pub physical_dns: &'a [Ipv4Addr], pub endpoint_is_hostname: bool }
pub struct RoutingFragments { pub parts: singbox_config::RoutingParts, pub warnings: Vec<RoutingWarning> }
pub enum RoutingWarning { SmartRuDisabled, BootstrapDnsFallback, InactiveApp(InactiveApp) } // .msg(): show each
pub fn build(i: &RoutingInputs) -> RoutingFragments;
```
Process rules: P1 `engine_paths` -> direct, P2 third-party cores -> direct, P3 split direct,
P4 split VPN (one rule per class). Domain rules: block -> Smart RU pins -> gov (+ maps) ->
user rules in order -> `geoip-ru` + Kimi direct; DNS rules mirror them (`dns-direct` = UDP to
`usable_physical_dns`, else `dhcp`). DNS rules match by domain only (domain lists, the
domain-only gov geosite; never `ip_cidr` / `ip_is_private` / an IP rule set), so they stay
valid next to the slot mode's `evaluate` bootstrap order (tested through `sing-box check`).
`BootstrapDnsFallback` = the endpoint is a host name and the physical adapters have no usable
resolver: the name resolves only through public resolvers (DoH / TCP), with no step at the
network's own DNS.

```rust
// routing::doc — Document `rules.json` (VERSION 1); open exactly one Store<RulesDoc>
pub struct RulesDoc { pub split_tunnel: SplitTunnel, pub dns: DnsSettings,
    pub domain_rules: Vec<DomainRule>, pub rule_hits: BTreeMap<Uuid, u64>, pub extra: Map<String, Value> }
pub struct SplitTunnel { pub apps: Vec<SplitApp>, pub removed_paths: BTreeSet<String> }
pub struct DnsSettings { pub custom: Vec<DnsProfile>, pub active_id: Option<String> }  // None = auto
pub struct ImportReport { pub added: usize, pub duplicates: usize, pub over_limit: usize }
pub const MAX_HIT_ENTRIES: usize = 10_000;
impl RulesDoc {   // mutate inside Store::update(|d| ..); AppResult errors carry engine.routing.* messages
    pub fn add_domain_rule(&mut self, pattern: DomainPattern, action: DomainAction) -> AppResult<Uuid>;
    pub fn update_domain_rule(&mut self, id: Uuid, pattern: Option<DomainPattern>,
                              action: Option<DomainAction>) -> AppResult<()>;
    pub fn delete_domain_rule(&mut self, id: Uuid) -> bool;
    pub fn reorder_domain_rules(&mut self, ids: &[Uuid]);
    pub fn import_domains(&mut self, patterns: &[DomainPattern], action: DomainAction) -> ImportReport;
    pub fn hit_count(&self, id: Uuid) -> u64;   pub fn add_hits(&mut self, hits: &BTreeMap<Uuid, u64>);
    pub fn dns_profiles(&self) -> Vec<DnsProfile>;   pub fn active_dns(&self) -> Option<DnsProfile>;
    pub fn select_dns(&mut self, id: Option<&str>) -> AppResult<()>;
    pub fn add_dns_profile(&mut self, name: &str, primary: DnsAddr, secondary: Option<DnsAddr>) -> AppResult<String>;
    pub fn update_dns_profile(&mut self, id: &str, name: Option<&str>, primary: Option<DnsAddr>,
                              secondary: Option<Option<DnsAddr>>) -> AppResult<()>;
    pub fn delete_dns_profile(&mut self, id: &str) -> AppResult<bool>;
    pub fn add_app(&mut self, path: AppPath, name: &str) -> Uuid;   pub fn add_command(&mut self, name: ProcessName) -> Uuid;
    pub fn remove_app(&mut self, id: Uuid) -> bool;   pub fn set_app_rule(&mut self, id: Uuid, rule: AppRule) -> bool;
    pub fn merge_discovered(&mut self, found: &[apps::InstalledApp]) -> usize;
    pub fn resolve_split(&self, probe: impl Fn(&AppPath) -> Probe) -> ResolvedSplit;
    // legacy electron-store sections (already decrypted); messages = what was dropped
    pub fn from_legacy(domain: Option<&Value>, dns: Option<&Value>, split: Option<&Value>) -> (RulesDoc, Vec<Msg>);
}

// routing::hits — per-rule hit counters from Clash /connections polls
pub struct ConnSample<'a> { pub id: &'a str, pub host: &'a str, pub rule: &'a str, pub chains: &'a [String] }
pub fn attribute(rules: &[DomainRule], conn: &ConnSample) -> Option<Uuid>;
#[derive(Default)] pub struct HitTracker;
impl HitTracker { pub fn observe<'a>(&mut self, rules: &[DomainRule], poll: impl IntoIterator<Item = ConnSample<'a>>);
                  pub fn take(&mut self) -> BTreeMap<Uuid, u64>; }

// routing::rulesets — Smart RU rule sets; Document `cache/rulesets.json` (VERSION 1)
pub const MAX_FILE_BYTES: usize = 8 MiB;
pub struct RuleSetsDoc { pub current: Option<String> /* gen-<ms> */, pub last_check: Option<UnixMs>,
    pub last_ok: Option<UnixMs>, pub last_error: Option<RefreshFault>, pub files: BTreeMap<String, FileInfo> }
pub struct FileInfo { pub size: u64, pub sha256: String, pub route: RouteKind }
pub enum RouteKind { Direct, UserProxy, HappSocks, HappHttp }      // .label() -> Msg
pub enum RefreshFault { Download { file: String }, Invalid { file: String }, EngineUnavailable, Storage } // .msg()
pub struct RefreshSettings { pub managed: bool, pub auto_update: bool, pub use_proxy: bool, pub interval_h: u32,
    pub bootstrap: BootstrapRouteMode, pub user_proxy: Option<Route> }
impl RefreshSettings { pub fn from_settings(s: &Settings) -> Self;
    pub fn auto_refresh(&self, smart_ru_enabled: bool) -> bool;  pub fn routes(&self) -> Vec<(RouteKind, Route)>; }
pub enum ActiveSource { Bundled, Managed { generation: String, since: UnixMs } }
pub enum RefreshOutcome { Fresh, Updated { generation: String }, Failed(RefreshFault), Cancelled }
impl RefreshOutcome { pub fn notice(&self) -> Option<Notice>; }   // toast it
pub struct RuleSetService;
impl RuleSetService {
    pub fn new(store: Arc<Store<RuleSetsDoc>>, dirs: &DataDirs) -> Self;  // <data>\cache\rulesets, resources\
    pub fn active(&self, managed: bool) -> Option<(ActiveSource, PathBuf)>; // dir with both .srs files; None = neither
    pub async fn refresh(&self, cfg: &RefreshSettings, force: bool, cancel: &CancellationToken) -> RefreshOutcome;
    pub fn prune(&self) -> usize;                                         // blocking; only before an engine start
}
```
Downloads are https-only (redirects too, <= 5), <= 8 MiB, 15 s connect / 45 s total, routed
per `bootstrapRouteMode`; both files are validated by the bundled `sing-box rule-set match`
with canaries and promoted together as a new immutable generation. A forced refresh during a
running one waits for it.

## `apps` — installed applications (split-tunnel picker)

```rust
pub struct InstalledApp { pub name: String, pub path: AppPath }
pub fn discover() -> Vec<InstalledApp>;   // blocking: HKLM 64 + 32, HKCU Uninstall, %LOCALAPPDATA%\Programs
pub fn scan_programs(root: &Path) -> Vec<InstalledApp>;
pub fn sanitize_name(name: &str, path: &str) -> String;  pub fn fallback_name(path: &str) -> String;
pub fn looks_corrupt(name: &str) -> bool;
```
Picker: `spawn_blocking(apps::discover)` then `store.update(|d| d.merge_discovered(&found))`;
adding by path: `SplitTarget::parse(raw)`, and for `App` require `probe_fs(..)` == `File` first.

## Wiring per (re)start (tunnel)

```rust
let active = rulesets.active(settings.managed);                   // after rulesets.prune() (blocking)
let doc = rules_store.snapshot();                                  // Store<RulesDoc>
let split = doc.resolve_split(probe_fs);                           // blocking
let dns = doc.active_dns().map(|p| p.primary);
let engines = [AppPath::parse(&xray_exe.to_string_lossy())?];   // slot mode / external proxy
let routing = routing::build(&RoutingInputs { smart, rule_set_dir: active.as_ref().map(|(_, d)| d.as_path()),
    domain_rules: &doc.domain_rules, split: &split, engine_paths: &engines,
    third_party_cores: local_proxy_mode, dns: dns.as_ref(), physical_dns: &phys_dns,
    endpoint_is_hostname });
for w in &routing.warnings { notify(w.msg()) }
// -> ConfigInputs { routing: routing.parts, phys_dns, .. } -> singbox_config::build -> SingBoxProcess
```
- Restarts on rule changes: watch `Store<RulesDoc>`, debounce 1.5 s, rebuild the fragments and
  restart only when `compat_key` / the fragments differ. DNS / Smart RU changes apply at the
  next connect.
- Hits: poll `ClashApi::connections()`, feed `HitTracker::observe(&doc.domain_rules, samples)`;
  every <= 30 s and on exit `store.update(|d| d.add_hits(&tracker.take()))`.
- Rule sets: auto refresh (start, settings change, hourly) only when
  `RefreshSettings::auto_refresh(smart_ru_enabled)`; "update now" = `refresh(cfg, true, ..)`.

## Events and messages to handle

| source | what |
| --- | --- |
| `XraySupervisor::new(.., events)` | `XrayEvent::Exited` of a running slot (crash when `!expected`) |
| `SingBoxProcess::exit_watch()` | `Some(ExitInfo)` once sing-box exited (crash unless `user_initiated`) |
| `SingBoxProcess::subscribe_lines()` | raw engine lines (traffic history parsing; secrets inside) |
| `RoutingWarning::msg()`, `Resolved::warning()`, `RefreshOutcome::notice()` | must be shown to the user |
| `Store<RulesDoc>` / `Store<RuleSetsDoc>` change notifications (`vpnte_core::store`) | UI refresh, restarts |

i18n: register `vpnte_engine::LOCALES` (4 fragments, all under `engine`). Key families:
`engine.config.invalid`; `engine.process.*` (+ `.xray.*`), `engine.clash.*`,
`engine.ports.exhausted`; `engine.xray.{reject, singBoxOnly, conflict, config, resolve}.*`;
`engine.routing.{domain, dns, split, warn, ruleSets, legacy}.*`. Every `Msg` this crate returns
uses one of these keys (a crate test checks that each literal key exists in ru and en and that
no fragment key is unused).

## Not implemented / not verified

- Not run: a real TUN start (needs elevation): routes, WFP interplay and runtime DNS are only
  checked by `sing-box check`; review risks R-E1..R-E5 (firewall vs mixed stack, IPv6 preference,
  UDP process lookup, link-local, VirtualBox) are open. The kill-not-delivered path of a stop
  (`ExitNotConfirmed` after a refused kill) was not executed. The graceful stop ran here against
  the real engines without TUN (sing-box mixed inbound, Xray SOCKS slot: both exit 0 on their own)
  and its kill fallback against a stand-in that ignores CTRL_BREAK (ping); that sing-box with a
  real TUN closes its adapter on CTRL_BREAK is read from the 1.14.4 / sing-tun source and proven
  only by the elevated `tunnel/tests/e2e_tun.rs` in CI. The proxy capture runs live in a
  loopback test (HTTP GET, CONNECT and SOCKS5 through `proxy-in`); process rules against proxy
  clients and SOCKS5 UDP through it were not executed (source-verified only).
- Not here: a sing-box config for a standalone loopback proxy / probe instance (no TUN):
  `proxies` / `probes` compose it from `vpnte_profiles::emit_singbox` + an authenticated mixed
  inbound and run it with `SingBoxProcess`. Planned `ipv6_egress` (IPv6 through the VPN) is not
  implemented. Clash `/proxies/<tag>/delay` is dropped.
- `resolve_hosts`: the 5-minute server-list IP seed is the caller's (leave known hosts out and
  merge them); one outbound with several different names and an empty server name keeps only
  the first pin (no warning). Xray `verifyPeerCertByName` / `mldsa65Verify` are not modelled;
  VLESS Encryption strings are not validated (Xray's own start failure is reported).
- Not run here: live rule-set downloads from GitHub (loopback HTTP tests only), the registry
  discovery smoke test (`#[ignore]`, reads this PC), directory-junction walking of `scan_programs`.
