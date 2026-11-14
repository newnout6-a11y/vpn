# vpnte-service — API

The helper service `vpnte-service.exe` (Windows service `VpnTunnelEnforcerService`, LocalSystem,
automatic start) and the library parts the app uses to talk to it. The service hosts the
privileged half of the tunnel — `vpnte_tunnel::runtime` with `TunCapture`, `RealEngines` and the
WFP `Protection` — behind one named pipe; the unelevated app drives it. Proxy mode (Soft) stays
in the app and never needs the service. Depends on `vpnte-base`, `-winnet`, `-profiles`,
`-engine`, `-tunnel`, `-probes` (the leak self-test, p-svc-recheck); new external dependency: none (`ring` for Ed25519 is already in the
workspace through rustls; the SCM is called through `windows` with `Win32_System_Services`).

```toml
vpnte-service.workspace = true
```

| module | what |
| --- | --- |
| `proto` | the pipe protocol: versions, typed requests / replies / events, wire mirrors, framing (`proto::frame`) |
| `pipe` | server `Listener` (name, DACL, first instance, remote refused), client identity (`pipe::ident`), the app's `pipe::client::Client` |
| `validate` | refuses what a SYSTEM engine must not get (provider sing-box keys outside the allow-list, provider JSON keys a Go decoder reads differently, a provider Xray graph failing its full import checks, non-loopback proxies, oversize text / lists, bad exceptions) |
| `sddl` | pipe / service / folder security descriptors, `path_admin_only` (trusted-folder check) |
| `host` | the session host: one runtime + kill switch, one controlling client, state changes in arrival order, events, client-gone stop, the kept last session and its resume (`keep_sessions_in`, `resume`) |
| `users` | Windows users (SIDs) of the service: the installing user and each user's first `Hello`; the last `ForgetMe` removes the service |
| `scm` | `scm::manage` (create / configure / start / stop / delete, installed binary path), `scm::dispatch` (running under the SCM; `Control::resumes()` counts wakes from `SERVICE_CONTROL_POWEREVENT`) |
| `install` | `install` / `uninstall` (elevated verbs), `remove_self`, `install::flow` (the order of their steps and what follows a failed one, over a `Machine` seam), `install::image` (the running exe through a locked handle), `install::pins` (SHA-256 against `resources/engines.toml`), `install::entry` (p-tails-a: the Settings > Apps entry under HKLM) |
| `per_user` | what the per-user side runs: `request_install` (the one elevated step, asked of Windows with `runas`), `request_uninstall` (the same for `uninstall`: Settings > Apps), `is_current`, `forget_me`, `status` |
| `paths` | service name, `%ProgramFiles%\VPN Tunnel Enforcer Service\`, `%ProgramData%\VPN Tunnel Enforcer\` with its private `service\` part (`DataFiles`), `secure_dir` |
| `service` | the service body (`run`): logging, WFP start-up, runtime, host, sandbox, graceful stop, the re-checks of a held kill switch (`service::recheck`: wake / network change, leak self-test); `trusted_install` / `FolderFault` |
| `logs` | the service log (p-logs): `init(dir)` (global subscriber, redacted app-log JSON lines in `service\service.log` + `service.1.log`, 1 MiB, each tagged `user` = the session's SID, else the controller's, else none; `"?"` when the host is busy), `attribute(owner)`, `owner_of`, `lines_for(dir, sid)` / `for_user(sid)` (service-wide lines and the caller's own, tag stripped, last `REPLY_LINES` = 2000) |
| `watchdog` | `Engaged` (a capture that records whether a session's filters are held) and `run` (the WFP watchdog exactly while they are) |
| `sandbox` | engines may not start programs: each engine process in a nested job with `ActiveProcessLimit = 1` |
| `update` | its own updates through the signed feed (p-svc-update): `swap` (the exe swap, trial, rollback), `engines` (`ServiceEngines`: Tunnel mode's engine store), `checks`, `source` (`Mirrors`), `trial` (`Judged`: the engines' trial from the host's starts), `in_flight` (`InFlight`, `Counted`: the host's calls in flight), `Updates` / `UpdatesDeps` (`Take` only, no schedule), `UpdateDesk` / `OwnSession`, `accepted_seq`, `staged_release`, `RESTART_EXIT` |
| `LOCALES` | `&[(ru_json, en_json)]`, keys under `service.*` |

## Binary verbs
```
vpnte-service run                          # the SCM's command line ("<exe>" run); not for people
vpnte-service install [--resources <dir>]  # elevated: copy + pin-check + register + start
vpnte-service uninstall                    # elevated: stop + WFP objects + engine firewall rules + delete + folders
                                           # (unelevated, e.g. winget's quiet run: asks Windows to run `uninstall --approved`)
vpnte-service request-install [--resources <dir>]  # per-user: asks Windows to run `install` elevated
vpnte-service request-uninstall            # Settings > Apps (unelevated): no console, asks Windows to run `uninstall --approved`, one message box on the outcome
vpnte-service forget-me                    # per-user uninstaller: this Windows user leaves (no prompt)
vpnte-service status                       # the installed service answers over its pipe (CI smoke)
vpnte-service sweep <pid>                  # started by the service's own removal only (see below)
```
Exit codes 0 / 1 (reason on stderr, English) / 2 (usage) / 3 the service stays to remove its
network filters later (`service.uninstall.filtersKept`: `uninstall`, `forget-me`) / 4 an upgrade
failed and the service is stopped until Windows starts it (`service.install.notRestarted`) / 5
nobody approved the prompt (`request-install`; the installer and the app then go on in proxy
mode) / 6 the service is removed but files another program holds open stay in its folder (retried
10 s first; `service.uninstall.filesLeft`, `folder`; never queued by path: review tailsa-a2).
`request-uninstall` lets go of the console Windows opened for it and tells the user in one message
box when the service stays for its filters (`service.uninstall.notYet`), files stay (`filesLeft`)
or the removal failed (`service.uninstall.failed`); nothing when it is gone or nobody approved
(tailsa-b1). `uninstall` run unelevated asks Windows itself instead of refusing (tailsa-b3). `request-install` asks nothing when the installed service exe is this build byte for byte
and no swap of it is on trial (`per_user::is_current`: an unsettled `update\swap.json` is not
current, so the release installer repairs a fresh exe that crashes before its trial counts) and
otherwise returns the elevated `install`'s own exit code. `install` copies this exe and
`sing-box.exe`, `libcronet.dll`, `wintun.dll`, `xray.exe`, `geoip-ru.srs`,
`geosite-category-gov-ru.srs` (default source `<exe dir>\resources`) into
`%ProgramFiles%\VPN Tunnel Enforcer Service\`. Everything is read and checked before anything
changes: the exe through a locked handle (below), each engine file once, hashed and later written
from the same buffer (`service.install.fileMismatch(file)` / `fileMissing(file)`); a missing or
changed file fails the install while the old service runs on, untouched. Then an existing
service is disabled (the SCM's recovery cannot start the old exe while its files change) and
stopped for good (a stop that does not reach `STOPPED` in 30 s fails the install, and the old
registration is enabled again), the files are replaced with retries, the folder gets the DACL
`ADMIN_ONLY_DIR_SDDL` (owner Administrators; SYSTEM / Administrators full, Users read) and is
checked as the service checks it (a folder it would refuse fails the install, naming the file and
the reason), the data folder is secured, the user of the installing Windows session is recorded
(also when an administrator's credentials elevated the verb), and the service is created or
updated (LocalSystem, `SERVICE_AUTO_START` again, quoted command line, unrestricted service SID,
`SERVICE_SDDL`, recovery restart 5 s / 10 s / 60 s reset after a day, also on non-crash
failures) and started. Any failure after the stop (files, trusted-folder check, data folder,
registration) gives the service its automatic start back and starts it again — the old files if
nothing was replaced yet, otherwise what is there, which refuses Tunnel mode with its own reason —
so an "Always" block it kept stays managed; the original error is returned, or
`service.install.notRestarted` when even that start failed (review 4555679947, `install::flow`).
`uninstall` disables, stops, removes our WFP objects and the Windows Firewall rules sing-box made
for the engines (`sing-tun (<file in the service folder>)`, lab F-8), deletes (a service already
marked for deletion counts as deleted) and removes both folders; it tries every step and reports the first
failure, so a rerun finishes what is left — except a failed WFP clean-up: then the registration
and the files stay, the service runs again (its start-up removes leftovers of a level no longer in
force) and `service.uninstall.filtersKept` is returned (review 4555679938). Folders come from
`SHGetKnownFolderPath`, never from environment variables.
The last user's leave (`remove_self`, inside the service) removes the same, but its own process
holds the engine files open until it exits (the engine pins, against a swap): those can be neither
deleted nor renamed, so it starts `sweep <its pid>` from its exe's tombstone (SYSTEM, detached),
which waits for that process to end (60 s at most) and removes what is left of the folder unless a
service is registered again by then; the running exe and the folder go at the next restart, as
before (p-live2, lab F-8: four engine files and the firewall rule outlived the uninstall).

Threat model of the elevated verbs (review service-a5). They run from the per-user app folder,
which every process of that user can write. What the folder held at the UAC prompt (the exe and
the DLLs it imports at process start) is what the administrator approved: a swap before the
prompt, or a write that lands before the process starts, is out of scope (the unsigned per-user
flow the owner chose). Everything after the start fails closed: the first step of `install`
(`install::image::read_running_exe`) opens the running exe with read sharing only (from then on
it cannot be written, renamed or deleted, and the open fails while anyone holds it for writing),
proves that the handle is the running image (`NtAreMappedFilesTheSame` over the mapped image
and a mapping of the handle: files, not names), and the bytes read through it are what is copied
(`service.install.imageChanged` when the file at the exe's path is no longer the running image).
Checked on Windows 11 by `install::image::tests`: a running exe can be renamed but not deleted,
`GetMappedFileNameW` then names its new path, a locked exe cannot be renamed. Later DLL loads by
name come from System32 only (`install::system_dlls_only`, `SetDefaultDllDirectories`).

## Protocol (`proto`)
Frame = 4-byte little-endian length + JSON, `1..=MAX_FRAME` (4 MiB) bytes. The first frame of a
connection is at most `frame::FIRST_FRAME_MAX` (16 KiB) and must arrive within `HELLO_TIMEOUT`
(10 s) as `Hello` (or `ForgetMe`, see the security model); at most `MAX_UNIDENTIFIED` (16)
connections wait for theirs, more are closed at once: nothing big is held for a client before it
is identified. Client ->
`ClientFrame { id, request }`; service -> `ServerFrame::{Reply { id, reply }, Failed { id, error },
Event { event }}`. `PROTOCOL = 4` (2 added `StatusWire::self_test`, 3 `RoutingInputs::rule_sets`, 4
`RoutingInputs::only_listed` and `StatusWire::rule_sets`; `SCOPE_PROTOCOL = 4` and
`RULE_SETS_PROTOCOL = 4` name them for the app; `HINTS_PROTOCOL = 5` names `ServerUpstream::{fresh,
hints}` (speed3 H2), stripped by `Request::speak` below it: until `PROTOCOL` is 5 nothing sends them);
`negotiate(client, service)` = the lower one while they differ by at most one (so a version-2
peer is refused now). Evolution: add requests / replies / events / optional fields only; the
newer side speaks the negotiated version (`Request::speak(protocol)` strips the rule sets for a
version-2 service and the scope for a version-3 one, which then runs every app through the tunnel, applied by `pipe::client` to every request after `Hello`; the service's
`Reply::speak` / `StatusWire::speak` drop `rule_sets` for a version-3 client; every status a
service of this build sends carries `self_test`, which versions 2 and 3 both know); structs refuse
unknown fields.
```rust
pub enum Request { Hello(Hello), Start(Box<TunnelStart>), Stop(StopTunnel), Restart(Box<TunnelStart>),
    RestartWithLast { reason: String }, RestartAdaptive(Box<AdaptiveRestart>), Switch(Box<TunnelStart>),
    Inputs(Box<RoutingInputs>), Status, KillSwitch(Box<ProtectionSettings>), Cleanup, ForgetMe,
    Update(UpdateAsk) /* p-svc-update: a first frame like ForgetMe, or after Hello */,
    ServiceLog /* p-logs: a first frame like Update, or after Hello; no PROTOCOL bump (never on a
                  negotiated connection from the app; an older service answers badRequest) */ }
pub enum UpdateAsk { State, Take { version: String } }
pub struct Hello { pub protocol: u32, pub app_version: String }
pub struct TunnelStart { pub upstream: Upstream, pub routing: RoutingInputs,
    pub protection: ProtectionSettings, pub adaptive: AdaptiveMode, pub engine: EnginePref, pub origin: Origin }
pub enum Upstream { LocalProxy { addr: SocketAddr /* loopback */, kind: ProxyKind }, Server(Box<ServerUpstream>) }
pub struct ServerUpstream { pub id: String, pub profile: Profile, pub device: Option<ClientDevice>, pub engine: EnginePref,
    pub fresh: bool, pub hints: Vec<NameHint> }   // speed3 H2: serde default, skipped when empty; protocol 5
impl ServerUpstream { pub fn facts(&self) -> Option<ServerFacts> /* None: out of bounds -> refused */;
    pub fn without_facts(&mut self) }              // as an older service reads it / as the resume memory keeps it
pub struct RoutingInputs { smart_ru, smart_ru_maps_direct, domain_rules: Vec<DomainRule>, split_direct,
    split_vpn: Vec<String> /* process_path_regex */, dns: Option<DnsAddr>, public_wifi, stealth,
    auto_restart_on_crash,
    rule_sets: Option<RuleSetFiles> /* protocol 3: the app's active Smart RU lists as bytes */,
    only_listed: Option<Vec<String>> /* protocol 4: «VPN только для выбранных приложений»; the app's
        own exe as process_path_regex values; checked like the split lists */ }
    // no rule-set dir, no inactive splits (the app adds their warnings to the start receipts)
pub enum Reply { Welcome { protocol, service_version }, Started(Option<StartReceiptWire>),
    Stopped(StopReceiptWire), Switched(Option<SwitchReceiptWire>), Status(Box<StatusReply>),
    Done { removing: bool }, Cleaned { filters, sublayer, provider }, Update(ServiceUpdateWire),
    ServiceLog(ServiceLogWire) }
pub struct ServiceLogWire { pub lines: Vec<ServiceLogLine { offset: u64, text: String }>, pub truncated: bool }
pub struct ServiceUpdateWire { pub version: String, pub phase: UpdatePhase /* Off | Idle | Working | Waiting
    | Restarting | Failed */, pub target: Option<String>, pub checked_at: Option<UnixMs> }
pub struct StatusReply { pub tunnel: StatusWire /* with SessionWire: Clash secret, proxy creds */,
    pub last_exit: Option<ExitWire>, pub recent_fault: Option<OutboundFault>, pub protection: ProtectionWire,
    pub kept: Option<KeptSession> }   // the running session, for its own user's take-over
pub struct KeptSession { pub receipt: StartReceiptWire /* current generation, pid, start, engine */,
    pub server_id: Option<String>, pub local_proxy: Option<SocketAddr> }
pub enum Event { Status(Box<StatusWire>), Tunnel(TunnelEventWire), Notice(Notice) }
pub struct WireError { pub code: ErrorCode, pub kind: ErrorKind, pub msg: Msg, pub warnings: Vec<Msg> }
pub enum ErrorCode { Busy, Version, HelloFirst, BadRequest, Refused, Failed }
```
Wire mirrors convert from the runtime's types and back where the app needs them
(`TunnelEvent`, `TunStatusKind`, `StopReceipt`, `ExitInfo`, `ProxyEndpoint`; `proto::back`:
`TunStatus` with its `SessionEndpoints`, `StartReceipt`, `SwitchReceipt`, `EngineRun` (a reason of
the "sing-box only" shape reads as none), `KillSwitchState`, `ProtectionWire::to_status`). A pushed
`StatusWire` also carries `last_exit` / `recent_fault`, for the session's own user only, and
`self_test: Option<vpnte_probes::leak::SelfTestResult>` (protocol 2): the service's latest leak
self-test, to the session's own user while his TUN session runs; a new result is pushed at once.
The app passes each new run (`at`) to its leak forwarder: a leak marks the session and is a toast,
and the leak check card shows the run, as for runs of its own.
`rule_sets: Option<RuleSetsWire { source: Handed | Kept | Pinned, digest, refused: Option<Msg> }>`
(protocol 4, psmart-b2): which Smart RU lists the service's last engine start ran
(`SharedInputs::rule_sets`; `None` while Smart RU is off); the app shows a line in Settings when
they are not its own set.
Certificates (p-speed, lab F-3): `Host::serve` turns `vpnte_base::http::verify_offline` on for the
whole service process: its HTTPS (DoH of server names, exit proofs) runs under the kill switch's DNS
block, where Windows' online revocation fetch stalls; rustls checks chains and names against the
bundled Mozilla roots and the Windows root store instead (revocation was soft-fail anyway).
speed3 H2: `prepare` hands a request's server facts to `SharedInputs::offer(Some((id, facts)))`; the
runtime takes them once through `InputsSource::server_facts(id)` (a fresh user's switch selects
first; Lane A's start reads the hints); never kept for a restart, never in the resume memory.
speed3 P-1: `SharedInputs::set(routing, level, owner_sid)`: the accepted hand-over and its store note
(`accepted-<hash of the SID>`) are per Windows user; a user whose own set fails runs his own last
accepted set, else the pinned files, never another user's (`handover::{accept, recall}` take the owner).
speed3 H3: `ForgetMe` also drops the user's recent server names (`vpnte_core::resolve::forget(sid)`).
Lab live-9 L9-2: `SharedInputs::set(self: &Arc<Self>, ..)` starts the check of a handed-over set in
the background the moment it arrives (start, restart or `Inputs` request); a start's snapshot finds it
accepted by digest or waits only for the rest (`Smart RU lists ready ms=..`; the accept logs `ms`).
Smart RU's lists (re-check item 12a): `host::SharedInputs` keeps the last `rule_sets` and checks
them at the next engine start (`InputsSource::snapshot`): the service's own pinned set as is (no
copy); another set once per content (`rulesets::handover::accept`: names, 2 MiB cap, canaries and
the content bounds against the pinned copies with the service's own sing-box, written flushed) into
`<ProgramData>\VPN Tunnel Enforcer\service\rulesets\gen-<digest16>`, reused only while its files hash
to the set (the running engine's folder is kept, older ones pruned); refused: the set in use before
it (the last one accepted, else the pinned files); absent: the pinned files of the install folder,
which holds all four `.srs` (`install::pins::FILES`). Without them all no handed-over set passes
either (they are the reference of the bounds): Smart RU off, with the usual warning.
Request -> runtime call: `Start` = `start`, `Restart` = `restart_protected`, `RestartWithLast`,
`RestartAdaptive`, `Switch` = `switch_upstream` (owner = this connection alive), `Stop` = `stop`.
Every start-like request first validates, applies its kill-switch settings (`Protection` level,
toggles, exceptions; saved in `service\protection.json` through a temp file synced before the
rename, so `strict` holds from boot; a missing file is Off, a damaged one strict, logged) and
replaces the routing inputs. The capture is always `Tun`. State changes (kill-switch settings,
routing inputs, cleanup) run one at a time in arrival order, each to its end even when its
request is dropped. A `Stop` cancels every start-like request sent before it, also one still
applying its settings. The controller has at most 32 requests in flight; its further frames are
not read until one finishes. Events of an operation are sent before its reply; a changed status
is sent before the tunnel event that goes with it; a lagged stream resends the status.

## The app's side (phase 2 builds on this)
```rust
use vpnte_service::{pipe::client::{Client, ServerCheck, CallError}, proto::*, scm::manage, sddl};
let exe = manage::installed_binary()?;          // None: not installed -> Proxy mode + "Install" button
let mut c = Client::connect(sddl::PIPE_NAME, &ServerCheck::Image(exe?), Duration::from_secs(5)).await?;
let (protocol, service_version) = c.hello(env!("CARGO_PKG_VERSION")).await?;   // Err Busy: another user
let reply = c.call(Request::Start(Box::new(start))).await;  // Err(CallError::Service(WireError))
let event = c.next_event().await?;              // events queued while a call waited come first
```
A long-lived controller splits the client after its `Hello` (`Client::split` -> `Requests` +
`Frames`): requests in flight at once (`Requests::id`, then `send`, written on a task of its own so
a dropped caller never leaves half a frame) and one ordered stream (`Frames::next` ->
`Incoming::{Event, Answer}`), so a reader that publishes events before completing answers keeps
"events before the reply". The app's remote runtime (`crates/app/src/svc_tunnel/remote.rs`) is
built that way.
`ServerCheck::Image` accepts the pipe's server (`GetNamedPipeServerProcessId`) when it is the process
the SCM runs for the service (`scm::manage::process_id`: interactive users may query it, and an
unelevated app cannot open a LocalSystem process to read its image), else when its image is the
SCM's binary path: a pipe someone else created is refused before anything is sent
(`service.pipe.notOurs`). A missing service reads as `service.pipe.unavailable`; the other
failures say what happened: `service.pipe.denied` (the pipe's DACL refuses this account),
`noAnswer` (every instance busy until the timeout), `lost` (the connection broke), `badReply` (a
frame this build cannot read), `tooLarge` (the request is over `MAX_FRAME`). `Busy` is
`service.pipe.busySelf` when the slot holder is the same Windows user (his app's previous
connection still closing). `Client` is cancel-safe: a `call` or `next_event` dropped half-way
(raced in a `select!`, or abandoned to send a `Stop`) loses no bytes; the abandoned call's reply
is dropped when it comes. A per-user uninstaller sends `ForgetMe` as its first frame (no
`Hello`): it is answered without the controller slot, also while another user is connected.

## Security model (research `service.md` §3; owner decisions of 12.11.2026)
- Pipe `\\.\pipe\ProtectedPrefix\Administrators\VpnTunnelEnforcer\Service` (only admins /
  SYSTEM can create it), `PIPE_SDDL = D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)` (users read /
  write without `FILE_CREATE_PIPE_INSTANCE`), `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`. Client identity = pid, session, token SID (impersonation at
  identification level after the first frame); `HostDeps::check` is the verification hook
  (`admit_all` by default: the boundary is the typed protocol, not the caller's image).
- One controlling client; others get `Busy` (`service.pipe.busy` / `busySelf`). Any interactive
  user who finds the slot free controls the machine's tunnel (upstream, DNS, kill switch) for
  every account and service on the PC: NOADMIN §4 (binding, as with Mullvad). His own server as
  the upstream gives the same reach, so a local proxy or a custom DNS is not restricted further;
  another user's app shows `Busy`, never a silent takeover (review service-b3).
- A session outlives a connection that drops without a `Stop` (owner question 23, default: the
  app's window crashed): a start / switch in flight is cancelled, kill-switch changes already
  asked for finish, and a running session keeps running. The same Windows user's next app takes
  it over (`StatusReply::kept`, then a start of the same upstream answered without a second
  start); a session nobody takes over keeps running until a `Stop` (the user can stop it from the
  app at any time). Another user's `Hello` ends a kept session of someone else first
  (`stop(preserve_protection = level in force == strict)`): its secrets and last exit are its
  user's. Quit and Disconnect send a `Stop`. The service owns our WFP objects
  (`Protection::in_service(.., SERVICE_NAME)`, ks-d): "If the VPN drops" is static (survives a
  crash of the service, gone after a reboot) and "Always" persistent under a provider registered
  with the service's name, so BFE adds it at boot only while the service starts automatically
  (uninstalled or Disabled: no block at the next boot, even after a failed cleanup; rescue for an
  administrator: Services -> Disabled -> restart). Service STOP / shutdown -> the stop above, the
  static set deleted ("Always" stays). The runtime's last exit and recent fault go only to the
  user whose start they came from.
- The last session (ks-d): every successful Start / Restart / Switch is kept with its user's SID
  in `service\session.json` (`host::memory`; it holds the upstream's key: private folder). The
  service starts it again with no client (`Host::resume`, then kept for that user's take-over, as
  after an app crash) when (a) its own crash left an armed "If the VPN drops" block behind: the
  restarted service takes the static block over (`Protection::paused`) and holds it until the
  session is up again; with nothing to resume, or a failed start, the block is lifted; and (b) at
  each of its starts while "Always" is in force (connect at Windows start: the VPN is up before
  anyone signs in; turning "Always" off turns it off). A stop keeps the record (for "Always");
  another user's `Hello` and the last user's leave drop it.
- Typed input only (`validate`). Provider JSON (the values of sing-box keys, an XHTTP `extra`, a
  native Xray graph's outbounds, rules, balancers, observatories and policy) may use only keys of
  printable ASCII, no two of one object equal ignoring ASCII case, at any depth: Go's decoder
  matches keys with Unicode folding (`ſ` = `s`, the Kelvin sign = `k`) and keeps the last of two,
  so `maſterKeyLog` would be Xray's `masterKeyLog`, a file SYSTEM creates (review service-b1). A
  native graph also passes its full import checks (reach, local files, insecure TLS, application
  bypass: `xray_native::compile`) at the boundary. Engine configs are built inside by the
  runtime; logs go to the data folder; engines run from the admin-only folder, pinned (the engine
  crate's elevated pin check) and each in its kill-on-close job (engine crate). `sandbox` confines
  every engine process of the folder in a nested job of its own with `ActiveProcessLimit = 1` (it
  cannot start programs; a seat belt: confinement follows the engine's start by a moment), swept
  on every runtime status change / event and every 10 s while a session runs.
- Tunnel refused (`service.folder.untrusted`) when the service folder, its exe or any engine file
  is writable by non-admins (`sddl::path_admin_only`: owner and every non-inherit-only allow ACE
  with write rights must be SYSTEM / Administrators / TrustedInstaller). A missing file is
  `service.folder.fileMissing(file)` instead (an antivirus quarantine, say: not tampering).
- Data folder `%ProgramData%\VPN Tunnel Enforcer\` (`ADMIN_ONLY_DIR_SDDL`: users read; `logs\`
  with the engine logs of TUN sessions, which the app reads directly, NOADMIN §4) and its
  private part `service\` (`PRIVATE_DIR_SDDL`: SYSTEM / Administrators only, nothing inherited:
  `users.json`, `protection.json`, `session.json`, `service.log` rotated at 1 MiB into
  `service.1.log`), each re-created when it is missing or user-writable. The service log reaches
  a user only through `ServiceLog` (p-logs): service-wide lines and those tagged with his own SID
  (the pipe token's, never a claim of the client); lines of another user, busy lines and the plain
  text of older builds stay private.
- Users: the elevated `install` records the user of its Windows session, and a user is recorded
  at his first `Hello` (he may use a service another account installed). `ForgetMe` (per-user
  uninstaller; first frame or after `Hello`, no controller slot needed) removes the caller's SID
  and every account Windows no longer knows; a failed save changes nothing (a retry repeats it).
  The last user's leave first stops the tunnel, sets the kill switch off (saved) and removes our
  WFP objects, before the answer: when that fails he stays recorded and hears
  `service.uninstall.filtersKept` (the service stays; its start-up removes the leftovers of the
  now-off level, and his retry repeats the leave). Then the service deletes its registration, its
  engine files and data, and stops. What is in use (the running exe, the open service log) is renamed
  to `<name>.<time>.deleted`, and only that tombstone, then the emptied folders, are queued for
  deletion at the next restart (`MOVEFILE_DELAY_UNTIL_REBOOT`): a reinstall before that restart
  keeps its files (Windows never deletes a folder that is not empty).
- The WFP watchdog (re-applies the filters after a BFE restart) runs while the kill switch holds
  a session's filters: from a successful `begin` to a successful `release` of the capture, so an
  engine crash, a preserved stop and "kill switch active" stay watched; an idle service has no
  timer.
- Re-checks of a held kill switch (RU audit item 11, p-svc-recheck; `service::recheck`), with the
  same lifetime as the watchdog: on a wake (`SERVICE_CONTROL_POWEREVENT` with
  `PBT_APMRESUMEAUTOMATIC`, sent on every wake) and on a network change (winnet `watch_network`,
  1.5 s debounce) the watchdog's filter check runs at once instead of at its next 30 s tick, and
  3 s later the leak self-test (curl.exe bound to each physical adapter: the filters do not
  permit it, so it measures what any program sees). The self-test also runs every 30 s while a
  TUN session runs with the kill switch on (level in force not Off); a leak is logged and runs
  the filter check at once. Results go to the status (above). In the service, not the app: with
  "Always" the session runs before any app does. The DNS canary stays in the app (a plain lookup).
- Its own updates (p-svc-update; owner answer 7: our own minisign key, no code signing): one key
  set with the app, `vpnte_update::policy::trusted_keys()` (`feed::verify`); without keys the
  service never checks (`UpdatePhase::Off`). See "Updates" below.

## Updates (`update`, p-svc-update)
The service fetches the signed feed and the files itself, directly over HTTPS from the compiled
mirrors (`source::Mirrors`; while a TUN session runs the requests go through it like any traffic,
the service's own exe being permitted), never from a file a client hands over; `vpnte_update::
feed::verify` with the compiled keys is the only trust. It checks only on the app's `Take`, sent
right before a release's installer runs (the user's «Обновить»; owner decisions 19 and 28, review
svcupd-b4): no schedule of its own, so the app's switches (automatic checks, download ahead, skipped
versions) decide, and a rollback stays a rollback (svcupd-a7). One check at a time; a feed older
than the newest accepted `seq` (`service\update.json`, private: `maxSeq`, `checkedAt`) or past
90 days is not acted on and reports `Failed`, never "up to date" (svcupd-a10). No request at all
while the kill switch blocks the machine with no TUN running ("Always" without a session, a held
block after a drop): the service's own program permit would pass that block (svcupd-b7). A block
that begins during a check ends its requests at once: they run under a token of the check,
cancelled as soon as the status or the held filters say so ("Always" read again every second
while a check runs), and the check reports `Failed` (svcfix-a3 / b1).
- Engines for Tunnel mode (`engines::ServiceEngines`): the engine store over `<install>\engines`
  with the install folder as the bundled set and `EngineStore::not_below_bundled` (after an exe
  swap the folder holds the previous release's engine files, which the new exe's pins refuse: the
  same version from the feed replaces them). Wanted: `feed.engine(id)` inside the compiled range,
  meant for this version, newer than what runs (or what runs fails the pins). Each archive goes to
  the staging folder, its listed members (hashes of the signed feed) into `<id>\<version>\` with
  the feed next to them (the engine crate's elevated pin check accepts that folder), the engine
  must report the feed's version and pass a TUN + Xray-slot config check (`checks::EngineChecks`).
  Every engine start reads the active paths (`RealEngines::following`); `Engaged::with_engines`
  permits a version installed after the start of the service in each session (the protection's
  own engine permits are those resolved at start). The previous version stays for one rollback;
  three failed starts in a row of a fresh version go back (the store's trial, settled by the
  outcome of each start the host asks for through `trial::Judged` and `RealEngines::starts`, as
  the app's trial: a start the user cancelled or another start replaced says nothing, svcupd-a5);
  no switch back to files this build refuses (bundled files after an exe swap, svcupd-b6); a
  version that failed its trial is never wanted again (`EngineState::failed`, svcupd-a4). A version
  folder that users could change is not run (bundled instead, logged).
- Its own exe (`swap`): `feed.service` when it is exactly the asked release, above its own
  version and never one that failed here, is downloaded into `<install>\update\`
  (`paths::secure_dir` before every download: ADMIN_ONLY_DIR_SDDL, re-created when users could
  change it) with the signed feed kept next to it, and run once with a bad argument: only an exe
  that starts on this Windows and exits with its usage code 2 is staged (`swap::probe`, svcupd-a9;
  one that does not is recorded as failed). `swap::ready` re-verifies feed (not older than the
  accepted `seq`: a withdrawn release stays out, svcupd-a3), size and SHA-256 right before any
  swap; a staged release stays only while the newest accepted feed lists it byte for byte
  (`swap::keep_listed`, kept with that feed; another user's stale ask no longer drops it,
  svcfix-b3). Right before every swap (idle, `Take`, the next start) the staged release's engines
  are judged again (`update::staged_release`: Tunnel mode must run exactly the versions its feed
  lists; after the engine trial went back the release is dropped, svcfix-a1). Engines go first and
  are judged by the build that runs them (svcupd-a6): the release is staged only when the feed's
  entry of every engine is meant for that release and this build alike (one minor series, inside
  this build's ranges) and Tunnel mode runs exactly those versions after the engines step; else
  its installer brings it. It goes in when no session runs or starts (the runtime's
  `StartBegan` / `StartFinished`) and no session's filters are held, at the service's next start
  (before anything runs), or at once on a `Take` whose caller owns the session or finds none.
  Whose session it is (`OwnSession`, the host's current session user) and idle are judged when the
  ask arrives, again right before the swap and again right before the restart, which waits while
  it would end someone else's session (svcupd-a1 / a2 / a11) or cut a host call: the host's kill
  switch (`in_flight::Counted`) and runtime (`trial::Judged`) count every start and filter change
  from its first step (`in_flight::InFlight`), and the restart waits for none in flight and none
  ended within 1 s (svcfix-a4). The swap: the staged file is flushed, `swap.json` written
  (synced), the running image gets a second name (`update\vpnte-service.prev.exe`, hard link:
  Windows refuses to replace the entry of a running exe with one name, checked by
  `swap::tests::a_running_exe_is_replaced_through_its_second_name`), the entry is replaced
  (`MoveFileExW` replace + write-through), the service stops with `RESTART_EXIT` (10) and the
  SCM's recovery starts the new file. Trial: every start of the new version counts first
  (`swap::at_start` in `service::run`, before the runtime is built); a start that runs 30 s ends
  it; the start after three that did not puts the previous exe back the same way and exits for
  the SCM again; that version is skipped from then on (the spent marker stays as the record; the
  first start after the rollback logs it once, `AtStart::After`; a release the probe refused leaves
  the same record and never that line, svcfix-b4). A
  fresh exe whose install folder holds a wintun.dll its pins refuse (a release that changed
  Wintun, which the feed never brings) gives its trial up at its first start (`swap::give_up`,
  svcupd-a8): its installer brings both. The install verb drops whatever the feed staged or
  swapped (`swap::forget`): an installer's exe is never on trial.
- Power loss (`swap` docs, tested state by state): before the marker, the old exe and the staged
  file (the next start swaps it in); marker / link written, entry not replaced: the old exe (its
  start drops both, swaps again); entry replaced: the new exe on trial; during a rollback: the new
  exe again (it rolls back again); rollback done: the old exe. `vpnte-service.exe` is never
  missing: the replace is one directory operation.
- `Update(State | Take { version })`: answered as the first frame of a connection for any user,
  without `Hello` or the controller slot (like `ForgetMe`), and after `Hello` alike; an older
  service answers `badRequest`. Every answer is immediate (no connection waits on a download).
  `Take` = the app runs the installer of `version` next: the service answers `Working` and checks
  on the one check task (asks wait as the latest version, so a burst leaves one check behind;
  within 60 s of a check its result stands in for the same release and the feed it read for any
  other: many asks never mean many feed reads, svcfix-b2); when the feed's service is exactly `version` and the
  restart ends no one else's session (the ask stands 3 min), it swaps and reports `Restarting`.
  A `version` that does not parse is dropped before anything logs it (svcupd-b3); one at or below
  the running service (a rollback) reads nothing and drops a staged release, also one a check
  running then stages: nothing newer goes in by itself (svcfix-a2). The app follows `State` until the
  service answers as `version`, so the installer's `request-install` finds it current
  (`per_user::is_current`: the same bytes) and asks nothing.

## Idle footprint (measured 12.11.2026, `examples/idle.rs`, this machine)
Current-thread runtime; the listener waits in an overlapped `ConnectNamedPipe`, the runtime actor
on its inbox, the WFP watchdog runs only while a session's filters are held. Real runtime
(`RealEngines`, no TUN) + host behind a private pipe, unelevated, measured after 12 s of settling:
- release build, 30 s idle: working set 8.9 MB, private bytes 1.6 MB, CPU 0 ms;
- debug build, 20 s idle: working set 10.5 MB, private bytes 1.6 MB, CPU 0 ms.
Most of the working set is shared image / system DLL pages that Windows trims from an idle
service; private memory is what the service itself holds (Happ's service, measured the same day:
8.8 MB working set, 9.5 MB private). Not measured: the installed service under the SCM (needs
elevation) — it adds the WFP engine handle and the SCM thread, no timer.

### Settings > Apps entry (`install::entry`, p-tails-a)
```rust
pub const DISPLAY_NAME: &str = "service.entry.displayName";   // «VPN Tunnel Enforcer — служба-помощник»
pub const PUBLISHER: &str = "VPN Tunnel Enforcer";
pub struct Place { pub hive: Hive, pub path: String }         // machine(): HKLM\SOFTWARE\Microsoft\Windows\
                                                              // CurrentVersion\Uninstall\VpnTunnelEnforcerService
pub struct Entry<'a> { pub exe: &'a Path, pub version: &'a str, pub bytes: u64, pub lang: Lang }
pub fn write(place: &Place, entry: &Entry) -> windows::core::Result<()>;   // 64-bit view
pub fn remove(place: &Place) -> windows::core::Result<bool>;               // false = none
pub fn names(place: &Place, version: &str) -> bool;          // the entry lists this DisplayVersion
pub fn outdated(place: &Place, version: &str, enabled: bool) -> bool; // a start rewrites it (tailsa-a4)
pub fn system_lang() -> Lang;                                 // GetSystemDefaultUILanguage: ru, else en
pub fn user_lang() -> Lang;                                   // GetUserDefaultUILanguage: ru, else en
pub fn text(key: &str, lang: Lang) -> String;                 // this crate's fragment (the verbs have no catalog)
```
`install` lists the service right after its registration (`DisplayName` in the machine's
language, `DisplayVersion`, `Publisher`, `InstallLocation`, `DisplayIcon` = the exe, `EstimatedSize`
= the placed bytes in KiB, `NoModify` / `NoRepair` = 1, `UninstallString` = `"<exe>"
request-uninstall`, `QuietUninstallString` = `"<exe>" uninstall`); a failed write is a warning
only. The entry goes with the registration: the uninstall flow's delete step and the last user's
`remove_self` remove it once `DeleteService` succeeded (a service that stays keeps it). A failed
install leaves no entry of its own: it is written only after the registration, which no failure
path deletes (a failed upgrade keeps the old service and its entry). `uninstall` run from the
program folder itself (Settings > Apps) leaves its own exe and the folder to the restart queue
(tombstones, as `remove_self`); a file another program keeps open is tried again for 10 s, then
named (exit 6). Each start (`run`, `install::relist`, before the service log) rewrites the entry
when it does not name the running version: the service's own update (a swap or its rollback)
changes the exe under it, and a service an older build installed has none yet; never while the
service is disabled (`install::registered`, the SCM's start type): the uninstall disables it
first, so a start that overlaps an uninstall does not write the entry back (tailsa-a4);
`EstimatedSize` is then the folder's files. The per-user app's HKCU entry is the installer's,
untouched.

## i18n keys (`locales/svc-core.*.json`, all under `service.`)
| Keys | Args | Emitted by |
| --- | --- | --- |
| `service.pipe.{busy,busySelf,version,helloFirst,badRequest}` | — | `WireError` of the first request |
| `service.pipe.{unavailable,denied,noAnswer,notOurs}` | — | `pipe::client::Client::connect` |
| `service.pipe.{lost,badReply,tooLarge}` | — | `pipe::client::Client` calls |
| `service.refused.{tooLong,tooMany,text}` | `field` | `validate` |
| `service.refused.localProxy` | — | `validate::start` |
| `service.folder.untrusted` / `service.folder.fileMissing` | — / `file` | `service::FolderFault::msg` (refused starts) |
| `service.install.{notElevated,imageChanged,failed}`, `service.install.{fileMissing,fileMismatch}` | — / `file` | `install` |
| `service.install.notRestarted`, `service.uninstall.filtersKept` | — | `install::flow` (exit codes 4 / 3), the last user's `ForgetMe` |
| `service.uninstall.filesLeft` | `folder` | `install` (exit code 6), `request-uninstall`'s message box |
| `service.uninstall.{notYet,failed}` | — | `per_user::uninstall_message` (`request-uninstall`, user's language) |
| `service.entry.displayName` | — | `install::entry` (read from the fragment: the verbs register no catalog) |

## Not implemented / not run
- Not run here (the shell is not elevated): the SCM paths, `install` / `uninstall`, WFP and the
  real TUN session. CI covers them (`cargo test -p vpnte-service -- --ignored elevated_`):
  `tests/elevated.rs::elevated_install_tun_session_and_uninstall_leave_nothing` (install, pipe,
  TUN session, upgrade over the running service, uninstall twice),
  `install::tests::elevated_the_restart_queue_gets_the_tombstone_not_the_exe`,
  `sddl::tests::elevated_the_private_folder_grants_users_nothing`,
  `sddl::tests::elevated_installed_files_pass_the_trusted_folder_check`. Never run anywhere: the
  watchdog re-applying filters after a real BFE restart (the gate is unit-tested).
- Phase 2 (package svc-wire, 13.11.2026): the app's remote runtime, the installer steps
  (`request-install` after install / upgrade, `forget-me` on uninstall), `xtask dist` bundling,
  the smoke-install checks and the CI steps are built. Elevated, CI only (`-- --ignored
  elevated_`): `tests/elevated_review.rs` (a failed upgrade starts the service again; "Always"
  filters go before the service, by `uninstall` and by the last user's leave) and the app's
  `svc_tunnel::remote::elevated::elevated_remote_tun_session_through_the_installed_service`.
  The filters-kept branch runs only against fakes: a real BFE failure cannot be forced.
- ks-d (13.11.2026), elevated, CI only: `tests/elevated_killswitch.rs` — AT-03-001 (the engine
  killed under "If the VPN drops": the static block holds, nothing persistent, a stop removes all),
  AT-03-002 (the service killed: its block survives, Windows restarts it, it resumes the session
  for the user, a stop leaves nothing), "Always" under the provider with `SERVICE_NAME`; the BFE
  restart with the service Disabled (provider `FWPM_PROVIDER_FLAG_DISABLED`, no persistent filter
  of ours active, back after enabling) only with `VPNTE_BFE_RESTART_TESTS` set. Needs a real reboot, never run: static filters gone after one,
  "Always" not enforced at boot after the service was removed or disabled.
- Not built (later): the HKLM uninstall entry, the persistent Wintun adapter (research §5),
  failover / confirmation seams over the pipe (`None` in the service), a non-admin squatting test
  (the DACL mask is unit-tested).
- Smart RU in the service uses the bundled, pinned rule sets, not the app's refreshed copies.
- p-svc-recheck (13.11.2026), elevated, CI only: `tests/elevated_recheck.rs` (a TUN session of the
  installed service under "If the VPN drops" gets a periodic self-test in its pushed status and in
  the answer to `Status`, never a leak). Never run anywhere: a real wake reaching the service's
  control handler and a real network change; the re-check's reaction to both is tested with fakes
  (`service::recheck::tests`).
- p-svc-update (13.11.2026): never run against a real feed (the owner's keys are placeholders) nor
  under the SCM here: the swap, the trial, the rollback and every power-loss state ran on plain
  files in a temp folder (and once on a running copy of PING.EXE); a real `RESTART_EXIT` restart by
  the SCM's recovery, the at-start swap of the installed service, a downloaded engine in a real TUN
  session (the engine crate's elevated pin check over the version folder) and the staging folder's
  owner as written by SYSTEM were not executed. The release pipeline's service asset
  (`release.yml`) runs in CI only.
- p-svc-fix (14.11.2026, review svcupd): engine-only feed updates reach Tunnel mode with the next
  release's `Take` (the service no longer checks by itself). `swap::probe` ran against a non-exe
  and the test binary (refused), never against a real service build; a crash inside the SCM
  dispatch of a fresh exe (before `service::run`) still never counts a trial start; the
  installer's `request-install` repairs it (`per_user::is_current` treats an unsettled
  `update\swap.json` as "not current", p-follow3).
