# vpnte-service — API

The helper service `vpnte-service.exe` (Windows service `VpnTunnelEnforcerService`, LocalSystem,
automatic start) and the library parts the app uses to talk to it. The service hosts the
privileged half of the tunnel — `vpnte_tunnel::runtime` with `TunCapture`, `RealEngines` and the
WFP `Protection` — behind one named pipe; the unelevated app drives it. Proxy mode (Soft) stays
in the app and never needs the service. Depends on `vpnte-base`, `-winnet`, `-profiles`,
`-engine`, `-tunnel`; new external dependency: none (`ring` for Ed25519 is already in the
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
| `host` | the session host: one runtime + kill switch, one controlling client, state changes in arrival order, events, client-gone stop |
| `users` | Windows users (SIDs) of the service: the installing user and each user's first `Hello`; the last `ForgetMe` removes the service |
| `scm` | `scm::manage` (create / configure / start / stop / delete, installed binary path), `scm::dispatch` (running under the SCM) |
| `install` | `install` / `uninstall` (elevated verbs), `remove_self`, `install::image` (the running exe through a locked handle), `install::pins` (SHA-256 against `resources/engines.toml`) |
| `paths` | service name, `%ProgramFiles%\VPN Tunnel Enforcer Service\`, `%ProgramData%\VPN Tunnel Enforcer\` with its private `service\` part (`DataFiles`), `secure_dir` |
| `service` | the service body (`run`): logging, WFP start-up, runtime, host, sandbox, graceful stop; `trusted_install` / `FolderFault` |
| `watchdog` | `Engaged` (a capture that records whether a session's filters are held) and `run` (the WFP watchdog exactly while they are) |
| `sandbox` | engines may not start programs: each engine process in a nested job with `ActiveProcessLimit = 1` |
| `update` | signed self-update hook: `verify(package, signature)` with `PUBLIC_KEY` (all zero = not set: refuses) |
| `LOCALES` | `&[(ru_json, en_json)]`, keys under `service.*` |

## Binary verbs
```
vpnte-service run                          # the SCM's command line ("<exe>" run); not for people
vpnte-service install [--resources <dir>]  # elevated: copy + pin-check + register + start
vpnte-service uninstall                    # elevated: stop + delete + WFP objects + folders
```
Exit codes 0 / 1 (reason on stderr, English) / 2 (usage). `install` copies this exe and
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
failures) and started. `uninstall` disables, stops, deletes (a service already marked for
deletion counts as deleted), removes our WFP objects and both folders; it tries every step and
reports the first failure, so a rerun finishes what is left. Folders come from
`SHGetKnownFolderPath`, never from environment variables.

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
Event { event }}`. `PROTOCOL = 1`; `negotiate(client, service)` = the lower one while they differ
by at most one. Evolution: add requests / replies / events / optional fields only; the newer
side speaks the negotiated version; structs refuse unknown fields.
```rust
pub enum Request { Hello(Hello), Start(Box<TunnelStart>), Stop(StopTunnel), Restart(Box<TunnelStart>),
    RestartWithLast { reason: String }, RestartAdaptive(Box<AdaptiveRestart>), Switch(Box<TunnelStart>),
    Inputs(Box<RoutingInputs>), Status, KillSwitch(Box<ProtectionSettings>), Cleanup, ForgetMe }
pub struct Hello { pub protocol: u32, pub app_version: String }
pub struct TunnelStart { pub upstream: Upstream, pub routing: RoutingInputs,
    pub protection: ProtectionSettings, pub adaptive: AdaptiveMode, pub engine: EnginePref, pub origin: Origin }
pub enum Upstream { LocalProxy { addr: SocketAddr /* loopback */, kind: ProxyKind }, Server(Box<ServerUpstream>) }
pub struct ServerUpstream { pub id: String, pub profile: Profile, pub device: Option<ClientDevice>, pub engine: EnginePref }
pub struct RoutingInputs { smart_ru, smart_ru_maps_direct, domain_rules: Vec<DomainRule>, split_direct,
    split_vpn: Vec<String> /* process_path_regex */, dns: Option<DnsAddr>, public_wifi, stealth,
    auto_restart_on_crash }   // no rule-set dir (the service's own pinned .srs), no inactive splits
pub enum Reply { Welcome { protocol, service_version }, Started(Option<StartReceiptWire>),
    Stopped(StopReceiptWire), Switched(Option<SwitchReceiptWire>), Status(Box<StatusReply>),
    Done { removing: bool }, Cleaned { filters, sublayer, provider } }
pub struct StatusReply { pub tunnel: StatusWire /* with SessionWire: Clash secret, proxy creds */,
    pub last_exit: Option<ExitWire>, pub recent_fault: Option<OutboundFault>, pub protection: ProtectionWire }
pub enum Event { Status(Box<StatusWire>), Tunnel(TunnelEventWire), Notice(Notice) }
pub struct WireError { pub code: ErrorCode, pub kind: ErrorKind, pub msg: Msg, pub warnings: Vec<Msg> }
pub enum ErrorCode { Busy, Version, HelloFirst, BadRequest, Refused, Failed }
```
Wire mirrors convert from the runtime's types and back where the app needs them
(`TunnelEvent`, `TunStatusKind`, `StopReceipt`, `ExitInfo`, `ProxyEndpoint`).
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
`ServerCheck::Image` compares the pipe server's process image (`GetNamedPipeServerProcessId`) with
the SCM's binary path: a pipe someone else created is refused before anything is sent
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
- The session belongs to the connection: client gone -> start / switch in flight cancelled,
  kill-switch changes already asked for finished, then `stop(preserve_protection = level in
  force == strict)`: only "Always" in force keeps its block. A stored `strict` works as "If the
  VPN drops" until `Protection::set_always_available(true)` (package ks-d; false today). Service
  STOP / shutdown -> the same stop, the dynamic WFP session closed. The runtime's last exit and
  recent fault go only to the user whose start they came from.
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
  `users.json`, `protection.json`, `service.log` rotated at 1 MiB), each re-created when it is
  missing or user-writable.
- Users: the elevated `install` records the user of its Windows session, and a user is recorded
  at his first `Hello` (he may use a service another account installed). `ForgetMe` (per-user
  uninstaller; first frame or after `Hello`, no controller slot needed) removes the caller's SID
  and every account Windows no longer knows; a failed save changes nothing (a retry repeats it).
  The last user leaving makes the service delete its registration, our WFP objects, its engine
  files and data, then stop. What is in use (the running exe, the open service log) is renamed
  to `<name>.<time>.deleted`, and only that tombstone, then the emptied folders, are queued for
  deletion at the next restart (`MOVEFILE_DELAY_UNTIL_REBOOT`): a reinstall before that restart
  keeps its files (Windows never deletes a folder that is not empty).
- The WFP watchdog (re-applies the filters after a BFE restart) runs while the kill switch holds
  a session's filters: from a successful `begin` to a successful `release` of the capture, so an
  engine crash, a preserved stop and "kill switch active" stay watched; an idle service has no
  timer.
- Signed self-update: only the hook (`update::verify`, Ed25519 over the whole package,
  `PUBLIC_KEY` constant to fill in; all zero refuses everything with `service.update.keyNotSet`).

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

## i18n keys (`locales/svc-core.*.json`, all under `service.`)
| Keys | Args | Emitted by |
| --- | --- | --- |
| `service.pipe.{busy,busySelf,version,helloFirst,badRequest}` | — | `WireError` of the first request |
| `service.pipe.{unavailable,denied,noAnswer,notOurs}` | — | `pipe::client::Client::connect` |
| `service.pipe.{lost,badReply,tooLarge}` | — | `pipe::client::Client` calls |
| `service.refused.{tooLong,tooMany,text}` | `field` | `validate` |
| `service.refused.localProxy` | — | `validate::start` |
| `service.folder.untrusted` / `service.folder.fileMissing` | — / `file` | `service::FolderFault::msg` (refused starts) |
| `service.update.{keyNotSet,badSignature}` | — | `update::UpdateError` |
| `service.install.{notElevated,imageChanged,failed}`, `service.install.{fileMissing,fileMismatch}` | — / `file` | `install` |

## Not implemented / not run
- Not run here (the shell is not elevated): the SCM paths, `install` / `uninstall`, WFP and the
  real TUN session. CI covers them (`cargo test -p vpnte-service -- --ignored elevated_`):
  `tests/elevated.rs::elevated_install_tun_session_and_uninstall_leave_nothing` (install, pipe,
  TUN session, upgrade over the running service, uninstall twice),
  `install::tests::elevated_the_restart_queue_gets_the_tombstone_not_the_exe`,
  `sddl::tests::elevated_the_private_folder_grants_users_nothing`,
  `sddl::tests::elevated_installed_files_pass_the_trusted_folder_check`. Never run anywhere: the
  watchdog re-applying filters after a real BFE restart (the gate is unit-tested).
- Not built (phase 2 / later): the app's `RemoteRuntime` over `Client`, installer verbs and the
  HKLM uninstall entry, the persistent Wintun adapter (research §5), the signed-update flow
  beyond the hook, failover / confirmation seams over the pipe (`None` in the service), a
  non-admin squatting test (the DACL mask is unit-tested).
- Smart RU in the service uses the bundled, pinned rule sets, not the app's refreshed copies.
