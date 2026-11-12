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
| `validate` | refuses what a SYSTEM engine must not get (provider sing-box keys outside the allow-list, non-loopback proxies, oversize text / lists, bad exceptions) |
| `sddl` | pipe / service / folder security descriptors, `path_admin_only` (trusted-folder check) |
| `host` | the session host: one runtime + kill switch, one controlling client, events, client-gone stop |
| `users` | Windows users (SIDs) of the service; the last `ForgetMe` removes the service |
| `scm` | `scm::manage` (create / configure / start / stop / delete, installed binary path), `scm::dispatch` (running under the SCM) |
| `install` | `install` / `uninstall` (elevated verbs), `remove_self`, `install::pins` (SHA-256 against `resources/engines.toml`) |
| `paths` | service name, `%ProgramFiles%\VPN Tunnel Enforcer Service\`, `%ProgramData%\VPN Tunnel Enforcer\`, `secure_dir` |
| `service` | the service body (`run`): logging, WFP start-up, runtime, host, sandbox, graceful stop |
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
`%ProgramFiles%\VPN Tunnel Enforcer Service\`, each engine file read once, hashed and written
from the same buffer (`service.install.fileMismatch(file)` / `fileMissing(file)`), sets the folder
DACL `ADMIN_ONLY_DIR_SDDL` (owner Administrators; SYSTEM / Administrators full, Users read),
secures the data folder, creates or updates the service (LocalSystem, `SERVICE_AUTO_START`,
quoted command line, unrestricted service SID, `SERVICE_SDDL`, recovery restart 5 s / 10 s / 60 s
reset after a day, also on non-crash failures) and starts it. An existing service is stopped
first (upgrade). Folders come from `SHGetKnownFolderPath`, never from environment variables.

## Protocol (`proto`)
Frame = 4-byte little-endian length + JSON, `1..=MAX_FRAME` (4 MiB) bytes. Client ->
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
toggles, exceptions; persisted for `strict` at boot) and replaces the routing inputs. The capture
is always `Tun`. Events of an operation are sent before its reply; a changed status is sent
before the tunnel event that goes with it; a lagged stream resends the status.

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
(`service.pipe.notOurs`). A missing service reads as `service.pipe.unavailable`.

## Security model (research `service.md` §3; owner decisions of 12.11.2026)
- Pipe `\\.\pipe\ProtectedPrefix\Administrators\VpnTunnelEnforcer\Service` (only admins /
  SYSTEM can create it), `PIPE_SDDL = D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)` (users read /
  write without `FILE_CREATE_PIPE_INSTANCE`), `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`. Client identity = pid, session, token SID (impersonation at
  identification level after the first frame); `HostDeps::check` is the verification hook
  (`admit_all` by default: the boundary is the typed protocol, not the caller's image).
- One controlling client; others get `Busy` (`service.pipe.busy`). The session belongs to the
  connection: client gone -> start / switch in flight cancelled, `stop(preserve_protection =
  level == strict)`. Service STOP / shutdown -> the same stop, the dynamic WFP session closed.
- Typed input only (`validate`); engine configs are built inside by the runtime; logs go to the
  data folder; engines run from the admin-only folder, pinned (the engine crate's elevated pin
  check) and each in its kill-on-close job (engine crate). `sandbox` confines every engine
  process of the folder in a nested job of its own with `ActiveProcessLimit = 1` (it cannot start
  programs; a seat belt: confinement follows the engine's start by a moment), swept on every
  runtime status change / event and every 10 s while a session runs.
- Tunnel refused (`service.folder.untrusted`) when the service folder, its exe or any engine file
  is writable by non-admins (`sddl::path_admin_only`: owner and every non-inherit-only allow ACE
  with write rights must be SYSTEM / Administrators / TrustedInstaller).
- Data folder `%ProgramData%\VPN Tunnel Enforcer\` (`logs\`, `users.json`, `protection.json`,
  `service.log` rotated at 1 MiB) is re-created admin-only when it is missing or user-writable.
- `ForgetMe` (per-user uninstaller) removes the caller's SID; the last one makes the service
  delete its registration, our WFP objects, its engine files and data, and queue the running exe
  and its folder for deletion at the next restart (`MOVEFILE_DELAY_UNTIL_REBOOT`), then stop.
- Signed self-update: only the hook (`update::verify`, Ed25519 over the whole package,
  `PUBLIC_KEY` constant to fill in; all zero refuses everything with `service.update.keyNotSet`).

## Idle footprint (measured 12.11.2026, `examples/idle.rs`, this machine)
Current-thread runtime; the listener waits in an overlapped `ConnectNamedPipe`, the runtime actor
on its inbox, the WFP watchdog runs only while a session runs. Real runtime (`RealEngines`, no
TUN) + host behind a private pipe, unelevated, measured after 12 s of settling:
- release build, 30 s idle: working set 8.9 MB, private bytes 1.6 MB, CPU 0 ms;
- debug build, 20 s idle: working set 10.5 MB, private bytes 1.6 MB, CPU 0 ms.
Most of the working set is shared image / system DLL pages that Windows trims from an idle
service; private memory is what the service itself holds (Happ's service, measured the same day:
8.8 MB working set, 9.5 MB private). Not measured: the installed service under the SCM (needs
elevation) — it adds the WFP engine handle and the SCM thread, no timer.

## i18n keys (`locales/svc-core.*.json`, all under `service.`)
| Keys | Args | Emitted by |
| --- | --- | --- |
| `service.pipe.{busy,version,helloFirst,badRequest}` | — | `WireError` of the first request |
| `service.pipe.{unavailable,notOurs}` | — | `pipe::client::Client::connect` |
| `service.refused.{tooLong,tooMany,text}` | `field` | `validate` |
| `service.refused.localProxy` | — | `validate::start` |
| `service.folder.untrusted` | — | `host::untrusted_folder` (refused starts) |
| `service.update.{keyNotSet,badSignature}` | — | `update::UpdateError` |
| `service.install.{notElevated,failed}`, `service.install.{fileMissing,fileMismatch}` | — / `file` | `install` |

## Not implemented / not run
- Not run here (the shell is not elevated): the SCM paths, `install` / `uninstall`, WFP and the
  real TUN session. `tests/elevated.rs::elevated_install_tun_session_and_uninstall_leave_nothing`
  covers them on CI (`cargo test -p vpnte-service -- --ignored elevated_`).
- Not built (phase 2 / later): the app's `RemoteRuntime` over `Client`, installer verbs and the
  HKLM uninstall entry, the persistent Wintun adapter (research §5), the signed-update flow
  beyond the hook, failover / confirmation seams over the pipe (`None` in the service), a
  non-admin squatting test (the DACL mask is unit-tested).
- Smart RU in the service uses the bundled, pinned rule sets, not the app's refreshed copies.
