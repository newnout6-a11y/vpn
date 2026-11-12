# vpnte-view — API

Pure start-page logic without a webview: the connection projection and big-word state machine,
labels as `Msg`, identity-column rules, traffic maths, text formatting and the mascot's behaviour
machine. No I/O, no clock reads, no threads, no elevation: callers pass every fact and every
`Instant` / `UnixMs`. View types are plain data (`Debug + Clone + PartialEq`, `Eq` unless they hold
a float; every enum is `Copy`); `MascotBrain` is `Clone + Debug`. Depends only on `vpnte-base` (+
`fastrand` for the mascot's RNG: pass the workspace `fastrand::Rng`).

Paths: `vpnte_view::{swiss, labels, identity, traffic, fmt, mascot}`, plus `vpnte_view::MascotPhase`
and `vpnte_view::LOCALES` at the root. Shared types used below: `vpnte_base::Msg`,
`vpnte_base::types::{Verdict, UnixMs}`, `std::time::{Instant, Duration}`, `std::net::IpAddr`.

## Locales (register before the UI starts)
```rust
pub const LOCALES: &[(&str, &str)];   // (ru_json, en_json) per fragment of this crate
vpnte_ui::lang::init_locales(vpnte_view::LOCALES);   // app (with the other backend layers) and every
                                                     // demo binary that renders view Msgs, BEFORE launch()
```
`launch()` calls `init_locales(&[])` itself and later calls are ignored, so a demo that skips this
shows raw `view.*` keys. Every `Msg` this crate returns is rendered with `vpnte_ui::lang::tr(&msg)`;
its keys come from the UI base layer (`dashboard.*`, `swiss.*`, `mascot.*`, the old app's strings)
or from `view.*` (this crate's fragment). Tests pin that every emitted key exists in ru and en and
that every `{{placeholder}}` is supplied.

| Keys | Arguments |
| --- | --- |
| `dashboard.swissWord{Cancel,Switch,Linking,Closing,Restart,Leak,Alert,Blocked,Degraded,Verify,Secure,Exposed}` | — (Latin in both languages) |
| `dashboard.switchingServer` | `name` |
| `view.status.degradedTun` | `name` |
| `view.identity.{country,countryCity}` | `country`, `city` |
| `view.identity.ping` / `view.identity.metaPing` | `ms` / `protocol` (upper-cased), `ms` |
| `view.identity.{metaOffline,metaUnchecked}` | `protocol` |
| `swiss.minAgo` | `n` |
| `view.traffic.hover` | `mbps`, `n` |
| `mascot.speed` / `mascot.slow` | `mbps` |
| `mascot.milestoneMin` / `mascot.milestoneHour` | `minutes` / `hours` |
| everything else | none |

Strings the UI shows on its own (column captions, the `swiss.smartPending` tooltip, …) stay `t!`.

## `swiss` — connection projection, big word, FitWord, ruler
```rust
pub enum TunnelState { Disconnected /*default*/, Connected, Error, Blocked, Unknown }
pub enum Transition { Connecting, Disconnecting, Reconnecting }
pub enum Mode { Tun, Soft }
pub enum Busy { Connecting, Disconnecting }
pub struct OpWindow { pub started: Instant, pub deadline: Option<Instant> }
#[derive(Default)]
pub struct ConnView {                 // the app projects the tunnel lifecycle snapshot into this
    pub state: TunnelState, pub transition: Option<Transition>, pub mode: Option<Mode>,
    pub cancelling: bool,             // user asked to cancel a connect / switch
    pub switching: Option<String>,    // target server name of a switch
    pub restarting: Option<(u8, u8)>, // auto-restart (attempt, max)
    pub degraded: bool, pub competing_tun: Option<String>,
    pub proxy_down: bool,             // published by the backend (D-23), no UI heuristic
    pub cleanup_required: bool,       // something of ours is installed -> power button = "turn off"
    pub started_at: Option<UnixMs>, pub operation: Option<OpWindow>,
}
impl ConnView {
    pub fn busy(&self) -> Option<Busy>;          // cancelling -> Disconnecting; restart -> Connecting
    pub fn connecting(&self) -> bool;  pub fn disconnecting(&self) -> bool;
    pub fn connected(&self) -> bool;             // Connected and no transition
    pub fn circle_busy(&self) -> bool;           // busy or switching (power button waits)
    pub fn swiss_busy(&self) -> bool;            // anything transient on the slab
    pub fn tun_running(&self) -> bool;  pub fn tun_started_at(&self) -> Option<UnixMs>;
    pub fn uptime_since(&self) -> Option<UnixMs>;            // settled TUN session only: the label
                                                             // says «в туннеле», Soft must not claim it
    pub fn degraded_any(&self) -> bool;                      // degraded || competing TUN
    pub fn competing_tun_banner(&self) -> Option<&str>;      // only while our TUN runs
}
#[derive(Default)]
pub struct SwissInput { pub cancelling: bool, pub switching: bool, pub connecting: bool,
    pub disconnecting: bool, pub restarting: bool, pub connected: bool, pub leak: bool,
    pub tunnel_state: TunnelState, pub proxy_down: bool, pub degraded: bool, pub verdict: Verdict }
impl SwissInput { pub fn new(conn: &ConnView, exit: &ExitIp) -> Self }
pub enum SwissState { Cancel, Switch, Linking, Closing, Restart, Leak, Alert, Blocked, Degraded,
    Verify, Secure, Exposed }
pub fn derive_swiss_state(i: &SwissInput) -> SwissState;
impl SwissState {
    pub fn word(self) -> Msg;         // big word
    pub fn is_alert(self) -> bool;    // .is-alert (Leak, Alert, Blocked, Degraded)
    pub fn is_on(self) -> bool;       // .is-on (Secure only)
}
pub fn swiss_phase(state: SwissState, busy: bool) -> MascotPhase;   // busy = conn.swiss_busy()
pub const WORD_MAX_PX: f64 = 150.0;  pub const WORD_MIN_PX: f64 = 40.0;
pub const WORD_HEIGHT_SHARE: f64 = 0.15;  pub const WORD_INITIAL_PX: f64 = 96.0;
pub fn fit_word(probe_px: f64, box_px: f64, window_h: f64, current: Option<f64>) -> Option<f64>;
    // probe_px = word width at 100 px; keeps `current` when not laid out or within 0.5 px
pub const RULER_CELLS: u8 = 10;
pub struct Ruler { pub lit: u8, pub indeterminate: bool }            // Default = empty
pub fn ruler(op: Option<&OpWindow>, busy: bool, now: Instant) -> Ruler;
```

## `MascotPhase` (root; also `mascot::MascotPhase`)
```rust
pub enum MascotPhase { On, Off, Connecting, Alert }
    // On = SECURE / VERIFY; Alert = LEAK / ALERT / BLOCKED / DEGRADED (a faulted tunnel alerts even
    // when it is not up); Connecting = anything in flight (conn.swiss_busy()); Off = EXPOSED
```
One type: `swiss::swiss_phase` produces it, `mascot::MascotEvent::Phase` consumes it.

## `identity` — exit IP, home IP, ping and best server
```rust
#[derive(Default)]
pub struct Geo { pub country: Option<String>, pub city: Option<String> }
#[derive(Default)]
pub struct ExitIp {                    // from the IP monitor
    pub ip: Option<IpAddr>,            // public address right now
    pub vpn_ip: Option<IpAddr>,        // confirmed tunnel exit
    pub verdict: Verdict,              // Ok = passed, Warn = changed/unverified, Fail, NotChecked
    pub leak: bool,
    pub geo: Option<(IpAddr, Geo)>,    // keyed by the IP it was looked up for
}
impl ExitIp { pub fn current_geo(&self) -> Option<&Geo> }   // only if keyed to `ip`
pub fn visible_leak(conn: &ConnView, exit: &ExitIp) -> bool;   // no leak shown mid-switch
pub struct HomeIp { .. }               // the real address, memory only (never persist it); Default = new()
impl HomeIp {
    pub fn new() -> Self;  pub fn get(&self) -> Option<IpAddr>;
    pub fn observe(&mut self, conn: &ConnView, exit: &ExitIp) -> Option<IpAddr>;  // idempotent
}
pub enum ServerHealth { Online, Offline, Unknown /*default*/ }
pub enum LocalPing { Pinging, Done(Option<u32>) }           // a ping run from the servers panel
pub fn ping_of(local: Option<LocalPing>, ping: Option<u32>, health_latency: Option<u32>) -> Option<u32>;
pub fn best_index(rows: impl IntoIterator<Item = (Option<u32>, ServerHealth)>) -> Option<usize>;
    // lowest ping among non-offline rows, ties -> first
```

## `labels` — every start-page text as `Msg`
```rust
pub fn status_label(conn: &ConnView) -> Msg;   // caption (role=status), power text while busy
pub enum PowerLook { Plain, On, Switching, Cancelling }       // "" / .is-on / .is-busy / .is-cancel
pub struct PowerButton { pub label: Msg /*text = accessible name*/, pub title: Msg,
    pub look: PowerLook, pub waiting: bool /*.is-wait, disabled*/ }
pub fn power_button(conn: &ConnView) -> PowerButton;
pub fn cancel_label(conn: &ConnView) -> Option<Msg>;          // None = no cancel button
pub struct FactValue { pub text: Msg, pub alert: bool, pub dim: bool }
pub fn mode_fact(soft: bool) -> FactValue;                    // view.fact.modeProxy / modeTunnel
pub struct SmartFact { pub value: FactValue, pub action: Msg, pub action_aria: Msg }
pub fn smart_fact(on: bool) -> SmartFact;
pub enum FwState { Verified, Inactive, Unknown,
    ProxyHold,    // no WFP in this process, level standard: Soft's system-proxy hold «Через прокси»
    NeedsAdmin }  // the level needs WFP, which an unelevated process cannot host (alert)
pub struct FirewallStatus { pub state: FwState, pub checking: bool }   // Default = Unknown, checking
impl FirewallStatus { pub fn in_mode(self, soft: bool) -> Self }       // ProxyHold in Hard -> NeedsAdmin
pub fn kill_switch_fact(fw: &FirewallStatus) -> FactValue;             // alert: Unknown / NeedsAdmin
pub fn leak_fact(summary: Verdict, checking: bool) -> FactValue;       // NotChecked -> «—», dim
pub struct SubLine { pub text: Msg, pub dash: bool /*«— » prefix*/, pub alert: bool,
    pub flag: Option<String> /*country for the flag coin*/ }
pub struct ExitLine { pub ip: Option<IpAddr> /*None -> dim «—»*/, pub dim: bool,
    pub unmeasured: bool /*settled off, no address yet: «ещё не определён»*/, pub sub: SubLine }
pub fn exit_line(conn: &ConnView, exit: &ExitIp) -> ExitLine;
pub enum RealLook { Hidden /*struck*/, Exposed /*«открыт всем»*/, Neutral /*dim: busy or faulted*/ }
pub struct RealLine { pub ip: Option<IpAddr>, pub look: RealLook }
impl RealLine { pub fn struck(&self) -> bool /*.is-hidden*/; pub fn sub(&self) -> Option<SubLine>;
    pub fn unmeasured(&self) -> bool /*Exposed without an address*/ }
pub fn real_line(conn: &ConnView, exit: &ExitIp, home: Option<IpAddr>) -> RealLine;
pub fn node_meta(protocol: Option<&str>, ping: Option<u32>, health: ServerHealth) -> Msg;
pub fn health_label(health: ServerHealth, minutes_ago: Option<u64>) -> Msg;
pub struct KillSwitchBanner { pub title: Msg, pub body: Msg }
pub fn kill_switch_banner(conn: &ConnView, fw: &FirewallStatus) -> Option<KillSwitchBanner>;
    // Verified / Unknown only, settled, no TUN running (ProxyHold / NeedsAdmin install no filters)
pub fn foreign_vpn_friendly_name(raw: Option<&str>) -> Option<String>;  // "happ-tun (…)" -> "Happ"
```

## `traffic` — traffic panel maths and the speed band
```rust
pub const HISTORY: usize = 48;  pub const SCALE_FLOOR_MBPS: f64 = 10.0;  pub const MIN_BAR_PCT: f64 = 4.0;
#[derive(Default)]
pub struct TrafficSample { pub ts: UnixMs, pub running: bool, pub download_bps: f64,
    pub upload_bps: f64, pub smoothed_download_bps: f64, pub smoothed_upload_bps: f64,
    pub session_download_bytes: u64, pub started_at: Option<UnixMs> }   // bytes/s, once a second
impl TrafficSample { pub fn down_bps(&self) -> f64; pub fn up_bps(&self) -> f64;   // smoothed || raw
    pub fn down_mbps(&self) -> f64; pub fn up_mbps(&self) -> f64; pub fn session_gb(&self) -> f64 }
pub fn to_mbps(bps: f64) -> f64;
pub fn speed_band(down_bps: f64) -> f32;   // >= 75 Mbit/s: 10 Mbit/s steps; 0.3–3: 0.5 steps; else 0
pub struct Bar { pub height_pct: f64, pub off: bool, pub hot: bool, pub faded: bool }
pub struct TrafficHistory { .. }           // Default = new()
impl TrafficHistory {
    pub fn new() -> Self;
    pub fn observe(&mut self, s: &TrafficSample) -> bool;   // true = bars changed; new started_at clears
    pub fn samples(&self) -> impl ExactSizeIterator<Item = f64> + '_;   // Mbit/s, oldest first
    pub fn scale_max(&self) -> f64;
    pub fn bars(&self, running: bool, hover: Option<usize>) -> Vec<Bar>;
    pub fn hover_msg(&self, i: usize) -> Option<Msg>;       // "{mbps} Mbit/s · {n} s ago"
}
```

## `fmt` — text helpers
```rust
pub fn to_fixed(v: f64, digits: usize) -> String;   // JS toFixed parity (ties away from zero)
pub fn format_uptime(d: Duration) -> String;        // HH:MM:SS, hours not wrapped
pub fn elapsed(since: UnixMs, now: UnixMs) -> Duration;   // saturating
pub fn minutes_ago(ts: Option<UnixMs>, now: UnixMs) -> Option<u64>;   // 0 / None = never checked
```
(The sidebar clock is `vpnte_ui::shell`'s own; this crate has no clock helpers.)

## `mascot` — «Пломбик»'s behaviour machine
```rust
pub const LABEL_KEY: &str = "mascot.name";           // aria-label / title of the mascot button
pub use crate::MascotPhase;
pub enum Mood { Calm, Worried, Scan, Happy, Love, Squint, Think, Dizzy, Wink, Excited, Sleep, Scared, Petted }
pub enum Fx { Confetti, Zzz, Dots, Sweat, Speed, Hearts }
pub enum BodyAnim { None /*default*/, Jump, Shake, Spin, Lean, Startle }
pub enum Perch { Home /*default*/, Toggle, Clock, Servers, Proxies, Leak, Smart }
impl Mood { pub fn as_str(self) -> &'static str }      // "calm", "petted", …
impl Fx { pub fn as_str(self) -> &'static str }        // "confetti", "zzz", …
impl BodyAnim { pub fn class(self) -> &'static str }   // "" | "m-jump" | "m-shake" | "m-spin" | "m-lean" | "m-startle"
impl Perch { pub fn as_str(self) -> &'static str }     // data-perch value: "home", "toggle", …
pub struct Speech { pub id: u32 /*key the bubble on it*/, pub msg: Msg, pub announce: bool /*aria-live*/ }
pub struct MascotView { pub mood: Mood, pub fx: Option<Fx>, pub fx_id: u32 /*replay on change*/,
    pub body: BodyAnim, pub body_id: u32 /*replay on change*/, pub speech: Option<Speech> }
pub enum MascotEvent {                                 // Copy + PartialEq
    Phase(MascotPhase),          // swiss_phase(..); only a change does something
    SpeedBand(f32),              // traffic::speed_band(sample.down_bps()); repeats are ignored
    SessionAge(Option<Duration>),// on a new conn.started_at: Some(fmt::elapsed(t, now_ms())), None = no session
    Activity { on_mascot: bool },// window mousemove/mousedown/keydown/wheel; target inside [data-mascot]
    Visible(bool),               // window shown / hidden (minimised, tray)
    PageActive(bool),            // the dashboard is / is not the active page
    ThemeDark(bool),             // resolved theme; the first value is only recorded
    HoverIn, HoverOut,           // pointer over the power button
    LeakStart, LeakOk, LeakWarn, LeakFail,   // leak check started / its verdict
    SmartOn, SmartOff,           // Smart RU saved on / off
    ProxyStart, ProxyRotate, ProxyStop, ProxyStopAll,   // external-proxy column actions
    NoticeError, NoticeWarn, NoticeOk,                  // a new notification (not info)
    Poke,                        // click / Enter / Space on the mascot button
    Pet,                         // a stroke over him (detected by the markup)
    GoHome,                      // the stage cannot place him on the current perch
}
pub struct MascotBrain { .. }    // Clone + Debug
impl MascotBrain {
    pub fn new(now: Instant, phase: MascotPhase, time_of_day: Option<Duration>, rng: &mut fastrand::Rng) -> Self;
        // time_of_day = local time since midnight while this app session has not greeted, else None
    pub fn handle(&mut self, ev: MascotEvent, now: Instant, rng: &mut fastrand::Rng);
    pub fn tick(&mut self, now: Instant, rng: &mut fastrand::Rng);   // fires every deadline <= now
    pub fn next_deadline(&self) -> Option<Instant>;                  // None while paused
    pub fn view(&self) -> MascotView;
    pub fn perch(&self) -> Perch;
}
```
The brain is paused while the window is hidden or another page is active (no deadline, timers
frozen and shifted on return, ambient reactions dropped). Geometry stays in the UI: finding the
`data-perch` target, the hop, `Excited` while airborne, the body palette by surface.

Host contract: `new` assumes the window is shown and the dashboard active, so after a start in
the tray send `Visible(false)` right after `new` (and `PageActive(false)` when another page opens
first); the greeting then waits until he is first shown. Send `SessionAge` only when
`conn.started_at` changes: a re-send restarts the 10-minute count, and one that lands just after a
mark the brain has not ticked yet skips that milestone.

## Main flows
Start page (one render pass; inputs `conn: ConnView`, `exit: ExitIp`, `sample: TrafficSample`,
`firewall: FirewallStatus`, `hovered: Option<usize>`; page state `home: HomeIp`,
`history: TrafficHistory`):
```rust
use vpnte_base::types::now_ms;
use vpnte_view::{fmt, labels, mascot::MascotEvent, swiss, traffic};
let state = swiss::derive_swiss_state(&swiss::SwissInput::new(&conn, &exit));
let busy = conn.swiss_busy();                       // stripes, busy dot, neutral identity column
let (word, on, alert) = (state.word(), state.is_on(), state.is_alert());
let caption = labels::status_label(&conn);
let uptime = conn.uptime_since().map(|t| fmt::format_uptime(fmt::elapsed(t, now_ms())));
let ruler = swiss::ruler(conn.operation.as_ref(), busy, Instant::now());
let power = labels::power_button(&conn);
let exit_line = labels::exit_line(&conn, &exit);
let real = labels::real_line(&conn, &exit, home.observe(&conn, &exit));
let banner = labels::kill_switch_banner(&conn, &firewall);
let ks_fact = labels::kill_switch_fact(&firewall.in_mode(soft));   // soft = routing setting is Soft
history.observe(&sample);                           // every sample
let bars = history.bars(sample.running, hovered);
let figure = fmt::to_fixed(sample.down_mbps(), 1);
// to the mascot host's event channel (ui-mascot):
mascot_bus.send(MascotEvent::Phase(swiss::swiss_phase(state, busy)));
mascot_bus.send(MascotEvent::SpeedBand(traffic::speed_band(sample.down_bps())));
```
Servers panel: `ping_of(local, row.ping, row.health_latency)` per row, `best_index(rows)`,
`node_meta(protocol, ping, health)`, `health_label(health, fmt::minutes_ago(checked_at, now_ms()))`.

Mascot host (one task owns the brain and the RNG; seed the RNG in tests):
```rust
use vpnte_view::mascot::{MascotBrain, MascotEvent};   // events: tokio mpsc Receiver<MascotEvent>
let mut rng = fastrand::Rng::new();
let mut brain = MascotBrain::new(Instant::now(), phase, time_of_day, &mut rng);
loop {
    let deadline = brain.next_deadline();
    let wake = async move {
        match deadline {
            Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        ev = events.recv() => match ev { Some(ev) => brain.handle(ev, Instant::now(), &mut rng), None => break },
        () = wake => brain.tick(Instant::now(), &mut rng),
    }
    view.set(brain.view());   // render; hop to brain.perch()
    perch.set(brain.perch());
}
```

## What the app fills
- `ConnView` from the tunnel lifecycle snapshot (`started_at` as `UnixMs`, `operation` as
  `Instant`s, `proxy_down` / `degraded` / `competing_tun` / `cleanup_required` as published).
- `ExitIp` from the IP monitor (geo keyed by the IP it was looked up for).
- `TrafficSample` once a second (the hover read-out's "N s ago" assumes 1 s sampling).
- `FirewallStatus` from the kill-switch read-back; `Verdict` summary of the last leak check.

## Not here / not implemented
- No elevation, network, persistence or clock access anywhere in this crate: nothing here needs
  admin rights or a running backend, and the unit tests (67) exercise it without either.
- The external-proxy refresh interval (spec §7.4) belongs to the UI panels package.
- Not ported on purpose: the unreachable «Перезапуск N/M» caption, the old traffic heuristic for
  "proxy down" (the backend publishes `proxy_down`), `FirewallStatus` reason strings, the dead
  `mascot.wanderLogs` line, the kill-switch banner suppression timer (D-28), the 5 s milestone
  poll (the brain arms the exact next 10-minute mark).
- The signatures above replace the spec's §6 sketch where they differ: the shared `Verdict`,
  `Msg` instead of translated strings, `ConnView` / `ExitIp` taken whole (`busy` derived, not
  stored), `UnixMs` instead of `SystemTime`; for the mascot `SessionAge(Option<Duration>)`
  instead of `StartedAt(Option<SystemTime>)` (the brain never reads a clock), the extra events
  `PageActive` / `GoHome`, `new(now, phase, time_of_day, rng)`, `&mut fastrand::Rng`, a typed
  `Perch`, `Speech { msg: Msg }`.
- Country detection from server names (spec `country::detect`) is `vpnte_profiles::countries`.
- Mascot stage geometry and animation are the UI's (JS helper in `crates/ui/assets/js/`).
