# vpnte-ui — API

Dioxus 0.7.10 desktop UI (WebView2): window frame, shell, the start page («Пломба»), the mascot, the
tray and every other page. The crate never calls backend crates: each page defines plain view-model
types and an `XxxApi` trait; the app (`vpnte-app`) implements the traits over the backend and hands
them to the UI as contexts. Depends on `vpnte-base` and `vpnte-view` only. Nothing in this crate needs
or requests elevation (the app runs as the user; see Elevation).

Module map (all public paths are `vpnte_ui::<module>::…`):

| Module | What | API trait / main component |
| --- | --- | --- |
| `assets`, `lang`, `theme`, `launch` | frame: embedded assets, i18n, theme, window + WebView2 | `launch::launch` |
| `hooks` | `use_watch`: a `watch::Receiver` as a signal | — |
| `units` | `format_bytes`: the one byte-size format of every page | — |
| `pages`, `shell` | page ids, navigation, page registry, title strip + sidebar | `shell::Shell` |
| `widgets` | shared controls, `Toasts`, `JobSlot`, `Load<T>`, `UiError` | `widgets::ToastHost` |
| `dashboard` | start page | `DashboardApi` / `Dashboard` |
| `panels` | panel row of the start page (traffic, servers, external proxies) | `PanelsApi` / `SwissPanels` |
| `mascot` | «Пломбик» overlay and its event bus | `MascotHost`, `MascotBus` |
| `tray` | tray icon, menu, close / quit flow | `TrayApi` / `TrayHost` |
| `servers` | Servers page | `ServersApi` / `ServersPage` |
| `settings` | Settings page | `SettingsApi` / `SettingsPage` |
| `logs` | Logs page (history, journal viewer) | `LogsApi` / `LogsPage` |
| `availability`, `speedtest` | Availability and Speed test pages | `AvailabilityApi`, `SpeedTestApi` |
| `schedule`, `split_tunnel`, `traffic_history` | Schedule, Apps (split tunnel), Traffic history | `ScheduleApi`, `SplitTunnelApi`, `TrafficHistoryApi` |
| `maintenance` | Repair page (advanced mode) | `MaintenanceApi` / `MaintenancePage` |
| `wizard` | first-run wizard overlay | `WizardApi` / `Wizard` |

Root: `pub const LOCALES: &[(&str, &str)]` — this crate's locale fragments as `(ru_json, en_json)`,
one per work package in file-name order.

## Conventions shared by every `XxxApi`

```rust
#[async_trait::async_trait(?Send)]
pub trait XxxApi: 'static {
    fn state(&self) -> tokio::sync::watch::Receiver<XxxSnapshot>; // one Clone + PartialEq snapshot
    async fn action(&self, ...) -> vpnte_base::AppResult<T>;       // called from spawn / JobSlot
}
```
- Handed down as a root context `Rc<dyn XxxApi>`; components call `use_context::<Rc<dyn XxxApi>>()`.
- Pushed state: the page root subscribes once (`hooks::use_watch(|| api.state())`). Publish a change
  through the `watch::Sender` *before* the action that caused it returns.
- State-changing work runs in the backend's own task (`tokio::spawn`), so it completes even when the
  page is left while the call is pending; a dropped future must not cancel a mutation. Calls that take
  a `CancellationToken` stop when it fires and return `ErrorKind::Cancelled` (shown silently).
- Errors are `AppError` with a `Msg`; the UI renders `err.user_msg()` through the catalog and never
  formats backend text. View models hold display data only: never secrets, no Dioxus types.
- Every `XxxApi` has a demo implementation (`<module>::demo::Demo…` or `Demo…Api`) with realistic fake
  data and short delays, used by the `demo_*` binaries and the tests.

## Startup (the app's `main`)

```rust
// Only when the process happens to be elevated (development, CI), first thing in main: WebView2
// must not inherit the user's overrides. The shipped app never runs elevated.
unsafe { vpnte_ui::launch::scrub_webview2_env() };
// Once, BEFORE launch() (later calls are ignored). Built in first: the old app's catalog
// (assets/locales) and vpnte_ui::LOCALES; then these layers, later ones overriding earlier ones.
let mut layers = vec![(
    include_str!("../../base/locales/base.ru.json"),   // canonical errors.* texts of vpnte-base
    include_str!("../../base/locales/base.en.json"),
)];
layers.extend_from_slice(vpnte_view::LOCALES);          // + every backend crate's LOCALES
vpnte_ui::lang::init_locales(&layers);
let options = LaunchOptions {
    lang,                                  // stored language, else lang::os_lang()
    theme: Theme { mode, custom },         // stored theme: Palette::complete(mode, |k| colors.get(k)) for custom ones
    start_hidden,                          // autostart to tray
    data_dir,                              // default %LOCALAPPDATA%\VPN Tunnel Enforcer\WebView2; an elevated run needs its own folder
    ..LaunchOptions::default()             // title APP_NAME, 1100x720, min 860x600
};
launch(options, App, move || vec![        // never returns; contexts are built inside our tokio runtime
    Box::new(Rc::new(dashboard_api) as Rc<dyn DashboardApi>),
    Box::new(Rc::new(panels_api) as Rc<dyn PanelsApi>),
    // … one Rc<dyn XxxApi> per trait below, plus Rc<dyn TrayApi> …
]);
```
`launch` registers the UI locales itself if nobody did (safety net), shows a message box and exits
with code 3 when the WebView2 runtime is missing, runs a 4-worker tokio runtime (threads `backend`;
every Dioxus task stays on the main thread), and keeps `<html lang>`, `data-theme`, the palette and
the window background in sync with `lang::LANG` / `theme::THEME` / the OS theme.

`start_hidden` hides the WebView2 controller too and sets its memory level to Low at the first render
(as hiding to the tray does; wry creates the controller visible whatever the window is), so a start
in the tray never renders the page; `tray::show_window` restores both.

When the page's renderer process dies (`ProcessFailed`), the frame opens a stand-in page (the app's
page with `?recover`; a script registered at start acknowledges every edit batch there and never
announces the page). The VirtualDom keeps its tree and keeps running: the tray, Quit with its
cleanup and a second launch's activation work; the window stays empty until the app restarts (at
most 3 stand-ins per process). The page itself cannot be built again in dioxus-desktop 0.7.10 (its
template cache belongs to the dead page; see known gaps). A dead browser process is only logged;
helper processes are restarted by WebView2.

## The app's root component

```rust
fn App() -> Element {
    Toasts::use_provider();                                     // the app-wide toast queue
    use_mascot_bus_provider();                                  // optional: the dashboard provides one otherwise
    let advanced: Signal<bool> = /* settings: advanced mode, kept in sync with the store */;
    let registry = use_hook(|| {
        let mut r = PageRegistry::new();
        r.register(Page::Dashboard, dashboard::Dashboard)
            .register(Page::Apps, split_tunnel::SplitTunnelPage)
            .register(Page::Servers, servers::ServersPage)
            .register(Page::SpeedTest, speedtest::SpeedTestPage)
            .register(Page::Availability, availability::AvailabilityPage)
            .register(Page::TrafficHistory, traffic_history::TrafficHistoryPage)
            .register(Page::Schedule, schedule::SchedulePage)
            .register(Page::Logs, logs::LogsPage)
            .register(Page::Settings, settings::SettingsPage)
            .register(Page::Maintenance, maintenance::MaintenancePage);
        r
    });
    rsx! {
        TrayHost {                                              // tray icon, close / quit flow
            Shell {
                version: env!("CARGO_PKG_VERSION"), advanced, registry,
                overlays: rsx! { Wizard {} },                   // + the app's shutdown overlay, if any
                toasts: rsx! { ToastHost { close_label: t!("common.close") } },
            }
        }
    }
}
```
An unregistered page shows a neutral placeholder; a page whose render fails shows «Не удалось
показать страницу.» with «Повторить» while the shell stays usable. `Page::Maintenance` is reachable
only while `advanced` is true; switching it off leaves Maintenance for the Dashboard and unmounts it
(the next visit starts fresh). `TrafficHistory` and `Logs` are mounted only while current; every other
page stays mounted (hidden) after its first visit. The title-strip clock runs only while the window
is visible.

## Frame: `assets`, `lang`, `theme`, `launch`, `hooks`

```rust
// assets — crates/ui/assets/** embedded, served on the custom protocol `app` (http://app.localhost)
pub const ORIGIN: &str; pub const CSP: &str;
pub fn file(path: &str) -> Option<&'static [u8]>;                  // "css/base.css", "locales/ru.json"
pub fn serve(id: WebViewId, req: Request<Vec<u8>>) -> Response<Cow<'static, [u8]>>;
pub fn index_html(title: &str, lang: Lang, theme: &Theme, scheme: Scheme) -> String;

// lang — catalog = old app's strings + vpnte_ui::LOCALES + the app's extra layers
pub use vpnte_base::i18n::Lang;
pub static LANG: GlobalSignal<Lang>;                                // write to switch the UI language
pub fn os_lang() -> Lang;                                           // Windows UI language: ru -> Ru, else En
pub fn init_locales(extra_layers: &[(&str, &str)]);                 // first call wins
pub fn translate(key: &str, vars: &[(&str, String)], default: Option<&str>) -> String; // subscribes to LANG
pub fn tr(msg: &Msg) -> String;                                     // subscribes to LANG (render code)
pub fn translate_now(key: &str, vars: &[(&str, String)]) -> String; // no subscription (handlers, tasks)
pub fn tr_now(msg: &Msg) -> String;                                 // no subscription (toasts, clipboard)
vpnte_ui::t!("key") / t!("key", "Default") / t!("key", count = n, name = x)

// theme
pub enum ThemeMode { Light, Dark, System /*default*/ }  // resolve(os_dark) -> Scheme, name(), from_name()
pub enum Scheme { Light, Dark }                         // name(), is_dark(), paper(), ink()
pub struct Rgb(pub u8, pub u8, pub u8);                 // from_hex("#rrggbb"), hex(), channels(), rgba()
pub struct Palette { background, sidebar, card, card_elevated, accent, text, text_secondary,
                     text_muted, border, border_strong, success, warning, danger: Rgb }
impl Palette { const LIGHT; const DARK; fn builtin(Scheme); fn levels(&self) -> [Rgb; 13];
               fn complete(mode: ThemeMode, colors: impl Fn(&str) -> Option<&str>) -> Palette }
pub const LEVELS: [(&str /*ThemeConfig key*/, &str /*css var*/); 13];
pub struct Theme { pub mode: ThemeMode, pub custom: Option<Palette> }  // builtin(mode), palette(scheme)
pub static THEME: GlobalSignal<Theme>;                  // write to switch (SettingsApi::set_theme does)
pub fn scheme() -> Scheme;                              // resolved light / dark, reactive
pub fn os_prefers_dark() -> bool;  pub fn accent_hover(Rgb, Scheme) -> Rgb;  pub fn vars_css(&Palette, Scheme) -> String;

// launch
pub const APP_NAME: &str = "VPN Tunnel Enforcer";
pub struct LaunchOptions { pub title: String, pub size: (f64, f64), pub min_size: (f64, f64),
    pub start_hidden: bool, pub data_dir: PathBuf, pub lang: Lang, pub theme: Theme }  // Default, demo(name, &DemoArgs)
pub fn launch(options: LaunchOptions, root: fn() -> Element, contexts: impl FnOnce() -> Vec<Box<dyn Any>>) -> !;
pub unsafe fn scrub_webview2_env();                     // only if elevated: first thing in main, single-threaded
pub fn desktop_config(&LaunchOptions) -> Config;  pub fn set_cloaked(&Window, bool);
pub fn apply_min_size(&Window, (f64, f64));  pub fn harden_webview(&DesktopContext);  // the frame calls both once at start
pub fn set_window_background(&DesktopContext, Rgb);    // window + WebView2 default background (wry's setter)
pub struct DemoArgs { pub theme, pub lang, pub size: Option<(u32, u32)>, pub scene, pub page: Option<String> } // parse()

// hooks
pub fn use_watch<T: Clone + PartialEq + 'static>(subscribe: impl FnOnce() -> watch::Receiver<T>) -> Signal<T>;

// units
pub fn format_bytes(bytes: u64) -> String;   // "1023 B", "1.5 KB", "4.8 MB", "2.2 GB", "1.5 TB" (base 1024)
```
The window is frameless with an HTML title strip (no Snap Layouts flyout on the maximise button).
Close = Dioxus' default (exit) until `TrayHost` switches it to hide-to-tray. Theme persistence and
custom-theme CRUD belong to the app; the UI takes a `Theme` value.

## Shell: `pages`, `shell`

```rust
pub enum Page { Dashboard, Apps, Servers, SpeedTest, Availability, TrafficHistory, Schedule, Logs,
                Settings, Maintenance }          // sidebar order; Copy + Eq + Ord + Hash
impl Page { const ALL: [Page; 10]; fn id(self) -> &'static str /*old ids: "trafficHistory", …*/;
    fn from_id(&str) -> Option<Page>; fn label_key(self) -> &'static str /*"sidebar.<id>"*/;
    fn advanced_only(self) -> bool /*Maintenance*/; fn active_only(self) -> bool /*TrafficHistory, Logs*/;
    fn nav(advanced: bool) -> impl Iterator<Item = Page>; fn allowed(self, advanced: bool) -> Page }
pub struct PageRegistry;                         // Copy; new(), register(page, fn() -> Element) -> &mut Self, get(page)
#[derive(Clone, Copy)] pub struct Nav;           // context: current(), advanced(), go(page)
pub fn use_nav() -> Nav;                         // inside the shell
pub fn use_page_active() -> Memo<bool>;          // own page current && window visible: pause readers when false
pub fn nav_number(index: usize) -> String;       // 0 -> "01"
#[component] pub fn Shell(version: String, advanced: ReadSignal<bool>, registry: PageRegistry,
    #[props(default = Page::Dashboard)] start: Page, #[props(default)] overlays: Element,
    #[props(default)] toasts: Element) -> Element;   // provides Nav and WindowState
#[derive(Clone, Copy)] pub struct WindowState;   // context: visible(), maximized(), focused()
```
A page root is a prop-less `fn() -> Element` and fills the page area (`div.c-swiss.swiss-skin`).
Navigate with `use_nav().go(Page::Servers)`. Hidden pages get `display:none` + `aria-hidden`.

## Widgets: `widgets` (shared controls of every page)

Controls (Dioxus components, «Пломба» tokens only): `Button { kind: ButtonKind, … }`, `IconButton`,
`Icon { glyph: IconGlyph }`, `Checkbox`, `Switch`, `Segmented`, `Tabs` (+ `roving_index`), `Modal { size:
ModalSize }`, `ConfirmDialog`, `Badge { tone: Tone }`, `ProgressBar`, `Spinner`, `Field` (+ `FieldCtx`),
`TextInput { kind: TextKind }`, `TextArea`, `NumberInput` (+ `NumberCommit`, `commit_number`), `Select`
(+ `SelectOption`, `SelectState`, `SelectAction`, `SelectKey`, `Indicator`, `Size`), `Table`, `HeadCell`,
`Cell` (+ `Align`, `Sort`), `Panel`, `Row`, `SectionHeader`, `EmptyState`, `Trunc`, `Loading`, `LoadError`.

```rust
pub struct Toasts;                               // Copy handle of the app-wide queue
impl Toasts { fn use_provider() -> Self /*app root, once*/; fn use_context() -> Self;
    fn success/error/warning/info(&self, title: impl Into<String>, description: Option<String>) -> u64;
    fn push(&self, kind: ToastKind, title, description) -> u64; fn dismiss(&self, id: u64);
    fn list(&self) -> Vec<Toast> /*oldest first, subscribes*/;
    fn failed(&self, title: &Msg, err: &AppError); }   // an action's failure: silent when Cancelled, else a
                                                    // warn log + error toast `title` / `err.user_msg()`
#[component] pub fn ToastHost(close_label: String) -> Element;      // into Shell { toasts }
pub const TOAST_TTL: Duration /*4 s*/; pub const TOAST_LIMIT: usize /*20*/;

pub struct UiError { pub kind: ErrorKind, pub msg: Msg }          // From<&AppError>
pub fn use_job<T: 'static>() -> JobSlot<T>;      // one cancellable action slot per button / form
impl JobSlot<T> { fn start(&self, f: impl FnOnce(CancellationToken) -> impl Future<Output = AppResult<T>>);
    fn cancel(&self); fn running(&self) -> bool; fn last(&self) -> Option<Result<T, UiError>>; fn clear(&self) }
pub enum Load<T> { Loading, Ready(T), Failed(UiError) }           // from_result, ready, error, is_loading, map
pub fn use_load<T, F>(fetch: impl FnMut() -> F) -> Loader<T>;     // state(), reload(), refreshing()
```
`JobSlot` is single flight: `start` does nothing while a run is in flight; the run lives in the owner's
scope and its token is cancelled when the owner unmounts; a cancelled run is silent. `Modal` /
`ConfirmDialog` are native modal `<dialog>`s (page behind inert, focus trap, Escape wherever the focus
is, focus returns to the opener); only a press that starts and ends on the backdrop closes them, and
`can_close: false` (a busy `ConfirmDialog`) also stops the browser's own close request. `NumberInput`
commits on blur / Enter (`commit_number` clamps), arrows step from the typed text.

## Start page: `dashboard`, `panels`, `mascot`

```rust
// dashboard — root component `Dashboard`; needs Rc<dyn DashboardApi>, Rc<dyn PanelsApi>, Toasts
pub struct DashboardView {
    pub conn: vpnte_view::swiss::ConnView,            // projection of the tunnel lifecycle snapshot
    pub exit: vpnte_view::identity::ExitIp,           // public / exit address from the IP monitor
    pub exit_country: Option<String>,                 // ISO alpha-2 of exit.geo (flag coin)
    pub firewall: vpnte_view::labels::FirewallStatus, // kill-switch read-back
    pub leak: Verdict,                                // last leak check; NotChecked = none
    pub soft_mode: bool, pub smart_ru: bool,          // settings (apply on the next connect)
    pub foreign_vpn: Option<String>,                  // another VPN's adapter, only while ours is down
    pub engine: Option<EngineLine>,                   // running engine + reason (identity column caption)
    pub autopick: Option<PickLine>,                   // the automatic server choice's step (one strip)
    pub pause: Option<PauseLine>,                     // ks-a: «Интернет на паузе» (strip with two buttons)
    pub no_pause_vpn: Option<String>,                 // ks-a: another VPN carries all traffic: no pause
    pub proxy_taken: bool,                            // ks-b: another program took the system proxy: one line + «Вернуть»
}
pub struct EngineLine { pub engine: Engine, pub reason: Option<Msg> }  // «Xray · REALITY» under the node
pub struct PickLine { pub title: Msg, pub body: Option<Msg> }  // step; during retries what traffic does
pub struct PauseLine { pub next_attempt: Option<UnixMs>, pub key_rejected: bool }  // countdown target, the key reason
pub trait DashboardApi: 'static {
    fn state(&self) -> watch::Receiver<DashboardView>;
    async fn connect(&self) -> AppResult<()>;                     // returns when the attempt is over
    async fn disconnect(&self) -> AppResult<Option<Msg>>;         // Some(w): off, recovery warned
    async fn cancel(&self) -> AppResult<Option<Msg>>;             // connect / switch in flight
    async fn set_smart_ru(&self, on: bool) -> AppResult<()>;
    async fn run_leak_check(&self) -> AppResult<Verdict>;         // verdict also lands in `leak`
    async fn copy_ip(&self, ip: IpAddr) -> AppResult<()>;
    async fn recheck_firewall(&self) -> AppResult<()>;            // result via `firewall`
    async fn release_kill_switch(&self) -> AppResult<()>;         // remove our filters after a session
    async fn retry_now(&self) -> AppResult<()>;                   // ks-a: «Подключить» in the paused state
    async fn reclaim_proxy(&self) -> AppResult<()>;               // ks-b: «Вернуть» on the system-proxy line
}
pub mod demo { pub enum DashScene { Disconnected, Connecting, Connected, …21 scenes };
    pub struct DemoDashboard; impl DemoDashboard {
        fn handle(scene) -> (Rc<dyn DashboardApi>, Rc<dyn PanelsApi>, DemoStart) } }
```
App duties: publish `conn.cancelling` the moment `cancel` is called; every transition clears `leak`;
`foreign_vpn` only while our tunnel is down; `exit_country` from the geo lookup. The page renders the
mascot inside the slab (render no second `MascotHost`) and binds Ctrl+Enter to the power button
(ignored inside open dialogs and when a control already handled the key). With "Always" in force
(the root `Rc<dyn SettingsApi>`'s kill-switch view: level `Strict` and `always_available`; ks-d)
the paused strip's second button reads «Выключить «Всегда»» and calls
`SettingsApi::set_kill_switch_level(Standard)` instead of disconnecting, and `foreign_vpn` gets
one more line, «Выбрать программу…» (`pick_app` + `add_exception`, once per VPN per run). Without
a `SettingsApi` in context (the demo) both stay as without "Always".

```rust
// panels — the row under the slab, rendered by Dashboard (`SwissPanels { local_pings, active, on_mascot, on_notice }`;
// `active: Option<Memo<bool>>` pauses the proxy health refresh while false, the dashboard passes use_page_active())
pub trait PanelsApi: 'static {
    fn traffic(&self) -> watch::Receiver<vpnte_view::traffic::TrafficSample>; // once a second while the engine runs
    fn servers(&self) -> watch::Receiver<ServersView>;
    fn proxies(&self) -> watch::Receiver<ProxiesView>;
    async fn ping_one(&self, id: &str) -> AppResult<Option<u32>>;            // None = no answer
    async fn ping_all(&self) -> AppResult<()>;                               // results via servers()
    async fn select_server(&self, id: &str) -> AppResult<Selected>;          // publish active_id first
    async fn proxy_start(&self, slot: u16, profile_id: &str) -> AppResult<ProxiesView>;
    async fn proxy_stop(&self, slot: u16) -> AppResult<ProxiesView>;
    async fn proxy_rotate(&self, slot: u16) -> AppResult<ProxiesView>;
    async fn proxy_stop_all(&self) -> AppResult<ProxiesView>;
    async fn proxy_refresh(&self) -> AppResult<()>;                          // refresh_interval() cadence, page active
}
pub struct ServersView { pub rows: Vec<ServerRowView>, pub active_id: Option<String>,
    pub tun_running: bool /*flip clears panel pings*/, pub locked: bool /*op or switch in flight*/ }
pub struct ServerRowView { id, name, country: Option<String>, protocol: Option<String>, ping, health_latency: Option<u32>,
    health: vpnte_view::identity::ServerHealth, checked_at: Option<UnixMs> }
pub struct ProxiesView { pub rows: Vec<ProxyRowView>, pub choices: Vec<ProxyChoice> }
pub struct ProxyRowView { slot: u16, process_running, ready: bool, health: ProxyHealth, profile_name, country,
    proxy_url: Option<String>, port: Option<u16>, latency_ms: Option<u32>, last_error: Option<Msg>,
    engine: Option<Engine> /* while running; the meta line names it: «:18001 · Xray · 46 мс» */ }
pub enum ProxyHealth { Stopped, Starting, Healthy, Degraded, Rotating, Quarantined, Failed }
pub struct ProxyChoice { id, name, country, protocol, health: ServerHealth, in_proxy: bool, vpn_server: bool }
pub enum Selected { Done, Cancelled }
pub fn Flag(country: String, size: u32 = 14) -> Element;   // round flag coin: the 65 ui.panels.country.* codes
pub mod demo { pub enum DemoScene { Connected, Disconnected, ServersEmpty, Live };
    impl DemoPanels { fn handle(scene) -> (Rc<dyn PanelsApi>, DemoFeed) } }
```
App duties: servers removed from their subscription are left out; `in_proxy` = a running slot uses
the server; every configured slot appears in `proxies().rows`; `select_server` and the proxy actions
publish what they changed through `servers()` / `proxies()` before they return (the panels render only
pushed views; a proxy action's returned view only feeds its toast).

```rust
// mascot — «Пломбик»: the brain is vpnte_view::mascot; this module hosts it and feeds it
pub use vpnte_view::mascot::{MascotEvent, MascotPhase, Perch};
pub struct MascotBus;   // Clone (not Copy), == means the same bus, Default = new(); send(MascotEvent),
                        // phase(MascotPhase), speed_band(f32), session_started(Option<UnixMs>), page_active(bool)
                        // (the four setters are idempotent: only a change is delivered)
pub fn use_mascot_bus_provider() -> MascotBus; // above every sender and the host
pub fn use_mascot_bus() -> MascotBus;          // no provider: a detached bus (events dropped) + a log warning
#[component] pub fn MascotHost(greet_time: Option<Duration>) -> Element;  // the overlay (Dashboard renders it)
```
The dashboard feeds the bus itself (phase, speed band, toasts → notices, proxy actions); the app only
provides the bus at the root when other parts of the window should nudge the mascot too.

## Tray: `tray`

```rust
pub trait TrayApi: 'static {
    fn state(&self) -> watch::Receiver<TrayState>;
    async fn start(&self) -> AppResult<()>;        // «Включить защиту»: connect per settings, owner manual, source tray
    async fn stop(&self) -> AppResult<()>;         // «Выключить защиту»
    async fn check_route(&self) -> AppResult<()>;  // leak check as a registry operation; verdict = a notice
    async fn open_logs(&self) -> AppResult<()>;    // the log folder in Explorer
    async fn quit(&self, mode: QuitMode) -> AppResult<()>; // bounded shutdown cleanup; Ok = exit now,
}                                                  // Err = exit refused (failed Proxy-mode rollback under Restore)
pub enum QuitMode { Restore, SkipRestore /*«Выйти без восстановления»*/ }
pub struct TrayState {
    pub tunnel: TunnelState, pub transition: Option<Transition>, pub degraded: bool,
    pub proxy: ProxyStatus /*Running | ProxyDown | Stopped*/, pub engine_running: bool,
    pub leak: bool /*monitoring's flag*/, pub kill_switch: bool /*WFP engaged*/,
    pub restart: Option<(u32, u32)> /*watchdog attempt (n, max)*/, pub public_ip: Option<String>,
    pub proxy_addr: Option<String> /*host:port, never credentials*/, pub down_bps: u64, pub up_bps: u64,
    pub minimize_to_tray: bool /*setting «Сворачивать в трей»*/,
    pub paused: bool /*ks-a: the kill switch holds a drop: menu «Подключить» / «Продолжить без VPN»*/,
}
pub enum TrayStatus { Protected, Leak, Off, Starting, ProxyDown, KillSwitch, Restarting, Stopping, Error, Unknown, Paused }
pub struct TrayModel { status, tooltip: Vec<Msg>, tooltip_speed: Option<Msg>, items: Vec<TrayItem> } // build(&state, quitting)
pub enum CloseAction { Hide, Quit }                              // TrayState::close_action(): the «Сворачивать в трей» setting
#[component] pub fn TrayHost(children: Element) -> Element;      // wraps the Shell; provides TrayContext
#[derive(Clone, Copy)] pub struct TrayContext { pub model: Memo<TrayModel>, pub native: Signal<Option<NativeReport>> }
pub fn show_window(desktop: &DesktopContext);   // tray click, «Показать окно», a second launch (pipe `activate`)
pub fn hide_to_tray(desktop: &DesktopContext);  // hides window + WebView2 controller (memory drops, rAF stops)
pub fn format_speed(bytes_per_second: u64) -> String;   // 0 -> "0 Kbps", 125 000 -> "1.0 Mbps"
pub struct DemoTray;                            // new(scene), scene(TrayStatus) -> TrayState, update(..), spawn_traffic()
```
`TrayHost` switches the window to hide-on-close and decides each close request without a question
(p-calm, owner 12.11.2026): `Hide` with «Сворачивать в трей» and a tray icon, otherwise `Quit`.
Quit hides the window first, runs `TrayApi::quit`, and closes only on `Ok`; a refused quit brings
the window back with «Повторить» / «Выйти без восстановления». The native tray (Win32 via
tray-icon / muda) is updated at most once a second for the speed lines; tooltip ≤ 127 UTF-16 units.

## First-run wizard: `wizard`

```rust
pub trait WizardApi: 'static {
    fn state(&self) -> watch::Receiver<WizardState>;
    async fn detect_proxy(&self) -> AppResult<Option<LocalProxy>>;          // Happ / local proxy, no side effects
    async fn check_key(&self, text: String, cancel: CancellationToken) -> AppResult<KeyCheck>; // cache by text
    async fn finish(&self, choices: WizardChoices) -> AppResult<()>;        // §6.7 order, see below
    async fn skip(&self, lang: Lang) -> AppResult<()>;
}
pub struct WizardState { pub open: bool, pub current: WizardDefaults }
pub struct WizardDefaults { connection: Connection, routing: Routing, smart_ru: bool /* on for a first run */, kill_switch: KillSwitchLevel, autostart: bool, servers: usize }
pub enum Connection { Key, LocalProxy }   pub enum Routing { Hard, Soft /* default */ }
pub struct LocalProxy { host: String, port: u16, kind: ProxyKind }   pub struct KeyCheck { servers: usize, subscription: bool }
pub struct KeyText(pub String);           // Debug prints `KeyText(..)`: the key never reaches a log
pub struct WizardChoices { lang, connection, routing, smart_ru: bool, key: Option<KeyText>, kill_switch: KillSwitchLevel, autostart: bool }
#[component] pub fn Wizard() -> Element;  // into Shell { overlays }; a modal shown while state.open
pub use demo::{DemoScene, DemoWizardApi};
```
Both routing modes are offered with either connection (NOADMIN §2): `routing` is sent as picked.
The page never sends `Soft` with `KillSwitchLevel::Strict` (it explains and holds «Завершить»);
the app still refuses that pair itself (`tunnel.lifecycle.soft.strictUnavailable`).
`finish` order: import the key through the normal profile import (dedupe; it stays if a later step
fails) → autostart if changed → kill-switch level if changed → one atomic settings write (`language`,
`connection_mode`, `routing_mode`, `smart_ru_split`, `kill_switch`, `first_run_complete = true`); on failure undo the
level, then autostart, and return the failing step's `Msg` (a failed undo is the app's own notice).
Push `open: false` after `finish` / `skip`; push `open: true` for `SettingsApi::open_wizard`.

## Servers page: `servers`

```rust
pub trait ServersApi: 'static {      // root component ServersPage; use_servers_api() reads the context
    fn state(&self) -> watch::Receiver<ServersView>;                    // store snapshot, pushed on change
    fn expanded_groups(&self) -> Vec<String>;                           // persisted UI state
    async fn save_expanded_groups(&self, ids: Vec<String>) -> AppResult<()>;
    async fn resolve_ips(&self) -> AppResult<()>;                       // single flight; answers via state
    async fn add(&self, input: String, target: AddTarget, device: ClientDevice,
        request: SubscriptionRequest /* a new subscription's HWID switch + header lines */) -> AppResult<ImportReport>;
    async fn remove(&self, id: &str) -> AppResult<()>;                  // soft delete, purged after 30 days
    async fn restore(&self, id: &str) -> AppResult<()>;
    async fn purge(&self, id: &str) -> AppResult<()>;
    async fn select(&self, id: &str) -> AppResult<SelectOutcome>;       // live switch while connected
    async fn cancel_switch(&self) -> AppResult<()>;                     // that select answers Cancelled
    async fn ping_one(&self, id: &str) -> AppResult<Option<u32>>;       // direct, never cached
    async fn ping_many(&self, ids: Vec<String>, results: mpsc::UnboundedSender<(String, Option<u32>)>) -> AppResult<()>;
    async fn verify_country(&self, id: &str) -> AppResult<CountryCheck>;
    async fn copy_key(&self, id: &str) -> AppResult<Duration>;          // returns the clipboard auto-clear time
    async fn save_key(&self, id: &str) -> AppResult<Option<String>>;    // None = Save dialog dismissed
    async fn export_all_keys(&self) -> AppResult<Option<ExportReport>>;
    async fn export_proxy_list(&self) -> AppResult<Option<ExportReport>>;
    async fn start_proxies(&self, ids: Vec<String>) -> AppResult<ProxyStartReport>;
    async fn refresh_group(&self, id: &str) -> AppResult<RefreshOutcome>;
    async fn set_refresh_interval(&self, id: &str, minutes: Option<NonZeroU32>) -> AppResult<()>;
    async fn rename_group(&self, id: &str, name: String) -> AppResult<()>; // trims, caps at 60 chars
    async fn set_send_hwid(&self, id: &str, on: bool) -> AppResult<()>;   // subscription's HWID switch
    async fn set_request_headers(&self, id: &str, lines: String) -> AppResult<Vec<String>>; // replaces all;
                                  // blank = none; answers the names (values never come back)
    async fn delete_group(&self, id: &str, delete_servers: bool) -> AppResult<()>;
    async fn check_group_health(&self, id: &str) -> AppResult<HealthReport>;  // { results: Vec<(id, KeyHealth)>,
                                  // not_checked: u32 /* deferred by the handshake budget / probe not started */ }
    async fn set_device(&self, id: &str, device: ClientDevice) -> AppResult<()>; // connected server reconnects
    async fn set_engine(&self, id: &str, engine: EnginePref) -> AppResult<()>; // own engine (Auto = setting);
                                  // impossible forced choice = Validation with the engine Msg; reconnects
    async fn probe(&self, id: &str) -> AppResult<ProbeReport>;          // passive: no TLS / HTTP to the endpoint
    async fn geo(&self, id: &str) -> AppResult<Option<GeoInfo>>;        // None = lookups off / unknown
    async fn live_check(&self, id: &str, mode: LiveMode, progress: mpsc::UnboundedSender<LiveProgress>) -> AppResult<LiveCheck>;
    async fn live_history(&self, id: &str) -> AppResult<Vec<LiveCheck>>;   // newest first, at most 20
    async fn live_batch(&self, ids: Vec<String>, stop: CancellationToken,  // up to 12 servers; stop = finish
        progress: mpsc::UnboundedSender<BatchProgress>) -> AppResult<BatchResult>; // with receipts so far
    async fn open_url(&self, url: String) -> AppResult<()>;            // http(s) in the user's browser
    // links and QR codes from phones (RU-2026 item 4, package w7-phones)
    fn link_arrivals(&self) -> watch::Receiver<u64>;                   // bumped per link Windows handed over
    fn take_link(&self) -> Option<String>;                             // that link, once (add dialog)
    async fn read_clipboard(&self) -> AppResult<String>;               // on the user's click only
    async fn read_key_file(&self) -> AppResult<Option<String>>;        // .txt .conf .json .yaml .yml; None = dismissed
    async fn scan_qr_file(&self) -> AppResult<Option<String>>;         // keys / links of a picture's QR codes
    async fn scan_qr_screen(&self, captured: oneshot::Sender<()>) -> AppResult<String>;
        // every screen; the page hides its window first and shows it again when `captured` fires
        // (right after the capture, before the decoding); a decode past its budget = app.phones.qr.slow
    async fn key_qr(&self, id: &str) -> AppResult<QrCode>;             // through shareable_profile (hidden: refused)
    async fn link_schemes(&self) -> AppResult<LinkSchemes>;            // who answers each scheme; portable copy?
    async fn set_link_scheme(&self, scheme: String, on: bool) -> AppResult<LinkSchemes>;
    async fn adopt_link_schemes(&self) -> AppResult<LinkSchemes>;      // portable copy: «open links here»
}
pub struct ServersView { loaded: bool, servers: Vec<ServerView>, groups: Vec<GroupView>, active_id, switching_to:
    Option<String>, tunnel_running, tunnel_busy, foreign_vpn, geo_lookup_disabled: bool }
```
Other types (all `pub use`d at `servers::`): `ServerView`, `GroupView`, `GroupSource`, `GroupStatus`,
`OnlineStatus`, `Stealth`, `KeyHealth`, `KeyHealthReason` (`from_code` / `code`; `EngineSetting` =
the neutral `RowSignal::Engine` mark, never "dead"), `EnginePlan { Runs { engine, reason }, Refused(Msg) }`
(`ServerView::engine_plan`, beside `ServerView::engine`: the row's own choice), `CheckVerdict { kind:
VerdictKind, advice: Option<VerdictAdvice>, detail: Msg, advice_detail: Option<Msg>, checked_at }`
(`ServerView::verdict`: the probe-discipline classifier's last word, a quiet mono caption in the row,
signal colour only for `Frozen` / `IpBanned`; the app sends none older than `health`), `HealthReport`,
`Archive`,
`ArchiveReason`, `AddTarget { Auto, Group(id) }`, `ImportReport`, `SkippedLine`, `SelectOutcome`,
`CountryCheck`, `ExportReport`, `ProxyStartReport`, `StartedProxy`, `ProxySkip`, `RefreshOutcome`,
`FetchError`, `ProbeReport`, `AsnInfo`, `LatencyStats`, `OpenPort`, `GeoInfo`; live checks:
`LiveMode`, `Stage`, `ProgressStatus`, `LiveProgress`, `LiveCheck` (+ `DnsDiag`, `Reachability`,
`TlsDiag`, `HttpDiag`, `PortProbe`, `RouteDiag`, `Infrastructure`, `Changes`, `Handshake`, `Egress`,
`PathDiag`, `PmtuDiag`, `MediaDiag`, `Throughput`, `SplitTunnelDiag`, `Finding`, `Severity`, …;
`LiveCheck::deferred` = the rendered note naming the requests the handshake budget left out, a strip
at the top of the receipt and a line under the batch table),
`BatchProgress`, `BatchResult`. Pure helpers: `buckets`, `sort_groups`, `displayed_ping`,
`row_signal`, `unusable`, `stealth_badge`, `relative_time`, `local_stamp`, `device_label`, `DEVICES`,
`engine_name` (product spelling, shared by every page), `fingerprint(&ServerView)` (the uTLS hello a
connect sends: the provider's pin, else the emitters' default — `chrome` for REALITY under sing-box,
never `android` / `ios` under Xray; replaces `default_fingerprint(device)`).
`ServerView::fingerprint_warning: Option<Msg>`: the engine's `engine.xray.warn.fingerprint*` about a
provider-pinned fingerprint (current REALITY servers refuse it, it fails everywhere, Xray does not
know it), shown as a warning strip in the server detail.
Provider facts and controls: `GroupView` carries `support_url` (an `http(s)` link opened
through `open_url` on a click), `announce` (plain text, never linkified), `provider_refresh_hours`,
`send_hwid`, `header_names`, `moved_at` (the provider moved the subscription: a note) and
`settings_hidden` (`hide-settings`); `ServerView::config_hidden` hides Save / Copy key in the detail
(the backend refuses them too: `servers.hidden.refused`), while protocol, engine, TLS / REALITY and
the protection state stay as they are. `ImportReport::providers: Vec<ProviderLine { name, servers,
error: Option<FetchError> }>` names the Mihomo providers of an import (`FetchError::Refused`: a
provider URL the redirect rules refused, never requested); `ExportReport::hidden` counts servers a
bulk export left out for their provider; `ServerView::config_hidden` also holds for keys that carried
their provider's `hide-settings` into another group. `SubscriptionRequest { send_hwid, headers }` is
the add dialog's request draft: it resets to the new-group defaults after an import and when the
dialog closes (a token header never reaches the next provider). The group toolbar's «Запрос» opens the request dialog (HWID switch,
header names, replace / remove); an empty list without the HWID shows a hint with the switch.
Links and QR codes (w7-phones): `QrCode { size, dark: Vec<bool> }` (row-major modules, no quiet zone;
`path()` = SVG path data; `Debug` prints the size only), `LinkScheme { scheme, owner: SchemeOwner {
Free, Ours, Other(Option<String>), Chosen(String) } }` (`Chosen` = the user's pick in Windows' own
settings: a disabled box with a hint to change it there), `LinkSchemes { list, portable }` (a portable
copy registers links only through the panel's «Открывать ссылки здесь»). Mount `LinkHandoff {}` once
under the shell (the root's overlays): it opens the Servers page for each handed-over link; the page
puts the link into the add dialog with a note and the new-group defaults (no previous provider's
headers, HWID or target group); nothing is imported without «Добавить». While the dialog imports or
reads a source the link waits in the inbox and opens once the dialog is free. The add dialog offers
clipboard / file / QR-picture / QR-on-screen sources; the header's «Ссылки» opens the scheme panel;
the detail shows `KeyQr` unless `config_hidden`.
Demo: `DemoServersApi` with `DemoScene`; `DemoServersApi::offer_link(link)` plays a handed-over link.

App duties: `ServerView.stealth` from `vpnte_profiles::caps`; finding titles / details and skipped-line
reasons are `Msg` keys of the backend's own fragments; `save_key` / `export_*` show the native Save
dialog (Desktop default) and return `Ok(None)` when it is dismissed; `copy_key` uses the 60 s
self-clearing secret clipboard; `open_url` must open the browser non-elevated; `live_check` /
`live_batch` abort the probe when their future is dropped (abort-on-drop around `tokio::spawn`) and
then store nothing; pings measured while the tunnel runs are never persisted.

## Settings page: `settings`

```rust
pub trait SettingsApi: 'static {     // root component SettingsPage; a dismissed dialog = ErrorKind::Cancelled (silent)
    fn state(&self) -> watch::Receiver<SettingsState>;           // live draft fields + instant preferences
    fn kill_switch(&self) -> watch::Receiver<KillSwitchView>;    // one channel per section, so a change made
    fn rotation(&self) -> watch::Receiver<RotationView>;         // anywhere (wizard, import, rotation, rule-set
    fn dns(&self) -> watch::Receiver<DnsView>;                   // updater) shows at once
    fn domains(&self) -> watch::Receiver<DomainsView>;
    fn notifications(&self) -> watch::Receiver<NotificationsView>;
    async fn save(&self, patch: SettingsPatch) -> AppResult<SaveReport>;   // changed fields only + side effects
    async fn set_language(&self, lang: Lang) -> AppResult<()>;             // the page already switched LANG
    async fn set_theme(&self, id: String) -> AppResult<()>;                // must also write theme::THEME
    async fn set_autostart(&self, on: bool) -> AppResult<bool>;            // state read back from Windows
    async fn set_location_privacy(&self, on: bool) -> AppResult<LocationOutcome>;
    async fn apply_browser_protection(&self) -> AppResult<BrowserView>;
    async fn rollback_browser_protection(&self) -> AppResult<BrowserView>;
    async fn retry_adaptive(&self) -> AppResult<bool>;                     // false = no session to re-check
    async fn reset_adaptive_learning(&self) -> AppResult<()>;
    async fn refresh_rule_sets(&self) -> AppResult<()>;                    // with the SAVED settings, never the draft
    async fn open_wizard(&self) -> AppResult<()>;                          // push WizardState { open: true }
    async fn open_logs_folder(&self) -> AppResult<()>;
    async fn export_diagnostics(&self) -> AppResult<DiagnosticsExport>;    // Save dialog + ZIP, single flight
    async fn clear_captures(&self) -> AppResult<()>;
    async fn set_kill_switch_level(&self, level: KillSwitchLevel) -> AppResult<()>; // apply, verify, persist
    async fn add_exception(&self, kind: ExceptionKind, value: String, label: String) -> AppResult<()>;
    async fn remove_exception(&self, id: String) -> AppResult<()>;
    async fn pick_app(&self) -> AppResult<Option<PickedApp>>;              // Open dialog for an .exe
    async fn set_launch(&self, choice: LaunchChoice) -> AppResult<()>;  // connect at launch (instant)
    async fn set_rotation(&self, patch: RotationPatch) -> AppResult<()>;
    async fn set_rotation_profile(&self, id: String, included: bool) -> AppResult<()>;
    async fn rotate_now(&self) -> AppResult<RotationOutcome>;
    async fn validate_dns(&self, address: String) -> AppResult<DnsKind>;
    async fn create_dns(&self, name: String, address: String) -> AppResult<()>;
    async fn delete_dns(&self, id: String) -> AppResult<()>;
    async fn select_dns(&self, id: Option<String>) -> AppResult<()>;      // None = automatic
    async fn add_domain_rule(&self, pattern: String, action: DomainAction) -> AppResult<()>;
    async fn update_domain_rule(&self, id: String, pattern: String, action: DomainAction) -> AppResult<()>;
    async fn delete_domain_rule(&self, id: String) -> AppResult<()>;
    async fn reorder_domain_rules(&self, ids: Vec<String>) -> AppResult<()>; // full new order
    async fn pick_domain_list(&self) -> AppResult<Option<DomainImportPreview>>;
    async fn import_domain_list(&self, action: DomainAction) -> AppResult<DomainImportReport>;
    async fn discard_domain_list(&self);
    async fn set_notification(&self, change: NotificationChange) -> AppResult<()>;
    async fn check_os_notifications(&self) -> AppResult<()>;               // result is pushed
    async fn reset_os_notification_block(&self) -> AppResult<ResetReport>;
    async fn open_windows_notification_settings(&self) -> AppResult<()>;
    async fn export_config(&self, mode: ExportMode) -> AppResult<()>;      // WithSecrets: consent dialog first
    async fn pick_config_import(&self) -> AppResult<Option<ImportPreview>>;
    async fn apply_config_import(&self, sections: Vec<ConfigSection>, mode: ImportMode) -> AppResult<()>;
    async fn discard_config_import(&self);
}
pub struct SettingsState { settings: SettingsView, locale: Option<Lang>, active_theme_id: String,
    themes: Vec<ThemeChoice>, autostart, location_privacy, proxy_credentials_saved, capture_consent_given: bool,
    capture_used_bytes: Option<u64>, connected, direct_session: bool, adaptive: AdaptiveView,
    rule_sets: RuleSetView, browser: BrowserView, diagnostics_export_running: bool,
    tun_available: bool /* false: Proxy only, the reason under the routing choice */,
    capture_available: bool /* false: the capture switch greyed out with the reason */ }
```
`SettingsView` (live values) and `SettingsPatch` (one `Option` per field, `apply_to`) are generated
from one field list: `connection_mode, routing_mode, soft_git, soft_gradle, soft_studio, proxy_engine,
leak_protection, public_wifi_compatibility, auto_restart_on_crash, stealth_mode, adaptive_bypass,
disable_geo_lookup, smart_ru_split, smart_ru_maps_direct, smart_ru_auto_update, minimize_to_tray,
autopilot, domain_enrichment, advanced_mode, proxy_override, proxy_type, bootstrap_route_mode,
check_interval_ms, adaptive_bypass_server_fallback, deep_inspection, deep_inspection_max_mb,
capture_quota_mb`. `SettingsDraft` holds the page's unsaved edits. Section views: `KillSwitchView`
(ks-a: `level`, `status`, `exceptions` (`broad` = an inline hint), `firewall_blocks_outbound` /
`hyperv_unfiltered` (lines in a closed Details panel), `always_available` ("Always" disabled with
«Нужна служба-помощник» when false; a stored "Always" stays shown)),
`RotationView` (+ `RotationPatch`, `RotationOutcome`), `SettingsState::launch` = `LaunchView
{ effective: LaunchChoice /* Off, LastUsed, LowestDelay, Random (provider) */, source: LaunchSource
/* Default, User, Provider */, server_mode }` («Поведение»; the segments show only the user's own
choice, so a click on «Нет» always stores an explicit Off), `DnsView`, `DomainsView` (rows carry
`overrides: Option<SmartRoute>`: Smart RU's own route where the user's rule sends the site the other
way; the row says so in one line) (+ import preview /
report), `NotificationsView` (+ `NotificationChange`, `NotifyEvent`, `NotifyMethod`), config
transfer `ExportMode`, `ImportMode`, `ConfigSection`, `ImportPreview`. Ranges: `CHECK_INTERVAL_SECS`,
`CAPTURE_MAX_MB`, `CAPTURE_QUOTA_MB`, `ROTATION_INTERVAL_MIN`. Demo: `settings::demo::DemoSettingsApi`.

App duties: feed the Shell's `advanced` signal from the saved `advanced_mode`; `smart_ru_auto_update`
ON = `{mode: managed, auto_update: true, use_proxy: true, 24 h}`, OFF = `{bundled, false, true, 24 h}`;
`check_interval_ms` 5 000..300 000; `leak_protection`, the Soft targets and `capture_quota_mb` live
outside core `Settings`.

## Logs page: `logs`

```rust
pub trait LogsApi: 'static {         // root component LogsPage (active-only: mounted while current)
    fn history(&self) -> watch::Receiver<LogsSnapshot>;          // whole history, any order (the page sorts)
    async fn reload_history(&self) -> AppResult<()>;             // after a failed read; result via history
    async fn export_history(&self, format: ExportFormat, file_name: String) -> AppResult<String>; // WHOLE history,
    async fn clear_all(&self) -> AppResult<ClearReport>;         // Save dialog suggesting file_name; returns the path
    async fn read_log(&self, source: LogSource) -> AppResult<LogTail>;  // last lines, whole, redacted, oldest first
    async fn open_log_folder(&self) -> AppResult<()>;
    async fn copy_text(&self, text: String) -> AppResult<()>;
}
pub struct LogsSnapshot { pub history: Load<Arc<[SessionRow]>> }
```
Types: `SessionRow`, `Outcome { kind: OutcomeKind, headline: Text, evidence }`, `Text` (a `Msg` or
plain imported text), `Evidence` (with `proxy_engine_reason: Option<Text>`, key `proxyEngineReason`) /
`EvidenceKey` / `EvidenceValue`, `DisconnectReason`, `Mode`,
`ExportFormat { Csv, Json }`, `LogSource { App, SingBox, Xray }`, `LogTail`, `ClearReport` /
`ArtifactReport`; history rules `Filters`, `Query`, `Period`, `SortState`, `Stats`, `split`, `stats`,
`sort_rows`; journal parsing `JournalLine`, `LineLevel`, `LevelFilter`, `parse_line`, `journal`;
formats `duration_msg`, `local_time`, `local_date`. Demo: `logs::demo::DemoLogs`
(scenes `full`, `empty`, `loading`, `failed`, `partial`).

App duties: `history` from the tunnel history store (outcome headline = the tunnel's `Msg`, or
`Text::Plain` for imported rows; empty strings → `None`); `export_history` writes the lifecycle CSV /
JSON of the whole history atomically; `clear_all` stops packet capture first, then clears
diagnostics, history and traffic, each part on its own (`ClearReport` says what failed); `read_log`
tails `logs/app.log` and the engine logs (`exists: false` for a missing file); `copy_text` = Windows
clipboard. The journal viewer re-reads its tail every 5 s while the page is visible.

## Tools: `availability`, `speedtest`

```rust
pub trait AvailabilityApi: 'static {     // root component AvailabilityPage
    fn state(&self) -> watch::Receiver<AvailabilityState>;   // { tunnel_running, history: Vec<UrlCheck>, history_error: Option<Msg> }
    async fn check_url(&self, input: String, cancel: CancellationToken) -> AppResult<UrlCheck>; // normalises
    async fn routing_test(&self, cancel: CancellationToken) -> AppResult<RoutingReport>;        // + saves first
    async fn clear_history(&self) -> AppResult<()>;
}
pub trait SpeedTestApi: 'static {       // root component SpeedTestPage
    fn state(&self) -> watch::Receiver<SpeedTestState>;      // { tunnel_running, history: Vec<SpeedResult>, history_error }
    async fn run(&self, progress: watch::Sender<SpeedProgress>, cancel: CancellationToken) -> AppResult<SpeedResult>;
}                                       // no tunnel = Conflict; result saved before returning
```
Types: `UrlCheck`, `UrlVerdict`, `PathReport` (+ `DnsStage`, `TcpStage`, `TlsStage`, `HttpStage`,
`PathSource`), `GeoInfo`, `RoutingReport`, `RoutingVerdict`; `SpeedResult`, `SpeedProgress`,
`SpeedPhase`, `Egress { Changed, Direct, NotChecked }`. Pure helpers take the language explicitly:
`format_age(Lang, now, then)`, `stage_rows(Lang, &PathReport)`, `format_date_time(Lang, ts, &TimeZone)`,
`verdict_look`, `routing_look`, `path_status`, `egress_look`, `phase_key`, `fmt_mbps`. An unusable
link is `ErrorKind::Validation`. Demos: `availability::demo::DemoAvailability`,
`speedtest::demo::DemoSpeedTest`. No backend package has a native STUN / UDP egress probe yet.

## Lists: `schedule`, `split_tunnel`, `traffic_history`

```rust
pub trait ScheduleApi: 'static {        // root component SchedulePage
    fn state(&self) -> watch::Receiver<ScheduleSnapshot>; // { schedules: Load<Vec<ScheduleEntry>>, next: Option<NextEvent>, servers: Vec<ServerChoice> }
    async fn reload(&self) -> AppResult<()>;
    async fn create(&self, input: ScheduleInput) -> AppResult<()>;
    async fn update(&self, id: String, input: ScheduleInput) -> AppResult<()>;   // replaces every field
    async fn set_enabled(&self, id: String, enabled: bool) -> AppResult<()>;
    async fn delete(&self, id: String) -> AppResult<()>;                         // unknown id is not an error
}
pub trait SplitTunnelApi: 'static {     // root component SplitTunnelPage (Page::Apps)
    fn state(&self) -> watch::Receiver<SplitSnapshot>;    // { apps: Load<Vec<SplitApp>> }; first empty read runs discovery
    async fn reload(&self) -> AppResult<()>;
    async fn refresh(&self) -> AppResult<usize>;          // rescan; returns how many new apps were found
    async fn add_app(&self) -> AppResult<Option<SplitApp>>;          // Open dialog (.exe); None = dismissed
    async fn add_process(&self, name: String) -> AppResult<SplitApp>; // bare process name, normalised by the service
    async fn set_rule(&self, id: String, rule: AppRule) -> AppResult<()>;
    async fn remove(&self, id: String) -> AppResult<()>;  // a later rescan does not bring it back
}
pub trait TrafficHistoryApi: 'static {  // root component TrafficHistoryPage (active-only)
    fn state(&self) -> watch::Receiver<TrafficSnapshot>;  // { domains: Load<Arc<[DomainRow]>>, tunnel_up: bool }
    async fn reload(&self) -> AppResult<()>;              // a failure keeps the published list
    async fn clear(&self) -> AppResult<()>;
    async fn open_site(&self, url: String) -> AppResult<()>;  // always https://<domain>, default browser
}
```
Types: `ScheduleEntry`, `ScheduleInput` (both with `capture: Capture` {Proxy, Tun} and `upstream:
Upstream` {Server, LocalProxy}: NOADMIN §2 keeps the two apart; `Upstream::uses_profile`),
`ScheduleSnapshot.tun_available` (`Capture::available(tun_available)`: false for a TUN schedule in
an unelevated app; the card, the next-event strip and the editor mark it unavailable), `HhMm`
(minutes; strict `H:MM` / `HH:MM`),
`NextEvent` (with its schedule's `capture`), `NextAction`, `ServerChoice`, form rules `ScheduleForm`, `FormProblem`, `time_until`,
`local_hhmm`; `SplitApp`, `AppKind`, `AppRule`, `display_path`, `matches`; `DomainRow`, `SiteInfo`,
`Moment`, `by_day`, `filter`, `totals`, `MAX_RENDERED`. Demos: `DemoSchedule`, `DemoSplitTunnel`,
`DemoTrafficHistory` (each in its module's `demo`). App duties: schedule `days` are 0 = Sunday,
`NextEvent.name` = the entry's name; split-tunnel icons are optional base64 PNGs; traffic
`connections` → `count`, enrichment → `SiteInfo`, `tunnel_up` from the lifecycle.

## Repair page: `maintenance` (advanced mode only)

```rust
pub trait MaintenanceApi: 'static {     // root component MaintenancePage
    fn state(&self) -> watch::Receiver<MaintenanceState>;
    async fn system_report(&self, cancel: CancellationToken) -> AppResult<SystemReport>;
    async fn verify_protection(&self) -> AppResult<ProtectionView>;   // read back from Windows, also published
    async fn repair(&self) -> AppResult<RepairView>;                 // refused unless the tunnel is idle; own task
    async fn leak_self_test(&self, cancel: CancellationToken) -> AppResult<LeakTestView>;
    async fn routing_self_test(&self, cancel: CancellationToken) -> AppResult<RouteTestView>;
    async fn check_network(&self, cancel: CancellationToken) -> AppResult<NetCheckView>;  // also published
    async fn export_diagnostics(&self, cancel: CancellationToken) -> AppResult<Option<ExportDone>>; // None = dismissed
    async fn restart_capture(&self) -> AppResult<CaptureView>;
    async fn open_snapshots_folder(&self) -> AppResult<()>;
    async fn delete_legacy_data(&self) -> AppResult<()>;              // %APPDATA%\vpn-tunnel-enforcer
    async fn retry_secrets_import(&self) -> AppResult<SecretsImport>;
    async fn set_aside_corrupt(&self, id: String) -> AppResult<()>;   // <name>.corrupt-<unix>.json, start empty
}
pub struct MaintenanceState { tunnel: TunnelPhase, protection: Option<ProtectionView>, repair: RepairView,
    capture: CaptureView, fault: Option<FaultView>, export: ExportView, legacy: LegacyView,
    network: NetworkView /* { running, last: Option<NetCheckView> } */ }
pub struct NetCheckView { at, via_session: bool, verdict: Verdict /* the result's colour */,
    steps: Vec<NetStepView>, modes: Vec<vpnte_view::netmode::NetMode>, headline: Msg, advice: Vec<Msg> }
pub struct NetStepView { kind: NetStepKind /* Dns Tcp Tls Bytes Udp Servers DnsCapture */, verdict: Verdict, detail: Msg }
```
«Режим сети» (RU audit items 9, 11, 6): the panel shows `state.network` (the backend also runs the
check at start and after a network change, and clears `last` when the network changes) with the
button «Проверить сеть», and «Проверить все серверы» (only where a `ServersApi` context exists):
`ServersApi::check_group_health` over every group in turn, summed; a group whose check failed
(engine missing, another check of the group, every key postponed) is counted with the first reason
(`ui.maintenance.network.servers.failed`), only an empty or vanished group is skipped. The
result's colour is `NetCheckView::verdict` (`Ok` only for a clean pass; no internet = `Fail`,
nothing proven = `NotChecked`). The start page's quiet network
strip (`dashboard::netmode`) reads the same `state.network.last.modes` through the
`MaintenanceApi` context (absent in demos: no strip) and names `vpnte_view::netmode::net_banner`.
Types: `SystemReport` / `DiagItem` / `DiagCategory`, `ProtectionView` (+ `KillSwitchState`,
`FirewallBlock`, `FwProfile`, `ProtectionTest`), `RepairStep` (`ALL`, run in order, each independent),
`StepOutcome` (`done` / `failed(msg)` / `blocked(msg)`), `StepState`, `RepairView`, `LeakTestView`
(+ `LeakVerdict`, `AdapterProbe`, `ProbeReach`), `RouteTestView` / `RouteVerdict`, `CaptureView` (`available:
false` disables «restart» up front, the first warning says why),
`EtwView`, `Counted`, `FaultView`, `ExportView`, `ExportDone`, `LegacyView` (+ `LegacyDir`,
`CorruptStore`), `SecretsImport`, `rules::Outcome` (`vpnte_ui::maintenance::Outcome`). Demo:
`maintenance::demo::DemoMaintenanceApi` (scenes `default`, `off`, `problems`, `leak`, `inconclusive`).

App duties: `system_report` = the probes system report mapped to `DiagItem`; `verify_protection` =
the protection `status()` read-back (filters, BFE, `INetFwPolicy2` profiles); `repair` =
`lifecycle.maintenance(…)`: reset of our filters (persistent ones only if the level is not strict),
legacy cleanup again, engine orphan sweep — a failure maps to `StepOutcome::failed(msg)`, a refusal to
`blocked(msg)`; `export_diagnostics` = Save dialog («Сохранить диагностику», Desktop,
`vpn-tunnel-enforcer-diagnostics-<ISO with ':' and '.' as '-'>.zip`) + the forensics export with progress
in `state.export`; capture fields from forensics `CaptureStatus` (`status_unavailable` when the read
fails); legacy fields from the storage import receipt.

## How the app implements an `XxxApi`

```rust
struct ServersBackend { state: Arc<watch::Sender<ServersView>>, svc: Arc<…> /* backend handles */ }

#[async_trait::async_trait(?Send)]
impl ServersApi for ServersBackend {
    fn state(&self) -> watch::Receiver<ServersView> { self.state.subscribe() }
    async fn remove(&self, id: &str) -> AppResult<()> {
        let (svc, tx, id) = (self.svc.clone(), self.state.clone(), id.to_owned());
        // the mutation finishes even if the page drops this future
        tokio::spawn(async move {
            svc.archive(&id).await?;
            tx.send_replace(project(&svc).await);   // publish before answering
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err(AppError::new(ErrorKind::Internal)))
    }
    // … long-running probes take the CancellationToken / abort on drop instead
}
// at start: Box::new(Rc::new(ServersBackend { … }) as Rc<dyn ServersApi>) into launch()'s contexts
```
A store change made anywhere (another page, automation, the tray) is projected into the snapshot
and sent on the `watch` channel; pages never poll. Each demo implementation (`<module>::demo`) is a
complete, runnable reference for the expected behaviour of its trait.

## i18n keys, messages and events the app must handle

- Register the catalog once before `launch` (see Startup). Every `Msg` a trait returns (errors,
  headlines, findings, reasons, warnings) is rendered with `lang::tr` / `tr_now`; its key must exist
  in a registered layer, in ru and en. The UI's own keys live in `vpnte_ui::LOCALES` under `ui.*` or a
  section of the old app's catalog (`sidebar`, `settings`, `logs`, `schedule`, `splitTunneling`,
  `trafficHistory`, `common`); `test_locales` keeps every fragment valid, paired and placeholder-equal.
- Canonical error texts are `errors.*` of `vpnte-base` (`AppError::user_msg()`); a cancelled action
  (`ErrorKind::Cancelled`, a dismissed dialog) is never shown.
- Language and theme: `SettingsApi::set_language` persists, the page has already written `lang::LANG`;
  `SettingsApi::set_theme` must write `theme::THEME`. Startup values go into `LaunchOptions`.
- Advanced mode: the Shell's `advanced` signal must follow the saved `advanced_mode` (Maintenance).
- Second instance / single-instance pipe `activate`: call `tray::show_window(&desktop)`.
- Window close: `TrayHost` owns it (hide-to-tray / quit flow); the app's own shutdown runs
  inside `TrayApi::quit`.
- Wizard: open it by pushing `WizardState { open: true, .. }` (first run, `SettingsApi::open_wizard`),
  close it by pushing `open: false` after `finish` / `skip`.
- Tray state, dashboard snapshot, panel traffic: pushed by the backend (traffic once a second while
  the engine runs); the UI never polls the backend except the journal tail (every 5 s while Logs is
  visible), the panel's proxy refresh (`refresh_interval`, while the start page is active) and explicit
  user actions.

## Elevation

Nothing in this crate needs elevation, and it never asks for it: the app runs as the user (manifest
`asInvoker`, no UAC). Privileged work is the backend's, run by the helper service `vpnte-service` or
in-process when the process happens to be elevated (development, CI). UI calls that can reach it:
`DashboardApi::connect`, `TrayApi::start`, `WizardApi::finish` (TUN capture),
`DashboardApi::{recheck_firewall, release_kill_switch}`, `SettingsApi::set_kill_switch_level`,
`MaintenanceApi::{verify_protection, repair}` (WFP kill switch / leak protection),
`SettingsApi::{apply_browser_protection, rollback_browser_protection}` (browser policies),
`MaintenanceApi::restart_capture` (packet capture / ETW). Without the service and without elevation
they return `ErrorKind::Permission`; the pages show its `errors.permission` text (diagnostics exports
add folder advice) and never report the action as done. `--no-elevate` means nothing. Only an
elevated development run needs `launch::scrub_webview2_env()` first and a WebView2 `data_dir` of its
own.

## Demo binaries

`cargo run -p vpnte-ui --bin demo_<name> -- [--theme light|dark|system] [--lang ru|en] [--size WxH]
[--scene <name>] [--page <id>]`: `demo_frame`, `demo_shell`, `demo_panels`, `demo_mascot`, `demo_widgets`,
`demo_dashboard`, `demo_tray`, `demo_servers`, `demo_settings`, `demo_logs`, `demo_tools`, `demo_lists`,
`demo_maintenance`, `demo_wizard`. Each shows its package over the module's demo API (the page demos
inside the real `Shell`); WebView2 data goes to `%TEMP%\vpnte-webview2\<binary>`.

## Footprint

Measured 2026-11-13 on the real app (debug build of `vpn-tunnel-enforcer.exe`, unelevated, throw-away
`VPNTE_DATA_DIR` / `VPNTE_LEGACY_DIR`, never connected, start page; WebView2 157.0.4341.46, 16 logical
CPUs). Sums over the exe and its 6 `msedgewebview2.exe` processes after 20 s (+15 s after hiding);
CPU over the next 60 s, in % of one core. Script: `.tmp/uiperf/measure.ps1`.

| State | Private working set | Private commit | CPU |
|---|---|---|---|
| Window open, idle | 146-150 MB (exe 13 MB) | 261-268 MB | 11-13 % |
| Hidden to the tray | 41-42 MB | 234 MB | 0.5-0.7 % |
| Started in the tray (`--autostart`), before `start_hidden` hid the controller | 147-149 MB | 263-267 MB | 12 % |
| Started in the tray, now | 48 MB | 144 MB | 1.5 % |

The open window's CPU is the start page's infinite CSS animations (pausing them while the window is
visible is an owner decision, not taken). Live feeds reach the page at most twice a second
(`vpnte-app` `api_dashboard::pace`). Not measured: a connected session with traffic, a release build,
GPU memory.

## Not implemented / known gaps

- Snap Layouts flyout on the HTML maximise button; DWM caption colours (frameless window by design).
- Forwarding WebView `error` / `unhandledrejection` to the log, a shutdown overlay: app / logging
  work (the Shell has the `overlays` slot).
- After a WebView2 renderer or browser process dies the window stays empty until the app restarts.
  dioxus-desktop 0.7.10 cannot rebuild a reloaded page (it allows its own page to load once, and
  its template ids and string caches belong to the page that died); a working window needs a new
  window with a new VirtualDom and the same root contexts, and `launch` takes its contexts once
  (`FnOnce`; the app's contexts also start the backend). After a renderer crash the stand-in page
  keeps the VirtualDom running; after a browser crash it stops, as before.
- PageTip strips (`tips.*`): need a persisted dismissal store; no page renders them.
- `OverflowMenu`, `SortableList` (drag reordering): not built; domain rules reorder with ↑ / ↓.
- Flag coins cover the 65 countries of `ui.panels.country.*` (flag-icons 7.5, `assets/flags/`); any
  other code shows a code mark (servers) or an empty ringed coin (panels).
- No view says up front that the helper service is missing: privileged controls stay enabled and a
  page learns that an action is unavailable from its `ErrorKind::Permission` answer (only read-backs
  such as the capture status have an "unavailable" state). Capability fields are for the `noadmin-*`
  packages to add.
- `TextInput` is controlled: very fast synthetic typing (CDP at zero delay) can drop keystrokes.
- Reset of Windows Firewall («Аварийно»), the dashboard's «Сбросить firewall»: dropped with the old
  firewall rules (protection is WFP now).
- STUN / WebRTC egress card (no backend probe), embedded OSM map, TLS / HTTP banner cards of the
  passive probe, wizard theme step.
- Not exercised: an OS light / dark flip while running, real mouse input on the title strip / resize
  handles, scales other than 200 %, Windows 10, an elevated run.
