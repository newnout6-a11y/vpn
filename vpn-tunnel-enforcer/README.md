# VPN Tunnel Enforcer

Windows Electron app for keeping traffic inside a controlled VPN path. It can
run its own sing-box + Wintun TUN tunnel from imported VPN keys, wrap a local
proxy exposed by Happ or another client, or apply softer per-app proxy settings.

## Current Capabilities

- **Direct VPN mode**: imports `vless://`, `trojan://`, `ss://`, `vmess://`,
  `hysteria2://`, sing-box outbound JSON, regular subscription URLs, and
  supported `happ://add/...` links.
- **Hard mode (TUN)**: creates a Wintun adapter with sing-box, routes external
  IPv4/IPv6 and DNS through `proxy-out`, keeps localhost/LAN direct, and can
  engage a firewall kill-switch.
- **Soft mode (Autoconfig)**: configures Android Studio, Gradle, Git, and
  `HTTP_PROXY` / `HTTPS_PROXY` environment variables, with rollback support.
- **Server picker and subscriptions**: groups keys by subscription, preserves
  removed-but-still-working post-trial keys, refreshes groups, checks key
  health, exports keys, and supports per-profile client device identity.
- **Device identity**: subscription fetches send stable HWID/device headers and
  profile connections can emulate PC, Android, iOS, or macOS client
  fingerprints.
- **Smart RU split routing**: optional RU/government rule-sets are bundled as
  local `.srs` files so sing-box startup does not depend on remote rule-set
  downloads.
- **Leak diagnostics**: captures route snapshots, sing-box logs, firewall state,
  DNS state, browser-visible IP checks, physical-adapter leak tests, and ZIP
  export for support.
- **Crash and stop safety**: stale baseline recovery, stop-time leak suppression,
  watchdog status for dead upstream servers, and UI guards against stale
  connect/disconnect events.
- **External proxy helper**: local control API and bundled scripts can start a
  temporary HTTP/SOCKS mixed proxy for another tool without enabling full TUN.
- **Installer hooks**: packaged builds request administrator rights, close old
  app/runtime processes during upgrade, and keep user settings/keys.

## Prerequisites

- Windows 10/11 x64
- Node.js 18+
- `resources/sing-box.exe`
- `resources/wintun.dll`
- Optional local proxy client such as Happ when using local-proxy Hard mode

The repo already includes the smart-RU rule-set resources:

- `resources/geoip-ru.srs`
- `resources/geosite-category-gov-ru.srs`

## Setup

```bash
npm install
```

If `sing-box.exe` or `wintun.dll` are missing, download them into `resources/`:

- sing-box: https://github.com/SagerNet/sing-box/releases
- Wintun: https://www.wintun.net/

## Development

```bash
npm run dev
```

`npm run dev` starts Electron through `electron-vite`. Open the Electron window,
not the plain Vite URL, because the renderer expects the preload IPC bridge.

## Build

```bash
npm run build
npm run dist:win
```

Installer output:

```text
dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe
```

Portable build:

```bash
npm run dist:portable
```

### Native ETW sidecar (`vpnte-etw-sidecar.exe`)

Traffic forensics uses a native real-time ETW consumer written in Rust
(`native/vpnte-etw-sidecar/`, built on the `ferrisetw` crate). It subscribes to
the TCPIP, DNS-Client, WFP, Winsock-AFD, and WebIO providers and appends
normalized NDJSON traffic events to the session's `events.ndjson`. The Electron
app prefers this binary and falls back to the bundled PowerShell poller
(`vpnte-etw-sidecar.ps1`) when it is absent.

The `dist*` scripts build it automatically via `npm run build:sidecar`, which
requires the Rust toolchain (install from <https://rustup.rs>, target
`x86_64-pc-windows-msvc`). It is a no-op (with a warning) when Rust is not
installed or the host is not Windows. To build it on its own:

```bash
npm run build:sidecar
# or directly:
cd native/vpnte-etw-sidecar && cargo build --release
```

## Test

```bash
npm test
```

The Windows-only networking operations are guarded in code and covered with
unit tests where possible. Real firewall, registry, Wintun, and route behavior
still needs Windows-device verification.

## How Hard Mode Works

1. Selects a Direct VPN profile or detects/uses a local SOCKS5/HTTP proxy.
2. Generates a sing-box runtime config with TUN inbound and `proxy-out` final
   route.
3. Hijacks DNS into sing-box; remote DNS resolvers are detoured through
   `proxy-out`.
4. Optionally applies network baseline cleanup, physical adapter lockdown,
   TUN interface metric, and firewall kill-switch.
5. Starts `vpnte-sing-box.exe` from the writable user-data runtime folder.
6. Monitors the runtime and upstream server/proxy; failures are surfaced as
   blocked/proxy-down instead of silently leaking through the physical adapter.

## External Proxy Control API

Packaged builds include:

- `vpnte-proxy.ps1`
- `vpnte-proxy.cmd`

The app listens on `127.0.0.1:17873` and exposes:

- `GET /api/external-proxy/status`
- `GET /api/external-proxy/list`
- `POST /api/external-proxy/start`
- `POST /api/external-proxy/rotate`
- `POST /api/external-proxy/connect`
- `POST /api/external-proxy/trigger`
- `POST /api/external-proxy/stop`

State-changing endpoints require `POST` plus `X-VPNTE-Control-Token`. The token
is generated per app session and written to
`%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-token`; bundled helper
scripts read it automatically. `GET /status` and `GET /list` remain read-only
automation helpers.

## Tech Stack

- Electron 30 + React 18 + electron-vite
- TypeScript
- Zustand for shared renderer state
- TailwindCSS and local design-system components
- lucide-react icons
- sing-box + Wintun
- electron-store for local app state
- Vitest

## License

MIT
