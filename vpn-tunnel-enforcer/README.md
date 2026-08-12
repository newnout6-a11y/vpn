# VPN Tunnel Enforcer

Windows Electron app that forces all traffic through a controlled VPN path. Runs its own sing-box + Wintun TUN tunnel from imported VPN keys, wraps a local proxy from Happ or any other client, or applies softer per-app proxy settings.

## Capabilities

### VPN Modes
- **Direct VPN**: imports `vless://`, `trojan://`, `ss://`, `vmess://`, `hysteria2://`, `naive://`, `anytls://`, `shadowtls://`, `tuic://`, sing-box outbound JSON, Clash YAML, Xray JSON, subscription URLs, and `happ://add/...` deep links
- **Hard mode (TUN)**: Wintun adapter via sing-box with `mixed` TCP stack (native Windows kernel + gVisor UDP), `strict_route` DNS hijack, `route_exclude_address` for private ranges, firewall kill-switch, physical adapter lockdown (IPv6 off + DNS pinning), and `DisableSmartNameResolution` registry hardening
- **Soft mode (Autoconfig)**: configures Android Studio, Gradle, Git, and `HTTP_PROXY` / `HTTPS_PROXY` environment variables via `setx` (uses `socks5h://` to force DNS through proxy), with rollback support
- **External proxy mode**: independent sing-box processes exposing mixed HTTP/SOCKS proxies on loopback ports starting at `127.0.0.1:17990`, controlled via HTTP API on port 17873 by default

### Proxy Client Detection
Automatically detects local proxies from:
- **Happ** — config file scan + port scan + listener enumeration
- **V2RayN / HiddifyN** — config scan in `AppData/v2rayN`, `AppData/HiddifyN`
- **Clash Verge Rev / FlClash / Mihomo Party** — config scan + port 7890/7891/7897
- **NekoRay / NekoBox** — config scan + listener detection
- **Hiddify Next** — config scan in `AppData/Hiddify`
- **Karing, Streisand, sing-box, Surfboard** — config scan + port scan
- System proxy settings (WinHTTP, WinINet, env vars)
- Live loopback listener enumeration (behavior-based, verifies SOCKS5/HTTP protocol)

### Server Management
- Groups keys by subscription, preserves removed-but-still-working post-trial keys
- Subscription refresh with connection-tuple dedup, multi-device support, DoH bypass for blocked URLs
- End-to-end key health checking through an isolated sing-box outbound for every supported protocol
- Per-profile client device identity (PC/Android/iOS/macOS) with uTLS fingerprint emulation
- Geolocation via 5-source voting (ip-api.com + ipwho.is + ipinfo.is + ipinfo.io + iplocation.net)
- Export keys to URI (all protocols) or bulk file

### Smart RU Split Routing
- RU government/geosite rule-sets bundled as local `.srs` files (no remote download = no FATAL sing-box startup failure)
- IP-checker domains pinned to `proxy-out` (prevent false leak reports)
- VPN-pinned media (YouTube/Google) forced through proxy
- Optional maps-direct toggle
- DNS rules mirror route rules (RU domains resolve via direct RU DNS)

### Leak Prevention (7 layers)
1. Physical adapter DNS pinning (`Set-DnsClientServerAddress → 192.168.250.254`)
2. sing-box `hijack-dns` route rule
3. sing-box `strict_route` WFP filter on port 53
4. IPv6 disabled on physical adapters (`Disable-NetAdapterBinding ms_tcpip6`)
5. `Clear-DnsClientCache` on lockdown apply
6. Teredo/6to4/ISATAP transition adapters disabled
7. `DisableSmartNameResolution` + `DisableParallelAandAAAA` registry keys

### Crash Recovery
- **Boot-time recovery script** (`vpnte-recover.ps1`): registered as scheduled task at system startup (SYSTEM account, before logon). Restores firewall, DNS, IPv6, transition adapters, registry keys, env proxy vars, and removes stale TUN adapter — all without the Electron app
- **Atomic manifest writes**: temp file + rename (survives BSOD mid-write)
- **Stuck firewall detection**: probes `DefaultOutboundAction=Block` even without VPNTE rules
- **Manifest preserved on failed rollback**: `deleteManifest()` only after verified success
- **Env autoconfig rollback** in crash recovery (`autoconfig.rollback(['env'])`)
- **onExit try/catch**: emergency cleanup (baseline + kill-switch + lockdown) if handler throws

### Diagnostics
- Route snapshots, sing-box logs, firewall state, DNS state, browser-visible IP checks
- Active physical-adapter leak test (curl bound to each adapter + Cloudflare DNS side-channel)
- ETW traffic forensics (pktmon + native Rust sidecar, **off by default** — enable in Advanced Settings)
- Diagnostics ZIP export with redaction of all secrets
- System diagnostics (13 collector groups in parallel)
- Store diagnostics and repair actions

### UI/UX
- **2026 glassmorphism design**: frosted glass cards (`backdrop-blur 20px`), gradient background depth, accent glow effects
- **Dark theme**: deep `13 13 17` background with radial accent/success gradient
- **Light theme**: soft `228 230 235` background (muted, not pure white)
- **Code-split pages**: `React.lazy` + `Suspense` — initial bundle 880 KB (was 1327 KB)
- **Global toast notifications**: visible on all pages via Zustand store
- **Micro-interactions**: button hover scale, tap shrink, card hover lift
- **Auto-save settings**: debounced 1.5s persistence — toggles never lost
- **Hot-reload with notification**: domain routing and split tunneling changes show "Применяем изменения" before tunnel restart

## Prerequisites

- Windows 10/11 x64
- Node.js 22+ (for development)
- `resources/sing-box.exe` (sing-box 1.13+)
- `resources/wintun.dll`
- Optional: local proxy client (Happ, V2RayN, Clash Verge, Hiddify, NekoRay, etc.)

Bundled resources:
- `resources/geoip-ru.srs`
- `resources/geosite-category-gov-ru.srs`
- `resources/vpnte-recover.ps1` (boot-time recovery)

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

Open the Electron window, not the plain Vite URL — the renderer expects the preload IPC bridge.

## Build

```bash
npm run dist:win
```

Installer: `dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe` (~112 MB)

Portable: `npm run dist:portable`

### Native ETW Sidecar

Traffic forensics uses a native Rust ETW consumer (`native/vpnte-etw-sidecar/`, `ferrisetw` crate). Built automatically by `dist*` scripts via `npm run build:sidecar`. No-op when Rust is not installed.

```bash
npm run build:sidecar
# or:
cd native/vpnte-etw-sidecar && cargo build --release
```

## Test

```bash
npm test
```

414 tests across 43 files. Windows-only networking operations are guarded and unit-tested where possible.

## How Hard Mode Works

1. Selects a Direct VPN profile or detects a local SOCKS5/HTTP proxy from any supported client
2. Generates sing-box config: TUN inbound (`mixed` stack, `auto_route`, `strict_route`, `route_exclude_address` for private ranges), DNS hijack, `proxy-out` final route
3. Applies physical adapter lockdown: IPv6 disabled, DNS pinned to TUN resolver, `DisableSmartNameResolution`, transition adapters off
4. Launches `vpnte-sing-box.exe` elevated from writable user-data runtime folder
5. Waits for TUN adapter via `os.networkInterfaces()` (no PowerShell spawn)
6. Sets TUN interface metric to 5 (wins route tiebreak over Wi-Fi)
7. Engages firewall kill-switch (`DefaultOutboundAction=Block` + Allow rules for sing-box/proxy/TUN)
8. Starts proxy/server watchdog (5s interval, 3-strike fail, fail-closed)
9. Monitors for leaks: IP check (30s), active adapter probe (30s + event-driven), competing TUN detector (15s)
10. On crash: kill-switch kept, auto-restart with backoff [2s, 5s, 10s], post-trial failover to sibling keys

## External Proxy Control API

Packaged builds include `vpnte-proxy.ps1` and `vpnte-proxy.cmd`. The app listens on `127.0.0.1:17873` by default. If that port is busy, it falls back to a free loopback port and writes the actual URL to `%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-endpoint.json`.

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/status` | GET | No | Current proxy URL (`?slot=1..47546`) |
| `/instances` | GET | No | Proxy instances with cached data-plane health |
| `/list` | GET | No | Profile list with persisted health (optional `?country=`) |
| `/start` | POST | Yes | Start with auto-picked profile (`?slot=1..47546`) |
| `/rotate` | POST | Yes | Round-robin next profile (`?slot=1..47546`) |
| `/connect` | POST | Yes | Specific profileId (`?slot=1..47546`) |
| `/trigger` | POST | Yes | Fire-and-forget reconnect (`?slot=1..47546`) |
| `/healthcheck` | POST | Yes | Run an immediate data-plane check for one slot |
| `/profiles/healthcheck` | POST | Yes | Check every profile in `?groupId=...` and persist live/dead status |
| `/stop` | POST | Yes | Kill proxy process (`?slot=1..47546`) |

Token: `X-VPNTE-Control-Token` header, generated per session, written to `%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-token`. `vpnte-proxy.ps1` reads the endpoint file automatically and also accepts `VPNTE_CONTROL_URL` as an override.

Slot 1 uses the legacy proxy port `17990`; each following slot uses the next TCP port. For example, slot 100 uses port `18089`. The PowerShell helper accepts `-Slot 1..47546` and derives the matching default port automatically.

Each `/instances` row includes `health` (`healthy`, `checking`, or `unhealthy`), `egressIp`, `latencyMs`, `lastCheckedAt`, `lastSuccessAt`, and `lastError`. `running` is true only after both the external-IP and HTTPS probes succeed through that row's `proxyUrl`; `processRunning` reports only whether the managed child process is still alive. Repeated timeout/EOF health failures trigger bounded restart attempts, then disable the slot while retaining its diagnostic result.

Each `/list` row includes `status` (`online`, `offline`, or `unknown`), `lastCheckedAt`, `healthLatencyMs`, `healthReason`, `selectedForVpn`, and the external-proxy `activeSlots`. Run `vpnte-proxy.ps1 profiles-health <groupId> -Json` to refresh these values through the authenticated API.

## Boot-Time Recovery

`vpnte-recover.ps1` runs at system startup (before user logon) as a scheduled task with SYSTEM privileges. It restores:

- Firewall `DefaultOutboundAction` to Allow + removes VPNTE rules
- DNS server addresses to DHCP (resets VPNTE resolver pinning)
- IPv6 adapter bindings (`Enable-NetAdapterBinding ms_tcpip6`)
- Teredo/6to4/ISATAP to default state
- `DisableSmartNameResolution` / `DisableParallelAandAAAA` registry keys
- DNS client cache flush
- Orphaned `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` env vars
- Stale Wintun TUN adapter removal

## Tech Stack

- **Electron 42** + React 18 + electron-vite 3
- TypeScript 5.9
- Zustand for shared renderer state
- TailwindCSS 3 + class-variance-authority + framer-motion
- sing-box 1.13 + Wintun (TUN adapter)
- electron-store 8 for local app state (shared singletons)
- Native Rust ETW sidecar (ferrisetw)
- Vitest 4 (414 tests)

## License

MIT
