# Session Context — VPN Tunnel Enforcer Optimization Session (2026-06-28)

## Overview

Full-day optimization session on the VPN Tunnel Enforcer Electron app. Started with startup performance analysis, progressed through network path investigation, dead code cleanup, security hardening, bug fixing, UI redesign, and multi-client proxy detection.

## Starting State
- Electron 30 (EOL), 15-second cold start, 91 MB installer
- ~4000 lines of dead code (widgets, components, functions)
- 35 crash-recovery/IP/ping/speed/race-condition bugs
- Light theme too bright, no glassmorphism, no code splitting

## Ending State
- Electron 42 (latest), ~2-3 second cold start, 112 MB installer
- All dead code removed, 414 tests passing
- 35 bugs fixed, glassmorphism UI, 8 VPN clients detected

---

## Phase 1: Startup Optimization (7 fixes)

### Problem: 15-second cold start vs 2-3 seconds for Happ

### Root Causes Found (10 agents)
- `createWindow()` gated behind 4-5 sequential PowerShell crash-recovery operations
- `recoverStaleKillSwitch` did 2 redundant firewall probes
- `isProcessElevated` spawned PowerShell (1-3s) instead of `cmd /c net session` (100ms)
- `waitForTunInterface` polled `Get-NetAdapter` via PowerShell (up to 25 spawns)
- `isSingboxRunning` used `Get-CimInstance` (1-3s) instead of `tasklist` (200ms)
- `captureSnapshot` spawned 14 parallel PowerShell processes per 60s tick
- Renderer `init()` ran 8 IPC calls sequentially, heavy probes blocked UI
- `happDetector.detect()` had no cache — every call did full port scan
- `repairOrphanedPhysicalAdapterDns` ran elevated PowerShell on every clean startup

### Fixes Applied
1. `createWindow()` before crash-recovery — window appears immediately, recovery in background
2. `recoverStaleKillSwitch` uses `readManifest()` directly instead of `isKillSwitchActive()` — eliminated double probe
3. `isProcessElevated` — fast `cmd /c "net session"` first, PowerShell as fallback
4. `happDetector.detect()` — 8-second in-flight cache, shared between `detectHapp` and `runAutoPilot`
5. Renderer `init()` — `detectHapp`/`runAutoPilot`/`getRoutingPlan` fire-and-forget, 5 status calls in `Promise.allSettled`
6. `captureSnapshot('app-start')` and `isKillSwitchActive()` deferred by 5 seconds
7. `performCrashRecovery` — single `tasklist` call shared across all 3 recovery steps

---

## Phase 2: Network Path Investigation (10 agents)

### Complete network path mapped:
- sing-box TUN inbound (`mixed` stack, `auto_route`, `strict_route`)
- DNS hijack via `protocol: 'dns', action: 'hijack-dns'` route rule
- 7-layer DNS leak prevention (pinning, hijack, WFP, IPv6 off, cache flush, Teredo off, SmartNameResolution)
- Firewall kill-switch (`DefaultOutboundAction=Block` + Allow rules)
- Physical adapter lockdown (IPv6 disable, DNS pin to 192.168.250.254)
- Smart RU split routing (geoip-ru.srs + geosite-category-gov-ru.srs, local files)
- ETW traffic forensics (pktmon + Rust sidecar, 4000 lines, default off)

---

## Phase 3: Network Optimization (12 fixes)

1. `stack: 'gvisor'` → `'mixed'` — native Windows TCP + gVisor UDP, CPU -30%
2. `DisableSmartNameResolution` + `DisableParallelAandAAAA` registry keys — closes DNS leak gap
3. `route_exclude_address` for private ranges — kernel-level bypass instead of sing-box route rule
4. `waitForTunInterface` → `os.networkInterfaces()` — eliminates up to 25 PS spawns
5. `isSingboxRunning` → `tasklist` — 200ms vs 1-3s per poll
6. `captureSnapshot` — 14 PS → 1 combined tagged script (-93% spawns)
7. Dead widget system removed (9 files + recharts dep, -17 MB asar)
8. `React.lazy` code splitting — initial bundle 1327 KB → 880 KB (-33%)
9. 5 renderer-only deps moved to devDependencies (-2.84 MB asar)
10. 9 unused `@radix-ui/*` packages removed
11. `stopInProgress` race fix — prevents start/stop conflict
12. `performCrashRecovery` — env autoconfig rollback added

---

## Phase 4: Dead Code Cleanup

### Files Deleted (5)
- `HeroStatus.tsx` (557 lines) — replaced by Dashboard inline power card
- `SpeedTestCard.tsx` (274 lines) — SpeedTest page self-contained
- `ModeSelector.tsx` (184 lines) — mode switching moved to Settings
- `MacToggle.tsx` (76 lines) — replaced by motion.button + MacSwitch
- `Apps.tsx` (158 lines) — route hijacked by SplitTunnel

### Dead Functions Removed
- `dispatchNotification` + `notificationPrefsService` (notificationPrefs.ts)
- `maybeAutoRefreshSmartRouteRuleSets` (ruleSetManager.ts)
- `applyToSingboxConfig` (dnsProfiles.ts)
- `probeBrowserGeoBlock` (urlAvailability.ts)
- `onVpnConnected/Disconnected/isActive/isVpnConnected` (granularKillSwitch.ts)
- `applyClientDeviceToProfile` (vpnProfiles.ts)
- `measureDownload/measureUpload` (speedTest.ts)
- `restoreTransitionAdapters` (physicalAdapterLockdown.ts)
- `updateTrayIcon` (tray.ts)
- `getCurrentForeignTun` (competingTunDetector.ts)

### Dead Store Actions Removed
- `clearLogs` (never dispatched)
- `toggleTarget` (only dead Apps.tsx called it)

### Dead i18n Keys Removed (48 keys × 2 locales)
- 15 dashboardWidgets.* (widget system deleted)
- 11 themes.* (no custom theme UI)
- 12 settings.* (hardcoded Russian or replaced)
- schedule.comingSoon, servers.comingSoon, common.confirmAction
- domainRouting.hitCount/resetHits/resetHitsConfirm

---

## Phase 5: Electron Upgrade

- Electron 30 (EOL Oct 2024) → Electron 42 (latest stable)
- Chromium 124 → 148, Node.js 20 → 24
- electron-builder 24 → 26, electron-vite 2 → 3
- @types/node 20 → 22
- Installer: 91 MB → 112 MB (Electron 42 framework larger)

---

## Phase 6: Store Singleton Consolidation

- Created `sharedStores.ts` — 3 singleton Store instances (server-picker, server-groups, granular-kill-switch)
- Replaced duplicates in `serverGroups.ts`, `keyHealthChecker.ts`, `tunController.ts`
- `configManager.ts` — 3 duplicates replaced with shared, widgetStore removed
- Fixed multi-writer clobber risk on `server-picker` (3 writers through separate copies)

---

## Phase 7: Bug Fixes (35 total, 10 agents)

### Crash Recovery (5)
1. Boot-time recovery script (`vpnte-recover.ps1`) — scheduled task at SYSTEM startup
2. `deleteManifest()` only on verified rollback success
3. Probe for stuck `DefaultOutboundAction=Block` without rules
4. Atomic manifest writes (temp + rename) in all 3 modules
5. Env autoconfig rollback in `performCrashRecovery`

### IP Detection (3)
6. IP chip shows spinner until `vpnIp` confirmed (not real IP in green)
7. IP baseline delayed 4s with TUN running check (prevents real IP as VPN baseline)
8. Geo lookup gated on `vpnIp` (prevents geolocating real IP)

### Ping Accuracy (4)
9. `probeServer` tunnel-aware (skips latency when TUN up)
10. QuickServers `≈` prefix when TUN running
11. ICMP anti-fake gate `≤3ms` (was only `<1ms`)
12. `stealthTcpProbe` resolves hostname to IP before `--resolve`

### Speed Test (4)
13. Upload sends `randomBytes` not `Buffer.alloc` (prevents compression inflation)
14. Upload Mbps from actual bytes, not expected
15. Post-test VPN egress IP verification
16. Timeout 60s → 180s (slow VPN connections measurable)

### UI Feedback (4)
17. Settings auto-save: debounced 1.5s persistence
18. Global `MacToast` in App.tsx (visible on all pages)
19. Hot-reload notification: "Применяем изменения" before tunnel restart
20. Profile rotation sends `server-active-changed` IPC to renderer

### Race Conditions (4)
21. `isProcessElevated().then()` checks `resolved` flag
22. Auto-restart timer checks `userInitiatedStop`/`stopInProgress`
23. `start()` only clears `userInitiatedStop` if `!stopInProgress`
24. `onExit` wrapped in try/catch with emergency cleanup

### Config Edge Cases (3)
25. Bootstrap DNS: `udp:1.1.1.1` instead of `type: local` (prevents circular dependency)
26. Hysteria2 `server_ports` array unwrapping (JSON import fix)
27. WebSocket path `ensureLeadingSlash()` (prevents malformed HTTP)

### Safety (3)
28. Kill-switch crash shows window (restore + focus BrowserWindow)
29. Auto-restart `.catch()` emits `notifyStatus('stopped')` (no stuck "Перезапуск")
30. `connectionBusy` 30s timeout (power button can't spin forever)

### Remaining (5)
31. Device switch hot-reload (restart tunnel when active profile fingerprint changes)
32. Latency: 5 samples + warmup + min/max trim
33. OVH/Tele2 cache-buster per stream
34. Stale TUN adapter check in crash recovery
35. Nuclear reset uses `execElevated` (works without admin)

---

## Phase 8: Other Fixes

- ETW forensics default off (`deepTrafficInspectionEnabled: false`)
- `scheduleTriggered` + `profileRotation` notifications wired
- Domain routing hit-count UI removed (always 0 — data pipeline never connected)
- Domain routing hot-reload added (`restartWithLastOptions` on rule change)
- Scheduler `profileId` fix (now calls `selectProfile` before connect)
- Rotation reconnect passes kill-switch/lockdown/stealth prefs
- NSIS finish page window draggable

---

## Phase 9: UI Redesign (2026 Glassmorphism)

### Dark Theme
- Background: `13 13 17` (deep dark) with radial gradient (accent top, success bottom)
- Cards: frosted glass (`backdrop-blur 20px`, 72% opacity, light border)
- Power button: dual-layer shadow (accent glow + depth)
- Sidebar: glass surface

### Light Theme
- Background: `228 230 235` (soft grey-blue, not pure white)
- Cards: `238 240 245` (off-white) with glassmorphism
- Accent: `0 90 170` (deep blue, less eye-strain)
- All glass/glow/gradient effects from dark theme applied

### Micro-interactions
- Buttons: hover `scale(1.02)` + tap `scale(0.96)` + accent glow
- Cards: hover lift + accent-tinted border
- Page transitions: framer-motion opacity + Y slide (180ms)

### IP Display Fix
- Green IP chip only when `publicIp === vpnIp` (confirmed VPN exit)
- Spinner "Определяем IP..." on glass background while waiting

---

## Phase 10: Multi-Client Proxy Detection

Expanded beyond Happ to support all major 2026 Windows VPN clients:

### Config Scan (20+ directories)
Happ, V2RayN, HiddifyN, Clash Verge Rev, FlClash, NekoRay, NekoBox, Hiddify Next, Karing, Mihomo Party, sing-box, Streisand

### Port Scan (expanded)
V2RayN: 10808, 10809 | Clash: 7890-7893, 7897 | Hiddify: 6450, 6451 | sing-box: 2080, 2081 | Shadowsocks: 8388 | General: 8080, 9090, 20170, 20171

### Process Exclusion (TUN loop prevention)
14 new processes added: v2rayN, sing-tun, clash-verge-service, flclash, mihomo-party, verge-mihomo, HiddifyN, shadowsocks-rust, karing, streisand, surfboard

---

## Commits (chronological)

1. `9309b0d` — Startup perf: reduce cold-start from ~15s to ~2-3s
2. `7a08ba0` — Network perf: TUN stack, DNS leak, PS spawns, bundle, race fix
3. `5ba0b69` — Dead code cleanup: 5 files deleted, dead functions/actions removed
4. `9e61b87` — ETW forensics default off
5. `f318fc4` — Wire notifications, remove hit-count UI
6. `bed634f` — Dead functions, hot-reload, scheduler/rotation fixes
7. `5635f28` — Dead i18n keys removed (48 × 2 locales)
8. `896389e` — Electron 30 → 42, electron-builder 24 → 26, electron-vite 2 → 3
9. `41d2161` — Store singletons consolidation (34 → 28)
10. `65dedbd` — Crash recovery, IP detection, ping, boot-time recovery (10 fixes)
11. `b352c77` — Ping accuracy, speed test, UI feedback, rotation notification (10 fixes)
12. `35cf139` — Bootstrap DNS, race conditions, onExit safety, config edge cases (10 fixes)
13. `2d51ce6` — Device hot-reload, latency, nuclear reset, remaining (5 fixes)
14. `2184d2a` — NSIS finish page draggable
15. `ce51dce` — 2026 glassmorphism redesign (dark theme)
16. `8f2d41e` — Multi-client proxy detection (V2RayN, Clash, Hiddify, NekoRay, etc.)
17. `acfe479` — Light theme glassmorphism redesign
18. `40d9063` — Darken light theme further + IP chip confirmed-only
19. README rewrite + this context file

---

## Architecture Notes

### Key Design Decisions
- `stack: 'mixed'` — native Windows TCP (performance) + gVisor UDP (isolation)
- IPv4-only TUN — prevents Happy Eyeballs IPv6 stalls
- Local `.srs` rule-sets — remote download timeout = FATAL sing-box error = real IP leak
- `route_exclude_address` — kernel-level private range bypass (sing-box 1.10+)
- `udp:1.1.1.1` bootstrap DNS — prevents circular dependency with adapter lockdown
- Atomic manifest writes — BSOD mid-write no longer corrupts recovery state
- Boot-time recovery script — network restored before user logon, independent of app

### Tech Stack (final)
- Electron 42, React 18, electron-vite 3, TypeScript 5.9
- Zustand, TailwindCSS 3, framer-motion, class-variance-authority
- sing-box 1.13, Wintun, Rust ETW sidecar (ferrisetw)
- electron-store 8 (shared singletons), Vitest 4 (414 tests)
- electron-builder 26, NSIS installer (~112 MB)
