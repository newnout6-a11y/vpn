## 2026-10-10 - Task: Address CodeRabbit and Revix review findings on PR #23
### What was done
- Sealed indeterminate IP auto-verification safety gates against incomplete adapter inspection (`LeakSelfTestResult.physicalAdapterInspectionComplete`): if physical adapter enumeration fails or is cancelled, rebaselining is strictly rejected.
- Verified route ownership after leak self-test and enforced exact baseline matching (`expectedIp`) in `ipMonitor.recheck`: fresh network samples are adopted as VPN baseline only when they match `leakResult.defaultRoutePublicIp` and TUN routes remain active.
- Passed all dynamic auto-verification log parameters and error messages through redactSensitiveText in compliance with Revix rule redact-before-log-event, safely retaining plain-text IP strings for debugging while sanitizing secrets and user paths.
- Modularized auto-verification logic into `src/main/indeterminateIpAutoVerify.ts` and prevented in-flight guard latching on synchronous early returns via `.finally()`.
- Restored original `suppressLeakSelfTestsFor(ms)` cancellation semantics on zero-ms calls while maintaining test isolation via `resetLeakTestThrottlesForTest()`.
- Replaced fragile substring checks in `indeterminateIpAutoVerify.test.ts` with end-to-end behavioral tests covering clean adoption, failed adapter enumeration, physical leaks, DNS leaks, route drops, IP sample mismatches, and sequential early returns.
- Added regression tests in `leakSelfTest.test.ts` for adapter enumeration failure, cancellation, and clean probe notifications.
### Testing
- `npm run typecheck` passed (exit code 0).
- `npm test` passed: 216 files, 2874 passed (100% green).
- `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py` passed: AC 927/927, F 210/210, 0 missing.
### Notes
- Git branch: `codex/wfp-firewall-lifecycle-perf` (PR #23).

## 2026-10-10 - Task: Auto-verify indeterminate VPN IP and disable probe socket keep-alive
### What was done
- Identified why `⚠️ 13.143.214.3 — VPN-IP изменился, требуется проверка` stayed indeterminate: Node's default global agent keep-alive pooled sockets across network transitions during startup, and no automatic re-verification mechanism existed to clear indeterminate states without user intervention.
- Configured dedicated HTTP and HTTPS agents with `keepAlive: false` in `src/main/ipMonitor.ts` so public IP probes never reuse pre-transition TCP sockets.
- Implemented `verifyIndeterminateVpnIp` in `src/main/index.ts`: when an indeterminate IP is reported while TUN is running, it verifies active routes and executes `runLeakSelfTest()`. If the physical adapter is blocked with zero leaks and egress is proven safe through TUN, it automatically calls `ipMonitor.recheck(true)` to rebaseline the IP and transition verdict to `'passed'` without requiring manual button clicks.
- Added `setLeakSelfTestCompletedCallback` in `src/main/leakSelfTest.ts` to trigger automatic rebaseline if any periodic leak test confirms clean zero-leak operation during an indeterminate state.
- Added automated tests in `indeterminateIpAutoVerify.test.ts`, `ipMonitor.test.ts`, and `leakSelfTest.test.ts`.
### Testing
- `npm run typecheck` passed (exit code 0).
- `npm test` passed: 216 files, 2862 passed (100% green).
- `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py` passed: AC 927/927, F 210/210, 0 missing.
### Notes
- Git branch: `codex/wfp-firewall-lifecycle-perf` (PR #23).

## 2026-06-19 - Task: Fix stale traffic-forensics running status after reinstall
### What was done
- Reconciled traffic-forensics status reads against the current managed sidecar process so stale manifests from a crash, app restart, or installer update are marked stopped with `stopReason: "zombie-recovery"` instead of keeping the UI on packet collection.
- Added a regression test for stale `running: true` plus `sidecar.running: true` when the managed sidecar process is already gone.
- Documented the manifest lifecycle invariant for diagnostics UI status.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 17 tests.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: reconciles stale running manifests during status reads.
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: covers zombie status recovery without a live managed sidecar.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents that diagnostics status must use reconciled manifest state.
- Rollback: revert the three file changes above or restore the previous commit/worktree state before this task.

## 2026-06-19 - Task: Rebuild Windows installer with traffic-forensics zombie-status fix
### What was done
- Rebuilt the production Electron app and packaged the Windows NSIS installer containing the stale traffic-forensics status recovery.
- Verified the built main bundle contains the `zombie-recovery` status reconciliation path.
### Testing
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Codebase memory index was refreshed after the implementation and packaging checks.
### Notes
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact for installing the fixed app.
- `vpn-tunnel-enforcer/out/main/index.js`: generated build output includes the stale manifest recovery code.
- `.codebase-memory/graph.db.zst`: refreshed codebase-memory artifact.
- Rollback: install the previous installer artifact or rebuild from the prior worktree state before this task.

## 2026-06-19 - Task: Surface live packet-capture health in diagnostics UI
### What was done
- Added live traffic-forensics health to status reads: ETL size, live snapshot time, artifact count, sidecar event counts, sidecar data-event counts, and explicit warnings when sidecar is running without TCP/DNS/WFP data.
- Expanded the diagnostics card so the UI shows `pktmon`, live snapshot, sidecar, and artifact health next to packet collection status.
- Added sidecar heartbeat/provider polling events so a running-but-silent PowerShell sidecar is visible instead of looking healthy by implication.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 18 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Codebase memory index was refreshed after the UI/health changes.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: computes live forensic health from artifacts and `events.ndjson`.
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: covers health reporting when sidecar has only lifecycle events.
- `vpn-tunnel-enforcer/src/renderer/components/DiagnosticsCard.tsx`: displays packet-capture health in the UI.
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.ps1`: writes heartbeat/provider polling health rows.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents the live health requirement.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the UI health surface.
- `.codebase-memory/graph.db.zst`: refreshed codebase-memory artifact.
- Rollback: revert the listed files or rebuild from the prior worktree state before this task.

## 2026-06-19 - Task: Reconcile running traffic-forensics manifests after stop artifacts appear
### What was done
- Fixed the status path so a manifest cannot keep reporting `running: true` once stop artifacts such as `pktmon-stop.txt`, `pktmon-stop.ps1`, or `pktmon-trace.*` exist.
- Added a regression test for the exact contradiction seen in the installed app: `running: true`, sidecar stopped, packet monitor stopped, and stop artifacts present.
- Documented stop-artifact reconciliation as a required diagnostics invariant.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 19 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified the built main bundle contains `status-reconciled-stop`.
- Codebase memory index was refreshed after the stop-artifact reconciliation change.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: reconciles stale running manifests using stop artifacts during status reads.
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: covers stop-artifact reconciliation.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents that stop artifacts override stale `running: true`.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the stop-artifact reconciliation fix.
- `.codebase-memory/graph.db.zst`: refreshed codebase-memory artifact.
- Rollback: revert the listed files or rebuild from the prior worktree state before this task.

## 2026-06-19 - Task: Add sidecar warmup grace period for diagnostics UI
### What was done
- Added a 30 second warmup window for newly started traffic-forensics sidecars so lifecycle-only startup events are shown as `warming up` instead of an immediate warning.
- Kept the warning after the warmup window when the sidecar is still running but has no TCP/DNS/WFP data events.
- Rebuilt the Windows installer with the warmup UI and health-status behavior.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 20 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified generated `out/main/index.js` and `out/renderer/assets/index-BJ5XmtU1.js` contain `sidecarWarmingUp`.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: reports `sidecarWarmingUp` and delays the no-data sidecar warning for 30 seconds.
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: covers both warmup silence and post-warmup warning behavior.
- `vpn-tunnel-enforcer/src/renderer/components/DiagnosticsCard.tsx`: displays sidecar `warming up` and preserves normal Russian UI text.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents the 30 second sidecar warning grace period.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the warmup fix.
- Rollback: revert the listed source/doc changes and rebuild the installer from the prior worktree state.

## 2026-06-19 - Task: Native real-time ETW sidecar (Rust/ferrisetw)
### What was done
- Added a native real-time ETW consumer `vpnte-etw-sidecar.exe`, built from the new Rust crate `vpn-tunnel-enforcer/native/vpnte-etw-sidecar/` (uses the `ferrisetw` crate over StartTrace/EnableTraceEx2/ProcessTrace + TDH parsing), replacing the PowerShell Event-Log poller as the primary source of normalized traffic events.
- CLI matches the existing integration contract: `--events <path> --session <id> --providers <csv>`. Subscribes to TCPIP, DNS-Client, WFP, Winsock-AFD, and WebIO and appends normalized NDJSON rows (categories tcp/dns/wfp/afd/webio) per `trafficForensics.ts`/`trafficForensicsSummary.ts`.
- Trace session uses a stable name `VPNTE-ETW` and reclaims any orphaned session before start (bounds orphaned kernel sessions to one despite TerminateProcess kills). DNS rows carry `queryName`/`queryResults`; TCP/AFD rows decode SOCKADDR/IN_ADDR blobs into the 5-tuple. 30s `health` heartbeat + `event-cap-reached` back-pressure guard; metadata only, never payloads.
- Wired packaging: `electron-builder.yml` ships the `.exe` next to `vpnte-etw-sidecar.ps1`; new `scripts/build-sidecar.mjs` + `npm run build:sidecar` (invoked by `dist*`, no-op with warning when Rust/Windows absent).
- Updated docs (`docs/traffic-observability-rfc.md` Phase 4 → implemented, README build section) and tests.
### Testing
- `cargo test --release` in the crate: 11 unit tests passed (provider/category mapping, GUID table, event/reason derivation, SOCKADDR IPv4/IPv6 parsing, arg parsing).
- Live admin smoke test on Windows Server 2022: real tcp/dns/afd data events captured (888+ data events incl. full TCP 5-tuples and resolved DNS names); verified orphan reclamation keeps a single `VPNTE-ETW` session across abrupt kills.
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 21 tests (added a synthetic tcp/dns/wfp NDJSON test asserting `sidecarDataEvents>0` and no warning).
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`; `vpnte-etw-sidecar.exe` is bundled in the install root.
### Notes
- `vpn-tunnel-enforcer/native/vpnte-etw-sidecar/`: new Rust crate (src/main.rs, src/classify.rs, Cargo.toml).
- `vpn-tunnel-enforcer/scripts/build-sidecar.mjs`, `package.json`: `build:sidecar` script wired into `dist*`.
- `vpn-tunnel-enforcer/electron-builder.yml`: bundles the native `.exe` (preferred over the `.ps1` fallback).
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`: synthetic native-event data-event test.
- The `.exe` is gitignored (like sing-box.exe/wintun.dll) and rebuilt from source via `npm run build:sidecar`.
- Rollback: revert the listed files and the `native/` crate, then rebuild.

## 2026-06-19 - Task: Rebuild installer with local Rust ETW sidecar binary
### What was done
- Installed/activated the Rust toolchain in the local user profile for this build session.
- Built `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` in release mode and copied the generated `vpnte-etw-sidecar.exe` into `vpn-tunnel-enforcer/resources/`.
- Rebuilt the Windows NSIS installer so the native Rust sidecar is bundled and preferred over the PowerShell fallback.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 21 tests.
- `npm.cmd run build:sidecar` passed and produced `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified `vpn-tunnel-enforcer/dist/win-unpacked/vpnte-etw-sidecar.exe` exists alongside the `.ps1` and `.cmd` fallback files.
### Notes
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`: generated native sidecar binary, intentionally ignored by Git.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the native sidecar.
- Rollback: delete `resources/vpnte-etw-sidecar.exe` and rebuild to package only the PowerShell sidecar fallback.

## 2026-06-20 - Task: Refresh from GitHub and rebuild ETW diagnostics installer
### What was done
- Pulled GitHub `main` through PR #4 (`ad62b72`), which adds rich ETW diagnostics to the diagnostics card and extends traffic-forensics health output.
- Rebuilt the native Rust ETW sidecar and the Windows NSIS installer from the refreshed codebase.
- Verified the generated renderer bundle contains the new ETW diagnostics UI fields and the unpacked app contains the native `vpnte-etw-sidecar.exe`.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 21 tests.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified `vpn-tunnel-enforcer/dist/win-unpacked/vpnte-etw-sidecar.exe` exists.
- Verified generated bundles contain `sidecarEngine`, `sidecarCategoryCounts`, `sidecarTopDomains`, and the ETW diagnostics UI text.
### Notes
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact from GitHub `main` `ad62b72`.
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`: regenerated native sidecar binary, ignored by Git.
- `progress.md`: records this local refresh/rebuild step.
- Rollback: reinstall the previous installer artifact or rebuild from the previous commit before PR #4.

## 2026-06-20 - Task: Refresh ETW noise filtering and rebuild installer
### What was done
- Pulled GitHub `main` through PR #5 (`7b9fd19`), which filters high-volume ETW rundown/data-path noise so the native sidecar does not exhaust the data-event cap immediately.
- Rebuilt the Rust `vpnte-etw-sidecar.exe` and the Windows NSIS installer from the refreshed codebase.
- Verified the rebuilt sidecar binary is present in both `resources/` and `dist/win-unpacked/`.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 21 tests.
- `cargo test --release` in `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` passed: 12 tests.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified the Rust sources contain `filteredNoise` heartbeat reporting and rundown/data-path filtering.
### Notes
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact from GitHub `main` `7b9fd19`.
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`: regenerated native sidecar binary with noise filtering, ignored by Git.
- `progress.md`: records this local refresh/rebuild step.
- Rollback: reinstall the previous installer artifact or rebuild from commit `ad62b72`.

## 2026-06-20 - Task: Refresh stale ETW data guard and rebuild installer
### What was done
- Pulled GitHub branch `devin/1781904822-stale-forensics-data` through commit `c7d7b96`, which prevents a previous app run's stale `events.ndjson` from appearing as live ETW diagnostics after restart/reinstall.
- Rebuilt the Rust sidecar and Windows NSIS installer from the refreshed codebase.
- Verified the generated main bundle contains the stale-session health guard and the unpacked app still includes the native sidecar.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 22 tests.
- `cargo test --release` in `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` passed: 12 tests.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified `vpn-tunnel-enforcer/dist/win-unpacked/vpnte-etw-sidecar.exe` exists.
### Notes
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact from commit `c7d7b96`.
- `vpn-tunnel-enforcer/resources/vpnte-etw-sidecar.exe`: regenerated native sidecar binary, ignored by Git.
- `progress.md`: records this local refresh/rebuild step.
- Rollback: reinstall the previous installer artifact or rebuild from commit `7b9fd19`.

## 2026-06-20 - Task: Add manual traffic-forensics restart button
### What was done
- Added a Diagnostics card button `Перезапустить сбор` that forces the current traffic-forensics capture to stop and then starts a fresh session using the previous mode/target.
- Exposed a new `restart-traffic-forensics` IPC path through main, preload, and the renderer API.
- Restored the Diagnostics card source text to valid UTF-8 while adding the new control.
- Rebuilt the Windows NSIS installer with the button and native Rust sidecar.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 22 tests.
- `cargo test --release` in `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` passed: 12 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed and produced `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Verified generated bundles contain `restart-traffic-forensics`, `restartTrafficForensics`, and `Перезапустить сбор`.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: adds manual restart helper.
- `vpn-tunnel-enforcer/src/main/index.ts`: registers the restart IPC handler.
- `vpn-tunnel-enforcer/src/preload/index.ts`: exposes `restartTrafficForensics`.
- `vpn-tunnel-enforcer/src/renderer/App.tsx`: updates the renderer API type.
- `vpn-tunnel-enforcer/src/renderer/components/DiagnosticsCard.tsx`: adds the button and refreshes status after restart.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing the UI restart control.
- Rollback: revert the listed source files and rebuild the installer.

## 2026-06-20 - Task: Fix locked traffic-forensics cleanup aborting capture start
### What was done
- Analyzed `vpn-tunnel-enforcer-diagnostics-2026-06-19T21-52-06-890Z.zip` and confirmed the visible `pktmon: EBUSY ... rmdir` error was caused by old locked session directories being pruned during a new capture start.
- Changed old session pruning to best-effort cleanup so a locked historical `pktmon.etl` is logged as cleanup debt but no longer aborts a new `pktmon` capture.
- Made diagnostics export re-check the latest manifest after copying the traffic-forensics tree and explicitly include the referenced latest session directory when it exists, preventing `latest-session.json` from pointing at a missing folder in ZIPs.
- Updated the sidecar build script so it finds the standard rustup cargo path under the user profile even when `.cargo\bin` is not on PATH.
- Rebuilt the Windows NSIS installer with the cleanup fix, diagnostics export consistency fix, manual restart button, and native Rust ETW sidecar.
### Testing
- `npm.cmd test -- trafficForensics.test.ts systemDiagnostics.test.ts speedTest.test.ts` passed: 3 files, 22 tests.
- `C:\Users\Redmi\.cargo\bin\cargo.exe test --release` in `vpn-tunnel-enforcer/native/vpnte-etw-sidecar` passed: 12 tests.
- `npm.cmd run build` passed.
- `npm.cmd run dist:win` passed; build output confirmed native sidecar was rebuilt and copied before packaging.
- Verified `vpn-tunnel-enforcer/dist/win-unpacked/vpnte-etw-sidecar.exe` exists and the generated bundles contain `failed to prune old traffic-forensics session`, `restart-traffic-forensics`, and `Перезапустить сбор`.
### Notes
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`: makes old session pruning non-fatal and ensures exported diagnostics include the latest referenced session directory.
- `vpn-tunnel-enforcer/scripts/build-sidecar.mjs`: resolves cargo from the rustup user profile path when PATH does not contain cargo.
- `vpn-tunnel-enforcer/docs/traffic-observability-rfc.md`: documents cleanup and ZIP consistency invariants for traffic forensics.
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`: rebuilt installer artifact containing this fix.
- Rollback: revert the listed source files plus the previous manual restart button changes if needed, then rebuild `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.

## 2026-09-12 - Task: Support mobile hotspot and tethering without DNS deadlocks or probe failures
### What was done
- Investigated and resolved why VPNTE failed on mobile phone hotspot and USB tethering while other clients (Happ) worked:
  1. Converted remote DNS servers to IP literals (e.g. `1.1.1.1` for Cloudflare, `8.8.8.8` for Google) with TLS SNI retention in `tunController.ts`, removing dependency on cellular carrier DNS bootstrap.
  2. Removed private RFC1918 CIDRs from Wintun `route_exclude_address`, routing all LAN traffic into TUN and handling private IP bypass via sing-box `route.rules` placed strictly AFTER `{ protocol: 'dns', action: 'hijack-dns' }`, preventing DNS leaks to mobile gateways.
  3. Added an outbound allow rule for `process.execPath` in `firewallKillSwitch.ts` under `DefaultOutboundAction=Block`.
  4. Increased `TUNNEL_PROBE_URL_TIMEOUT_MS` from 4000ms to 8000ms in `serverPicker.ts` with retry logic to handle cellular jitter and avoid premature 11s tunnel restart loops.
  5. Preserved IPv6 binding (`ms_tcpip6`) on tethering and cellular adapters in `physicalAdapterLockdown.ts` by inspecting adapter names, descriptions, gateway subnets, and CLAT default routes, preventing 464XLAT breakage.
  6. Avoided TUN adapter alias collisions with USB RNDIS devices by implementing dynamic alias resolution in `tunAdapter.ts`.
  7. Added `udp_fragment: true` to SOCKS outbounds in `tunController.ts`.
### Testing
- `npm run typecheck` (`tsc --noEmit`): passed with 0 errors.
- `npm test`: 96 test suites passed, 924 passed, 3 skipped.
- `npm run build`: built main, preload, and renderer bundles cleanly.
### Notes
- Files modified: `tunController.ts`, `firewallKillSwitch.ts`, `physicalAdapterLockdown.ts`, `tunAdapter.ts`, `serverPicker.ts`, `connectionPlanner.ts`.
- Tests added/updated: `tunAdapter.test.ts`, `tunControllerConfig.test.ts`, `firewallKillSwitchValidation.test.ts`, `physicalAdapterLockdownSource.test.ts`, `serverPickerTunnelProbe.test.ts`.

## 2026-09-13 - Task: Fix Kimi Desktop project chats, stuck Dashboard warning, and Gemini split-session detection
### What was done
- Researched via Sentinel multi-agent swarm and resolved three interacting network and UI issues:
  1. **R1 (Kimi Desktop Project Chats)**: Added dedicated Inbound and Outbound allow rules for both IPv4 (`127.0.0.0/8`) and IPv6 (`::1/128`) loopback in `firewallKillSwitch.ts`, preventing WFP `DefaultOutboundAction=Block` from dropping Happy Eyeballs localhost sockets. Added direct-out and direct DNS routing in `smartRoute.ts` for Moonshot AI / Kimi domains (`.kimi.com`, `.kimi.ai`, `.moonshot.cn`, `.volces.com`, `.aliyun.com`, `.trustdecision.com`) to bypass domestic Chinese IP geo-blocking of datacenter VPNs. Hardened `getProxyOwnerProcesses` in `tunController.ts` to capture `xray.exe`, `happd.exe`, `Happ.exe`.
  2. **R2 (Dashboard Stuck Warning & Watchdog Recovery)**: Decoupled watchdog confirmation in `tunController.ts` via `hasRecentWatchdogConfirmation` to check real traffic activity (> 1024 B/s download/upload) and probe confirmation, immediately suppressing failure counts and invoking `markProxyRecovered()`. Expanded `ipMonitor.ts` with multi-provider endpoints (`cloudflare`, `ipify`, `icanhazip`, `myip`) with racing and failover under HTTP 429 rate limits. Added self-healing in `App.tsx` and `Dashboard.tsx` (`isProxyActuallyDown`) to clear stale `proxyDown` flags when traffic is actively flowing.
  3. **R3 (Gemini "Unusual Traffic" & Google Split-Session Leak)**: Pinned all Google and Gemini domains (`GOOGLE_AND_GEMINI_PINNED_SUFFIXES`) to `proxy-out` and `dns-remote` strictly before RU domain and `geoip-ru` rules in `smartRoute.ts`, preventing Google Global Cache (GGC) nodes inside Russia or maps from splitting active Google sessions. Intercepted STUN UDP ports 19302 and 3478 to prevent WebRTC leaks.
### Testing
- `npm run typecheck` (`tsc --noEmit`): 0 errors.
- `npm test`: 98 test suites passed, 950 tests passed, 3 skipped, 0 failures.
- Added tests: `src/main/ipMonitor.test.ts` (10 tests), `src/main/watchdogTrafficRecovery.test.ts` (10 tests).
- `npm run build`: built cleanly in 3.67s without dynamic bundle require errors.



## 2026-09-29 — WP-1: Secrets, IPC, and trusted boundary
### What was done
- Added a process-wide Electron IPC trust boundary installed before any `ipcMain.handle` registration. Every invoke now requires the main renderer frame, an exact development origin or the packaged `file://.../renderer/index.html`, and a bounded plain structured-clone payload. Subframes, hostile file pages, foreign origins, dangerous prototypes, cyclic payloads, excessive depth/size, and unsupported values fail closed.
- Added a `safeStorage`-backed `SecretRef` format and migrated persisted server-profile `outbound` and `sourceUri` values without changing the in-memory `ServerProfile` contract. Migration builds the complete encrypted replacement before committing it, preserves a one-time pre-migration backup when a real store file exists, records completion metadata, and leaves the legacy store unchanged on injected encryption failures.
- Applied the same secure-storage policy to settings fields that can contain raw keys, subscription links, or complete cached outbounds (`directVpnInput`, `directVpnCachedInput`, `directVpnCachedSource`, `directVpnCachedProfiles`). Production refuses plaintext persistence when OS encryption is unavailable; the test-only cipher is gated by `NODE_ENV=test` and is never a production fallback.
- Removed the duplicate plaintext `electron-store` instance from `serverPicker.ts`; profile reads/writes now share one encrypting facade with server groups, config import/export, and tunnel startup.
- Removed the unused renderer-facing `connection-history:add` mutation channel and added strict runtime validation for notification preference patches.
- Made runtime binary staging fail closed when the privileged runtime directory cannot be verified as admin-only. No sing-box/Wintun/Cronet file is copied after ACL verification fails.
- Hardened the external-proxy control boundary: strict loopback `Host`/port validation prevents DNS rebinding; control-token files receive protected Windows ACLs and are deleted if ACL application fails.
- Moved subscription HWID, device metadata, and fingerprint-bearing User-Agent values out of curl argv. Curl reads all subscription headers through stdin (`-H @-`), so WMI/process listings no longer disclose the stable device identity.
- Added an effective renderer `<meta>` CSP for packaged `file://` builds and explicitly enabled Chromium sandboxing alongside context isolation and disabled Node integration.
- Added a final recursive text/JSON secret-redaction pass immediately before diagnostics compression, covering copied manifests and future staged artifacts that might otherwise bypass source-specific redactors.
- Added explicit warnings before single-key, batch-key, proxy-list, and full-config exports. Clipboard exports are cleared after 60 seconds only when the clipboard still contains the exported secret, so newer user content is never destroyed.
- Added focused tests traced to AT-01-001…011: atomic migration/rollback, safeStorage fail-closed behavior, diagnostics final scan, hostile sender/origin, generic malformed IPC payloads, DNS-rebinding Host headers, packaged CSP, sandbox parity, export/clipboard cleanup, and property-based secret redaction.

### Verification
- `npm run typecheck`: passed.
- Focused WP-1 and adjacent regression suites: passed, including profile/group refresh, profile switching, VPN parser regressions, IPC channel contract, notification preferences, connection history, secure-store rollback, CSP/sandbox, diagnostics redaction, clipboard cleanup, and 500 property-based redactor cases.
- Full `npm test` on Linux: 1122 passed, 12 skipped, 43 failed. The failure count is identical to the pre-WP-1 baseline; failures remain in Windows-only PowerShell/ACL/ETW/pktmon/sing-box smoke suites and seven existing live-server suites that cannot load in this environment. WP-1 introduced no additional full-suite failures.
- `python3 docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC 927/927, F 210/210.
- Windows L3 acceptance remains required for real DPAPI persistence, NTFS ACL read-back, WMI argv inspection, packaged CSP smoke, and diagnostic ZIP scanning on OS-W11-24H2.

### Rollback and chronology
- Reverting this WP-1 commit restores plaintext profile/settings persistence, per-module unguarded IPC registration, argv subscription headers, response-header-only CSP, and warning-only runtime ACL behavior.
- The `*.pre-safe-storage-v1.bak` files are intentionally never deleted automatically. They allow recovery after a migration fault but contain legacy plaintext secrets and should be removed by a future verified cleanup step only after successful Windows acceptance.

## 2026-09-29 — WP-3: Firewall baseline, adapters, DNS, and boot recovery
### What was done
- Corrected kill-switch normalization: missing, undefined, malformed, and legacy-absent values now remain OFF; only explicit `true` enables the global firewall policy.
- Made firewall activation transactional at the manifest boundary. If durable manifest commit fails after rules/default-block were applied, VPNTE immediately restores the captured profile defaults and removes its rules; a manifest-less Block state is no longer reported as success.
- Reworked baseline rollback into independent named steps. HKCU Internet Settings, HKCU Environment, HKLM Connections, and WinINet notification all continue after an earlier failure; every failure is reported and the manifest remains for retry until all steps succeed.
- Corrected packaged boot-recovery path to the actual `extraResources` destination (`process.resourcesPath/vpnte-recover.ps1`). The scheduled-task action uses UTF-16LE `-EncodedCommand`, eliminating nested quoting failures for Program Files paths. Registration failures are visible in logs, clear the process guard, and can be retried; concurrent settings operations cannot register duplicate tasks.
- Restricted SYSTEM recovery to a single canonical ProgramData location. Recovery validates protected ACL, owner SID, and write-capable ACEs before loading a manifest; all AppData and cross-user profile scanning was removed.
- Hardened ProgramData manifest persistence before every write using the verified admin/SYSTEM-only directory policy. A failed ACL check or write is fatal instead of a warning, so SYSTEM never consumes an untrusted fallback manifest. userData remains diagnostic-only and is no longer authoritative for rollback.
- Replaced hard-coded `Ethernet 5`/`VPNTE-TUN` cleanup with driver-identity discovery. Boot recovery removes only adapters whose InterfaceDescription identifies Wintun, preventing deletion/disable of a physical NIC with a colliding alias.
- Changed physical-adapter lockdown on an empty adapter set from false success to explicit `applied: false`; no transition settings or manifest are changed in that branch.
- Added strict app/IP exception validation. IP/CIDR masks are bounded for IPv4/IPv6; app exceptions require an existing readable `.exe` and persist its canonical path; equivalent duplicates are rejected.
- Serialized exception mutations and synchronized a changed exception set with an already-active firewall policy. Failed live application restores the previous in-memory and persisted set, so UI/scheduler races cannot silently lose or partially apply updates.
- Fixed DNS replace-import referential integrity: when the imported active ID is absent, selection is reset to an existing imported DNS profile (or null) instead of retaining a dangling deleted ID.
- Updated source and behavioral tests for authoritative ProgramData recovery, encoded task registration, explicit kill-switch defaults, IP/CIDR/app-path validation, config import, rollback continuation, and existing firewall validation.

### Verification
- `npm run typecheck`: passed.
- Focused WP-3 suites: 10 files / 91 tests passed.
- Full Linux run: 1139 passed, 12 skipped, 43 failed. The same 43 pre-existing Windows-only/fixture failures remain; WP-3 added no new full-suite failures.
- Required Windows L3 matrix remains: OS-W10-22H2, OS-W11-23H2, OS-W11-24H2 plus NET-FLAP and NET-IPV6-ONLY, including pktmon/external leak oracle, SYSTEM reboot recovery, real NTFS ACL abuse, adapter hot-plug, and injected partial rollback.

### Rollback and chronology
- This commit follows WP-1 commit `8f77f19` and is intentionally isolated so firewall/recovery behavior can be reverted independently.
- Reverting restores the old default-on normalization bug, AppData SYSTEM manifest search, hard-coded adapter deletion, nested schtasks quoting, fail-open ProgramData writes, and sequential rollback abort behavior.

## 2026-09-30 — Merge PR #13: Harden VPN recovery, firewall transactions, and secret boundaries
### What was done
- Merged GitHub PR #13 (`genspark_ai_developer` -> `main`), integrating the complete security change-sets across WP-1 and WP-3.
- Trusted recovery storage: all recovery manifests and intermediate scripts are isolated to `%ProgramData%\VPNTE\manifests`, validated against strict schema, restricted to SYSTEM (`S-1-5-18`) and Administrators (`S-1-5-32-544`), and protected against reparse-point / symlink hijacking.
- Transactional firewall policy: manifests are committed in a `prepared` phase before changing outbound actions or adding rules; any failed step triggers immediate rollback and compensation.
- Strict recovery safety: `vpnte-recover.ps1` maintains fail-closed behavior (`DefaultOutboundAction Block`) if `strictMode` was active, refusing to unblock traffic until explicit user action.
- Secret export consent: native confirmation dialogs in main process for single-key, bulk-key, and proxy exports; removed plaintext URIs from IPC return values; implemented 60s fingerprint-checked clipboard auto-clear in main.
- IPC import boundary: domain routing and configuration file imports require native open-dialog selection with one-time capability tokens, preventing unprivileged renderers from reading arbitrary host paths.
- Windows platform compatibility: resolved Node 24 `util.isObject` compatibility for `sudo-prompt` in `admin.ts`, cross-platform path separators in `bootRecoveryRegistration.test.ts`, and mocked `recoveryManifest` in `granularKillSwitch` tests to prevent unmocked elevated executions during unit testing.

### Verification
- `npm run typecheck`: passed with 0 errors.
- `npm test`: 150 test suites passed, 1413 tests passed, 0 failed, 10 skipped.
- `npm run build`: built main, preload, and renderer production bundles cleanly in 3.17s.
- `npm run test:vpn-profiles`: 12/12 profile parsing checks passed.
- `python docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC 927/927 (100%), F 210/210 (100%).

## 2026-09-30 — WP-4 / F-064: Explicit subscription refresh failures
### What was done
- Failed subscription fetches now return `ok: false` with the original error through `groups:refresh`, so the existing renderer error branch displays the failure and automatic refresh counts it as failed.
- Empty subscription responses also return an explicit error instead of reporting a successful refresh with zero changes.
- Saved profiles and the active profile remain unchanged on failure; attempt/error metadata is retained for diagnostics and retry scheduling.
- Added 11 regression cases traced to the failure-result subset of AT-04-007 / AC-SRV-SUB-001…006 / F-064: DNS/TCP/TLS/HTTP/timeout/parser failures, empty responses, partial multi-device fetch failure, IPC propagation, automatic counters, and a successful retry after failure.

### Verification
- Before the fix, `npm.cmd test -- src/main/serverGroupsRefresh.test.ts`: 11 new regressions failed, 13 existing tests passed.
- After the fix, `npm.cmd test -- src/main/serverGroupsRefresh.test.ts`: 24/24 tests passed.
- `npm.cmd run typecheck`: passed with 0 errors after correcting the typed test fixture.
- `npm.cmd test -- --reporter=dot`: 150 files passed, 2 skipped; 1424 tests passed, 10 skipped, 0 failed.
- `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` from `vpn-tunnel-enforcer`: exit 0, AC 927/927, F 210/210.
- The network boundary is mocked in these regressions. This scoped repair does not establish completion of the full WP-4 transaction, parser, fuzzing, or Windows acceptance matrix.

### Rollback
- Revert this change to restore the previous `ok: true` responses for failed/empty refreshes; no store migration or schema change was introduced.

## 2026-09-30 — WP-11: Electron 42 → 44 migration
### What was done
- Pinned Electron 44.4.3, electron-vite 5.0.0, electron-builder 26.15.3 and Node 24 types (24.13.3) in the app manifest and lockfile. This addresses F-166 and the Electron/toolchain subset of F-167; the rest of WP-11 is separate work.
- Replaced electron-vite's deprecated externalizeDepsPlugin with build.externalizeDeps, retaining the existing main snapshot banner and sandboxed preload bundle.
- Migrated secret clipboard handling to Electron 44's Promise-based read/write API and ClipboardItem types. Copy-key IPC acknowledges only a completed write; shutdown awaits cleanup. Serialized operations and ownership-bound timeouts preserve a replacement key's 60-second deadline, failed-write cleanup, and foreign clipboard data. Seven additional regressions cover asynchronous failures/delays and races (AT-01-008, AC-SRV-EXP-001…003, F-158).
- Added explicit prepare:electron hooks before dist targets because modern Electron downloads its runtime on demand. Added test:electron with isolated userData, actual production preload and actual IPC/security/secret-storage modules; no VPN runtimes, network settings or user clipboard are changed by this smoke harness.
- Reviewed upstream breaking changes for Electron 43/44 and electron-vite 5. References: https://www.electronjs.org/docs/latest/breaking-changes and https://electron-vite.org/guide/migration .
- Verified the user-downloaded electron-v44.4.3-win32-x64.zip against the npm package's upstream checksums: 158247567 bytes, SHA-256 790a355b684d5c7cc8dc3cdd8c4cca7c4b2d054685427c7554a956879a82e70b. The background installer also completed successfully and installed runtime 44.4.3.

### Verification
- npm.cmd run typecheck: exit 0, no errors; also executed by final build/packaging commands.
- npm.cmd test -- src/main/appLoggerRotation.test.ts src/main/xrayEngine.live.test.ts src/main/secretClipboard.test.ts src/main/serverKeyExportSecurity.test.ts: 34 passed, 1 skipped, exit 0.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 150 files passed, 2 skipped; 1431 tests passed, 10 skipped, 0 failed, exit 0. Earlier default-worker runs had an Xray timeout and an existing appLoggerRotation.test.ts stat/rename race; these failures are not concealed or treated as passes. The interrupted pre-download run was also not a successful validation.
- npm.cmd run test:electron: exit 0, 8 native smoke checks passed on Electron 44.4.3 / embedded Node 24.21.0: native safeStorage encrypted file round-trip; production contextBridge/sandbox; reload; invalid payload rejected before handler; unregistered WebContents rejected; navigated file origin rejected; development loopback parity; exact runtime version. Traces AT-01-001/003/004/007/010 for the corresponding regression subsets.
- npm.cmd run dist:win: final rebuild exit 0, native ETW sidecar built and NSIS packaged with Electron 44.4.3. Optional mksnapshot was absent and reported an explicit fallback warning; bundler and sidecar deprecation warnings remain.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927, F 210/210. git diff --check: exit 0.
- Final artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139144849 bytes, SHA-256 4B4C702EFBB5D1326F25BBFDE5D52C4C0482FA0F05CF5903DBAFBB196232BE1B, Authenticode NotSigned. Application version remains 1.1.22; no release was published or installed.
- Full Windows VM install/upgrade/uninstall matrix and active-tunnel acceptance were not run. Native clipboard/Win32 acceptance and cross-version DPAPI migration against an actual Electron 42 store remain separate from the native round-trip smoke. This does not claim completion of all WP-11 or all referenced AT tests. Normative docs were not edited.
- Automatic approval review rejected cleanup of known interrupted-download temporary directories outside the workspace with reason "blocked by policy"; those directories were left intact. Smoke harness directories under .tmp were removed successfully by the harness.

### Rollback
- Revert this migration commit and reinstall the app dependencies from its restored lockfile. No user-store schema or encrypted data format changed.

## 2026-09-30 — WP-3/WP-11: Localized SYSTEM breaks installer recovery read-back
### Finding and fix
- The installer screenshot showed `Recovery task read-back mismatch` after the registration call in vpnte-recover.ps1. Native ScheduledTasks inspection reproduced the localization: New-ScheduledTaskPrincipal -UserId SYSTEM returns UserId `СИСТЕМА` on this Windows installation. The old allow-list rejects that name even though NTAccount.Translate resolves it to S-1-5-18; the native startup trigger is MSFT_TaskBootTrigger.
- Resolve the principal account to its SID before read-back comparison. Only S-1-5-18 is accepted; an unresolvable account fails closed. Existing RunLevel, action executable/arguments, action count and startup-trigger checks remain mandatory. Registration errors still abort the installer.
- Added native PowerShell regression coverage of the actual production resolver/read-back condition using New-ScheduledTask CIM objects without registering or executing tasks. It accepts the native localized name, SYSTEM, NT AUTHORITY\\SYSTEM and S-1-5-18, and rejects 10 altered-principal/action/trigger cases. Traces the registration subsets of AT-03-002 / AT-11-001/007, AC-LEAK-RCV-001…004, F-043/F-150/F-203.

### Verification
- npm.cmd test -- src/main/bootRecoveryTaskReadBack.test.ts src/main/bootRecoveryRegistration.test.ts src/main/bootRecoveryScriptSource.test.ts src/main/eosInstallerCompatibility.test.ts: 4 files / 12 tests passed, exit 0. The initial harness exceeded Windows command-line length; embedding only the resolver fragment corrected the harness, then all native cases passed.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 151 files passed, 2 skipped; 1432 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927, F 210/210.
- npm.cmd run dist:win: exit 0; installer rebuilt with Electron 44.4.3. Source and unpacked recovery resource hashes match: 20D25BF66364EDF64AEB9455B63A3CD5F9BC543BA18C6EC285A8D248EA8EF849.
- Updated artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139145006 bytes, SHA-256 85E26D483780AE9961A369EEE08319BC76D03AA66564B398F4DFE9F6CE238420, Authenticode NotSigned. This replaces the installer from the preceding migration entry.
- git diff --check: exit 0. No real task was created/changed by the regression test, and no network recovery was invoked. Actual elevated installation and reboot acceptance await rerunning the rebuilt installer; this does not claim the full VM acceptance matrix passed.

### Rollback
- Revert this fix to restore the previous name-based comparison; no store schema, task action or recovery policy changed.

## 2026-09-30 — WP-3 / WP-0 regression: cancellation recovery and immediate UI feedback
### Evidence and changes
- At 23:16 MSK, app.log records refusal to start because `happ-tun` is active, followed by cancel-tun, baseline rollback command failures, and the warning shown in the user's screenshot. The full native error was lost behind the logger's truncation of a long EncodedCommand. Current native processes include Happ; no live network recovery was invoked during this investigation.
- A production rollback command generated with a minimal valid nine-value fixture is 10,482 characters. A harmless PowerShell payload of comparable length fails with exit 1 through the Windows shell and succeeds with exit 0 through direct execFile/spawn. The diagnostic did not execute the captured recovery script or modify network/registry settings; its temporary file under the app's .tmp was removed.
- Baseline PowerShell calls now use execFile directly. The already-elevated execElevated branch recognizes only the fixed generated PowerShell invocation and also bypasses cmd.exe; other shell commands and the existing non-elevated sudo-prompt path retain their semantics. Packaged startup requires elevation. Native stderr is reported before the log length limit, with the encoded snapshot omitted.
- Clarification to the initial explanation: startDirectVpnProtection starts baseline preparation before tunController checks competing TUNs. The retained snapshot can come from this same refused connection attempt, not necessarily an earlier connection. This ordering and recovery ownership policy were not changed.
- The cancellation button immediately shows a spinner and `Отменяем…` / `Cancelling…`, disables repeat clicks and keeps the global busy state until cleanup IPC returns, including across Dashboard remounts and intermediate stopped events. Success, recovery warnings and failures are visibly reported; failed cancellation does not claim the tunnel stopped.
- Connection generations now survive Dashboard remounts. Preparation checks the generation after each awaited lookup/settings save, and late start success/failure cannot overwrite a cancelled operation or initiate a start after cancellation.
- Traces: WP-3 AT-03-003/007/012 subsets, F-033, AC-LEAK-RCV-001…004 recovery-report subset; WP-0 AT-00-003/008 and F-021 cancellation/UI subsets. This scoped regression repair does not claim completion of either entire WP or their L3 acceptance matrix.

### Verification
- Initial targeted run: 2 UI tests failed because both the power button and cancellation button share the status label. The test queries were narrowed by aria-busy; no production behavior was changed to satisfy this query issue.
- With VPNTE_PWSH set to native powershell.exe: npm.cmd test -- src/main/admin.test.ts src/main/adminPowerShellTransport.test.ts src/main/systemNetwork.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/renderer/store.connectionBusy.test.ts src/renderer/AppSource.test.ts --reporter=dot --maxWorkers=4: 6 files / 70 tests passed, exit 0. Includes native script parsing, harmless native transport success/failure and real React DOM cancellation checks.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 153 files passed, 2 skipped; 1444 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210.
- npm.cmd run dist:win: exit 0, rebuilt NSIS installer with Electron 44.4.3. Existing optional mksnapshot fallback/bundler/sidecar warnings remain; the DOM test exposed an existing MacToast/framer-motion ref warning without a failed assertion.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139144754 bytes, SHA-256 7050457F3B7166205031CAD1257E1A5939E46CF8C74C1D130EA4167AB804004F. Version remains 1.1.22; no release published or live installation performed.
- Native transport tests run the production elevated branch with only the elevation check simulated; they execute harmless PowerShell on this Windows host. Actual elevated recovery of the user's retained manifest, live cancellation after installing this build and the full VM acceptance matrix remain unverified. The retained snapshot was not deleted. Normative documents were not edited.

### Rollback
- Revert this regression fix; no persisted store schema, snapshot format or ownership policy changed.

## 2026-09-30 — WP-3 / WP-0: native rollback array decoding and cancellation circle colour
### Finding and fix
- The repeated user scenario now logs `Invalid baseline recovery report` (23:38:44–23:38:58 MSK), rather than the earlier PowerShell launch failure. Native Windows PowerShell is 5.1.26100.9444.
- Added a regression that executes the production JSON decoding/report loop with only Restore-Snapshot replaced by a harmless effect stub. Before the fix, all ten cases fail: the report has one step instead of nine. Windows PowerShell ConvertFrom-Json emits the decoded array as one pipeline object; wrapping the assignment in @() adds another array layer.
- Assign the decoded array directly before foreach. Keep the strict nine-step/name/type report validation, independent failure collection, trusted manifest checks and snapshot retention rules. This fixes the actual protocol boundary rather than relaxing verification. Existing mocked command responses had hidden the native array shape.
- Ten native cases now verify all-success and each single failed step, including exact ordered step names and continuing after failure. Another native case executes production Restore-Snapshot/Get-Snapshot for DWord, String, ExpandString, QWord, Binary, MultiString, empty and absent values below a GUID-named HKCU test subtree; the subtree is deleted in finally. Real network registry keys, HKLM and the user's retained manifest are not touched. No test subtrees remain.
- The large power circle immediately switches to a distinct violet cancellation colour and matching glow/backdrop. Cancellation overrides connected/server-switch colours and hides their animations until cleanup finishes; the status text keeps theme-appropriate contrast. The colour returns to the normal state after cleanup. React DOM tests cover both a pending connection and a still-connected tunnel.
- Traces: AT-03-003/007/012 subsets, F-033, AC-LEAK-RCV recovery-report subset; AT-00-008 / F-021 cancellation visual feedback. Normative documents and recovery ownership policy were not changed.

### Verification
- With VPNTE_PWSH set to powershell.exe: npm.cmd test -- src/main/systemNetwork.test.ts src/renderer/pages/Dashboard.cancel.test.tsx --reporter=dot --maxWorkers=4: 2 files / 44 tests passed, exit 0. Includes native parser, production report-loop matrix and isolated native registry read-back.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 153 files passed, 2 skipped; 1456 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210.
- npm.cmd run dist:win: exit 0, rebuilt NSIS with Electron 44.4.3. Existing build/optional mksnapshot and MacToast ref warnings remain non-fatal. git diff --check: exit 0.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139144897 bytes, SHA-256 F50BD23408CFBCEC7C6EA0583178E3351EC677A209AC65351B95A5380D402BBA, Authenticode NotSigned. Supersedes the preceding same-version installer.
- Live recovery using the user's retained snapshot, visual acceptance in the installed app and full Windows VM acceptance remain unverified. No live VPN/network operation or installation was performed during this fix.

### Rollback
- Revert this fix; persisted snapshots and settings formats are unchanged.

## 2026-09-30 — WP-0 / WP-9: cancellation presentation polish
### Changes
- Per owner feedback, the visible `Отменяем…` label now appears only on the small cancellation button. The status paragraph is screen-reader-only while cancelling, preserving its polite live announcement; normal visible status returns after cleanup. The button remains disabled and shows its spinner until cleanup completes.
- Added two static violet rings, a soft halo and a restrained surface highlight around the large cancellation circle. Other state colours and the small warning-coloured button remain unchanged. No additional repeating animation was introduced.
- Extended the real React DOM regression to cover the visible button label, hidden live status during cancellation/remount and restored visible status after cleanup. Traces: AT-00-008 / F-021 and AT-09-009 subsets; no normative documents changed.

### Verification
- npm.cmd test -- src/renderer/pages/Dashboard.cancel.test.tsx --reporter=dot --maxWorkers=4: 1 file / 7 tests passed, exit 0.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 153 files passed, 2 skipped; 1456 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210.
- The compiled renderer stylesheet includes the cancellation ring rules and sr-only utility. Installed-app visual acceptance is not claimed; no live connection or installation was performed.
- npm.cmd run dist:win: exit 0, rebuilt NSIS installer with Electron 44.4.3. Existing build warnings and the MacToast/framer-motion ref warning remain non-fatal. git diff --check: exit 0.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139144989 bytes, SHA-256 1B2420B66299738C559FCF30F1B3583E7EF30FE511EC1044107B36F407B0673C, Authenticode NotSigned. Supersedes the preceding same-version installer.

### Rollback
- Revert this scoped UI change; connection lifecycle and persisted settings are unchanged.
## 2026-10-01 — WP-2 / WP-3: failed connection, native adapter identity and startup hang
### Measured evidence
- app.log records the attempt from 00:00:08.380 to 00:01:25.194 MSK (76,814 ms). Xray reports ready at 00:00:18.058; at 00:00:20.111 the async startup callback rejects with `VPNTE TUN driver identity mismatch`. The application logs an unhandled rejection instead of completing the attempt. The user closes the app at 00:01:19.949; cleanup then settles the pending start. This is a hung validation path, not a measured 77-second server handshake.
- At 00:00:35.760, the live-exception update and compensation report unknown, matching the screenshot. Native in-memory execution of the production script fails before the fix for empty and multi-rule lists (2/3 cases); its extra @() wrapper nests ConvertFrom-Json arrays. The previous log omitted the underlying script errors, so it cannot independently prove which policy produced this particular warning. New logging preserves bounded native errors with EncodedCommand omitted.
- A read-only adapter inventory shows `sing-tun Tunnel` as InterfaceDescription and `Wintun Userspace Tunnel` as DriverDescription, with a SWD/Wintun PnP identity. The failed VPNTE adapter had already disappeared; these local metadata observations and native fixtures explain why matching the friendly interface description is incorrect. Native production ownership verification rejects the valid sing-tun/Wintun fixture before the fix (1 failed positive case).

### Changes and scope
- Match DriverDescription and PnPDeviceID when recording TUN ownership, keeping exact alias, GUID and IPv4 /30 checks. Boot recovery applies the same driver/device checks after selecting the exact recorded GUID; an existing device with mismatched identity preserves the ownership journal and reports a warning. Foreign adapters remain untouched.
- Decode the firewall rule list directly, retaining strict rule/filter/set read-back, compensation and durable pending-journal semantics. No protection validation was relaxed.
- Catch failures throughout the asynchronous startup poll callback, wait for the parallel firewall transaction before rollback, independently attempt process/Xray/adapter/firewall cleanup, then settle the connection with failure even if cleanup or a status listener throws. Prevent overlapping native polls. Add ownership-phase timing and replace the misleading intermediate claim that VPN continues without required kill-switch protection.
- Real callback tests cover successful start, required firewall failure, unready TUN, probe failure, ownership failure during a pending firewall transaction, all cleanup failures, a throwing status listener and overlapping ticks. Native PowerShell tests use fake cmdlets/storage exclusively.
- Traces: AT-02-004/005 and AT-03-002/008/009 subsets, AC-CONN-MODE-004.3, F-131, F-031 and F-204 regression boundaries. This scoped repair does not claim completion of all WP-2 or full Windows L3 acceptance. Normative documents and owner decisions were not changed.

### Validation
- Initial typecheck found an inferred Promise<never> in the test stub; an explicit Promise<void> fixed it. Initial full runs exposed one whitespace-dependent source assertion after adding try/catch indentation; it now ignores indentation, with behavior covered by the actual callback tests.
- Native full-script boot harness initially exceeded Windows command-line limits and used a Unix-only ProgramData fixture. It now runs its mocked harness from a unique app .tmp file and uses the real known-folder value with all I/O/network boundaries still mocked. Temporary harness files/directories were removed.
- With VPNTE_PWSH=powershell.exe: npm.cmd test -- src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryBehavior.test.ts src/main/recoveryManifestStorage.test.ts src/main/firewallTransactions.test.ts src/main/tunControllerStartup.test.ts src/main/auditFixesRegression.test.ts --reporter=dot --maxWorkers=4: 6 files / 79 tests passed, exit 0.
- npm.cmd run typecheck: exit 0, no errors.
- npm.cmd test -- --reporter=dot --maxWorkers=4: 154 files passed, 2 skipped; 1477 tests passed, 10 skipped, 0 failed, exit 0.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210. git diff --check: exit 0.
- No actual VPN connection, registry/firewall/adapter modification, installation or reboot was performed by this task. A fresh installed-app connection and its normal latency remain unverified; no connection-time guarantee is made. Read-only inspection currently sees another active Happ TUN, which must be considered separately when retrying.
- npm.cmd run dist:win: exit 0, Electron 44.4.3 NSIS rebuilt. Packaged main JS contains the driver/device checks, caught startup-failure path and ownership timing; packaged recovery script hash matches source: B96EFEF41BCE618AF3DAF455469437981D37D9E30DF6A19208BF48EE4C7F6C0C. The initial ASAR lookup used slash separators; using the archive's native Windows path confirmed its entry.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139145575 bytes, SHA-256 6835F8894A83FF345A6E685C137CCCF01911089EB62038F531FA5F2C5EF687E2, Authenticode NotSigned. Supersedes the preceding same-version installer. Existing optional snapshot/build warnings remain non-fatal.

### Rollback
- Revert this scoped regression repair; manifest schemas, firewall policies and saved settings formats are unchanged.
## 2026-10-02 — WP-2 / WP-3 / WP-7 / WP-8: phone hotspot detection and failure-path logging

### Evidence and acceptance boundary
- The latest installed-client attempt (16:59:37–17:01:12 MSK) started the local Xray SOCKS and TUN, but all four foreign HTTPS probes timed out repeatedly. Russian sites are eligible for direct-out under the user's Smart RU setting; their availability does not verify VPN egress. The user's ordinary-Wi-Fi comparison is accepted and does not need repetition.
- The physical uplink was MediaTek Wi-Fi attached to a Galaxy S24 Ultra network with a modern 10/8 hotspot DHCP subnet. The existing classifier returned isCellularOrTethering=false because it ignored the connected network profile and used device descriptions/legacy DHCP subnet patterns. IPv6 was already disabled in the pre-start snapshot: this classifier defect alone does not establish the cause of this attempt's egress failure.
- Read-only elevated inspection confirmed that the selected IPv4 VPN endpoint was excluded from TUN routing, MTU was already 1280, and sing-box proxy-out used the local Xray SOCKS. The short last Xray run contained 27 dial attempts and one protocol tunneling-request record; this does not prove an HTTPS response. The sampled sing-box connection-refused records coincide with user stop/adaptive restart and cannot be treated as the initial cause. Exact upstream TCP/TLS/REALITY failure remains unconfirmed in the old evidence.

### Changes
- Read connected network profiles and IPv4 gateways in the physical adapter snapshot. Recognize modern phone profiles (including Galaxy) without treating every private 10/8 network as tethering. Keep the existing mobile IPv6 exception and the recorded pre-existing IPv6 state. Profile names are used transiently and are not stored in manifests or diagnostic messages. Strictly validate candidate subnet IPs.
- Log classifier method, original IPv6 state, resolver source/count and default-route count; log bootstrap DNS methods, safe error codes, durations and fallback results. Explicitly label Xray readiness as local SOCKS readiness with remoteVerified=false.
- For failed foreign HTTPS races, preserve fixed target identifiers, response status, safe error codes and elapsed time, including the existing literal-IP target that does not need DNS. Cancel remaining requests after a winner and discard late results after a session change.
- Before returning a failed health check to adaptive recovery, collect bounded (256 KiB each) Xray/sing-box log summaries from the current session. Record unreadable/missing logs honestly, count protocol progress separately from successful egress, and count timeout/reset/access/TLS/REALITY/local-SOCKS failures without copying addresses or messages.
- Compare TCP CONNECT to the selected VPN endpoint through mixed-direct-in with certificate-validated HTTPS to the existing literal-IP reflector through Xray SOCKS, bypassing TUN and DNS. Each additional path probe has a 3-second overall deadline; late sockets are closed. Rate-limit collection to one per 30 seconds per session and suppress stale publication. Assessments describe measured path differences, never assert carrier/DPI blocking. Diagnostics do not mark a failed health check successful.
- Bound the Xray stderr accumulator to its last 64K characters. Traces: AT-02-006, AT-03-006, AT-07-002 and AT-08-001 subsets; F-207 buffer boundary. This is a scoped hotspot/observability repair, not complete Windows L3 or whole-WP acceptance. Normative documents and code-signing decisions were not changed.

### Validation and artifact
- Initial focused run exposed a missing default export in a TLS test mock and typecheck exposed a variadic mock signature; both were corrected. A later assessment typecheck and a filesystem mock default export were also corrected before final validation.
- npm.cmd test -- src/main/networkFailureDiagnostics.test.ts src/main/physicalAdapterLockdownSource.test.ts src/main/serverPickerTunnelProbe.test.ts src/main/xrayDns.test.ts src/main/xrayDnsNative.test.ts src/main/xrayEngine.test.ts src/main/xrayRuntimeLifecycle.test.ts --reporter=dot --maxWorkers=4: 7 files / 67 tests passed at that revision.
- Initial full run: 1896 passed, 4 failed native PowerShell tests by timeout, 10 skipped. npm.cmd test -- src/main/firewallExceptionReadback.test.ts src/main/recoveryManifestStorage.test.ts src/main/recoveryPsProtocol.test.ts src/main/systemSnapshot.test.ts src/main/networkFailureDiagnostics.test.ts src/main/appLoggerRedaction.test.ts --reporter=dot --maxWorkers=2: all 6 files / 166 tests passed. Production timeout thresholds were not relaxed.
- npm.cmd test -- src/main/physicalAdapterHotspot.test.ts --reporter=dot: 3 behavior tests passed, including both original IPv6 states and ordinary Wi-Fi with the same 10/8 gateway.
- Final npm.cmd run typecheck: exit 0. Final npm.cmd test -- --reporter=dot --maxWorkers=4: exit 0, 176 files passed / 2 skipped, 1905 tests passed / 10 skipped / 0 failed.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py: exit 0, AC 927/927 and F 210/210. git diff --check: exit 0.
- npm.cmd run dist:win: exit 0; Electron 44.4.3 NSIS rebuilt. ASAR inspection confirmed five new classifier/diagnostic/bootstrap/readiness markers in the packaged main bundle. Existing optional mksnapshot and bundling warnings remain non-fatal.
- Artifact: vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe, 139159588 bytes, SHA-256 0EE7F14562CF300AC1C9624A1DCE0026C3121ACA4F2653885031A71F39D06E90, Authenticode NotSigned. Supersedes the previous same-version installer. No installation, actual VPN connection, adapter/firewall mutation or live hotspot acceptance was performed. A retry with this build is required to confirm availability or capture the new failure-path event.

## 2026-10-02 — WP-4 / WP-2: Happ comparison identifies lossy Xray configuration handling

- Owner confirms Happ works on the same phone uplink where VPNTE fails. Read-only comparison found the installed Happ Xray binary and VPNTE bundled Xray binary have identical SHA-256 hashes and both report version 26.7.28, commit 5ca6f4b. The client configuration path is therefore the next repair target; earlier recommendations to change provider/server were premature.
- Fetched the selected Norway profile's subscription with the existing VPNTE PC subscription identity, without changing persisted application state or publishing credentials. Its Xray JSON sets `norwayvless1` REALITY fingerprint to `firefox` and mux to `{enabled:true, concurrency:6, xudpConcurrency:4, xudpProxyUDP443:'reject'}`. The persisted VPNTE profile has `chrome`. `applyClientDeviceToOutbound` overwrites the imported fingerprint; `xrayOutboundToProfiles` omits Xray mux, and `toXrayOutbound` rebuilds the outbound without restoring mux.
- The provider's `bridgenorwayvless1` uses `streamSettings.sockopt.dialerProxy = LOOP-L1-BRIDGE`, backed by loopback outbounds and routing balancers. The current importer discards that chain and the runtime compiler does not restore it. Consequently a VPNTE profile named as a bridge is currently a direct connection, so its Wi-Fi success does not verify the provider's bridge path.
- Happ documents JSON passthrough at https://www.happ.su/main/dev-docs/examples-of-links-and-parameters. VPNTE needs to preserve source TLS settings, mux, and the referenced outbound/routing dependencies while retaining its managed local listeners and traffic-isolation policy. Arbitrary passthrough of provider listeners or direct application-routing exceptions is not proposed.
- Normative discrepancy recorded against `docs/01` section 3.4 and `docs/03` section 3.1 (preservation of imported uTLS/ALPN). The owner subsequently approved its repair and requested a broader Happ comparison. The implementation and checks below follow that approval. These confirmed defects do not establish which individual setting causes the hotspot stall or prove a repaired connection succeeds.

### Approved repair and extended comparison
- Preserve explicit source fingerprint/ALPN before device defaults and adaptive rotation; profile metadata now reports the actual fingerprint. Preserve native Xray outbound fields inside the encrypted outbound rather than translate away mux, XUDP, sockopt, XHTTP mode/extra and other stream settings.
- Compile the reachable provider connection graph with consistent outbound/balancer/virtual-inbound names: bridge dialer dependencies, loopback routes, VLESS/Hysteria helpers, fallback, observatory/burstObservatory and policy. Full composite JSON imports as one connection; the current authoritative response imports as 10 profiles. Independent outbounds retain only their own dependencies to avoid quadratic copies.
- Keep managed loopback listeners, application routing, DNS and isolation. Do not inherit provider global direct exceptions, API, listeners or file paths; reject missing/cyclic/unsupported dependencies and plain application fallback. Allow freedom only as a physical dialer of an encrypted VPN outbound. Fail closed on unmatched conditional virtual routes.
- Auto uses Xray for native JSON, with a clear refusal for forced sing-box. Health checks compile the same graph and attach physical probe detours only at leaves. Bootstrap every reachable hostname with bounded parallelism and cancellation. URI export refuses to silently drop the graph. Effective-configuration logging records fingerprint/mux/counts, while diagnostics redact the entire native payload.
- Additional findings recorded in `vpn-tunnel-enforcer/docs/happ-compatibility-audit-2026-10-02.md`: adaptive network identity conflates Wi-Fi and hotspot on one card; profile learning identity omits transport/REALITY/fingerprint/native graph; URI XHTTP/gRPC and some sing-box multiplex translation still differ. These are follow-up proposals, including the recorded TЗ-03 §2.3 discrepancy; they were not silently folded into the approved import repair.
- Traces: AT-04-001/002/006 and AT-02-002/005 subsets, F-051/F-052. No normative documents, active app settings, network, adapter or firewall state were changed.

### Verification and artifact
- `npm.cmd run typecheck`: exit 0; packaging also reran typecheck successfully.
- `npx.cmd vitest run src/main/nativeXrayCompatibility.test.ts src/main/vpnProfilesClientDevice.test.ts src/main/xrayEngine.test.ts src/main/tunControllerConfig.test.ts src/main/lifecycleCleanup.test.ts src/main/appLoggerRotation.test.ts src/main/xrayEngine.live.test.ts`: 7 files passed, 170 tests passed, 1 skipped, exit 0.
- Initial full `npm.cmd test -- --reporter=dot`: 1912 passed / 7 failed / 10 skipped, plus an unhandled harness error. Four extraction-harness failures were repaired to include the new startup dependencies; logger/live-core timeout cases passed in the focused rerun. Production timeout thresholds were not increased.
- Final `npm.cmd test -- --maxWorkers=4`: exit 0, 177 files passed / 2 skipped; 1923 tests passed / 10 skipped / 0 failed. Expected RootErrorBoundary stderr is not a failing test.
- `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC 927/927, F 210/210. `git diff --check`: exit 0.
- The synthetic full VLESS/Hysteria/bridge fixture passed the bundled Xray `run -test` in the permanent regression suite. A separate read-only inspection ran all 10 actual subscription documents through the current production import/compiler in memory, replaced secrets/addresses/URLs before temporary disk writes, then checked every structural copy with the bundled Xray: 10/10 passed, 10 imported profiles. Temporary inspection artifacts were removed. No real server connection was performed by these config checks.
- `npm.cmd run dist:win`: exit 0; Electron 44.4.3 NSIS rebuilt. ASAR inspection confirmed native payload, preserved source marker, namespaced balancers, effective configuration logging and connection-graph DNS bootstrap. Existing optional snapshot/bundling warnings remain non-fatal.
- Artifact: `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139163262 bytes, SHA-256 `ACAF462C12DCAF77A243FF5679657CA244F1C288ECA19574B3B6AC8152125873`, Authenticode NotSigned. Supersedes the preceding same-version installer. Installation and live hotspot L3 acceptance remain unverified.
- After installation, refresh the subscription: previously flattened stored profiles cannot reconstruct their lost native fields or bridge dependencies. Use Auto/Xray and a full provider configuration.

### Repair rollback
- Revert this scoped import/compiler repair and refresh the subscription with the chosen version. Older clients cannot use native graph metadata. No network ownership manifest format was changed.

### Rollback
- Revert this scoped repair. Persisted settings and manifest formats remain compatible. Diagnostic-only physical TCP probes contact only the selected VPN endpoint; reflector probes always use the VPN engine.

## 2026-10-02 — WP-10 / WP-4: approved Happ comparison follow-up

### Evidence and changes
- Owner reports the repaired client now works on the phone uplink and explicitly authorizes all remaining recorded findings, including the normative adaptive-key discrepancy. Fresh installed-client logs confirm preserved native JSON / firefox / mux with 19 outbounds, 5 balancers, 5 virtual routes at 20:09:24 MSK, TUN with kill switch at 20:09:30, and three successful tunnel probes at 20:09:55 (last 200 ms). The combined configuration repair succeeds; this does not identify a single causal setting or prove all Windows L3 leak criteria.
- Adaptive learning uses a versioned private HMAC of physical NLA profile/GUID, gateways and subnet plus canonical connection parameters, transport, REALITY/obfs, device/fingerprint and native graph. Ignore cosmetic fields, DHCP host addresses and IPv6 lockdown changes on dual-stack. Native reads are bounded to four seconds; unknown identity skips reuse and persistence. Recheck identity after the unchanged stable probe window, invalidate on network changes, and fence late reads/learning after cancellation or newer lifecycle state. Old keys expire automatically; TTL 30 days / maximum 24 records retained. No raw identity or credentials enter the learning log/store.
- Preserve XHTTP mode and nested extra through URI/VMess import, Xray conversion and export, including saved legacy transport.method. Remove the second URL decode that damaged literal percent escapes. Preserve explicit gRPC gun/multi independently of idle_timeout, reject conflicting/unknown modes. Auto chooses Xray for these Xray-specific transport settings; forced sing-box gives a clear refusal.
- Preserve explicit sing-box multiplex on VLESS/VMess/Trojan/Shadowsocks, normalize legacy mux, reject unsupported protocol combinations. Copy/file export automatically selects complete native JSON for graphs and JSON for multiplex-bearing sing-box profiles; retain managed graph boundaries and native main-owned secret-export consent. Bulk export becomes a JSON array when required; re-import preserves bridge/mux/balancers. Ordinary URI exports remain available.
- Traces: AT-10-007 / F-126 / F-128, AT-04-001/002/006, AT-02-004, AT-01-008 subsets. Normative docs and code-signing decisions were not changed. Full details in vpn-tunnel-enforcer/docs/happ-compatibility-audit-2026-10-02.md.

### Validation and artifact
- Focused command: `npx.cmd vitest run src/main/adaptiveBypass.test.ts src/main/adaptiveNetworkIdentity.test.ts src/main/transportCompatibility.test.ts src/main/nativeXrayCompatibility.test.ts src/main/tunControllerConfig.test.ts src/main/serverKeyExportSecurity.test.ts src/main/serverPickerSwitch.test.ts src/main/profileRotation.test.ts src/main/lifecycleCleanup.test.ts src/main/auditFixesRegression.test.ts --maxWorkers=4`: 10 files / 250 tests passed, exit 0. Includes real bundled Xray preflight for four XHTTP modes / two gRPC modes / exported bridge graph and bundled sing-box checks for four multiplex protocols. Native script behavior uses fake cmdlets only.
- Initial focused failures exposed a missing test import and a real double-decoding bug. Initial full run: 1958 passed / 12 failed / 10 skipped plus two errors; repaired the new cancellation generation guard and default/named child_process mock. Typecheck found a test parameter type and duplicate import, also repaired. Production verification thresholds/timeouts were not relaxed.
- Final `npm.cmd run typecheck`: exit 0. Final `npm.cmd test -- --maxWorkers=4`: 179 files passed / 2 skipped, 1972 tests passed / 10 skipped / 0 failed, exit 0 (105.12 s).
- `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC 927/927, F 210/210. `git diff --check`: exit 0.
- `npm.cmd run dist:win`: exit 0, Electron 44.4.3 NSIS rebuilt. Seven packaged-ASAR markers verified: NLA read, learning decision, v2 key, XHTTP extra, native JSON export, gRPC multi_mode, unsupported multiplex refusal. Existing optional snapshot/bundling warnings remain non-fatal.
- Artifact: `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139165276 bytes, SHA-256 `0200D166C2221072C7771F11BB87AA5C269EC4C94F3F9A844EC6912F2C088ED6`, Authenticode NotSigned. Supersedes the preceding same-version installer. This follow-up installer has not been installed or exercised on a live uplink by the agent; the user's working connection was not changed. Already refreshed native profiles require no subscription refresh for this follow-up.

### Rollback
- Return to the preceding native-graph repair build. Native profiles stay compatible; the preceding build does not reuse new v2 learning keys. No network ownership manifest format changed.

## 2026-10-02 — WP-10 / WP-0: remove cold network-identity imports

- Owner approved starting with the measured identity-reader regression. Replaced cold Get-NetAdapter / Get-NetConnectionProfile / Get-NetRoute module imports with three fresh read-only CIM queries, preserving visible/up/MAC-bearing physical adapter selection, NLA Name/InstanceID, GUID, active default gateways, v2 HMAC privacy and IPv4 preference. A failed query still produces unknown identity; bounded hidden process remains 4000 ms / 256 KiB. No cached network snapshot or helper queue dependency was added.
- Added a monotonic `Network identity read completed` event with reader/durationMs/known only. Regression tests exposed and fixed empty `.NextHop` expansion into `[null]`; profile-only and completely empty identities now have proper array semantics.
- Actual Windows read-only comparison with the previous HEAD reader: 2329→448 / 2270→429 / 2403→469 ms, 3/3 identical normalized identities on the current network, no raw topology printed/persisted. This is reader latency, not installed full-connect acceptance. Previous installed cycles were 9939 / 8504 ms; firewall awaits remain 3161 / 2867 ms. Full investigation and actual Happ control-path observations recorded in docs-factory8090/07-журнал-ускорения-lifecycle.md, stage 26.
- `npm.cmd run typecheck`: exit 0. Focused `npx.cmd vitest run src/main/adaptiveNetworkIdentity.test.ts src/main/adaptiveBypass.test.ts src/main/serverPickerSwitch.test.ts src/main/profileRotation.test.ts src/main/lifecycleCleanup.test.ts --maxWorkers=4`: 5 files / 122 tests passed, exit 0. Initial focused run had 2 gateway-empty failures, both repaired.
- Full `npm.cmd test -- --maxWorkers=4`: exit 0, 179 files passed / 2 skipped, 1981 tests passed / 10 skipped / 0 failed, 83.97 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC927/927 F210/210. `git diff --check`: exit 0. Normative docs unchanged.
- `npm.cmd run dist:win`: exit 0, typecheck repeated successfully; seven packaged-ASAR markers confirmed. Installer `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139165757 bytes, SHA256 `AAB87DB5754FEEB3429856F93F31A110AA1C11CBD79797B6F0C629022CAB00D1`, Authenticode NotSigned. Current network and installed client unchanged; live full-connect timing of this artifact remains unmeasured. Own temporary benchmark/test/build artifacts removed after recording results.

### Rollback
- Revert this scoped reader/timing change; the adaptive key format and stored profiles remain compatible. This restores the slower module-based identity read. No firewall or network ownership manifest format changed.

## 2026-10-02 — WP-0 / WP-2 / WP-6 / WP-7: repair route evidence, IP waves and early cancel

- Owner approved repairing the three installed-log findings. Latest installed cycles before this patch: connect 6872/5420/5449 ms, ordinary stop 3762/3694 ms, cancel 3402 ms. CIM identity is already 498/474/469 ms. The old /0-/1 route heuristic misreported a live TUN with 60 fragmented routes; 57 public-IP successes occurred in 10 s. Full measured phases recorded in lifecycle journal stage 27.
- Route evidence now uses trusted TUN ownership plus fresh CIM adapter/address checks and Windows-selected routes for three IPv4 canaries, without forcing the route's interface or sending packets. Unknown/invalid/late evidence fails closed. This is supporting route evidence, not full egress/IPv6 leak acceptance.
- One in-flight HTTP provider wave per owner; abort losers and old generations, with no result cache between completed waves; back off 429 providers. Post-start checks use four 2 s waits and route proof before one baseline adoption; rebaseline does not duplicate the immediate timer wave. A failed fresh baseline returns null and profile switching retries rather than publishing cached data as freshly verified.
- Early cancellation still awaits the startup owner/native compensation. Skip redundant runtime kill/wait only after fresh exit proof; errors retain kill/wait and all network rollback steps. Add runtime-stop-preflight timing; expected Xray firewall cancellation is info while real failure remains warn.
- Final `npm.cmd run typecheck`: exit 0. Focused 11-file command listed in stage 27: 192 tests passed; final baseline-specific two-file run: 15 passed. Full `npm.cmd test -- --maxWorkers=4`: exit 0, 181 files passed / 2 skipped, 2017 tests passed / 10 skipped / 0 failed, 106.28 s. Coverage checker: AC927/927, F210/210, exit 0. Initial failures and their resolution recorded in stage 27.
- Normative docs and network ownership formats unchanged. Full installed cancellation ≤1 s and new live start/stop/egress/IPv6 acceptance remain unverified; current connection was not changed.
- `npm.cmd run dist:win`: exit 0, eight packaged-ASAR markers verified; main SHA256 b45dc2614702858c815dc2fea5f91dc37d95465c2a3a2e39bbf497ac9c386f04. Installer `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139166458 bytes, 23:18:45 MSK, SHA256 BEE4F9D7ACAE234DFFFBF8072ED5F55A59E4810DA12FECDF86139FA92B0B0EAF, Authenticode NotSigned. Optional V8 snapshot remains unavailable; application builds successfully. Artifact supersedes the previous same-version installer and was not installed by the agent.

### Rollback
- Revert the scoped route/IP/cancel change. Settings, profile and ownership manifest formats remain compatible. Own temporary test/build logs removed after recording results.


## 2026-10-02/03 — WP-3 / WP-0: ускорение правил Windows Firewall

- Владелец разрешил исправить и измерить firewall участок. Начальный checkout 74c5019 был чистым. New/Get/Remove собственных правил теперь используют COM HNetCfg.FwPolicy2/FwRule; snapshot/set/restore профилей, NotConfigured, durable journal, TUN barrier, Allow-before-Block и независимый CIM read-back исключений сохранены. Lazy handle не кеширует коллекции или proof; после удаления выполняется свежая проверка. Physical-adapter policy запрещает новый firewall API. Backend указан в command timing.
- Native disabled-rule benchmark, три пары production типов: create CIM604/562/590 vs COM212/72/73 ms; read CIM326/333/346 vs COM77/25/35; verified remove CIM954/1022/1149 vs COM172/157/167. 3/3 CIM signatures совпали. Расширенные IPv6/duplicate-name fixtures тоже 3/3 совпали, 14 rules/API. Исправлена найденная native проверкой ошибка COM interface setter: явная VARIANT array allocation вместо string[] cast. Исходный IPv6 loopback отклоняется обоими API, прежняя обработка сохранена.
- Все тестовые правила были выключены, уникальный benchmark namespace, profilesUnchanged/activeOwnRulesUnchanged/cleanupOk=true. Финальное CIM/COM чтение текущих правил: 11/11, имена равны. Остаток VPNTE-benchmark rules — 0. Действующий VPN и установленный клиент не менялись. Измерено ускорение компонентов; новые full start/stop/cancel времена и L3 egress/leaks/boot acceptance ещё не подтверждены. Полные данные, первые failed runs и границы записаны в lifecycle journal, этап 28.
- `npm.cmd run typecheck`: exit 0. Focused шестью suites (точная команда в этапе 28): 139 passed / 1 skipped, exit 0. Финальный `npm.cmd test -- --maxWorkers=4`: exit 0, 182 files passed / 2 skipped, 2040 tests passed / 10 skipped / 0 failed, 109.29 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC927/927 F210/210. `git diff --check`: exit 0. Нормативные docs не менялись.
- `npm.cmd run dist:win`: exit 0, Electron 44.4.3 NSIS. 10 packaged-ASAR markers проверены, main совпадает с compiled output, SHA256 62b4552ec859d52b45cfd0f82df2f23e2cbfb11d09925a6fb31b4031e05d3949. Optional snapshot пропущен как раньше.
- Installer `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139167722 bytes, 03.10.2026 00:02:15 MSK, SHA256 DDEDA7E356AD54EDD40BDEE8AFC59972845F1FBE5CFF634B77755E89623C16BC, NotSigned. Artifact заменяет предыдущий с тем же номером; агентом не установлен. Удаление собственных временных файлов отклонено automatic approval review (`blocked by policy` без пояснения), они оставлены в `.tmp`; прежние артефакты сохранены.

### Откат

- Revert scoped firewall API change; settings/profile/recovery manifest форматы совместимы. Возвращает прежние NetSecurity операции с правилами.

## 2026-10-03 — WP-3 / WP-0: adapter apply и ранняя отмена

- Владелец разрешил продолжать ускорение по прежней схеме. Начальный checkout 2a5c410, чистый. Установленная COM-сборка: starts 4501/3578/3273 ms, stops 3276/2966 ms, cancel 3296 ms; firewall await уже 502/643/403 ms. Adapter lockdown тёплый 1833/1813 ms, native mutation 1130/1132 ms. При cancel новый adapter batch запускался уже после сигнала отмены и Xray exit, затем компенсировался. Baseline rollback остаётся ~1 s.
- Adapter apply получил startup AbortSignal и проверки перед новыми effects. Общие snapshot reads разрешено завершить; после отмены до journal/native dispatch новые изменения не отправляются. Durable journal и уже отправленные native пакеты остаются под владельцем компенсации после runtime exit proof. Отмена и поздний native отказ не запускают преждевременный rollback из parallel apply wrapper.
- Свежая GUID/binding проверка пропускает повторный Disable IPv6 только при доказанном boolean=false; missing/ambiguous/nonboolean/read-back failure не проходят. Mobile/464XLAT исключение сохранено. Два reg.exe add заменены .NET Registry с проверкой DWORD=1, пропуском повторной записи и read-back после изменений. Baseline восстановления прежних значений/отсутствия сохранён. Missing policy proof и частичные ошибки сохраняют conservative recovery journal.
- Неизвестный результат helper, timeout/exit/stop и nonzero reply больше не переигрываются fallback transport; fallback разрешён только известному отказу до dispatch. Диагностика включает cancelled, phase/pendingRecovery, ipv6AlreadyOff. Нормативные docs и manifest/settings/profile форматы не менялись.
- Safe replay старого/нового production apply после abort: mutation batches 1→0, journal writes 2→0. Native read-only proof текущего GUID/IPv6/DNS-policy: первый 433 ms, тёплые 343/313/336/330/306 ms, 6/6 доказательства успешны, binding unchanged. Это отдельный компонент, не полный installed apply. Реальные уникальные HKCU registry fixtures: warm reg 11–12 ms/value, .NET 0–1 ms/value; первый cold .NET 62 ms vs reg27. 12/12 independent reg query proofs, cleanupOk=true. Реальные HKLM/сетевые настройки и установленный клиент не менялись.
- Финальные `npm.cmd run typecheck`: exit 0; focused seven-suite command из lifecycle journal этапа29: 174 passed, exit 0. `npm.cmd test -- --maxWorkers=4`: 183 files passed / 2 skipped, 2073 tests passed / 10 skipped / 0 failed, exit 0, 113.14 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC927/927 F210/210, exit 0. `git diff --check`: exit 0. Первые test typing / CLIXML / benchmark-interface setup замечания и границы записаны в журнале.
- `npm.cmd run dist:win`: exit 0, 7 packaged-ASAR markers, main SHA256 ab4a2493df59584735f6e33949d3c5821067722828fc959242747b8d119f81a2, совпадает с compiled output. Installer dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe: 139168386 bytes, 03.10.2026 00:32:56 MSK, SHA256 1C830BDB249EB61B2BE2DBD7CA92E7A3ABC9E4014F5334BD20E0FABE376ABC53, NotSigned. Agent did not install it; новые full start/stop/cancel и L3 acceptance пока не измерены. 11 собственных временных файлов этого этапа удалены, прежние сохранены.

### Откат

- Revert scoped adapter/cancellation change; сетевые baseline/settings/profiles совместимы. Возвращает прежние повторные native операции и apply после отмены.

## 2026-10-03 — WP-3 / WP-2 / WP-0: baseline rollback и остановка runtime

- Владелец разрешил следующий измеренный участок и запросил тесты. Начальный checkout cf3b16b, чистый. Установленная сборка этапа29: cold start4938 / warm3037/3116 ms, stops3394/3198 ms, cancel2221 ms. Baseline обычных stops1104/1118 ms; runtime stop788/787 ms + отдельный fresh exit wait231/171 ms. Adapter cancellation уже прерывает новые эффекты в snapshot phase.
- Девять typed baseline restore/read-back и WinINet notification объединены в один PowerShell. SID guard, trusted journal, независимые шаги, сохранение manifest при partial/notification/malformed outcome и operation lock сохранены. Новый baseline native phase timing разделяет registryMs/notifyMs.
- Остановка трёх фиксированных owned runtime exe передана existing recovery worker через закрытый stop-runtime request; прежний 8000 ms deadline и отдельный fresh exit proof сохранены. Только типизированный unavailable до dispatch допускает fallback. Unknown/dispatched failures не переигрываются. Malformed counts/names и CIM query failure не превращаются в успех. Прежний prefix ownership predicate сохранён; external proxy исключён.
- Actual Windows benchmarks, три alternating pairs: runtime fresh PS489/455/441 vs warm worker150/92/92 ms; baseline two PS975/796/811 vs merged573/545/526 ms. Остановка только собственных renamed Node children в unique .tmp fixture; tracked exits и свежий inspect-runtime доказаны 6/6, workerExited/cleanupOk=true. Baseline только unique HKCU subtree, 9 verified slots / 6 types / cleanupOk во всех 6 samples. WinINet declaration компилируется, DLL calls подменены; реальные уведомления и сетевые настройки не изменялись. Это компоненты, полные installed stop/cancel ещё не подтверждены.
- Focused baseline до изменений: 224 passed / 1 skipped. Expanded final nine-suite command из lifecycle journal этапа30: 299 passed / 1 skipped / 0 failed, exit0,52.62 s. Первый expanded focused и первый full run выявили два устаревших source oracles после переноса fixed stop script; они обновлены на shared production script / stop-runtime с сохранением исключения external proxy. Полный первый run2127 passed/1 failed/10 skipped не принят как окончательная проверка.
- `npm.cmd run typecheck` повторён после последнего test oracle fix: exit0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit0,AC927/927,F210/210. Нормативные docs не менялись.
- Окончательный `npm.cmd test -- --maxWorkers=4` — **184 files passed / 2 skipped, 2128 tests passed / 10 skipped / 0 failed**, exit 0, **106.17 s**. Последние три focused suites — **132 passed**, exit 0. Typecheck после последней правки — exit 0; runtime/test source затем не менялся. Ожидаемый RootErrorBoundary stderr сохранён. Точные команды и первые отказы записаны в lifecycle journal этапа 30.
- `npm.cmd run dist:win`: exit0, Electron44.4.3 NSIS. Optional snapshot пропущен как прежде. 6 packaged-ASAR markers, main совпадает с compiled output; SHA2561763c21247e138d95973fe701ceb3aae3a6ce6f8796f3474d66c581fc5206527. Installer dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe:139168882 bytes,03.10.2026 01:04:20 MSK,SHA25668AAA3C8FBB630D4952A0D16EE0890FFD32510FCBE803C47C2C6007A885BC6B6,NotSigned. Агентом не установлен, заменяет предыдущий same-version artifact. Runtime source после сборки не менялся, последний fix только test oracle.

- Итоговые traceability AC 927/927 / F 210/210 и `git diff --check` — exit 0. Удалены 12 собственных временных файлов этапа 30; предыдущие артефакты сохранены.

### Откат

- Revert scoped baseline/stop change; manifest/settings/profile форматы совместимы. Возвращает два baseline процесса и свежий PowerShell для runtime stop.

## 2026-10-03 — WP-0 / WP-7 / WP-10: переключение серверов и ложный IP leak

- По прямой команде владельца исправлены четыре подтверждённых дефекта: прежняя adaptive verification после ручной смены, пропущенный IP rebaseline при adaptive fallback, устаревший профиль в UI и классификация любого отличия VPN-IP как видимого real IP. Начальный checkout `0c38ac7`, чистый.
- Ручной IPC до первого ожидания инвалидирует и отменяет старые adaptive/IP пробы, сериализуется с уже отправленным protected restart. Новая проверка привязана к текущему профилю/runtime, owner guards стоят после каждой пробы/ожидания. All adaptive branches и manual switch используют общий protected IP barrier: сохранение native protection, fresh route proof, один свежий IP sample, корректное снятие suppression. Старый IP getter из критического пути удалён (в исходном логе ожидание **8467 ms** внутри switch **12568 ms**).
- Adaptive fallback обновляет selected profile и существующий renderer event. UI получает IP baseline/verdict из main: mismatch — `indeterminate`, unavailable — `not-checked`, без false real-IP alarm или геолокации неподтверждённого IP. Независимые physical/DNS alarms сохранены. Удалённые/disabled профили не используются как новые цели.
- Первый focused run:96 passed/2 failed, исправлены устаревшие test oracles. Expanded focused:108 passed. Первый full:2150 passed/1 failed/10 skipped; source route guard oracle перенесён на общий helper с сохранением проверки порядка и отказа. Последующая focused группа:59 passed. Детальные точные команды и причины записаны в lifecycle journal этапа31.
- Финальный `npm.cmd run typecheck` — exit0. `npm.cmd test -- --maxWorkers=4` — **188 files passed / 2 skipped, 2156 passed / 10 skipped / 0 failed**, exit0,129.93 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — exit0,AC927/927,F210/210. Нормативные docs не менялись; полная Windows acceptance/общая scheduler-rotation coordination не объявляется закрытой.
- `npm.cmd run dist:win` — exit0,Electron44.4.3 NSIS. Packaged main/preload равны compiled outputs,6 main/3 renderer markers подтверждены. Main SHA25650f1a1c68d92edad6509eaf96f8d273db72f23290959a099badc7c84244f48d1. Installer1.1.22:139170274 bytes,03.10.2026 12:02:17 MSK,SHA2564368E9C63E696578947055D94B9C67D83A1D459A98492863AB4BBC5927E2547F,NotSigned. Агентом не установлен. Installed latency новой смены ещё не измерена.

### 2026-10-03 — PR #16: подтверждены и исправлены три замечания ревью

- Проверены repo/ветка/remote head 4f11942 и чистый исходный worktree. Fallback commit/UI теперь после fresh route/IP и окна 20 s с >=2/3 HTTP-пробами; мёртвый sibling не сохраняется, provisional runtime останавливается с сохранением firewall/adapter protection. Manual cancel и runtime ownership ограждены.
- Route proof повторяется до 3 раз через 500 ms; null/invalid native Xray endpoint блокирует graph publication/config write/spawn вместо DNS deadlock. Новые executable regressions и обновлённые source oracles.
- `npm.cmd run typecheck`: exit 0. Focused command (точный список в lifecycle journal этап 32): 6 files / 121 passed / 0 failed, exit 0, 6.50 s. `npm.cmd test -- --maxWorkers=4`: 189 files passed / 2 skipped, 2172 passed / 10 skipped / 0 failed, exit 0, 96.16 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: exit 0, AC 927/927, F 210/210. `git diff --check`: exit 0.
- Нормативные docs не менялись; полный Windows L3/installed acceptance не запускался. Installer в этом PR repair не пересобирался и не установлен агентом.

## 2026-10-03 — WP-2 / WP-0: DNS при смене сервера

- В installed логе Norway switch 6160 ms: один успешный DNS запрос native graph 3025 ms, stage 3029 ms. Fresh-IP barrier около 0.79 s, identity 461 ms, protected stop 300 ms. Главный измеренный участок — DNS. PR #16/ветка проверены, remote пустой ee254b2 включён fast-forward без source изменений.
- После 100 ms ожидания основного DNS запускается существующий IPv4 system lookup; первый валидный результат завершает операцию. Быстрый основной DNS не вызывает lookup; ранняя ошибка сразу вызывает fallback. Ошибка одной ветки не отменяет другую. Resolver принадлежит операции, отмена и поздние OS результаты ограждены; исправлен повторный cancel. Межсетевой application cache и новые сетевые исключения не добавлены. Fresh route/IP и adaptive health проверки сохранены.
- Первые новые тесты поймали double cancel: 138 passed / 2 failed. После исправления focused command из lifecycle journal этапа 33: 140 passed, exit 0. На реальном локальном DNS стенде primary 3053 ms → новый путь 115 ms; fake-clock fixture 3025 ms → 120 ms. Это компонент, installed switch ускорение пока не измерено.
- `npm.cmd run typecheck`: exit 0. `npm.cmd test -- --maxWorkers=4`: 189 files passed / 2 skipped, 2183 passed / 10 skipped / 0 failed, exit 0, 132.10 s. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC 927/927 / F 210/210, exit 0. Нормативные docs не изменены.
- `npm.cmd run dist:win`: exit 0, Electron44.4.3 NSIS; packaged main/preload равны compiled outputs, 4 main markers подтверждены. Main SHA256 0c26e9868cc2c304d6f951b9756dd8dba88b021da9013f6022885e7b267880c3. Installer1.1.22:139170825 bytes,03.10.2026 20:30:50 MSK,SHA2566875F8B743AAEEF6E378DEF6CBC5AFDB739FF521CCB7E88DDD9D68CF2511AA72,NotSigned. Агентом не установлен. Итоговый diff check exit0.

## 2026-10-04 — WP-1: локальная приёмка секретов и доверенной границы

- Продолжены оставленные изменения после `7da36fb` в `codex/wp1-security-acceptance`: DPAPI prefix/schema v2, auth в proxyOverride/adaptive secret, default-redacted config export с отдельным native-consent режимом, IPC audit/typed validation, узкая CSP, fresh runtime tree ACL/owner/reparse и SHA-256 staging. Пользователь разрешил завершить изменения, коммит и PR; VM отсутствует, VM-проверки исключены из этой сессии, но не засчитаны как PASS.
- Исправлены review/native находки: backup-step audit; preflight всех startup stores до recovery; graceful startup refusal без network cleanup; сохранение Chromium Local State ключа между процессами; builtin PowerShell Security import вместо PS7 module discovery; ACL oracle не принимает failed inspection за безопасный owner refusal; p99 покрывает все envelope-классы bounded histogram.
- Финальные `npm run typecheck` и `npm run build`: exit 0. `npm test -- --maxWorkers=4`: 200 files passed / 2 skipped; **2397 passed / 10 skipped / 0 failed**, 108.44 s. Native Electron smoke: 8 checks PASS. Локальные native WP-1 subsets PASS; same-version DPAPI/store migration после исправления повторена 2/2 PASS. Полный `test:wp1:fuzz`: 155 × 100000 = **15500000 rejected envelopes**, zero handler effects, p99 upper bound 1 ms на всех каналах; 3 × 100000 redactor cases PASS, 342.01 s.
- Traceability: AC927/927, F210/210, exit 0; это покрытие ссылок, не полная приёмка. Подробные команды, ранние отказы и AT-01-001…011 границы записаны в `vpn-tunnel-enforcer/docs/wp1-security-acceptance-2026-10-04.md`.
- Настоящий Electron 42→44 остаётся NOT-CHECKED: нет `VPNTE_ELECTRON42_EXE`, runner честно возвращает exit77. Clipboard не менялся; native TTL/installed/full VPN secret scan/elevated ACL abuse/OS matrix/VM также NOT-CHECKED. Полный WP-1 не объявляется принятым. Нормативные `docs/`, действующий VPN/Firewall/DNS/IPv6 и установленный клиент не менялись; installer не пересобирался.
- Совместимость: новый reader читает legacy ciphertext; прежний executable не понимает новый `enc:dpapi:v1:` prefix. Непроверенный downgrade после новых записей не рекомендован, ciphertext/backup вручную не удалять и не переписывать.

## 2026-10-04 — WP-1 / WP-2: исправления ревью PR #21

- Исправлен подтверждённый пробел runtime namespace: единый per-userData instance path `%ProgramData%\VPNTE\runtime\<hash>\`, OS known-folder сверка даже при уже существующем runtime, root-first ACL/owner/reparse-проверка всех предков, включая DELETE_CHILD/DELETE/WRITE_DAC/WRITE_OWNER. SYSTEM/Admins и TrustedInstaller разрешены для системных предков; InheritOnly не считается эффективным правом на родителя. Для исполняемого дерева проверяются также наследуемые write-гранты, опасные для новых файлов.
- Application-компоненты создаются с ограниченным DACL атомарно. Никаких Set-Acl/icacls repair для уже существующих недоверенных каталогов, рекурсивного bootstrap или ужесточения AppData. Небезопасный pre-existing компонент блокирует запуск. Обновлены getters, firewall program path, логи, диагностика, cleanup и форензика. Версионный diagnostic probe выполняется только после проверки; форензика отказывается от elevated scripts при failed ACL и от session/ETL paths вне текущего root.
- Исправлены остальные подтверждённые замечания: export mode enum в preload, allowlisted startup failure details и ограниченный размер обычных Error, настоящий quit-helper вместо new Function, cleanup helper с сохранением primary/cleanup ошибок и overall PASS только после удаления owned fixture. Широкий secret redactor не ослаблялся.
- Проверки: typecheck/build exit 0; финальный full Vitest с `--maxWorkers=4`: **203 files passed / 2 skipped; 2439 passed / 10 skipped / 0 failed**, 99.45 s. Native read-only PowerShell policy/known-folder/script syntax тесты проходят; focused runtime/path/diagnostic/forensics: 123/123; hostile session paths: 4/4; cleanup Node tests: 10/10; Electron smoke: 8 checks; WP-1 native subsets: 6; same-version migration: PASS. Traceability AC927/927 и F210/210, exit 0.
- Промежуточный full run с default workers: два существующих bundled-core preflight теста превысили 5 s; отдельный повтор 85/85 и финальный full run с 4 workers прошли без изменения таймаутов.
- Старые runtime/forensics данные не мигрируются и не исполняются; перед обновлением нужен штатный stop старого клиента. Installer/живой VPN/сеть/clipboard не менялись. ProgramData bootstrap с elevation и concurrent ACL abuse, VM/OS matrix, реальный 42→44 и rollback-reader остаются NOT-CHECKED. Полный WP-1 не объявляется принятым; нормативные `docs/` не редактировались.

## 2026-10-04 — PR #21: второй проход ревью, логи и capture cleanup

- Исправлены unsafe runtime mkdir при очистке логов и hard-coded developer fixture paths. Missing runtime не создаётся; existing logs требуют ACL proof. Все forensics/staging/sidecar fixtures изолированы в уникальном os.tmpdir.
- Stop `pktmon/netsh` требует native exit=0 и acknowledgement до best-effort artifacts. При ошибке capture остаётся running/cleanupPending с повторяемым stop; concurrent stops объединены, restart и diagnostic deletion не подавляют ошибку. Runtime ACL refusal допускает path-free cleanup только провайдера с in-memory ownership текущего процесса, не произвольного disk manifest. Потеря сайдкара/stop artifacts не доказывает остановку packet capture (F-198); UI честно показывает unknown/pending, включая failed status request.
- Legacy AppData marker читается ограниченно и только как недоверенный hint: warning/блок нового capture без выполнения старых scripts, импорта PID/paths или изменения данных. Автоматический reclaim и controlled installer shutdown/handoff после прерванного обновления **не реализованы**; WP-11/L3 oracle остаётся открыт.
- Typecheck/build/dist:win exit 0; финальный full run: **206 files passed / 2 skipped; 2459 passed / 10 skipped / 0 failed**, 98.86 s. Cleanup Node tests 10/10. Native PowerShell control-flow tests используют harmless provider stubs; действующий pktmon/VPN/Firewall/DNS/clipboard не трогались. Traceability AC927/927, F210/210, exit 0. Нормативные docs не изменены; полный WP-1/AT-08-004/005 L3 не заявляется.
- Пересобран `VPN-Tunnel-Enforcer-Setup-1.1.22.exe` (139179636 bytes, NotSigned), без установки. SHA-256 `AEEA3D7D04098422D50C72F72100C6C7D9CAC6F08DD08CE6831BE374ED177EC6`; packaged main/preload/renderer проверены, dist/checksums.txt обновлён. Подробнее: `vpn-tunnel-enforcer/docs/wp1-security-acceptance-2026-10-04.md`.

## 2026-10-04 — PR #21: третий проход, capture race и локализация

- Два regression cases подтвердили гонку до патча: новый capture стартовал до окончания старой stop finalization. Общая promise-очередь сериализует start/stop/restart/staging; внутренние recovery/restart не создают nested wait. Late old-sidecar callbacks игнорируются, persistence объединяет наблюдение sidecar с текущим provider state; status projection не перезаписывает состояние.
- Legacy false-stopped hints с ошибкой/неподтверждёнными метаданными блокируют новый capture без выполнения старых scripts или изменения данных. CleanupPending после process restart определяется отсутствием текущего ownership, не доверяет timestamp. Новые предупреждения/status block переведены RU/EN; UI test проверяет смену языка.
- Узкий production delta: +57 строк net с переводами; добавлено 17 regression cases. Focused suite 59/59; typecheck/build/dist:win exit 0; full suite **2476 passed / 10 skipped / 0 failed**, 206 files passed / 2 skipped, 109.40 s. Traceability AC927/927, F210/210, exit 0.
- EXE 1.1.22 пересобран (139180033 bytes, NotSigned), не установлен; SHA-256 `7C42C3F6F08F12B827C4C64BD429FF25A2CCFA4DEAA0FF8DE4FFC3DD15BA8DD4`. 40 packaged files и новые markers проверены; dist/checksums.txt обновлён. VM и live capture не запускались, VPN/Firewall/DNS/clipboard не трогались. Полный WP-1/L3 и installer handoff/42→44/rollback не объявлены принятыми; нормативные docs не менялись.

## 2026-10-04 — WP-8 / WP-11: согласованный shutdown перед обновлением (PR #21)

- По команде владельца исправлен второй retained concern, не credential downgrade. Main shutdown ждёт capture stop/finalization до helper disposal/exit; неполные capture/network/env receipts блокируют выход, показывают RU/EN предупреждение и сохраняют helpers для retry. Остальные cleanup steps не пропускаются после отказа.
- `--shutdown-for-update` использует существующий single-instance IPC. NSIS ждёт открытый handle исходного primary и dedicated success exit 73, затем отсутствие VPNTE processes. Ordinary exit/crash/timeout/unknown identity не дают успех; image-name taskkill удалён, default builder force-kill override заменён тем же gate. PowerShell встроен immutable EncodedCommand, literal InstallDir передаётся в process environment без interpolation/temp-script execution.
- Старые EXE без команды требуют предварительного штатного «Выхода»; orphan kernel captures после прошлых убийств и старый chained uninstaller не объявлены автоматически исправленными. ТЗ/AT-11-002/009/F-183 учтены, полного installed/L3 PASS нет.
- +24 regression cases; focused shutdown/lifecycle 99/99, финальный full run **2500 passed / 10 skipped / 0 failed**, 207 files passed / 2 skipped, 115.64 s. Typecheck/build/dist:win exit 0, embedded command/source и PS syntax проверены; AC927/927, F210/210 exit 0. Native fixtures не трогают реальный клиент/захват/сеть; настоящий handle проверен на безвредных PowerShell children с exit 0/73.
- EXE 1.1.22: 139180341 bytes, NotSigned, SHA-256 `F08247EA9B97B6651EE6A19AC62E0391F1607D83D8DDD41010380025B07C1F4B`; 40 packaged files сверены, checksums обновлён, установка не выполнялась. VM отсутствует, нормативные docs не менялись; cross-version credential recovery и installed active-upgrade/OS matrix остаются NOT-CHECKED.

## 2026-10-04 — PR #21: проверки результата shutdown после ревью be104c1

- Закрыты два actionable пробела CodeRabbit: main проверяет `success` и полноту `killed/candidates` owned-runtime stop; строгий `autoconfig.isApplied('env')` передаёт ошибку чтения в shutdown guard вместо UI fallback `applied:false`. Неизвестное состояние не даёт exit 73; helpers и env backup сохраняются без blind rollback, capture cleanup продолжается.
- `env.isApplied()` использует проверенный parser registry value: access-denied/timeout/неразбираемый успешный stdout отклоняются; только распознанный missing-value с exit 1 и без termination indicators означает отсутствие. Parser также не допускает подготовки ложного backup перед apply. UI `getStatus()` контракт не менялся. Новых зависимостей или менеджеров нет.
- Nitpick Revix: 10 harmless PowerShell cases перенесены в `installerShutdown.itest.ts`; отдельный `npm run test:installer-shutdown` использует opt-in integration mode, обычный test glob их не запускает. Суммарно добавлено 35 regression cases, старые native cases не потеряны.
- Typecheck/build/dist:win exit 0; focused 134/134, native integration 10/10; full **2525 passed / 10 skipped / 0 failed**, 208 files passed / 2 skipped, 90.36 s. AC927/927, F210/210 exit 0. Первый test launch поймал незакрытую скобку в редактируемом Vitest config, исправлено до этих финальных прогонов.
- EXE 1.1.22 пересобран, **139180693 bytes, NotSigned**, SHA-256 `D157455011C95E1580DFA4E6FCF260330746E09AD78EB74228C7E0423909B70F`. Все 185 файлов `out/` совпали с packaged ASAR по SHA-256; runtime/env strict markers подтверждены, checksums EXE/blockmap обновлены. Установка не выполнялась; VM и live network/capture/registry не трогались. Legacy capture recovery, credential downgrade и installed/L3 matrix не расширялись; нормативные docs не менялись.

## 2026-10-05 — PR #21: финальный согласованный env ownership / residual polling follow-up

- По команде владельца завершены два замечания к c2c5342; новые раунды ревью не запрашивать и будущие замечания без отдельной команды не исправлять.
- Чужие proxy variables без VPNTE backup не считаются нашей cleanup obligation: status не читает registry и не требует rollback; чужие значения остаются нетронутыми. Валидный backup является durable pending receipt, даже если HTTP_PROXY уже восстановлен/отсутствует. Короткий process-local флаг удерживает ранее наблюдавшееся обязательство при исчезновении receipt; исчезнувший known backup не пересоздаётся из изменённого окружения.
- Rollback проверяет все четыре HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY: уже восстановленные пропускает, неизвестные не изменяет, после set/delete требует readback. Ошибка команды/readback/retirement сохраняет obligation и backup для retry; независимые entries продолжаются. Production delta **+21 строки net**, без новых зависимостей/схем/менеджеров.
- Native remaining fixture больше не выбрасывает ошибку из Start-Sleep: настоящий production polling достигает 5s deadline и проверяется конкретное сообщение отказа. Дополнительно проверяется освобождение после нескольких polls, число запросов и конкретные причины остальных отказов; процессов VPNTE/сети тесты не трогают.
- Typecheck/build/dist:win exit 0; focused **181/181**, opt-in native **11/11**; full **2572 passed / 10 skipped / 0 failed**, 208 files passed / 2 skipped, 105.66 s. AC927/927, F210/210 exit 0. Registry fixture полностью in-memory, покрывает чужой proxy, partial rollback каждой переменной, exit-zero mismatch, недоступный/повреждённый/исчезнувший receipt и повторные попытки.
- EXE 1.1.22: **139180562 bytes, NotSigned**, SHA-256 `721C1083EE77336116F35A6DB2D679738FA51B1C604F65DEBD278546C711947C`. Все 185 out-files совпадают с packaged ASAR; readback/shutdown markers подтверждены, checksums обновлён. Не устанавливался; VM/live registry/VPN/Firewall/DNS/capture не трогались. Полный installed/L3/OS/42→44/credential rollback не заявлен; нормативные docs не менялись.
- Граница: backup уже служит recovery metadata, не новым защищённым ownership store. Его потеря между процессами не восстанавливается process-local флагом; не добавлен автоматический reclaim отсутствующих/legacy receipts. Эти retained limits не объявлены устранёнными.

## 2026-10-05 — WP-1 / PR #21: диагностика отказа runtime по запросу владельца

- По логу от 04.10 подтверждён отказ Direct VPN до запуска Xray на подготовке runtime; конкретная нативная причина старой сборкой не записывалась. Без изменения ACL/VPN добавлена ограниченная PowerShell failure receipt: operation/path, allowlisted policy reason, корневой exception type/HResult, owner/ACE SID и rights. Bootstrap/elevation/readback отказы записывают её в `runtime-acl`; сырой stderr/argv/exception message не выводится, логи проходят существующий redactor. Проверки доверия и запрет исправлять небезопасные существующие каталоги сохранены.
- Вызов `powershell.exe` вместо `powershell` теперь попадает в уже существующий direct execFile transport в `admin.ts`, минуя предел cmd.exe для длинного EncodedCommand. Это обнаруженная возможная причина старого отказа, не доказанный диагноз старого запуска.
- AT-01-002/009: 14 дополнительных регрессий, включая native read-only/synthetic owner/inheritance/write/access-denied receipts, nonzero exit и secret non-disclosure. Typecheck/dist:win PASS; полный Vitest **2586 passed / 10 skipped / 0 failed**, 208 файлов passed / 2 skipped; traceability AC927/927, F210/210; diff --check PASS.
- Пересобран локальный `VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139181284 bytes, NotSigned**, SHA-256 `7263614ab230a2e876780e5c48b0c2f3fd8032c058d45e74693afc949de6b876`. Все 185 out-files совпадают с ASAR, diagnostic markers подтверждены. EXE не устанавливался; приложение/VPN не запускались; системные ACL/Firewall/DNS/IPv6/registry/capture не менялись. VM/L3/исправление реального ACL не заявлены; нормативные docs не изменялись. Чужая whitespace-правка `connectionLifecycle.ts` сохранена и исключена из коммита.

## 2026-10-05 — WP-0: снижение нагрузки тестов с сохранением проверок

- По запросу владельца обычный Vitest ограничен двумя workers с изоляцией файлов. Main/shared/preload запускаются в Node.js; renderer и `recoveryManifestStorage.test.ts` остаются в jsdom. Последняя native-фикстура зависит от различий разрешения mock `child_process`; слепой перенос в Node менял смысл её проверок. Integration сохраняет исходный glob `src/**/*.itest.ts` и Node.js. Бюджеты fuzz и настройки coverage сохранены; код приложения не изменялся.
- Добавлены семь регрессий конфигурации: реальная коллекция Vitest сравнивается с исходными glob для обоих режимов; проверяются пропуски, дубли, окружения, изоляция и лимит процессов. Тесты поддерживают исполнимость существующих AT-* (включая native AT-03-012 и integration AT-11-002), без заявления о выполнении их отдельных приёмочных сценариев.
- Из `vpn-tunnel-enforcer`: `node scripts/check-vitest-config.mjs` — exit 0; `npx.cmd vitest run src/main/testRunnerConfig.test.ts` — **7 passed**, exit 0; `npm.cmd run typecheck` — exit 0; `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — **AC927/927, F210/210**, exit 0.
- Полный `npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/test-load-audit-20261005/production-npm-test.tests.json` без переопределения workers — **2593 passed / 10 skipped / 0 failed**, **209 файлов passed / 2 skipped**, **125.40 с**, exit 0. Машинное сравнение имён/файлов с исходным прогоном подтвердило сохранение всех **2596 прежних случаев**, плюс семь новых; нормализовано только динамическое время `startedAt` в имени одного теста. `git diff --check` — exit 0.
- Для минимальной одновременной нагрузки доступен `npm test -- --maxWorkers=1` из папки приложения. Coverage run, Electron/native smoke и VM/L3 в этой задаче не запускались; новые закрытия F/AC не заявлены. Нормативные docs не изменялись. Предсуществующая whitespace-правка `connectionLifecycle.ts` сохранена и исключена из коммита; исследовательские результаты находятся в игнорируемой `.tmp/test-load-audit-20261005/`.

## 2026-10-05 — WP-1 / WP-2 / WP-6 / WP-9: исправления по логам приложения и движков

- По команде владельца исправлены повторная DPAPI-проверка неизменённых encrypted backups (477 сообщений за пять минут), завершение Xray до sing-box (152 ошибки при остановке), скрытая локальным SOCKS политика Mux UDP/443 и неверное обещание всего трафика через VPN при Smart RU. Кеш содержит только SHA-256 аутентифицированных байтов; текущий файл и доступность шифрования проверяются при каждом обращении. Native cleanup сортирует owned processes и ждёт выхода sing-box перед upstream; ошибки cleanup продолжают фиксироваться. Default/reject UDP/443 даёт быстрый TCP fallback с reject/default, allow/skip и остальной допустимый UDP сохранены. UI сообщает запуск и ожидание проверки выхода на RU/EN.
- Добавлено 20 regression cases с AT-трассировкой. `npm.cmd run typecheck` — exit 0; `npx.cmd vitest run src/main/recoveryPsProtocol.test.ts src/main/tunShutdownOrder.test.ts src/main/secretStorage.test.ts src/main/ownedRuntimeStop.test.ts src/main/ownedRuntimeStatus.test.ts --reporter=dot` — 153 passed, exit 0; итоговый `npm.cmd test -- --reporter=dot` — **2613 passed / 10 skipped / 0 failed**, **211 файлов passed / 2 skipped**, **151.22 с**, exit 0. Дополнительный byte-cache case проверен итоговым full run. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0. `npm.cmd run dist:win` и `git diff --check` — exit 0.
- Новый EXE 1.1.22 — **139182096 bytes, NotSigned**, SHA-256 `3D1EC7178467B27FA3D7609BAC3304380D3450C1B9DDBEB201DCCC19F84E9E0C`; 185 out-files побайтно сверены с ASAR, markers подтверждены, checksums обновлён. Не установлен; реальный VPN/Firewall/DNS/IPv6/capture не запускались и не менялись. Native dispatcher проверен с fake cmdlets; Process.WaitForExit дополнительно проверен на безвредном отдельном child.
- Первичный native regression run выявил две ошибки нового кода/fixture (PS comment syntax и expected result); исправлены до итогового PASS. Проверка ASAR первоначально использовала неверный Windows separator; повторная проверка успешна. 150 рабочих TCP upload reset, таймауты provider health-ветвей и шесть DNS parse errors не имеют установленной первопричины; не объявлены исправленными. Graceful-период/full AT-02-009 и L3/VM не заявляются принятыми. Нормативные docs не изменялись, существующая правка `connectionLifecycle.ts` сохранена и исключена.
- Трассировка локальных регрессий: backups — AT-01-001/010; stop order — F-029, AT-02-005/009; UDP configuration — AT-02-008, AT-06-001; сообщения Smart RU — F-078/079, AT-06-003/09-011. Связь с AT не означает полной приёмки соответствующих сценариев. Основание UDP-политики: [Xray Mux](https://xtls.github.io/en/config/outbound.html), [Xray UDP/443 handler](https://github.com/XTLS/Xray-core/blob/main/app/proxyman/outbound/handler.go), [sing-box reject/default](https://sing-box.sagernet.org/configuration/route/rule_action/). Полные логи приложения и движков и журналы проверок сохранены в игнорируемой `.tmp/engine-log-read-20261005/`.
- По замечанию владельца отдельный MD-отчёт удалён; результаты остаются в существующем журнале прогресса.

## 2026-10-06 — WP-2 / WP-6: совместимость Xray с браузерными прокси

- Владелец подтвердил зависание Google при включённом «ЮБуст»: Chrome запрашивал `185.69.221.62:59751`, а Xray заменял назначение на `www.google.com:59751` после TLS sniffing. В генерируемом SOCKS inbound включён `routeOnly: true`: HTTP Host/TLS SNI/QUIC используются для маршрутизации без замены исходного адреса и порта. Native connection graph, balancers и fallback сохраняются. Изменение не требует отключения sniffing или расширения обхода VPN.
- AT-02-008 / AT-06-001: добавлены три регрессии и расширена проверка обычного SOCKS-конфига. Два теста запускают настоящий комплектный Xray и передают HTTP / синтетический TLS ClientHello между loopback-сокетами на динамических нестандартных портах; проверяются исходные байты назначения и выбор доменного маршрута. До изменения production-кода — 4 failed / 38 passed / 1 skipped, включая два реальных таймаута; после — 42 passed / 1 skipped. Пропуск относится к внешнему REALITY handshake без тестового ключа; локальные новые сценарии выполнены. Временные fixture-каталоги удалены.
- Из `vpn-tunnel-enforcer`: `npx.cmd vitest run src/main/xrayEngine.test.ts src/main/nativeXrayCompatibility.test.ts src/main/xrayEngine.live.test.ts --reporter=dot` — 42 passed / 1 skipped, exit 0; `npm.cmd run typecheck` — exit 0; `npm.cmd test -- --reporter=dot` — 2616 passed / 10 skipped / 0 failed, 211 файлов passed / 2 skipped, 137.08 с, exit 0; `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `npm.cmd run dist:win` — exit 0; `git diff --check` — exit 0.
- Установщик 1.1.22 пересобран: 139181950 bytes, NotSigned, SHA-256 `A7ADD23BAAA0C2D37633CF62F72541D18C510D0E61EB7C82B469F1295B3709A3`. Все 185 файлов `out/` совпали с packaged ASAR; `routeOnly: true` присутствует, `dist/checksums.txt` обновлён. Установленная копия и её активный туннель не изменялись; реальный поиск с расширением после установки новой сборки и полный L3/VM не проверялись. Нормативные документы не менялись, предсуществующая whitespace-правка `connectionLifecycle.ts` исключена из коммита.

## 2026-10-06 — WP-11 / WP-8: установщик и ограничение логов

- По команде владельца удалён сломанный NSIS NGEN-блок с вложенными кавычками: установщик больше не пытается менять глобальную переменную DOTNET_NGEN_OPT и выполнять общесистемный ngen update. Для standalone uninstall добавлен customUnInstall до удаления файлов: удаляется только BootRecoveryTask в \VPNTE\ с SYSTEM principal и действием, указывающим на скрипт этой установки. Отсутствие задачи допускается; чужое действие, отказ доступа/удаления и неуспешный read-back останавливают удаление с ошибкой. При --updated задача сохраняется для нового установщика. Трассировка локальных контрактов — AT-11-005/009, F-167; реальные uninstall/upgrade и OS/VM-матрица не выполнялись.
- Добавлена ротация sing-box.log/xray.log во время работы: проверка размеров каждые 5 секунд, native ACL-проверка только перед записью, сериализованные проверки, ограниченное чтение хвоста, отказ hard-link/reparse leaf. Текущий файл усекается на месте после сохранения предыдущего поколения: реальные append handles продолжают писать без перезапуска/переподключения. Целевой объём шести retained log-files — 50 МиБ (app.log/app.prev.log по 5; по 10 для текущего/предыдущего файла каждого движка). Это периодический предел: за 5 секунд между проверками и при отказе ACL/доступа превышение возможно; отказ виден в app.log и повторяется безопасно. Объём настроек, packet capture, конфигураций и Chromium cache в этот лимит не входит.
- Xray и предыдущее поколение включены в getFullLogs с существующим redaction. Очистка логов ждёт текущую ротацию, очищает оба движка и возобновляет единичный watcher. AT-08-001/AT-01-009 здесь — поддерживающие локальные регрессии диагностических источников/доверенного namespace, без заявления о полном L3 PASS.
- Добавлено 20 regression cases: 7 файловых/таймерных, 9 native PowerShell task-removal fixtures с fake cmdlets, 2 installer contracts и 2 сценария настоящих комплектных Xray/sing-box. В последних после ротации проходит loopback SOCKS-запрос, лог продолжает расти без NUL holes, процесс остаётся жив. Установленный клиент, реальная сеть, маршруты, DNS, firewall и Task Scheduler не изменялись. Read-only запрос отсутствующей задачи подтвердил реальный ObjectNotFound, отличаемый от отказа доступа.
- Из vpn-tunnel-enforcer: npx vitest run src/main/appLoggerCleanup.test.ts src/main/engineLogRetention.test.ts src/main/engineLogRetention.live.test.ts src/main/installerCleanup.test.ts src/main/installerShutdown.test.ts src/main/bootRecoveryTaskReadBack.test.ts src/main/appLoggerRotation.test.ts src/main/appLoggerRedaction.test.ts src/main/appLoggerError.test.ts --reporter=dot — 41 passed, exit 0; npm run typecheck — exit 0; npm test -- --reporter=dot --reporter=json --outputFile=.tmp/installer-logs-tests-20261006.json — 2636 passed / 10 skipped / 0 failed, 214 файлов passed / 2 skipped, 146.24 с, exit 0; python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; npm run dist:win и git diff --check — exit 0. Финальные production-изменения после полного прогона — только отступы; NSIS contract-test адаптирован к LF/CRLF, удалено неиспользованное чтение fixture-source. Финальный npx vitest run src/main/installerCleanup.test.ts src/main/appLoggerCleanup.test.ts --reporter=dot — 14 passed, exit 0; production build повторно выполнил typecheck.
- NSIS 1.1.22: 139183217 bytes, NotSigned, SHA-256 C2DF288E5FF75C490BC0DB2A594964E46FDC67A96A6F1698FB880EC487336AC9. Все 185 out-files побайтно совпали с ASAR; packaged recovery script совпал с исходником, markers ротации/удаления присутствуют. ASAR SHA-256 FF2D9E1BEB85F1812C95D1835F3E4E5C4696640760992355684457D65D70BD04; dist/checksums.txt обновлён. Опциональный mksnapshot отсутствует: сборка штатно пропустила только snapshot. EXE не устанавливался.
- Первый native fixture использовал слишком длинный EncodedCommand; исправлен на чтение проверяемого source-файла. Первичная ASAR-сверка использовала неверный разделитель Windows; повторная сверка успешна. Временные fixture-каталоги удалены, JSON полного прогона остаётся в игнорируемой .tmp. Новые MD-файлы не создавались, нормативные документы не изменены. Предсуществующая whitespace-правка connectionLifecycle.ts сохранена и исключена из коммита.

## 2026-10-06 — PR #22: остановка при отказе и отдельные интеграционные тесты
- При отказе/таймауте/ошибке проверки выхода runtime stop возвращает ошибку до завершения Xray и снятия сетевой защиты; status/PID сохраняются, повторная остановка допускается. Native PowerShell прекращает цикл при неподтверждённом выходе sing-box. Рабочий код: 8 добавленных / 5 удалённых строк, включая комментарии; новые абстракции не добавлены. AT-02-005/009, F-029: обновлены регрессии отказа, таймаута, неизвестного выхода и retry; настоящий stop body проверяет отсутствие rollback и возобновление мониторинга при отказе.
- Xray/engine-log fixtures перенесены в .itest.ts без изменения содержимого; native installer fixtures отделены от двух unit contracts. npx.cmd vitest run --mode integration src/main/engineLogRetention.itest.ts src/main/xrayEngine.itest.ts src/main/installerCleanup.itest.ts --reporter=dot — 17 passed / 1 skipped (внешний REALITY без ключа). Focused stop/protocol/config: 171 passed; npx.cmd vitest run src/main/lifecycleCleanup.test.ts src/main/tunShutdownOrder.test.ts --reporter=dot — 95 passed. Первичный red run: 6 failed; первый full run: один устаревший тест требовал rollback при отказе runtime, ожидание исправлено.
- npm.cmd run typecheck и npm.cmd run build — exit 0; npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/pr22-review-fixes-final-tests-20261006.json — 2623 passed / 9 skipped / 0 failed, 212 файлов passed / 2 skipped, 130.55 с, exit 0. python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; git diff --cached --check — exit 0. Установленный VPN/системная сеть не менялись, NSIS не пересобирался, полный Windows/L3 не выполнялся. Предсуществующая whitespace-правка connectionLifecycle.ts исключена; новые MD-файлы не создавались.

## 2026-10-06 — PR #22: сохранить watchdog при отказе остановки
- По повторному ревью перенесён единственный stopProxyWatchdog после подтверждённого выхода runtime: отказ/таймаут/ошибка проверки сохраняют живой upstream, мониторинг и сетевую защиту. Удалён tunShutdownOrder.test.ts с поиском фрагмента исходника и точными последовательностями mock calls; пять сценариев перенесены в существующий AST harness полного stop (AT-02-005/009, F-029). Проверяются состояния runtime/upstream/watchdog/baseline/firewall/adapters до proof, после успеха, при трёх отказах и retry. Два дублировавшихся случая уже покрыты full-stop/native tests; новых рабочих сущностей нет, код и тесты уменьшились на 34 строки до записи журнала.
- Red run: npx.cmd vitest run src/main/lifecycleCleanup.test.ts --reporter=dot — 5 failed / 88 passed до переноса строки. Green: npx.cmd vitest run src/main/lifecycleCleanup.test.ts src/main/tunControllerRecoverySource.test.ts --reporter=dot — 113 passed; npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/pr22-watchdog-tests-20261006.json — 2621 passed / 9 skipped / 0 failed, 211 файлов passed / 2 skipped, 134.42 с. npm.cmd run typecheck и npm.cmd run build — exit 0; python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; git diff --cached --check — exit 0. Установленный клиент и системная сеть не менялись; installer/L3 не проверялись. Новых MD-файлов нет; предсуществующая whitespace-правка connectionLifecycle.ts исключена.

## 2026-10-06 — WP-2 / WP-3: отказ остановки в main и сохранение мониторинга (PR #22)

- По самостоятельной проверке кода исправлены три подтверждённых дефекта: shutdown продолжал снимать сетевую защиту после неподтверждённого выхода runtime; обычный Stop очищал IP/счётчики и восстанавливал адаптеры при success:false; монитор чужого TUN отключался до подтверждения выхода. Верхний Stop теперь проверяет результат до побочных действий, сохраняет живую сессию и снимает свой флаг при исключении. Shutdown сначала выполняет native backstop и свежий inspect-runtime с requireProof=true; при отказе/частичном kill, живом процессе или ошибке запроса прекращает очистку и не допускает installer ACK. После восстановившего выход fallback контроллер повторно подтверждает остановку и согласует своё состояние.
- Обработчик stopping/error/adapting сохраняет счётчики, sampler и forensics, пока runtime отмечен живым; трей не показывает off/protected при неподтверждённой остановке. Монитор чужого TUN выключается рядом с watchdog после exit proof. История закрывается после подтверждённой остановки со снимком счётчиков до сброса. В рабочих исходниках 48 добавленных / 43 удалённых строки, прирост 5; новые рабочие сущности и MD-файлы не создавались.
- Существующий AST harness полных production-функций расширен на 16 случаев (AT-02-005/009, AT-03-007, AT-11-002): отказ/исключение Stop и retry, ожидание результата без очистки/истории, сохранение счётчиков, свежий proof и согласование контроллера после fallback, живой/неизвестный runtime, шесть статусов main. Имеющиеся five-case проверки полного stop теперь учитывают также competing monitor. Старые фикстуры отказа сетевого rollback уточнены: runtime уже остановлен, сетевое восстановление не подтверждено. Red: npx.cmd vitest run src/main/lifecycleCleanup.test.ts --reporter=dot — 18 failed / 89 passed на старом коде; промежуточно 4 старые фикстуры отказа сети требовали уточнения. Финальный npx.cmd vitest run src/main/lifecycleCleanup.test.ts src/main/tunControllerRecoverySource.test.ts src/main/mainIpcRegression.test.ts --reporter=dot — 149 passed, exit 0.
- Из vpn-tunnel-enforcer: npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/pr22-main-stop-tests-20261006.json — 2637 passed / 9 skipped / 0 failed, 211 файлов passed / 2 skipped, 135.67 с, exit 0; npm.cmd run typecheck — exit 0; npm.cmd run build (включая финальный typecheck) — exit 0; python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; git diff --check — exit 0. Проверки lifecycle выполнялись с fake OS boundaries; установленный клиент, системная сеть и нормативные документы не менялись. NSIS не пересобирался; реальные upgrade/L3 не проверялись. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — сверка WP-1/WP-3/WP-11 после PR #21/#22 и порядок работ

- Обновлены статусы плана ТЗ-06, индекс docs, адресные строки срезов томов 2/3 и существующий отчёт WP-1. PR #21 (`5764bc8`) реализовал default masking/main-owned opt-in export, DPAPI preflight, IPC/CSP и runtime ACL/hash; #21/#22 (`324c7cc`) реализовали controlled installer shutdown и сохранение защиты до runtime exit proof. F-144/F-183 больше не представлены отсутствующей реализацией, но полная приёмка не объявляется.
- Раздел 7 ТЗ-06 согласован с порядком docs/README.md: миграция Electron выполнена; WP-1 частично проверен; следующий рекомендуемый фокус — адресная матрица AT-03-001…012 и остаток WP-3, затем WP-0 → WP-2 → WP-10. WP-3 уже реализовывался, однако packet oracle/SYSTEM reboot/NAT64/hot-plug/DNS/ACL/OS matrix не приняты; отдельный остаток WP-1 сохраняется.
- Из vpn-tunnel-enforcer: npm.cmd run typecheck — exit 0; npm.cmd test -- --reporter=dot — 211 файлов passed / 2 skipped, 2648 тестов passed / 9 skipped / 0 failed, 157.84 с, exit 0. Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0. Inline python -X utf8 - проверил 52 local links, четыре столбца таблиц, неизменность требований перед срезами и порядок WP; первый отказ был неточным строковым ожиданием checker, исправленный checker — PASS. git diff --check — exit 0.
- Только документация: source/tests/resources и действующая система не изменялись. Windows/L3/native/full fuzz/42→44/NSIS не выполнялись; старые результаты отчётов не выданы за свежий прогон. Предсуществующая правка connectionLifecycle.ts сохранена и исключена из коммита.

## 2026-10-07 — решение владельца: WP-1 завершён

- По прямому сообщению владельца «wp -1 завершён» текущий статус WP-1 изменён на завершён в индексе, плане ТЗ-06 (§10.10), пояснениях срезов томов 2/3 и отчёте WP-1. Предыдущая частичная отметка заменена; следующий рекомендуемый пакет — WP-3, затем WP-0. Исторические PASS/FAIL/NOT-CHECKED сохранены, невыполненные системные проверки не объявлены PASS.
- Только документация. npm.cmd run typecheck — exit 0; npm.cmd test -- --reporter=dot — 211 файлов passed / 2 skipped, 2648 тестов passed / 9 skipped / 0 failed, 159.09 с, exit 0. python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0. Inline python -X utf8 -: согласованный статус в пяти документах, локальные ссылки и неизменность нормативных требований перед срезами — PASS; git diff --check — exit 0. Предсуществующая правка connectionLifecycle.ts сохранена отдельно.

## 2026-10-07 — WP-3 / AT-03-007: ошибка вместо успеха при неполном rollback

- Исправлён подтверждённый аудитом ложный общий успех: обычный Stop после подтверждённого выхода runtime, но при ошибках baseline/firewall/adapters/DNS, возвращает success:false, сводку ошибок и рекомендацию повторить остановку/проверить диагностику. currentStatus сохраняет предупреждение; статус error заменяет stopped, поэтому UI не получает сообщение об обычном восстановленном маршруте. Независимость шагов отката и повторная попытка сохранены. В рабочих исходниках суммарно +5 строк; нормативные документы не менялись.
- Внутренний runtimeStopped отделяет доказанный выход процесса от полного успеха очистки. Main закрывает завершившуюся сессию и очищает связанные ресурсы, сохраняя ошибочный результат для IPC; внутренние подтверждения в IPC не передаются. При неподтверждённом выходе main по-прежнему сохраняет живую сессию/мониторинг/защиту. Shutdown выполняет свежий native exit proof и повторяет неподтверждённые сетевые шаги; оставшийся отказ блокирует ACK и освобождение recovery helper. Исполняемые тесты расширены; удалена устаревшая source assertion, закреплявшая success:true при неполном rollback.
- Red: npx.cmd vitest run src/main/lifecycleCleanup.test.ts --reporter=dot — 12 failed / 104 passed на старом коде, exit 1. Green: npx.cmd vitest run src/main/lifecycleCleanup.test.ts src/main/tunControllerRecoverySource.test.ts src/main/mainIpcRegression.test.ts --reporter=dot — 155 passed, exit 0; после этого добавлены ещё две регрессии свежего shutdown proof, включённые в полный прогон. Из vpn-tunnel-enforcer: npm.cmd run typecheck — exit 0; npm.cmd test -- --reporter=dot --reporter=json --outputFile=.tmp/wp3-stop-tests-20261007.json — 211 файлов passed / 2 skipped, 2656 тестов passed / 9 skipped / 0 failed, 159.24 с, exit 0. Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py — AC927/927, F210/210, exit 0; git diff --check — exit 0.
- Закрыт конкретный дефект общего результата AT-03-007 (том 2 §2.1), а не весь WP-3 или полный AT с единым correlation id всех шагов. Дефекты recovery/schema, hot-plug и IPv6/NAT64 из аудита остаются открытыми. Исходные находки F-040/F-148 относятся к другим компонентам и этим изменением не объявляются закрытыми. Проверки lifecycle используют подменённые OS boundaries; installed клиент, системная сеть, L3/reboot и NSIS не менялись и не проверялись. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — WP-3 / AT-03-003/006/012: recovery preflight и смена NIC

- Boot recovery проверяет ACL и версии всех пяти входных журналов до сетевых изменений; использует единый прочитанный набор. Неизвестная версия и недоверенный ACL оставляют сеть неизменной с ошибкой. Повреждённое доверенное содержимое изолируется в карантин; для firewall допускается предусмотренный ТЗ Allow fallback только при собственных правилах и отсутствии выбранного strict. Неизвестная strict policy не разрешает сброс. Обычный firewall rollback также различает corruption, неподдерживаемую версию и ошибку доверия; неподдерживаемый/недоверенный вход не вызывает системных изменений. Quarantine требует повторной проверки каталога/файла и подтверждения rename.
- Lockdown снимает свежий набор GUID перед применением и после native batch; повторное использование журнала также проверяет фактический набор. Добавление, исчезновение, замена NIC или ошибка запроса вызывают компенсацию; неподтверждённая компенсация сохраняет pending journal и предупреждение. Переименование того же GUID допустимо. Это исправляет обнаружение hot-plug внутри apply, но не является доказательством L3 защиты при смене NIC в течение всей активной сессии.
- Red: новые NIC-регрессии — 7 failed / 33 passed; новые boot-регрессии — 8 failed / 45 passed в объединённом прогоне. Green: `npx.cmd vitest run src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryBehavior.test.ts src/main/bootRecoveryScriptSource.test.ts src/main/physicalAdapterLifecycle.test.ts` — 67 passed; `npx.cmd vitest run src/main/firewallTransactions.test.ts src/main/recoveryManifestStorage.test.ts` — 108 passed / 1 skipped. Boot execution теперь запускается автоматически на Windows с PowerShell, без обязательного VPNTE_PWSH; все системные эффекты в harness подменены.
- Проверки из vpn-tunnel-enforcer: `npm.cmd run typecheck` — exit 0; `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-recovery-nic-tests-20261007.json` — 2682 passed / 4 skipped / 0 failed, exit 0. Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0. Предсуществующая правка connectionLifecycle.ts исключена.
- IPv6/NAT64: выявлено противоречие тома 2 §1.1.3 — явный Windows Firewall Block перекрывает Allow. Владелец выбрал отдельный WFP-фильтр, разрешил уточнить нормативный механизм и увеличить объём кода. Реализация и Windows L3 остаются следующими шагами; WP-3 не объявлен завершённым.

## 2026-10-07 — WP-3 / AT-03-010: отдельная IPv6 WFP-политика и независимое восстановление

- По прямому решению владельца уточнены том 2 §1.1.3/§2.1 и AT-03-010; решение записано в §10.11 ТЗ-06. Вместо невыполнимого приоритета обычного Allow над Block ::/0 реализован собственный WFP sublayer `VPNTE.IPv6.v1`: persistent блокировка обоих ALE-направлений, boot-time блокировка до запуска BFE и узкие soft permit. Нативный помощник — C# поверх штатного user-mode WFP API, без драйвера; закреплённый SHA-256 одинаково проверяется приложением и recovery-скриптом до компиляции. Новый ресурс включён в electron-builder.
- Разрешение VPN ограничено совместными условиями App ID + endpoint `/128` + LUID физического интерфейса; TUN проверяется по GUID/драйверу/PnP/подсети. DNS64-префикс /32, /40, /48, /56, /64, /96 признаётся только по обеим контрольным ответам ipv4only.arpa; разрешается синтезированный адрес сервера, а не весь NAT64-префикс. Неизвестные endpoint не получают разрешение. У локального прокси автоматически доказаны только уже установленные IPv6 TCP-соединения; неизвестный UDP endpoint остаётся заблокированным. Это ограничение доступности, а не доказательство работоспособности CLAT.
- Подготовленная политика сохраняется в доверенный firewall.json до эффектов; native apply атомарен, read-back проверяет точный набор до/после commit, перечисление включает boot-time/disabled фильтры. Live-исключения отражаются в WFP и Firewall; компенсация каждого механизма выполняется независимо. Ошибка cleanup сохраняет журнал, включая boot recovery; strict recovery WFP не снимает. Повторный старт проверяет IPv6, прежний обход проверки через `isKillSwitchActive()` удалён.
- Устранены общие mutable-флаги ошибки чтения журнала: read-only probes не карантинируют файлы, recovery сериализован с firewall-мутациями. Вложенная будущая IPv6-схема блокирует изменения; карантин повторно проверяет fingerprint повреждённого содержимого и выполняется через типизированный привилегированный worker, без повторения uncertain completion. Native fixture проверяет отказ для изменённого/недоверенного содержимого и настоящий rename только в собственной `.tmp`-папке. Расширение скрипта обнаружило лимит командной строки Windows: фиксированный worker теперь передаётся с gzip-сжатием в памяти; настоящий PowerShell framing/read/quarantine/exit снова прошёл.
- Проверки из `vpn-tunnel-enforcer`: `npx.cmd vitest run src/main/wfpIpv6.test.ts --reporter=dot` — 17 passed, включая компиляцию production C#, SDK x64 ABI и транзакционные fault fixtures; `npx.cmd vitest run src/main/recoveryManifestStorage.test.ts src/main/recoveryPsWorker.test.ts src/main/firewallTransactions.test.ts --reporter=dot` — 145 passed / 1 skipped после исправления transport; дополнительные регрессии включены в финальный полный прогон. `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-wfp-final-tests-20261007.json` — **2718 passed / 4 skipped / 0 failed**, 214 файлов в JSON-отчёте (213 с passed-тестами), 136.57 с, exit 0. `npm.cmd run typecheck`, `npm.cmd run build`, `npm.cmd run dist:win` — exit 0. `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` из корня — AC927/927, F210/210, exit 0. Проверка локальных ссылок изменённых документов и `git diff --check` — exit 0.
- В `dist/win-unpacked/resources/` подтверждены C#-ресурс и recovery; проверка SHA-256 в ресурсе, boot script и main внутри app.asar — PASS (`99382d8ef48069fa80ca8cb5811e7dec708e4440f98a04e74eed2a742d69997e`). Инсталлятор `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: SHA-256 `5ee9a07fb135641fcede5e52799b90be778cb7d12598886a04e2506545300aa9`, Authenticode `NotSigned`. Проверка asar первоначально использовала POSIX-путь на Windows; исправленная проверка с `path.normalize(pkg.main)` прошла. Установка не выполнялась.
- Нативная попытка read-only enumeration вернула Win32 error 5 / Access denied в текущем непривилегированном процессе. Реальные фильтры не устанавливались/не удалялись; безопасность и доступность WFP, persistent→boot переход, packet oracle, IPv6-only/NAT64/464XLAT, SYSTEM reboot и OS-матрица **не подтверждены** этими fixtures. Затронута реализация AC-LEAK-NET-003…005, AT-03-001/003/004/007/008/010/012, F-016/F-030/F-031/F-033/F-034/F-043/F-186; находки и весь WP-3 не объявлены полностью принятыми. Следующий шаг — Windows/L3 WP-3, после приёмки WP-0. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

### 2026-10-07 — WP-3: исправление регрессии установленного kill-switch и задержек отмены

- По `%APPDATA%/vpn-tunnel-enforcer/logs/app.log` в установленной сессии 19:15–19:16 подтверждён отказ нового WFP-кода из `5fcb825`: Windows PowerShell 5.1 передаёт JSON-массив одним объектом в pipeline, присваивание массива `id` полю Guid падает (`System.Object[] → System.Guid`). Подключение отменено с rollback, успешная защита не заявлена. Декодирование правил заменено явным `foreach`; нативный тест теперь исполняет настоящие генерируемые apply/verify-скрипты с production C# и fake WFP engine. Прежняя фикстура проверяла C# с вручную созданными правилами и не покрывала этот мост JSON/PowerShell.
- IPv6/NAT64 discovery через отдельный `Resolve-DnsName` занял 11642 мс; запрос отмены ждал завершения старта 8816 мс. Теперь отдельный Node Resolver ограничен общим таймером 1500 мс, имеет одну попытку, получает AbortSignal от lifecycle и отменяет DNS при Cancel. Отсутствие AAAA/таймаут не создаёт IPv6 transport permit: изоляция сохраняется, доступность IPv6-only аплинка без доказанных адресов не обещается. Проверены stalled DNS, немедленная отмена, уже отменённый старт, отсутствие IPv6, передача сигнала и запрет эффектов после отмены.
- В логах каждого WFP-запроса helper отвергал `Add-Type`, вызывая protected-file fallback и повторную компиляцию (подготовка заняла ещё 2000 мс). Добавлена отдельная helper policy `wfp-ipv6`: исключён из запретов только точный bundled загрузчик после проверки SHA-256; произвольный Add-Type, изменённый загрузчик и посторонние firewall/adapter mutations остаются запрещены. Сборка типа повторно используется внутри постоянного PowerShell, свежие native reads выполняются каждый раз. Сама внутренняя stop-процедура в проблемной сессии заняла 1290 мс; длительная отмена включала ожидание неотменяемого discovery и повторный cleanup. Ускорение реального installed подключения после исправления пока не измерено.
- Проверки из `vpn-tunnel-enforcer`: `npx.cmd vitest run src/main/wfpIpv6.test.ts src/main/elevatedPsHelper.test.ts src/main/elevatedPsHelperNative.test.ts src/main/firewallTransactions.test.ts src/main/firewallManifestSecurity.test.ts --reporter=dot` — 120 passed / 1 skipped, exit 0. `$env:VPNTE_PWSH = (Get-Command pwsh.exe).Source; npx.cmd vitest run src/main/wfpIpv6.test.ts --reporter=dot` — 24 passed на PowerShell 7.6, exit 0; нативная фикстура также прошла на штатном Windows PowerShell 5.1. `npm.cmd run typecheck` — exit 0.
- Первый полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-runtime-regression-tests-20261007.json` — 2722 passed / 6 failed / 4 skipped, exit 1: извлечённый startup callback в тестовом стенде не имел нового `startAbortController`. Стенд дополнен настоящим AbortController и проверкой передачи сигнала; `npx.cmd vitest run src/main/tunControllerStartup.test.ts src/main/wfpIpv6.test.ts src/main/elevatedPsHelper.test.ts src/main/firewallTransactions.test.ts --reporter=dot` — 129 passed / 1 skipped, exit 0. Финальный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-runtime-regression-final-20261007.json` — **2728 passed / 4 skipped / 0 failed**, 214 файлов в JSON, 124.27 с, exit 0.
- `npm.cmd run dist:win` — exit 0; проверено наличие decoder, новой helper policy, DNS deadline и AbortSignal в main внутри packaged app.asar. Инсталлятор `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe` пересобран; SHA-256 `fb6a28e04d6b2405c53974c1c5c4541894e80ce991f80f683a52ef13f7c53e13`. Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0. Установка, реальное подключение, изменения системной сети и reboot в этой проверке не выполнялись; WP-3 остаётся частичным. Предсуществующая правка connectionLifecycle.ts не включена.

## 2026-10-07 — WP-3: фактический native WFP read-back и лишнее DNS-ожидание

- В новой installed-сессии (app.log, 16:40 UTC) старый JSON/Guid отказ исчез. DNS вернул ENODATA примерно за 16 мс; stop занял 274 мс. Новая причина отказа — `Foreign WFP sublayer; unchanged`, ошибочно скрытая за общим `DefaultOutboundAction`. Elevated диагностика внутри откаченной транзакции показала: перед Ensure собственный sublayer отсутствует (`0x80320007`), после создания GUID/name/description/flags/provider совпадают, но BFE вернул weight 65533 вместо запрошенного 65535. Фиксированный requested weight больше не используется как доказательство чужого владельца: идентичность проверяется отдельно, безопасность — по фактическому приоритету и отсутствию более высоких/равных активных hard permit.
- Реальный BFE, в отличие от прежнего fake engine, выявил ещё два дефекта: ненулевой enum template с пустым Layer GUID даёт `0x80320004`; Windows добавляет `INDEXED (0x40)` к persistent фильтру (`flags=65`). Перечисление теперь идёт отдельно по трём требуемым слоям; INDEXED принимается как оптимизация поиска. Неизвестные flags и disabled persistent фильтры по-прежнему отвергаются, disabled boot допустимы после BFE transition. Проверены негативные flags, приоритеты ниже/равно/выше и неактивный hard permit. SHA-256 C# одинаково обновлён в main и recovery: `26aa1dd13059f6a3582ebbae2421833323d03340771bfbce5198d1dad628e712`.
- На текущем компьютере обнаружен активный `sing-tun` hard permit на ALE_AUTH_CONNECT_V6 с weight 65535, sublayer `13f79b99-1874-4007-8639-6a38f4804c99`; одновременно работают Happ.exe, happd.exe и sing-box.exe. Конкретный App ID чужого фильтра не сопоставлялся с процессом: принадлежность Happ вероятна, не объявлена доказанной. Такой permit может обойти более низкую IPv6-политику, поэтому production activation отклоняется с понятным сообщением о конфликте. Чужие фильтры и процессы не изменялись. По исходнику SagerNet sing-tun strict_route создаёт собственный hard permit для ядра; пустой собственный WFP-контейнер теперь резервируется **до** запуска нашего sing-box, а фильтры трафика по-прежнему устанавливаются только после подтверждения TUN и записи recovery journal. Проверены ожидание раннего reserve и прекращение старта при конфликте. Нормативные документы не изменялись.
- DNS discovery больше не выполняется, если существующий read-only этап подготовки не обнаружил физический IPv6 default route: для IPv4-only аплинка нет запроса DNS и дополнительного helper roundtrip. При физическом IPv6 discovery сохраняет предел 1500 мс и AbortSignal; узкие endpoint permits создаются только после доказательства адреса/маршрута. Проверены hostname и IPv4 literal без IPv6, отсутствие подтверждённого снимка, timeout/cancel и сохранение блокировок. Работоспособность NAT64/CLAT этим не доказана.
- Из `vpn-tunnel-enforcer`: `npx.cmd vitest run src/main/wfpIpv6.test.ts src/main/firewallTransactions.test.ts src/main/elevatedPsHelper.test.ts src/main/tunControllerStartup.test.ts src/main/tunControllerPreparation.test.ts` — **142 passed / 1 skipped**, exit 0. `npm.cmd run typecheck` — exit 0. `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-wfp-native-final-20261007.json` — **2734 passed / 4 skipped / 0 failed**, exit 0 (170.2 с по интервалу testResults; параллельно выполнялась сборка). Ожидаемый stderr RootErrorBoundary не является провалом теста. Из корня `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0.
- Elevated Windows PowerShell: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/test-wfp-ipv6-native.ps1 -OutputPath .tmp/wp3-native-20261007.json` — exit 0: `ok=true`, `rules=23`, `aborted=true`, **priority=conflict**. Скрипт проверил настоящие Add/Enum/read-back для block/LAN/TUN/VPN/user-app/user-IP на всех трёх слоях внутри транзакции без commit. Тестовый wrapper отделяет ABI-проверку от отдельно вызываемой production проверки приоритета; успешный ABI smoke **не означает успешное включение защиты**. Более ранние native прогоны действительно падали на enum layer и flags до исправления. Трафиковые фильтры не оставлены; AT-03-001/010 L3 с внешним capture, мобильная сеть и reboot не выполнялись, WP-3 остаётся частичным.
- `npm.cmd run dist:win` — exit 0. Пересобран `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139195283 байта, SHA-256 `0bf0b174d59098597b8253cd2049aca374fac3e68645b8079b4960cfce225748`. Проверены reserve/uplink/conflict и новый hash в main из app.asar, совпадение bundled C# и recovery pin. Установщик в этом прогоне не устанавливался, фактическое подключение после обновления не измерено. Предсуществующая правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — WP-3: отказ обязательного LAN Allow в установленной сессии

- Свежий app.log (19:49 UTC / 22:49 МСК): WFP reserve, prepare и apply выполнены; Windows Firewall отказался продолжать без `VPNTE-killswitch-allow-lan`. Весь start-direct-vpn с компенсацией занял 8347 мс. Долгого IPv6 DNS discovery в этой попытке нет; start Xray занял 2583 мс (prepare-runtime 1400 мс, allow-firewall 955 мс, включая очередь). Позднейший обычный stop в 19:50 UTC занял 409 мс и подтвердил cleanup. Happ TUN обнаружен после отказа; он не объявляется причиной данной попытки.
- Причина доказана без изменения системной сети: настоящий `HNetCfg.FwRule.RemoteAddresses` отвергает `::1/128` и `::1`; остальные IPv4/IPv6 LAN CIDR принимаются вместе. Ошибочный комментарий про несовместимость смешанных семейств исправлен: сам API допускает оба семейства ([INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)). Исключён только IPv6 loopback из обязательного LAN-правила; отдельная WFP loopback-политика, IPv4 loopback и IPv6 LAN `fc00::/7`, `fe80::/10`, `ff00::/8` сохранены. Нормативные документы не менялись.
- Новый AT-03-001/010 regression исполняет извлечённый из настоящей enable-транзакции LAN-блок и production COM API с реальным unregistered FwRule; Rules.Add заменён коллекцией в памяти. Проверяется успешное создание обязательного правила и read-back полного набора LAN-адресов. До исправления: `npx.cmd vitest run src/main/firewallTransactions.test.ts -t 'real Windows COM address validation'` — 1 failed / 67 skipped, `WARN allow-lan: Value does not fall within the expected range.`, exit 1. После: `npx.cmd vitest run src/main/firewallTransactions.test.ts src/main/firewallRulesApi.test.ts src/main/wfpIpv6.test.ts --reporter=dot` — 117 passed / 1 skipped, exit 0, Windows PowerShell 5.1. Повтор нового теста с `$env:VPNTE_PWSH=(Get-Command pwsh.exe).Source` — 1 passed / 67 skipped на PowerShell 7, exit 0.
- Из vpn-tunnel-enforcer: `npm.cmd run typecheck` — exit 0; `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-lan-native-final-20261007.json` — 2735 passed / 4 skipped / 0 failed, exit 0 (165.24 с по интервалу testResults; параллельно сборка). Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0. `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0. Исправленные LAN scopes проверены внутри packaged app.asar. Пересобран `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139195308 байт, SHA-256 `5b758ebc6fcff8bf702e6d569655bcd2cab313a5e727e5fc3dc784f8067b44d8`. Установка и реальное подключение после этой правки не выполнялись; native property validation не заменяет L3 трафик/reboot/NAT64, WP-3 остаётся частичным. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — WP-3: проверка свежих логов и двух дополнительных регрессий

- Installed app.log (19:59–20:00 UTC / 22:59–23:00 МСК) после c1acb05: три успешных start-direct-vpn за 6824, 4986 и 4986 мс; initial-apply-policy, commit recovery journal и kill-switch подтверждены. Отключения целиком по IPC заняли 2690, 2865 и 2778 мс (внутренний stop 2440, 2540, 2414 мс); cancel-tun — 2121 мс, отменённый start вернул явный отказ. Все networkCleanup baseline/firewall/adapters подтверждены. SIGKILL Xray следует за пользовательским stop, а не является самостоятельным падением. Startup warning об отсутствии owned DNS baseline сохраняет чужие настройки. Новых error в этом интервале нет, долгого IPv6 discovery нет. Ответы старта содержат vpnIp=null: внешний egress IP и отсутствие утечек этим не доказаны.
- Проверены изменения d0471a7..c1acb05: WFP native flags/ABI, приоритеты, prepare/DNS/NAT64, отмена, apply/verify/rollback, live exceptions, manifests/quarantine, helper policy, worker launcher и boot recovery. Найден пропуск в новой проверке WFP priority: она учитывала только статический PERMIT с CLEAR_ACTION_RIGHT, игнорируя deciding callouts. FWP_ACTION_CALLOUT_TERMINATING/UNKNOWN могут вернуть PERMIT; callback может снять ACTION_WRITE ([FWPM_ACTION0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0), [classifyFn](https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nc-fwpsu-fwps_callout_classify_fn1)). Более высокий/равный deciding callout теперь признаётся непроверенным конфликтом; disabled/inspection, soft permit и более низкий приоритет не вызывают этот отказ. Чужие фильтры не изменяются. SHA-256 C# одинаково обновлён в main и recovery: 6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249.
- Скомпилированный production C# regression проверяет все три слоя, оба типа deciding callout, флаги CLEAR_ACTION_RIGHT/PERMIT_IF_CALLOUT_UNREGISTERED, disabled и приоритеты ниже/равно/выше. До исправления `npx.cmd vitest run src/main/wfpIpv6.test.ts -t 'transaction/ABI regressions'` — 1 failed / 27 skipped, exit 1 (`higher deciding callout must be rejected`); после проходит также с `$env:VPNTE_PWSH=(Get-Command pwsh.exe).Source`: 1 passed / 27 skipped, exit 0. Это доказательство дефекта статической проверки, не выполненный трафиковый тест с kernel callout.
- Второй дефект воспроизведён настоящими Windows FileStream/Replace/Move на временных файлах: FileShare.Read|Delete не мешает атомарной замене pathname; проверялись старые повреждённые байты, а в quarantine уходил новый файл. Production quarantine теперь проверяет хэш реально перенесённого файла с read-lock. Если перенесена замена, её возвращают только в свободный исходный путь и отказывают recovery до сетевых эффектов. Если там уже появился ещё более новый baseline, он не перезаписывается, обе версии сохраняются и успех не выдаётся. Исправление общее для typed worker и privileged fallback.
- AT-03-003/012 native quarantine дополнен replaced/replaced-again: до исправления `npx.cmd vitest run src/main/recoveryManifestStorage.test.ts -t 'native quarantine with replaced'` — 1 failed / 1 passed / 58 skipped, exit 1 (ошибочный успех вместо отказа). После тот же фильтр на PowerShell 7 — 2 passed / 58 skipped, exit 0; полный focused на штатном Windows PowerShell 5.1 прошёл. Временные диагностические файлы удалены; системная сеть и реальные manifests тестами не изменялись.
- Из vpn-tunnel-enforcer: `npx.cmd vitest run src/main/wfpIpv6.test.ts src/main/firewallTransactions.test.ts src/main/firewallRulesApi.test.ts src/main/bootRecoveryExecution.test.ts src/main/elevatedPsHelper.test.ts src/main/elevatedPsHelperNative.test.ts src/main/recoveryManifestStorage.test.ts src/main/recoveryPsWorker.test.ts src/main/tunControllerStartup.test.ts --reporter=dot` — 258 passed / 1 skipped, exit 0 (до второго исправления). После обоих: `npx.cmd vitest run src/main/recoveryManifestStorage.test.ts src/main/recoveryPsWorker.test.ts src/main/firewallTransactions.test.ts src/main/wfpIpv6.test.ts --reporter=dot` — 179 passed / 1 skipped, exit 0. `npm.cmd run typecheck` — exit 0.
- Первый общий прогон после обоих исправлений: `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-wfp-recovery-audit-final-20261007.json` — 2736 passed / 1 failed / 4 skipped, exit 1. Упавший старый twitchHlsProbe.test.ts действительно ходит к двум внешним Twitch-серверам с бюджетом 3500 мс на каждый, но лимит теста 5000 мс; сбой произошёл на 5020 мс. Этот код в задаче не менялся. `npx.cmd vitest run src/main/twitchHlsProbe.test.ts --reporter=verbose` — 14 passed, exit 0. Финальный повтор без параллельной сборки: `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-wfp-recovery-audit-recheck-20261007.json` — **2737 passed / 4 skipped / 0 failed**, exit 0, 164.81 с по testResults. Нестабильность сетевого теста остаётся отдельным ограничением; первый отказ не скрыт. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0. В packaged app.asar проверены quarantine moved-file read-back и новый pin; bundled C# и boot recovery содержат совпадающий pin. Финальный dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe — 139195820 байт, SHA-256 ff02ba30045149049c344f8117f5b0c148fd0516acf23ad9c25f561e4cf72d0a. Эта сборка в проверке не устанавливалась; L3 с внешним capture, NAT64/CLAT, матрица Windows и reboot не выполнены. Нормативные документы не менялись; предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-07 — WP-3: лишняя WFP-проверка Xray и параллельная подготовка runtime

- По команде владельца проверены installed app.log/app.prev.log. До отдельной WFP-политики повторные успешные start-direct-vpn: 3404/3664 мс; свежие 22:59 — 4986/4986 мс, 23:24 — 4504 мс; первый свежий запуск 23:23 — 7781 мс. Это отдельные наблюдения, а не статистика или одинаковый лабораторный стенд. В последних двух успешных запусках kill-switch подтверждён; прежний DefaultOutboundAction/WFP отказ не повторился.
- На запуске 23:24 Xray allow-firewall занял 645 мс: COM presence read 219 мс и ненужный здесь WFP presence read 416 мс, включая ожидание общей helper queue. Затем отдельно prepare-runtime sing-box занял 694 мс. Установка IPv6-политики занимает дополнительное время и остаётся обязательной; ошибки защита/скорость не подменяются ложным успехом.
- ensureKillSwitchProgramAllowed проверяет доверенный manifest и свежие собственные Windows Firewall rules; WFP-only presence не вызывает добавление COM Allow и не ставится в эту очередь. isKillSwitchActive, orphan WFP cleanup, reservation перед strict_route, journal/apply/read-back WFP и профиль Block сохранены. Не добавлен кэш состояния защиты.
- В Direct VPN/Xray подготовка sing-box ACL/бинарников перекрывается с Xray startup; существующая дедупликация делит только ещё выполняющуюся проверку ACL, завершённые proofs по-прежнему не кешируются. Конфигурация ждёт фактические SOCKS port/resolved endpoint Xray. Cancellation проверяется до/после ACL и перед конфигурацией; finally удерживает владельца start до завершения параллельной подготовки файлов. SHA-256/identity/reparse проверки ресурсов сохранены. Local proxy validation и прямой sing-box path сохранены. Трассировка: AT-01-009, AT-02-002/005, AT-03-003/004/010/012, F-030/F-043.
- Регрессии выполняют production preparation с подменёнными OS-границами: actual endpoint/port barrier, отказ ACL, отмена во время ACL/после staging, Xray failure, ранний отказ staging, ownership до его завершения, orphan WFP/Firewall и недоверенный journal. При заданных задержках Xray 1500 мс / staging 700 мс join завершён за 1500 мс вместо последовательных 2200; это компонентное доказательство, не новая installed latency.
- Из vpn-tunnel-enforcer: `npm.cmd run typecheck` — exit 0. `npx.cmd vitest run src/main/tunControllerPreparation.test.ts src/main/tunControllerStartup.test.ts src/main/firewallTransactions.test.ts src/main/runtimeDirSecurity.test.ts src/main/runtimeArtifact.test.ts src/main/xrayRuntimeLifecycle.test.ts src/main/tunControllerRecoverySource.test.ts src/main/wfpIpv6.test.ts --reporter=dot` — **279 passed / 1 skipped**, 8 файлов, 9.44 с, exit 0. Первый focused из 3 файлов до адаптации тестового стенда: 99 passed / 3 failed / 1 skipped; две старые проверки порядка ожидали последовательную подготовку, третья считала объявление PS-функции её вызовом. Стенд исправлен; production/native обходов проверок для получения PASS нет.
- Полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-connect-overlap-20261007.json` — **2750 passed / 4 skipped / 0 failed**, 214 файлов в JSON, 128.48 с, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0 (трассировка, не L3). `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0, Electron 44.4.3/NSIS; optional mksnapshot штатно пропущен. ASAR main побайтово совпадает с compiled output; проверены parallel startup/join/cancel markers и отсутствие WFP presence в program allow; неизменённый bundled WFP source совпадает с pin. Main SHA-256 a067ce8725dc23649ee3e8ac5a9139b4b71f1665b8f6a7f20c01fca206dca44b. `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139195623 байт**, **07.10.2026 23:38:27 МСК**, SHA-256 **73d20f139b9641c636bcb2ca0b397a8d5a94b3da77fe6f3ed589d45bea153330**, Authenticode NotSigned.
- Сборка агентом не установлена; новое реальное время подключения, L3 packet oracle, NAT64/CLAT и reboot не проверены. Нормативные документы не менялись, WP-3 остаётся частичным. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита. Revert scoped commit возвращает последовательную подготовку и лишний presence round-trip, формат manifests/settings не меняется.

## 2026-10-08 — WP-3: проверка первого подключения и перенос чтения runtime ACL в worker

- По запросу владельца проверен installed app.log. После предыдущего исправления 07.10 в 23:49 первое/повторное start-direct-vpn заняли 4108/2821 мс. После запуска приложения 08.10 в 08:45:59 первое подключение в 08:46:04 заняло **6563 мс**, повторное — **4080 мс**. В обоих свежих подключениях kill-switch подтверждён; новых ошибок защиты в просмотренных логах до 09:10:52 нет. Это наблюдения отдельных запусков, без одинакового стенда и статистической оценки.
- На первом утреннем запуске Xray prepare-runtime занял 2836 мс, на повторном — 887 мс; весь Xray startup — 3587/1384 мс. Physical DNS sources — 2182/391 мс; adapter lockdown — 3138/1686 мс; TUN kill-switch — 1583/1195 мс, часть этапов перекрывается. Prepare-runtime включает чтение ACL, staging и проверки ресурсов: все 2836 мс не приписываются ACL. Уже существующий прогрев helper/recovery worker завершился до первого подключения; повторный прогрев не добавлялся.
- Чтение ACL использует существующий постоянный RecoveryPsWorker через новую фиксированную операцию inspect-runtime-acl. Standalone/bootstrap и worker разделяют один алгоритм инспекции: известный ProgramData, родительская цепочка root-first, owner/ACE/type/reparse, полный список потомков. Каждая попытка получает свежий снимок; кэш успешных proofs не добавлен. Изменение ACL, ошибка, неполный снимок, закрытый worker/очередь/таймаут запрещают успех. Standalone чтение разрешено только при unavailable до dispatch. Создание защищённых каталогов остаётся прежней отдельной фиксированной командой; SHA-256/identity проверки бинарников сохранены. Прогрев worker импортирует встроенный ACL-модуль по пути PSHOME. В журнал добавлены transport/durationMs чтения ACL. Трассировка: AT-01-009, AT-03-012, F-002/F-005/F-006/F-104.
- Native компонентный замер выполнен без повышения прав на существующем C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security: одинаковые production проверки отказались авторизовать этот системный каталог как runtime. До прогрева Security-модуля отдельные процессы: 522/461/446 мс; worker: 186/22/26 мс. После штатного warmup: standalone **502/406/488 мс**, worker **146/77/34 мс**. Worker завершён с подтверждённым exit. Защищённый runtime приложения недоступен процессу Codex (исходный замер остановился на EPERM); измерение на системном каталоге доказывает выигрыш транспорта, а не время elevated подключения или запуск после reboot. Временный read-only harness .tmp/runtime-acl-transport-bench.cjs использовался командой `node .tmp/runtime-acl-transport-bench.cjs 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security'`.
- Добавлены регрессии на свежую проверку изменённого родителя, недопустимый/неполный worker proof, сохранение bounded diagnostic отказа, отсутствие fallback после busy/closed/timeout/exited/protocol/rejected, повторную native валидацию входных полей/путей и целостность frames после отказа. Native dispatcher с подменёнными cmdlets возвращает полную цепочку и отклоняет writable parent без OS mutations.
- Из vpn-tunnel-enforcer: `npx.cmd vitest run src/main/runtimeDirSecurity.test.ts src/main/recoveryPsWorker.test.ts src/main/recoveryPsProtocol.test.ts src/main/recoveryPsWorkerNative.test.ts` — **220 passed**, 4 файла, 132.35 с, exit 0 (до последних dispatcher регрессий). `npx.cmd vitest run src/main/runtimeDirSecurity.test.ts src/main/recoveryPsProtocol.test.ts src/main/recoveryPsWorkerNative.test.ts src/main/recoveryPsWarmup.test.ts` — **197 passed**, 3 совпавших файла, 113.93 с, exit 0. `npm.cmd run typecheck` — exit 0.
- Полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-cold-acl-20261008.json` — **2769 passed / 4 skipped / 0 failed**, 214 файлов в JSON, 147.31 с по testResults, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; это трассировка, не Windows L3 acceptance. `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0; optional mksnapshot штатно пропущен. Packaged app.asar main совпадает с compiled output; проверены inspect-runtime-acl / Read-RuntimeAclSnapshot / inspection timing. Main SHA-256 **7f196dee5e5189350382b4f6453bfa2466aa8c68829f3abe563c6b58868aabb1**. Installer dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe: **139195897 байт**, **08.10.2026 09:13:27 МСК**, SHA-256 **db709aa533c21e7ccdbcb4d5327760eb556774a609f180a5c15fa7ed204ea36b**, Authenticode NotSigned.
- Установка сборки и новый замер первого/повторного подключения остаются ручной проверкой; L3 packet oracle, NAT64/CLAT и reboot не выполнялись. Нормативные документы не менялись, WP-3 остаётся частичным. Предсуществующая whitespace-правка connectionLifecycle.ts исключена из коммита.

## 2026-10-08 — WP-3: устранение задержек прогрева и DNS в очереди подключения

- По команде владельца разобран installed app.log после утренней сборки: start-direct-vpn 09:18:58.472 → 09:19:04.116 — **5644 мс**; повторные подключения — **2480/2524 мс**. Во всех трёх kill-switch подтверждён и leak-test успешен. Последняя запись лога — 09:26:25; новых подключений во время исправления нет. Эти отдельные наблюдения не являются статистикой после reboot.
- Первый запрос Firewall ждал уже выполнявшийся необязательный прогрев адаптеров: total 1180 мс при native execution 22 мс. Прогрев закончился в 09:18:59.711, через 1239 мс после кнопки. Далее чтение физических адаптеров/DNS занимало helper 734 мс; WFP reservation получил total 830 мс при native execution 93 мс. Эти перекрывающиеся этапы не складываются как независимые задержки всего подключения; прочие холодные Windows-запросы также медленнее повторных.
- Из helper удалён прогрев NetAdapter/DnsClient/NetTCPIP; оставшийся прогрев Firewall пропускается при уже допущенных командах. Эти адаптерные модули готовит существующий RecoveryPsWorker, куда добавлен DnsClient. Уже исполняющийся native запрос не прерывается. Отдельные новые процессы или очереди мутаций не добавлены.
- Полный read-only снимок физических адаптеров выполняется в том же RecoveryPsWorker через фиксированную операцию inspect-physical-adapters; DNS discovery больше не занимает очередь WFP/Firewall. Исходный PS-алгоритм вынесен без изменения классификации в physicalAdapterSnapshot.ts и общий для обоих транспортов. Запрос допускает только поле op; native и JS отклоняют произвольный script/alias. Для отсутствующих адаптеров native dispatcher возвращает строку `[]`; lockdown по-прежнему отказывает при пустом наборе. Helper fallback разрешён только при unavailable до dispatch, без повтора busy/closed/timeout/exited/protocol/rejected. Существующие сроки кэшей, свежие snapshots перед/после lockdown, GUID ownership, durable journal, read-back, отмена и rollback сохранены. Трассировка: AT-02-005, AT-03-005/006/007/010/012.
- Регрессии проверяют свободный helper при незавершённом DNS-чтении, свежий снимок после invalidation, отсутствие fallback при uncertain completion, пустые результаты и закрытые поля протокола. Настоящий PowerShell dispatcher проверяет baseline/IPv6-only/отсутствующие адаптеры с fake cmdlets без OS writes; настоящий постоянный worker читает адаптеры/DNS дважды, сохраняет framing и завершение с подтверждённым exit. Native проверка выявила пустой PS pipeline при отсутствии адаптеров; обработка исправлена и повторный прогон зелёный. Read-only диагностика `node .tmp/ps-warmup-cost.cjs` показала только стоимость прежних импортов в отдельных процессах: NetAdapter/DnsClient/NetTCPIP **2791/2172/2563 мс**, не новую installed latency.
- Из vpn-tunnel-enforcer: `npx.cmd vitest run src/main/elevatedPsWarmup.test.ts src/main/elevatedPsHelperNative.test.ts src/main/physicalAdapterHotspot.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/physicalAdapterLockdownSource.test.ts src/main/recoveryPsWorker.test.ts --reporter=dot` — **93 passed**, 6 файлов, exit 0. `npx.cmd vitest run src/main/physicalAdapterSnapshot.test.ts src/main/recoveryPsWorkerNative.test.ts --reporter=dot` — **15 passed**, 2 файла, exit 0. После исправления пустого native результата: `npx.cmd vitest run src/main/recoveryPsProtocol.test.ts -t physical --reporter=dot` — **5 passed / 92 skipped** (фильтр), exit 0. `npm.cmd run typecheck` — exit 0. Полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-cold-queue-20261008.json` — **2790 passed / 4 skipped / 0 failed**, 215 файлов, 186.39 с по testResults, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; это трассировка, не Windows L3 acceptance.
- `npm.cmd run dist:win` — exit 0; optional mksnapshot штатно пропущен. `node .tmp/verify-cold-queue-artifact.mjs` — exit 0: app.asar внутри NSIS совпадает с win-unpacked, main совпадает с compiled output; проверены новая фиксированная операция, guard очереди, отсутствие тяжёлого helper warmup и неизменённый WFP pin/source в приложении и boot recovery. Main SHA-256 **d7b760d08b010f554c84826dc3c8be536b5a95d2735764f49d97bc29758683d6**. Installer dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe: **139196061 байт**, **08.10.2026 19:45:45 МСК**, SHA-256 **d64c387048f6f37b07943dae58e70355f7d96a987f1961f5d59a60c0e07adcca**, Authenticode NotSigned. dist/checksums.txt обновлён; отчёты оставлены в .tmp, собственные временные harness и распаковка удалены.
- Сборка агентом не установлена, новое реальное время подключения не измерено. L3 packet oracle, NAT64/CLAT и reboot не выполнялись; WP-3 остаётся частичным, нормативные документы не менялись. Предсуществующая whitespace-правка connectionLifecycle.ts сохранена и исключена из коммита. Возврат scoped commit восстанавливает прежний транспорт снимка и прогрев; форматы settings/manifests не изменены.

## 2026-10-08 — WP-3: исправление регрессии очереди DNS/ACL после da47906

- Installed логи сессии 19:53 МСК после da47906 подтвердили ухудшение: start-direct-vpn 7373/3715/3793 мс вместо прежних 5644/2480/2524 мс; stop 2689/2276/2287 мс, cancel-tun 2116 мс. Первый полный снимок адаптеров в recovery worker занял 896 мс, поставленная за ним проверка ACL — 1044 мс. Baseline/read-back также занимали этот worker. Первый native adapter batch — 1816 мс против повторных 536/542 мс; удалённый прогрев откладывал загрузку модулей до подключения. Это наблюдения отдельных сессий, не статистика. Все три старта подтверждали DefaultOutboundAction Block; level=error не было, cleanup baseline/firewall/adapters подтверждён. SIGKILL соответствовал пользовательскому stop. Эти логи не доказывают отсутствие утечек.
- Исправление по команде владельца: routing/bootstrap DNS использует закрытую read-only операцию `inspect-physical-dns`, читающую только выбранные физические адаптеры и IPv4 DNS. Полный снимок с GUID, binding, routes, профилями, источником DNS и классификацией hotspot возвращён в существующий elevated helper вместе с adapter mutations; он больше не занимает очередь runtime ACL. Общий фиксированный выбор адаптеров исключает расхождение двух запросов. Полные baseline и read-back не заменены DNS-кэшем; журнал, свежие проверки после lockdown, rollback и WFP не ослаблены.
- Routing-only кэш сохраняет прежние 60 секунд, одновременные запросы объединяются. Некорректные JSON, индексы, alias и DNS отвергаются. Повтор через helper разрешён только при typed `unavailable` до отправки; busy/timeout/exited/closed/protocol/rejected не переигрываются. Старый полный worker op отвергается, канал по-прежнему не принимает scripts/произвольные alias.
- Прогрев helper восстановлен четырьмя отдельными фиксированными read-only командами NetAdapter/DnsClient/NetTCPIP/NetConnection после NetSecurity. Проверка admitted queue и владельца выполняется перед каждой; при поступлении рабочей команды следующие импорты пропускаются. Уже выполняемый native импорт не прерывается. Результаты прогрева не используются как доказательство защиты. Дополнительных процессов и параллельных сетевых mutations нет.
- Регрессии AT-01-009/AT-02-005/AT-03-006/010/012: отложенный full baseline не отправляется в ACL worker; отмена после снимка не выдаёт applied; одновременное чтение DNS отправляется один раз; helper fallback остаётся узким; malformed data и expanded requests отвергаются; IPv6-only/mobile classification сохраняется. Native helper исполняет пять production warmup commands и полный production snapshot. Native worker исполняет новый DNS op дважды с подтверждённым exit. Native dispatcher использует запрещающие fake baseline cmdlets: узкий DNS reader их не вызывает и OS writes не выполняет.
- Read-only сравнение production RecoveryPsWorker до/после: `node .tmp/wp3-dns-queue-bench.cjs` — exit 0. Первый запрос 1866 → 202 мс, повторные 312/312 → 83/74 мс; ожидание поставленной за ним ACL-validation 1922 → 271 мс, повторные 321/318 → 92/128 мс. ACL-validation намеренно отказывает на несовпадении ProgramData до чтения ACL файлов; это замер очереди, не успешная проверка настоящего runtime и не время полного подключения. Worker exit подтверждён; сеть не изменялась. Отчёт `.tmp/wp3-dns-queue-benchmark-20261008.json` сохранён.
- Из vpn-tunnel-enforcer: `npx.cmd vitest run src/main/physicalAdapterSnapshot.test.ts src/main/elevatedPsWarmup.test.ts src/main/elevatedPsHelperNative.test.ts src/main/physicalAdapterHotspot.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/recoveryPsWorker.test.ts src/main/recoveryPsWorkerNative.test.ts --reporter=dot` — **109 passed**, 7 файлов, exit 0. `npx.cmd vitest run src/main/recoveryPsProtocol.test.ts -t physical --reporter=dot` — **4 passed / 93 skipped** (фильтр), exit 0. `npm.cmd run typecheck` — exit 0; повторён также внутри успешной сборки после последнего изменения.
- Финальный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-dns-queue-regression-20261008.json` — **2798 passed / 4 skipped / 0 failed**, 215 файлов, 281.81 с по testResults, exit 0. Новый native DNS-only positive case прошёл в полном наборе. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; это покрытие трассировки, не Windows L3 acceptance. `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0; optional mksnapshot пропущен. `node .tmp/verify-dns-queue-artifact.mjs` — exit 0: NSIS app.asar совпадает с win-unpacked, main с out; подтверждены узкий DNS reader, helper baseline, пять раздельных warmup commands, guard очереди и отсутствие старого полного worker op. WFP source/pin **6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249** неизменён, совпадает в main/boot recovery и ресурсах внутри NSIS. Main SHA-256 **dc18027682675ce841d8825d9fe4aadc61ac7e2a7b1e843d6bfad55dc811ac6a**. Installer `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139196358 байт**, **08.10.2026 20:22:50 МСК**, SHA-256 **81e1ba449e996100e8af69066767854d49315d19c1e1332dd1c745f276699669**, Authenticode NotSigned. dist/checksums.txt обновлён; JSON-отчёты оставлены в .tmp, собственные harness и распаковка удалены.
- Новая сборка агентом не установлена, её полное время первого/повторного подключения не измерено. L3 packet oracle, NAT64/CLAT и reboot не выполнены; WP-3 остаётся частичным. Нормативные документы и форматы manifests/settings не менялись. Предсуществующая whitespace-правка connectionLifecycle.ts сохранена и исключена из коммита.

## 2026-10-08 — WP-3: продолжение прерванного прогрева с приоритетом lifecycle

- Installed main SHA-256 подтвердил сборку 5f9f027. В сессии 20:26–20:27 МСК: успешные start-direct-vpn **5793/3437/3455 мс**, stop-tun **2389/2267/2156 мс**, cancel-tun **1577 мс**; отменённый start вернул явный отказ за 1732 мс. DefaultOutboundAction Block подтверждён на всех трёх стартах; cleanup baseline/firewall/adapters — true после каждого stop/cancel; level=error нет. SIGKILL следовал за ручной остановкой/отменой. Ускорение относительно da47906 подтверждено, но прежние повторные 2480/2524 мс не достигнуты; сравнение отдельных сессий не является статистикой. Завершённого leak-test в коротких соединениях нет.
- Причина оставшейся задержки: warmup выполнил NetSecurity и NetAdapter, затем `pendingCommands.size > 0` завершил цикл навсегда. Остальные Net-модули подгружались при первом full snapshot: native **1877 мс** против повторных **372/362 мс**. Чтение routing DNS уже короткое — worker 174 мс; ACL roundtrip 316 мс. Первый Xray resolve-server — 1209 мс; system-lookup дал IPv4 после 1097 мс (1208 мс с начала гонки), повторные resolve4 — 13–43 мс. Код уже гоняет operation-owned resolver с Windows lookup после 100 мс, отменяет только свой resolver и не публикует поздние ответы. Искусственного секундного sleep нет; внешний DNS-ответ не считается устранённой задержкой этим исправлением.
- По команде владельца warmup теперь ждёт освобождения admitted queue и продолжает с того же модуля. Фиксированные команды/политики и последовательный native runner сохранены; результаты не используются как доказательство защиты. `ConnectionLifecycle.busy` охватывает startup, полный stop effect и закрытый lifecycle. Main передаёт gate busy/running/shutdown/quit: optional imports не начинаются в паузах между native-шагами пользовательской операции. Уже исполняемый импорт не прерывается. При остановке/замене исходного helper ожидание прекращается, другой процесс не запускается; таймер ожидания unref. Логи содержат только фиксированное имя модуля и события deferred/resumed/timing.
- Регрессии AT-02-005/AT-03-007: admitted work до начала и между импортами; продолжение без повторного импорта пройденных модулей; lifecycle busy при пустой native queue; stop effect после окончания startup; закрытый lifecycle; замена/остановка helper во время ожидания; running/shutdown/quit gate; отсутствие оставшихся таймеров и приватного native payload. До изменения `npx.cmd vitest run src/main/elevatedPsWarmup.test.ts src/main/connectionLifecycle.test.ts --reporter=dot` — **10 failed / 19 passed**, exit 1; в частности прежний код оставлял 0/2 imports вместо 5 после освобождения очереди. После исправления тот же запуск — **29 passed**, exit 0. Первый typecheck обнаружил недостающую аннотацию `call` в новом тесте; исправлено, повторный `npm.cmd run typecheck` — exit 0.
- `npx.cmd vitest run src/main/elevatedPsWarmup.test.ts src/main/connectionLifecycle.test.ts src/main/elevatedPsHelperNative.test.ts src/main/elevatedPsHelper.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/xrayDns.test.ts src/main/xrayDnsNative.test.ts --reporter=dot` — **116 passed**, 7 файлов, exit 0. Native DNS использовал только локальный UDP fixture: held response 3059 мс, hedged lookup 109 мс; этот сценарий не измеряет DNS провайдера. Native helper исполнял реальные fixed module imports и fresh adapter baseline без сетевых/registry mutations.
- `node .tmp/wp3-resumable-warmup-bench.cjs` — exit 0: actual production warmup function/runner до/после с одной admitted service-read командой (фикстура удерживает её 150 мс). Все три прежних прогона завершились после NetSecurity/NetAdapter, все три новых продолжили DnsClient/NetTCPIP/NetConnection; native exit подтверждён. Native full-baseline **2813/2223/2402 → 421/452/434 мс**, roundtrip **2816/2227/2407 → 422/453/436 мс**. Это чтение снимка после фоновой подготовки, не полное время installed VPN connect; процессы запускались последовательно, Windows file cache не изолировался. Сеть не изменялась, installer не запускался. JSON `.tmp/wp3-resumable-warmup-benchmark-20261008.json` сохранён.
- Финальный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-resumable-warmup-suite-20261008.json` — **2808 passed / 4 skipped / 0 failed**, 215 файлов, 171.29 с по testResults, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0. Трассировка не означает Windows L3 PASS.
- `npm.cmd run dist:win` — exit 0, включая повторный typecheck; optional mksnapshot штатно пропущен. `node .tmp/verify-resumable-warmup-artifact.mjs` — exit 0 после исправления проверки поля module (bundler переименовал локальную переменную в module2; используется AST поля, не буквальный shorthand). NSIS app.asar совпадает с win-unpacked, main с out; busy/pause/owner gates, unref, deferred/resumed и module timing подтверждены. WFP source/pin **6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249** неизменён и совпадает в main/boot recovery и внутри NSIS. Main SHA-256 **649d133926fdff97b67a9f74d68ec404b82551a467902362715d4228b8318f43**. Installer `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139196646 байт**, **08.10.2026 20:48:27 МСК**, SHA-256 **a78e2ac5e39a0c354e59a8dc38ebd3c3d36dd71ed81e5e35744c6c9ad10d2f45**, Authenticode NotSigned. dist/checksums.txt обновлён; JSON-отчёты сохранены, собственные harness/распаковка удалены.
- Сборка с продолжением прогрева агентом не установлена; её первое/повторное подключение ещё не измерено. Если подключение началось до завершения фоновой подготовки, оставшиеся imports ждут окончания lifecycle; гарантии одинаковой cold/warm latency нет. L3 packet oracle, NAT64/CLAT и reboot не выполнялись; WP-3 остаётся частичным, нормативные документы не менялись. В connectionLifecycle.ts коммит включает только новый busy getter; предсуществующая whitespace-правка первого комментария сохранена вне коммита.

## 2026-10-08 — WP-3: ускорение свежего определения сети перед подключением

- По команде владельца исправлен отдельный PowerShell для adaptive network identity. В установленной предыдущей сборке fbc0409 журнал 21:02 МСК показал первое подключение **4475 мс**, повторные **3030/2914 мс**; определение сети перед каждым запуском занимало **525/517/495/474 мс**, включая отменённую попытку. У первого запуска свежий снимок адаптеров занимал 916 мс против 333/342 мс у повторных; это остающийся источник cold-start latency, не устранённый данной правкой.
- Добавлена фиксированная read-only операция `inspect-network-identity` существующего RecoveryPsWorker. Запрос допускает только `op`, без script/path/alias; JS и native dispatcher повторно проверяют поля. Исходный CIM-скрипт перенесён без изменения в adaptiveNetworkIdentityScript.ts и используется обоими транспортами. Каждый вызов получает свежие адаптеры, NLA-профили и активные default routes; кэш результатов не добавлен. HMAC, IPv4/IPv6-only identity, отказ от обучения при unknown и отсутствие приватного payload в логах сохранены.
- Standalone fallback разрешён только для `unavailable` до dispatch; busy/closed/timeout/exited/protocol/rejected и ошибки JSON возвращают unknown без скрытого повторного процесса. Сохранены deadline 4000 мс и предел 256 KiB ответа; владение допущенными worker-командами/завершение процесса не изменены. Native запрос не меняет сеть, реестр, ACL или файрвол. Трассировка: AT-10-007, AT-03-012; эта правка не закрывает весь WP-10/3 или F-128.
- Добавлены регрессии на отсутствие spawn в обычном пути, свежий изменившийся fingerprint input, все worker failure classes, ограниченный fallback, malformed/oversized ответы, Unicode и IPv6-only. Реальный dispatcher исполняется с fake CIM cmdlets: три отказа провайдера, profile-only/gateway-only/empty и отбор физических NIC. Постоянный настоящий worker читает новую операцию дважды, сохраняет последующие DNS frames и подтверждает собственный exit. Первый `npx.cmd vitest run src/main/adaptiveNetworkIdentity.test.ts --reporter=dot` до реализации — **15 failed / 10 passed**, exit 1; четыре native failures включали ошибку тестового harness ENAMETOOLONG. Harness переведён на gzip launcher по образцу production; ожидания ошибок CIM уточнены до `fixture failure`. После исправления `npx.cmd vitest run src/main/adaptiveNetworkIdentity.test.ts src/main/adaptiveBypass.test.ts src/main/recoveryPsWorkerNative.test.ts --reporter=dot` — **52 passed**, 3 файла, exit 0.
- `node .tmp/wp3-network-identity-bench.cjs` — exit 0: production reader до/после на настоящем Windows PowerShell, текущей сети и одном уже прогретом worker. Старый/новый скрипт совпал; все три свежих результата совпали, значения сети не сохранены. **Standalone 684/432/436 → worker 231/73/70 мс**; собственный worker завершён с подтверждённым exit. Admin boundary подменена только в read-only harness, UAC и сетевые изменения не выполнялись. Это компонентный выигрыш транспорта **453/359/366 мс**, а не measured installed VPN startup. Worker startup/warmup выполнен до замеров, как при штатной подготовке приложения; ОС/file cache не изолировались. JSON `.tmp/wp3-network-identity-benchmark-20261008.json` сохранён.
- `npm.cmd run typecheck` — exit 0. Полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-network-identity-suite-20261008.json` — **2824 passed / 4 skipped / 0 failed**, 215 файлов, **240.72 с** по testResults, exit 0. `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — **AC927/927, F210/210**, exit 0; это coverage, не Windows L3 PASS. `git diff --check` — exit 0.
- `npm.cmd run dist:win` — exit 0, включая повторный typecheck; optional mksnapshot штатно пропущен. `node .tmp/verify-network-identity-artifact.cjs` — exit 0 после исправления Windows-разделителя пути в собственном ASAR harness. Извлечённый из NSIS app.asar совпал с win-unpacked, main — с out; новая fixed operation, свежие active routes, output bound/fallback, resumable warmup и narrow DNS подтверждены. Main SHA-256 **606f07be94410829541882f1d7d793d652c7a362a67bcfff4299216f1a56ef8b**. Embedded WFP/boot recovery совпадают с ресурсами; WFP pin **6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249** сохранён. Installer `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139196569 байт**, **08.10.2026 21:25:35 МСК**, SHA-256 **8b500786f4c26517d3777de8af5ff216911031540a611532f63c49ccb75ad00a**, Authenticode **NotSigned**. dist/checksums.txt обновлён; JSON suite/benchmark/artifact reports сохранены, собственные harness и распаковка удалены.
- Агент не устанавливал сборку и не измерял первое/повторное подключение после неё. Оставшаяся очередь helper, cold NetConnection и установка kill-switch данной правкой не сокращаются; стабильные 2–3 с первого подключения не заявляются. Нормативные документы не менялись, L3 packet oracle/NAT64/CLAT/reboot не выполнялись, WP-3 остаётся частичным. Предсуществующая whitespace-правка connectionLifecycle.ts сохранена вне коммита.

## 2026-10-08 — WP-3: отдельная очередь чтений адаптеров и короткий прогрев recovery

- Установленная сборка ab791e2 подтверждена по main SHA-256. Сессия 21:29–21:30 МСК: успешные подключения **6659/3225/3260 мс**, stop **2400/2331/2412 мс**, cancel **2562 мс**. Чтение adaptive identity ускорилось до **216/84/85/81 мс**, но общее подключение не ускорилось. Первый full snapshot исполнялся **1912 мс** в elevated helper; разрешение Xray исполнялось **25 мс**, но roundtrip **1420 мс** включал **1395 мс** очереди/транспорта. Recovery warm-up был монолитным, **2045 мс**; foreground manifest read занял 671 мс. Native Set-NetFirewallProfile Block занял 586 мс против прежних 150 мс — причина вариации Windows этой сессией не установлена. Все три старта подтвердили Block, stop/cancel cleanup baseline/firewall/adapters — true; level=error нет. Это не L3 packet oracle.
- По команде владельца создана вторая постоянная очередь на существующем классе RecoveryPsWorker: только fixed read-only adapter inspections. Full baseline/read-back и transition snapshot больше не занимают elevated helper или runtime ACL/recovery queue. Узкое чтение routing DNS и fresh TUN identity используют тот же подготовленный adapter process; результаты DNS не подменяют full lockdown proof. Исходные full/DNS/transition scripts, выбор NIC, mobile/IPv6-only classification, свежая проверка GUID после mutations и сохранение pending manifest до mutations не изменены. AT-03-005/006/007/010/012, F-035/F-039/F-044; весь WP-3 не объявляется принятым.
- Native adapter role повторно ограничивает операции: warmup-adapters, inspect-physical-dns, inspect-tun, inspect-physical-adapters, inspect-transition-adapters. ensure/remove/ACL/runtime mutations отклоняются до исполнения. module — только NetAdapter/DnsClient/NetTCPIP/NetConnection, никаких incoming script/path. Recovery warm-up импортирует только Security; Net modules прогреваются по одному в adapter worker, с уступкой admitted queue и busy/running/shutdown/quit между imports и после подтверждения process readiness. Пройденные imports не повторяются; остановка исходного процесса прекращает ожидание. Таймер deferred unref; логи — fixed module/operation/outcome/timing без native payload. Уже исполняемый import не прерывается.
- Admission shutdown закрывается сразу для обеих очередей; stop ждёт всё admitted work и фактический close обоих процессов. Snapshot fallback допускается только при unavailable до dispatch; timeout/exited/protocol/busy/closed/rejected и generic failure не запускают повторное чтение или mutation. Сохранены queue cap 8, ограничение frame/output и прежние deadlines. Новое состояние сети не кэшируется сверх существующих operation caches; rollback/Firewall/WFP mutations остаются прежними.
- RED `npx.cmd vitest run src/main/adapterInspectionWorker.test.ts src/main/recoveryPsWorker.test.ts --reporter=dot` — **6 failed / 33 passed**, exit 1 до реализации. Первый расширенный запуск 8 файлов — **33 failed / 213 passed**, exit 1: увеличенный native fixture превысил CreateProcess argv limit; в test harness payload перенесён на stdin, проверки invalid requests теперь требуют конкретную native validation error. Production gzip launcher работал в persistent native tests. Первый typecheck выявил недостаточно узкий тип нового test table; исправлено. Повтор `npx.cmd vitest run src/main/adapterInspectionWorker.test.ts src/main/recoveryPsWorker.test.ts src/main/recoveryPsProtocol.test.ts src/main/recoveryPsWorkerNative.test.ts src/main/physicalAdapterSnapshot.test.ts src/main/physicalAdapterHotspot.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/elevatedPsWarmup.test.ts --reporter=dot` — **246 passed**, exit 0.
- Дополнительный `npx.cmd vitest run src/main/adapterInspectionWorker.test.ts src/main/recoveryPsWorker.test.ts src/main/recoveryPsWorkerNative.test.ts src/main/physicalAdapterSnapshot.test.ts src/main/physicalAdapterHotspot.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/elevatedPsWarmup.test.ts src/main/elevatedPsHelperNative.test.ts src/main/physicalAdapterLockdownSource.test.ts --reporter=dot` — **149 passed**, exit 0. Регрессии охватывают held full snapshot при независимом ACL, один процесс с изменившимися reads, DNS/TUN queue routing, обе shutdown admissions, startup/elevation race, отказ native mutation в adapter role, отмену до adapter effects, недоступность/ошибки транспорта, прежний hotspot/IPv6-only baseline и post-mutation verification.
- `node .tmp/wp3-adapter-queues-bench.cjs` — exit 0, реальные PowerShell/production runner и worker, без сетевых/registry mutations. При подготовленных NetSecurity/NetAdapter и холодных остальных модулях: profile read во время full snapshot **3956/3476/3657 → 69/39/48 мс**; full snapshot **4010/3530/3719 → 3098/2938/3175 мс**; independent ACL read **198/160/198 → 258/227/236 мс**. Снимки во всех трёх парах совпали; исходный full script совпал с HEAD. Exit обоих RecoveryPsWorker после каждого прогона подтверждён; helper штатно остановлен с выдержкой его exit grace. Admin boundary подменена только в read-only harness, UAC/installer не запускались. Это компонентный замер очереди, не VPN connect benchmark; Windows/file cache не изолировались. JSON `.tmp/wp3-adapter-queues-benchmark-20261008.json` сохранён без сетевых идентификаторов.
- Первый полный `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-adapter-queues-suite-20261008.json` запускался до финальной правки readiness gate: **2852 passed / 2 failed / 4 skipped**, exit 1 (manual-priority regression и ETIMEDOUT native profile-only fixture). После правки `npx.cmd vitest run src/main/recoveryPsWorker.test.ts src/main/adapterInspectionWorker.test.ts --reporter=dot` — **47 passed**; адресный повтор с identity fixture `npx.cmd vitest run src/main/adaptiveNetworkIdentity.test.ts src/main/recoveryPsWorker.test.ts --reporter=dot` — **66 passed**, exit 0. Финальный неизменяемый код: `npm.cmd test -- --reporter=json --outputFile=.tmp/wp3-adapter-queues-suite-final-20261008.json` — **2854 passed / 4 skipped / 0 failed**, **216 файлов**, **193.96 с**, exit 0. `npm.cmd run typecheck` — exit 0; `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC927/927, F210/210, exit 0; `git diff --check` — exit 0. Coverage не является выполнением L3 AT.
- `npm.cmd run dist:win` — exit 0, включая повторный typecheck; optional mksnapshot штатно пропущен. `node .tmp/verify-adapter-queues-artifact.cjs` — exit 0: NSIS embedded ASAR совпал с win-unpacked, main с out; isolated pools, native read-only gate, bounded fixed operations, cooperative warm-up и прежний identity read подтверждены. Embedded WFP/boot recovery совпали с исходниками; WFP pin **6eebcb4430e2b8969d94d9afb09eb803296dfd8cbea5eaf24b8a78407db06249** неизменён. Main SHA-256 **4b7886919cbd7ed64149e942b32cc292611a82768be162f14c0f8040610e55ac**. Installer `dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`: **139197055 байт**, **08.10.2026 22:03:52 МСК**, SHA-256 **c37b673aa4c2773d2694a9f197ae1248bb7bbbd58afb0fa13e1cc3cc71703a02**, Authenticode **NotSigned**; dist/checksums.txt обновлён. JSON-отчёты сохранены, собственные harness/распаковка удалены.
- Новая сборка агентом не установлена. Полное первое/повторное подключение и cancellation latency после неё ещё не измерены; 2–3 секунды не гарантируются. Native firewall transaction не ускорялась и остаётся отдельным ограничением. Нормативные документы не менялись; L3/NAT64/CLAT/reboot не выполнялись. Предсуществующие два пробела перед первым комментарием connectionLifecycle.ts сохранены вне коммита.

## 2026-10-10 — PR #23: исправление замечаний CodeRabbit и Revix (WFP preflight и обработка ошибок исключений)

### Что сделано
- В `vpn-tunnel-enforcer/src/main/index.ts`: в `clearStaleKillSwitchBeforeStart` убран аргумент `{ probeWfp: settings.firewallKillSwitch }`, вызов `isKillSwitchActive()` теперь выполняется безусловно. Если после предыдущего падения или аварийного завершения в системе остались изолированные фильтры WFP, preflight корректно обнаруживает их и выполняет очистку перед запуском Direct VPN независимо от значения пользовательской настройки `firewallKillSwitch`.
- В `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts`: в `updateExceptionsUnlocked` вызов `prepareWfpIpv6Exceptions` обёрнут в `try...catch`. При сбое подготовки WFP-исключений возвращается типизированный результат `{ success: false, state: 'unknown', message: 'IPv6 exception preparation failed; firewall unchanged', details: String(error) }` вместо необработанного отклонения промиса, журнал транзакции и правила брандмауэра остаются нетронутыми.
- В `vpn-tunnel-enforcer/src/main/firewallTransactions.test.ts`: добавлен модульный тест на сбой подготовки WFP-исключений при живом обновлении (AT-03-008), проверяющий возврат `state: 'unknown'`, отсутствие мутаций журнала манифеста и отсутствие запуска скриптов брандмауэра.
- В `vpn-tunnel-enforcer/src/main/lifecycleCleanup.test.ts`: добавлены тесты для `clearStaleKillSwitchBeforeStart` (AT-03-005/007), проверяющие безусловный опрос `isKillSwitchActive()` и снятие старой защиты перед запуском.

### Тестирование и Definition of Done
- `npm run typecheck` — без ошибок (exit 0).
- `npm test` — 2857 passed / 4 skipped / 0 failed (100% зелёные), 216 тест-файлов.
- `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC: 927/927, F: 210/210 (exit 0).
- Коммит `973c2a7` отправлен в ветку `codex/wfp-firewall-lifecycle-perf` репозитория `vpn` (PR #23), локальный `main` синхронизирован fast-forward.

## 2026-10-10 — Ускорение холодного подключения и устранение замечаний ревьюеров по PR #24

### 1. Ускорение первого холодного подключения VPN
- **CIM-пакетные запросы в PowerShell**:
  - `src/main/physicalAdapterSnapshot.ts`: прямой опрос через `Get-CimInstance` классов `MSFT_NetAdapter`, `MSFT_NetAdapterBindingSettingData`, `MSFT_DNSClientServerAddress`, `MSFT_NetRoute`, `MSFT_NetConnectionProfile` в пространстве `root/StandardCimv2`.
  - Устранена дорогостоящая загрузка тяжеловесного модуля `NetAdapter` на холодном старте.
  - Сохранён 100% совместимый fallback на командлеты в блоке `catch`.
- **Ранний фоновый прогрев адаптеров**:
  - `src/main/physicalAdapterLockdown.ts`: функции `getLocalNetSignature()`, `warmPhysicalAdaptersSnapshot()`, кеширование снимка адаптеров с TTL 30 секунд.
  - `src/main/index.ts`: вызов `warmPhysicalAdaptersSnapshot()` при старте окна, сброс кеша по `setNetworkChangeCallback`.

### 2. Исправление замечаний ревьюеров по PR #24 (CodeRabbit & Revix)
- **Счётчик поколений кэша** (`snapshotGeneration`) в `physicalAdapterLockdown.ts`:
  - `clearPhysicalAdaptersSnapshotCache()` инкрементирует поколение.
  - Асинхронный промис `snapshotPhysicalAdapters()` записывает результат в кэш только если `snapshotGeneration` не изменился с момента старта запроса.
  - Сброс `snapshotPromise` в `.finally` защищён проверкой `snapshotPromise === p`, предотвращая затирание более новых запросов.
- **Свежий снимок при наложении локдауна**:
  - `applyPhysicalAdapterLockdown()` по умолчанию запрашивает свежий снимок `{ forceFresh: options.forceFresh !== false }` перед записью манифеста восстановления, гарантируя актуальность DNS и шлюзов при формировании `pendingAdapters`.
  - `forceFresh: true` гарантированно обходит in-flight промис прогрева адаптеров.
  - Выровнен TTL в `warmPhysicalAdaptersSnapshot` до 30 секунд в соответствии со `snapshotPhysicalAdapters`.
- **Унификация и обработка ошибок CIM-запросов** в `physicalAdapterSnapshot.ts`:
  - Выделен единый шаблон исключения виртуальных адаптеров `ADAPTER_EXCLUSION_PATTERN`.
  - Дополнительные пакетные CIM-запросы (`MSFT_NetAdapterBindingSettingData`, `MSFT_DNSClientServerAddress`, `MSFT_NetRoute`, `MSFT_NetConnectionProfile`) выполняются с `-ErrorAction Stop`. При сбое любого из них управление передаётся в блок `catch` с гарантированным откатом на командлеты.
- **Очистка PR от временных скриптов**:
  - Удалены временные воркфлоу и скрипты триажа, ветка PR #24 сохранена строго сфокусированной на задаче ускорения холодного подключения.

### 3. Тестирование и Definition of Done
- `npm run typecheck` — 0 ошибок (exit 0).
- `npm test` — 2879 passed / 4 skipped / 0 failed (100% зелёные), 218 тест-файлов.
- `python ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC: 927/927, F: 210/210 (exit 0).

## 2026-10-13 — Нативные чтения, CI, исправление находок разбора PR (PR #26–#41)

Сессия охватывает работу после «Разбора всех PR репозитория» (11.10.2026). Порядок пакетов ТЗ в этой сессии не соблюдался: работа шла по списку находок разбора, привязка к WP дана ниже. По AGENTS.md это замечание: дальше работать по WP.

### Нативные чтения и запуск (WP-3 / WP-2, скорость запуска)
- **#26 → #27 → #30.** Низкоуровневые чтения сети через koffi (iphlpapi, реестр, WinINet) вместо холодного PowerShell. #26 принёс `koffi.view`, который под Electron 44 роняет процесс при запуске; #27 заменил его на `koffi.decode` и добавил проверку под настоящим Electron. #30 вынес все нативные чтения в `utilityProcess`: фатальная ошибка koffi теперь убивает только хост, основное приложение переживает и перезапускает его; любой сбой хоста — откат на PowerShell (fail-closed).
- **#28.** Свежий снимок адаптеров при локдауне по умолчанию (`forceFresh`), снимок экспортируется.
- **#32.** Читатель DNS для маршрутизации терпит адаптер без IPv4-DNS (категория `ObjectNotFound`), любая другая ошибка по-прежнему проваливает чтение.

### CI и окружение (WP-11)
- **#29.** GitHub Actions на Windows: типы, юнит-тесты, трассировка AT, сборка ETW-сайдкара, проверка нативных чтений под Electron. Версии действий закреплены по хешам, движки Xray и sing-box скачиваются с проверкой SHA-256.
- **Защита main:** слияние только через PR с зелёными обязательными проверками.
- **#33.** Минимум Node поднят до 24.21.0 (на Node 22.13 `fs.lstat` по пути на Windows возвращает `dev: 0`, из-за чего падали тесты безопасности). Обновлены `.nvmrc`, `engines`, README, AGENTS.md.
- **#38 (часть).** `fast-uri` 4.1.5 и `js-yaml` 4.3.2 берутся из npm, а не из GitHub по `git+ssh`. `gitHead` версий в npm совпадает с закреплёнными коммитами.
- **#35, #41.** Версии 1.1.23 и 1.1.24.

### Находки аудита, закрытые в этой сессии
| Находка | WP | Что сделано | PR |
|---|---|---|---|
| F-193 | WP-10 | `computeNextEvent` для ночных окон просматривает и вчерашний день; утреннее отключение больше не теряется | #34 |
| F-010 | WP-7 | несовпадение внешнего IP в тесте скорости не глотается: флаг `egressMismatch`, предупреждение в интерфейсе | #34 |
| F-210 | WP-7 | прямой ответ 401/403 без замера через VPN даёт `unknown`, а не `works-only-with-vpn` | #34 |
| F-047 | WP-4 | WireGuard собирается как `endpoint` sing-box 1.13 (`singBoxEndpoint.ts`); решение владельца: вариант C | #36 |
| F-076 | WP-6 | split tunneling по полному пути (`process_path_regex`, обе записи пути 8.3/длинная); файл переименован/удалён — правило не создаётся, запись в журнал | #37 |
| F-011 | WP-6 | счётчики попаданий доменных правил считаются по опросу подключений (смысл: домен подходит под шаблон) | #38 |
| AT-09-014 | WP-9 | мастер первого запуска: шаги импорта ключа и автозапуска, откат автозапуска при сбое | #38 |
| F-002 / F-104 (остаток) | WP-1 | создание защищённого runtime-каталога идёт через helper под политикой `runtime-acl`, без пути через голый `execElevated` | #39 |

Дополнительно в #38: `inspect-vpn-input` больше не записывает введённый ключ в настройки до подтверждения; `setLoginItemChecked` ждёт задачу планировщика, читает её обратно и откатывает при сбое.

### Что не доказано и не закрыто
- **Живая проверка на установленной сборке не сделана:** совпадение пути процесса, который видит sing-box, с нормализованным (split tunneling); запуск туннеля на WireGuard; шаги мастера на чистом профиле; задержка запуска после нативных чтений.
- Критерии приёмки пакетов WP-4, WP-6, WP-7, WP-9, WP-10 закрыты не целиком: исправлены отдельные находки.
- Открыты: вопрос подписи кода (раздел 10.8 ТЗ-06), PR #40 (сайт) и #41 (версия) ждут проверок.
- Известная нестабильность: `adaptiveNetworkIdentity.test.ts` изредка падает при полном локальном прогоне (холодный PowerShell дольше таймаута 10 с под нагрузкой); отдельно и в CI проходит.

## 2026-10-17 — Goal: WP-3 → WP-0 → WP-2; сверка WP-3 и строгие CIDR

Поручение владельца: последовательно закончить WP-3, WP-0, WP-2; вести этот
журнал, делать атомарные коммиты и PR, разбирать CI/review до отсутствия
существенных замечаний. Текущий пакет — WP-3; переход дальше пока не выполнен.

- Создана ветка `codex/wp3-acceptance` от актуального `vpn/main` (`c76d45a`).
  Предыдущий PR #45 проверен отдельно: Windows и Rust CI success; Revix neutral;
  замечания ревью — minor. Это не приёмка WP-3.
- Прочитаны AGENTS.md, все 12 AT-03, методология, нормативные разделы тома 2
  и принятые решения ТЗ-06. Матрица доказательств/пробелов каждого AT находится
  в `vpn-tunnel-enforcer/docs/wp3-acceptance-2026-10-17.md`.
- **AT-03-009:** найдено принятие масок `/0x10`, `/1e1`, `/+24`, `/24.0`
  и пробелов из-за `Number(prefix)`. В granular API они молча нормализовались;
  live firewall API допускал их до native effects. Теперь маска проверяется
  как десятичные цифры до преобразования. Валидные адреса/маски и действующие
  ограничения wildcard не изменены.
- Регрессии покрывают валидатор, granular validation и запрет journalling/native
  effects. Добавлены generated IPv4/IPv6 и numeric-coercion properties
  (seed 30009/30010/30011). До исправления: 17 failed / 106 passed / 1 skipped;
  после: 123 passed / 1 skipped, 3 files passed, exit 0.

Фактически выполненные проверки из `vpn-tunnel-enforcer/`:

```text
npm.cmd test -- src/main/firewallKillSwitchValidation.test.ts src/main/killSwitchExceptionValidation.test.ts src/main/firewallTransactions.test.ts
123 passed, 1 skipped; exit 0
npm.cmd run typecheck
exit 0
npm.cmd test
3113 passed, 5 skipped, 0 failed; 232 files passed, 2 skipped; 166.42 s; exit 0
```

Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
— AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.

Остаток и обнаруженные ограничения:

- AT-03-007: baseline пишет результаты шагов без общего operation/correlation id;
  это отдельный пробел наблюдаемости, требующий проверки/исправления.
- L3 не выполнен. Текущий агент без административного токена; Hyper-V VM
  зарегистрирована, но её VHDX отсутствует. Нет полной OS-матрицы, внешнего
  packet oracle и физического операторского 464XLAT-тетеринга. Рабочее
  установленное приложение запущено; сеть/DNS/firewall хоста не изменялись.
- Запуск `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
  vpn-tunnel-enforcer/scripts/test-wfp-ipv6-native.ps1` — exit 1, `ok=false`,
  `aborted=false`, cleanup `WFP error 0x8032000D` скрывает исходный отказ.
  Следующий шаг — исправить smoke harness, добавить привилегированную ABI-проверку
  в CI и разобрать её результат. Это не заменяет packet/reboot/OS acceptance.
- WP-3 остаётся частичным; локальный PASS и трассировка не дают основания
  объявить его принятым или перейти к WP-0. Нормативные `docs/` не менялись.

### WP-3: PR #46 и нативная проверка BFE

- Коммит `094662f` опубликован в PR #46:
  https://github.com/newnout6-a11y/vpn/pull/46 (base main, отдельная ветка WP-3).
- Исправлен smoke harness `scripts/test-wfp-ipv6-native.ps1`: отмечается только
  успешно начатая транзакция, нет Abort после отказа Begin/повторного Abort,
  Commit никогда не передаётся в native engine. Любая ошибка, включая Dispose,
  снимает `ok`. ABI/LUID fixture может использовать виртуальную NIC CI;
  это не приёмка физических интерфейсов или утечек.
- Добавлен fault-injection тест compiled C# wrapper с fake IEngine:
  исходная ошибка Begin сохраняется; несуществующая транзакция не откатывается;
  Commit не вызывается; начатая транзакция откатывается один раз.
- Добавлен обязательный Windows CI шаг «IPv6 WFP — нативный ABI и откат
  транзакции». Скрипт проверяет настоящие Windows API, не коммитит фильтры,
  результат пишет в RUNNER_TEMP и job log. Нужен фактический PASS на head PR.
- `npm.cmd test -- src/main/wfpIpv6.test.ts` — 28 passed, exit 0.
- `npm.cmd run typecheck` — exit 0.
- `npm.cmd test` — 3113 passed, 5 skipped, 0 failed;
  232 files passed, 2 skipped; 171.67 s, exit 0.
- Трассировка — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
- Повторный локальный native smoke — exit 1 с истинной причиной:
  `WFP error 0x00000005` (Access denied) на Begin. Транзакция не началась;
  L3 не пройден. Поиск доступных VHD/VHDX/ISO в Downloads/Public Documents
  не нашёл готового образа; зарегистрированный VHDX повторно проверен по
  точному пути из Hyper-V — отсутствует.
- Следующая доступная работа в WP-3: correlation id rollback-событий,
  расширение L1/L2 матрицы и разбор замечаний/проверок PR #46.

### WP-3: корреляция rollback, seeded race и реальные 8.3 paths

- В `systemNetwork.ts` baseline rollback получает UUID и возвращает его в
  `SystemNetworkResult.operationId`. Тот же ID есть у начала, двух native timings,
  девяти registry outcomes, WinINet notification, завершения/ошибки. Retry имеет
  новый ID. В журнал начала включается причина автоматического отката.
  Это корреляция baseline; общий контекст всех подсистем Stop ещё не доказан.
- Новые assertions сначала дали 11 failed / 40 passed / 1 skipped. После
  исправления `npm.cmd test -- src/main/systemNetwork.test.ts src/main/lifecycleCleanup.test.ts`
  — 171 passed / 1 skipped, exit 0.
- `granularKillSwitch.test.ts`: 50 смешанных add/remove (seed 30008). Проверены
  каждый native exception set, итоговые in-memory/store данные и audit-порядок.
- Там же: настоящий Win32 GetShortPathName для созданного `.exe`, затем
  отклонение 8.3 alias как эквивалентного длинному пути. На томах без alias
  сценарий явно SKIP; локально он прошёл. `npm.cmd test -- src/main/granularKillSwitch.test.ts`
  — 12 passed, exit 0. Изолированный временный каталог удалён самим тестом.
- CI на `9f8e26f`: Windows success, Rust success, Revix success.
  https://github.com/newnout6-a11y/vpn/actions/runs/39055637354/job/117463031596
  Нативный BFE smoke: `ok=true`, `aborted=true`, `rules=23`, `priority=verified`.
  Подтверждён ABI/read-back на runner; это не packet/reboot/CLAT/OS acceptance.
- Подтверждён ещё один дефект текущего main: `isKillSwitchActive()` считает
  манифеста достаточным для active; IPC отдаёт только boolean, Dashboard по нему
  утверждает «Интернет заблокирован файрволом». Полнота фактических правил,
  профилей и WFP не проверяется; неудачный refresh сохраняет прошлое значение.
  Требуются свежий verifier и обработка unknown во всех потребителях. Этот
  остаток WP-3 не исправлен текущим baseline-коммитом и не считается закрытым.
- Финальные проверки перед baseline-коммитом: `npm.cmd run typecheck` — exit 0;
  `npm.cmd test` — **3117 passed, 5 skipped, 0 failed**, 232 files passed,
  2 skipped, 164.69 s, exit 0. Трассировка AC 927/927, F 210/210 и
  `git diff --check` — exit 0. После push CI/review нового SHA проверяются заново.

### WP-3: свежая проверка kill-switch вместо ложного active

- На e622512 Windows/Rust CI success, Revix neutral с двумя nitpick: временный
  root и context.skip. Тест 8.3 теперь использует os.tmpdir() и destructured skip.
- IPC/preload/renderer передают verified/inactive/unknown, причину и cleanupRequired.
  Наличие манифеста по-прежнему требует lifecycle cleanup, но не доказывает
  блокировку. Новый read-only verifier сериализован с firewall-транзакциями.
- Проверяются эффективные ActiveStore-профили, BFE/MpsSvc, полнота имён и scopes,
  отсутствие неизвестных outbound Allow, точная WFP-политика и живая TUN identity
  (доверенный GUID, Wintun, адрес, LUID). Недоверенные/prepared/pending журналы,
  orphan/неполнота/ошибка и неизвестные helper scopes дают unknown.
- Пассивный запрос не запускает UAC/helper: проверен startIfUnavailable:false,
  включая отдельную защиту от исчезновения helper во время await WFP prelude.
- Store сразу снимает старую верификацию, отбрасывает старые ответы, ошибки
  оставляют unknown. Cleanup/reset запускают повторную проверку. Dashboard,
  crash/proxy-down log и tray не утверждают безусловную блокировку по presence.
- Production PowerShell snapshot прочитан на хосте без изменений сети: exit 0;
  BFE/MpsSvc Running, все три Enabled=True/Block, 131 чужое outbound Allow.
  Это не доказательство утечки, но оснований подтвердить полную блокировку нет.
- Реальный snapshot вернул dotted IPv4 masks. Новая регрессия до канонизации:
  1 failed / 31 passed; исправлены network equivalence, contiguous-mask check,
  отрицательные broader masks. Журнал approved helper paths старых версий
  неполон, поэтому произвольные proxy scopes консервативно дают unknown.
- Native PowerShell fixture исполняет production status script и требует
  ActiveStore/PersistentStore явно. WFP проверка привязана к fresh TUN identity.
- Playwright CLI: настоящий Dashboard, изолированный Vite/подставной IPC.
  Визуально просмотрены unknown dark/light, verified light и 414 px. Проверены
  recheck, failed cleanup, inactive hides banner, reset confirmation dismiss.
  При 280/320 px documentWidth=280/320, alertWidth=232/272: overflow не обнаружен.
  Это UI fixture, не installed E2E. Vite/browser остановлены. Скрипты gates из
  design-doctrine отсутствуют в установленном skill; PASS этих gates не заявлен.
- Автопроверка инструментов отклонила cleanup собственных временных файлов
  (blocked by policy). .tmp/wp3-ui, .playwright-cli и output/playwright оставлены
  локально вне коммита; исходные .claude/ и .wrangler/ сохранены.

Фактически выполненные команды (из vpn-tunnel-enforcer):

```text
npm.cmd test -- src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts src/main/elevatedPsHelper.test.ts src/main/wfpIpv6.test.ts src/renderer/store.firewallStatus.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/renderer/store.connectionBusy.test.ts
201 passed, 1 skipped; 7 files passed; exit 0
npm.cmd run typecheck
exit 0
npm.cmd run build
exit 0 (включая tsc; существующие предупреждения о dynamic/static imports)
npm.cmd test
3168 passed, 5 skipped, 0 failed; 234 files passed, 2 skipped; 132.11 s; exit 0
```

Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py
— AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
Отчёт wp3-acceptance-2026-10-17.md обновлён. Нормативные docs/ не менялись.
WP-3 остаётся частичным: packet oracle, SYSTEM reboot, OS matrix и физический
464XLAT не приняты. Следом — проверки/ревью нового SHA PR #46 и остаток WP-3;
переход к WP-0 не выполнен.

### WP-3: review f1b22f7 и небольшие уточнения UI

- f1b22f78a03ba9ffd2c25d17867c86a5d0e536e7 опубликован в PR #46.
  Windows job 117468856033 success, Rust 117468856338 success,
  Revix 117468871161 neutral. Windows: 3169 passed / 4 skipped;
  нативный BFE smoke ok=true, aborted=true, priority=verified.
  Это не L3 packet/boot acceptance.
- Проверено issue Revix 4303919025: два изменённых log сообщения App.tsx
  вынесены в i18n.t с en/ru keys.
- Suggestion 4303919028 принято частично: баннер не показывается во время
  checking, когда read-back ещё не завершён. Не скрываем unknown/unavailable
  после отказа: недоступный helper не доказывает отсутствие orphan правил.
  Отдельный UI regression подтверждает отсутствие cleanup alert до ответа.
- Позднее опубликованный minor CodeRabbit по e622512 подтверждён: retry после
  отказа шага baseline теперь проверяет очистку state.manifest после success.
- Сверка следующего AT-03-007: общий Stop уже отдаёт частичные отказы в UI
  как error, но общего operationId для baseline/firewall/adapters ещё нет.
  Следующая работа остаётся внутри WP-3.

Проверки текущего уточнения из vpn-tunnel-enforcer:
- npm.cmd run typecheck — exit 0.
- npm.cmd test — 3169 passed, 5 skipped, 0 failed; 234 files passed,
  2 skipped; 124.12 s; exit 0.
Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py
— AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
Сборка предыдущего f1b22f7 проверена; после этого изменения её не повторяли.
CI/review нового SHA проверяются отдельно после push.

### WP-3: общий operationId остановки и независимых rollback (AT-03-007)

- На c697842 проверены live CI: Windows 117470594831, Rust 117470595030,
  Revix 117470608305 — success. Windows: 3170 passed / 4 skipped,
  235 files passed / 1 skipped, 136.08 s; BFE ABI transaction aborted=true,
  priority=verified. CodeRabbit на этом SHA всё ещё сообщает Review in progress;
  опубликованный подробный review пока относится к e622512, а не к c697842.
- Stop создаёт UUID после синхронного допуска операции и передаёт его baseline,
  firewall/WFP, adapter rollback и DNS safety repair. Одновременные Stop
  возвращают ID общей операции; самостоятельный retry получает новый UUID.
- Старт/результат каждого controller шага, общий итог и forensic-события имеют
  operationId. Promise fulfillment с success:false/rolledBack:false/repaired:false
  не записывается как успешный шаг. Результаты внутренних baseline registry,
  Firewall/WFP и adapter/DNS rollback сохраняют тот же ID.
- Порядок teardown и защита до свежего runtime exit proof сохранены. Эта работа
  не вводит общий FSM WP-0 и не объявляет корреляцию всех фоновых transport timings,
  startup/crash/shutdown-backstop путей. Другие вызовы baseline сохраняют свой UUID.
- Добавлены fault-injection regression: runtime/Xray/baseline/firewall/adapters/DNS,
  concurrent Stop и retry, Firewall/WFP partial failure, продолжение следующего
  адаптера/DNS policy. Настоящий Dashboard на IPC fixture показывает полный
  перечень неудачных шагов и рекомендацию повторить остановку без success toast.
- До реализации: 8 новых controller tests FAIL из-за отсутствия operationId;
  первый дополнительный baseline test также упал из-за пропущенного import
  в самом тесте (исправлен). Адресные проверки после реализации: 314 passed,
  2 skipped, exit 0; дополнительный renderer/adapter/source прогон: 74 passed.
- Первый полный прогон: 3185 passed / 1 failed / 5 skipped, 127.99 s. Единственный
  отказ — source assertion старого текста DNS warning; прежний текст сохранён,
  поведенческий тест проверяет warn и оба DNS результата. Полный прогон повторён.
- При чтении обнаружен следующий WP-3 пробел, пока без исправления: resolved
  success:false baseline rollback игнорируется в autoPilot.ts и failure/startup
  путях index.ts (они ловят только rejection). Нужно проверить вывод recovery
  warnings в UI; CodeRabbit отмечал это как существующий caller-contract gap.
- Матрица AT обновлена в ненормативном отчёте. WP-3 остаётся частичным;
  L3 packet/SYSTEM reboot/OS matrix/физический 464XLAT не приняты.

Финальные проверки перед correlation-коммитом:
- Из vpn-tunnel-enforcer: npm.cmd run typecheck — exit 0.
- npm.cmd test — 3187 passed / 5 skipped / 0 failed; 234 files passed,
  2 skipped; 122.16 s; exit 0.
- Из корня: python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py
  — AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
- npm.cmd run build — exit 0 на финальном коде; Vite warnings о смешанных imports/размере чанка сохранены.

### WP-3: ошибки baseline recovery в вызывающем коде (AT-03-003/007)

- Windows job 117473468125 на 966bf95 — success: 3188 passed / 4 skipped,
  235 files passed / 1 skipped, 199.73 s. Native BFE smoke: aborted=true,
  priority=verified. Rust 117473468357 success; Revix 117473468622 neutral.
- Проверен вопрос Revix 4303983423 про cleanupRequired при unavailable:
  отсутствие helper на Windows не доказывает отсутствие persistent/orphan
  защиты, поэтому inactive по одному этому факту запрещён. Non-Windows —
  неподдерживаемая для продукта среда; консервативный placeholder не доказывает
  работоспособность там. Это question без нового production defect, не approve.
  CodeRabbit для нового SHA подробный review пока не опубликовал.
- Подтверждён caller-contract gap: baseline возвращает success:false с
  сохранённым снимком; прежние catch в start-tun/direct-vpn/AutoPilot/startup
  и crash callbacks его не замечали. Начальный новый прогон: 7 failed,
  194 passed, 1 skipped; четыре failure — отсутствующий новый API, три —
  реально потерянный recovery error в итоговом результате запуска.
- Добавлен явный rollbackTunNetworkBaselineOrThrow для exception-based callers.
  Существующий result API Stop/shutdown не изменён; trusted absence остаётся
  no-op. Отказ включает сообщение, failed-step details и рекомендацию повторить
  восстановление. Сам снимок не удаляется при неполном recovery.
- Ручной start сохраняет исходную ошибку и добавляет recovery error в IPC;
  AutoPilot добавляет failed recovery step и подробности в message.
  Обычный/emergency onExit теперь пишет отказ и при resolved success:false.
- Startup recovery выполняется ДО createWindow: IPC toast в этот момент
  потерялся бы. Отказ показан нативным warning dialog с подробностями.
  Тесты используют подставной dialog и не открывают окно на рабочем хосте.
- Адресный прогон: npm.cmd test -- src/main/systemNetwork.test.ts
  src/main/autoPilot.test.ts src/main/lifecycleCleanup.test.ts — 206 passed,
  1 skipped, 3 files passed, exit 0. npm.cmd run typecheck — exit 0.
  npm.cmd run build — exit 0; обычные Vite warnings сохранены.
- Полный набор запущен отдельно. Трассировка AC 927/927, F 210/210 и
  git diff --check — exit 0. Нормативные docs/ не менялись.
- Первый полный прогон текущего исправления: 3198 passed / 1 failed / 5 skipped,
  132.96 s. Единственный failure — adaptiveNetworkIdentity.test.ts,
  MSFT_NetRoute native fixture: Test timed out in 5000ms (не assertion результата).
  Отдельно npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts:
  25 passed, 2.46 s, exit 0. Причина задержки не установлена; полный набор повторён.
- Дополнительная сверка startup recovery выявила две связанные ветки:
  isBaselineApplied() мог бросить до обработчика предупреждения; ошибка tasklist
  раньше означала fall-through к rollback без exit proof. Новые regression:
  2 failed / 4 passed при изолированном прогоне startup cases.
- recoverStaleBaseline теперь проверяет доверенный baseline и вызывает
  isOwnedTunRuntimeRunning(true) в общей error boundary. Unknown runtime или
  untrusted baseline дают предупреждение без rollback; живой owned runtime
  сохраняет baseline. Подтверждённое отсутствие допускает восстановление.
  Адресный повтор трёх файлов: 209 passed / 1 skipped, 11.07 s, exit 0.
- Повтор полного набора на предыдущем срезе (до усиления startup boundary): 3199 passed / 5 skipped, 234 files passed / 2 skipped, 125.74 s, exit 0. Для финального startup-кода DoD запускается заново.
- Финальный startup-код: npm.cmd run typecheck — exit 0; npm.cmd run build —
  exit 0; npm.cmd test — 3202 passed / 5 skipped, 234 files passed / 2 skipped,
  123.10 s, exit 0. python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py
  — AC 927/927, F 210/210, exit 0; git diff --check — exit 0.
- CodeRabbit завершил review 966bf95: один Minor (4304029954) про четыре
  CIM filter query на каждое firewall rule. Проверка и отдельный repair следуют
  после текущего коммита. Следом также проверить negative runtime proof:
  существующий observer исключает процессы с нечитаемым ExecutablePath.
  L3 по-прежнему NOT-CHECKED; WP-0/WP-2 не начаты.

### WP-3: достоверное отсутствие runtime перед снятием защиты

- 093f48f опубликован в PR #46; Windows job 117476794211 ещё выполняется,
  Rust 117476794279 success, Revix 117476805053 neutral. CodeRabbit pending.
- Подтверждён связанный с startup/Stop proof дефект: native observer исключал
  процесс с недоступным ExecutablePath, возвращая false. stop-runtime также
  захватывал соседний каталог по префиксу (runtime-extra). Новые native tests
  до исправления: 3 failed / 17 passed / 87 skipped, exit 1.
- Worker и standalone fallback теперь используют один readonly status script.
  Нечитаемый путь кандидата даёт явную ошибку, а не exit proof. В обоих
  запросах ownership ограничен каталогом с завершающим слэшем; чужой соседний
  каталог не останавливается. Порядок sing-box exit перед Xray сохранён.
- npm.cmd test -- src/main/recoveryPsProtocol.test.ts
  src/main/tunControllerRecoverySource.test.ts src/main/lifecycleCleanup.test.ts
  — 265 passed, 3 files passed, 46.16 s, exit 0. Дополнительный standalone
  fallback regression: 4 passed / 138 skipped, exit 0. Это fake CIM/Stop-Process,
  реальные процессы и сеть не менялись.
- npm.cmd run typecheck и npm.cmd run build — exit 0. Полный набор запущен;
  traceability AC 927/927, F 210/210 и git diff --check — exit 0.
- Для замечания CodeRabbit 4304029954 отдельно проверено readonly на хосте:
  ActiveStore содержит 632 rules и 632 application filters; association
  InstanceID совпадает с rule.Name, bulk lookup даёт ровно 1 запись.
  Это проверка формы данных, не системная приёмка фильтрации.
- Первый полный прогон observer-изменения: 3198 passed / 8 failed / 5 skipped,
  126.30 s, exit 1. Все 8 — два прежних AST harness без новой зависимости
  OWNED_RUNTIME_STATUS_QUERY_SCRIPT. Harness обновлены; отдельный прогон
  ownedRuntimeStatus.test.ts и tunRuntimeExitProof.test.ts — 29 passed,
  2 files passed, exit 0. Дублирующие новые fallback cases удалены из lifecycle
  tests, проверка остаётся в существующих профильных suites.
- Повторное readonly чтение всех типов native filters: AddressFilter -All
  отказал с Access denied из текущего non-admin процесса. Привилегированный
  snapshot этим не проверен; batch implementation должна сохранять отказ.
- Windows CI 093f48f (117476794211) завершился success: typecheck, unit,
  traceability, BFE smoke и native Electron reads. CodeRabbit пока review in
  progress именно для 966bf95…093f48f (comment 6237997423).
- Финальный полный повтор observer-изменения: npm.cmd test — 3202 passed /
  5 skipped, 234 files passed / 2 skipped, 123.97 s, exit 0.
  npm.cmd run typecheck — exit 0; build — exit 0; traceability и diff check
  — exit 0. Нормативные docs/ не менялись.
- Лог Windows 093f48f: 3203 passed / 4 skipped, 235 files passed / 1 skipped;
  BFE ok=true, aborted=true, priority=verified. Это ABI/read-back с Abort,
  не packet oracle или reboot. Отдельный Electron native smoke: 1 passed /
  1 skipped. CI/review следующего SHA проверяются после push.

### WP-3: пакетный read-back firewall status (CodeRabbit 4304029954)

- Замечание Minor подтверждено: четыре association CIM-запроса на каждое
  собственное правило давали линейный рост native round trips при фиксированном
  status timeout 15 s. Превышение таймаута на рабочем хосте не воспроизводилось.
- FIREWALL_STATUS_PS теперь один раз читает каждый из Application/Address/Port/
  Interface filters с -All -PolicyStore ActiveStore. На каждом вызове строятся
  новые индексы InstanceID; join идёт по rule.Name, не DisplayName. Дубликаты
  не затираются: для каждого собственного правила по-прежнему нужен ровно один
  filter каждого типа. Пустые ID/неполный read-back/ошибки чтения дают отказ.
  Никаких повторов через иной privilege path или старый cache не добавлено.
- Native fixture сначала дал 11 failed / 31 skipped (старый reader пытался
  вызывать per-rule cmdlet). После реализации: 129 passed / 1 skipped в двух
  suites. Расширенный окончательный адресный прогон: npm.cmd test --
  src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts —
  135 passed / 1 skipped, 2 files passed, 6.22 s, exit 0.
- Матрица из 17 native fixtures: малый/110-rule/пустой набор, одинаковые
  DisplayName с разными scopes/Name, обратный порядок фильтров, пропущенные и
  повторные фильтры всех четырёх типов, пустые rule/filter ID, отказ каждого
  cmdlet. Успех требует ровно четырёх filter queries и неизменного snapshot.
- Метаданные всех четырёх настоящих cmdlet на хосте подтвердили поддержку All
  и PolicyStore. Производственный привилегированный snapshot локально не
  запускался; tests исполняют production script на fake native boundaries.
- npm.cmd run typecheck — exit 0; npm.cmd run build — exit 0. Полный набор
  выполняется; traceability AC 927/927, F 210/210 и git diff --check — exit 0.
- Полный набор на финальном batch reader: npm.cmd test — 3218 passed /
  5 skipped, 234 files passed / 2 skipped, 129.39 s, exit 0.
- Revix review 9cf85bb (5559549646) — COMMENTED/neutral; единственное новое
  предложение 4304071624: защита от будущего drift имени sing-box между
  controller constant и query. Сейчас оба vpnte-sing-box.exe, расхождения нет;
  добавить проверку согласованности в существующую runtime suite следующим
  тестовым изменением. Windows CI и CodeRabbit для этого SHA ещё не закончены.

### WP-3: генераторы типов, путей, длин и дубликатов (AT-03-009)

- 36611ed опубликован в PR #46. Windows CI предыдущего 9cf85bb
  (117478370005) завершился success, Rust success, Revix neutral; CodeRabbit
  ещё не опубликовал новый подробный review. Проверки нового SHA независимы.
- IPC production handler kill-switch:add-exception проверен fast-check:
  non-string type/value/label, неизвестные строковые типы, label >200/value
  >2048 и пустые строки. Каждый отказ называет поле; exceptions/store остаются
  пустыми, native effects отсутствуют. Seed 30012, 200 runs + явные границы.
- Seed 30013: 50 normalized-CIDR duplicate attempts с ведущими нулями маски
  и пробелами/переводами строк не добавляют второй entry, commit или native
  update; исходный store остаётся неизменным.
- Seeds 30014/30015: по 50 canonical/negative path cases. Реальные readable
  files с ./ дают один realpath; labels длины 1 и 200 нормализуются (явные
  examples). Control chars, relative/UNC/ADS/.. и неверные расширения отвергаются;
  readable directory.exe не принимается за файл. Файлы только в .tmp,
  созданная тестом директория удаляется его finally/afterEach.
- Revix 4304071624 закрыт проверкой согласованности имени: существующий AST
  harness извлекает controller RUNTIME_EXE_NAME и требует его в status/stop
  scripts. Production поведение этим тестовым коммитом не меняется.
- npm.cmd test -- src/main/granularKillSwitch.test.ts
  src/main/killSwitchExceptionValidation.test.ts src/main/ownedRuntimeStatus.test.ts
  — 52 passed, 3 files passed, 1.04 s, exit 0 (до добавления явных examples).
  Typecheck после examples — exit 0. Полный набор запущен; traceability
  AC 927/927, F 210/210 и git diff --check — exit 0.

### WP-3: проверка замечаний Revix на 36611ed

- Windows CI 36611ed (117479394378) success: 3219 passed / 4 skipped,
  235 files passed / 1 skipped. BFE smoke ok=true, aborted=true,
  priority=verified; Electron read smoke 1 passed / 1 skipped. Rust success,
  Revix neutral. CodeRabbit status на этом SHA — pending, Review in progress.
- Issue 4304097366 про «unchecked scope broadened to Any» проверен по
  enableKillSwitchUnlocked и matchesFirewallPolicy. Для sing-box/app правила
  создаются с Program и прочими scopes Any; для TUN — InterfaceAlias;
  LAN/TUN/loopback — соответствующая address scope; DHCP/NTP — UDP+ports.
  Поэтому приведённый remote Any у sing-box совпадает с создаваемой политикой,
  а не расширяет её. Другие неограниченные поля уже Any. Контрпример утечки
  не подтверждён; production policy по этому замечанию не менялась.
- Связанное замечание 4304097372 к комбинированному regression обосновано:
  теперь каждый из 11 ограничивающих scope fields проверяется независимо,
  включая protocol и ports отдельно у DHCP/NTP. Тесты PASS на production
  matcher; enabled/direction/action/profile и duplicate scopes проверяются
  существующими отдельными cases. Это не packet/системная приёмка.
- 4304097382 про отсутствующую .tmp: тесты теперь создают проектную .tmp
  перед mkdtemp, сохраняя требование AGENTS.md о проектной временной папке.
  Для новых generated path fixtures добавлена та же подготовка. Корень .tmp
  и чужие файлы не удаляются; finally удаляет только свой mkdtemp child.
- Финальные 4 адресные suites: npm.cmd test -- src/main/firewallStatus.test.ts
  src/main/killSwitchExceptionValidation.test.ts src/main/granularKillSwitch.test.ts
  src/main/ownedRuntimeStatus.test.ts — 102 passed, 4 files passed, 6.15 s,
  exit 0. npm.cmd run typecheck — exit 0.
- Полный прогон до последних scope/tmp regression: 3222 passed / 5 skipped,
  234 files passed / 2 skipped, 126.26 s, exit 0. Финальный полный повтор
  запущен после всех тестовых изменений. Production source не менялся с
  проверенного build 36611ed; повторная сборка для test-only diff не нужна.
- Финальный полный прогон: npm.cmd test — 3224 passed / 5 skipped,
  234 files passed / 2 skipped, 127.01 s, exit 0. Typecheck — exit 0;
  python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC 927/927, F 210/210, exit 0; git diff --check — exit 0.

- После push этого тестового коммита оставить SHA стабильным до CI/review,
  проверить новые замечания отдельно от переякоренных старых. Следующая
  доступная работа WP-3 — оставшаяся partial-manifest матрица AT-03-003;
  L3 packet/SYSTEM reboot/OS matrix/physical 464XLAT остаются NOT-CHECKED.
  WP-3 не завершён, WP-0/WP-2 не начаты.

### WP-3: CI fdfac87 и матрица частичных recovery inputs

- Windows CI 117481176778 — success на merge fdfac87 в c76d45a:
  3225 passed / 4 skipped, 235 files passed / 1 skipped; traceability
  AC 927/927, F 210/210. BFE smoke ok=true, aborted=true,
  priority=verified; Electron native reads 1 passed / 1 skipped.
  Rust 117481176884 success; Revix 117481188119 neutral/COMMENTED.
  CodeRabbit для fdfac87 ещё pending; head не менялся во время его проверки.
- Boot recovery: четыре production-script fixtures с частичными firewall,
  adapter, baseline и TUN inputs подтверждают продолжение других валидных
  recovery, явный warnings/exit 1 и сохранение неподтверждённых записей.
  Неполный firewall snapshot карантинируется; Allow fallback помечен unknown.
- Restore-RegValue: шесть native fixtures проверяют missing snapshot,
  неверный registry type и DWORD overflow на обеих позициях DNS policy.
  Только валидный step меняет fake registry; read-back и отдельные сообщения
  по обоим steps обязательны. Физическая сеть/системные registry keys не менялись.
- Первый адресный прогон: 77 passed / 6 failed из-за потерянных обратных
  слешей в новом TypeScript template harness. Исправлен сам harness на
  String.raw; повтор npm.cmd test -- src/main/bootRecoveryBehavior.test.ts
  src/main/bootRecoveryExecution.test.ts src/main/firewallStatus.test.ts —
  83 passed, 3 files passed, 10.05 s, exit 0.
- Revix 4304125808: fixture.ps1 запускается с process-only ExecutionPolicy,
  как boot harness. 4304125811: вместо postfix non-null assertion — assert
  с именем отсутствующего rule. Нит 4304125817 о .itest suffix пока не принят:
  перенос убрал бы L2-матрицу из default npm test/Windows CI; другие native
  fixtures здесь также собираются обычным режимом. Статуса APPROVED нет.
- Расхождение/неоднозначность AT-03-003(c) записаны в отчёте: «шаги без
  подписи» не определены; есть ACL/owner/schema trust, криптографических
  подписей шагов нет. Обычный baseline/adapter validator требует полный
  документ. Владельцу задано уточнение, норматив docs не менялся; полный
  PASS этой матрицы не заявляется. WP-3 остаётся частичным.
- До startup-dialog fix полный npm.cmd test — 3234 passed / 5 skipped,
  234 files passed / 2 skipped, 129.86 s, exit 0; typecheck — exit 0.
  После разделения wrong-type и overflow inputs (у wrong-type валидное data=0)
  и следующего startup fix: четыре адресных suites — 223 passed,
  4 files passed, 16.44 s, exit 0. Финальный полный прогон — 3236 passed /
  5 skipped, 234 files passed / 2 skipped, 128.34 s, exit 0.
  python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC 927/927, F 210/210, exit 0; git diff --check — exit 0.

### WP-3: предупреждение не задерживает startup recovery (CodeRabbit 4304147637)

- CodeRabbit review fdfac87 (5559652610) опубликован: одно новое Minor.
  Status CodeRabbit Review completed/success. Замечание подтверждено:
  await native warning удерживал recoverStaleBaseline, остальные recovery
  и createWindow до нажатия ОК; rejected dialog прерывал recovery.
- Четыре новые/уточнённые проверки до ремонта дали 4 failed / 4 passed /
  132 skipped (startup subset): pending/rejected dialog и неверный заголовок
  при ошибке runtime/storage preflight. Это воспроизведение дефекта, а не
  системная Windows/L3-приёмка.
- recoverStaleBaseline больше не ждёт закрытия диалога. Rejection показа
  логируется отдельно и не прерывает цепочку восстановления. Сообщение
  различает неудачный rollback и отказ предварительной проверки, при котором
  rollback ещё не запускался; runtime exit barrier сохранён.
- npm.cmd test -- src/main/lifecycleCleanup.test.ts
  src/main/bootRecoveryBehavior.test.ts src/main/bootRecoveryExecution.test.ts
  src/main/firewallStatus.test.ts — 223 passed, 4 files passed, 16.44 s,
  exit 0. npm.cmd run typecheck и npm.cmd run build — exit 0.
- Финальный npm.cmd test — 3236 passed / 5 skipped, 234 files passed /
  2 skipped, 128.34 s, exit 0. Traceability AC 927/927, F 210/210;
  git diff --check — exit 0. Новые SHA отправляются вместе после завершения
  проверки fdfac87; текущие CI/review должны быть проверены отдельно.

### WP-3: review 0d175b5 — fixtures, два P1 и корреляция логов P2

- f6a651c и 0d175b5 отправлены в PR #46. Windows 117484451024 success:
  3237 passed / 4 skipped, 235 files passed / 1 skipped; traceability
  AC 927/927, F 210/210; BFE ok=true, aborted=true, priority=verified;
  Electron reads 1 passed / 1 skipped. Rust 117484450921 success;
  Revix 117484454145 neutral/COMMENTED. Automatic CodeRabbit был skipped
  (manual review required), поэтому отправлен один @coderabbitai review
  (6239656395); бот подтвердил запуск. Review 5559714772 завершён/success,
  только 2 nitpicks: GUID fixture и final profile state.
- Revix 4304178126 / CodeRabbit: physical fixture разделял GUID и Wintun
  поля с TUN. Усиленные assertions воспроизвели 3 failed / 1 passed /
  16 skipped. Физическому адаптеру даны собственные GUID/index/driver/PnP;
  проверяется отсутствие его удаления и успешная очистка TUN record.
  Boot execution/behavior: 33 passed, 2 files passed, 8.78 s, exit 0.
  Полный набор после разделения GUID: 3236 passed / 5 skipped,
  234 files passed / 2 skipped, 127.23 s, exit 0; typecheck/traceability
  и git diff --check — exit 0. Production код в этом изменении не менялся.
  Final profile assertions добавлены в report boundary и существующий
  injected Domain failure case: проверяется конечный read-back.
- P1 4304183201 подтверждён: DisabledInterfaceAliases не попадал в status.
  Native snapshot теперь требует property и сохраняет список; явный CIM null
  нормализуется в пустой список, missing/untyped не маскируются. Parser
  требует string[]; matcher принимает только [] или один NotConfigured.
  Excluded alias в любом профиле и неизвестные данные не дают verified.
  Native/typed/status API regressions до ремонта: 13 failed / 52 passed.
  Реальные ActiveStore профили прочитаны только read-only (native null);
  настройки firewall не менялись.
- P1 4304193950 подтверждён: startup использовал нестрогие runtime callbacks.
  Production query + wrapper + startup/firewall bodies на fake CIM до
  ремонта: 3 failed / 1 passed / 140 skipped (owned/mixed/unknown/absent).
  Добавлен строгий startup gate; firewall callback и adapter rollback требуют
  requireProof=true. Live/unknown сохраняет сетевые настройки; ошибка даёт
  native warning без ожидания закрытия. Поздние отказы наблюдения перед
  firewall/adapter отдельно проверены; оставшиеся cleanup не выполняются.
- Финальные адресные 5 suites: npm.cmd test --
  src/main/lifecycleCleanup.test.ts src/main/ownedRuntimeStatus.test.ts
  src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts
  src/main/bootRecoveryExecution.test.ts — 339 passed / 1 skipped,
  5 files passed, 20.72 s, exit 0. npm.cmd run build — exit 0;
  полный набор и typecheck выполняются после всех изменений.
- L3-среда перепроверена read-only: процесс не elevated, Windows 26300;
  Hyper-V VM Windows 10 MSIX packaging environment выключена, её VHDX
  отсутствует. SYSTEM reboot/packet oracle/OS matrix/physical 464XLAT
  не появились. Уточнение AT-03-003(c) о подписях остаётся без ответа.
  Норматив docs не менялся; WP-3 частичный, WP-0/WP-2 не начаты.

- P2 4304208372 подтверждён настоящим appLogger/redaction/file write:
  UUID receipt превращался в одинаковый <redacted-uuid> для failed/retry.
  Регрессия до исправления падала на сравнении записанных ID с receipts.
  Внутренние baseline/Stop IDs теперь baseline_/stop_ + 32 hex-символа;
  наследование ID сохранено. Redactor и UUID durable firewall manifest
  не ослаблялись. Тест реального файла проверяет failed baseline rollback,
  успешный retry, девять step results на каждый ID и маскирование UUID
  credentials. Для Stop проверены формат/наследование/concurrent retry,
  отдельного настоящего Stop file-log прогона здесь нет.
- Полный прогон после двух P1 сначала дал 3257 passed / 1 failed / 5 skipped:
  mainIpcRegression ожидал старый нестрогий callback в строке source.
  Ожидание приведено к строгому callback; поведение отдельно проверяется
  шестью whole-chain startup сценариями, а не этим строковым assertion.
- После всех трёх исправлений: npm.cmd test -- src/main/systemNetwork.test.ts
  src/main/lifecycleCleanup.test.ts src/main/mainIpcRegression.test.ts
  src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts
  src/main/bootRecoveryExecution.test.ts — 397 passed / 2 skipped,
  6 files passed, 23.09 s, exit 0. npm.cmd run build — exit 0.
- Итоговый полный npm.cmd test после всех исправлений — 3259 passed /
  5 skipped, 234 files passed / 2 skipped, 130.84 s, exit 0.
  npm.cmd run typecheck — exit 0; python -X utf8
  docs/04-приёмочные-тесты/traceability/check-coverage.py — AC 927/927,
  F 210/210, exit 0; git diff --check — exit 0. Лог полного прогона:
  vpn-tunnel-enforcer/.tmp/wp3-review-final-full.log.

### WP-3: отправка исправлений и remote gates b31807f

- В PR #46 отправлены пять атомарных коммитов: a29feaa (boot fixtures),
  fb5ceb2 (DisabledInterfaceAliases), 80e4b37 (startup runtime proof),
  3a4ba9e (log correlation), b31807f (журнал/отчёт). Tracked tree после
  отправки чист; ранее существовавшие untracked каталоги не включены.
- Windows job 117488889602 завершён success на b31807f: 3260 passed /
  4 skipped, 235 files passed / 1 skipped, 129.54 s; AC 927/927, F 210/210.
  Native BFE smoke: ok=true, aborted=true, priority=verified. Electron
  native read smoke: 1 passed / 1 skipped. Rust 117488889576 success.
  Лог сохранён в vpn-tunnel-enforcer/.tmp/wp3-ci-117488889602.log.
- Revix 117488897178 завершён neutral. Его check-run сохраняет заголовок
  2 issue(s) found и summary Needs changes; актуальная PR Timeline для
  b31807f отмечает два исправления и Low risk в 19:57 UTC. Новых inline
  findings с original_commit_id=b31807f нет; формального APPROVED нет.
- Автоматический CodeRabbit skipped не принят за review. Одна ручная
  команда 6239986186 получила ответ 6239987347: Review rate limited /
  Action not completed. Последнее завершённое review 5559714772 проверяло
  0d175b5, а не b31807f. До восстановления квоты повторные команды не
  отправляются; одно included review в час, последнее завершилось 19:39 UTC.
- Повторная сверка среды: elevated=false, Windows build 26300; единственная
  зарегистрированная VM выключена, известный VHDX отсутствует. Нет новых
  доказательств packet oracle/SYSTEM reboot/OS matrix/mobile 464XLAT.
  Владельцу задан вопрос о доступной изолированной L3-лаборатории; ранее
  заданное уточнение AT-03-003(c) о подписях всё ещё без ответа. Норматив
  не менялся, WP-3 не завершён, WP-0/WP-2 не начаты.
- Эта запись меняет только журнал и acceptance report. Локальные проверки
  исходников: 3259 passed / 5 skipped, typecheck/build exit 0 (см. выше);
  новые CI/review после отправки этой записи проверяются отдельно.

### 18.10.2026 — L3-приёмка WP-3 пропущена владельцем

- Владелец ответил на запрос лаборатории: «нет. нету . да и не надо.
  отметь как пропущено владельцем», затем уточнил: «не не проверено
  а пропущено владельцем,это разное».
- Для оставшихся L3-сценариев WP-3 установлен отдельный итоговый статус
  **«Пропущено владельцем»** (`SKIPPED_BY_OWNER`). Решение охватывает
  поддерживаемую OS-матрицу, packet oracle, SYSTEM reboot, чужие firewall
  rules, отсутствие NIC/hot-plug, DNS failure, IPv6/NAT64/mobile 464XLAT,
  системные ACL-манифесты и L3-часть AT-03-003. Ожидание лаборатории снято.
- Решение внесено в ТЗ-06 §10.12, текущую матрицу acceptance report,
  корневой README и индекс docs/README.md. Обновление статуса документов
  прямо запрошено владельцем. Тестовые оракулы и исходники не менялись.
- Открытое уточнение L1/L2-части AT-03-003(c) и PR review остаются
  отдельными пунктами. Пропуск L3 не назначает статус другим пакетам.
- npm.cmd run typecheck — exit 0. Первый npm.cmd test: 3258 passed /
  1 failed / 5 skipped, 173.62 s; adaptiveNetworkIdentity.test.ts получил
  Test timed out in 5000ms на существующей native fixture. Отдельный
  npm.cmd test -- src/main/adaptiveNetworkIdentity.test.ts — 25 passed,
  1 file passed, 3.24 s, exit 0. Код теста и runtime не менялись.
- python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC 927/927, F 210/210, exit 0. Одноразовая проверка согласованности статуса:
  12/12 строк матрицы и 5 документов, PASS. git diff --check — exit 0.
- Повторный полный npm.cmd test — 3259 passed / 5 skipped,
  234 files passed / 2 skipped, 155.93 s, exit 0. Логи первого и повторного
  прогонов: vpn-tunnel-enforcer/.tmp/wp3-owner-skip-full.log и
  vpn-tunnel-enforcer/.tmp/wp3-owner-skip-full-recheck.log.

### 18.10.2026 — review 251a634 и решение о частичных записях AT-03-003(c)

- Windows CI 117506906954 на 251a634 — success: 3260 passed / 4 skipped,
  235 files passed / 1 skipped, 212.40 s; AC 927/927, F 210/210. Electron
  native reads: 1 passed / 1 skipped. Rust 117506906749 — success.
  Лог: vpn-tunnel-enforcer/.tmp/wp3-ci-117506906954.log.
- CodeRabbit review 5560162474 завершён в 21:24 UTC, проверены изменения
  0d175b5 → 251a634, включая исправления P1/P2. Осталось одно Minor:
  прогон 13 октября назван последним в README. Исправлено на исторический
  прогон со ссылкой на актуальные отчёты. Revix 117506917043 — neutral;
  старый заголовок 2 issue(s) found не равен формальному APPROVED. Новых
  inline findings для 251a634 нет. Minor-only gate этого SHA соблюдён;
  новые изменения требуют собственной проверки.
- Владелец пояснил, что подписи EXE нет; после отделения этого вопроса от
  записей файла отката подтвердил: «Да, восстановить исправные записи».
  Решение §10.13: невалидные записи доверенного файла пропускаются с явной
  ошибкой; валидные независимые соседи восстанавливаются. Подпись EXE
  остаётся отложенной. L3 имеет отдельный статус «Пропущено владельцем».
- Baseline, saved firewall profiles и adapter snapshots теперь допускают
  частичные записи только при recovery после проверки доверия и общего
  документа. Apply/write/passive status сохраняют строгую схему. Дубли
  target/profile/GUID отклоняются целиком, включая первую запись.
  DNS policy и transition records обрабатываются независимо. Неполный
  откат возвращает ошибку и сохраняет исходный файл; детали идут в Stop/UI
  и startup warning без ожидания закрытия диалога.
- Production boot script восстанавливает валидных соседей того же файла,
  логирует пропущенные записи, сохраняет incomplete journals и strict.
  Native fixture подставляет сетевые API и registry handles; реальные
  firewall/DNS/сетевые ключи Windows не менялись.
- Адресный npm.cmd test -- src/main/systemNetwork.test.ts — 64 passed /
  1 skipped, 4.35 s. Промежуточные проверки нашли устаревшее ожидание состава
  логов и недостающую зависимость netshState в тестовом harness; исправлено.
  Семь suites systemNetwork/firewallTransactions/physicalAdapterLifecycle/
  physicalAdapterLockdownSource/bootRecoveryExecution/bootRecoveryBehavior/
  lifecycleCleanup — 399 passed / 2 skipped, 26.95 s, exit 0.
- npm.cmd run typecheck и npm.cmd run build — exit 0; coverage — AC 927/927,
  F 210/210, exit 0. После усиления boot per-record guards:
  npm.cmd test -- src/main/bootRecoveryExecution.test.ts
  src/main/bootRecoveryBehavior.test.ts src/main/physicalAdapterLifecycle.test.ts
  — 88 passed, 15.96 s, exit 0. Дополнительные strict/startup/source suites:
  firewallTransactions/bootRecoveryExecution/bootRecoveryScriptSource/
  lifecycleCleanup — 271 passed / 1 skipped, 23.69 s, exit 0.
- Первый полный прогон изменений — 3279 passed / 1 failed / 5 skipped,
  176.95 s: source-test firewallKillSwitchValidation ошибочно проверял
  условие из другой функции. Ожидание ограничено фактическим helper body.
  npm.cmd test -- src/main/firewallKillSwitchValidation.test.ts
  src/main/firewallTransactions.test.ts — 122 passed / 1 skipped, 8.09 s,
  exit 0. Полный повтор и dist:win проверяются отдельно ниже.
- Полный повтор `.tmp/wp3-partial-full-final.log` — 3281 passed / 5 skipped,
  189.32 s, exit 0. Следующий `.tmp/wp3-partial-frozen-full.log` —
  3283 passed / 5 skipped, 193.23 s, exit 0. Во время второго прогона
  self-review выявил пропущенные поля transition snapshot: boot теперь
  отличает missing от допустимого null, пропускает запись с ошибкой и
  сохраняет журнал. Boundary netsh в native fixture подставлен, системные
  переходные адаптеры не меняются. Адресный
  `npm.cmd test -- src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryScriptSource.test.ts`
  — 35 passed, 20.10 s, exit 0. Итоговый полный прогон после этих правок
  записывается отдельно ниже, код до его окончания не меняется.
- `npm.cmd run typecheck` — exit 0. `npm.cmd run dist:win` — exit 0,
  Electron 44.4.3, NSIS 1.1.24; production build/typecheck выполнены внутри
  команды. Финальный ресурс находится в `dist/win-unpacked/resources/`,
  SHA-256 совпадает с исходником vpnte-recover.ps1:
  `155c175332855980933b7c7081db58784af8c9bd2e09b2dda76f2b4fa414e490`.
  Setup 139728889 bytes, SHA-256
  `dc085e8fd4867f1eaadefae48a6f6a415cb844f3f0b5404bd866cab5ccc4d23e`.
  Get-AuthenticodeSignature: NotSigned. Установщик не устанавливался.
  Логи: `.tmp/wp3-partial-frozen-dist.log`, `.tmp/wp3-partial-frozen-artifacts.json`.
- Финальный неизменявшийся код: `npm.cmd test` — **3285 passed / 5 skipped /
  0 failed**, 234 files passed / 2 skipped, 181.74 s, exit 0.
  Лог: `.tmp/wp3-partial-commit-full.log`. `npm.cmd run typecheck` — exit 0;
  `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` —
  AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0. Оставшиеся
  L3-сценарии не запускались: **«Пропущено владельцем»**. Новые CI/review
  после отправки коммита учитываются отдельно; WP-0/WP-2 ещё не начаты.

### 18.10.2026 — обычный Stop с повреждённым JSON и review 526a82b

- 526a82b отправлен в PR #46. Windows CI 117515333565 — success:
  3286 passed / 4 skipped, 235 files passed / 1 skipped, 222.80 s;
  AC 927/927, F 210/210. Native BFE: priority=verified, aborted=true;
  Electron native reads: 1 passed / 1 skipped. Rust 117515333353 — success.
  Лог: `.tmp/wp3-ci-117515333565.log`.
- Владелец сообщил, что trial CodeRabbit закончился, и прямо потребовал
  игнорировать сервис. Новые review CodeRabbit не запрашиваются и больше
  не являются условием перехода. Проверки CI и существенные замечания
  действующих review сохраняются как обязательный порог.
- Контроль AT-03-003(b) воспроизвёл старый дефект обычного Stop: прямой
  disable отправлял повреждённый доверенный JSON в карантин и Allow fallback,
  но wrapper disableKillSwitchIfActive завершался на read-only probe раньше
  этого шага. До исправления: 1 passed / 1 failed (новая пара direct/Stop),
  exit 1. Лог `.tmp/wp3-corrupt-gate-before.log`.
- Wrapper теперь передаёт только trusted invalid-content в существующий
  explicit recovery, который повторно проверяет storage и карантин по hash.
  Passive probes остаются read-only; unsupported-version, недоверенный ACL
  и отказ карантина по-прежнему запрещают native effects. Новые guard tests
  проходят. `npm.cmd test -- src/main/firewallTransactions.test.ts
  src/main/firewallKillSwitchValidation.test.ts src/main/lifecycleCleanup.test.ts`
  — 275 passed / 1 skipped, 19.56 s, exit 0.
- Revix review 5560309494 на 526a82b: три новых комментария, Timeline Low risk;
  check 117515345476 neutral, заголовок сохраняет 4 issues / Needs changes,
  что не считается APPROVED. 4304702666 подтверждён: пустой valid baseline
  теперь тоже пишет completion receipt success=false с тем же operationId.
  4304702671: тестовый parser сообщает явную ошибку отсутствующего payload.
  `npm.cmd test -- src/main/systemNetwork.test.ts` — 64 passed / 1 skipped,
  5.78 s, exit 0. 4304702670 — вопрос, поведение намеренное: при live/unknown
  runtime вся startup-очистка, включая env proxy и orphan DNS, сохраняется
  за свежим exit proof. Это проверяет production whole-chain regression
  lifecycleCleanup, включая отсутствие вызовов env/DNS при live/unknown.
- Новые финальные full/dist/remote gates учитываются ниже; WP-3 пока
  не закрыт, WP-0/WP-2 не начаты. L3 — «Пропущено владельцем».
- Финальный стабильный код: `npm.cmd test` — **3289 passed / 5 skipped /
  0 failed**, 234 files passed / 2 skipped, 181.64 s, exit 0.
  Лог `.tmp/wp3-review-final-full.log`. Предыдущий промежуточный полный
  прогон — 3289 passed / 5 skipped, 187.75 s; после него дополнены receipt
  и fixture guard, поэтому финальный результат указан отдельно.
- `npm.cmd run dist:win` — exit 0, включая `npm run build` и
  `npm run typecheck`. Setup 1.1.24: 139728924 bytes, SHA-256
  `d99a6288c36cb291223b970668492ea991ca1bf8ff8016978a3fa64c366fd019`;
  Authenticode NotSigned. Recovery resource SHA-256 совпадает с исходником:
  `155c175332855980933b7c7081db58784af8c9bd2e09b2dda76f2b4fa414e490`.
  Логи `.tmp/wp3-review-final-dist.log` и `.tmp/wp3-review-final-artifacts.json`.
  Установка и L3 не выполнялись. Coverage: AC 927/927, F 210/210, exit 0;
  `git diff --check` — exit 0. CI/review следующего head проверяются отдельно.

## 18.10.2026 — возврат к P2 PR #46: пустой снимок физических NIC

- По прямому запросу владельца проверен комментарий
  https://github.com/newnout6-a11y/vpn/pull/46#discussion_r4304712554.
  Замечание подтверждено. Оно появилось до merge PR #46 и было пропущено
  при итоговой сверке; прежний вывод о только minor-остатке был неполным.
  PR #46 уже слит (`d786e30`), исправление ведётся отдельным follow-up PR.
- WP-0 временно отложен. Его незавершённые изменения сохранены адресным
  stash `WP-0 in progress before PR46 P2 follow-up`, без посторонних файлов.
  Прежний полный прогон WP-0: 3290 passed / 5 skipped / 1 failed
  (adaptiveNetworkIdentity profile-only: default Vitest timeout 5000 ms),
  200.02 s, exit 1; это не PASS. Лог `.tmp/wp0-initial-full.log`.
- Production Boot Recovery принимал adapters:[] без предупреждения,
  удалял журнал и писал restored. Обычный TypeScript rollback имел тот же
  дефект. До исправления новые регрессии: **2 failed / 1 passed / 79 skipped**,
  exit 1; `.tmp/pr46-empty-adapters-before.log`. Положительный соседний
  сценарий уже проходил, поэтому отказ не вызван поломанной фикстурой.
- Пустой исходный снимок теперь явно неполный: Boot Recovery возвращает
  warnings/exit 1 и сохраняет журнал; ordinary rollback возвращает
  rolledBack:false с предупреждением. Валидные transition и обе DNS-policy
  записи продолжают восстанавливаться; NIC без ownership snapshot не меняется.
  Strict read/write validation отклоняет пустой снимок. Непустой валидный
  снимок по-прежнему восстанавливает NIC и разрешает удаление журнала.
- `npm.cmd test -- src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryBehavior.test.ts src/main/physicalAdapterLifecycle.test.ts src/main/physicalAdapterSnapshot.test.ts`
  — **121 passed / 0 failed**, 4 файла, 20.23 s, exit 0.
- `npm.cmd run typecheck` — exit 0;
  `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0.
- Полный прогон и CI/review follow-up head учитываются ниже. WP-3 требует
  закрытия этого подтверждённого P2 до возврата к WP-0. L3 остаётся
  **«Пропущено владельцем»**, CodeRabbit по решению владельца не ожидается.
- Финальный локальный `npm.cmd test` — **3292 passed / 5 skipped / 0 failed**,
  234 файла passed / 2 skipped, 188.19 s, exit 0.
  Лог `.tmp/pr46-empty-adapters-full.log`. Локальный timeout из предыдущего
  прогона WP-0 здесь не повторился; production и тестовые таймауты не менялись.
- `npm.cmd run dist:win` — exit 0 (включая build/typecheck).
  Recovery resource в dist/win-unpacked совпадает с исходником:
  SHA-256 `36399cd3020f1a774a4c30d155b01db75170034aaaf7770e2733e370d4bd23b7`.
  Setup 1.1.24: 139729025 bytes,
  SHA-256 `0383c425d75109230a50d1b269c28d02900dffff0d2d29eb0430e24f3ab84298`,
  Authenticode NotSigned. Установка не выполнялась. Логи
  `.tmp/pr46-empty-adapters-dist.log`, `.tmp/pr46-empty-adapters-artifacts.json`.

## 18.10.2026 — P2 PR #46 закрыт, возврат к WP-0

- Follow-up PR #47 (https://github.com/newnout6-a11y/vpn/pull/47) слит
  17.10.2026 22:41:12 UTC (18.10 01:41:12 Москва), merge
  `d6b940121eaed719ad0c547df194fa72abd2ffab`.
- Проверенный code head `af6c7aa2f62ac13884431668825d8f40f0ae8d83`:
  Windows check 117522257407 — success, 3293 passed / 4 skipped,
  216.62 s; coverage AC 927/927, F 210/210; BFE priority verified,
  transaction aborted=true; Electron reads 1 passed / 1 skipped.
  Rust check 117522257150 — success. CI run 39075692494.
  Лог `.tmp/pr46-empty-adapters-ci.log`.
- Revix check 117522270974 на том же head — success, Ready to merge,
  0 annotations; actionable review comments отсутствуют. CodeRabbit не ожидался.
- Комментарий 4304712554 закрыт кодом и негативными/положительными
  регрессиями. L3 сохраняет статус «Пропущено владельцем».
- main и codex/wp0-contracts fast-forward до merge; отложенные WP-0
  изменения восстановлены без конфликтов. Продолжается вся матрица
  AT-00-001…010, затем WP-2. Цель остаётся активной.

## 18.10.2026 — замечания PR #45: единые DST-границы расписаний

- По запросу владельца проверен комментарий
  https://github.com/newnout6-a11y/vpn/pull/45#discussion_r4304221291.
  P2 подтверждён: нормализованный start сравнивался с ненормализованным
  настенным временем и подавлял сам себя. До исправления адресный прогон:
  **4 failed / 34 passed**, exit 1 (New York/Lord Howe gap, повторный час,
  overnight end после gap).
- Активность при перезапуске и события используют одни конкретные локальные
  интервалы; пересекающиеся/соприкасающиеся интервалы объединяются по timestamp.
  Политика DST сохраняет Date compatible: gap сдвигается на величину перехода,
  repeated time выбирает ранний instant один раз; collapsed/reversed окно
  пропускается. Каждая граница разрешается на собственном календарном дне.
  В тестах TZ задаётся и восстанавливается внутри изолированного Vitest fork;
  часовой пояс ОС не меняется. Добавлены 8 DST-регрессий (AT-10-001/002).
- Revix question 4303565564 проверен: after определён в site.js и добавляет
  handle в timers; restore вызывает clearTimeout. Удалён повторный stop()
  из cleanup scheduler tests (4303565574). Suggestions об AST/source extraction
  (4303565570/4303565580) — замечания к устройству тестов, production-дефект
  ими не установлен; архитектура тестовых harness в этой правке не меняется.
  CodeRabbit по решению владельца не вызывается и не ожидается.
- Ветка PR #45 синхронизирована с main d6b9401 (включая fixes PR #46/#47)
  обычным merge без force. Незавершённые WP-0 изменения остаются в адресном
  stash `WP-0 in progress before PR45 review fixes`.
- В vpn-tunnel-enforcer:
  `npm.cmd test -- src/main/scheduler.test.ts src/main/serverPickerMigration.test.ts`
  — **43 passed**, exit 0; `npm.cmd run typecheck` — exit 0;
  `npm.cmd test` — **3309 passed / 5 skipped / 0 failed**, 235 файлов passed /
  2 skipped, 199.86 s, exit 0. Лог `.tmp/pr45-review-full.log`.
- В website: `npm.cmd test` — **3 passed**, exit 0;
  `npm.cmd run build` — 9 страниц, exit 0.
- Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
  — AC 927/927, F 210/210, exit 0; `git diff --check` и
  `git diff --cached --check` — exit 0.
- Это адресное исправление PR, не полная приёмка AT-10-001/002 или WP-10;
  10 000 property cases, смена системной зоны и прочие AT-10-* не заявляются.
  Installed E2E не запускались. CI/review нового head проверяются отдельно.

## 18.10.2026 — до WP-0 закрыть все открытые PR: #43, #44, #45

- Владелец изменил приоритет: сначала исправить и слить все открытые PR,
  затем возвращаться к WP-0. На момент запроса открыты ровно #43/#44/#45.
  WP-0 stash сохранён; CodeRabbit не вызывается и не ожидается.
- PR #45: head 9ce7b43d53f3990dc42457de85b17a0ba4b275bd прошёл Windows
  и Rust CI, run 39077186370. Windows — **3310 passed / 4 skipped**, 209.80 s;
  AC 927/927, F 210/210; WFP rollback aborted:true, Electron native probe
  1 passed / 1 skipped. Revix neutral: проверенный вопрос after и два
  предложения к устройству тестов. Merge **bfd0d97d3380f88d42eb2cce677dcbd276034c66**.
- PR #43: документация решения владельца о командах по имени; функциональных
  замечаний нет, Windows/Rust CI и Revix Ready to merge на aa0e2e2 — success.
  Merge **0b70a7a21ddd425f54b719e72f31b78eb49b1c21**. Уточнения формулировок
  и дубль README входят в зависимый PR #44.
- PR #44: был mergeable:false/dirty, название docs не отражало кодовые изменения.
  При merge актуального main разрешены пять конфликтов. Старый active/unverified
  fallback не возвращается: сохранён более сильный свежий read-back статуса
  firewall из WP-3 и его IPC-контракт; новые rollback/correlation тесты сохранены.
  WFP helper получает явную policy во всех путях, включая обновлённый rollback.
- Revix 4269895276 подтверждён: failed/throw restart при работающем TUN и
  устаревших правилах вызывал немедленную рекурсию. Теперь автоматическая
  перепроверка выполняется только после успешного restart; явный повтор позже
  разрешён. Две регрессии сначала провалились (3 попытки вместо 1).
- Revix 4269895286 уточнён: redactSensitiveText сохраняет публичный IP,
  но удаляет credentials/URI. Его удаление нарушало redaction до logEvent.
  Вызовы восстановлены, четыре регрессии проверяют отсутствие синтетического
  токена в payload logEvent (success, safety gate, route loss, mismatch).
  В сумме до исправления **6 failed / 21 passed**, exit 1.
- Revix 4269895267 проверен: fast-uri 4.1.5 и js-yaml 4.3.2 уже берутся из
  registry.npmjs.org, git+ssh/ssh URL в lockfile нет; SSH rewrite не требуется.
  Website CI дополнен запуском тестов таймеров из PR #45.
- Адресно: scheduler-independent PR #44 suite (splitTunnelingStartRace,
  indeterminateIpAutoVerify, firewallPolicySelection, firewallTransactions,
  firewallStatus, physicalAdapterLifecycle, singBoxEndpoint) — **270 passed /
  1 skipped / 0 failed**, 7 файлов, 9.73 s, exit 0.
- `npm.cmd run typecheck` — exit 0; coverage — AC 927/927, F 210/210, exit 0.
  В website: `node tools/build.mjs` — 9 страниц; `node tools/lint-html.mjs`
  — теги/ссылки корректны; `npm.cmd test` — 3 passed, все exit 0.
  `npm.cmd test` — **3327 passed / 5 skipped / 0 failed**, 237 файлов passed /
  2 skipped, 164.13 s, exit 0; лог `.tmp/pr44-review-full.log`.
  После уточнения AT-метки повторно `npm.cmd test -- src/main/indeterminateIpAutoVerify.test.ts`
  — 20 passed, exit 0. CI/review нового head PR #44 учитываются отдельно.

## 18.10.2026 — открытые PR закрыты, WP-0 возобновлён

- PR #44 слит с разрешения владельца после принятия проверки агента без
  нового Revix: merge `f0aef8f726852e5d8e292903bc670f06c4102319`.
  Head `6f535ad0012256779cb2f0b7177d097d12b80ff8`: Windows, Rust, website
  CI success. Windows — 3328 passed / 4 skipped, typecheck и coverage зелёные.
  REST-проверка после слияния: открытых PR 0; #43/#45 также merged.
- Ветка codex/wp0-contracts обновлена fast-forward до main f0aef8f.
  Stash WP-0 применён; конфликт только в progress.md разрешён сохранением
  обеих записей. Stash пока оставлен как резервная копия. Чужие untracked
  .claude/.wrangler/.playwright-cli/output не затрагивались.
- WP-3 завершён с L3 «Пропущено владельцем» (SKIPPED_BY_OWNER, §10.12),
  не PASS. WP-0 в работе: полная матрица в docs/wp0-acceptance-2026-10-18.md
  внутри приложения; ранее исправленный passive rejection dedup перепроверяется
  на актуальном main, затем продолжается AT-00-001…010.

- Перепроверка восстановленного passive rejection dedup на main f0aef8f:
  `npm.cmd test -- src/main/firewallTransactions.test.ts` — 97 passed /
  1 skipped, 6.25 s, exit 0; `npm.cmd run typecheck` — exit 0.
  `npm.cmd test` — 3329 passed / 5 skipped / 0 failed, 237 файлов passed /
  2 skipped, 161.72 s, exit 0, `.tmp/wp0-resumed-full.log`.
  Coverage — AC 927/927, F 210/210, exit 0; оба diff --check — exit 0.
  Это проверка первого адресного исправления WP-0, не приёмка всего пакета.

## 18.10.2026 — WP-0: устойчивость истории подключений (AT-00-010; F-143)

- Подтверждены два пробела: обрезанный JSON выбрасывал SyntaxError при
  загрузке модуля; Array.isArray принимал повреждённые записи и позволял
  молчаливо терять историю при неверной корневой схеме. Первичный файловый
  regression: 8 failed / 2 passed, 1.04 s, exit 1;
  `.tmp/wp0-history-before.log`.
- Десериализация проверяет корневую схему, обязательные и используемые
  optional/outcome/evidence поля. Валидные записи смешанного массива
  сохраняются, невалидные отсеиваются с количеством; повреждение JSON
  сообщает `history.corrupted`. Raw содержимое и ошибки парсера не логируются.
  Повреждённый файл до следующей записи сохраняется; новые записи работают,
  Conf выполняет существующий атомарный write. Ошибки I/O не подавляются.
- Дедуп по SHA-256 относится только к повторным чтениям одного повреждения;
  после изменения содержимого или успешной записи/очистки новое повреждение
  снова логируется. Некорректный addEntry отклоняется до изменения файла.
- Стенд использует настоящий Conf и временные файлы внутри .tmp,
  перезагружает сервис после 100 записей. Оболочка Electron userData/version
  подставлена; это L2, не проверка полного перезапуска Electron/Windows.
  Матрица covers legacy records, truncation/tail, schema corruption,
  typed fields, structured evidence, runtime damage и filesystem failure.
- Первый адресный прогон после правки: 41 passed / 1 failed: после успешной
  записи fingerprint не сбрасывался до следующего чтения. Исправлено сбросом
  только после успешного set/clear; добавлены регрессии. Расширенный прогон
  connectionHistoryStorage/connectionHistory/auditFixesRegression — 73 passed.
  Typecheck обнаружил несовпадение возвращаемого типа deserialize; исправлено
  явной ConnectionHistoryStoreSchema с безопасным пустым представлением.
  Финальные проверки и PR учитываются ниже. WP-0 остаётся в работе.

- Финальный `npm.cmd run typecheck` — exit 0.
  `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/connectionHistory.test.ts src/main/auditFixesRegression.test.ts`
  — 73 passed, 3 файла, 1.23 s, exit 0.
  `npm.cmd test` — 3350 passed / 5 skipped / 0 failed, 238 файлов passed /
  2 skipped, 161.76 s, exit 0; `.tmp/wp0-history-full.log`.
  `npm.cmd run build` (включая typecheck) — exit 0;
  `.tmp/wp0-history-build.log`. Coverage — AC 927/927, F 210/210, exit 0;
  `git diff --check` и staged diff check — exit 0.

## 18.10.2026 — WP-0 PR #48: проверка Revix Low risk

- PR https://github.com/newnout6-a11y/vpn/pull/48 создан на head
  `2a672792868053b52f76155db6bce742da2aa9c5`, оба адресных исправления
  закоммичены и запушены. Revix check 117639398277 — completed/neutral,
  Low risk: suggestion 4306503597 и question 4306503603.
- Question об исключении addEntry проверен по настоящим call sites:
  index.ts writeSessionEntry оборачивает addEntry в try/catch и логирует
  предупреждение; recordStartFailure тоже catches. Ошибка истории не выходит
  из этих границ и не обрывает teardown. Код остановки менять не требуется.
- Suggestion подтверждён: unknown outcome из нового приложения нельзя
  уничтожать при следующей записи старым reader. Теперь отбракованные
  элементы сохраняются в rejectedConnectionHistory внутри того же store;
  не возвращаются как валидные записи и не попадают в log payload.
  Повторные записи не дублируют их; явная пользовательская очистка удаляет
  и обычную, и отбракованную историю. Добавлены файловые регрессии.
- Runtime SESSION_OUTCOME_KINDS стал общим источником union-типа и проверки
  истории; дублирующий ручной список удалён. Каждое значение общего списка
  проходит write/reload regression. Полные проверки нового head — ниже.

- Финальные проверки доработки Revix: `npm.cmd run typecheck` — exit 0;
  `npm.cmd test -- src/main/connectionHistoryStorage.test.ts src/main/connectionHistory.test.ts src/main/sessionOutcome.test.ts src/main/auditFixesRegression.test.ts`
  — 104 passed, 4 файла, 1.27 s, exit 0. Полный `npm.cmd test` —
  3366 passed / 5 skipped / 0 failed, 238 файлов passed / 2 skipped,
  154.57 s, exit 0; `.tmp/wp0-review-full.log`. `npm.cmd run build`
  (включая typecheck) — exit 0, `.tmp/wp0-review-build.log`.
  Coverage — AC 927/927, F 210/210, exit 0; diff checks — exit 0.
- Исходный PR head 2a67279 завершил все три CI success (run 39115166050).
  После доработки требуется новый head CI/review; результаты не переносятся.
  Далее в том же WP-0 — разрешение wrapper-регистраций IPC и AT-00-001,
  затем остальные незавершённые строки матрицы. WP-2 не начат.
