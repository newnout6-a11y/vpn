# VPN Tunnel Enforcer Audit Tracker

Last updated: 2026-07-04

Purpose: durable context for Codex context compaction. Keep this file current while fixing audit findings. When a point is implemented, change its `Status` to `DONE`, add changed files and verification evidence. Do not rely on chat history alone.

Workspace: `C:\Users\Redmi\CascadeProjects\vpn`
App root: `vpn-tunnel-enforcer/`

## Status Legend

- `TODO`: confirmed or likely-valid finding, not fixed yet.
- `PARTIAL`: partly mitigated, but still needs a deliberate follow-up.
- `DONE`: code changed and at least targeted verification ran.
- `VERIFY`: source looks acceptable, but needs a test or Windows runtime check.
- `NOFIX`: reviewed and intentionally not changing.

## Ground Rules

- Do not delete or revert unrelated user/generated changes. Existing untracked `.kimchi/` is unrelated.
- Prefer `codebase-memory-mcp` for code discovery.
- Use `apply_patch` for manual edits.
- For TUN, system-network, watchdog, kill-switch, sing-box config, or soft-mode changes, use the `testing-bye-block` skill and clearly mark Windows-only verification gaps.
- After every completed batch, update this file before final response.

## Already Fixed Before This Tracker

| ID | Status | Summary | Files | Verification |
| --- | --- | --- | --- | --- |
| N1 | DONE | System-network baseline marker cleanup and exported real manifest path. | `vpn-tunnel-enforcer/src/main/systemNetwork.ts`, `vpn-tunnel-enforcer/src/main/systemNetwork.test.ts` | Targeted tests passed. |
| N3 | DONE | Diagnostics and snapshot now use the real baseline manifest path. | `vpn-tunnel-enforcer/src/main/systemSnapshot.ts`, `vpn-tunnel-enforcer/src/main/diagnosticsExport.ts` | Targeted tests/build passed. |
| S7 | DONE | IPv6 public IP check now has multiple endpoints and parser support for `ip/query/address/string`. | `vpn-tunnel-enforcer/src/main/leakDiagnostics.ts`, `vpn-tunnel-enforcer/src/main/leakDiagnostics.test.ts` | Targeted tests passed. |
| N2 | DONE | Smart-RU self-test no longer reports false OK for unverified RU egress. | `vpn-tunnel-enforcer/src/main/routingSelfTest.ts` | Targeted tests passed. |
| N4 | DONE | Stale TUN adapter disable fallback now attempts rename instead of silently accepting alias collision. | `vpn-tunnel-enforcer/src/main/tunController.ts` | Build passed. Windows runtime still useful. |
| S1/S2 helper hardening | DONE | Elevated PS helper has bounded script size/queue and an explicit policy gate for allowed elevated script families. | `vpn-tunnel-enforcer/src/main/elevatedPsHelper.ts`, `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts`, `vpn-tunnel-enforcer/src/main/physicalAdapterLockdown.ts`, `vpn-tunnel-enforcer/src/main/elevatedPsHelper.test.ts` | `npm test -- elevatedPsHelper.test.ts firewallKillSwitchValidation.test.ts --reporter=dot` passed: 13 tests; `npm run build` passed. |
| S3 | DONE | Kill-switch requires core allow rules before setting `DefaultOutboundAction=Block`. | `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts` | Targeted tests passed. |
| S4 | DONE | Nuclear firewall reset now asks for explicit confirmation. | `vpn-tunnel-enforcer/src/renderer/pages/Dashboard.tsx` | Build passed. |
| V1 rotation race | DONE | Profile rotation guarded against reentry. | `vpn-tunnel-enforcer/src/main/profileRotation.ts` | Targeted tests passed. |
| V1 import race | DONE | Concurrent same-source server imports deduped with an in-flight lock. | `vpn-tunnel-enforcer/src/main/serverPicker.ts` | Build passed. |

Last verification for the previous batch:

```powershell
npm test -- systemNetwork.test.ts leakDiagnostics.test.ts routingSelfTest.test.ts profileRotation.test.ts firewallKillSwitchValidation.test.ts --reporter=dot
# 48 tests passed

npm run build
# passed

npm test -- splitTunneling.test.ts dnsProfiles.test.ts leakSelfTest.test.ts trafficMonitor.test.ts --reporter=dot
# 4 test files passed, 35 tests passed

npm run build
# passed

npm test -- granularKillSwitch.test.ts happDetector.test.ts --reporter=dot
# 2 test files passed, 4 tests passed

npm run build
# passed

npm test -- externalProxy.test.ts keyHealthChecker.test.ts --reporter=dot
# 2 test files passed, 11 tests passed

npm run build
# passed

npm test -- externalProxy.test.ts --reporter=dot
# 1 test file passed, 3 tests passed

npm run build
# passed

npm test -- firewallKillSwitchValidation.test.ts --reporter=dot
# 1 test file passed, 10 tests passed

npm run build
# passed

npm test -- tunControllerConfig.test.ts --reporter=dot
# 1 test file passed, 43 tests passed

npm run build
# passed

npm test -- splitTunneling.test.ts dnsProfiles.test.ts profileRotation.test.ts serverGroupsRefresh.test.ts serverPickerConsolidate.test.ts speedTest.test.ts --reporter=dot
# 6 test files passed, 55 tests passed

npm run build
# passed

npm test -- profileRotation.test.ts serverPickerPingPoisoning.test.ts --reporter=dot
# 2 test files passed, 21 tests passed

npm run build
# passed

npm test -- tunControllerRecoverySource.test.ts splitTunneling.test.ts splitTunnelProcess.test.ts systemNetwork.test.ts granularKillSwitch.test.ts granularKillSwitchInit.test.ts --reporter=dot
# 6 test files passed, 26 tests passed

npm test -- splitTunnelProcess.test.ts splitTunneling.test.ts --reporter=dot
# 2 test files passed, 16 tests passed

npm run build
# passed

npm test -- mainIpcRegression.test.ts traySource.test.ts notificationsReset.test.ts notificationsGating.test.ts trafficMonitor.test.ts store.connectionBusy.test.ts AppSource.test.ts --reporter=dot
# 7 test files passed, 24 tests passed

npm run build
# passed

npm test -- elevatedPsHelper.test.ts --reporter=dot
# 1 test file passed, 7 tests passed

npm run build
# passed
```

Known previous full-suite blocker: resolved. Full `npm test -- --reporter=dot` now passes after logger isolation fixes.

Latest verification after current work:

```powershell
npm test -- LogsSource.test.ts diagnosticsPreflight.test.ts MaintenanceSource.test.ts preloadValidation.test.ts mainIpcRegression.test.ts systemDiagnostics.test.ts -- --reporter=dot
# 6 test files passed, 33 tests passed

npm test -- --reporter=dot
# 61 test files passed, 499 tests passed

npm run build
# passed

npm run dist:win
# passed; installer rebuilt at `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe` (117450296 bytes, 2026-07-04 18:51:23 local time)

Get-AuthenticodeSignature .\dist\VPN-Tunnel-Enforcer-Setup-1.1.0.exe
Get-AuthenticodeSignature ".\dist\win-unpacked\VPN Tunnel Enforcer.exe"
# both NotSigned; no real Authenticode publisher certificate is present
```

## MEDIUM Audit Tracker

### Networking

| ID | Status | Finding | Current decision | Files likely involved | Done evidence |
| --- | --- | --- | --- | --- | --- |
| M-N1 | DONE | `systemNetwork.ts` silently swallows `reg`/`netsh winhttp reset proxy` failures. | Added `warnings` to baseline result, logs `netsh` and unexpected `reg` failures, ignores only expected missing-value deletes. | `vpn-tunnel-enforcer/src/main/systemNetwork.ts`, `vpn-tunnel-enforcer/src/main/systemNetwork.test.ts` | `npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts --reporter=dot` passed: 34 tests. |
| M-N2 | DONE | `granularKillSwitch.ts` can apply policy before `singboxExePath` init. | `engageKillSwitch()` now fails fast before init or failed firewall install; `setLevel()` rolls back stored granular and legacy state on apply failure. | `vpn-tunnel-enforcer/src/main/granularKillSwitch.ts`, `vpn-tunnel-enforcer/src/main/granularKillSwitch.test.ts` | `npm test -- granularKillSwitch.test.ts happDetector.test.ts --reporter=dot` passed: 4 tests; `npm run build` passed. |
| M-N3 | DONE | Split-tunnel rule generation uses `basename()` and can miss `.exe` for process entries. | Route-rule/process-name getters now use `normalizeProcessName`, appending `.exe` for process entries and normalizing casing. | `vpn-tunnel-enforcer/src/main/splitTunneling.ts`, `vpn-tunnel-enforcer/src/main/splitTunneling.test.ts` | `npm test -- splitTunneling.test.ts dnsProfiles.test.ts leakSelfTest.test.ts trafficMonitor.test.ts --reporter=dot` passed: 35 tests; `npm run build` passed. |
| M-N4 | DONE | `validateProxyFullTunnel` suspicious cross-check is mostly unreachable due immediate fallback race. | Direct-IP comparison now gets a short grace window when the proxy returned a public IP, so same-IP split/direct proxy detection is reachable without adding long startup latency. | `vpn-tunnel-enforcer/src/main/tunController.ts` | `npm test -- tunControllerConfig.test.ts --reporter=dot` passed: 43 tests; `npm run build` passed. |
| M-N5 | DONE | `pickFreeLocalPort` TOCTOU. | Existing mitigation verified: both direct and Clash ports are pre-resolved with `bind(0)`, collision is excluded, and startup has a one-shot `WSAEACCES` retry with fresh ports. | `vpn-tunnel-enforcer/src/main/tunController.ts`, `vpn-tunnel-enforcer/src/main/tunControllerConfig.test.ts` | `npm test -- tunControllerConfig.test.ts --reporter=dot` passed: 43 tests; `npm run build` passed. |
| M-N6 | DONE | Some start/early paths clear `restartTimer` but not `stableTimer`. | `start()` now uses `clearRestartTimers()` instead of manually clearing only `restartTimer`. | `vpn-tunnel-enforcer/src/main/tunController.ts` | `npm run build` passed. |
| M-N7 | DONE | DNS IPv6 boundary cases lack explicit tests. | Added boundary tests and switched IPv6 validation to Node `net.isIP` after zone stripping, covering IPv4-mapped IPv6. | `vpn-tunnel-enforcer/src/main/dnsProfiles.ts`, `vpn-tunnel-enforcer/src/main/dnsProfiles.test.ts` | `npm test -- splitTunneling.test.ts dnsProfiles.test.ts leakSelfTest.test.ts trafficMonitor.test.ts --reporter=dot` passed: 35 tests; `npm run build` passed. |

### Security And Privileges

| ID | Status | Finding | Current decision | Files likely involved | Done evidence |
| --- | --- | --- | --- | --- | --- |
| M-S1 | DONE | TUN adapter allow rule polls only about 5s. | Firewall script now polls TUN alias for about 15s before failing the required allow-rule gate; JS warning no longer fires prematurely at 5s while the firewall poll is still running. | `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts`, `vpn-tunnel-enforcer/src/main/tunController.ts` | `npm test -- firewallKillSwitchValidation.test.ts --reporter=dot` passed: 10 tests; `npm run build` passed. |
| M-S2 | DONE | CIDR validator allows `0.0.0.0/0`, `::/0`, `0.0.0.0`, `::`. | Switched validation to `net.isIP`; rejects unspecified addresses and `/0` wildcard exceptions. | `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts`, `vpn-tunnel-enforcer/src/main/firewallKillSwitchValidation.test.ts` | `npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts --reporter=dot` passed: 34 tests. |
| M-S3 | DONE | IPv6 leak window between firewall install and adapter lockdown. | Verified ordering: adapter lockdown promise is awaited before kill-switch engagement; TUN remains IPv4-only and DefaultOutboundAction blocks physical IPv6. Also moved incomplete-warning after kill-switch result. | `vpn-tunnel-enforcer/src/main/tunController.ts`, `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts` | `npm test -- firewallKillSwitchValidation.test.ts --reporter=dot` passed: 10 tests; `npm run build` passed. Windows runtime smoke still useful. |
| M-S4 | DONE | Teredo rollback falls back to `default` if snapshot parse failed. | Unknown transition adapter state now emits `TRANS_*:unknown`, leaves the adapter disabled, and logs a warning instead of restoring `default`. | `vpn-tunnel-enforcer/src/main/physicalAdapterLockdown.ts` | `npm run build` passed. Windows runtime rollback still useful. |
| M-S5 | DONE | Orphan DNS repair only catches current VPNTE DNS constants. | Orphan DNS repair now detects current constants plus current and legacy TUN IPv4 prefixes. | `vpn-tunnel-enforcer/src/main/physicalAdapterLockdown.ts` | `npm run build` passed. Windows runtime repair still useful. |
| M-S6 | DONE | `extractRealErrors` free-text regex has false positives. | Error extraction now requires sing-box error levels or known failure contexts instead of arbitrary words in INFO text. | `vpn-tunnel-enforcer/src/main/leakDiagnostics.ts`, `vpn-tunnel-enforcer/src/main/leakDiagnostics.test.ts` | `npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts --reporter=dot` passed: 34 tests. |
| M-S7 | DONE | IPv4 public IP fallback depends only on `curl.exe` after axios endpoints. | Added PowerShell `Invoke-RestMethod` fallback and stricter IPv4 extraction. | `vpn-tunnel-enforcer/src/main/leakDiagnostics.ts`, `vpn-tunnel-enforcer/src/main/leakDiagnostics.test.ts` | `npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts --reporter=dot` passed: 34 tests. |
| M-S8 | DONE | Cyrillic adapter names may miss VPN detection due regex boundaries/description handling. | VPN-like adapter detection now checks adapter name + description and includes Cyrillic `впн/туннел/тунель` patterns without fragile word-boundaries. | `vpn-tunnel-enforcer/src/main/leakDiagnostics.ts` | `npm run build` passed. Windows runtime adapter-name check still useful. |
| M-S9 | DONE | Direct-out leak parser can silently return zero on sing-box log format drift. | Classifier counts unparsed `direct-out` lines and the UI item warns on parser drift instead of reporting clean. | `vpn-tunnel-enforcer/src/main/leakDiagnostics.ts`, `vpn-tunnel-enforcer/src/main/leakDiagnostics.test.ts` | `npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts --reporter=dot` passed: 34 tests. |
| M-S10 | DONE | `curl --interface` binds TCP only, not DNS. | Reviewed after M-S11: interface-bound curl remains a TCP egress diagnostic, while DNS leak coverage is handled by the separate multi-endpoint DNS side-channel probe. | `vpn-tunnel-enforcer/src/main/leakSelfTest.ts`, `vpn-tunnel-enforcer/src/main/leakSelfTest.test.ts` | `npm test -- splitTunneling.test.ts dnsProfiles.test.ts leakSelfTest.test.ts trafficMonitor.test.ts --reporter=dot` passed: 35 tests; `npm run build` passed. |
| M-S11 | DONE | DNS leak detection uses a single Cloudflare trace endpoint. | DNS side-channel now tries multiple trace/IP endpoints and parses both `ip=` trace output and plain IP output. | `vpn-tunnel-enforcer/src/main/leakSelfTest.ts`, `vpn-tunnel-enforcer/src/main/leakSelfTest.test.ts` | `npm test -- splitTunneling.test.ts dnsProfiles.test.ts leakSelfTest.test.ts trafficMonitor.test.ts --reporter=dot` passed: 35 tests; `npm run build` passed. |
| M-S12 | DONE | Git autoconfig uses `git config --global`, leaking proxy scope. | Git autoconfig remains intentionally user-global for tool compatibility, but now uses `execFile`, preserves/restores previous global proxy, and exposes `scope=user-global`, warning, managed path, and backup path in status metadata. | `vpn-tunnel-enforcer/src/main/autoconfig/git.ts`, `vpn-tunnel-enforcer/src/main/autoconfig/index.ts`, `vpn-tunnel-enforcer/src/renderer/store.ts`, `vpn-tunnel-enforcer/src/renderer/App.tsx` | `npm run build` passed. |
| M-S13 | DONE | Gradle autoconfig writes user-global `~/.gradle/gradle.properties`. | Gradle autoconfig remains intentionally user-global for Gradle daemon/tool compatibility, but now uses a managed block, preserves the original backup, and exposes `scope=user-global`, warning, managed path, and backup path in status metadata. | `vpn-tunnel-enforcer/src/main/autoconfig/gradle.ts`, `vpn-tunnel-enforcer/src/main/autoconfig/index.ts`, `vpn-tunnel-enforcer/src/renderer/store.ts`, `vpn-tunnel-enforcer/src/renderer/App.tsx` | `npm run build` passed. |
| M-S14 | DONE | Gradle backup/write flow can lose original on partial write failure. | Backup is created only once, original backup is not overwritten by repeated Apply, and writes use temp+rename. | `vpn-tunnel-enforcer/src/main/autoconfig/gradle.ts` | `npm run build` passed. |
| M-S15 | DONE | `setx` persists env and child processes keep old env after rollback. | Apply/rollback now updates current `process.env` and broadcasts `WM_SETTINGCHANGE`; already-running child processes remain an OS limitation. | `vpn-tunnel-enforcer/src/main/autoconfig/env.ts` | `npm run build` passed. Windows runtime check still useful. |
| M-S16 | DONE | Browser hardening HKLM vs HKCU enforcement is not clearly surfaced/read back. | Chromium policy writes are read back; details now warn when only HKCU policy is confirmed. | `vpn-tunnel-enforcer/src/main/browserHardening.ts` | `npm run build` passed. Windows browser policy page check still useful. |
| M-S17 | DONE | Chromium Preferences are rewritten minified. | Chromium Preferences now preserve multiline JSON indentation/newline style when rewritten. | `vpn-tunnel-enforcer/src/main/browserHardening.ts` | `npm run build` passed. |
| M-S18 | DONE | Browser hardening rollback deletes Preferences if backup missing/corrupt. | Rollback now skips existing files when their backup is missing instead of deleting them. | `vpn-tunnel-enforcer/src/main/browserHardening.ts` | `npm run build` passed. |
| M-S19 | DONE | `execElevatedPs` callers can wait for timeout if helper unavailable. | Added `ElevatedPsHelperError` and typed `elevated-helper-unavailable` failure when helper cannot start. | `vpn-tunnel-enforcer/src/main/elevatedPsHelper.ts`, `vpn-tunnel-enforcer/src/main/elevatedPsHelper.test.ts` | `npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts --reporter=dot` passed: 34 tests. |
| M-S20 | DONE | Pending elevated PS commands rejected generically on shutdown. | Pending commands now reject with typed `elevated-helper-stopped`, `elevated-helper-exited`, or `elevated-helper-timeout`. | `vpn-tunnel-enforcer/src/main/elevatedPsHelper.ts`, `vpn-tunnel-enforcer/src/main/elevatedPsHelper.test.ts` | `npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts --reporter=dot` passed: 34 tests. |

### VPN Profiles And Servers

| ID | Status | Finding | Current decision | Files likely involved | Done evidence |
| --- | --- | --- | --- | --- | --- |
| M-V1 | DONE | Happ config scan regex can false-positive ports in comments/text. | Config scan now strips comments, only accepts explicit local proxy/listen keys, collects candidates instead of first match, and requires protocol verification before returning. | `vpn-tunnel-enforcer/src/main/happDetector.ts`, `vpn-tunnel-enforcer/src/main/happDetector.test.ts` | `npm test -- granularKillSwitch.test.ts happDetector.test.ts --reporter=dot` passed: 4 tests; `npm run build` passed. |
| M-V2 | DONE | Happ/Clash on port 443 excluded from loopback listener detection. | Loopback listener scan and fallback typical-port probing now allow 443, still requiring HTTP/SOCKS protocol verification. | `vpn-tunnel-enforcer/src/main/happDetector.ts`, `vpn-tunnel-enforcer/src/main/happDetector.test.ts` | `npm test -- granularKillSwitch.test.ts happDetector.test.ts --reporter=dot` passed: 4 tests; `npm run build` passed. |
| M-V3 | DONE | `urlAvailability` calls `session.setProxy(...).catch(...)` without await before `loadURL`. | Offscreen render now waits for `session.setProxy` before `loadURL`. | `vpn-tunnel-enforcer/src/main/urlAvailability.ts` | `npm test -- vpnProfilesProtocolCoverage.test.ts urlAvailabilityVerdict.test.ts --reporter=dot` passed: 21 tests; `npm run build` passed. |
| M-V4 | DONE | External proxy control server port conflict handling weak. | Control server now logs `EADDRINUSE`, falls back to an ephemeral loopback port when the default is busy, and writes endpoint metadata for CLI discovery. | `vpn-tunnel-enforcer/src/main/externalProxy.ts`, `vpn-tunnel-enforcer/resources/vpnte-proxy.ps1`, `vpn-tunnel-enforcer/README.md` | `npm test -- externalProxy.test.ts --reporter=dot` passed: 3 tests; `npm run build` passed. |
| M-V5 | DONE | External proxy sing-box child has no pidfile; can orphan on parent crash. | Added managed child pidfile lifecycle: stale cleanup before start, pidfile write after spawn, removal on stop/exit with pid guard. | `vpn-tunnel-enforcer/src/main/externalProxy.ts`, `vpn-tunnel-enforcer/src/main/managedChildProcess.ts` | `npm test -- externalProxy.test.ts keyHealthChecker.test.ts --reporter=dot` passed: 11 tests; `npm run build` passed. |
| M-V6 | DONE | Hysteria2 health-check child has no pidfile; can orphan on parent crash. | HY2 probe now writes a temp-dir pidfile, removes it in finally, and scans/removes stale probe dirs before new probes. | `vpn-tunnel-enforcer/src/main/keyHealthChecker.ts`, `vpn-tunnel-enforcer/src/main/managedChildProcess.ts` | `npm test -- externalProxy.test.ts keyHealthChecker.test.ts --reporter=dot` passed: 11 tests; `npm run build` passed. |
| M-V7 | DONE | Hysteria2 `server_ports` rejects comma-separated list. | Hysteria2 `server_ports/mport` now accepts comma-separated single ports and ranges, and exports ranges back to URI form. | `vpn-tunnel-enforcer/src/main/vpnProfiles.ts`, `vpn-tunnel-enforcer/src/main/vpnProfilesProtocolCoverage.test.ts` | `npm test -- vpnProfilesProtocolCoverage.test.ts urlAvailabilityVerdict.test.ts --reporter=dot` passed: 21 tests; `npm run build` passed. |
| M-V8 | DONE | Server latency sampling can take 15s+ without total cap. | Latency sampling now has an overall ~7s budget and returns partial/loss results when the cap is hit. | `vpn-tunnel-enforcer/src/main/serverProbe.ts` | `npm run build` passed. |
| M-V9 | DONE | Rotation availability can be misled when TUN is up. | Rotation availability no longer runs live `smartOfflinePing` while TUN is active; it uses only fresh cached status and treats stale/unknown entries as unavailable until direct probing is safe. | `vpn-tunnel-enforcer/src/main/profileRotation.ts`, `vpn-tunnel-enforcer/src/main/serverPicker.ts` | `npm test -- profileRotation.test.ts serverPickerPingPoisoning.test.ts --reporter=dot` passed: 21 tests; `npm run build` passed. |

### UI And IPC

| ID | Status | Finding | Current decision | Files likely involved | Done evidence |
| --- | --- | --- | --- | --- | --- |
| M-U1 | NOFIX | UI reviewer aborted; possible `trafficMonitor` subscriber/timer leak. | Focused review found `start/stop` clears respawn timer, fallback interval, reader process, and unsubscribe filters callbacks; no confirmed leak. | `vpn-tunnel-enforcer/src/main/trafficMonitor.ts`, `vpn-tunnel-enforcer/src/main/trafficMonitor.test.ts` | `npm test -- splitTunneling.test.ts dnsProfiles.test.ts leakSelfTest.test.ts trafficMonitor.test.ts --reporter=dot` passed: 35 tests. |
| UI-extra-1 | DONE | Duplicate `CheckCircle2` import reported in Dashboard. | Duplicate lucide import removed. | `vpn-tunnel-enforcer/src/renderer/pages/Dashboard.tsx` | `npm run build` passed. |

### Cross-Cutting

| ID | Status | Finding | Current decision | Files likely involved | Done evidence |
| --- | --- | --- | --- | --- | --- |
| M-X1 | DONE | No unified IPC payload validation. | Added shared IPC payload validators and applied focused validation/field allowlists to high-risk config, DNS, kill-switch, split-tunnel, server-picker, and rotation IPC boundaries. Full schema-library migration is not required for this audit item. | `vpn-tunnel-enforcer/src/main/ipcValidation.ts`, `configManager.ts`, `dnsProfiles.ts`, `granularKillSwitch.ts`, `splitTunneling.ts`, `serverPicker.ts`, `profileRotation.ts` | `npm test -- granularKillSwitch.test.ts dnsProfiles.test.ts splitTunneling.test.ts serverPickerConsolidate.test.ts serverPickerPingPoisoning.test.ts profileRotation.test.ts --reporter=dot` passed: 55 tests; `npm run build` passed. |
| M-X2 | DONE | Sensitive network topology data in logs. | IPC args use compact redaction and `appLogger` now centrally redacts IP/MAC/topology-like fields in messages, details, console output, and exported app log snapshots. | `vpn-tunnel-enforcer/src/main/ipcLogging.ts`, `vpn-tunnel-enforcer/src/main/appLogger.ts`, feature IPC wrappers | `npm test -- appLoggerRedaction.test.ts --reporter=dot` passed: 1 test; earlier IPC redaction test batch passed 55 tests; `npm run build` passed. |
| M-X3 | DONE | Shell-string `exec` pattern is widespread. | High-risk shell-string paths now use `execFile`/argv or encoded PowerShell: autoconfig Git/env, diagnostics ZIP compression, split-tunnel registry scan, browser/location registry operations, and TUN normal config/probe launch paths. The old Store repair helper hardened in this batch was later removed from the app. Remaining `exec` uses are static diagnostics or the `sudo-prompt` UAC command-string boundary. | `vpn-tunnel-enforcer/src/main/autoconfig/git.ts`, `autoconfig/env.ts`, `admin.ts`, `diagnosticsExport.ts`, `splitTunneling.ts`, `browserHardening.ts`, `locationPrivacy.ts`, `tunController.ts` | `npm test -- tunControllerConfig.test.ts splitTunneling.test.ts --reporter=dot` passed: 47 tests; `npm run build` passed. |
| X-extra-1 | DONE | Several feature-local IPC wrappers log raw `args`. | Added shared `compactForIpcLog()` and replaced raw args logging in config, DNS, rotation, groups, split tunneling, speed test, and server picker wrappers. | `vpn-tunnel-enforcer/src/main/ipcLogging.ts`, `configManager.ts`, `dnsProfiles.ts`, `profileRotation.ts`, `serverGroups.ts`, `splitTunneling.ts`, `speedTest.ts`, `serverPicker.ts` | `npm test -- splitTunneling.test.ts dnsProfiles.test.ts profileRotation.test.ts serverGroupsRefresh.test.ts serverPickerConsolidate.test.ts speedTest.test.ts --reporter=dot` passed: 55 tests; `npm run build` passed. |

## Recommended Fix Order

1. Kill-switch and diagnostics safety: `M-S2`, `M-S6`, `M-S7`, `M-S9`, `M-S19`, `M-S20`, `M-N1`.
2. Windows state rollback safety: `M-S4`, `M-S5`, `M-S15`, `M-S16`, `M-S18`.
3. User-input command/config hardening: `M-X1`, `M-X3`, `M-S12`, `M-S13`, `M-S14`, autoconfig escaping.
4. VPN/profile reliability: `M-V3`, `M-V5`, `M-V6`, `M-V7`, `M-V8`, `M-V9`.
5. Smaller correctness/tests/UI polish: `M-N3`, `M-N6`, `M-N7`, `M-U1`, `UI-extra-1`, `X-extra-1`.

## Progress Log

```text
2026-07-02 - M-S2/M-S6/M-S7/M-S9/M-S19/M-S20/M-N1 DONE
Files:
- vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts
- vpn-tunnel-enforcer/src/main/firewallKillSwitchValidation.test.ts
- vpn-tunnel-enforcer/src/main/leakDiagnostics.ts
- vpn-tunnel-enforcer/src/main/leakDiagnostics.test.ts
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.ts
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.test.ts
- vpn-tunnel-enforcer/src/main/systemNetwork.ts
- vpn-tunnel-enforcer/src/main/systemNetwork.test.ts
Verification:
- npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts --reporter=dot
- Result: 4 test files passed, 34 tests passed.
Windows-only gap:
- Real Windows behavior for netsh/reg baseline warnings and elevated PS helper fallback still needs runtime smoke if desired.
Notes:
- Firewall exceptions now reject unspecified/wildcard IPs.
- Leak diagnostics gained stricter error extraction, IPv4 PowerShell fallback, and direct-out parser-drift warning.
- Elevated PS helper now uses typed errors for unavailable/stopped/exited/timeout.
- System-network baseline now surfaces non-fatal reset warnings instead of swallowing them.
```

```text
2026-07-02 - M-S4/M-S5/M-S15/M-S16/M-S17/M-S18 DONE
Files:
- vpn-tunnel-enforcer/src/main/physicalAdapterLockdown.ts
- vpn-tunnel-enforcer/src/main/autoconfig/env.ts
- vpn-tunnel-enforcer/src/main/browserHardening.ts
Verification:
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows rollback/repair should still be smoke-tested for transition adapter netsh state, orphan DNS repair, WM_SETTINGCHANGE broadcast, and browser policy read-back.
Notes:
- Unknown Teredo/6to4/ISATAP prior state is left disabled and logged instead of restored to default.
- Orphan DNS repair now detects current and legacy TUN prefixes, not only exact DNS constants.
- Env autoconfig updates current process env and broadcasts Environment changes after apply/rollback.
- Browser hardening read-backs policy writes, preserves Chromium Preferences formatting, and avoids deleting existing files when backup is missing.
```

```text
2026-07-02 - M-S14 DONE; M-S12/M-S13/M-X3 INTERMEDIATE STATUS (SUPERSEDED BELOW)
Files:
- vpn-tunnel-enforcer/src/main/autoconfig/git.ts
- vpn-tunnel-enforcer/src/main/autoconfig/env.ts
- vpn-tunnel-enforcer/src/main/autoconfig/gradle.ts
Verification:
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows autoconfig smoke should verify setx/reg/powershell execFile calls and Git backup restore behavior.
Notes:
- Git/env user-input command paths now use execFile instead of shell-interpolated exec.
- Git stores the user's previous global http/https proxy and restores it on rollback.
- Gradle backup is no longer overwritten by repeated Apply; gradle.properties writes are atomic temp+rename.
- Superseded: M-S12/M-S13/M-X3 are now DONE in later log blocks.
- Superseded: Git/Gradle still modify user-global config while applied, but scope is now explicit in status metadata and managed by backup/rollback.
```

```text
2026-07-02 - M-V3/M-V7/M-V8 DONE
Files:
- vpn-tunnel-enforcer/src/main/urlAvailability.ts
- vpn-tunnel-enforcer/src/main/vpnProfiles.ts
- vpn-tunnel-enforcer/src/main/vpnProfilesProtocolCoverage.test.ts
- vpn-tunnel-enforcer/src/main/serverProbe.ts
Verification:
- npm test -- vpnProfilesProtocolCoverage.test.ts urlAvailabilityVerdict.test.ts --reporter=dot
- Result: 2 test files passed, 21 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Offscreen BrowserWindow proxy behavior should still be smoke-tested in Electron on Windows.
Notes:
- URL rendered probe now waits for setProxy before loadURL.
- Hysteria2 mport/server_ports preserves comma-separated ports/ranges.
- Server latency probing has a hard total cap and records remaining samples as loss.
```

```text
2026-07-02 - M-N3/M-N6/M-N7/M-S8/M-S11/UI-extra-1 DONE; M-U1 NOFIX
Files:
- vpn-tunnel-enforcer/src/main/splitTunneling.ts
- vpn-tunnel-enforcer/src/main/splitTunneling.test.ts
- vpn-tunnel-enforcer/src/main/tunController.ts
- vpn-tunnel-enforcer/src/main/dnsProfiles.ts
- vpn-tunnel-enforcer/src/main/dnsProfiles.test.ts
- vpn-tunnel-enforcer/src/main/leakDiagnostics.ts
- vpn-tunnel-enforcer/src/main/leakSelfTest.ts
- vpn-tunnel-enforcer/src/main/leakSelfTest.test.ts
- vpn-tunnel-enforcer/src/main/trafficMonitor.ts
- vpn-tunnel-enforcer/src/main/trafficMonitor.test.ts
- vpn-tunnel-enforcer/src/renderer/pages/Dashboard.tsx
Verification:
- npm test -- splitTunneling.test.ts dnsProfiles.test.ts leakSelfTest.test.ts trafficMonitor.test.ts --reporter=dot
- Result: 4 test files passed, 35 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Cyrillic adapter detection and live split-tunnel process_name matching should still be smoke-tested on Windows.
Notes:
- Split-tunnel route rules and getters now use normalizeProcessName, including .exe append for bare process entries.
- TUN start path now clears both restartTimer and stableTimer through clearRestartTimers().
- DNS IPv6 validation now uses Node net.isIP after zone stripping, with explicit boundary tests.
- Leak diagnostics recognizes VPN-like Cyrillic adapter names and descriptions.
- Leak self-test DNS side-channel tries multiple endpoints.
- trafficMonitor lifecycle review found no confirmed timer/subscriber leak; existing tests pass.
- Dashboard duplicate CheckCircle2 import removed.
```

```text
2026-07-02 - M-N2/M-V1/M-V2 DONE
Files:
- vpn-tunnel-enforcer/src/main/granularKillSwitch.ts
- vpn-tunnel-enforcer/src/main/granularKillSwitch.test.ts
- vpn-tunnel-enforcer/src/main/happDetector.ts
- vpn-tunnel-enforcer/src/main/happDetector.test.ts
Verification:
- npm test -- granularKillSwitch.test.ts happDetector.test.ts --reporter=dot
- Result: 2 test files passed, 4 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should still verify live loopback listener detection on port 443 and actual firewall elevation failure messaging.
Notes:
- Granular kill-switch no longer silently stores standard/strict when sing-box path is not initialized or firewall rule installation fails; stored level and legacy firewallKillSwitch are rolled back.
- Happ config scanning now ignores comments/unrelated fields, collects explicit local proxy/listen ports, and only returns protocol-verified candidates.
- Happ/Clash detection now allows port 443 in listener/fallback probing while still requiring HTTP/SOCKS verification.
```

```text
2026-07-02 - M-V5/M-V6 DONE
Files:
- vpn-tunnel-enforcer/src/main/managedChildProcess.ts
- vpn-tunnel-enforcer/src/main/externalProxy.ts
- vpn-tunnel-enforcer/src/main/keyHealthChecker.ts
Verification:
- npm test -- externalProxy.test.ts keyHealthChecker.test.ts --reporter=dot
- Result: 2 test files passed, 11 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should verify stale pidfile cleanup kills only matching sing-box command lines and leaves mismatched/reused PIDs untouched.
Notes:
- Added a shared managed child pidfile helper with guarded cleanup.
- External proxy writes `external-proxy.pid`, removes it on stop/exit, and attempts stale cleanup before start.
- HY2 health probes write `sing-box.pid` inside their temp dir, remove it in `finally`, and scan stale `vpnte-hy2-probe-*` dirs before new probes.
```

```text
2026-07-02 - M-V4 DONE
Files:
- vpn-tunnel-enforcer/src/main/externalProxy.ts
- vpn-tunnel-enforcer/resources/vpnte-proxy.ps1
- vpn-tunnel-enforcer/README.md
Verification:
- npm test -- externalProxy.test.ts --reporter=dot
- Result: 1 test file passed, 3 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real packaged smoke should verify `vpnte-proxy.ps1` discovers `external-proxy-control-endpoint.json` after a default-port conflict.
Notes:
- Control server keeps default port 17873 when available.
- If default port is busy and `VPNTE_CONTROL_PORT` was not explicitly set, the app falls back to an ephemeral loopback port and writes endpoint metadata.
- `vpnte-proxy.ps1` reads endpoint metadata and supports `VPNTE_CONTROL_URL` override.
```

```text
2026-07-02 - M-S1/M-S3 DONE
Files:
- vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts
- vpn-tunnel-enforcer/src/main/tunController.ts
Verification:
- npm test -- firewallKillSwitchValidation.test.ts --reporter=dot
- Result: 1 test file passed, 10 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should verify a slow TUN adapter can appear within the new 15s firewall allow-rule polling window.
Notes:
- TUN InterfaceAlias allow-rule polling increased from about 5s to about 15s.
- The required-rule fatal gate still prevents DefaultOutboundAction=Block when TUN/sing-box/core allow rules are missing.
- Startup ordering was rechecked: adapter lockdown is awaited before kill-switch engagement, TUN is IPv4-only, and DefaultOutboundAction blocks physical IPv6.
- The old 5s incomplete warning was removed; warning now happens only after the kill-switch result is known.
```

```text
2026-07-02 - M-N4/M-N5 DONE
Files:
- vpn-tunnel-enforcer/src/main/tunController.ts
- vpn-tunnel-enforcer/src/main/tunControllerConfig.test.ts
Verification:
- npm test -- tunControllerConfig.test.ts --reporter=dot
- Result: 1 test file passed, 43 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should still verify a forced WSAEACCES bind failure retries once with fresh direct/clash ports.
Notes:
- validateProxyFullTunnel now gives the direct-IP probe a short grace window before accepting a proxy public IP as safe.
- Existing port mitigation was reviewed: direct and clash ports are both pre-resolved with bind(0), collision is excluded, and startup has a one-shot WSAEACCES retry.
```

```text
2026-07-02 - X-extra-1 DONE; M-X2 INTERMEDIATE STATUS (SUPERSEDED BELOW)
Files:
- vpn-tunnel-enforcer/src/main/ipcLogging.ts
- vpn-tunnel-enforcer/src/main/configManager.ts
- vpn-tunnel-enforcer/src/main/dnsProfiles.ts
- vpn-tunnel-enforcer/src/main/profileRotation.ts
- vpn-tunnel-enforcer/src/main/serverGroups.ts
- vpn-tunnel-enforcer/src/main/splitTunneling.ts
- vpn-tunnel-enforcer/src/main/speedTest.ts
- vpn-tunnel-enforcer/src/main/serverPicker.ts
Verification:
- npm test -- splitTunneling.test.ts dnsProfiles.test.ts profileRotation.test.ts serverGroupsRefresh.test.ts serverPickerConsolidate.test.ts speedTest.test.ts --reporter=dot
- Result: 6 test files passed, 55 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- None specific; runtime logs should be spot-checked to confirm redacted IPC payloads are readable enough for support.
Notes:
- Added compactForIpcLog() with redactSensitiveConfig() and truncation.
- Replaced raw IPC args logging in feature-local wrappers.
- Superseded: M-X2 is now DONE after centralized appLogger topology redaction.
```

```text
2026-07-02 - M-V9 DONE
Files:
- vpn-tunnel-enforcer/src/main/profileRotation.ts
- vpn-tunnel-enforcer/src/main/serverPicker.ts
Verification:
- npm test -- profileRotation.test.ts serverPickerPingPoisoning.test.ts --reporter=dot
- Result: 2 test files passed, 21 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should confirm rotation with an active TUN skips stale live probes and only rotates to freshly cached-online profiles.
Notes:
- Rotation availability now detects active TUN and skips smartOfflinePing for stale entries to avoid tunnel-routed false availability.
- Fresh cached status remains usable so recently checked online profiles can still rotate without a live probe.
```

```text
2026-07-02 - M-S10 DONE
Files:
- vpn-tunnel-enforcer/src/main/leakSelfTest.ts
- vpn-tunnel-enforcer/src/main/leakSelfTest.test.ts
Verification:
- Reused earlier M-S11 verification: npm test -- splitTunneling.test.ts dnsProfiles.test.ts leakSelfTest.test.ts trafficMonitor.test.ts --reporter=dot
- Result: 4 test files passed, 35 tests passed.
- Reused later npm run build results after leakSelfTest changes.
Windows-only gap:
- Real DNS side-channel behavior still benefits from Windows runtime smoke under an active TUN.
Notes:
- curl --interface remains TCP-only by nature and is used only as a per-adapter TCP egress diagnostic.
- DNS leak coverage is now provided by a separate multi-endpoint DNS side-channel probe, so the original limitation is no longer the only DNS signal.
```

```text
2026-07-02 - M-X1 DONE
Files:
- vpn-tunnel-enforcer/src/main/ipcValidation.ts
- vpn-tunnel-enforcer/src/main/configManager.ts
- vpn-tunnel-enforcer/src/main/dnsProfiles.ts
- vpn-tunnel-enforcer/src/main/granularKillSwitch.ts
- vpn-tunnel-enforcer/src/main/splitTunneling.ts
- vpn-tunnel-enforcer/src/main/serverPicker.ts
- vpn-tunnel-enforcer/src/main/profileRotation.ts
Verification:
- npm test -- granularKillSwitch.test.ts dnsProfiles.test.ts splitTunneling.test.ts serverPickerConsolidate.test.ts serverPickerPingPoisoning.test.ts profileRotation.test.ts --reporter=dot
- Result: 6 test files passed, 55 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real UI smoke should confirm bad renderer payloads surface as handled IPC errors and normal forms still submit cleanly.
Notes:
- Added small shared IPC validators instead of adding a new schema dependency.
- High-risk handlers now validate strings, enums, ports, bounded arrays, and rotation patch fields before touching stores/network/file flows.
- DNS optional secondary keeps accepting empty strings to preserve existing form behavior.
```

```text
2026-07-02 - M-X3 DONE
Files:
- vpn-tunnel-enforcer/src/main/autoconfig/git.ts
- vpn-tunnel-enforcer/src/main/autoconfig/env.ts
- vpn-tunnel-enforcer/src/main/admin.ts
- vpn-tunnel-enforcer/src/main/diagnosticsExport.ts
- vpn-tunnel-enforcer/src/main/splitTunneling.ts
- vpn-tunnel-enforcer/src/main/storeRepair.ts (historical; deleted later in MAINTENANCE REPAIR AUDIT/FIX PASS)
- vpn-tunnel-enforcer/src/main/browserHardening.ts
- vpn-tunnel-enforcer/src/main/locationPrivacy.ts
- vpn-tunnel-enforcer/src/main/tunController.ts
Verification:
- npm test -- tunControllerConfig.test.ts splitTunneling.test.ts --reporter=dot
- Result: 2 test files passed, 47 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should cover diagnostics ZIP export, browser/location rollback, and elevated TUN launch.
- Store repair actions are no longer in scope here: the Store repair/diagnostics implementation and renderer IPC were deleted in the Maintenance repair audit pass.
Notes:
- Converted high-risk shell-string invocations with paths/user-adjacent data to execFile argv or EncodedCommand PowerShell.
- TUN normal config check/probe launch no longer shells through quoted paths; sudo-prompt remains a command-string boundary by API design.
- Remaining exec() findings are static diagnostics/probes or elevated command wrappers and are not treated as the original widespread user-input shell-risk.
```

```text
2026-07-02 - M-S12/M-S13 DONE
Files:
- vpn-tunnel-enforcer/src/main/autoconfig/git.ts
- vpn-tunnel-enforcer/src/main/autoconfig/gradle.ts
- vpn-tunnel-enforcer/src/main/autoconfig/index.ts
- vpn-tunnel-enforcer/src/renderer/store.ts
- vpn-tunnel-enforcer/src/renderer/App.tsx
Verification:
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should apply/rollback Git and Gradle autoconfig and inspect the returned status metadata.
Notes:
- Git and Gradle proxy settings remain user-global because the current app autoconfig feature targets external CLI tools rather than a known project directory.
- Both targets now advertise scope=user-global plus warning, managedPath, and backupPath in getStatus(), while existing boolean apply/rollback remains compatible.
- The original values/files are preserved and restored on rollback, so the global scope is explicit and managed rather than silent.
```

```text
2026-07-02 - M-X2 DONE
Files:
- vpn-tunnel-enforcer/src/main/ipcLogging.ts
- vpn-tunnel-enforcer/src/main/appLogger.ts
- vpn-tunnel-enforcer/src/main/appLoggerRedaction.test.ts
- feature IPC wrappers listed in earlier X-extra-1 block
Verification:
- npm test -- appLoggerRedaction.test.ts --reporter=dot
- Result: 1 test file passed, 1 test passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real diagnostics export should be spot-checked to confirm logs remain useful after topology redaction.
Notes:
- appLogger now redacts IPv4, IPv6, MAC addresses, and topology-like detail fields before app.log writes and console output.
- Exported app log snapshots are redacted again on read, covering older JSON-lines and direct log file reads.
- IPC compact redaction from X-extra-1 remains in place for feature wrapper args.
```

```text
2026-07-02 - S1/S2 helper hardening DONE
Files:
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.ts
- vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts
- vpn-tunnel-enforcer/src/main/physicalAdapterLockdown.ts
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.test.ts
Verification:
- npm test -- elevatedPsHelper.test.ts firewallKillSwitchValidation.test.ts --reporter=dot
- Result: 2 test files passed, 13 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should verify helper-backed firewall and adapter lockdown scripts still execute through the persistent elevated helper.
Notes:
- execElevatedPs now requires an explicit policy: firewall-killswitch or physical-adapter-lockdown.
- The helper rejects blocked PowerShell tokens such as Invoke-Expression, Start-Process, web downloads, Add-Type, Remove-Item, and scripts with no command token from the selected policy.
- Existing size and queue limits remain in place.
```

```text
2026-07-02 - REAL-BUGS BATCH 1
Commit checkpoint:
- Stabilization/audit hardening committed as 0520d9b Hardening stability and audit fixes.

Items:
- RB-1 DONE: Renderer tab/page state no longer resets just because the user switches sidebar tabs.
  Files: vpn-tunnel-enforcer/src/renderer/App.tsx
  Note: App now keeps visited pages mounted and hides inactive pages instead of replacing one keyed page subtree.
- RB-2 DONE: External proxy no longer steals the main VPN selected-server name/right-panel active marker.
  Files: vpn-tunnel-enforcer/src/main/externalProxy.ts, vpn-tunnel-enforcer/src/main/externalProxy.test.ts
  Note: external proxy selection is tracked by external proxy runtime state, not server-picker activeProfileId.
- RB-3 DONE: Direct VPN server selection now hot-reloads the running tunnel from main-side servers:select.
  Files: vpn-tunnel-enforcer/src/main/serverPicker.ts, vpn-tunnel-enforcer/src/renderer/components/ProfileSelectorInline.tsx
  Note: renderer no longer tries startTun() against an already-running tunnel; main stops/starts directVpn with the selected outbound.
- DPI-1 FUTURE IDEA ONLY: ByeDPI-like improvement is parked for the future and is not part of the current audit-fix scope.
  Do not implement this now unless the user explicitly reopens it as a feature task.
  Current base: settings.stealthMode already lowers TUN MTU and enables sing-box TLS fragmentation where safe.
  Future direction: an explicit anti-DPI profile could tune sing-box fragmentation/utls/ALPN/transport parameters per outbound and optionally run a local pre-upstream proxy only in modes where it does not create TUN-over-TUN loops.
  Future Windows-only proof: test against real blocked/slow sites and Russian-IP-preserving smartRuSplit paths on Windows.

Verification:
- npm test -- externalProxy.test.ts serverPickerConsolidate.test.ts serverPickerPingPoisoning.test.ts tunControllerConfig.test.ts --reporter=dot
- Result: 4 test files passed, 58 tests passed.
- npm run build
- Result: passed.

Subagent findings used:
- tab state resets because App keyed/remounted one page subtree per sidebar page.
- external proxy wrote serverPicker.selectProfile(profile.id), overwriting the main selected profile.
- server selection only changed activeProfileId; live sing-box kept the old outbound until manual stop/start.
```

```text
2026-07-02 - VPN PROFILES REVIEW BATCH 1 DONE
Files:
- vpn-tunnel-enforcer/src/main/vpnProfiles.ts
- vpn-tunnel-enforcer/src/main/serverPicker.ts
- vpn-tunnel-enforcer/src/main/vpnProfilesRegression.test.ts
- vpn-tunnel-enforcer/src/main/vpnProfilesProtocolCoverage.test.ts
- vpn-tunnel-enforcer/src/main/serverPickerPingPoisoning.test.ts

Items:
- VP-H1 DONE: happ://add and mantaray://add base64 blobs with multiple glued VPN URIs now unwrap to the first extracted URI instead of returning the whole blob to parseVpnProfiles.
- VP-H2 DONE: appendProfilesToGroup now serializes the read-dedupe-save critical section so parallel imports from different subscription URLs do not overwrite each other's saved profiles.
- VP-M1 DONE: HTTP 3xx subscription responses without Location now throw a clear redirect error instead of falling through as an empty final body.
- VP-M2 DONE: resolveVpnProfiles now has a module-level in-flight guard keyed by input plus fetch/client-device options, covering direct callers such as inspectVpnInput.
- VP-M3 DONE: addFromInput computes trimmed/canonical/clientDevice once for its lock key and passes the same canonical value into addFromInputUnlocked.
- VP-L1 DONE: trojan, hysteria2/hy2, anytls, and shadowtls URI parsing rejects empty passwords instead of producing invalid sing-box outbounds.
- VP-L2 DONE: tunnelHttpProbe cache is tied to the current tunnel session key (startedAt/pid/mode/proxy/profile), so reconnects cannot reuse stale success/failure values.

Verification:
- npm test -- vpnProfilesRegression.test.ts vpnProfilesProtocolCoverage.test.ts serverPickerPingPoisoning.test.ts serverGroupsRefresh.test.ts --reporter=dot
- Result: 4 test files passed, 36 tests passed.
- npm run build
- Result: passed.

Windows-only gap:
- Real Windows smoke should import two different subscriptions concurrently, verify both groups/profiles remain, reconnect TUN, and confirm live ping probes are not reused across the old/new tunnel session.

Notes:
- The profile-store write queue only wraps the store mutation section; subscription fetches still run concurrently.
- The resolveVpnProfiles in-flight guard is option-sensitive so different client-device/HWID fetches do not collapse into one request.
```

```text
2026-07-02 - HIGH RE-REVIEW BATCH 2 DONE
Files:
- vpn-tunnel-enforcer/src/main/tunController.ts
- vpn-tunnel-enforcer/src/main/routingSelfTest.ts
- vpn-tunnel-enforcer/src/main/granularKillSwitch.ts
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.ts
- vpn-tunnel-enforcer/src/main/settings.ts
- vpn-tunnel-enforcer/src/main/tunControllerConfig.test.ts
- vpn-tunnel-enforcer/src/main/routingSelfTest.test.ts
- vpn-tunnel-enforcer/src/main/granularKillSwitchInit.test.ts
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.test.ts
- vpn-tunnel-enforcer/src/main/settingsLoginItem.test.ts

Items:
- N1 DONE + RUNTIME HOTFIX: remote DNS bootstrap resolvers now use `type: local` with no detour. The earlier `type: udp` + `detour: direct-out` avoided the proxy hostname circular dependency but sing-box 1.13 rejects it at runtime with `detour to an empty direct outbound makes no sense`.
- N2 DONE: tunController.stop() no longer emits stopped/desktop disconnect notification before baseline/kill-switch/adapter rollback finishes.
- N3 DONE: tunController.stop() resumes ipMonitor through a guarded finally path, so teardown exceptions cannot leave leak monitoring suspended forever.
- N12 DONE: routingSelfTest.ruEgressIp is no longer a dead stub; Smart-RU self-test now probes RU-domain echo pages through the normal TUN path.
- N14 DONE: granularKillSwitch.setLevel rejects standard/strict before init(singboxExePath), without mutating store/settings first.
- S1 DONE (superseded by BATCH 3): elevatedPsHelper now has policy-forbidden command patterns so required tokens cannot authorize cross-policy payloads like netsh advfirewall reset or HKLM Run persistence. BATCH 3 later tightened this further for cross-policy payloads, cmd invocation, and route table mutation.
- U4 DONE: settingsStore.save no longer applies login item / boot-recovery schtask on unrelated settings saves; boot recovery is ensured at most once per app process via sync/login changes.
- S32 ALREADY DONE BEFORE THIS BATCH: autoconfig/env.ts already uses socks5h:// plus ALL_PROXY for SOCKS5 env-mode proxying.
- V1/V2 ALREADY DONE BEFORE THIS BATCH: see VPN PROFILES REVIEW BATCH 1 and commit 5c7751e.

Verification:
- npm test -- tunControllerConfig.test.ts routingSelfTest.test.ts elevatedPsHelper.test.ts granularKillSwitchInit.test.ts settingsLoginItem.test.ts --reporter=dot
- Result: 5 test files passed, 61 tests passed.
- npm test -- tunControllerConfig.test.ts --reporter=dot
- Result after runtime hotfix: 1 test file passed, 44 tests passed.
- npm run build
- Result: passed.

Windows-only gap:
- Real Windows smoke should stop a live TUN and verify DNS/firewall rollback completes before UI settles on stopped; verify Boot Recovery task is present once after startup and not recreated on ordinary settings saves.
- Smart-RU live self-test depends on RU echo pages being reachable from the user's network; if both pages are blocked it will still return partial.
```

```text
2026-07-02 - HIGH RE-REVIEW BATCH 3 DONE
Files:
- vpn-tunnel-enforcer/src/preload/index.ts
- vpn-tunnel-enforcer/src/preload/preloadValidation.test.ts
- vpn-tunnel-enforcer/src/main/index.ts
- vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.ts
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.test.ts

Items:
- U1 DONE: preload wrappers with renderer-controlled arguments now validate type/shape/enum/size before ipcRenderer.invoke; oversized VPN/subscription payloads are capped at 256 KiB.
- U2 DONE: main-side inspect-vpn-input rejects non-string and oversized input before resolveVpnProfiles/settingsStore.save, preventing disk bloat even if preload is bypassed.
- U3 DONE: tun:kill-stale-singbox uses top-level execFile(taskkill, argv) instead of dynamic child_process/promisify imports and shell command strings.
- S1 DONE+: elevatedPsHelper policy now rejects cross-policy payloads such as physical-adapter token + netsh advfirewall reset, firewall token + HKLM Run persistence, cmd invocation, and route table mutation.

Verification:
- npm test -- preloadValidation.test.ts mainIpcRegression.test.ts elevatedPsHelper.test.ts vpnProfilesRegression.test.ts serverPickerPingPoisoning.test.ts --reporter=dot
- Result: 5 test files passed, 22 tests passed.
- npm run build
- Result: passed.

Windows-only gap:
- Real Windows smoke should click the maintenance stale-process cleanup and confirm taskkill argv execution succeeds without shell quoting regressions.
- Preload validation is covered by unit tests; a renderer smoke should still exercise common flows (settings save, server add, split tunnel rule, DNS edit) to catch any too-strict validator in daily use.
```

```text
2026-07-02 - MEDIUM RE-REVIEW NETWORKING/UI BATCH 4 DONE
Files:
- vpn-tunnel-enforcer/src/main/tunController.ts
- vpn-tunnel-enforcer/src/main/tunControllerRecoverySource.test.ts
- vpn-tunnel-enforcer/src/main/systemNetwork.ts
- vpn-tunnel-enforcer/src/main/systemNetwork.test.ts
- vpn-tunnel-enforcer/src/main/granularKillSwitch.ts
- vpn-tunnel-enforcer/src/main/granularKillSwitch.test.ts
- vpn-tunnel-enforcer/src/main/splitTunneling.ts
- vpn-tunnel-enforcer/src/main/splitTunneling.test.ts
- vpn-tunnel-enforcer/src/main/splitTunnelProcess.test.ts

Items:
- N4/N5 DONE: WSAEACCES startup retry now uses the shared restartTimer and checks userInitiatedStop/stopInProgress before retrying; post-trial failover captures a stop-cancel generation and exits before health promotion/restart after Stop.
- N6 DONE: localProxy no longer starts prepareRuntime before validateProxyFullTunnel passes; runtime files are prepared only after validation.
- N10 DONE: systemNetwork baseline apply/rollback/auto-rollback now run through one module-level queue; manifest temp writes use unique temp paths.
- N15 VERIFIED: granularKillSwitch.setLevel already awaits firewall installation and rolls back store/settings on install failure.
- N16 DONE: granular kill-switch notification target now prefers the focused non-destroyed window instead of BrowserWindow.getAllWindows()[0].
- N18 DONE: split-tunnel registry discovery string-casts DisplayName/Path before JSON output.
- N19 DONE: split-tunnel store mutations for setRule/addApp/addProcessName/removeApp are serialized through one write queue.
- N20 DONE: split-tunnel route generation no longer emits redundant vpn->proxy-out rules; vpn/none follow the default proxy-out route.
- S7 VERIFIED: firewallKillSwitch already requires all core allow rules before DefaultOutboundAction=Block, so partial "any rule exists" success is not present.

Verification:
- npm test -- tunControllerRecoverySource.test.ts splitTunneling.test.ts splitTunnelProcess.test.ts systemNetwork.test.ts granularKillSwitch.test.ts granularKillSwitchInit.test.ts --reporter=dot
- Result: 6 test files passed, 26 tests passed.
- npm test -- splitTunnelProcess.test.ts splitTunneling.test.ts --reporter=dot
- Result: 2 test files passed, 16 tests passed.
- npm run build
- Result: passed.

Windows-only gap:
- Real Windows smoke should trigger a WSAEACCES/startup retry if possible, press Stop while retry/failover is pending, and verify no delayed reconnect happens.
- Real Windows smoke should apply/rollback the system-network baseline around an active TUN session and confirm DNS/proxy state remains consistent.

Notes:
- The failover source-level regression test intentionally checks cancellation invariants because fully exercising sing-box crash recovery requires a real Windows runtime.
- splitTunneling.addProcessName is now async; IPC already awaited it and tests were updated.
```

```text
2026-07-02 - MEDIUM RE-REVIEW UI/IPC BATCH 5 DONE
Files:
- vpn-tunnel-enforcer/src/main/index.ts
- vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts
- vpn-tunnel-enforcer/src/main/tray.ts
- vpn-tunnel-enforcer/src/main/traySource.test.ts
- vpn-tunnel-enforcer/src/main/notifications.ts
- vpn-tunnel-enforcer/src/main/notificationsReset.test.ts
- vpn-tunnel-enforcer/src/main/trafficMonitor.ts
- vpn-tunnel-enforcer/src/main/trafficMonitor.test.ts
- vpn-tunnel-enforcer/src/renderer/App.tsx
- vpn-tunnel-enforcer/src/renderer/AppSource.test.ts
- vpn-tunnel-enforcer/src/renderer/store.ts
- vpn-tunnel-enforcer/src/renderer/store.connectionBusy.test.ts

Items:
- U-medium save-settings DONE: main-side save-settings now requires a plain object payload before settingsStore.save, covering bypasses around preload validation.
- U-medium tray DONE: tray active-state now treats firewallKillSwitchActive and killswitch status as active protection, so "Enable protection" is not available while firewall rules are blocking.
- U-medium notifications DONE: resetWindowsNotificationBlock now deletes only blocked Enabled=0 values and preserves Enabled=1/current AUMID allow-state; it no longer uses /va.
- U-medium App restarting DONE: renderer applies restartingProgress before busy clear and store refuses to clear connectionBusy while auto-restart progress is active.
- U-medium detectHapp DONE: periodic Happ re-detection now has exponential backoff on detector errors and resets the backoff after a successful detect call.
- U-medium store toasts DONE: global toasts are capped at 20 and timers are tracked/cleared when a toast is dismissed or displaced.
- U-medium trafficMonitor DONE: non-Windows dev fallback publishes running=false/adapterFound=false instead of a misleading running=true no-adapter state.
- U-medium externalProxyList DONE: preload/API typings now accept an optional country filter and pass it to `external-proxy:list`; main already supported this argument.
- U-medium before-quit cleanup VERIFIED: `performShutdownCleanup()` is guarded by `shutdownInProgress`, and `before-quit` prevents re-entry while cleanup is already running.

Verification:
- npm test -- mainIpcRegression.test.ts traySource.test.ts notificationsReset.test.ts notificationsGating.test.ts trafficMonitor.test.ts store.connectionBusy.test.ts AppSource.test.ts --reporter=dot
- Result: 7 test files passed, 24 tests passed.
- npm test -- preloadValidation.test.ts --reporter=dot
- Result: 1 test file passed, 5 tests passed.
- npm run build
- Result: passed.

Windows-only gap:
- Real Windows smoke should open the tray while kill-switch is active and verify only "Disable protection" is actionable.
- Real Windows smoke should block/unblock notifications in Windows Settings and confirm reset clears only explicit blocks.

Notes:
- Source-level regression tests are used for Electron tray/App ordering where full runtime UI automation would be heavier than the bug surface.
```

```text
2026-07-02 - MEDIUM RE-REVIEW SECURITY BATCH 6 DONE
Files:
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.ts
- vpn-tunnel-enforcer/src/main/elevatedPsHelper.test.ts

Items:
- S2 DONE: elevated PS helper policy now rejects PowerShell call/chaining operators (`&`, `&&`, `||`) and pipes into external interpreters (`cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`) before helper execution.
- S2 SAFE PIPELINE VERIFIED: native PowerShell pipelines such as `Get-NetFirewallRule | Remove-NetFirewallRule` remain allowed for the firewall policy.

Verification:
- npm test -- elevatedPsHelper.test.ts --reporter=dot
- Result: 1 test file passed, 7 tests passed.
- npm run build
- Result: passed.

Windows-only gap:
- Real Windows smoke should verify persistent helper still accepts real firewall and physical-adapter scripts after the additional operator guard.

Notes:
- The guard intentionally does not block all `|` usage because the app's allowed elevated scripts legitimately use PowerShell pipelines.
```

```text
2026-07-04 - DNS RUNTIME HOTFIX DONE
Files:
- vpn-tunnel-enforcer/src/main/tunController.ts
- vpn-tunnel-enforcer/src/main/tunControllerConfig.test.ts
- vpn-tunnel-enforcer/src/main/systemNetwork.ts
- vpn-tunnel-enforcer/src/main/systemNetwork.test.ts
- vpn-tunnel-enforcer/src/main/locationPrivacy.ts

Items:
- DNS-H1 DONE: sing-box DNS now sets `dns.final = dns-remote`, so normal hijacked app DNS cannot silently use the first bootstrap resolver. This fixes the likely recursion path where bootstrap/local DNS hit the TUN resolver `192.168.250.254` and timed out.
- DNS-H2 DONE: remote bootstrap resolvers no longer use `type: local` and no longer detour to `direct-out`; they are direct UDP DNS servers with no detour. This avoids both sing-box 1.13's `detour to an empty direct outbound makes no sense` fatal and the local-resolver recursion under adapter DNS pinning.
- DNS-H3 DONE: default remote DNS no longer depends on UDP/XUDP through VLESS/Reality. No-profile fallback is DoH over HTTPS/443 through `proxy-out`; user plain DNS profiles are sent as TCP/53 through `proxy-out`; user DoH/DoT profiles preserve host/path/port/SNI.
- PROGDATA-H1 DONE: ProgramData backup paths now catch Electron `app.getPath('programData')` failures and fall back to `%ProgramData%` / `C:\ProgramData`, restoring baseline/diagnostics/export paths on Electron builds that throw for `programData`.
- DPI-1 STILL FUTURE: ByeDPI/zapret/WinDivert-style packet desync is intentionally not implemented in this hotfix. Current work only uses built-in sing-box/VLESS DNS and transport-shape changes.

Verification:
- npm test -- tunControllerConfig.test.ts systemNetwork.test.ts --reporter=dot
- Result: 2 test files passed, 50 tests passed.
- npm run build
- Result: passed.
- resources/sing-box.exe check -c %TEMP%/vpnte-dns-check.json
- Result: passed for representative VLESS Reality + DoH `dns-remote` + direct UDP bootstrap + `dns.final=dns-remote` config.

Windows-only gap:
- Real Windows smoke still needs to start Direct VPN, verify `Resolve-DnsName example.com -Server 192.168.250.254` succeeds, verify public IP remains VPN, export diagnostics ZIP, and stop TUN to confirm DNS/firewall/baseline rollback.

Notes:
- This is a targeted DNS/runtime recovery patch, not a broad security-hardening batch.
- If a specific server still has DNS failures after this, the next investigation should compare DoH/TCP/DoT per-profile at runtime rather than reverting the whole audit series.
```

```text
2026-07-04 - UI SERVER/SPLIT-TUNNEL POLISH DONE
Files:
- vpn-tunnel-enforcer/src/renderer/pages/Servers.tsx
- vpn-tunnel-enforcer/src/renderer/pages/SplitTunnel.tsx

Items:
- UI-SRV-1 DONE: server selection now has an explicit in-row switching state. The target row animates, shows a pulsing "switching" badge and spinner, and other select buttons are locked until the IPC completes to avoid jitter/double-click races.
- UI-APP-1 DONE: split-tunnel app rules now render as a single table-like list with visible "Application" and "Route" columns instead of separated cards.
- UI-APP-2 DONE: per-app route selection is now a segmented control with pending state/spinner for the row being applied.

Verification:
- npm run build
- Result: passed.

Windows-only gap:
- Real UI smoke still should click several servers and split-tunnel app rules in the packaged app to confirm the motion feels smooth with real IPC latency.

Notes:
- No TUN/firewall/DNS runtime behavior changed in this UI pass.
```

```text
2026-07-04 - LOG CLEAR PERSISTENCE FIX DONE
Files:
- vpn-tunnel-enforcer/src/main/appLogger.ts
- vpn-tunnel-enforcer/src/main/connectionHistory.ts
- vpn-tunnel-enforcer/src/preload/index.ts
- vpn-tunnel-enforcer/src/renderer/App.tsx
- vpn-tunnel-enforcer/src/renderer/pages/Logs.tsx

Items:
- LOG-H1 DONE: the Logs page clear button now clears the persistent connection-history electron-store, not only the visible UI state / app.log file.
- LOG-H2 DONE: app log cleanup now also clears previous rotated app log and sing-box log files, so raw logs do not come back from leftover files after reinstall/restart.
- LOG-H3 DONE: preload exposes `connectionHistoryClear`, and renderer types know about it.

Verification:
- npm test -- connectionHistory.test.ts --reporter=dot
- Result: 1 test file passed, 30 tests passed.
- npm run build
- Result: passed.

Windows-only gap:
- Real packaged-app smoke should click Logs -> Clear, reopen the app/reinstall over it, and confirm connection history/raw logs do not reappear except for new startup log lines.

Notes:
- `sing-box.json` is intentionally not deleted by log clearing because it is runtime config, not a log file.
```

```text
2026-07-04 - TRAFFIC CATEGORY DETECTION IMPROVED
Files:
- vpn-tunnel-enforcer/src/renderer/trafficCategory.ts
- vpn-tunnel-enforcer/src/renderer/trafficCategory.test.ts
- vpn-tunnel-enforcer/src/renderer/pages/TrafficHistory.tsx

Items:
- TRAFFIC-CAT-1 DONE: traffic category detection moved out of `TrafficHistory.tsx` into a dedicated tested module.
- TRAFFIC-CAT-2 DONE: domains are normalized before classification, including URLs, ports, wildcards, trailing dots, and common multi-label public suffixes like `co.uk`.
- TRAFFIC-CAT-3 DONE: classification no longer treats every `api.*` host as Development/AI. Known providers are matched by exact/base domain instead.
- TRAFFIC-CAT-4 DONE: added higher-quality categories inspired by current public datasets: ads/RTB, analytics/tracking, telemetry, messengers, social, streaming/media, dev/AI, cloud/CDN, system updates, mail, payments, auth/SSO, marketplaces, and suspicious/threat keywords.
- TRAFFIC-CAT-5 DONE: rule order now prefers product/security meaning before generic infrastructure, e.g. `cloudflareinsights.com` is analytics/tracking, while `cloudflare.com` remains cloud/CDN; `cdn.discordapp.com` remains messenger, not CDN.

Verification:
- npm test -- trafficCategory.test.ts --reporter=dot
- Result: 1 test file passed, 7 tests passed.
- npm run build
- Result: passed.

Research:
- Used Tavily search/extract (not tavily_research).
- DuckDuckGo Tracker Radar confirmed useful category families such as Analytics, CDN, Advertising, Ad Motivated Tracking, Session Replay, SSO, Fraud Prevention, Social Network, Malware.
- Public Suffix List docs confirmed why site grouping needs public-suffix/eTLD-style handling.
- HaGeZi DNS blocklists confirmed modern DNS filtering categories: ads, tracking, analytics, metrics, telemetry, phishing, malware, scam, cryptojacking.

Windows-only gap:
- Real packaged-app smoke should open Traffic History on real captured traffic and sanity-check category badges against known domains.

Notes:
- This is offline deterministic classification, not a cloud lookup. It avoids runtime API/privacy dependencies.
```

```text
2026-07-04 - DIAGNOSTICS ZIP REGRESSION PASS DONE
Source:
- C:\Users\Redmi\Downloads\vpn-tunnel-enforcer-diagnostics-2026-07-04T11-43-24-877Z.zip

Files:
- vpn-tunnel-enforcer/src/renderer/pages/Servers.tsx
- vpn-tunnel-enforcer/src/main/leakSelfTest.ts
- vpn-tunnel-enforcer/src/main/leakSelfTest.test.ts
- vpn-tunnel-enforcer/src/main/trafficForensicsSummary.ts
- vpn-tunnel-enforcer/src/main/trafficForensics.test.ts
- vpn-tunnel-enforcer/src/renderer/store.ts
- vpn-tunnel-enforcer/src/renderer/pages/Dashboard.tsx
- vpn-tunnel-enforcer/src/renderer/components/ProfileSelectorInline.tsx
- vpn-tunnel-enforcer/src/renderer/components/DashboardSide.tsx

Items:
- ZIP-R1 DONE: fixed Servers page runtime crash from `GroupCard` using `switchingId` without receiving it as a prop.
- ZIP-R2 DONE: traffic-forensics now reads runtime TUN `interface_name` from `<userData>/tun-runtime/sing-box.json`, so a TUN named `Ethernet 5` is not misclassified as a physical Ethernet adapter.
- ZIP-R3 DONE: leak self-test no longer raises a red DNS leak solely because Cloudflare trace IP differs from `api.ipify.org`; that mismatch is now diagnostic detail unless a physical adapter actually reaches the internet.
- ZIP-R4 DONE: central Dashboard power circle now has a separate animated "server switching" state when a live Direct VPN server is changed from the inline selector or right-side quick picker.

Verification:
- npm test -- leakSelfTest.test.ts trafficForensics.test.ts Servers.test.ts trafficCategory.test.ts --reporter=dot
- Result: 4 test files passed, 32 tests passed.
- npm run build
- Result: passed.

Windows-only gap:
- Need live packaged smoke: start Direct VPN, switch active server from Dashboard selector/right picker, confirm central circle shows switching animation and that post-switch public IP/DNS check is stable.

Notes:
- The ZIP showed sing-box DNS hijack working and `runtime-sing-box.json` using `interface_name: Ethernet 5`; the previous forensic heuristic treated the name `Ethernet` as physical and produced a false DNS leak verdict.
```

```text
2026-07-04 - SERVER SWITCH FALSE LEAK/BANNER FIX DONE
Source:
- C:\Users\Redmi\Downloads\vpn-tunnel-enforcer-diagnostics-2026-07-04T12-08-09-597Z.zip
- Screenshot: C:\Users\Redmi\AppData\Local\Temp\codex-clipboard-063756a0-19e2-4ae7-8831-1f9f92289afd.png

Files:
- vpn-tunnel-enforcer/src/main/serverPicker.ts
- vpn-tunnel-enforcer/src/main/serverPickerSource.test.ts
- vpn-tunnel-enforcer/src/renderer/App.tsx
- vpn-tunnel-enforcer/src/renderer/AppSource.test.ts
- vpn-tunnel-enforcer/src/renderer/pages/Dashboard.tsx

Items:
- SW-IP-1 DONE: after a live Direct VPN profile switch, `serverPicker` resumes `ipMonitor` and rebaselines the fresh public IP after `tunController.start()` succeeds, so the new VPN server IP is not compared against the old VPN IP as a leak.
- SW-UI-1 DONE: renderer suppresses stale leak/self-test events while `serverSwitchingName` is active.
- SW-UI-2 DONE: transient `stopped` status during internal server switch no longer resets connection state, flips Hard mode off, or logs the user-facing "protection disabled" path.
- SW-UI-3 DONE: Dashboard hides leak/firewall banners during the explicit server-switch transition.

Verification:
- npm test -- AppSource.test.ts serverPickerSource.test.ts leakSelfTest.test.ts trafficForensics.test.ts Servers.test.ts trafficCategory.test.ts --reporter=dot
- Result: 6 test files passed, 36 tests passed.
- npm run build
- Result: passed.
- npm run dist:win
- Result: passed; installer rebuilt at `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe` (117452957 bytes, 2026-07-04 15:24:14 local time).

Windows-only gap:
- Need live packaged smoke: connect Direct VPN, switch from `polandvless3` to `poland2`, confirm no red "uteka" chip/banner for the selected server IP and no firewall-blocked banner during the switch.

Notes:
- Root cause: hot switch uses stop/start internally; before this patch the IP monitor baseline stayed on the old VPN IP, so the new VPN IP could be marked as `isLeak=true`.
```

```text
2026-07-04 - DIRECT VPN ENDPOINT ROUTE FIX DONE
Source:
- Runtime error shown by user: `vpnte-sing-box.exe run -c ... sing-box.json`
- Runtime log: C:\Users\Redmi\AppData\Roaming\vpn-tunnel-enforcer\tun-runtime\sing-box.log

Files:
- vpn-tunnel-enforcer/src/main/tunController.ts
- vpn-tunnel-enforcer/src/main/tunControllerConfig.test.ts

Items:
- ROUTE-ENDPOINT-1 DONE: Direct VPN configs now add the IPv4 server endpoint itself to TUN `route_exclude_address` as `/32`.
- ROUTE-ENDPOINT-2 DONE: hostnames are not blindly added to `route_exclude_address`; only concrete IPv4 endpoints are excluded.

Verification:
- Runtime `sing-box.log` showed `dial tcp 91.224.75.185:443: no route to internet`, while `sing-box check -c` on the original config passed, proving this was route reachability, not JSON/schema syntax.
- npm test -- tunControllerConfig.test.ts --reporter=dot
- Result: 1 test file passed, 47 tests passed.
- npm run build
- Result: passed.
- `vpnte-sing-box.exe check -c` against a temp no-BOM copy of the live config plus `91.224.75.185/32`
- Result: passed with exit code 0.
- npm run dist:win
- Result: passed; installer rebuilt at `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe` (117453107 bytes, 2026-07-04 17:43:58 local time).

Windows-only gap:
- Need live packaged smoke after installing rebuilt EXE: start Direct VPN on `poland2` / `91.224.75.185`, confirm `sing-box.log` no longer reports `no route to internet` for the VPN endpoint and that public IP resolves through the selected server.

Notes:
- Root cause: full-tunnel routes (`0.0.0.0/1`, `128.0.0.0/1`) captured the connection to the VPN server itself. The underlay TCP connection to the VPN endpoint must stay outside the TUN; all normal app traffic still uses `proxy-out`.
```

## Update Template

When finishing a point, update its row and append a short note here:

```text
2026-07-04 - MAINTENANCE REPAIR AUDIT/FIX PASS DONE
Source:
- User request: audit and improve "Починка" functions, verify fake/legacy items, mandatory Tavily 2026 research.
- Subagents: repair map, repair quality audit, Tavily best-practices research.

Files:
- vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts
- vpn-tunnel-enforcer/src/main/tunController.ts
- vpn-tunnel-enforcer/src/main/index.ts
- vpn-tunnel-enforcer/src/main/systemDiagnostics.ts
- vpn-tunnel-enforcer/src/main/systemDiagnostics.test.ts
- vpn-tunnel-enforcer/src/main/systemNetwork.ts
- vpn-tunnel-enforcer/src/main/systemNetwork.test.ts
- vpn-tunnel-enforcer/src/main/physicalAdapterLockdown.ts
- vpn-tunnel-enforcer/src/main/diagnosticsExport.ts
- vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts
- vpn-tunnel-enforcer/src/preload/index.ts
- vpn-tunnel-enforcer/src/preload/preloadValidation.test.ts
- vpn-tunnel-enforcer/src/renderer/App.tsx
- vpn-tunnel-enforcer/src/renderer/store.ts
- vpn-tunnel-enforcer/src/renderer/pages/Logs.tsx
- vpn-tunnel-enforcer/src/renderer/pages/Maintenance.tsx
- vpn-tunnel-enforcer/src/renderer/MaintenanceSource.test.ts
- deleted: vpn-tunnel-enforcer/src/main/storeDiagnostics.ts
- deleted: vpn-tunnel-enforcer/src/main/storeRepair.ts

Items:
- REPAIR-FW-1 DONE: full Windows Firewall reset now exports a `.wfw` backup before `netsh advfirewall reset` and reports the backup path.
- REPAIR-FW-2 DONE: Maintenance UI now labels full firewall reset as an emergency action and warns that it deletes all Windows Firewall rules, not only VPNTE rules.
- REPAIR-FW-3 DONE: full Windows Firewall reset now requires a main-side confirmation token; renderer `confirm()` is no longer the only guard.
- REPAIR-FW-4 DONE: normal Maintenance auto-repair uses targeted `repairVpnteFirewallRules()` and does not call `netsh advfirewall reset`.
- REPAIR-PROC-1 DONE: stale runtime kill now terminates only VPNTE-owned binaries whose executable path is inside the app `tun-runtime`.
- REPAIR-PROC-2 DONE: stale runtime cleanup reports PowerShell/process-query failure as `success:false` instead of pretending "0 killed"; owned-runtime wait now checks executable path, not only process name.
- REPAIR-DNS-1 DONE: physical adapter lockdown manifest records DNS source (`dhcp/static/unknown`) and rollback avoids turning DHCP-provided DNS into a static override.
- REPAIR-DNS-2 DONE: orphaned DNS repair without manifest only resets explicit manual VPNTE DNS, reducing accidental DHCP/static damage.
- REPAIR-NET-1 DONE: TUN network baseline rollback is idempotent; missing manifest is a skipped no-op, not an auto-repair failure.
- REPAIR-LOGS-1 DONE: Logs clear now also clears traffic history, snapshots and traffic-forensics artifacts through a dedicated IPC.
- REPAIR-ZIP-1 DONE: diagnostics ZIP now includes a clean README and `diagnostics-manifest.json` with version/runtime/redaction metadata.
- REPAIR-ZIP-2 DONE: diagnostics ZIP/health-check active path no longer includes Microsoft Store repair diagnostics or Store category noise.
- REPAIR-UI-1 DONE: Microsoft Store repair block, preload IPC, main IPC, renderer store state, and legacy implementation files were removed from the active app.
- REPAIR-UI-2 DONE: Maintenance visible summary is based only on visible VPN/network categories, so hidden/non-VPN checks cannot turn the screen warn/fail.
- REPAIR-UI-3 DONE: Maintenance now has three primary actions (`Проверить`, `Починить`, `ZIP`) plus one clearly separated emergency firewall reset.
- REPAIR-UI-4 DONE: Maintenance firewall health and auto-repair step results now live in global renderer store, so leaving and returning to the tab does not wipe the repair result view.
- REPAIR-TRACE-1 NOFIX: `pktmon`, `netsh trace`, and WFP capture are already implemented in `trafficForensics` and staged into diagnostics ZIP; Tavily/Microsoft docs confirm these are current diagnostics tools, not repair buttons.
- REPAIR-CRASH-1 NOFIX: Crashpad is not advertised in the repaired Maintenance/ZIP flow; local search found no `crashReporter`/Crashpad implementation, so no fake crash-dump promise remains in this pass.

Verification:
- Tavily sources reviewed: Microsoft netsh winhttp, Set-DnsClientServerAddress, Windows Firewall command-line docs, netsh advfirewall/WFP, taskkill, Electron diagnostics/security docs.
- Tavily 2026/current-source conclusion: targeted PowerShell firewall/DNS rollback is appropriate for repair; `pktmon`/`netsh trace`/`netsh wfp` belong to diagnostics; `netsh advfirewall reset` remains emergency-only.
- Subagent review findings addressed: idempotent baseline rollback, hidden Store warning, destructive `apply-tun-network-baseline` renderer IPC removal, main-side reset token, Store deletion from active diagnostics, runtime cleanup error semantics.
- PowerShell syntax smoke for snapshot DNS source subexpression passed.
- npm test -- diagnosticsPreflight.test.ts firewallKillSwitchValidation.test.ts tunControllerConfig.test.ts --reporter=dot
- Result: 3 test files passed, 65 tests passed.
- npm test -- appLoggerRotation.test.ts mainIpcRegression.test.ts --reporter=dot
- Result: 2 test files passed, 5 tests passed.
- npm test -- MaintenanceSource.test.ts preloadValidation.test.ts mainIpcRegression.test.ts ipcChannelContract.test.ts systemNetwork.test.ts systemDiagnostics.test.ts diagnosticsPreflight.test.ts firewallKillSwitchValidation.test.ts tunControllerConfig.test.ts -- --reporter=dot
- Result: 9 test files passed, 94 tests passed.
- npm test -- MaintenanceSource.test.ts store.connectionBusy.test.ts preloadValidation.test.ts mainIpcRegression.test.ts systemDiagnostics.test.ts -- --reporter=dot
- Result: 5 test files passed, 29 tests passed.
- npm test -- --reporter=dot
- Result: 60 test files passed, 497 tests passed.
- npm run build
- Result: passed.
- npm run dist:win
- Result: passed; installer rebuilt at `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe` (117450296 bytes, 2026-07-04 18:51:23 local time).
- Get-AuthenticodeSignature on installer and unpacked app
- Result: `NotSigned`; no real Authenticode publisher certificate is present in this environment.

Windows-only gap:
- Need live packaged smoke: Maintenance -> clear logs, export ZIP, emergency firewall backup path creation, manual orphaned DNS repair no-op/success on a real adapter, stale runtime kill while a VPNTE runtime process is present.
- Need live packaged smoke: start Direct VPN, run Maintenance health-check/auto-repair in a clean state, confirm missing baseline manifest is shown as skipped/no-op rather than failure.

Notes:
- Full firewall reset remains available by design, but is last resort with backup and a main-side confirmation token. The normal repair path is diagnostics, targeted VPNTE firewall cleanup, network-baseline rollback, DNS/adapter rollback, and owned runtime cleanup.
- Store repair was removed as irrelevant to the VPN app repair surface. If Store support is ever needed, it should return as a separate explicit feature, not under VPN Maintenance.
```

## Current Remaining Verification Matrix

As of 2026-07-04, there are no active `TODO`, `PARTIAL`, or `VERIFY` audit rows left in this tracker outside the status legend and historical notes. The remaining work is live packaged Windows smoke verification, not unimplemented source-code items.

Source-level evidence already rechecked after the Maintenance/repair pass:
- `rg "storeRepair|storeDiagnostics|maintenanceStore|runStore" vpn-tunnel-enforcer/src` returns only regression tests that assert legacy Store repair is absent.
- `rg "apply-tun-network-baseline" vpn-tunnel-enforcer/src` returns only the regression test that asserts the destructive renderer IPC is absent.
- Targeted Maintenance tests assert targeted firewall repair appears before emergency full reset, the reset passes `RESET_WINDOWS_FIREWALL_CONFIRMED`, and repair UI state survives tab switches.
- Fresh tracker-audit regression check: `npm test -- LogsSource.test.ts diagnosticsPreflight.test.ts MaintenanceSource.test.ts preloadValidation.test.ts mainIpcRegression.test.ts systemDiagnostics.test.ts -- --reporter=dot` passed with 6 files / 33 tests.
- ZIP README/manifest presence is now pinned by `diagnosticsPreflight.test.ts`: `diagnostics-manifest.json` and clean `README.txt` must be staged before `Compress-Archive`, with redaction metadata present.
- Logs clear persistence is now pinned by `LogsSource.test.ts`: the visible clear action must clear app logs, connection history, traffic history, diagnostic artifacts, and renderer state together.
- Latest full suite: `npm test -- --reporter=dot` passed with 61 files / 499 tests.
- Latest packaged build: `npm run dist:win` passed and rebuilt `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.

2026-07-05 - RUNTIME-DIAG-STOP-WATCHDOG-MAINT DONE
Files:
- `vpn-tunnel-enforcer/src/main/tunController.ts`
- `vpn-tunnel-enforcer/src/main/index.ts`
- `vpn-tunnel-enforcer/src/preload/index.ts`
- `vpn-tunnel-enforcer/src/renderer/App.tsx`
- `vpn-tunnel-enforcer/src/renderer/pages/Dashboard.tsx`
- `vpn-tunnel-enforcer/src/main/tunControllerRecoverySource.test.ts`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
Fixes:
- Diagnostics ZIPs `vpn-tunnel-enforcer-diagnostics-2026-07-05T09-25-21-556Z.zip` and `vpn-tunnel-enforcer-diagnostics-2026-07-05T09-28-20-595Z.zip` showed `TUN stopped` followed by renderer `Не удалось выключить защиту: runtime process stop: vpnte-sing-box.exe is still running`; `tunController.stop()` now publishes final `stopped` and returns `success: true` with `warning` when the runtime is already stopped but cleanup has warnings.
- Direct VPN server watchdog now suppresses false `proxy-down` if `ipMonitor` recently confirmed public VPN egress, matching the ZIP sequence where public IP checks were succeeding while the UI showed `Сервер не отвечает`.
- Maintenance stale-runtime cleanup now uses the actual local `psSingleQuote` helper instead of undefined `psSingleQuote`/old `psQuote` mismatch.
- Targeted Maintenance firewall repair refuses to disable VPNTE firewall rules while TUN is running; health-check remains available, but repair requires VPN off.
Verification:
- `npm test -- tunControllerRecoverySource.test.ts mainIpcRegression.test.ts AppSource.test.ts -- --reporter=dot` passed: 3 files / 15 tests.
- `npm test -- --reporter=dot` passed: 61 files / 503 tests.
- `npm run build` passed.
- `git diff --check` passed.
- `npm run dist:win` passed; installer rebuilt at `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe` (117450488 bytes, 2026-07-05 16:54:25 local time).
- `Get-AuthenticodeSignature` on the rebuilt installer: `NotSigned`; no real Authenticode publisher certificate is available in this environment.
- Codebase index refreshed with `index_repository(mode=fast, persistence=true)`.
Windows-only gap:
- Needs live packaged smoke for Direct VPN watchdog recovery, Stop UI state after runtime cleanup warnings, and Maintenance repair behavior while TUN is active.

2026-07-05 - RUNTIME-DIAG-MAINT-ZIP-2 DONE
Files:
- `vpn-tunnel-enforcer/src/main/index.ts`
- `vpn-tunnel-enforcer/src/renderer/pages/Maintenance.tsx`
- `vpn-tunnel-enforcer/src/main/diagnosticsExport.ts`
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
- `vpn-tunnel-enforcer/src/renderer/MaintenanceSource.test.ts`
- `vpn-tunnel-enforcer/src/main/diagnosticsPreflight.test.ts`
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`
Findings from fresh post-reinstall ZIP:
- `vpn-tunnel-enforcer-diagnostics-2026-07-05T14-00-56-621Z.zip` was created by the rebuilt app, but its diagnostics bundle still included older `snapshots` from `2026-07-05T08:41Z..09:28Z` and traffic-forensics sessions from `2026-06-20/21`; this was an export/staging bug, not a user mistake.
- Maintenance auto-repair was run while TUN was active. Firewall repair skipped safely, but the runtime cleanup step still killed the live `vpnte-sing-box.exe`, causing a crash and auto-restart.
Fixes:
- `tun:kill-stale-singbox` now refuses to kill runtime while TUN is running and returns a skipped/no-op result.
- `firewall:repair-vpnte-rules` active-TUN guard now returns skipped success instead of a hard failure.
- Maintenance renderer maps skipped/no-op repair results to warning instead of error.
- Diagnostics ZIP now exports a bounded recent snapshot set instead of every historical snapshot in `userData`.
- Traffic-forensics staging now exports only the latest/current session and skips stale historical sessions when deep traffic inspection is disabled.
Verification:
- `npm test -- mainIpcRegression.test.ts MaintenanceSource.test.ts diagnosticsPreflight.test.ts trafficForensics.test.ts -- --reporter=dot` passed: 4 files / 42 tests.
- `npm test -- --reporter=dot` passed: 61 files / 505 tests.
- `npm run build` passed.
- `git diff --check` passed.
Windows-only gap:
- Needs live packaged smoke: run Maintenance auto-repair while Direct VPN is active; firewall/runtime steps should show skipped/warn and must not kill sing-box.
- Needs live packaged smoke: export ZIP after reinstall/start; snapshots should be recent/bounded and old June traffic-forensics sessions should not appear unless they are the current/latest active session.

2026-07-05 - RUNTIME-DIAG-MAINT-ZIP-3 DONE
Files:
- `vpn-tunnel-enforcer/src/main/index.ts`
- `vpn-tunnel-enforcer/src/renderer/pages/Maintenance.tsx`
- `vpn-tunnel-enforcer/src/main/systemDiagnostics.ts`
- `vpn-tunnel-enforcer/src/main/diagnosticsExport.ts`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
- `vpn-tunnel-enforcer/src/renderer/MaintenanceSource.test.ts`
- `vpn-tunnel-enforcer/src/main/systemDiagnostics.test.ts`
- `vpn-tunnel-enforcer/src/main/diagnosticsPreflight.test.ts`
Findings from fresh ZIP/screenshots:
- `vpn-tunnel-enforcer-diagnostics-2026-07-05T14-17-07-690Z.zip` no longer included old June traffic-forensics sessions, but snapshots still included a previous app run inside the 2h recent window.
- Maintenance auto-repair after a clean state displayed clean no-op steps as yellow warnings (`already clean`, `manifest not found`, `changes not needed`).
- Health-check showed `Current proxy: directvpn idle` as WARN even though Direct VPN does not need a local proxy when stopped.
- `sing-box log` treated benign `ERROR ... connection upload closed` lines as health warnings.
Fixes:
- Maintenance now distinguishes blocked actions from clean no-op actions: blocked active-TUN repair remains WARN, clean no-op repair steps become OK.
- Active-TUN firewall/runtime maintenance guard results now include `blocked: true`.
- Direct VPN idle proxy diagnostic is INFO instead of WARN.
- Sing-box log health ignores benign `connection upload closed` noise while preserving real fatal/error/timeout/refused signals.
- Diagnostics ZIP snapshot export now starts at the latest `app-start` snapshot inside the recent window.
Verification:
- `npm test -- mainIpcRegression.test.ts MaintenanceSource.test.ts diagnosticsPreflight.test.ts systemDiagnostics.test.ts -- --reporter=dot` passed: 4 files / 29 tests.
- `npm test -- --reporter=dot` passed: 61 files / 507 tests.
- `npm run build` passed.
- `git diff --check` passed.
Windows-only gap:
- Needs live packaged smoke: after fresh install/start, export ZIP should include snapshots only from the latest app run, and Maintenance clean no-op repair should be green/OK.

Live smoke still needed before the whole goal can honestly be marked complete:
- Safe packaged UI smoke: open Maintenance, switch tabs away/back, verify health/firewall/repair results stay visible.
- Safe packaged UI smoke: clear logs, restart/reinstall, verify connection history, app logs, rotated logs, snapshots, and traffic-forensics artifacts do not repopulate from old files.
- Safe packaged UI smoke: export diagnostics ZIP and verify `README` plus `diagnostics-manifest.json` are included and no Store category/report is present.
- Network runtime smoke: start Direct VPN on a known working profile, switch to another server, verify the center power circle enters the server-switching animation, no false leak banner appears, and no firewall-disabled banner appears during the internal switch.
- Network runtime smoke: after server switch, verify public IP is rebaselined to the new VPN IP and `run-leak-self-test` does not flag Cloudflare/API public-IP mismatch as a DNS leak unless a physical adapter is actually reachable.
- TUN route smoke: verify the selected profile endpoint IPv4 is present as `/32` in `route_exclude_address`, sing-box starts cleanly, and the endpoint no longer falls into `no route to internet`.
- Maintenance runtime smoke: run health-check and auto-repair in a clean state; missing network-baseline manifest should show skipped/no-op, not fail.
- Windows repair smoke requiring care: emergency full firewall reset should create a `.wfw` backup before `netsh advfirewall reset`. This is destructive and must be run only with explicit approval.
- Windows repair smoke requiring care: orphaned DNS repair and adapter lockdown rollback should be tested on a real adapter with known DNS state, confirming DHCP DNS is not converted into static DNS.
- Windows repair smoke requiring care: stale runtime cleanup should kill only VPNTE-owned `tun-runtime` processes and report process-query failures as errors.

Do not mark the thread goal complete until the live smoke items above are either executed successfully on the real Windows environment or explicitly waived by the user.

```text
YYYY-MM-DD - <ID> DONE
Files:
- path
Verification:
- command/result
Windows-only gap:
- if any
Notes:
- short rationale
```

2026-07-05 - RUNTIME-DIAG-MAINT-ZIP-4 DONE
Files:
- `vpn-tunnel-enforcer/src/main/routingSelfTest.ts`
- `vpn-tunnel-enforcer/src/main/systemNetwork.ts`
- `vpn-tunnel-enforcer/src/main/systemDiagnostics.ts`
- `vpn-tunnel-enforcer/src/main/routingSelfTest.test.ts`
- `vpn-tunnel-enforcer/src/main/systemNetwork.test.ts`
- `vpn-tunnel-enforcer/src/main/systemDiagnostics.test.ts`
Findings from fresh ZIP/screenshots:
- `vpn-tunnel-enforcer-diagnostics-2026-07-05T14-27-47-360Z.zip` showed clean stop/rollback/kill-switch disable, but health summary stayed WARN because app-log treated benign `reg delete` misses for optional proxy/env values as real warnings.
- Routing self-test reported an impossible RU host IP (`384.518.844.978`) because IPv4 extraction accepted any `ddd.ddd.ddd.ddd` token from RU echo HTML without validating octet ranges.
Fixes:
- Routing self-test now validates IPv4 octets before accepting an echo result, so impossible HTML/script numbers are ignored and the next endpoint can answer.
- TUN network baseline cleanup now treats missing optional proxy/env registry values as clean debug/no-op instead of warning.
- System diagnostics filters already-recorded benign optional proxy cleanup warnings so old app-log rows do not keep the health panel yellow after update/reinstall.
Verification:
- `npm test -- routingSelfTest.test.ts systemNetwork.test.ts systemDiagnostics.test.ts --reporter=dot` passed: 3 files / 23 tests.
Windows-only gap:
- Needs live packaged smoke: rerun routing self-test with Smart-RU enabled; RU host IP must be valid IPv4 or null/inconclusive, never an impossible octet value.
- Needs live packaged smoke: start/stop Direct VPN and open Maintenance health; missing optional proxy/env registry values must not make `App log` WARN.

2026-07-05 - RUNTIME-TRANSITION-LEAK-FIREWALL-1 DONE
Files:
- `vpn-tunnel-enforcer/src/main/leakSelfTest.ts`
- `vpn-tunnel-enforcer/src/main/index.ts`
- `vpn-tunnel-enforcer/src/main/trafficForensics.ts`
- `vpn-tunnel-enforcer/src/main/leakSelfTest.test.ts`
- `vpn-tunnel-enforcer/src/main/trafficForensics.test.ts`
- `vpn-tunnel-enforcer/src/renderer/App.tsx`
- `vpn-tunnel-enforcer/src/renderer/pages/Dashboard.tsx`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
Findings from fresh ZIP:
- `vpn-tunnel-enforcer-diagnostics-2026-07-05T14-59-53-978Z.zip` is small because old heavy forensic artifacts are no longer staged; it still contains the current app log, system diagnostics, runtime config/logs, settings, README/manifest, and latest-run snapshots.
- One leak warning appeared during Direct VPN startup (`2026-07-05T14:52:22Z`) after a network-change event fired while TUN/firewall/baseline were still settling; later leak checks were OK.
- The short "internet blocked by firewall" banner was a renderer transition flicker: kill-switch state could arrive before the final running/stopped status settled.
- `get-traffic-forensics-status` was still returning an old stopped June session while deep capture was disabled, bloating current IPC logs with stale artifact metadata.
Fixes:
- TUN start now suppresses event/periodic leak self-tests for a short transition window and cancels any in-flight stale leak probe before the tunnel settles.
- Dashboard suppresses the firewall block banner briefly around TUN status handoffs, while still showing real stuck kill-switch states outside that window.
- Disabled traffic forensics no longer surfaces old stopped session manifest/summary/artifact files in live status; old data stays on disk but stops polluting current IPC logs.
Verification:
- `npm test -- leakSelfTest.test.ts AppSource.test.ts trafficForensics.test.ts routingSelfTest.test.ts systemNetwork.test.ts systemDiagnostics.test.ts --reporter=dot` passed: 6 files / 51 tests.
- `npm test -- --reporter=dot` passed: 61 files / 513 tests.
- `npm run build` passed.
- `npm run dist:win` passed and rebuilt `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- `git diff --check` passed.
- Codebase index refreshed with `index_repository(mode=fast, persistence=true)`.
Windows-only gap:
- Needs live packaged smoke: switch Direct VPN servers and verify no transient leak banner and no transient firewall-block banner during the internal stop/start handoff.
- Needs live packaged smoke: export ZIP after the new build and verify `app-log.json` no longer contains repeated huge disabled `get-traffic-forensics-status` payloads for old sessions.

2026-07-05 - REINSTALL-FIREWALL-UI-ANIMATION-1 DONE
Files:
- `vpn-tunnel-enforcer/src/main/index.ts`
- `vpn-tunnel-enforcer/src/main/tunController.ts`
- `vpn-tunnel-enforcer/src/main/leakDiagnostics.ts`
- `vpn-tunnel-enforcer/src/main/leakDiagnostics.test.ts`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
- `vpn-tunnel-enforcer/src/renderer/pages/Servers.tsx`
- `vpn-tunnel-enforcer/src/renderer/pages/SplitTunnel.tsx`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
Findings from screenshot:
- After reinstall, Maintenance/diagnostics can still show `Firewall VPNTE WARN` because Windows firewall rules, DefaultOutboundAction, and the VPNTE manifest live outside the installer payload and can survive uninstall/install.
- Startup crash recovery was kicked off in the background after the renderer/tray were already created, so the UI could show stale firewall state before recovery finished.
- Startup recovery also treated any process named `vpnte-sing-box.exe` as a live protected tunnel. That can preserve stale firewall state after reinstall if a stale/foreign process with the same name exists.
- Routing diagnostics still treated benign sing-box `connection upload closed` / remote-host reset noise as a warning.
- Servers/Apps used expensive framer-motion list layout/height animations (`layout`, `AnimatePresence`, height-to-auto), which is janky on large lists.
Fixes:
- Startup recovery now runs before creating the renderer window/tray.
- Startup firewall/adapter recovery uses `isOwnedTunRuntimeRunning()`, which checks the process executable path under this app's `userData/tun-runtime` instead of trusting `tasklist` by image name.
- The owned-runtime probe no longer falls back to plain image-name `tasklist` on probe failure.
- Routing diagnostics filters benign sing-box upload-close / forcibly-closed lines while preserving real failures.
- Servers group body rendering no longer animates `height: auto`, and server profile cards no longer use framer-motion `layout`.
- Apps/Split Tunneling list rows no longer use framer-motion layout/enter/exit animation.
Verification:
- `npm test -- mainIpcRegression.test.ts leakDiagnostics.test.ts AppSource.test.ts splitTunneling.test.ts --reporter=dot` passed: 4 files / 38 tests.
- `npm test -- --reporter=dot` passed: 61 files / 516 tests.
- `npm run build` passed.
- `npm run dist:win` passed and rebuilt `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- `git diff --check` passed.
- Codebase index refreshed with `index_repository(mode=fast, persistence=true)`.
Windows-only gap:
- Needs live packaged smoke after reinstall: app startup should clear stale VPNTE firewall rules/manifest/DefaultOutboundAction before Maintenance shows results.
- Needs live packaged UI smoke: Servers and Apps lists should no longer visibly fly in or lag during open/filter/select.

2026-07-05 - FIREWALL-ACTIVE-SPLIT-NAMES-SERVER-LOAD-1 DONE
Files:
- `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts`
- `vpn-tunnel-enforcer/src/main/index.ts`
- `vpn-tunnel-enforcer/src/main/splitTunneling.ts`
- `vpn-tunnel-enforcer/src/main/splitTunneling.test.ts`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
- `vpn-tunnel-enforcer/src/renderer/pages/Servers.tsx`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
Findings from screenshots:
- Maintenance still showed `Firewall VPNTE WARN` while VPNTE rules/manifest/stuck outbound policy existed. During an active protected TUN this can be expected firewall state, not stale cleanup debris.
- Split Tunneling app names showed mojibake (`U+FFFD`, CJK/Hangul fragments) from PowerShell/registry display-name encoding and from already persisted broken names.
- Servers first paint waited for both profile data and group metadata, so a slow `groupsList` made the Servers page appear slower than other tabs.
Fixes:
- `firewall:repair-health` now passes active TUN state into `getFirewallRepairHealth`; active VPNTE firewall rules are reported as protecting the tunnel instead of cleanup WARN.
- Targeted firewall repair remains blocked while TUN is active and returns health marked as protected-active.
- Split Tunneling registry discovery now forces UTF-8 PowerShell output.
- Split Tunneling sanitizes registry and stored app display names, removing replacement chars/CJK/Hangul garbage and falling back to stable folder/exe names for fully corrupt names.
- Stored split-tunnel app names are normalized on read, so old corrupted names in `electron-store` are repaired without manual deletion.
- Servers initial page load no longer waits for group metadata; profiles render first and groups load in parallel.
Verification:
- `npm test -- splitTunneling.test.ts mainIpcRegression.test.ts AppSource.test.ts leakDiagnostics.test.ts --reporter=dot` passed: 4 files / 43 tests.
- First full `npm test -- --reporter=dot` hit a transient `appLoggerRotation.test.ts` timing failure; rerunning that file passed: 1 file / 2 tests.
- Second full `npm test -- --reporter=dot` passed: 61 files / 521 tests.
- `npm run build` passed.
- `npm run dist:win` passed and rebuilt `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Installer check: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe` size 117,452,009 bytes, last write 2026-07-05 22:54:56.
- `Get-AuthenticodeSignature` still reports `NotSigned` for the installer despite electron-builder printing signtool steps; real Publisher/UAC identity still requires a valid code-signing certificate.
- `git diff --check` passed with only line-ending warnings.
Windows-only gap:
- Needs live packaged smoke: with Direct VPN active, Maintenance should show firewall state OK/protecting, not cleanup WARN.
- Needs live packaged smoke: Split Tunneling should show cleaned names for Hiddify, WinRAR, YandexMusic, Office/WebView, and should repair existing stored names after opening the Apps tab.
- Needs live packaged UI smoke: Servers should display profiles before slow group metadata finishes and no longer feel delayed on first open.

2026-07-05 - PROXY-LIST-EXPORT-1 DONE
Files:
- `vpn-tunnel-enforcer/src/main/vpnProfiles.ts`
- `vpn-tunnel-enforcer/src/main/serverPicker.ts`
- `vpn-tunnel-enforcer/src/shared/ipc-types.ts`
- `vpn-tunnel-enforcer/src/preload/index.ts`
- `vpn-tunnel-enforcer/src/renderer/pages/Servers.tsx`
- `vpn-tunnel-enforcer/src/main/vpnProfilesProtocolCoverage.test.ts`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
Finding:
- Existing bulk export writes VPN client URI lines (`vless://`, `trojan://`, etc.). Some proxy pool tools instead require plain proxy-list lines like `host:port`, `host:port:user:pass`, or `protocol://user:pass@host:port`, one proxy per line.
- The attached export file contains VLESS Reality profiles; those are not plain HTTP/SOCKS proxy credentials and must not be rewritten into fake `host:port:user:pass` lines.
Fix:
- Added `exportOutboundToProxyLine()` for real plain proxy outbounds only: HTTP, SOCKS/SOCKS4/SOCKS5, mixed, and Naive-as-HTTPS-proxy.
- Added `servers:export-all-proxies-file` IPC and preload API.
- Added a separate Servers page button `Proxy list` so the existing VPN-key export remains unchanged.
- Proxy-list export writes strict one-proxy-per-line output with no header comments for maximum importer compatibility.
- Unsupported VPN protocols are skipped and surfaced via exported/skipped counts; all-VLESS input returns `unsupported-all` rather than creating a misleading file.
Verification:
- `npm test -- vpnProfilesProtocolCoverage.test.ts mainIpcRegression.test.ts AppSource.test.ts --reporter=dot` passed: 3 files / 35 tests.
- `npm test -- --reporter=dot` passed: 61 files / 525 tests.
- `npm run build` passed.
- `npm run dist:win` passed and rebuilt `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Installer check: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe` size 117,452,531 bytes, last write 2026-07-05 23:14:01.
- `Get-AuthenticodeSignature` still reports `NotSigned`; real Publisher/UAC identity still requires a valid code-signing certificate.
- `git diff --check` passed with only line-ending warnings.
Windows-only gap:
- Needs live packaged UI smoke: click Servers -> `Proxy list`; with only VLESS profiles it should show an unsupported/skipped message, while HTTP/SOCKS profiles should produce a plain one-proxy-per-line `.txt`.

2026-07-05 - SERVERS-SELECT-LOADING-POLISH-1 DONE
Files:
- `vpn-tunnel-enforcer/src/renderer/design-system/MacSelect.tsx`
- `vpn-tunnel-enforcer/src/renderer/pages/Servers.tsx`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
Findings from screenshots/diagnostics:
- The add form `Группа` / `Устройство` dropdown was rendered inside the add card with local `absolute z-50`; following server/group cards could paint over it, making the dropdown look clipped or hidden under the list.
- The Servers page had become too abrupt after removing expensive height/layout animations.
- Long key/subscription imports only showed the button spinner; there was no page-level feedback that keys were being loaded/parsed/saved.
- Fresh diagnostics still show Firewall health OK/protecting active tunnel, matching the previous firewall health fix.
Fixes:
- Open `MacSelect` now raises its own stacking context (`z-[200]`) and dropdown menu (`z-[220]`), so `Группа` and `Устройство` stay above the server list.
- Server group body open animation now uses lightweight opacity/translate motion only, avoiding old `layout` and `height: auto` animation costs.
- Add/import form disables input/selects during import and shows an inline indeterminate progress panel: `Загружаем и проверяем ключи...`.
- Initial Servers page loading state now shows spinner + indeterminate progress instead of a static loading label.
Verification:
- `npm test -- AppSource.test.ts --reporter=dot` passed: 1 file / 8 tests.
- `npm test -- --reporter=dot` passed: 61 files / 526 tests.
- `npm run build` passed.
- `npm run dist:win` passed and rebuilt `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Installer check: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe` size 117,453,134 bytes, last write 2026-07-05 23:26:46.
- `Get-AuthenticodeSignature` still reports `NotSigned`; real Publisher/UAC identity still requires a valid code-signing certificate.
- `git diff --check` passed with only line-ending warnings.
Windows-only gap:
- Needs live packaged UI smoke: open `Группа` and `Устройство` dropdowns in Servers add form; both should render above server cards/toolbars.
- Needs live packaged UI smoke: paste a slow subscription/key batch and confirm visible inline progress until import finishes.

2026-07-05 - SERVERS-SELECT-BULK-FEEDBACK-POLISH-2 DONE
Files:
- `vpn-tunnel-enforcer/src/renderer/design-system/MacSelect.tsx`
- `vpn-tunnel-enforcer/src/renderer/pages/Servers.tsx`
- `vpn-tunnel-enforcer/src/renderer/pages/SplitTunnel.tsx`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
Finding:
- Live packaged test showed the portal-based `MacSelect` correction made the add-form dropdowns not open visibly at all.
- Bulk key/proxy export still had no page-level feedback beyond a small button spinner and log entry.
- Servers/Applications lists still felt too jumpy because large lists used transform/layout-style motion and broad `transition-all` effects.
Fix:
- Removed the portal dropdown from `MacSelect` and returned to an inline absolute menu, but now the open select raises its stacking context (`z-[120]`) and the menu uses `z-[130]`.
- Raised the Servers add card itself above the server list (`relative z-30 overflow-visible`) and kept the server-list body at a lower layer.
- Added a visible `bulkNotice` status panel for saving all keys and exporting `Proxy list`, with indeterminate progress during the operation and success/error summaries afterward.
- Removed transform hover from server rows and removed layout/enter/exit motion from large server/app rows; app rule buttons now use `transition-colors` instead of `transition-all`.
Verification:
- `npm test -- AppSource.test.ts --reporter=dot` passed: 1 file / 8 tests.
- `npm run build` passed and produced `out/renderer/assets/MacSelect-DdF9ZPF8.js` with inline dropdown classes, not the app-level portal implementation.
- `rg` verified `absolute z-[130]`, `relative z-30 overflow-visible`, `servers.exportProxyListWorking`, and `transition-colors duration-100` in source/built renderer output.
- `npm test -- --reporter=dot` passed: 61 files / 526 tests.
- `git diff --check` passed with only line-ending warnings.
- `npm run dist:win` passed and rebuilt `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Installer check: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe` size 117,453,752 bytes, last write 2026-07-05 23:53:28.
- `Get-AuthenticodeSignature` still reports `NotSigned`; real Publisher/UAC identity still requires a valid code-signing certificate.
Windows-only gap:
- Needs live packaged UI smoke after installing the rebuilt EXE: open Servers -> Group/Device selects; menus should appear over the server cards instead of disappearing or hiding under the list.
- Needs live packaged UI smoke: click `Сохранить ключи` and `Proxy list`; the page should show a visible progress/result panel.
- Needs live packaged UI smoke: scroll/click Servers and Applications lists; row hover/switching should feel less jumpy.

2026-07-06 - SPLIT-TUNNEL-PATH-MAINTENANCE-LABEL-1 DONE
Files:
- `vpn-tunnel-enforcer/src/renderer/pages/SplitTunnel.tsx`
- `vpn-tunnel-enforcer/src/renderer/pages/Maintenance.tsx`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
Finding:
- Split Tunneling app names were cleaned, but the displayed `path` still surfaced mojibake in corrupted executable/path segments, e.g. `YandexMusic\���� ��Ӝ.exe`.
- Maintenance showed `stuck block: да` even when firewall health was `OK` and the active TUN was protected; technically true for DefaultOutboundAction=Block, but misleading to users.
Fix:
- Added renderer-only `displaySplitTunnelPath()` for Apps: corrupt path segments are cleaned for display and a corrupt executable leaf falls back to a safe app-name leaf such as `YandexMusic.exe`.
- The stored/route `app.path` is not mutated by this UI display fix, avoiding accidental route-rule breakage without verifying the real file on disk.
- Maintenance now uses `block default: активная защита` when `protectedTunnelActive && summary === ok && stuckBlockDefault`; stale states still show `залипший Block`.
Verification:
- `npm test -- AppSource.test.ts splitTunneling.test.ts --reporter=dot` passed: 2 files / 19 tests.
- `npm run build` passed and produced updated renderer chunks `SplitTunnel-BENxXy7Z.js` and `Maintenance-DFe50JY5.js`.
- `rg` verified `displaySplitTunnelPath`, `block default:`, and `активная защита` in source/built renderer output.
- `npm test -- --reporter=dot` passed: 61 files / 528 tests.
- `git diff --check` passed with only line-ending warnings.
- `npm run dist:win` passed and rebuilt `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Installer check: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe` size 117,453,455 bytes, last write 2026-07-06 12:30:01.
- `Get-AuthenticodeSignature` still reports `NotSigned`; real Publisher/UAC identity still requires a valid code-signing certificate.
Windows-only gap:
- Needs live packaged UI smoke: Apps row for YandexMusic should display a clean path leaf instead of mojibake.
- Needs live packaged UI smoke: Maintenance with active protected tunnel should show `block default: активная защита`, not `stuck block: да`.

2026-07-06 - SETTINGS-GEO-PRIVACY-TRUTH-1 DONE
Files:
- `vpn-tunnel-enforcer/src/renderer/pages/Settings.tsx`
- `vpn-tunnel-enforcer/src/renderer/components/ServerDetailModal.tsx`
- `vpn-tunnel-enforcer/src/main/serverProbe.ts`
- `vpn-tunnel-enforcer/src/main/urlAvailability.ts`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
Finding:
- The setting `Отключить гео-определение IP` claimed the app would not send VPN IP to `ipapi.co`, but the promise was only partially true: Dashboard already skipped current-IP lookup when `disableGeoLookup` was enabled, while Server Detail still fetched `https://ipapi.co/${host}/json/` directly from the renderer.
- Main-process `server:probe` also fetched ASN/country from `ipapi.co` for the selected server even when `disableGeoLookup` was enabled.
- URL Availability used `ipapi.co` for ASN/country enrichment of resolved target IPs. That is not the VPN exit IP, but it is still an app-controlled `ipapi.co` geo lookup, so the same privacy switch should gate it.
- Minimal Tavily check confirmed the core assumption: `ipapi.co` JSON endpoints return geo/ASN data for the IP being queried, so a privacy toggle must prevent the request rather than only hide the UI result.
Fix:
- `ServerDetailModal` now reads `settings.disableGeoLookup` from the app store. When enabled, it does not start the renderer `fetch(ipapi.co)`, does not show the geo loading state, and hides the online location card/map fallback.
- `serverProbe.probeServer()` now accepts `disableGeoLookup`; the IPC handler passes `settingsStore.get().disableGeoLookup`, and ASN enrichment is skipped when true.
- `urlAvailability.checkUrl()` / `probeNative()` / `fetchAsn()` now carry `disableGeoLookup`; URL Availability IPC passes the saved setting, and `fetchAsn()` returns `null` before contacting `ipapi.co` when true.
- Settings copy now matches behavior: it says the app will not send the current VPN IP or selected server IP to `ipapi.co`; online country/city/provider/map are disabled; locally saved/derived country hints may remain.
- Regression tests cover the renderer setting wiring, server-probe gating, and URL-availability ASN gating.
Verification:
- `mcp__tavily.tavily_search` minimal search used for current `ipapi.co` endpoint behavior.
- `npm test -- AppSource.test.ts mainIpcRegression.test.ts --reporter=dot` passed: 2 files / 22 tests.
- `npm test -- --reporter=dot` passed: 61 files / 531 tests.
- `npm run build` passed and produced updated main/renderer bundles, including `Settings-DWj0bdUS.js`, `Servers-BuxyoSIJ.js`, and `Availability-CiBZIQgZ.js`.
- `git diff --check` passed with only existing line-ending warnings.
Windows-only gap:
- Needs live packaged UI smoke: with `Отключить гео-определение IP` enabled, open Dashboard/Server Detail/Availability and confirm no live country/city/provider/map enrichment appears from `ipapi.co`.
- Installer was not rebuilt in this checkpoint; only `npm run build` was run.

2026-07-06 - SETTINGS-FULL-COPY-BEHAVIOR-AUDIT-1 DONE
Files:
- `vpn-tunnel-enforcer/src/main/tunController.ts`
- `vpn-tunnel-enforcer/src/main/settings.ts`
- `vpn-tunnel-enforcer/src/main/tunControllerRecoverySource.test.ts`
- `vpn-tunnel-enforcer/src/renderer/pages/Settings.tsx`
- `vpn-tunnel-enforcer/src/renderer/store.ts`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
Question:
- User asked whether every Settings point had really been checked. Honest answer before this checkpoint: not exhaustively; only geo privacy had been proven/fixed. This checkpoint completed a code-level pass over Settings page toggles/copy and their main/renderer behavior.
Checked settings and behavior:
- `strictAdapterLockdown`: start paths pass `enableAdapterLockdown`; physical lockdown disables IPv6 and optionally DNS-pins physical adapters.
- `publicWifiCompatibility`: UI promised DHCP/DNS stays as-is. Found bug: `tunController.start()` always passed `forceDns: true`. Fixed to `forceDns: !publicWifiCompatibility`; IPv6 lockdown remains active.
- `autoRestartOnCrash`: sing-box exit handler gates restart on setting, lastStartOptions, user stop state, and 3 backoff slots.
- `desktopNotifications`: notification helper returns early when disabled.
- `stealthMode`: start paths pass setting into `generateSingboxConfig`; config applies lower MTU / TLS fragmentation behavior as implemented.
- `disableGeoLookup`: previous checkpoint fixed Dashboard/Server Detail/server probe/URL availability ipapi.co gating.
- `smartRuSplit` / `smartRuMapsDirect`: start reads settings every run and passes to Smart Route config; maps direct only when master switch is on.
- `smartRuRuleSetAutoUpdate` / mode: rule-set manager uses managed/bundled source, update interval, and bootstrap route policy.
- `autoStart`: `settingsStore.save()` applies login item only when autoStart changes; boot recovery task is ensured once per process.
- `minimizeToTray`: main window close flow respects setting and keeps active protection running in background when minimized.
- `autoPilotEnabled`: renderer startup runs autoPilot only when enabled and not in Direct VPN mode.
- `locationPrivacyEnabled`: UI applies/rolls back immediately; stop path rolls back if setting remained applied.
- `advancedMode`: renderer hides Maintenance/advanced parameters, but Apps is intentionally normal visible workflow. Fixed stale copy that claimed Apps was opened by advanced mode.
- `proxyOverride` / `proxyType`: Dashboard, tray start, leak checks, subscriptions/key checks, autoconfig, and bootstrap paths read saved values.
- `bootstrapRouteMode`: used for subscription/key/Smart-RU service downloads only; copy kept scoped to service downloads.
- `checkInterval`: `save-settings` and startup call `ipMonitor.setCheckInterval`.
- `autoNetworkBaseline`: start paths apply baseline only when enabled and rollback on start failure/stop.
- `deepTrafficInspectionEnabled` / size / retain: traffic-forensics start/status reads settings and clamps values. Fixed renderer default to match main default (`false`) so UI does not briefly overstate packet capture before settings load.
Copy fixes:
- Smart-RU text no longer overpromises broad RU domain matching; it now says RU-hosted IPs and narrow gov/maps lists are direct, while broad category-ru is avoided.
- Smart-RU auto-update text now says it uses the service-download route, not always the selected proxy.
- Advanced mode text now says it opens Maintenance and advanced network options, not Apps.
Verification:
- `npm test -- AppSource.test.ts tunControllerRecoverySource.test.ts mainIpcRegression.test.ts --reporter=dot` passed: 3 files / 29 tests.
- `npm test -- --reporter=dot` passed: 61 files / 533 tests.
- `npm run build` passed and produced updated renderer chunks including `Settings-DwQEzoip.js`.
- `git diff --check` passed with only LF->CRLF warnings.
Windows-only gap:
- Needs live packaged UI smoke after installer rebuild/install: toggle public Wi-Fi compatibility ON, connect with strict adapter lockdown, and confirm physical adapter DNS is not forced to VPNTE TUN while IPv6 lockdown still applies.
- Needs live packaged UI smoke: Settings copy should match behavior and deep traffic capture should default off before/after settings load.

2026-07-06 - SETTINGS-FIX-INSTALLER-REBUILD-1 DONE
Files/artifacts:
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe.blockmap`
Context:
- Previous Settings checkpoint had `npm run build` only. Rebuilt the Windows installer so the public Wi-Fi DNS behavior and Settings copy fixes are present in the installable EXE.
Verification:
- `npm run dist:win` passed: sidecar build, snapshot step (skipped because `mksnapshot` is not installed), production build, and `electron-builder --win nsis`.
- Installer artifact: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe`, size `117,453,757` bytes, last write `2026-07-06 13:21:21`.
- Blockmap artifact: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe.blockmap`, size `123,569` bytes, last write `2026-07-06 13:21:24`.
- `Get-AuthenticodeSignature` on installer, unpacked app EXE, and ETW sidecar all returned `NotSigned`.
Notes:
- Electron-builder logs `signing with signtool.exe`, but Authenticode verification is authoritative here and shows no valid digital signature. Real UAC Publisher still requires a real code-signing certificate.
Windows-only gap:
- Install this rebuilt EXE and smoke Settings/public-Wi-Fi behavior in the packaged app.

2026-07-06 - SETTINGS-GEO-PRIVACY-ALL-PROVIDERS-1 DONE
Files/artifacts:
- `vpn-tunnel-enforcer/src/main/serverPicker.ts`
- `vpn-tunnel-enforcer/src/main/ipMonitor.ts`
- `vpn-tunnel-enforcer/src/main/leakDiagnostics.ts`
- `vpn-tunnel-enforcer/src/main/settings.ts`
- `vpn-tunnel-enforcer/src/renderer/pages/Settings.tsx`
- `vpn-tunnel-enforcer/src/renderer/components/BrowserIpCard.tsx`
- `vpn-tunnel-enforcer/src/renderer/components/ServerDetailModal.tsx`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
- `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`
User report:
- Screenshot showed `Отключить гео-определение IP` ON while external `2ip.ru` still showed VPN IP `144.31.1.75`, location `Рашин, Польша`, provider `H2NEXUS LTD`.
- Diagnostic zip `vpn-tunnel-enforcer-diagnostics-2026-07-06T10-38-32-085Z.zip` had `settings.disableGeoLookup: true`.
Findings:
- `2ip.ru` is an external website and can always geolocate the IP it sees; the app cannot prevent that without changing the VPN exit IP. The Settings copy made this boundary unclear.
- Real code gap found: previous geo privacy fix gated Dashboard/Server Detail/server probe/URL availability `ipapi.co`, but `serverPicker.ts` could still call `ip-api.com`, `ipwho.is`, `ipinfo.is`, `ipinfo.io`, and `iplocation.net` for country verification/backfill paths.
- Routine public-IP checks also used `ipinfo.io/json` as a fallback in `ipMonitor`, `leakDiagnostics`, and `BrowserIpCard`, which made the privacy setting look untrustworthy even though those checks only extracted the IP for leak detection.
Fix:
- Added `geoLookupDisabled()` in `serverPicker.ts` and gated all app-controlled server country lookup paths: secondary geo votes, batch lookup, exported `geolocateIp`, `verifyProfileCountry`, and IPC handlers `servers:verify-active-country` / `servers:verify-country`.
- IPC now returns `reason: 'geo-lookup-disabled'` before starting geo lookup when the setting is ON.
- Removed `https://ipinfo.io/json` from routine public-IP fallback lists in `ipMonitor`, `leakDiagnostics`, and `BrowserIpCard`.
- Settings title/copy now says the app disables online geo lookup inside the app, lists covered providers, and explicitly says sites like `2ip.ru` can still show the country of the VPN IP they see.
- Settings interface comment updated to describe all app-controlled third-party geo providers and the external-site limitation.
Verification:
- `npm test -- AppSource.test.ts mainIpcRegression.test.ts --reporter=dot` passed: 2 files / 25 tests.
- `npm test -- --reporter=dot` passed: 61 files / 535 tests.
- `git diff --check` passed with only existing LF->CRLF warnings.
- `npm run build` passed.
- `npm run dist:win` passed.
- Installer artifact: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe`, size `117,453,815` bytes, last write `2026-07-06 14:03:00`.
- Blockmap artifact: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe.blockmap`, size `123,551` bytes, last write `2026-07-06 14:03:04`.
- `Get-AuthenticodeSignature` on installer, unpacked app EXE, and ETW sidecar still returned `NotSigned`.
Windows-only gap:
- Install this rebuilt EXE and smoke: with geo privacy ON, open Dashboard/Server Detail/Servers country verification and confirm no app-side country/city/provider enrichment happens; external websites such as `2ip.ru` will still show VPN IP geolocation by design.

2026-07-06 - FINAL-ROLLUP-BEFORE-PUSH-1 DONE
Scope:
- Final rollup before commit/push of the accumulated stability, diagnostics, UI, Settings, VPN profile, and geo-privacy work.
Primary completed areas:
- Direct VPN/TUN stability: fixed DNS bootstrap circular detour, safer stop/rollback ordering, IP monitor resume paths, server-switch leak/banner suppression, stale sing-box cleanup behavior, and profile switching state handling.
- Firewall/repair diagnostics: made active protected firewall block-default show as protection instead of stale stuck state; repair paths are targeted and blocked while TUN is active; benign sing-box upload-close/block noise is no longer surfaced as a critical problem.
- VPN profiles/server picker: fixed Happ add/base64 parsing, subscription/profile race handling, safer profile resolution/in-flight behavior, proxy-list export path, server/group UI loading behavior, and smoother list behavior.
- Settings truth audit: checked settings copy against implemented behavior; fixed public-Wi-Fi DNS behavior, Smart-RU copy, Advanced Mode copy, deep traffic default mismatch, and geo privacy behavior/copy.
- Geo privacy: `disableGeoLookup` now gates app-controlled geo lookups across Dashboard/Server Detail/server probe/URL availability/server picker providers; routine IP checks no longer use `ipinfo.io/json`; copy explicitly explains that external sites like `2ip.ru` still geolocate the VPN IP they see.
- UI polish: improved server/app list behavior, dropdown layering, key/proxy import feedback, split-tunnel corrupt path display, maintenance text, and server-switch transitional UI.
Verification before push:
- `npm test -- AppSource.test.ts mainIpcRegression.test.ts --reporter=dot` passed: 2 files / 25 tests.
- `npm test -- --reporter=dot` passed: 61 files / 535 tests.
- `git diff --check` passed with only LF->CRLF warnings.
- `npm run build` passed.
- `npm run dist:win` passed.
- Codebase index updated via `mcp__codebase_memory_mcp.index_repository` fast mode with persistence.
Installer:
- Latest installer: `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Size: `117,453,815` bytes.
- Last write: `2026-07-06 14:03:00`.
- Blockmap: `VPN-Tunnel-Enforcer-Setup-1.1.0.exe.blockmap`, `123,551` bytes, `2026-07-06 14:03:04`.
Known remaining caveats:
- Installer/app/sidecar Authenticode status remains `NotSigned`; UAC Publisher cannot become `VYT` without a real trusted code-signing certificate.
- Final runtime confidence still needs live packaged Windows smoke after install: TUN start/stop, firewall rollback, server switch, geo privacy ON, public Wi-Fi compatibility, Smart-RU, repair page, tray/notifications.
- `.kimchi/` and `vpn-tunnel-enforcer/.kimchi/` are untracked local directories and intentionally left out of git staging.

2026-07-07 - SETTINGS-PROTECTION-SEVEN-AGENT-AUDIT-1 DONE
Source:
- User request: audit the visible Settings/Protection toggles with 7 subagents, especially because `disableGeoLookup` looked useless/non-working from the UI.
- Subagents reviewed: strict adapter lockdown, public Wi-Fi compatibility, auto-restart, Windows notifications, stealth mode, geo lookup privacy, Smart-RU.

Files:
- `vpn-tunnel-enforcer/src/renderer/pages/Dashboard.tsx`
- `vpn-tunnel-enforcer/src/renderer/App.tsx`
- `vpn-tunnel-enforcer/src/renderer/AppSource.test.ts`
- `vpn-tunnel-enforcer/src/main/index.ts`
- `vpn-tunnel-enforcer/src/main/mainIpcRegression.test.ts`
- `vpn-tunnel-enforcer/src/main/tunController.ts`
- `vpn-tunnel-enforcer/src/main/tunControllerRecoverySource.test.ts`
- `vpn-tunnel-enforcer/src/main/routingSelfTest.ts`
- `vpn-tunnel-enforcer/src/main/routingSelfTest.test.ts`
- `vpn-tunnel-enforcer/src/main/ruleSetManager.ts`
- `vpn-tunnel-enforcer/src/main/physicalAdapterLockdown.ts`
- `vpn-tunnel-enforcer/src/main/physicalAdapterLockdownSource.test.ts`
- `vpn-tunnel-enforcer/resources/vpnte-recover.ps1`
- `vpn-tunnel-enforcer/src/main/bootRecoveryScriptSource.test.ts`

Items:
- SET-PROT-1 DONE: local-proxy start now saves the latest Settings before `startTun`, matching Direct VPN and avoiding stale debounced toggles.
- SET-PROT-2 DONE: Dashboard geo lookup effect now depends on `settings.disableGeoLookup`, clears stale geo display immediately, and aborts in-flight `ipapi.co` fetches when the toggle changes.
- SET-PROT-3 DONE: renderer no longer ignores terminal `stopped` from auto-restart recovery just because restart progress set `connectionBusy=connecting`.
- SET-PROT-4 DONE: `lastStartOptions` now preserves `stealthMode`, so split/domain hot-reload and crash recovery do not silently lose MTU/fragmentation behavior.
- SET-PROT-5 DONE: pending auto-restart rereads `autoRestartOnCrash`; if the user turns the setting off during backoff, the restart is cancelled and adapter lockdown is rolled back.
- SET-PROT-6 DONE: `save-settings` restarts a running tunnel when `strictAdapterLockdown`, `publicWifiCompatibility`, or `stealthMode` changes; `restartWithLastOptions` now refreshes Settings-controlled toggles before replay.
- SET-PROT-7 DONE: Smart-RU self-test respects `disableGeoLookup` by skipping RU external echo probes when privacy is ON.
- SET-PROT-8 DONE: Smart-RU self-test no longer uses `2ip.ru`, because IP checkers are intentionally pinned to VPN by Smart-RU and using them as a direct-RU proof caused false partial verdicts.
- SET-PROT-9 DONE: physical adapter lockdown manifest now snapshots DNS registry policy values and rollback restores pre-existing values instead of blindly deleting them.
- SET-PROT-10 DONE: physical adapter lockdown no longer treats changed `forceDns`/resolver manifests as idempotent; it rolls back before reapplying.
- SET-PROT-11 DONE: physical adapter lockdown surfaces `DNS_*_err` apply/rollback markers as warnings/incomplete rollback instead of silently reporting success.
- SET-PROT-12 DONE: boot-time recovery script now uses the adapter lockdown manifest before restoring DNS/IPv6/transition/registry state; without a manifest it does only narrow orphan DNS cleanup and no longer enables IPv6 on every disabled physical adapter.
- SET-PROT-13 DONE: Smart-RU managed rule-set auto-refresh now has a non-blocking startup/settings hook via `maybeRefreshSmartRouteRuleSets`, honoring `smartRuSplit`, managed mode, auto-update and interval logic.

Verification:
- `npm test -- AppSource.test.ts mainIpcRegression.test.ts routingSelfTest.test.ts tunControllerRecoverySource.test.ts networkCompatibility.test.ts tunControllerConfig.test.ts physicalAdapterLockdownSource.test.ts bootRecoveryScriptSource.test.ts ruleSetManager.test.ts -- --reporter=dot`
- Result: 9 test files passed, 105 tests passed.
- `npm run build`
- Result: passed.
- `npm test -- --reporter=dot`
- Result: 63 test files passed, 547 tests passed.
- `git diff --check`
- Result: passed with only existing LF->CRLF working-copy warnings.

Windows-only gap:
- Needs live packaged smoke: toggle `disableGeoLookup` ON while Dashboard already shows country/city; UI should clear immediately and Smart-RU self-test must not contact `2ip.ru`/RU echo endpoints while privacy is ON.
- Needs live packaged smoke: toggle `strictAdapterLockdown`, `publicWifiCompatibility`, and `stealthMode` while Direct VPN is running; tunnel should restart and regenerated `sing-box.json` should reflect the new DNS/MTU/fragmentation behavior.
- Needs live packaged smoke: kill `vpnte-sing-box.exe` with auto-restart ON, then toggle auto-restart OFF during backoff; restart should cancel, adapter lockdown should roll back, and UI must not stay stuck on restart progress.
- Needs real Windows registry smoke: pre-create `DisableSmartNameResolution` and `DisableParallelAandAAAA`, start/stop TUN, and verify rollback restores original values rather than deleting them.
- Needs boot-time recovery smoke after a forced crash with manifest present: only manifest-backed adapters/registry/transition state should be restored; a manually disabled IPv6 adapter not touched by VPNTE must stay disabled.
- Needs Smart-RU managed-cache smoke: managed auto-update should run non-blocking when managed mode is enabled, and corrupt managed `.srs` fallback still needs a separate runtime hardening pass.

Notes:
- The notification subagent found copy/semantics issues (`desktopNotifications` disables the whole main notification pipeline, not only Windows toasts; sound pref is not enforced). These were not changed in this batch because they are lower risk than routing/privacy/runtime correctness and should be handled as a separate notification semantics pass.
- Smart-RU managed `.srs` integrity fallback remains a follow-up: current cache completeness still primarily checks file existence/size before sing-box runtime validation.

2026-07-08 - EXTERNAL-PROXY-PSR-ROTATION-1 DONE
Source:
- User request: let another already-running local app (`C:\psr`) use VPNTE's external proxy, rotate it itself, and avoid global kill-switch/other settings killing or misrouting that external proxy path.

Files:
- `vpn-tunnel-enforcer/src/main/firewallKillSwitch.ts`
- `vpn-tunnel-enforcer/src/main/externalProxy.ts`
- `vpn-tunnel-enforcer/src/shared/ipc-types.ts`
- `vpn-tunnel-enforcer/src/renderer/components/ExternalProxyCard.tsx`
- `vpn-tunnel-enforcer/resources/vpnte-proxy.cmd`
- `vpn-tunnel-enforcer/src/main/firewallKillSwitchValidation.test.ts`
- `vpn-tunnel-enforcer/src/main/externalProxy.test.ts`
- `C:\psr\src\utils\vpnte_proxy.py`
- `C:\psr\src\platforms\kwork_ext.py`
- `C:\psr\src\platforms\kwork.py`
- `C:\psr\src\browser\browser_manager.py`
- `C:\psr\src\api\routes\settings.py`
- `C:\psr\desktop\src\pages\Settings.tsx`
- `C:\psr\.env.example`
- `C:\psr\README.md`
- `C:\psr\tests\unit\test_vpnte_proxy.py`

Items:
- EXT-PROXY-1 DONE: external proxy sing-box runtime now has a stable program path and is included in kill-switch outbound allow-list creation.
- EXT-PROXY-2 DONE: starting or rotating the external proxy ensures its firewall allow rule before stopping the previous process, so active global kill-switch should not strand the proxy during rotation.
- EXT-PROXY-3 DONE: external proxy status now exposes the actual control URL/port; UI and `vpnte-proxy.cmd` no longer assume the fallback control port when the app had to bind another one.
- EXT-PROXY-4 DONE: PSR gained an opt-in VPNTE proxy client that reads VPNTE's endpoint/token files from `%APPDATA%\VPN Tunnel Enforcer`, starts/rotates the proxy through the local control API, and returns a stable local proxy URL.
- EXT-PROXY-5 DONE: PSR Kwork TLS/client path, browser startup path, and proxy rotator now use VPNTE proxy when `VPNTE_PROXY_ENABLED=1`.
- EXT-PROXY-6 DONE: PSR defaults to strict mode when VPNTE proxy is enabled, so VPNTE/control failures do not silently fall back to direct traffic unless explicitly disabled.
- EXT-PROXY-7 DONE: PSR settings UI/API/env example/README now expose `VPNTE_PROXY_*` and `VPNTE_CONTROL_*` knobs.
- EXT-PROXY-8 DONE: `/start` is now idempotent for already-running external proxy instances and returns the current stable `proxyUrl` instead of restarting/rotating.
- EXT-PROXY-9 DONE: external proxy JSON errors now include both `error` and `detail`, while text-mode helper output remains unchanged.
- EXT-PROXY-10 DONE: external proxy sing-box route rules now keep `localhost`, loopback, and private IP destinations on `direct-out` so the proxy does not try to send local control/discovery calls through the VPN outbound.
- EXT-PROXY-11 DONE: VPNTE now writes external proxy discovery/token files both to Electron `userData` (`%APPDATA%\vpn-tunnel-enforcer`) and the PSR contract path (`%APPDATA%\VPN Tunnel Enforcer`), fixing `RuntimeError: VPNTE control token not found`.

Verification:
- `npm test -- externalProxy.test.ts firewallKillSwitchValidation.test.ts preloadValidation.test.ts -- --reporter=dot`
- Result: 3 test files passed, 26 tests passed.
- `python -m pytest tests\unit\test_vpnte_proxy.py -q`
- Result: 2 tests passed.
- `python -m py_compile src\utils\vpnte_proxy.py src\platforms\kwork_ext.py src\browser\browser_manager.py src\platforms\kwork.py`
- Result: passed.
- `python -m pytest tests\unit\test_kwork_service.py -q`
- Result: 23 tests passed.
- `python -m ruff check src\utils\vpnte_proxy.py src\platforms\kwork_ext.py src\browser\browser_manager.py src\platforms\kwork.py tests\unit\test_vpnte_proxy.py`
- Result: passed.
- `npm test -- externalProxy.test.ts firewallKillSwitchValidation.test.ts preloadValidation.test.ts AppSource.test.ts mainIpcRegression.test.ts -- --reporter=dot`
- Result: 5 test files passed, 55 tests passed.
- `npm test -- --reporter=dot`
- Result: 63 test files passed, 553 tests passed.
- Follow-up VPNTE contract run: `npm test -- --reporter=dot`
- Result: 63 test files passed, 554 tests passed.
- Follow-up route syntax smoke: bundled `resources\sing-box.exe check` passed on an external-proxy config containing `localhost`, loopback, private-IP, DNS and final proxy rules.
- Live local smoke: copied current running token/endpoint to `%APPDATA%\VPN Tunnel Enforcer`, then `POST http://127.0.0.1:17873/start` with `X-VPNTE-Control-Token` returned the running external proxy status.
- Follow-up discovery-path run: `npm test -- --reporter=dot`
- Result: 63 test files passed, 555 tests passed.
- `python -m pytest tests\unit\test_vpnte_proxy.py tests\unit\test_kwork_service.py -q`
- Result: 25 tests passed.
- `npx vite build` in `C:\psr\desktop`
- Result: passed with existing large chunk warning.
- `npm run dist:win`
- Result: passed; installer rebuilt at `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Follow-up `npm run dist:win`
- Result: passed after VPNTE-only contract patch.
- Follow-up discovery-path `npm run dist:win`
- Result: passed after writing discovery/token to both app-data paths.
- `git diff --check` in VPNTE and PSR
- Result: passed with only LF->CRLF working-copy warnings.
- Codebase index full refresh completed for `C:\Users\Redmi\CascadeProjects\vpn` and `C:\psr`; cross-repo intelligence completed with no static cross edges.

Installer:
- Latest installer: `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.0.exe`.
- Size: `117,456,679` bytes.
- SHA256: `1ED9D968446B0D9C3E7B3A92BF503213D75F5C1BB4328F8509947F1E15A74522`.
- Follow-up size: `117,456,844` bytes.
- Follow-up SHA256: `110BAA1C1CEFDFB9C7E34BBA51937A759515CE41127862DA53213ED694D55588`.
- Discovery-path follow-up size: `117,456,975` bytes.
- Discovery-path follow-up SHA256: `230C24DB4D297D8E25B707EC058613C51BAC06C2E0590FEDA7773D32C18C03AC`.
- Authenticode: installer and unpacked app still report `NotSigned`.

Windows-only gap:
- Needs live packaged smoke with kill-switch already active: enable external proxy, rotate via PSR/control API, confirm `vpnte-external-proxy.exe` keeps outbound access while unrelated outbound traffic remains blocked.
- Needs PSR end-to-end smoke against the target site: set `VPNTE_PROXY_ENABLED=1`, run one request/browser flow, rotate, and confirm the next request exits via the newly selected VPNTE external proxy profile.
