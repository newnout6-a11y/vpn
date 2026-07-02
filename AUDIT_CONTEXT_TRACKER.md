# VPN Tunnel Enforcer Audit Tracker

Last updated: 2026-07-02

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

Known pre-existing full-suite blocker: full `npm test` has an older `src/main/appLoggerRotation.test.ts` timeout/noisy stdout issue.

Latest verification after current work:

```powershell
npm test -- firewallKillSwitchValidation.test.ts leakDiagnostics.test.ts systemNetwork.test.ts elevatedPsHelper.test.ts vpnProfilesProtocolCoverage.test.ts urlAvailabilityVerdict.test.ts --reporter=dot
# 6 test files passed, 55 tests passed

npm run build
# passed

npm test -- appLoggerRedaction.test.ts elevatedPsHelper.test.ts firewallKillSwitchValidation.test.ts tunControllerConfig.test.ts splitTunneling.test.ts granularKillSwitch.test.ts dnsProfiles.test.ts profileRotation.test.ts serverPickerConsolidate.test.ts serverPickerPingPoisoning.test.ts --reporter=dot
# 10 test files passed, 112 tests passed

npm run build
# passed
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
| M-X3 | DONE | Shell-string `exec` pattern is widespread. | High-risk shell-string paths now use `execFile`/argv or encoded PowerShell: autoconfig Git/env, diagnostics ZIP compression, split-tunnel registry scan, Store repair PS helper, browser/location registry operations, and TUN normal config/probe launch paths. Remaining `exec` uses are static diagnostics or the `sudo-prompt` UAC command-string boundary. | `vpn-tunnel-enforcer/src/main/autoconfig/git.ts`, `autoconfig/env.ts`, `admin.ts`, `diagnosticsExport.ts`, `splitTunneling.ts`, `storeRepair.ts`, `browserHardening.ts`, `locationPrivacy.ts`, `tunController.ts` | `npm test -- tunControllerConfig.test.ts splitTunneling.test.ts --reporter=dot` passed: 47 tests; `npm run build` passed. |
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
- vpn-tunnel-enforcer/src/main/storeRepair.ts
- vpn-tunnel-enforcer/src/main/browserHardening.ts
- vpn-tunnel-enforcer/src/main/locationPrivacy.ts
- vpn-tunnel-enforcer/src/main/tunController.ts
Verification:
- npm test -- tunControllerConfig.test.ts splitTunneling.test.ts --reporter=dot
- Result: 2 test files passed, 47 tests passed.
- npm run build
- Result: passed.
Windows-only gap:
- Real Windows smoke should cover diagnostics ZIP export, browser/location rollback, Store repair actions, and elevated TUN launch.
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
- DPI-1 DESIGN TODO: ByeDPI-like improvement should be a separate staged design, not a second TUN stacked on the existing TUN.
  Current base: settings.stealthMode already lowers TUN MTU and enables sing-box TLS fragmentation where safe.
  Proposed direction: add an explicit anti-DPI profile that can tune sing-box fragmentation/utls/ALPN/transport parameters per outbound and optionally run a local pre-upstream proxy only in modes where it does not create TUN-over-TUN loops.
  Windows-only gap: must be tested against real blocked/slow sites and Russian-IP-preserving smartRuSplit paths on Windows.

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
- N1 DONE: remote DNS bootstrap resolvers now use direct-out, avoiding proxy-out circular dependency when the VPN/proxy endpoint itself is hostname-based.
- N2 DONE: tunController.stop() no longer emits stopped/desktop disconnect notification before baseline/kill-switch/adapter rollback finishes.
- N3 DONE: tunController.stop() resumes ipMonitor through a guarded finally path, so teardown exceptions cannot leave leak monitoring suspended forever.
- N12 DONE: routingSelfTest.ruEgressIp is no longer a dead stub; Smart-RU self-test now probes RU-domain echo pages through the normal TUN path.
- N14 DONE: granularKillSwitch.setLevel rejects standard/strict before init(singboxExePath), without mutating store/settings first.
- S1 PARTIAL DONE: elevatedPsHelper now has policy-forbidden command patterns so required tokens cannot authorize cross-policy payloads like netsh advfirewall reset or HKLM Run persistence.
- U4 DONE: settingsStore.save no longer applies login item / boot-recovery schtask on unrelated settings saves; boot recovery is ensured at most once per app process via sync/login changes.
- S32 ALREADY DONE BEFORE THIS BATCH: autoconfig/env.ts already uses socks5h:// plus ALL_PROXY for SOCKS5 env-mode proxying.
- V1/V2 ALREADY DONE BEFORE THIS BATCH: see VPN PROFILES REVIEW BATCH 1 and commit 5c7751e.

Verification:
- npm test -- tunControllerConfig.test.ts routingSelfTest.test.ts elevatedPsHelper.test.ts granularKillSwitchInit.test.ts settingsLoginItem.test.ts --reporter=dot
- Result: 5 test files passed, 61 tests passed.
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

## Update Template

When finishing a point, update its row and append a short note here:

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
