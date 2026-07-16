# Adaptive Bypass Autopilot

Status: draft. No implementation has started.

## Goal

Replace the current global `stealthMode: boolean` with an automatic, local-only
connection policy for ordinary users. The application must choose the least
intrusive configuration that works on the current network, remember a verified
result locally, and recover safely when the network or server becomes hostile.

The feature is about reliability under protocol filtering. It must not claim to
make a VPN invisible or to guarantee access on every network.

## Research Basis

The plan is based on the following constraints, verified during July 2026
research:

- Russian protocol restrictions vary by ISP, region, connection type and time;
  they include protocol filtering and IP/statistical heuristics. A global
  permanent client setting cannot be assumed to be correct everywhere.
  Source: Human Rights Watch, "Disrupted, Throttled, and Blocked";
  https://www.hrw.org/report/2025/07/30/disrupted-throttled-and-blocked/state-censorship-control-and-increasing-isolation
- RKS Global reports continuing attempts to restrict advanced transports,
  including VLESS/Reality. Therefore a client-side handshake change alone is
  not a complete response to endpoint reputation or transport blocking.
  Source: https://rks.global/en/research/runet-2025
- sing-box documents `record_fragment` as TLS handshake record fragmentation
  for firewall bypass. It does not alter the entire tunneled data flow.
  Source: https://sing-box.sagernet.org/configuration/shared/tls
- TLS record fragmentation has experimental evidence against one censorship
  implementation, but that evidence cannot be generalized to every Russian
  operator. It is one bounded fallback, not a universal default.
  Source: https://upb-syssec.github.io/blog/2023/record-fragmentation

## Product Contract

The normal user gets one setting:

> **Автоподстройка сети**
> Приложение проверяет подключение после запуска. Если сеть мешает VPN, оно
> попробует безопасный режим или другой сервер. Решения хранятся только на этом
> компьютере.

The normal UI must not expose MTU, TLS fragmentation, uTLS fingerprints,
Reality, XHTTP, or transport internals.

Visible runtime states:

| Internal phase | User-facing text |
| --- | --- |
| `baseline-start` | Подключаемся... |
| `verifying` | Проверяем соединение... |
| `compatibility-retry` | Подстраиваем соединение под эту сеть... |
| `server-failover` | Ищем более доступный сервер... |
| `connected-baseline` | Подключено. Обычный режим |
| `connected-compatibility` | Подключено. Режим совместимости для этой сети |
| `external-managed` | Подключено. Транспортом управляет внешний VPN-клиент |
| `failed` | Не удалось подобрать режим для этой сети |

The Settings page also gets a single `Сбросить запомненные настройки сети`
button. Protocol diagnostics remain available only through the diagnostics
export and advanced mode.

## Scope

### In scope

- Automatic baseline versus compatibility selection for the active connection.
- A bounded retry with transport-aware settings.
- Bounded server failover among compatible profiles in the current allowed
  group.
- Local network-specific learning, expiry, reset, and safe diagnostics.
- Correct interaction with the TUN lifecycle, kill switch, adapter lockdown,
  baseline rollback, watchdogs, and external proxy bypass.
- Clear non-technical status in the UI.

### Explicitly out of scope for the first implementation

- Provisioning or changing the remote server configuration.
- Turning an arbitrary VLESS profile into NaiveProxy, XHTTP, or another
  transport. Those transports require server-side support and explicit profile
  metadata.
- ECH or `tls.spoof` as a default. The current bundled sing-box is 1.13.13;
  `tls.spoof` requires a later runtime and must be a separately validated
  server/profile capability.
- Automatic changes outside the active server group.
- Uploading learned decisions, SSIDs, server URIs, or probe data.

## Current Code Constraints

The implementation must work with these existing facts rather than duplicate
their logic:

- `src/main/tunController.ts:716-1041` always enables uTLS and ALPN for TLS
  outbounds. The current stealth switch only additionally selects MTU 1280,
  enables `record_fragment` for non-Reality TLS, and may rotate a fingerprint.
- `record_fragment` must never be enabled for Reality. It is intentionally
  excluded by the existing config generator.
- In local SOCKS/HTTP proxy mode, VPNTE owns a plain local proxy outbound, not
  the upstream VPN TLS handshake. Changing the mode there is not a real
  anti-DPI action; only TUN MTU can change.
- `src/main/tunController.ts:3043-3214` `stop()` is a full user stop. It
  disables the kill switch, rolls back adapter lockdown and network baseline,
  clears retry state, and repairs DNS.
- `restartWithLastOptions()` calls that full `stop()` and then starts again.
  It is therefore unsafe for adaptive retries because it creates a protection
  gap.
- `src/main/keyHealthChecker.ts:382-466` has a safe profile health probe. It
  avoids a direct TLS handshake when that would expose a real front SNI.
- `src/main/serverPicker.ts:234-282` `tunnelHttpProbe()` is the existing
  proof that traffic can actually leave through a running TUN. TCP reachability
  alone is not a sufficient success criterion.
- Existing crash restart, `WSAEACCES` recovery, profile rotation,
  `attemptPostTrialFailover()`, watchdogs, and Settings-driven restarts already
  have timers. Adaptive retries cannot become another independent retry loop.
- `vpnte-external-proxy.exe` is intentionally allowed through the kill switch
  and routed `direct-out`. Any new lifecycle code must preserve that behavior.

## Data Model

### Resolved session mode

Replace the session use of `stealthMode: boolean` with a resolved mode. The old
setting stays only as a migration input during the compatibility release.

```ts
type AdaptiveMode =
  | 'baseline'
  | 'tls-compatibility'
  | 'mtu-compatibility'
  | 'external-managed'

interface AdaptiveCapabilities {
  canUseTlsFragment: boolean
  canUseMtuCompatibility: boolean
  externallyManaged: boolean
  reason?:
    | 'reality'
    | 'local-proxy'
    | 'quic'
    | 'unsupported-transport'
}

interface AdaptiveStartContext {
  connectionGeneration: number
  requestedBy: 'user' | 'autostart' | 'recovery' | 'rotation'
  mode: AdaptiveMode
  capabilities: AdaptiveCapabilities
  usedSavedDecision: boolean
}
```

`StartOptions` and `generateSingboxConfig()` receive this resolved,
session-only mode. They must not reread a global checkbox during a retry.

### User settings

```ts
interface AppSettings {
  // Existing fields...
  adaptiveBypassEnabled: boolean          // default true
  adaptiveBypassServerFallback: boolean   // default true; advanced UI only
}
```

Migration rules:

- Existing `stealthMode: true` becomes adaptive enabled with a one-release
  legacy preference to start in compatibility mode.
- Existing `stealthMode: false` or missing becomes adaptive enabled with
  `baseline` first.
- The new coordinator never writes the old `stealthMode` field during normal
  operation.
- The old visible switch is removed after the migration release; no automatic
  setting save may trigger a recursive restart.

### Local learning store

Use a dedicated `electron-store`, for example `adaptive-network-learning`, not
the global settings store.

```ts
interface AdaptiveNetworkLearningState {
  version: 1
  records: AdaptiveNetworkRecord[]
}

interface AdaptiveNetworkRecord {
  networkKey: string
  profileKey: string
  mode: AdaptiveMode
  confidence: 0 | 1 | 2 | 3
  successfulRuns: number
  failureCount: number
  lastSucceededAt: number
  expiresAt: number
  cooldownUntil?: number
  lastOutcome: 'success' | 'inconclusive' | 'failed'
}
```

Rules for the store:

- `networkKey` is an HMAC using a per-install secret from Windows
  `safeStorage`; it is never a plain SSID, BSSID, MAC, gateway, IP address, or
  adapter alias.
- Build it from the most stable available physical-network identifiers: Windows
  network profile/SSID/BSSID when available, then gateway and adapter context.
  Do not use a DHCP-assigned local IP as the key.
- `profileKey` is a keyed fingerprint of protocol, host, port, transport and
  relevant non-secret TLS properties. Never include a UUID, password, URI, or
  raw subscription payload.
- Retain at most 24 LRU records, with a 30-day TTL. Corrupt/missing state falls
  back to baseline without blocking startup.
- Record a success only after a stable window of 20-30 seconds and a fresh
  verified egress probe. One initial HTTP 204 is not sufficient.
- A failed profile-mode combination has a bounded cooldown. It must not be
  retried repeatedly during one outage.
- Diagnostics omit records by default. An opt-in diagnostic summary may contain
  only counts, modes, age and outcome, never the keyed identifiers.

## Capability Matrix

Capability is determined from the parsed outbound, not from a display name.

| Outbound condition | Allowed adaptive action | UI behavior |
| --- | --- | --- |
| Regular TLS, non-Reality | `baseline` then `tls-compatibility` | Normal compatibility behavior |
| Reality | Baseline or bounded MTU compatibility only; no TLS record fragment | Do not claim traffic camouflage changed |
| Hysteria2, QUIC, UDP transport | No TLS record fragment; only validated MTU behavior or server failover | Do not call this stealth mode |
| Local SOCKS/HTTP proxy | `external-managed`; no fake TLS retry | State says external VPN client controls transport |
| Explicit `clientDevice` / fingerprint | Preserve the imported device fingerprint | Never overwrite declared device identity |
| Unknown or unsupported transport | Baseline plus server failover only | Conservative status and diagnostics |

The existing always-on uTLS/ALPN defaults are baseline behavior. They must not
be described as a result of adaptive mode.

## Adaptive State Machine

There is one coordinator in the main process:

```text
idle
  -> prepare
  -> baseline-start
  -> verify
       -> succeeded
       -> compatibility-retry
       -> server-failover
       -> failed

compatibility-retry
  -> verify
       -> succeeded
       -> server-failover
       -> failed

server-failover
  -> baseline-start (candidate profile)
       -> verify
       -> failed

any state -> cancelled (user Stop, quit, explicit server change, network change)
```

The coordinator owns a monotonically increasing `connectionGeneration`, an
abort signal, and every timeout. It is the only owner of adaptive attempts.

### Start algorithm

1. Determine the active profile/outbound and its `AdaptiveCapabilities`.
2. Build a privacy-safe network/profile lookup key.
3. If an unexpired, confident learned mode exists, start with it. Otherwise
   start in baseline.
4. Start the TUN through the protected transition path.
5. When TUN reports running, wait for route propagation and run a fresh egress
   verification. Do not rely on a cached negative result.
6. Mark success only when TUN status, egress verification, and the stability
   window all agree.
7. If the failure classifier permits it and a compatibility mode is supported,
   run exactly one compatibility retry of the same profile.
8. If that fails and allowed sibling candidates exist, run a bounded server
   failover. Promote a candidate only after it passes actual egress verification
   and the stability window.
9. On terminal failure, restore network state according to the protected
   transition rules, present one clear result, and stop all adaptive timers.

### Budgets and timing

- Maximum three TUN starts for one user connection intent.
- Maximum 45 seconds of adaptive activity per intent.
- At most one same-profile compatibility retry.
- At most one automatic sibling-server promotion in the first release.
- No reaction to one transient watchdog event. Require repeated, normalized
  evidence after a grace period.
- Explicit user Stop, profile selection, settings restart, app shutdown, or
  connection-generation change cancels the run immediately.

## Failure Classification

The adaptive policy must classify failures before changing a transport mode.

| Evidence | Classification | Adaptive action |
| --- | --- | --- |
| Invalid config, unsupported field, missing credential, auth failure | Configuration/profile error | Terminal; do not enable compatibility |
| UAC failure, port bind `WSAEACCES`, runtime staging error | Local runtime error | Use existing local recovery only |
| `sing-box` access violation or unrelated core crash | Core failure | One existing crash recovery at most; collect diagnostics |
| Local proxy unavailable or proxy watchdog down | Upstream local client issue | `external-managed`; no adaptive stealth retry |
| Captive portal / no physical internet | Network unavailable | Pause and present a network message |
| Single DNS error or one blocked probe URL | Inconclusive | Stay on current mode and retry verification later |
| Server TCP unavailable | Endpoint/IP failure | Candidate server failover, no fragment retry first |
| Repeated TLS reset/timeout plus failed fresh egress after TUN up | Probable transport filtering | Compatibility retry if capability permits |
| TUN up, server TCP live, repeated independent egress failures | Probable tunnel data-plane issue | Compatibility retry once, then server failover |

`checkProfileHealth()` remains a candidate filter, not a proof of a working
VPN. Its current SNI leak protections must remain intact.

The egress verifier must use multiple maintained neutral anchors and distinguish
their individual results. `all probes failed` is stronger evidence than one
failed URL, but still remains inconclusive unless corroborated by TUN/runtime
events.

## Protected Reconfiguration

Do not use public `stop()` or `restartWithLastOptions()` for an adaptive retry.
They intentionally perform a full user teardown and open a period without the
firewall kill switch, adapter lockdown, and system baseline.

Add an internal-only lifecycle operation, conceptually:

```ts
restartForAdaptiveChange(next: StartOptions, ctx: AdaptiveStartContext): Promise<Result>
```

Required behavior:

1. Serialize against `startInProgress`, `stopInProgress`, crash recovery,
   profile rotation and Settings restarts.
2. Mark the old core exit as an intentional adaptive transition so `onExit`
   cannot schedule an independent auto-restart.
3. Keep the firewall kill switch active between attempts whenever it was active
   before the transition. It must still allow only the VPN core and the
   currently required endpoint paths.
4. Keep adapter lockdown and baseline ownership during the short transition.
   Do not point physical DNS at a removed TUN for longer than the bounded
   transition deadline.
5. Keep external proxy process allowances and `direct-out` routing untouched.
6. If the next core cannot become healthy before the deadline, either start the
   next already-planned attempt immediately under protection, or perform one
   terminal rollback. Never leave the computer indefinitely offline.
7. Terminal failure, cancellation, and user Stop must execute exactly one full
   cleanup: rollback baseline, disable the kill switch as appropriate, restore
   adapter settings, repair orphaned DNS, and resume leak monitoring.

This needs an explicit lifecycle owner/lease. Reusing `restartAttempt` is not
allowed: crash recovery and adaptive retry require separate budgets.

## Server Failover Policy

- Direct VPN only in the first release.
- Limit candidates to enabled siblings in the active, user-permitted group.
- Respect a profile/endpoint cooldown and do not select the currently failed
  candidate again during the same intent.
- Prefer candidates with a valid profile schema, compatible transport and a
  recent verified result on this network. Use health checks only to eliminate
  clearly unreachable candidates.
- Do not permanently change `activeProfileId` until the candidate has passed
  actual egress and the stability window.
- Manual server selection cancels the coordinator and always wins.
- Existing `attemptPostTrialFailover()` is a useful implementation seed, but it
  is restricted to expired groups and must be generalized rather than copied.

## Network Changes

`leakSelfTest` already observes network changes, but its IP/CIDR signature is
not stable enough for persisted learning. The adaptive service needs its own
privacy-safe network identity provider.

On a network change:

1. Cancel a pending adaptive run.
2. Give DHCP/captive portal and route changes a short grace period.
3. Run verification without immediately restarting a healthy connection.
4. Only create a new adaptive intent after repeated evidence of failed egress.
5. On a real loss of connectivity, suspend adaptation until physical network
   connectivity returns.

## IPC and Renderer Contract

Add typed IPC methods:

```ts
'adaptive-bypass:get-status': () => AdaptiveBypassStatus
'adaptive-bypass:retry': () => { ok: boolean; error?: string }
'adaptive-bypass:reset-learning': (scope: 'current' | 'all') => { ok: boolean }
```

```ts
interface AdaptiveBypassStatus {
  enabled: boolean
  phase: 'idle' | 'verifying' | 'retrying' | 'switching-server' | 'connected' | 'limited' | 'failed'
  effectiveMode: AdaptiveMode | null
  usedSavedDecision: boolean
  messageKey: string
  updatedAt: number
}
```

The main process is the only policy owner. The renderer receives no raw SSID,
network fingerprint, profile fingerprint, server URI, UUID, secret, or detailed
probe data. Existing `notifyStatus()` can carry compact adaptive status events;
the typed status IPC remains the source of truth after renderer reload.

## Observability and Privacy

Structured events use the `adaptive-bypass` scope. They may include phase,
attempt number, capability class, normalized failure class, elapsed duration,
and outcome. They must not include raw network identifiers or connection
secrets.

The diagnostic export must describe an adaptive run as a sequence of redacted
state transitions. It must not expose the learned key store by default.

No telemetry leaves the computer. Probe endpoints are fixed application health
anchors, never URLs from browsing history or user input.

## Implementation Plan

### Phase 0: contracts and instrumentation

- Add `AdaptiveMode`, `AdaptiveCapabilities`, normalized failure types and
  structured event schemas.
- Add a session-only `adaptiveMode` to `StartOptions` and preserve it through
  non-adaptive restarts.
- Extract pure capability detection and failure decision functions.
- Add redacted phase/status events without changing connection behavior.

Exit criterion: existing behavior remains byte-for-byte equivalent when
adaptive bypass is disabled.

### Phase 1: config and local learning foundation

- Extend `networkCompatibility.ts` to resolve MTU from `AdaptiveMode` while
  retaining 1500/1380/1280 behavior.
- Change `generateSingboxConfig()` to consume a resolved mode, retaining the
  Reality guard and explicit device fingerprint guard.
- Implement the encrypted/salted learning store with migration, TTL, LRU,
  reset and corruption handling.
- Add the single user setting and read-only runtime status UI.

Exit criterion: learned baseline/compatibility choices can be selected but no
automatic retry happens yet.

### Phase 2: same-profile adaptive retry

- Implement `adaptiveBypass.ts` as a serial state machine with injected clock,
  tunnel lifecycle interface and cancellation.
- Integrate fresh egress verification and normalized failure classification.
- Add the internal protected reconfiguration path in `tunController`.
- Route direct-VPN and local-proxy start entry points through the coordinator.
- Keep local-proxy and Reality behavior capability-limited and visible as such.

Exit criterion: a supported regular TLS profile can make one protected
compatibility retry without a firewall/DNS/adapter leak window.

### Phase 3: controlled server failover

- Generalize candidate collection from `attemptPostTrialFailover()`.
- Add cooldown, compatibility filtering, verification before promotion, and
  manual-selection cancellation.
- Integrate direct VPN watchdog events as evidence, not as an unconditional
  switch trigger.

Exit criterion: only a verified sibling is promoted, with no more than the
configured connection budget.

### Phase 4: hardening and rollout

- Add network-change behavior and stale-learning invalidation.
- Expose retry and reset actions, but keep transport details hidden.
- Add diagnostic summaries and support-friendly status descriptions.
- Validate across real Windows networks before enabling by default for existing
  installations.

Exit criterion: all acceptance criteria pass on Windows and fallback behavior
is proven under injected failures.

## File-Level Work Map

New files:

- `src/main/adaptiveBypass.ts`: state machine, classification, budgets,
  cancellation and orchestration.
- `src/main/adaptiveNetworkStore.ts`: local learning, HMAC, TTL/LRU and reset.
- `src/main/adaptiveBypass.test.ts`: pure policy and coordinator tests.
- `src/main/adaptiveNetworkStore.test.ts`: persistence and privacy tests.

Existing files:

- `src/main/settings.ts`: settings, defaults, normalization and migration.
- `src/main/tunController.ts`: resolved mode, config generation, protected
  transition and recovery interaction.
- `src/main/networkCompatibility.ts`: mode-to-MTU resolver.
- `src/main/index.ts`: direct/local connection entry points and IPC wiring.
- `src/main/serverPicker.ts`: fresh tunnel egress verification and candidate
  integration.
- `src/main/keyHealthChecker.ts`: reusable normalized probe results; retain
  SNI leak protections.
- `src/main/profileRotation.ts` and `src/main/autoPilot.ts`: route their start
  requests through the coordinator; do not run parallel policies.
- `src/main/diagnosticsExport.ts`: redacted adaptive status export.
- `src/preload/index.ts` and `src/shared/ipc-types.ts`: typed IPC contract.
- `src/renderer/store.ts` and `src/renderer/pages/Settings.tsx`: one toggle,
  status and learning reset.
- `src/main/tunControllerConfig.test.ts`, `networkCompatibility.test.ts`,
  `keyHealthChecker.test.ts`, `profileRotation.test.ts`,
  `firewallKillSwitchValidation.test.ts`, `systemNetwork.test.ts`, and main
  IPC regression tests: targeted coverage updates.

## Test Matrix

### Pure unit tests

- Capability matrix for regular TLS, Reality, local SOCKS/HTTP, Hysteria2,
  QUIC, unsupported transports and explicit device fingerprints.
- Failure classifier: config/UAC/port/core crash/DNS/captive portal/endpoint
  timeout/egress failure/unknown evidence.
- Decision table: baseline, compatibility, server failover, terminal failure,
  disabled mode and saved decision behavior.
- Learning store: no plain SSID/IP/MAC in persisted JSON, TTL, LRU, salt/key
  migration, corruption fallback, reset and profile fingerprint invalidation.

### Coordinator and lifecycle tests

- Fake timers prove no more than three starts or 45 seconds per intent.
- Repeated watchdog events are coalesced.
- User Stop, Settings change, manual server change, network change, app quit
  and process exit cancel all future adaptive callbacks.
- Crash auto-retry, WSAEACCES retry, rotation and adaptive retry cannot run at
  the same time.
- A failure before TUN start never turns into a fragment retry.
- A candidate TCP success alone cannot become a successful VPN verdict.

### Protection tests

- Kill switch remains active during protected adaptive attempts.
- Terminal failure and user Stop remove protection exactly once and restore
  baseline, adapter DNS and IPv6 state exactly once.
- No orphaned TUN DNS remains after cancellation or a failed retry.
- External proxy firewall allowance and `direct-out` exception survive every
  adaptive reconfiguration.
- Baseline ownership cannot be applied or rolled back twice by competing paths.

### Windows integration tests without UI automation

- Controlled endpoint causes TLS reset, timeout, valid response and port bind
  failure.
- Simulated sing-box config error, core crash and UAC failure remain terminal
  or use only their existing recovery paths.
- Network change while retrying cancels the old generation.
- Direct VPN, Reality and local proxy behavior match the capability matrix.
- Inspect firewall manifests, adapter DNS/IPv6 and runtime process ownership
  before, during and after every scenario.

UI automation is not part of this validation plan. Renderer coverage is limited
to source, store, IPC and component tests as requested.

## Acceptance Criteria

1. A normal user controls the feature with one switch and does not select
   protocol internals.
2. A new network starts baseline once; compatibility retry occurs only after
   classified evidence and only on a supported outbound.
3. Reality and local proxy modes never receive a fake `record_fragment` result
   or a misleading stealth status.
4. At most three starts and 45 seconds are spent on one connection intent.
5. User Stop always wins and cancels all queued work immediately.
6. Only one of adaptive retry, crash recovery, server rotation and Settings
   restart may own the TUN lifecycle at a time.
7. Learned choices remain local, expire, can be reset, and do not persist raw
   network/server/secrets data.
8. A learned decision is reused only after a fresh egress confirmation.
9. Kill switch, baseline, adapter lockdown, DNS repair and external proxy
   bypass retain their existing safety guarantees through every transition.
10. All behavior is covered by unit, lifecycle and Windows integration tests;
    no UI launch is required for verification.

## Open Decisions Before Implementation

1. Confirm whether the first release should default adaptive bypass to enabled
   for existing installations, or enable it only for new installations during a
   one-release observation period.
2. Choose the application-owned, neutral egress anchor set and its maintenance
   policy. It must not depend on a single blocked CDN.
3. Define exactly when a kill switch may be retained after a terminal failure
   when the user explicitly enabled it. The default must avoid both a leak and
   an indefinitely offline machine.
4. Decide whether `mtu-compatibility` for Reality/QUIC should be offered in
   the first release or deferred until field validation proves benefit.
5. Define a supported server-profile capability schema before adding Naive,
   XHTTP, ECH, or newer sing-box features.
