# Roadmap: censorship resilience and next protocol/features pass

## Goal

Make VPN Tunnel Enforcer materially stronger against modern blocking while keeping
the current Windows Electron + sing-box architecture operable and debuggable.

This document is based on:

- current project architecture and indexed codebase
- current upstream sing-box, mihomo, Hysteria, and AmneziaWG materials
- practical fit with the existing `tunController` / `vpnProfiles` / `serverGroups`
  / `externalProxy` / diagnostics model

Подробные планы по фазам лежат в
[`censorship-resilience-phases/`](./censorship-resilience-phases/README.md).

## Current state in this repo

Strong points already present:

- Windows TUN path with kill-switch, adapter lockdown, diagnostics, snapshots,
  leak tests, and tray-driven lifecycle
- direct VPN and local-proxy hard mode
- profile import for `vless`, `trojan`, `ss`, `vmess`, `hysteria2`,
  `naive`, `anytls`, `shadowtls`, and `tuic`
- anti-DPI defaults in TLS import path:
  - browser-like uTLS fingerprint
  - ALPN defaults
  - Reality parsing in `buildTls()`
- server groups, subscriptions, client-device identity, health checks
- managed Smart-RU `.srs` cache with bundled local fallback
- active-profile capability diagnostics for stealth/ECH/Hysteria2 warnings

Current architectural limits:

- transport import is still narrow: `ws`, `grpc`, `httpupgrade`, `http/h2`
- no parser/import path for `wireguard` or `amneziawg`
- no full remote rule-provider channel management beyond the current managed Smart-RU cache
- no proxy chaining / bootstrap chaining model similar to `dialer-proxy`
- no ECH-first UX or validation surface
- no Hysteria Realm / NAT traversal flow
- no engine abstraction for a second core such as mihomo

Current conceptual risk:

- the app currently defaults most TLS outbounds to browser-like uTLS
  impersonation; current sing-box docs now explicitly warn that uTLS has had
  repeated fingerprinting issues and recommend NaiveProxy for TLS fingerprint
  resistance instead

## External landscape that matters now

### 1. sing-box is still the closest fit for this codebase

Why:

- your app is already deeply coupled to sing-box config generation and runtime
- sing-box officially exposes the same family of outbounds/inbounds you need:
  `Naive`, `WireGuard`, `ShadowTLS`, `TUIC`, `Hysteria2`, `AnyTLS`, `VLESS`
- rule-set management is richer now, including remote rule-sets with
  `http_client`, `update_interval`, and detoured downloads

What changed upstream that is relevant:

- latest stable is newer than your bundled `sing-box-1.13.8-windows-amd64`
- `1.13.12` updated NaiveProxy
- `1.14.0-alpha.26` adds Hysteria2 `gecko` obfuscation
- sing-box docs expose remote rule-set refresh, Naive outbound, ECH in TLS, and
  Hysteria Realm service mode
- sing-box docs now describe uTLS as "not recommended" for censorship
  circumvention and explicitly point users toward NaiveProxy for TLS
  fingerprint resistance

Conclusion:

- short-term expansion should stay sing-box-first
- do not jump to a second engine before exhausting sing-box coverage

### 2. Hysteria is moving fast in the exact anti-blocking direction you care about

Notable current items:

- `Gecko` obfuscation fragments QUIC handshake packets into randomized chunks
- `Hysteria Realms` adds rendezvous + NAT traversal / hole punching
- upstream keeps shipping protocol-hardening and security fixes in this area

Conclusion:

- Hysteria2 should become a first-class advanced path in this app, not just a
  generic imported outbound

### 3. mihomo has the widest "modern transport toolbox", but it is a bigger step

Important capabilities:

- `MASQUE`
- `xhttp` transport work and frequent updates
- `dialer-proxy` chaining
- mature `proxy-providers` and `rule-providers`
- WireGuard page documents `amnezia-wg-option`

But:

- adopting mihomo means adding an engine boundary, runtime manager, config
  translator, diagnostics compatibility, and new failure modes
- it is a product-level decision, not a tactical patch

Conclusion:

- use mihomo as an ideas source now
- treat actual mihomo runtime support as a later milestone

### 4. AmneziaWG is strategically interesting

Why it matters:

- standard WireGuard is easy to fingerprint via fixed headers and packet sizes
- AmneziaWG adds header mutation, size randomization, junk packets, and protocol
  mimicry at the transport layer while preserving the WireGuard crypto core

Conclusion:

- this is worth testing as a dedicated "UDP stealth tunnel" track
- but it should be isolated as an experiment first, not merged into the main
  tunnel path immediately

## Recommended product direction

### Primary strategy

Strengthen the existing sing-box core first.

That gives the best ratio of:

- implementation cost
- compatibility with your diagnostics and safety model
- chance of getting real resilience gains quickly

### Secondary strategy

Borrow concepts from mihomo even before adopting mihomo itself:

- provider channels
- rule-provider management
- detoured bootstrap downloads
- proxy chaining
- health-check policy

### Tertiary strategy

Keep a clean path for a future second core:

- mihomo sidecar
- or a dedicated WireGuard / AmneziaWG execution path

But only after the app has a core abstraction layer.

## Concrete plan

## Phase 1: Low-risk, high-leverage sing-box upgrade pass

Priority: highest

Actions:

1. Upgrade bundled sing-box from `1.13.8` to current stable `1.13.x`.
2. Add version-aware runtime reporting in diagnostics:
   - bundled sing-box version
   - runtime sing-box version
   - rule-set source versions
3. Add canary tests around generated configs and startup behavior.
4. Re-run Windows leak / startup / stop / restart validation on the upgraded
   binary.
5. Revisit the blanket `uTLS=chrome` default:
   - keep it as a compatibility fallback, not the only stealth strategy
   - add a feature flag so Naive/ECH experiments can become the preferred path
     for selected profiles

Why first:

- unlocks newer protocol behavior without architecture churn
- reduces drift from upstream fixes
- gives a safer base for later features like Naive or remote rule-sets

Definition of done:

- upgrade branch passes full vitest
- startup/stop diagnostics still work
- packaged app stages the upgraded runtime correctly

## Phase 2: Dynamic rule-set and update channel layer

Priority: highest

Actions:

1. Replace purely static smart-route assets with a rule-set source model:
   - bundled fallback `.srs`
   - optional remote update channel
   - cached last-known-good copy
2. Add UI controls for:
   - update cadence
   - direct vs detoured download
   - fallback to bundled set on failure
3. Add metadata and observability:
   - last update time
   - source URL
   - hash / version if available
   - last error
4. Reuse your existing diagnostics ZIP to include rule-set state.

Why:

- censorship targets shift fast; static `geoip-ru` + `geosite-category-gov-ru`
  is helpful but not enough as the only model
- this is one of the cleanest real gains available without protocol churn

## Phase 3: Expand sing-box protocol and transport coverage in the app layer

Priority: high

Actions:

1. Add import/export support for:
   - `naive`
   - `anytls`
   - `shadowtls`
   - `tuic`
   - `wireguard`
2. Expand VLESS/VMess/Trojan transport import to include newer variants where
   sing-box supports them and your parser currently rejects them.
3. Add validation/linting in the UI:
   - unsupported transport
   - missing TLS/ECH fields
   - invalid fingerprint / ALPN combinations
4. Add protocol capability badges in Servers UI.

Why:

- right now the core can go farther than the import UX allows
- protocol support in the product is limited more by parsing and UX than by
  the underlying engine

## Phase 4: Naive + ECH track

Priority: high

Actions:

1. Add Naive outbound import and config editing.
2. Add ECH configuration support and validation surface.
3. Add "stealth presets" for:
   - Reality/uTLS
   - Naive + ECH
   - Hysteria2 + obfs
4. Extend diagnostics:
   - did ECH config load
   - did TLS fallback occur
   - cert/self-signed warnings

Why:

- Naive remains one of the strongest "looks like browser traffic" families
- ECH is the cleanest path for hiding SNI without layering increasingly weird
  transport tricks everywhere else

## Phase 5: Hysteria2 advanced mode

Priority: high

Actions:

1. Promote Hysteria2 from generic imported node to first-class feature set.
2. Add explicit support for:
   - `salamander`
   - `gecko`
   - gecko min/max packet size
   - hop interval controls if available in chosen engine version
3. Add Hysteria Realms / rendezvous mode as an advanced workflow.
4. Add protocol-specific diagnostics:
   - QUIC blocked
   - handshake fragment path
   - hole punching success/failure
   - NAT type hints if obtainable

Why:

- this directly targets present-day QUIC-based blocking and home-hosted /
  no-public-IP usage

## Phase 6: Bootstrap chaining and fetch detours

Priority: medium-high

Actions:

1. Introduce an internal "bootstrap route" abstraction for:
   - subscription fetches
   - rule-set downloads
   - geo checks
   - health probes
2. Support download detours / chained bootstrap path:
   - direct
   - current local proxy
   - selected external proxy profile
3. Add separate policy for "control plane" vs "user traffic plane".

Why:

- one of the biggest practical failures under blocking is not data forwarding
  itself, but inability to fetch configs, refresh rules, or bootstrap a new
  node
- mihomo's `dialer-proxy` and provider model is the right conceptual reference

## Phase 7: Experimental stealth tunnel track

Priority: medium

Actions:

1. Run a design spike for AmneziaWG support.
2. Decide between:
   - native dedicated execution path
   - second engine / sidecar path
   - import-only compatibility path
3. Build a lab matrix:
   - blocked QUIC
   - blocked known WireGuard signature
   - mixed IPv4/IPv6
   - mobile hotspot / NAT environments

Why:

- this is promising, but the architecture cost is much higher than phases 1-6

## Phase 8: Engine abstraction for future mihomo support

Priority: medium-low for now

Actions:

1. Define a `CoreAdapter` abstraction:
   - generate config
   - start/stop
   - status
   - health
   - diagnostics hooks
2. Move sing-box specifics behind that boundary.
3. Only then prototype:
   - mihomo sidecar
   - MASQUE mode
   - xhttp mode
   - provider/rule-provider import compatibility

Why:

- MASQUE and xhttp are attractive
- but forcing them straight into the current sing-box-coupled main path would
  create a hard-to-debug hybrid

## What should not be done yet

1. Do not stuff 8 new protocols into the current parser/UI without a protocol
   capability layer.
2. Do not add mihomo runtime support before a core abstraction exists.
3. Do not make alpha-only upstream features the default path for all users.
4. Do not replace local rule-set fallbacks with remote-only downloads.
5. Do not add stealth features without extending diagnostics for them.

## Suggested execution order

1. sing-box stable upgrade
2. dynamic rule-set channel
3. protocol/transport import expansion
4. Naive + ECH
5. Hysteria2 advanced mode
6. bootstrap chaining
7. AmneziaWG spike
8. engine abstraction
9. optional mihomo sidecar experiments

## First three concrete deliverables

### Deliverable A

Upgrade sing-box and add version telemetry.

### Deliverable B

Implement remote rule-set channels with cached fallback and diagnostics.

### Deliverable C

Add parser/UI/runtime support for Naive, AnyTLS, ShadowTLS, TUIC, and
WireGuard, plus a capability matrix in the Servers screen.

## Success criteria

This roadmap is working if, after the first three deliverables:

- the app can refresh its own routing intelligence safely under blocking
- the import surface matches more of what modern subscriptions actually ship
- the diagnostics story remains stronger than generic proxy clients
- the next anti-blocking features can be added without turning `tunController`
  and `vpnProfiles` into an unmaintainable blob
