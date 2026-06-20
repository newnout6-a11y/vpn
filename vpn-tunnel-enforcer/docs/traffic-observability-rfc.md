# RFC: Windows traffic observability for VPN Tunnel Enforcer

Date: 2026-06-19
Status: proposed

## Decision

The most effective near-term solution is not a custom kernel driver and not
"capture every packet forever" through WinDivert. The best result-to-risk ratio
for this codebase is:

1. Keep the current `pktmon` / `netsh trace` traffic-forensics layer.
2. Add a normalized correlation layer over the artifacts it already produces.
3. Add a real-time ETW sidecar only after the artifact schema is stable.
4. Treat a custom WFP callout driver as a later phase, only if the remaining
   blind spots are proven by production diagnostics.

This gives practical packet-level forensics now, with enough evidence to answer
why traffic leaked, stalled, reset, bypassed TUN, hit kill-switch rules, used the
wrong DNS path, or failed inside Windows networking. It avoids the highest-risk
work first: kernel driver signing, WHQL, EDR conflicts, and high-throughput
packet copying into user space.

## Existing baseline

VPN Tunnel Enforcer already has a strong start in
`src/main/trafficForensics.ts`.

Current session lifecycle:

- starts before local-proxy TUN mode is brought up
- starts before direct-VPN mode is brought up
- stops on user stop, failed start, terminal status, and shutdown
- stages artifacts into diagnostics exports

Current engines:

- primary: `pktmon`
- fallback: `netsh trace`

Current `pktmon` capture includes:

- packet capture and trace
- full packet size capture via `--pkt-size 0`
- circular log mode with bounded file size
- ETW providers:
  - `Microsoft-Windows-TCPIP`
  - `Microsoft-Windows-WFP`
  - `Microsoft-Windows-Winsock-AFD`
  - `Microsoft-Windows-WebIO`
- converted artifacts:
  - `pktmon.etl`
  - `pktmon-trace.txt`
  - `pktmon-trace.pcapng`
  - live variants during diagnostics export
- WFP state:
  - `wfp-netevents.xml`
  - `wfp-state.xml`
  - live variants

Current state snapshots include:

- TCP and UDP endpoints
- `ipconfig /all`
- route table and `route print`
- ARP table
- DNS cache and DNS client server configuration
- adapters, adapter stats, and IP interfaces
- firewall profiles and firewall rules
- recent DNS-Client and TCPIP operational events
- Chromium policy state

This baseline is valuable. The missing part is not "more raw files"; it is
normalization, correlation, verdicts, and a stable artifact contract.

## Goals

The observability system must let support or engineering answer these questions
from a diagnostics ZIP without reproducing the issue:

- Did the packet/flow go through the intended TUN path?
- Did anything bypass the tunnel or physical-interface lockdown?
- Was DNS resolved through the tunnel, local system DNS, browser policy, DoH, or
  another path?
- Did Windows block the traffic through WFP, firewall, route selection, adapter
  state, or kill-switch rules?
- Was the failure a local reset, remote reset, timeout, retransmit storm, MTU
  issue, or upstream censorship/interference?
- Did sing-box receive, route, reject, or fail the flow?
- Which mode was active: local proxy or direct VPN?
- Which profile, target, adapter, routes, DNS config, and kill-switch state were
  active when the failure happened?

## Non-goals

This RFC intentionally does not promise literal perfect logging of every packet
under every Windows condition.

Out of scope for the near-term implementation:

- permanent full-payload packet retention
- kernel-accurate PID attribution for every packet without a WFP driver
- replacing Windows routing/firewall behavior with a custom stack
- building a WFP or NDIS driver before current artifact blind spots are proven
- using WinDivert as a global all-traffic capture path

Those can become later work, but only after the current evidence pipeline is
structured enough to show exactly what remains invisible.

## Architecture

### Session model

Every observability run is a forensic session.

Session starts:

- before local-proxy TUN startup
- before direct-VPN startup
- before traffic can leave through the intended controlled path

Session stops:

- on user stop
- on startup failure
- on `killswitch-active`
- on `stopped`
- on app shutdown

Session can be snapshotted while still running during diagnostics export.

The session directory is the source of truth. A diagnostics ZIP should be useful
even if the app crashes immediately after the snapshot.

### Collectors

Collector 1: packet and drop evidence

- `pktmon` packet trace
- `pktmon` counters
- `pktmon` drop counters
- ETL to TXT conversion
- ETL to PCAPNG conversion
- fallback `netsh trace`

Collector 2: Windows network state

- routes
- adapters
- interface metrics
- DNS client state
- DNS cache
- TCP/UDP endpoints
- firewall rules/profiles
- WFP state and netevents

Collector 3: app events

- VPN lifecycle events
- TUN startup/stop events
- kill-switch events
- profile and mode selection
- public IP checks
- leak self-test results
- traffic monitor results
- sing-box process lifecycle and logs

Collector 4: real-time ETW sidecar (implemented — `vpnte-etw-sidecar.exe`)

The sidecar subscribes to high-value providers and writes normalized NDJSON
events without blocking traffic:

- `Microsoft-Windows-TCPIP`
- `Microsoft-Windows-DNS-Client`
- `Microsoft-Windows-WFP`
- `Microsoft-Windows-Winsock-AFD`
- `Microsoft-Windows-WebIO`

It is a small native Rust component (`native/vpnte-etw-sidecar/`, `ferrisetw`).
Node/Electron controls its lifecycle and parses the NDJSON it emits, rather than
becoming the ETW parser itself. See Phase 4 below for the full implementation.

## Artifact contract

The current raw artifacts should remain available. The next implementation
should add normalized files next to them.

Required files:

- `session-manifest.json`
- `timeline.ndjson`
- `flows.ndjson`
- `dns.ndjson`
- `drops.ndjson`
- `tcp-health.ndjson`
- `packet-metrics.ndjson`
- `route-snapshots.json`
- `app-events.ndjson`
- `summary.json`

Raw files to preserve:

- `pktmon.etl`
- `pktmon-trace.txt`
- `pktmon-trace.pcapng`
- `pktmon-status.txt`
- `pktmon-counters.json`
- `pktmon-drop-counters.json`
- `wfp-netevents.xml`
- `wfp-state.xml`
- all live snapshot variants
- all current Windows state snapshots

### `session-manifest.json`

Manifest v2 should include:

- schema version
- app version
- OS version/build
- session id
- mode
- profile id/name when available
- target
- started/stopped timestamps
- stop reason
- selected engine
- capture size limits
- retained session policy
- adapter identifiers
- active DNS configuration summary
- active route summary
- kill-switch state summary
- artifact list with size and modified time
- parse/correlation errors

Lifecycle invariant:

- `running: true` is valid only while the current app process can either
  actively manage the capture engine or observe its managed real-time sidecar.
- If `running: true` and `sidecar.running: true` survive an app restart,
  installer update, or crash without a managed sidecar process, status reads
  must mark the session stopped with `stopReason: "zombie-recovery"`.
- Diagnostics UI must use the reconciled manifest state, not a stale
  `latest-session.json` value, so reinstalling the app cannot leave
  "packet collection" shown while VPN protection is off.
- Diagnostics UI must expose live health directly: active engine, ETL size,
  latest live snapshot time, sidecar event counts, and explicit sidecar
  warnings. Users should not need a ZIP just to see whether `pktmon` is
  collecting while the ETW sidecar is only alive but not producing TCP/DNS/WFP
  data events.
- Diagnostics UI must give a newly started sidecar a 30 second warmup window
  before showing the "no TCP/DNS/WFP data events" warning. During that window
  lifecycle-only sidecar output is displayed as startup progress, not failure.
- Status reconciliation must also treat stop artifacts as authoritative. If a
  manifest still says `running: true` but `pktmon-stop.*`, `netsh-stop.*`,
  `pktmon-trace.*`, or equivalent stop outputs already exist, the status read
  must finalize the session as stopped. A stale manifest must not keep the UI
  badge on "packet collection" after capture has stopped.
- Old session pruning is best-effort only. A locked historical `pktmon.etl`
  must be logged as cleanup debt, but it must not fail a new capture start.
- Diagnostics export must be self-consistent: `latest-session.json` must not
  point at a session directory that is missing from the exported
  `traffic-forensics/sessions/` tree.

### `timeline.ndjson`

One event per line, sorted by timestamp.

Event categories:

- app lifecycle
- VPN lifecycle
- route change
- DNS change
- TCP health
- WFP block/drop
- packet counter sample
- public IP result
- leak-test result
- sing-box log event

### `flows.ndjson`

One normalized flow record per observed connection/flow candidate.

Expected fields:

- local address/port
- remote address/port
- protocol
- direction
- process id/path when available
- adapter/interface index when available
- first/last seen timestamps
- byte/packet counters when available
- DNS names mapped to remote address when available
- verdict
- evidence references

### `dns.ndjson`

One DNS decision per record.

Expected fields:

- query name
- query type
- result addresses
- source provider
- resolver address when available
- interface index when available
- whether resolver was tunnel-safe
- linked flow ids when possible
- verdict

### `drops.ndjson`

One drop/block/reset observation per record.

Expected fields:

- timestamp
- source: `pktmon`, `wfp`, `tcpip`, `firewall`, `app`
- reason
- direction
- 5-tuple when available
- filter id/rule id when available
- interface index when available
- linked flow id when possible
- evidence reference

### `packet-metrics.ndjson`

One normalized numeric metric per observed `pktmon` counter value.

Expected fields:

- timestamp
- source: `pktmon`
- artifact: `pktmon-counters.json`, `pktmon-drop-counters.json`, or live
  variants
- metric path/name from the source JSON
- numeric value
- category: packet, byte, drop, error, or generic counter
- labels derived from the source JSON hierarchy when available

### `summary.json`

Machine-readable conclusion file.

It should answer:

- `trafficLeakDetected`
- `dnsLeakDetected`
- `tunPathConfirmed`
- `killSwitchBlockedTraffic`
- `windowsFirewallBlockedTraffic`
- `remoteResetLikely`
- `localResetLikely`
- `timeoutOrPacketLossLikely`
- `mtuIssueLikely`
- `singBoxFailureLikely`
- `insufficientEvidence`

Every conclusion must include evidence references back to raw or normalized
artifacts. No conclusion should be emitted without evidence.

## Verdict matrix

### Traffic bypass

Signal:

- active VPN mode expects traffic through TUN
- route snapshot shows physical interface preferred for public destination
- packet/flow evidence appears on physical adapter without tunnel route evidence
- public IP check returns non-VPN egress

Verdict:

- `trafficLeakDetected: true`

### DNS leak

Signal:

- DNS-Client events or DNS state show resolver outside tunnel policy
- DNS endpoint appears on physical interface
- Chromium policy allows independent resolver path while app expects strict mode

Verdict:

- `dnsLeakDetected: true`

### Kill-switch block

Signal:

- app status is `killswitch-active`
- WFP/firewall evidence shows blocked outbound traffic
- route/interface state matches lockdown

Verdict:

- `killSwitchBlockedTraffic: true`

### Remote reset or censorship/interference

Signal:

- TCP connection leaves local stack
- retransmits/timeouts/resets appear in TCPIP events
- no local WFP/firewall drop explains the failure
- sing-box did not reject the flow locally

Verdict:

- `remoteResetLikely: true` or `timeoutOrPacketLossLikely: true`

### Local Windows block

Signal:

- WFP netevents or firewall rules identify a local block
- packet never reaches expected tunnel/core path
- TCPIP does not show normal outbound progression

Verdict:

- `windowsFirewallBlockedTraffic: true` or `localResetLikely: true`

### MTU or fragmentation issue

Signal:

- repeated retransmits
- large packets near path MTU
- tunnel path active
- no local WFP block
- failure depends on payload size or TLS handshake size

Verdict:

- `mtuIssueLikely: true`

### sing-box/core failure

Signal:

- Windows route/DNS path is correct
- packets reach local proxy/TUN path
- sing-box logs show dial/handshake/routing failure
- public IP/leak tests fail after core errors

Verdict:

- `singBoxFailureLikely: true`

## Implementation phases

### Phase 1: schema and manifest v2

Scope:

- keep current collectors
- add schema versioning
- expand `session-manifest.json`
- include app version, OS version, profile/mode metadata, adapter summary, DNS
  summary, route summary, and artifact inventory

Output:

- diagnostics ZIP becomes self-describing

### Phase 2: summary generator over existing artifacts

Scope:

- parse existing JSON/text/XML artifacts after stop or live snapshot
- produce `timeline.ndjson`, `drops.ndjson`, `route-snapshots.json`, and
  `summary.json`
- preserve raw artifacts exactly as collected

Output:

- support can answer basic leak/block/DNS/routing questions without opening
  PCAP manually

### Phase 3: app event bridge

Scope:

- write selected app lifecycle events into `app-events.ndjson`
- include TUN state, kill-switch state, public IP checks, leak tests, profile
  selection, and sing-box lifecycle events
- avoid duplicating large logs; reference existing log files where possible

Output:

- Windows evidence can be correlated with app decisions

### Phase 4: real-time ETW sidecar — implemented

Scope:

- add a small native ETW consumer process
- write normalized `events.ndjson`
- subscribe to TCPIP, DNS-Client, WFP, Winsock-AFD, and WebIO providers
- track event loss counters and buffer pressure

Output:

- better timestamp precision and richer TCP/DNS/WFP timelines

Implementation:

- Native Rust binary `vpnte-etw-sidecar.exe` built from
  `native/vpnte-etw-sidecar/` using the `ferrisetw` crate (a safe wrapper over
  `StartTrace` / `EnableTraceEx2` / `ProcessTrace` + TDH parsing). Target
  `x86_64-pc-windows-msvc`, single static executable, no runtime dependency.
- CLI contract matches `trafficForensics.ts`:
  `--events <path> --session <id> --providers <csv>`. It opens a real-time trace
  session named `VPNTE-ETW` (a stable name so an orphan from an abruptly-killed
  prior run is reclaimed before start, bounding orphans to at most one),
  enables the requested providers by name (falling back to a known-GUID table),
  and appends one normalized NDJSON row per event, flushing after each line.
- Normalization mirrors the previous PowerShell poller's `Convert-Event`:
  `category` ∈ {`tcp`,`dns`,`wfp`,`afd`,`webio`}; TCP rows carry the 5-tuple
  (`localAddress`/`localPort`/`remoteAddress`/`remotePort`, decoded from
  `SOCKADDR`/`IN_ADDR` blobs); DNS rows carry `queryName`/`queryResults`. WFP
  block/drop events map to `event:"block"`, `reason:"wfp-block-observed"`.
- Health: a `category:"health"` heartbeat (with `observedEvents`/`dataEvents`
  counters) every 30s, plus an `event-cap-reached` health row once a per-session
  data-event cap is hit (back-pressure guard). Only metadata is recorded — never
  packet payloads (see Privacy).
- Lifecycle: `category:"lifecycle"` `started`/`stopped` rows; the process exits
  cleanly when stdin closes (the Electron integration also kills it on stop).
- The binary is built by `npm run build:sidecar` (invoked automatically by
  `dist*`) and bundled next to `vpnte-etw-sidecar.ps1` via `electron-builder.yml`.
  The PowerShell poller remains a fallback for environments without the binary.

### Phase 5: flow correlation

Scope:

- correlate DNS names, TCP/UDP endpoints, packet/drop evidence, WFP data, route
  state, and app events
- produce `flows.ndjson`
- add stable flow ids referenced by all summary conclusions

Output:

- diagnostics can answer "what happened to this destination" instead of only
  "what files were captured"

### Phase 6: optional WFP callout driver

Only start this phase if phases 1-5 prove that user-space observability cannot
answer required production questions.

Driver constraints:

- metadata-first
- no full-payload copying by default
- no packet modification in the logging path
- explicit self-injection detection if packet injection is ever added
- minimal surface area for EDR compatibility

Expected value:

- stronger PID/process attribution
- stronger kill-switch enforcement
- fewer race conditions in flow attribution

Cost:

- driver development
- signing and release pipeline
- compatibility testing
- possible conflicts with EDR/VPN/firewall products

## Privacy and safety

Packet captures can contain sensitive payloads, domains, IPs, DNS queries,
tokens, and user metadata. The product must treat traffic forensics as sensitive
debug data.

Rules:

- collection must remain bounded by size and retention settings
- default mode should be circular capture, not unbounded logging
- diagnostics export must clearly include traffic-forensics artifacts only when
  the feature is enabled
- summary files should prefer metadata and verdicts over raw payload display
- UI should warn that PCAP/ETL may contain sensitive traffic
- retention defaults should stay conservative
- future redaction must happen in generated summaries, not by modifying raw
  evidence silently

## Performance policy

Defaults:

- capture only during VPN sessions or explicit diagnostics windows
- keep circular capture enabled
- keep default max size bounded
- retain a small number of sessions
- do not parse huge PCAP files synchronously on the Electron main thread
- generate summaries in a background worker/process
- record parser errors as evidence instead of failing the whole diagnostics
  export

## Risks and unknowns

- ETW event loss under high throughput
- `pktmon` availability and behavior differences across Windows builds
- admin-right requirements
- large diagnostics archives
- antivirus/EDR interference
- third-party VPN/firewall conflicts
- incomplete process attribution without a WFP driver
- DNS-over-HTTPS paths hidden behind browser/app behavior
- PCAP parsing cost for large sessions

## Definition of done for MVP

MVP is done when a diagnostics ZIP can answer, in under five minutes:

- whether traffic leaked outside the tunnel
- whether DNS leaked outside the tunnel
- whether kill-switch blocked traffic intentionally
- whether Windows firewall/WFP blocked traffic unexpectedly
- whether the failure is likely local, remote, MTU-related, or sing-box-related
- which raw artifacts prove each conclusion

The MVP does not need perfect packet attribution. It needs trustworthy,
evidence-linked conclusions from the data the app already collects.

## Next implementation checklist

1. Add manifest schema versioning and richer session metadata.
2. Add a pure parser/summarizer module for current traffic-forensics artifacts.
3. Generate `summary.json` and `timeline.ndjson` during stop and live staging.
4. Add focused tests with synthetic `pktmon`, WFP, DNS, route, and firewall
   fixtures.
5. Add diagnostics README entries explaining the new normalized files.
6. Add UI/status surface only after summaries are stable.
7. Prototype the ETW sidecar after artifact correlation proves its exact input
   contract.
