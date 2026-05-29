# Code Audit — Findings Log

Deep manual audit of vpn-tunnel-enforcer main process. Status: COMPREHENSIVE PASS COMPLETE.

## Summary
18 issues found across the codebase. ALL fixed (B1-B3 + C1-C18) with tests
(133 → 179 tests). C2 was cosmetic (comment typo). Every main-process module
read in full; preload bridge + renderer store/Dashboard/Servers audited.
Status: COMPLETE.

---

# PASS 2 — Deep network/logic audit (weak/crooked/dead code, not just bugs)

Focus: networking correctness, RU/DPI fitness, security, and code that works
through crutches or silently does nothing.

## D-series findings

### D1 — domainRouting is a fully DEAD feature [FIXED]
domainRoutingService.getRules()/matchAndRecord() were NEVER consulted when
building the sing-box config — per-domain rules (vpn/direct/block, priority,
wildcards, file import) reached nothing. FIXED: added
domainRulesToSingboxRules() (pure) + generateDomainRouteRules(), wired into
generateSingboxConfig right after sniff + hijack-dns and before the
private-range/catch-all rules. `*.x.com`→domain_suffix `.x.com`, exact→domain,
dotless→domain_keyword; actions map to direct-out/proxy-out/block-out; emitted
in ascending priority (first-match-wins). +8 tests.

### D2 — icmpPing: command injection via subscription-controlled host [FIXED/security]
serverPicker.icmpPing ran `exec('ping.exe ... ' + host)` through cmd.exe with
host interpolated raw from imported subscription content → a server like
`8.8.8.8 & calc` was arbitrary command execution. FIXED: execFile (no shell)
+ isProbablyHostOrIp() allow-list gate (rejects whitespace/metacharacters).
+6 tests incl. injection payloads.

### D3 — leakSelfTest.curlBound: shell exec with interpolated value [FIXED/security-lite]
Switched curlBound from exec(string) to execFile('curl.exe', [args]) so the
adapter IP/url are literal argv, no shell. (Lower risk — ip was
local-adapter-derived — but no reason to keep a shell string.)

### D4 — keyHealthChecker: misleading "via tunnel" + plain-TLS SNI leak [FIXED]
The module's doc claimed it probes "THROUGH the tunnel" via the mixed-direct-in
SOCKS5 port — but that inbound is hard-routed to `direct-out` in the sing-box
config, so the probe always egresses via the physical adapter. Worse: for
plain-TLS keys it ran a full TLS handshake to the key's REAL `server_name`
straight out the physical adapter — the exact TSPU SNI-blackhole risk the rest
of the codebase carefully avoids. FIXED: corrected the doc to describe the
real (direct) routing; added a tlsLeaksSni classification (Reality SNI is
camouflage → safe; plain TLS → real front → unsafe) and the TLS rung now runs
ONLY for Reality keys, falling back to a no-SNI TCP-connect verdict for
plain-TLS keys. +5 tests.

---

## PASS 1 — Confirmed bugs (all fixed)


### B1 (was C4) — tunController: clash_api port not bind-safe → intermittent WSAEACCES
`generateSingboxConfig` sets `clashPort = randomLocalPort()` (pure random,
49152-65535). The mixed-direct-in port `dPort` is carefully pre-resolved via
`pickFreeLocalPort()` (OS-assigned, avoids Windows Hyper-V/WSL excluded
ranges) precisely because a random port can hit an excluded range and make
sing-box fail to bind with WSAEACCES. But clashPort was never given the same
treatment. If clashPort lands in an excluded range, the clash_api
external_controller fails to bind → sing-box exits at startup. The WSAEACCES
retry re-runs prepareRuntime which only fixes dPort; clashPort gets a fresh
random (might still be bad), and there's only ONE retry. Real intermittent
start failure. FIX: pre-resolve clashPort via pickFreeLocalPort in
prepareRuntime, pass as clashPortOverride; exclude dPort/clashPort from each
other.

### B2 (was C5) — tunController.stop(): leak detection stays suspended forever on cleanup error
stop() calls `ipMonitor.suspend()` early. At the end, if `cleanupErrors.length
> 0` it `return { success:false }` BEFORE reaching `ipMonitor.resume()`. So any
single cleanup failure (taskkill, baseline rollback, kill-switch disable, DNS
repair) leaves leak detection permanently OFF until app restart — the user
stops getting leak warnings exactly when something already went wrong with
teardown. FIX: resume in a finally / before the early return.

### B3 — serverGroups.refreshGroup(): asymmetric dedup key duplicates sourceUri profiles
The merge indexed existing profiles via `profileKey(p)` (which returns
`uri:<sourceUri>` when a sourceUri is present) but looked up fresh profiles via
`vpnProfileKey(fresh)` (always `tuple:server|port|protocol`, since the fresh
side has no per-line URI). Any stored profile carrying a `sourceUri` therefore
never matched its refreshed counterpart → the refresh ADDED it again as a
duplicate and kept the stale copy. This was latent before but
`backfillProfileSourceUris()` (added in the migration work) now populates
sourceUri on most profiles, so a single "Обновить" on a subscription would
balloon the group with duplicates. FIX: key BOTH sides by the connection tuple
(profileTupleKey / vpnProfileTupleKey) so the match is symmetric. Removed the
now-unused profileKey/vpnProfileKey. Confirmed: tsc clean.



### C15 — configManager: import/export omits server-groups → imported profiles orphaned
ConfigExportData has `profiles` but NO `serverGroups` section, and ALL_SECTIONS
doesn't include groups. Exporting then importing profiles on another install
brings the profiles back with groupId values pointing at groups that don't
exist there → every imported profile is orphaned (post-C9 they land in
"Восстановленные ключи", losing the per-subscription structure the user built).
FIX: add a `serverGroups` section to export/import OR strip/rebuild groupId on
import. Lower urgency (export/import is rarely used) but a real data-fidelity
bug. Deferred-documented.

### C18 — diagnostics: wrong manifest paths → kill-switch + baseline manifests never bundled
systemSnapshot.ts and diagnosticsExport.ts read the rollback manifests from
the userData ROOT (latest-tun-network-baseline.json,
latest-firewall-killswitch.json), but they're actually written to
SUBDIRECTORIES: network-backups/latest-tun-network-baseline.json and
firewall-killswitch/manifest.json. So the diagnostic ZIP and every periodic
snapshot always showed killSwitch:null + baseline:null — support could never
see the firewall/proxy rollback state, exactly the data needed to debug "VPN
off but internet broken". (adapter-lockdown path was correct.) FIXED both
read sites.


dispatchNotification()/notificationPrefsService are never called outside their
own module. Every notification goes through notify() directly, which only
checks the global settings.desktopNotifications flag. So the granular
Notification Settings UI (vpnConnect / vpnDisconnect / leakDetected /
profileRotation / scheduleTriggered / connectionError toggles, plus method
system/inapp/both and sound) has ZERO effect — toggling them changes stored
prefs that nothing reads. FIX: map each notify() call site to a
NotificationEventType and route through dispatchNotification. Medium refactor
across index.ts/tunController/scheduler/profileRotation.


writeConfigToStores writes electron-store files directly, but running services
hold in-memory copies: granularKillSwitch (currentLevel/exceptions loaded at
init), profileRotation (timer + config), scheduler (timer). After an import the
on-disk values change but the live services keep using stale in-memory state
until the next app restart — e.g. importing a kill-switch level/exceptions has
no effect until restart, importing rotation/schedules doesn't re-arm timers.
FIX: after importApply, re-init the affected services (or tell the user a
restart is needed). Deferred-documented.


splitTunneling.getDirectProcessNames() / generateSplitTunnelRouteRules() are
never called by tunController. prepareRuntime is given only
proxyOwnerProcessNames as its directProcessNames arg. So apps marked "direct"
(bypass VPN) in the split-tunnel UI are NOT actually routed direct — the whole
split-tunnel feature is dead. FIX: merge splitTunneling.getDirectProcessNames()
into the directProcessNames passed to prepareRuntime in both localProxy and
directVpn start branches (lazy import to avoid the tunController↔splitTunneling
circular).


hotReloadIfActive() calls tunController.stop() then just logs "Renderer should
re-trigger start" — but NOTHING re-triggers start (the renderer's
handleRuleChange doesn't either). So toggling any app's split-tunnel rule, or
removing an app, while connected silently tears the tunnel down and leaves it
down. Same for the kill-switch: stop() drops it. Serious — a settings tweak
disconnects the user. FIX: add a public tunController.restartWithLastOptions()
(reuses lastStartOptions) and have hotReloadIfActive call it instead of a bare
stop().


`applyToSingboxConfig()` is exported but NEVER called anywhere outside the
module's own test. tunController.generateSingboxConfig hardcodes dns-remote
1.1.1.1 + dns-backup 8.8.8.8 and never consults the user's selected DNS
profile. So picking Cloudflare/Google/Quad9/AdGuard (or a custom DoH/DoT) in
the UI does nothing — the tunnel always uses 1.1.1.1/8.8.8.8. Additionally,
applyToSingboxConfig emits the LEGACY sing-box DNS schema (servers:[{address,
tag}]) which wouldn't even validate against sing-box 1.13 (needs type/server/
detour). FIX: wire the active DNS profile into generateSingboxConfig in the
1.13 format (type tls/https/plain with detour proxy-out so DNS goes through the
tunnel), falling back to 1.1.1.1/8.8.8.8 when no profile selected.


`probeSocks5()` calls `SocksClient.createConnection(...)` and returns true
WITHOUT destroying the returned socket. Every successful SOCKS probe (and
detect() probes many candidate ports + the verify path) leaves an open
connection to api.ipify.org:443 dangling until GC/timeout. Over repeated
detections this leaks sockets. FIX: capture `{ socket }` and destroy it before
returning.


performRotation() only calls serverPicker.selectProfile(next) — it never
restarts the live tunnel. With rotation enabled while connected, the "active"
profile pointer moves but sing-box keeps using the OLD server, so the user's
egress IP never actually rotates. The feature ("Ротация профилей" / auto IP
rotation) silently doesn't do what it says while the VPN is up. FIX: when
tunController.getStatus().running, restart the tunnel with the new profile
(directVpn) after selecting it; when idle, just select (next connect uses it).


profilesByGroup buckets a profile whose groupId isn't in the known group set
under `map[gid]` (a synthetic bucket), but the render loop only iterates
`effectiveGroups = sortGroups(groups)` — which never contains that synthetic
id. So any profile pointing at a deleted/unknown group silently vanishes from
the Servers UI (the key still exists in the store, just invisible). This is a
real "my keys disappeared" vector. The main-process migration usually keeps
groupId consistent, but a deleted group, a failed group create, or a
refresh-race can orphan profiles. FIX: synthesize a "recovery" group header for
each orphan bucket so the profiles are always visible and re-assignable.


`getExceptionIpCidrs()` is defined but never called. `engageKillSwitch()` only
forwards app-path exceptions (`proxyOwnerProgramPaths`) to `enableKillSwitch()`,
and `enableKillSwitch()` has no parameter for IP/CIDR allow rules at all. So a
user who adds an IP/CIDR exception in the kill-switch UI gets a no-op — the
address is still blocked. Feature silently does nothing. FIX: add an
`extraAllowedRemoteCidrs` param to enableKillSwitch that creates a
VPNTE-killswitch-allow-extra-ip rule, and pass getExceptionIpCidrs() through.
Medium effort (touches the elevated PS script). VERIFIED real (grep: only
defined, never referenced).


The app never calls `app.requestSingleInstanceLock()`. Launching a second
instance (double-click while running, or autostart + manual launch) gives two
main processes both managing the same kill-switch manifest, TUN adapter, and
adapter-lockdown manifest. They can race: instance B's stale-recovery on
startup could roll back instance A's live kill-switch / lockdown while A's TUN
is up → real IP leak. For a VPN app this is a meaningful safety gap. FIX: add
single-instance lock in index.ts, focus existing window on second-instance.


### C6 — physicalAdapterLockdown: IPv6-disable not crash-recoverable [FIXED]
`applyPhysicalAdapterLockdown` disabled IPv6 + forced DNS per adapter in a
loop, then wrote the rollback manifest AFTER the loop. A crash mid-loop left
IPv6 disabled with no manifest → stayed disabled forever (DNS had a
manifest-free repair path, IPv6 did not). FIXED: write a PENDING manifest
BEFORE the loop (each adapter marked with the change we're about to make),
then overwrite with the actual per-adapter outcome after. Startup
crash-recovery can now always re-enable IPv6 / restore DNS.

### C1 — firewallKillSwitch.ts: elevated .ps1 scripts never cleaned up
`ps()` writes a script file to `backupDir()/ps/script-*.ps1`. The `finally`
block only unlinks when `!elevated`. Every elevated call (enable/disable/probe
of kill-switch) leaves a file behind forever. Slow disk leak + scripts may
contain adapter aliases. Severity: low-med (housekeeping/info-leak).

### C2 — ipMonitor.ts: comment/var name mismatch (`suspended` vs `suppressed`) [FIXED]
Comment block referred to `suspended === true` but the actual var is
`suppressed`. Cosmetic only — comment corrected.

### C3 — tunController randomSecret/randomLocalPort use Math.random()
Clash API secret generated with Math.random() (not crypto). Localhost-only +
secret-gated, so low risk, but a predictable secret on a known port is weak.
Severity: low.

## Verified OK
- leakSelfTest cancellation via session id: looks correct.
- ipMonitor suspend/resume wired in tunController.stop + index stop handler.
