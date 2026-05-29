# Code Audit — Findings Log

Deep manual audit of vpn-tunnel-enforcer main process. Status: COMPREHENSIVE PASS COMPLETE.

## Summary
18 issues found across the codebase. ALL fixed (B1-B3 + C1-C18) with tests
(133 → 179 tests). C2 was cosmetic (comment typo). Every main-process module
read in full; preload bridge + renderer store/Dashboard/Servers audited.
Status: COMPLETE.

---

# PASS 3 — DPI/TSPU circumvention research vs our config (2025-2026 intel)

Sources (rephrased, content rephrased for licensing compliance):
- [Lantern circumvention-corpus: Russia TSPU ECH direct block](https://corpus.lantern.io/findings/2025-niere-encrypted__russia-tspu-ech-direct-block/)
- [Lantern: GFW ESNI 4-byte segmentation](https://corpus.lantern.io/findings/2020-gfw-esni-blocking__four-byte-segmentation-defeats-gfw-esni/)
- [Lantern: AnyTLS padding scheme / protocol comparison](https://corpus.lantern.io/findings/2026-anon-anytls-anytls-sing-box-2026__anytls-protocol-comparison-performance-obfuscation/)
- [Lantern: stateless single-record SNI matcher limitation](https://corpus.lantern.io/findings/2023-niere-poster__gfw-single-record-sni-matcher-limitation/)

Key 2025-2026 facts:
1. **TSPU upgraded TCP reassembly.** TLS *record* fragmentation ALONE (our
   current `record_fragment: true`) is now often insufficient — the corpus
   notes TCP segmentation + TLS record fragmentation are needed *in
   combination* against ECH/SNI blocking. record_fragment is still useful but
   no longer a silver bullet.
2. **First TCP segment ≤4 bytes** (below the 5-byte TLS record header) defeats
   SNI/ESNI classifiers that can't reassemble across segments. Client-side
   this is a TCP-level split, distinct from TLS record fragmentation.
3. **Reality is the strongest VLESS obfuscation** (rated "high"); it embeds
   auth in a camouflage ClientHello to a real site. We correctly do NOT
   fragment Reality (would break its handshake) — that's right.
4. **AnyTLS / padding** is the TCP-only fallback when UDP is blocked, trading
   throughput for obfuscation. Not worth adding for us now (limited client
   support, large surface).
5. **Mux/multiplexing HURTS** under DPI — it makes flow patterns more
   distinguishable and breaks Reality's per-connection camouflage. We must
   never enable multiplex for Reality outbounds.

What our config already does RIGHT:
- uTLS (chrome fp) forced on every TLS outbound — avoids Go-stdlib ClientHello
  fingerprint that TSPU rate-limits. ✓
- Reality preserved & never fragmented. ✓
- record_fragment in stealth mode for non-Reality TLS. ✓ (but see N1)
- DNS tunnelled through proxy-out (no plaintext DNS leak). ✓
- IPv6 blocked to prevent leak. ✓

## Network findings (N-series)

### N1 — multiplex must be explicitly stripped from imported outbounds [planned]
We never SET multiplex, but a user-pasted/subscription outbound can ARRIVE
with a `multiplex: { enabled: true }` block (some panels ship it). Under DPI
that's actively harmful (point 5) and especially bad layered on Reality. We
should defensively delete `multiplex`/`mux` from the proxy outbound in
sanitizeProxyOutbound unless the user opts in. Low effort, config-safe.

### N2 — record_fragment alone is weakening; document + keep, don't over-trust [info]
Per point 1, record_fragment is no longer sufficient on its own against
upgraded TSPU. sing-box's client TLS doesn't expose a separate "first TCP
segment ≤4 bytes" knob in the stable outbound TLS object the way Xray's
`fragment` does, so we can't safely add TCP-segmentation without risking
config-validation failure / version drift. Decision: keep record_fragment,
do NOT invent unverified TLS fields (would break `sing-box check`), and lean on
Reality (point 3) as the primary bypass — which our parser already preserves.
Documented, no code change (correctness > cargo-culting unknown options).

### N3 — stealth uTLS fingerprint pool weak/biased [planned]
The stealth fp rotation hashes server:port:uuid with a weak `h*31+c` and picks
from only 4 fps [chrome,firefox,safari,edge]. `safari` on Windows is an
implausible fingerprint (no Safari on Windows) and stands out. Trim to
plausible-on-Windows fps [chrome, firefox, edge] and keep deterministic seed.



Focus: networking correctness, RU/DPI fitness, security, and code that works
through crutches or silently does nothing.

## D-series findings

### D7 — no warning when a foreign VPN intercepts our ping probes [FIXED]
User report: "другие норм пингуются, а выбранный всё равно криво", then after
the D6.5 fix still "почему кто-то нормально а кто-то нет" with a screenshot
showing wildly inconsistent pings (DE 46, SE 45, LV1 45, LV2 1, LV3 3, RU 3/4
…). Live diagnosis on the user's box (TTL + TCP-connect probes) proved the
numbers were ALL fake: a second VPN — **Happ** (FlyFrogLLC\Happ, Xray engine,
adapter `happ-tun` 172.18.0.1) — was running. Its TUN captured every
TCP-connect we make for latency measurement and answered locally, even to
non-routable RFC5737 TEST-NET addresses (203.0.113.77 / 198.51.100.55 both
"connected in 1 ms"). So per-server pings collapsed to the RTT of Happ's tun
stack (~1-46 ms jitter), not the real servers. Even 1.1.1.1 / 8.8.8.8 replied
"1 ms, TTL=128" — physically impossible from RU, conclusive proof of local
interception. NOT a bug in our probe (it's honest); no client can measure
correctly while another VPN owns the route.

FIX: surface it to the user.
  - New IPC `system:detect-foreign-vpn` reuses the existing locale-independent
    `detectForeignTun()` (os.networkInterfaces, ~1ms). Returns the foreign
    adapter descriptor when OUR tunnel is OFF; returns null when ours is ON
    (the competingTunDetector already raises a stronger route-conflict banner
    in that case, so we avoid a duplicate).
  - `useForeignVpn` hook polls it every 5 s while our tunnel is down;
    `foreignVpnFriendlyName` maps the raw adapter to a vendor label
    (Happ / Hiddify / WireGuard / OpenVPN / Xray-V2Ray / fallback).
  - `ForeignVpnBanner` renders a warning above the profile selector
    (Dashboard) and at the top of the Servers page: "Обнаружен другой VPN:
    Happ — пинг ненадёжен, закройте его полностью". Self-contained,
    auto-clears when the foreign adapter disappears.
  +7 tests (foreignVpnFriendlyName vendor mapping). 215 → 222.


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

### D6 — ping shows fake "1 ms" on every server + measures the wrong thing for RU [FIXED]
The Servers page showed "1 ms" on all servers including a Netherlands node —
physically impossible. Two root causes:
  (a) The offline probe ladder ran ICMP FIRST. Routers/gateways answer ICMP
      with "time<1ms" on behalf of hosts the VPN port can't actually reach, so
      every server looked alive at 1 ms even when TSPU had IP-blackholed it.
  (b) ICMP reachability ≠ "the obfuscation actually gets through". The real
      RU question is whether the VPN ENDPOINT accepts a connection (TSPU's
      main weapon is IP-blackholing known VPN IPs), which a TCP-connect to the
      actual port answers and ICMP does not.
FIX: reordered smartOfflinePing to TCP-connect-to-VPN-port FIRST → stealth
curl (disguised 443) → ICMP last. Added a sub-ms plausibility gate
(parseIcmpReply rejects "time<1ms" for non-loopback hosts — extracted as a
pure, tested function). Net effect: the number now reflects whether the server
is genuinely reachable from this network (the real "обход работает?" signal),
and a TSPU-blackholed server correctly shows offline instead of fake 1 ms.
The definitive bypass test remains "Проверить ключи" (TLS/Reality handshake,
keyHealthChecker), which the row UI already prioritises over raw ping.
+7 tests (parseIcmpReply).

### D6.5 — pingAll poisoned the active profile with tunnel-RTT, surviving disconnect [FIXED]
User report: "другие норм пингуются, а выбранный всё равно криво" (screenshot:
right-side list 16-817 ms realistic, but "Текущий профиль AE ОАЭ" pill 2 ms).
Two combined bugs (one main, two renderer):

(M) `serverPicker.pingAll`, when called while the tunnel was UP, measured a
    SINGLE tunnel-RTT (HTTPS GET to yandex/gosuslugi via the active outbound
    — typically 2-5 ms once Reality is warm) and stamped it onto the ACTIVE
    profile's persisted `ping`/`status`/`lastChecked` fields. The dropdown row
    (`ProfileSelectorInline`) reads `profile.ping` directly to render
    "· X ms" next to the protocol. After disconnect the bogus value stayed
    in the store forever — until the next OFFLINE pingAll, which the user
    never explicitly triggered for the active profile.
(R1) `ProfileSelectorInline.pingMs` (component state) wasn't reset on
    `tunRunning` transitions, so a value pinged WHILE connected (tunnel-RTT,
    rendered with "≈ " prefix) kept showing as plain "X ms" after disconnect
    (the prefix is gated on `tunRunning`, the value isn't).
(R2) `DashboardSide.pings` (right-list state) had the same staleness flaw,
    though it was less visible because the user usually re-pings the list.

FIX: 
  (M) `pingAll` while the tunnel is up is now a no-op on persisted state.
      The pill button still gets a live tunnel-RTT via its own `serversPingOne`
      IPC call (which goes through `tunnelHttpProbe`), but nothing ever lands
      in the store from that path. Per-server numbers are written only when
      the tunnel is DOWN — when they actually mean per-server latency.
  (M2) Added `clearStaleStoredPings` migration, run on every startup, that
      wipes `ping`/`status`/`lastChecked` from every saved profile. This
      cleans up data already poisoned by older builds and gives every
      session a clean baseline.
  (R1, R2) Both components now `setPingMs(null)` / `setPings({})` whenever
      `tunRunning` flips. The two ping modes (per-server when off,
      tunnel-RTT when on) never bleed into each other.
+7 tests (3 pingAll-tunnel-up + 4 clearStaleStoredPings). 208 → 215.

### D5 — geolocateAll: rate-limit-violating per-IP geo loop [FIXED]
Country labels were filled via ipapi.co one IP at a time, 3 concurrent with a
1.1s inter-batch sleep — i.e. ~2.7 req/s against a free tier the code's own
comment says is "~1 req/sec". On any sizeable subscription (the user has 112
keys) this tripped 429s and left most country labels empty. Crutch design.
FIXED: rewrote to resolve all hostnames→IPs in parallel (local DNS), then
geolocate via ip-api.com/batch (up to 100 IPs per POST, free, no key,
45 req/min) — two POSTs cover 200 servers, written back in a single store
update. Removed the now-unused GEOLOCATE_CONCURRENCY/DELAY constants. (ip-api
free tier is HTTP-only; the request carries only public server IPs, no secrets.)

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
