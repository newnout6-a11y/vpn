# Code Audit — Findings Log

Deep manual audit of vpn-tunnel-enforcer main process. Status: COMPREHENSIVE PASS COMPLETE.

## Summary
18 issues found across the codebase. ALL fixed (B1-B3 + C1-C18) with tests
(133 → 179 tests). C2 was cosmetic (comment typo). Every main-process module
read in full; preload bridge + renderer store/Dashboard/Servers audited.
Status: COMPLETE.

---

# PASS 4 — Pentest hardening, feature work, stability (S/F/L series)

Focus shifted from "visible bugs" to attack surface, a requested feature
(per-command VPN bypass), and long-running stability/logging.

### S1 — window navigation hijack + missing CSP [FIXED/security]
The main BrowserWindow had no setWindowOpenHandler and no will-navigate guard,
and there was no Content-Security-Policy. `webPageUrl` is read verbatim from a
subscription's `profile-web-page-url` HTTP header (vpnProfiles.ts) — provider-
controlled, not user — and rendered as a target=_blank link on the Servers
page. A hostile panel could navigate our trusted, preload-bearing window to a
phishing page or smuggle a custom scheme. FIX: pure tested
`classifyNavigation()` (allow-internal / open-external / block); wired into
setWindowOpenHandler + will-navigate + will-attach-webview block; strict CSP
via onHeadersReceived in packaged builds; the offscreen geo-block probe window
now runs sandbox:true + deny-all window-open. +8 tests.

### F1 — per-command VPN bypass (terminal commands route direct) [DONE/feature]
User wanted a single terminal command (curl/git/yt-dlp) to bypass the VPN
without exempting a whole installed app. sing-box matches `process_name` on
Windows and our split-tunnel pipeline already routes getDirectProcessNames() to
direct-out; the gap was the UI only accepting registry-discovered apps with a
real path. Added SplitTunnelApp.kind='process', normalizeProcessName() (pure,
tested — strips dir/quotes, appends .exe, lower-cases, rejects illegal chars),
addProcessName() (auto-direct, de-dup, re-arm), IPC split-tunnel:add-process,
preload bridge, and a "Команда мимо VPN" card on the Split Tunnel page. Honest
limitation documented: matches by executable name, not a single invocation
(true per-launch isolation needs binary copying). +11 tests.

### L1 — app.log grew unbounded (no rotation) [FIXED/stability]
Every IPC call logs at debug level and the logger only appended, so app.log
reached hundreds of MB over weeks (slow append queue, disk pressure, huge
diagnostics ZIP — hidden because getFullLogs only reads the 1 MB tail). FIX:
size-based rotation (5 MB to app.prev.log, one generation kept, total bounded
~2x cap); in-memory byte counter seeded by one stat() so the hot path never
stats per line; app.prev.log included in diagnostics with the same redaction.
+2 tests.

### F2 — overnight schedules were silently dead [FIXED]The Schedule page lets the user pick any start/end via <input type="time"> with
no validation. A natural "protect me overnight" entry (e.g. 22:00–06:00) was
silently inert: isScheduleActive used `current >= start && current < end`,
which is an empty set when start > end, so the VPN never came on, and
computeNextEvent put the stop event in the past. FIX: isScheduleActive now
handles wrap-past-midnight windows (active in the evening segment on a listed
day OR the morning segment whose window opened the previous listed day) and
rejects zero-length (start === end) windows; computeNextEvent pushes the stop
event to the next calendar day for overnight windows. +7 tests incl. evening/
morning/gap/zero-length and next-event timing; verified the overnight cases
fail against the old same-day-only logic.

### F3 — smart RU split-routing (real IP for RU services, VPN for the rest) [DONE/feature]
User wanted RU banks / gov portals / shops / maps to open with their REAL IP
while everything non-RU still sees the VPN — and explicitly NOT a naive ".ru"
TLD redirect. Implemented the same approach mature clients (Hiddify/Nekoray)
use, native to sing-box 1.13:
  - geoip-ru rule-set → route by DESTINATION IP country, so RU-hosted services
    go direct regardless of their domain/TLD (catches .com/.рф faces);
  - geosite-category-ru + category-gov-ru rule-sets → curated upstream RU
    domain lists (covers big properties incl. non-.ru domains);
  - remote .srs downloaded through proxy-out (GitHub raw is itself throttled in
    RU; tunnel is up by load time) and persisted via experimental.cache_file;
  - DNS correctness: a `dns-direct` (local) resolver + DNS rules binding the RU
    rule-sets to it, so RU domains resolve to their REAL RU IPs — otherwise the
    tunnelled DNS returns a foreign CDN node and geoip-ru misses;
  - optional maps sub-toggle (Yandex/2GIS/Google Maps tiles → direct) for real-
    location results ("карты по желанию");
  - user's own Domain Routing rules still evaluated BEFORE the smart-route
    rules, so explicit overrides win.
New pure module smartRoute.ts (rule-sets / route rules / DNS rules), gated by
settings.smartRuSplit + smartRuMapsDirect (off by default), wired into
generateSingboxConfig, with UI toggles in Settings. Verified the REAL generated
config passes `sing-box.exe check` (resources/sing-box.exe 1.13.8) via an
opt-in integration test (smartRouteCheck.itest.ts, RUN_SINGBOX_CHECK=1).
+17 unit tests (smartRoute pure generators + config integration). 250 → 267.

### F4 — availability check: "HTTP 200 ≠ доступно" + fragile geo-block regex [FIXED]
User report: the URL checker is "туповат" — a 200 OK was treated as "works",
but geo-blocked sites (Gemini, ChatGPT, …) return a healthy 200 whose body says
"not available in your country". The old detector regex-matched a handful of
English phrases on innerText — fragile (one wording change breaks it), narrow
(English only), and useless when the page is an SPA. Two concrete bugs:
  (a) `available = httpStatus < 500` treated 451 (Unavailable For Legal
      Reasons) and 403 as "available".
  (b) geo-block = 5-phrase English innerText regex.
FIX: new pure, tested geoBlockDetect module with layered signals, strongest
first:
  1. DIFFERENTIAL (reliable, language-independent): render the page through
     BOTH exits (foreign via TUN, local via the direct-out SOCKS port) and
     compare — local tiny vs foreign full, local redirect to a block-shaped
     URL, block marker present locally but not abroad. No phrase list needed.
  2. HARD HTTP: 451 → blocked outright; 403 on a short page → strong hint.
  3. FINAL-URL shape: /sorry, /unavailable, ?error=country_unsupported, …
     (language-independent).
  4. MARKER text (weak fallback, only when we can't compare — VPN off):
     broadened to many phrasings + EN/RU/ES/PT/DE/FR, but only TRUSTED on an
     interstitial-sized page so a long article quoting the phrase isn't
     flagged.
The offscreen probe now returns a structured PageSignal (final URL, title,
innerText sample+length, main-frame status) instead of a bare boolean; geo
determination moved to checkUrl orchestration (differential when tunnel is on,
single-page when off). deriveVerdict now reads the reliable geoBlocked flag:
tunnel-ok + direct-geo-blocked → "works-only-with-vpn"; VPN exit itself
geo-blocked → tell the user to switch server country. UI shows a distinct
"Гео-блок" state ("сеть пропускает, но сайт закрыт для региона"). +18 tests
(13 detector + 5 verdict). 267 → 285.

### F5 — verify routing works + pin IP-checkers to the VPN [DONE/feature]
Two related asks: (a) "how do I verify the per-site routing actually works?"
and (b) IP-checkers must always reflect the VPN IP and NOT be caught by the
RU-direct routing. Problem behind (b): smart RU split would send an RU-hosted
checker (2ip.ru, myip.ru, …) DIRECT, the page would show the REAL IP, and the
user would wrongly conclude "the VPN leaks".

FIX (b): IP_CHECKER_SUFFIXES (global + RU checkers) pinned to proxy-out as the
FIRST smart-route rule — ahead of every RU-direct rule — and their DNS pinned
to dns-remote (tunnelled), so an RU checker can't fall into the RU-direct DNS
rule and resolve to its RU node. Pure, unit-tested.

FIX (a): new routingSelfTest module + "Проверить маршрутизацию" button on the
Availability page. Measures the egress IP two ways at once: VPN path (Node
request captured by TUN → proxy-out) vs direct path (HTTP over the local
mixed-direct-in SOCKS port, hard-routed to direct-out = physical NIC). IPs
DIFFER → split is real; EQUAL → leak/misconfig. With smart-RU on, it surfaces
the RU egress and confirms RU hosts leave with the real IP. deriveRoutingVerdict
is pure + tested; per-domain routing correctness is asserted by the
smartRoute/config unit tests (+ real config passes `sing-box check`).
+9 tests. 285 → 294.

### F6 — IP-checker pin missed the APEX domain (2ip.ru still showed real IP) [FIXED]
User screenshot: opened `2ip.ru` with smart-RU on → it showed the real Beeline
Moscow IP + "Прокси: не используется". Root cause was a bug in F5's own pin:
sing-box `domain_suffix: ".2ip.ru"` matches `www.2ip.ru` but NOT the bare apex
`2ip.ru` (leading dot = "subdomains only"). The user opened the apex, it slipped
past the proxy-out pin, fell into the RU-direct rules (2ip.ru is RU-hosted via
geoip-ru/geosite), egressed direct, and leaked the real IP — the exact symptom
the pin was meant to prevent.
FIX: new pure `suffixListToMatcher()` emits BOTH an exact `domain` (apex) AND
the dotted `domain_suffix` (subdomains) for every pinned entry; applied to the
IP-checker pin, the maps list, and all smart-route DNS rules. We keep the
dotted suffix (not a dotless one) so we don't over-match `my2ip.ru`. Verified
the real config still passes `sing-box check`. +4 tests (apex regression +
suffixListToMatcher). 294 → 298.

### F7 (U1) — connection busy-state lost on tab switch → double-start breaks routing [FIXED]
User report (with diagnostic ZIP): "если во время включения соединения, переходишь
в другую вкладку, то при возвращении сбрасывается UI-статус, доступно ещё раз
запустить — запускаешь и всё ломается." Root cause: the connecting/disconnecting
transition flags were LOCAL React `useState` inside both `Dashboard.tsx` and
`HeroStatus.tsx`. Switching tabs unmounts those components, destroying the
`connecting=true` state. On return they remount with the flag reset to false;
because the tunnel is still mid-start, `tunRunning` is also still false, so the
power button rendered "Отключено"/"Включить" and stayed clickable. A second
click fired a second `startDirectVpn`/`startTun`. The main process DOES guard a
true double-start (`startInProgress`), but the racing start/save-settings churn
was enough to wedge routing — the diagnostics show two sing-box starts 29s
apart from the same session.
FIX: moved the transition into the GLOBAL Zustand store as
`connectionBusy: 'connecting' | 'disconnecting' | null` so it survives unmount.
Both `Dashboard` and `HeroStatus` now read it from the store (Hero maps it onto
its starting/stopping phase vocabulary), and both `handleConnect`/`handleStart`
and `handleDisconnect`/`handleStop` early-return if `connectionBusy` is already
set (re-entry guard against the double-click). App.tsx's `tun-status-changed`
handler clears `connectionBusy` on any definitive status (running/stopped/
killswitch-active) as a self-healing backstop so the button can never get stuck
on "Запускается…". `setTunRunning` deliberately does NOT auto-clear the flag —
the UI owns the clear so a 'running' status arriving before the start IPC
resolves can't prematurely re-enable the button. +4 store tests. 302 → 306.

### F8 — smart-RU remote rule-sets are FATAL on startup → real IP leaked while UI says "Подключено" [FIXED/critical]
User report (with diagnostic ZIP): "перестал скрывать IP вообще; блокировка
файрволом после отключения пропала." Screenshot showed the app "Подключено"
with a green power button while the displayed IP was `79.104.7.207` — the
user's REAL Beeline IP, not the VPN's. Root cause from `runtime-sing-box.json`
+ app-log:

```
FATAL start service: initialize rule-set[0]: geoip-ru: dial tcp 144.31.1.75:443: i/o timeout
                    | initialize rule-set[1]: geosite-category-gov-ru: i/o timeout
```

The smart-RU split feature (F3) registered geoip-ru + geosite-category-gov-ru
as sing-box `remote` rule-sets, downloaded THROUGH proxy-out at startup. In
sing-box a `remote` rule-set whose INITIAL fetch fails is a FATAL startup error
— the entire core refuses to run. So when the VPN server was slow to handshake
(or GitHub raw was throttled in RU), the 5s download timed out, sing-box exited
before the TUN inbound opened, the start path logged "TUN-адаптер не поднялся
за 5 с — kill-switch пропущен" and SKIPPED the firewall kill-switch (by design,
so as not to brick the internet on a failed start). Net result: no tunnel, no
kill-switch, real IP fully exposed — yet the renderer had optimistically set
tunRunning=true and showed "Подключено". A chicken-and-egg too: the rule-set
download NEEDS the tunnel, but the tunnel start was being GATED on that very
download. A routing nicety was taking down the core "hide my IP" function.

FIX (defence in depth):
1. **Bundle the .srs locally** (resources/geoip-ru.srs + geosite-category-gov-
   ru.srs, added to electron-builder extraResources). prepareRuntime stages
   them into the runtime dir next to sing-box.exe (copyResourceIfStale, same as
   the binaries).
2. **Load as `type: local`** (smartRoute.ts: new `ruleSetDir` option →
   smartRouteRuleSets emits `{type:'local', path}` instead of `{type:'remote',
   url, download_detour}`). A local file can't time out, so rule-set init can
   never again be a FATAL startup error.
3. **Fail-safe**: if ANY .srs can't be staged, prepareRuntime drops the feature
   for that run (forces smartRuSplit=false into generateSingboxConfig) so the
   tunnel still starts and everything safely egresses via proxy-out — never the
   old `remote` fallback that could re-introduce the fatal path.

Verified BOTH the remote-fallback and the local-rule-set configs pass the real
bundled `sing-box check` (smartRouteCheck.itest.ts, RUN_SINGBOX_CHECK=1),
including parsing the actual binary .srs. +5 tests (3 unit + 2 integration).
306 → 309.

Note on "firewall block after disconnect": that's the `firewallKillSwitch`
setting (already opt-in, default off; user has it on). It only "vanished"
because sing-box never started — once the tunnel starts cleanly the kill-switch
behaves per the setting again. Left as the optional extra; no code change.

### F9 — route-diagnostics screamed false "УТЕЧКА" because it was blind to smart-RU split + directVpn [FIXED]
User report (VPN now hides the IP correctly): "много непонятных записей" in the
diagnostics. Three were FALSE POSITIVES introduced by features the diagnostics
predate:
1. **"Прокси: Порт не отвечает" (red/fail)** — in directVpn mode there is NO
   local SOCKS proxy; sing-box IS the tunnel core. The check was probing a
   stale `proxyOverride` (127.0.0.1:10808, left from a past Happ-proxy session)
   and flagging it red. Fixed: when `connectionMode==='directVpn'` the proxy
   item is now informational ("Direct VPN (sing-box)"), not a probe.
2. **"Direct-out приложений: 9 записей" (red/fail)** — every "leaked" IP was
   Russian (77.88.21.24=api.passport.yandex.ru, 95.213.56.2=queuev4.vk.com,
   etc.) going direct because it matched geoip-ru/gov-ru — i.e. smart-RU split
   working EXACTLY as designed. The classifier didn't know about smart-RU and
   counted RU-direct as a leak. Fixed: `classifyDirectPublic` now buckets
   rule_set=geoip-ru/geosite-category-gov-ru direct-out hits as `smartRu`
   (informational when the feature is on), separate from genuine leaks and
   VPN-core process exclusions.
3. **sing-box log "errors" inflated** by benign `block-out: operation not
   permitted` lines — that's the core refusing a UDP listen socket for QUIC/
   HTTP3 we deliberately route to block-out on a tcp-only Reality outbound.
   Fixed: `isBenignBlockLine` excludes them from the error summary so a healthy
   session stops showing scary "errors:".

runLeakCheck now receives `connectionMode` + `smartRuSplit` from the IPC
handler and tray path. Extracted pure helpers (classifyDirectPublic,
isBenignBlockLine, extractRealErrors) and tested them against real log excerpts
from the user's diagnostic; verified the smart-RU test fails if the classifier
is reverted. +8 tests. 309 → 317.

Note: the WebRTC "local addresses" browser warning is NOT a false positive —
those are private LAN IPs that don't expose the public IP, and the warning
about a possible browser-level WebRTC leak is legitimately informational. Left
as-is.

### F10 — diagnostics cosmetics: "proxy-out: 0" on VLESS + raw DNS type numbers [FIXED]
User asked what the DNS / sing-box-log rows mean and what the yellow numbers
are. Two were genuine display bugs (the data was fine, the rendering lied):
1. **sing-box log "proxy-out: 0"** even on a fully working VLESS/Reality
   session. The counter regex was `outbound/(socks|http)[proxy-out]` — but in
   Direct VPN mode the tunnel outbound is vless/vmess/trojan/hysteria2, so it
   matched nothing. Diagnostics showed `proxy-out: 0; direct-out: 3` which
   looked like "nothing goes through the VPN" when the real log had 276
   vless[proxy-out] connections. Fixed: count ANY `outbound/<type>[proxy-out]`.
2. **DNS row "1: 104.20.23.154"** — the yellow `1:` is the DNS record Type.
   PowerShell `Resolve-DnsName | ConvertTo-Json` serializes the RecordType enum
   to its NUMERIC value (1=A, 28=AAAA), so the card showed `1:`/`28:` instead
   of `A:`/`AAAA:`. Fixed with a `dnsTypeName` map. (The yellow colour itself is
   just the neutral `info` status styling — not an error.)
Extracted pure helpers `summarizeSingboxLog` + `dnsTypeName`. +6 tests.
317 → 323.

Browser WebRTC protection — confirmed REAL, not a placeholder. applyBrowser
LeakProtection writes the Chromium `WebRtcIPHandlingPolicy=disable_non_proxied_
udp` policy key (HKLM/HKCU) for Yandex/Chrome/Edge/Brave/Vivaldi/Opera/Chromium,
patches each profile's Preferences (`webrtc.ip_handling_policy`,
multiple_routes_enabled=false, nonproxied_udp_enabled=false), and sets Firefox
user.js peerconnection prefs. Every change is backed up first (reg export +
file .bak) into a manifest; rollbackBrowserLeakProtection restores from it
(reg import / copy back, or delete if the value didn't exist before). Requires
a full browser restart to take effect (the warning text says so). The user
hadn't clicked it yet in the diagnostics, which is why the WebRTC warning
persisted.

### F11 — DNS over the tunnel was DoT → multi-second lookups ("каждое видео по несколько секунд") [FIXED/perf]
User: "всё медленнее, у Happ такого нет… как будто я подключаюсь к YouTube и он
с каждым видео проверяет, не РФ ли это — доходит до нескольких секунд. Happ
летает." Measured from the user's own sing-box log (16-20 diag):
DNS exchanges median **536ms, p90 ≈ 8s, worst 33s**; 122 of 289 lookups > 1s.
The very slow ones (5-33s) cluster right after connect.

Root cause: the tunnelled resolver was **DoT** (`type: tls`, Cloudflare/Google
on 853) detoured through the tcp-only Reality outbound. Every cold DNS lookup
opened a fresh TLS-in-TLS handshake; when a page load fires dozens of lookups
at once right after connect, the cold connection pool serialized them → multi-
second stalls. Happ "flies" because it uses one multiplexed resolver and
doesn't reopen a handshake per query.

FIX:
1. **DoT → DoH** for the tunnelled resolver (`type: https`). DoH multiplexes
   every concurrent query over ONE persistent HTTP/2 connection — after the
   first request there are no more handshakes. DoH on 443 is also harder for
   TSPU to throttle than DoT on 853. Pointed at the resolver IP directly
   (Cloudflare/Google serve DoH on the IP SAN) so no bootstrap lookup needed.
2. **plain-IP DNS profiles → `tcp`** (was `udp`). A tcp-only Reality outbound
   can't carry UDP and our route blocks UDP on it, so a `udp` DNS server
   detoured through proxy-out would silently fail; TCP DNS works and is already
   inside the Reality tunnel.
3. **cache_file always-on** (was gated on smart-RU). Persisting the DNS answer
   cache across restarts skips re-resolving every hostname on warm reconnects,
   directly cutting the cold-start storm.

Verified the real-world config shape (DoH fallback + local rule-sets + smart-RU
+ tcp-only Reality, MTU 1280) passes the bundled `sing-box check`. Tests
updated for https/tcp + always-on cache. 323 → 324.

Note: stealth-mode MTU 1280 (more fragmentation) is a deliberate anti-DPI knob
the user enabled; left as-is. The smart-RU geoip decision per destination is
inherent to the split feature the user asked for and is cheap now that DNS is
fast (median 84ms warm).

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
