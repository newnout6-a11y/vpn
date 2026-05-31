/**
 * Server Picker Service — profile management, ping measurement, and selection.
 *
 * Responsibilities:
 * - Store and manage server profiles in electron-store
 * - Measure latency (ping) to each server via TCP connection timing
 * - Ping all servers concurrently with a concurrency limit
 * - Parse subscription links (ss://, vmess://, vless://, trojan://) and URLs
 * - Group profiles by protocol
 * - Register IPC handlers for all ServerChannels
 */

import { app, dialog, ipcMain, type IpcMainInvokeEvent } from 'electron'
import { Socket } from 'net'
import { promises as dns } from 'dns'
import { writeFile } from 'fs/promises'
import { join } from 'path'
import { exec as execCb, execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import axios from 'axios'
import { randomUUID } from 'crypto'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import { resolveVpnProfiles, exportOutboundToUri, type VpnProfile } from './vpnProfiles'
import { settingsStore } from './settings'
import { tunController } from './tunController'
import {
  serverGroups,
  ensureManualKeysGroup,
  findGroupBySourceUrl,
  canonicalizeSubscriptionUrl,
  refreshGroup as refreshSubscriptionGroup
} from './serverGroups'
import type { ServerProfile } from '../shared/ipc-types'

// Promisified `exec` is used by the ICMP probe (Windows `ping.exe`). We
// take the buffer form because Russian Windows prints CP866-encoded output
// and we need the raw bytes for the locale-tolerant decoder below.
const exec = promisify(execCb)

// `execFile` is what we want for the stealth-curl probe — argv-style
// invocation avoids any shell-quoting issues with hostnames or query
// strings, which matters because we feed `--resolve <host>:443:<ip>` as a
// raw arg and don't want any cmd.exe to ever see it.
const execFile = promisify(execFileCb)

// ─── Persistent Store ────────────────────────────────────────────────────────

interface ServerPickerStore {
  profiles: ServerProfile[]
  activeProfileId: string | null
}

const store = new Store<ServerPickerStore>({
  name: 'server-picker',
  defaults: {
    profiles: [],
    activeProfileId: null
  }
})

// ─── Constants ───────────────────────────────────────────────────────────────

const PING_TIMEOUT_MS = 3500
const PING_CONCURRENCY = 5

// Neutral "is the tunnel responsive" probe targets, ordered RU-friendly first.
//
// The original list (Cloudflare trace + gstatic 204) is well-behaved on most
// networks but Russian university Wi-Fi and some federal-ISP TSPU configs
// outright drop 1.1.1.1 and gstatic.com. Result: every ping during a working
// tunnel returns "—" because neither URL ever responds.
//
// Mitigation: race a longer list with two RU-domestic anchors at the front.
//   - yandex.ru/favicon.ico     — Yandex is the largest RU search engine; no
//                                 operator blocks the homepage. The favicon
//                                 keeps the response tiny (~1 KB) so the RTT
//                                 we measure is dominated by tunnel cost,
//                                 not download time.
//   - gosuslugi.ru/favicon.ico  — Federal government services portal; every
//                                 RU ISP and university actively whitelists
//                                 it, so it survives even the strictest
//                                 captive-portal regimes.
//   - 1.1.1.1/cdn-cgi/trace     — Source-of-truth on non-RU networks; small
//                                 plain-text response (~30 bytes), no rate
//                                 limit, allow-listed almost everywhere
//                                 globally.
//   - gstatic.com/generate_204  — 204-No-Content backup via Google.
//
// The probe races them in parallel (see `tunnelHttpProbe`), so adding more
// URLs cannot make a "Ping all" slower; it can only make it faster on
// networks where some endpoints are blocked.
const TUNNEL_PROBE_URLS = [
  // RU-friendly endpoints (almost never blocked, even on uni Wi-Fi):
  'https://yandex.ru/favicon.ico',
  'https://www.gosuslugi.ru/favicon.ico',
  // Then the global fallbacks. Keep them — they're the source of truth
  // when the user is on a non-RU network.
  'https://1.1.1.1/cdn-cgi/trace',
  'https://www.gstatic.com/generate_204'
] as const

// Cache the last tunnel-probe result for a short window so a `pingAll`
// sweep across N profiles doesn't fan out into N identical requests
// against the same CDN (the tunnel itself is the bottleneck — every
// profile would otherwise report the same number anyway).
//
// We deliberately use a **shorter** TTL when caching a *failure*. The
// previous fix bumped the success TTL to 3.5 s, but applied the same
// window to negative results — meaning a single transient failure
// (network blip, captive-portal interstitial) made the next ~3.5 s of
// pings all return null even after the situation recovered. Tunnel
// probing is reactive on user action and we want it to feel snappy when
// connectivity comes back: a 1.5 s negative cache is enough to dedupe a
// `pingAll` sweep but short enough that the user never has to wait more
// than one extra click to see "the network is back".
const TUNNEL_PROBE_SUCCESS_CACHE_MS = 3500
const TUNNEL_PROBE_FAILURE_CACHE_MS = 1500
let tunnelProbeCache: { value: number | null; at: number } | null = null

// Per-URL timeout for the tunnel probe race. 4 s covers any reasonable
// global RTT plus TLS handshake jitter — anything longer means the URL is
// effectively dead and another racer should already have won.
const TUNNEL_PROBE_URL_TIMEOUT_MS = 4000

// ICMP / TCP timeouts for the offline (VPN-off) ladder. Kept short on
// purpose: the user wants snappy "Ping all" feedback, and DPI-blocked hosts
// usually fail fast (RST) or never respond at all (drop). 1.5 s is the
// sweet spot between "give a slow link a chance" and "don't make the UI
// hang on dead servers".
const ICMP_PROBE_TIMEOUT_MS = 1500

// ─── Ping Measurement ────────────────────────────────────────────────────────

/**
 * Measures latency to a server, with two paths:
 *
 *   1. VPN OFF → smart offline ladder. Plain TCP-connect to known VPN IPs
 *      gets blackholed at the firewall on Russian university nets and
 *      similar TSPU-policed networks: the operator instant-RSTs anything
 *      that looks like a VPN endpoint, so every server shows "—".
 *      `smartOfflinePing` tries ICMP first (rarely blocked, no SNI on the
 *      wire), then falls back to plain TCP — see its own JSDoc.
 *
 *   2. VPN ON → race a list of HTTPS probes through the tunnel. Whichever
 *      one returns first wins. RU-friendly endpoints (yandex.ru,
 *      gosuslugi.ru) are listed first; global fallbacks come after.
 *
 * Returns latency in ms or null if the server is fully unreachable.
 */
export function pingServer(host: string, port: number): Promise<number | null> {
  return tunController.getStatus().running
    ? tunnelHttpProbe()
    : smartOfflinePing(host, port)
}

/**
 * Tunnel-aware RTT measurement via HTTPS GET to a neutral CDN.
 *
 * The Node `axios` request goes through the OS kernel network stack,
 * which — with TUN strict_route + auto_route active — is captured by
 * sing-box and dispatched through `proxy-out`. So whatever number this
 * function returns is the real round-trip cost of the *tunnel* (TLS
 * handshake + GET request + response from the CDN), not just a fake
 * "connect" event from sing-box's local SYN hijack.
 *
 * Why we no longer probe `host:port` of the picker entry through the
 * tunnel: when `host` is the active VPN endpoint (the most common case
 * — users ping the server they're connected to), the connection turns
 * into a self-loop. sing-box dispatches the connect via vless to the
 * same upstream IP, vless tries to dial that IP locally, and the chain
 * stalls until our 5 s timeout. Confirmed in user diagnostics: every
 * ping during an active tunnel returned `ms: 5000` followed by
 * `Пинг … не прошёл`.
 *
 * Strategy: race all probe URLs concurrently and take the first one that
 * resolves. This shaves up to (N-1) * timeout off per "Ping all" call
 * when one of the URLs is firewall-blocked but others work — which is
 * exactly the scenario on RU university Wi-Fi where Cloudflare and
 * gstatic are dropped but Yandex / Gosuslugi sail through.
 *
 * Caches the winning result for a few seconds so back-to-back pingAll
 * sweeps don't fire identical requests against the same CDN (the tunnel
 * itself is the bottleneck — every profile would return the same number
 * anyway).
 */
export async function tunnelHttpProbe(): Promise<number | null> {
  const cached = tunnelProbeCache
  if (cached) {
    // Asymmetric TTL: short window for a cached failure (so we react
    // quickly when the network recovers), longer window for a cached
    // success (so a pingAll sweep doesn't fan out into N identical
    // CDN hits).
    const ttl = cached.value == null
      ? TUNNEL_PROBE_FAILURE_CACHE_MS
      : TUNNEL_PROBE_SUCCESS_CACHE_MS
    if (Date.now() - cached.at < ttl) return cached.value
  }

  // Fire every probe in parallel. `validateStatus < 500` accepts any
  // success/redirect/client-error response — generate_204 returns 204,
  // the trace endpoint returns 200, favicons return 200 — all count as
  // "the tunnel made it through". `Connection: close` ensures we measure
  // a fresh round-trip rather than the warmth of a pooled TLS session.
  const start = Date.now()
  const races = TUNNEL_PROBE_URLS.map(url =>
    axios
      .get(url, {
        timeout: TUNNEL_PROBE_URL_TIMEOUT_MS,
        validateStatus: status => status < 500,
        headers: { 'Cache-Control': 'no-cache', Connection: 'close' }
      })
      .then(() => Date.now() - start)
  )

  try {
    // Promise.any is native in Node 18+; this project targets Electron with
    // Node ≥ 18, so no polyfill needed. First successful response wins; the
    // rest keep going harmlessly until their per-request timeout fires.
    const ms = await Promise.any(races)
    tunnelProbeCache = { value: ms, at: Date.now() }
    return ms
  } catch {
    // All racers rejected — Promise.any throws AggregateError. The tunnel
    // is genuinely unreachable, or every probe URL is blocked on this
    // network (vanishingly unlikely with four geographically diverse
    // anchors, but we cache the negative result either way so we don't
    // hammer the network repeatedly).
    tunnelProbeCache = { value: null, at: Date.now() }
    return null
  }
}

/**
 * Multi-strategy "is this VPN server alive at all" probe used when the
 * tunnel is OFF. Tries each method in order, returns the first successful
 * latency number.
 *
 * Order is chosen for DPI safety:
 *
 *   1. ICMP echo (Windows ping.exe). Most university and corporate nets
 *      allow ICMP to arbitrary hosts; ICMP packets carry no SNI / TLS
 *      ClientHello and so cannot be IP-blackholed by a TSPU box that
 *      pattern-matches on "known VPN front" SNI strings. Stealthiest
 *      check we can do.
 *   2. Plain TCP-connect (no TLS handshake). Some firewalls deny ICMP
 *      but allow TCP on common ports. SYN/SYN-ACK alone still does NOT
 *      put server_name on the wire, so it's safe from SNI-based
 *      blackholing.
 *   3. Stealth-TCP probe via curl `--resolve`: a regular HTTPS request
 *      to `yandex.ru` on the wire (so the firewall sees a domain it
 *      can't block), but with DNS overridden so the actual TCP
 *      destination is the VPN server's IP. We read curl's
 *      `%{time_connect}` writeout — the SYN/SYN-ACK round-trip — and
 *      stop caring once the TLS handshake fails (cert mismatch is
 *      expected). This rung exists for hostile networks where BOTH
 *      ICMP and direct outbound TCP to the VPN port are blackholed
 *      (Beeline dorm Wi-Fi was the field-report that motivated it):
 *      the stateful firewall lets the request through because it sees
 *      a ClientHello to yandex.ru, and we get a real RTT measurement
 *      against the VPN endpoint anyway.
 *
 * We deliberately do NOT add a normal TLS-handshake rung here. That
 * would put the **VPN's actual** `server_name` in plaintext during
 * ClientHello, and Russian TSPU is known to IP-blackhole the destination
 * for ~10 minutes the moment it spots a known VPN-front SNI. Killing the
 * user's internet for 10 minutes because they pressed the Ping button is
 * the bug we're specifically avoiding. (The stealth rung above is fine
 * because the SNI it leaks is `yandex.ru` — a domain no operator can
 * afford to block.)
 */
async function smartOfflinePing(host: string, port: number): Promise<number | null> {
  // Rung order is chosen so the number the user sees reflects REAL endpoint
  // reachability under RU conditions, not a meaningless router echo.
  //
  // 1. TCP-connect to the actual VPN port. This is the strongest cheap
  //    signal: it proves the VPN endpoint accepts a connection from THIS
  //    network. If TSPU has IP-blackholed the server (the common RU failure),
  //    the SYN gets no SYN-ACK and this fails — correctly reporting the
  //    server as unreachable. No SNI/TLS on the wire, so it's DPI-safe.
  //    (ICMP used to be first, but routers answer ICMP on behalf of dead
  //    hosts and return bogus "<1 ms" for servers the VPN port can't reach —
  //    that's the fake "1 ms на всех серверах" the user reported.)
  const tcp = await plainTcpPing(host, port)
  if (tcp != null) return tcp

  // 2. Disguised HTTPS to yandex.ru that actually targets our VPN host.
  //    Works on hostile nets that blackhole direct TCP to the VPN port but
  //    let port-443 traffic through because the SNI says yandex.ru.
  const stealth = await stealthTcpProbe(host, port)
  if (stealth != null) return stealth

  // 3. ICMP echo — last resort. Weakest signal (routers answer for dead
  //    hosts), so we only trust it when both TCP rungs failed AND it returns
  //    a plausible RTT. icmpPing itself rejects implausible sub-ms replies
  //    for non-loopback hosts.
  const icmp = await icmpPing(host, ICMP_PROBE_TIMEOUT_MS)
  if (icmp != null) return icmp

  return null
}

/**
 * ICMP echo via the system `ping.exe`. Windows-only; returns null on any
 * non-Windows platform so callers can fall through to the TCP probe.
 *
 * We shell out to `ping.exe -n 1 -w <ms> <host>` rather than open a raw
 * ICMP socket because:
 *   - Raw sockets require admin / SeImpersonatePrivilege on Windows,
 *     which we don't have at app launch.
 *   - `ping.exe` is on every Windows install since XP, no extra deps.
 *
 * Locale handling is the awkward part: Russian Windows prints output in
 * CP866, so the byte sequence for "время" doesn't decode as UTF-8. The
 * `decodeMaybeCp866` helper handles both encodings; the regex matches
 * either the English "time=53ms" or the Russian "время=53мс" form.
 */
/**
 * Conservative allow-list for values we pass to ping.exe as a host argument.
 * Accepts IPv4, bracketed/bare IPv6, and DNS hostnames (letters, digits,
 * dots, hyphens). Rejects anything with whitespace or shell metacharacters —
 * defence in depth on top of the execFile (no-shell) invocation, and a way to
 * skip spawning a process for obviously-bad input from imported subscriptions.
 */
export function isProbablyHostOrIp(host: string): boolean {
  const h = String(host || '').trim()
  if (!h || h.length > 255) return false
  // No shell metacharacters / whitespace ever.
  if (/[\s&|;`$<>(){}[\]"'\\^%!]/.test(h)) return false
  // Bare IPv6 (contains a colon) — allow the hex+colon shape only.
  if (h.includes(':')) return /^[0-9a-fA-F:]+$/.test(h)
  // IPv4 or hostname: letters, digits, dots, hyphens.
  return /^[a-zA-Z0-9.-]+$/.test(h)
}

async function icmpPing(host: string, timeoutMs: number): Promise<number | null> {
  if (process.platform !== 'win32') return null
  // Hard gate: only ever hand a clean hostname/IP to ping.exe. `host` comes
  // from imported subscription content (outbound.server), so a malicious
  // subscription could otherwise smuggle shell metacharacters. We also use
  // execFile (no shell) below as defence-in-depth, but reject anything that
  // isn't a plausible host up front so we never even spawn the process for
  // garbage input.
  if (!isProbablyHostOrIp(host)) return null
  try {
    // `encoding: 'buffer'` keeps the raw bytes — we decode below. The
    // outer `timeout` is a safety net in case ping.exe itself hangs;
    // ping's own `-w` is the per-echo deadline. execFile (NOT exec) so the
    // arguments are passed to ping.exe directly without a cmd.exe shell —
    // no command-injection surface from `host`.
    const { stdout } = await execFile(
      'ping.exe',
      ['-n', '1', '-w', String(Math.max(1, Math.floor(timeoutMs))), host],
      { windowsHide: true, timeout: timeoutMs + 1500, encoding: 'buffer', maxBuffer: 64 * 1024 }
    )
    const text = decodeMaybeCp866(stdout as unknown as Buffer)
    return parseIcmpReply(text, host)
  } catch {
    // Non-zero exit (timeout / unreachable / DNS failure) — let the next
    // rung in the ladder try.
    return null
  }
}

/**
 * Pure parser for `ping.exe` output. Exported for testing. Returns the RTT in
 * ms, or null when the output doesn't show a genuine reply from the
 * destination. Implements the anti-fake-"1 ms" gates:
 *   - require a canonical "Reply from / Ответ от" line (ping exits 0 even on
 *     gateway "unreachable" replies);
 *   - reject if any unreachable/TTL-expired marker is present;
 *   - reject sub-millisecond "time<1ms" for non-loopback hosts (that's a LAN
 *     hop to the router, never a real RTT to a remote VPN server).
 */
export function parseIcmpReply(text: string, host: string): number | null {
  const echoOk = /(?:Reply from|Ответ от|Ответ из)\s+/i.test(text)
  if (!echoOk) return null

  if (/(?:Destination .*unreachable|Заданный узел недоступен|Сеть недоступна|Превышен интервал)/i.test(text)) {
    return null
  }

  const isLoopback = /^127\./.test(host) || host === '::1' || host === 'localhost'
  const ltMatch = text.match(/(?:time|время)\s*<\s*1\s*(?:ms|мс)/i)
  if (ltMatch && !isLoopback) return null

  // English: "time=53ms" / "time<1ms" / "time=1.2 ms"
  // Russian: "время=53мс" / "время<1мс"
  const m = text.match(/(?:time|время)\s*[<=]\s*([0-9.]+)\s*(?:ms|мс)/i)
  if (m) return Math.max(1, Math.round(Number(m[1])))
  // Some Russian locales emit a comma decimal separator.
  const m2 = text.match(/(?:time|время)\s*[<=]\s*([0-9,]+)\s*(?:ms|мс)/i)
  if (m2) return Math.max(1, Math.round(Number(m2[1].replace(',', '.'))))
  return null
}

/**
 * Decode `ping.exe` output, tolerating both UTF-8 (English Windows) and
 * CP866 (default Russian Windows console). We try UTF-8 first because
 * that's the cheap path; if it doesn't contain the marker bytes we expect
 * for either locale, we re-decode the buffer treating bytes 0x80-0xFF as
 * CP866 cyrillic.
 *
 * No external dep: `iconv-lite` is not in package.json and pulling it in
 * just for this one path isn't worth the install footprint. The mapping
 * we need is a tiny window of CP866 (just the Cyrillic block), so a
 * hand-rolled table is both smaller and easier to audit.
 */
function decodeMaybeCp866(buf: Buffer): string {
  // Fast path: English Windows already prints UTF-8-compatible ASCII for
  // the digits and "time=" markers. If we can match either locale word
  // already, no re-decode needed.
  const utf8 = buf.toString('utf8')
  if (/(?:time|время)\s*[<=]/i.test(utf8)) return utf8

  // CP866 → Unicode for the Cyrillic block:
  //   0x80-0x8F → U+0410-U+041F  (А..П, uppercase)
  //   0x90-0x9F → U+0420-U+042F  (Р..Я, uppercase)
  //   0xA0-0xAF → U+0430-U+043F  (а..п, lowercase)
  //   0xE0-0xEF → U+0440-U+044F  (р..я, lowercase) — "время" needs this
  // ASCII bytes < 0x80 pass through unchanged. Everything else maps to
  // '?' since we only care about the regex hit on "время".
  const out: number[] = []
  for (const b of buf) {
    if (b < 0x80) out.push(b)
    else if (b >= 0x80 && b <= 0x8F) out.push(0x410 + (b - 0x80))
    else if (b >= 0x90 && b <= 0x9F) out.push(0x420 + (b - 0x90))
    else if (b >= 0xA0 && b <= 0xAF) out.push(0x430 + (b - 0xA0))
    else if (b >= 0xE0 && b <= 0xEF) out.push(0x440 + (b - 0xE0))
    else out.push(0x3F) // '?'
  }
  return String.fromCodePoint(...out)
}

/**
 * Plain TCP-connect timing. Returns the SYN→SYN-ACK round-trip in ms or
 * null on connect failure / timeout. Used as the second rung of
 * `smartOfflinePing` and kept exported-by-position so future callers can
 * still get at it directly if they really want a TCP-only measurement.
 *
 * Critically: no TLS, no data, no SNI. We just see if the remote port
 * answers. Anything more (TLS handshake) would leak server_name and
 * trigger TSPU-style IP blackholing for ~10 minutes.
 */
function plainTcpPing(host: string, port: number): Promise<number | null> {
  return new Promise((resolve) => {
    const socket = new Socket()
    const start = Date.now()
    let done = false
    const finish = (value: number | null) => {
      if (done) return
      done = true
      socket.removeAllListeners()
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(PING_TIMEOUT_MS)
    socket.once('connect', () => finish(Date.now() - start))
    socket.once('timeout', () => finish(null))
    socket.once('error', () => finish(null))
    socket.connect(port, host)
  })
}

/**
 * "Stealth TCP probe" — measures TCP connect-time to the target VPN
 * host:port while looking like a regular HTTPS request to yandex.ru on
 * the wire. We use curl's `--resolve` to override DNS for one specific
 * (host, port) tuple, point yandex.ru at the VPN server's IP, then race
 * the request. We do NOT care about the response body — we read curl's
 * `%{time_connect}` writeout, which is the SYN/SYN-ACK round trip.
 *
 * Why this works on hostile firewalls (e.g. Beeline dorm Wi-Fi where
 * BOTH ICMP and direct outbound TCP to the VPN port get blackholed):
 *   - The TCP destination (VPN IP, port 443/etc) is the same as a
 *     regular VPN handshake would use, but the operator's stateful
 *     firewall sees a ClientHello with `server_name = yandex.ru` and
 *     happily lets it through — yandex is a domain they can never
 *     afford to block.
 *   - TLS handshake will fail server-side (the VPN server doesn't have
 *     a yandex.ru certificate) but `time_connect` is reported by curl
 *     *before* TLS even starts, immediately after SYN-ACK. So we pull
 *     out the RTT we wanted and bail before any handshake noise can
 *     affect the measurement.
 *   - curl prints the writeout regardless of exit code (cert errors,
 *     TLS errors, even some timeouts). We just parse stdout and don't
 *     trust the exit status.
 *
 * Returns ms or null. Hard-bounded at ~2.5 s by curl's own timeouts;
 * the outer execFile timeout is a belt-and-suspenders deadline. No
 * fallback if curl is missing — every Windows install has it shipped
 * since 1809 (October 2018), well before our minimum supported OS.
 *
 * Windows-only on purpose: macOS/Linux users aren't behind RU TSPU and
 * the existing ICMP/TCP rungs cover their needs without us having to
 * audit `curl`'s flags on every distro.
 */
async function stealthTcpProbe(host: string, port: number): Promise<number | null> {
  if (process.platform !== 'win32') return null
  // We always disguise as yandex.ru:443 regardless of the VPN's actual
  // port. The firewall's stateful inspection only allows port 443 for
  // "ordinary" HTTPS anyway, so probing on 443 (and getting back a
  // truthful TCP-connect time to the VPN host's IP on 443) is the most
  // permissive path and the closest analogue to a real ClientHello
  // request. We accept the small caveat that we measure host:443 even
  // when the VPN listens on, say, 8443 — for the purpose of "is this
  // host reachable from this hostile network at all" that's still a
  // strictly better signal than null.
  void port
  try {
    const args = [
      '-sS',
      '-o', 'NUL',
      '-w', '%{time_connect}',
      '--max-time', '2.5',
      '--connect-timeout', '2',
      '--resolve', `yandex.ru:443:${host}`,
      'https://yandex.ru:443'
    ]
    const { stdout, stderr } = await execFile('curl.exe', args, {
      windowsHide: true,
      timeout: 4000,
      encoding: 'utf8',
      maxBuffer: 64 * 1024
    })
    void stderr
    // %{time_connect} is in seconds with decimal, e.g. "0.142315".
    // Trim, parse, convert to integer ms. Reject NaN / non-positive.
    const seconds = parseFloat(String(stdout).trim())
    if (!Number.isFinite(seconds) || seconds <= 0) return null
    return Math.max(1, Math.round(seconds * 1000))
  } catch (err: unknown) {
    // curl exits non-zero on cert mismatch (60), TLS handshake error
    // (35), and timeout (28) — **all expected** here, since the VPN
    // server doesn't actually serve a yandex.ru cert. Node's
    // promisified `execFile` throws on non-zero exit, but it still
    // attaches the full stdout/stderr buffers to the error object. The
    // writeout we care about is in `err.stdout`, so we try to recover
    // it before giving up.
    try {
      const out =
        err && typeof err === 'object' && 'stdout' in err
          ? String((err as { stdout: unknown }).stdout ?? '')
          : ''
      const seconds = parseFloat(out.trim())
      if (Number.isFinite(seconds) && seconds > 0) {
        return Math.max(1, Math.round(seconds * 1000))
      }
    } catch {
      /* fall through to null */
    }
    return null
  }
}

/**
 * Pings all servers concurrently with a concurrency limit.
 * Updates ping/status/lastChecked fields for each profile.
 */
export async function pingAll(): Promise<ServerProfile[]> {
  const profiles = getProfiles()
  const now = Date.now()

  // When the tunnel is UP, a per-server ping is meaningless: every probe goes
  // through the same tunnel and returns the SAME round-trip number — the
  // tunnel itself is the bottleneck, not the remote endpoint. We MUST NOT
  // stamp that number onto any profile's stored .ping, because:
  //   1. it would poison the dropdown / right-list UI which read profile.ping
  //      directly (e.g. ProfileSelectorInline shows " · X ms" for the active
  //      profile from the stored value);
  //   2. after disconnect the stale value persists and the user sees a fake
  //      ~2 ms latency for the active profile while every other profile shows
  //      a realistic number — the exact "выбранный всё равно криво" symptom.
  //
  // So while connected: do nothing to the persisted profile state. The pill
  // button in ProfileSelectorInline and the LiveTraffic widget already give
  // the user a live tunnel-RTT readout via separate IPC calls; pingAll only
  // exists for offline per-server comparison.
  if (tunController.getStatus().running) {
    return profiles
  }

  // Process in batches of PING_CONCURRENCY
  for (let i = 0; i < profiles.length; i += PING_CONCURRENCY) {
    const batch = profiles.slice(i, i + PING_CONCURRENCY)
    const results = await Promise.all(
      batch.map((profile) => pingServer(profile.server, profile.port))
    )

    for (let j = 0; j < batch.length; j++) {
      const idx = i + j
      const latency = results[j]
      profiles[idx] = {
        ...profiles[idx],
        ping: latency,
        status: latency !== null ? 'online' : 'offline',
        lastChecked: now
      }
    }
  }

  saveProfiles(profiles)
  return profiles
}

// ─── Geolocation ────────────────────────────────────────────────────────────

/**
 * Resolve a hostname to its first IPv4 address. Returns null on any failure;
 * we don't want geolocation hiccups to throw out of the picker pipeline.
 */
async function resolveHostIp(host: string): Promise<string | null> {
  if (!host) return null
  // Already an IPv4 — skip DNS.
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return host
  try {
    const records = await dns.resolve4(host)
    return records[0] || null
  } catch {
    try {
      const lookup = await dns.lookup(host, { family: 4 })
      return lookup.address || null
    } catch {
      return null
    }
  }
}

/**
 * Resolve many hostnames to IPv4 in parallel (bounded). DNS is local and
 * fast, so a modest concurrency is fine. Returns a Map host→ip (missing
 * entries = resolution failed).
 */
async function resolveHostsToIps(hosts: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>()
  const unique = [...new Set(hosts.filter(Boolean))]
  const CONCURRENCY = 8
  for (let i = 0; i < unique.length; i += CONCURRENCY) {
    const batch = unique.slice(i, i + CONCURRENCY)
    const ips = await Promise.all(batch.map(h => resolveHostIp(h)))
    batch.forEach((h, idx) => { if (ips[idx]) out.set(h, ips[idx] as string) })
  }
  return out
}

/**
 * Bulk-geolocate IPs via ip-api.com's batch endpoint: up to 100 IPs per
 * POST, free, no API key, 45 requests/min. This replaces the previous
 * per-IP ipapi.co loop, which fired 3 concurrent requests against a "~1
 * req/sec" free tier and got rate-limited (429) on any sizeable
 * subscription — leaving most country labels empty. Two batch POSTs now
 * cover 200 servers.
 *
 * ip-api.com is HTTP-only on the free tier (HTTPS is paid). That is
 * acceptable here: the request carries only public server IPs (no user
 * data, no secrets) and the response is advisory UI metadata. Returns a
 * Map ip→country (missing = lookup failed / private IP).
 */
async function batchGeolocateIps(ips: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>()
  const unique = [...new Set(ips.filter(Boolean))]
  const CHUNK = 100
  for (let i = 0; i < unique.length; i += CHUNK) {
    const chunk = unique.slice(i, i + CHUNK)
    try {
      // `fields` trims the response to just what we need. `query` echoes the
      // IP back so we can map results to inputs regardless of order.
      const resp = await axios.post(
        'http://ip-api.com/batch?fields=status,country,query',
        chunk,
        { timeout: 10000, headers: { 'Content-Type': 'application/json' } }
      )
      const rows = Array.isArray(resp.data) ? resp.data : []
      for (const row of rows) {
        if (row && row.status === 'success' && row.query && typeof row.country === 'string' && row.country.trim()) {
          out.set(String(row.query), row.country.trim())
        }
      }
    } catch (err) {
      logEvent('debug', 'server-picker', 'batch geolocate chunk failed', { size: chunk.length, err: (err as Error)?.message })
      // Leave this chunk's countries empty — the next pass retries.
    }
    // Stay well under 45 req/min even with many chunks.
    if (i + CHUNK < unique.length) await new Promise(r => setTimeout(r, 1500))
  }
  return out
}

/**
 * Background pass that fills in `country` for every picker profile that
 * doesn't have one yet. Idempotent: if all profiles are tagged it returns
 * immediately.
 *
 * Pipeline: resolve all pending hostnames → IPs (parallel, local DNS) →
 * one ip-api.com/batch POST per 100 IPs → write countries back in a single
 * store update. Far fewer network calls than the old per-IP loop and no
 * free-tier rate-limit dance.
 *
 * Why we do this server-side (in main) and not via a client probe:
 *   1. The Dashboard side panel never issues per-row probes, so country
 *      labels there were always empty for subscriptions whose names don't
 *      include a country word.
 *   2. Keeping the lookup behind the picker store means every UI that reads
 *      `profile.country` gets the populated value uniformly.
 *
 * Triggered after addFromInput() and on app start.
 */
let geolocateInFlight = false
export async function geolocateAll(opts: { force?: boolean } = {}): Promise<void> {
  if (geolocateInFlight) return
  geolocateInFlight = true
  try {
    const todo = getProfiles().filter(p => opts.force || !p.country)
    if (!todo.length) return

    logEvent('info', 'server-picker', 'geolocate pass started', {
      total: getProfiles().length,
      pending: todo.length,
      force: Boolean(opts.force)
    })

    // 1. host → ip for every pending profile.
    const hostToIp = await resolveHostsToIps(todo.map(p => p.server))
    // 2. ip → country in bulk.
    const ipToCountry = await batchGeolocateIps([...hostToIp.values()])

    // 3. Write back in one pass. Re-read the store first — pingAll/select
    //    can mutate concurrently while we were on the network.
    const current = getProfiles()
    let updated = 0
    let dirty = false
    for (const profile of todo) {
      const ip = hostToIp.get(profile.server)
      if (!ip) continue
      const country = ipToCountry.get(ip)
      if (!country) continue
      const idx = current.findIndex(p => p.id === profile.id)
      if (idx === -1) continue
      if (current[idx].country !== country) {
        current[idx] = { ...current[idx], country }
        dirty = true
        updated++
      }
    }
    if (dirty) saveProfiles(current)

    logEvent('info', 'server-picker', 'geolocate pass finished', {
      pending: todo.length,
      updated
    })
  } catch (err) {
    logEvent('warn', 'server-picker', 'geolocate pass failed', err)
  } finally {
    geolocateInFlight = false
  }
}

// ─── Profile Management ──────────────────────────────────────────────────────

/**
 * One-time migration from the legacy "directVpnCachedProfiles" stored in
 * settings.json into the server-picker store. Runs only when the picker is
 * empty AND legacy profiles exist, so it is safe to call on every startup.
 *
 * Why: V2 unifies server management around the server-picker store; the
 * Settings page no longer ingests subscriptions. Without this migration,
 * users upgrading from a previous build would see an empty Servers page
 * and have to re-import their subscription manually.
 */
export function migrateLegacyDirectVpnProfiles(): void {
  const existing = getProfiles()
  if (existing.length > 0) return

  const settings = settingsStore.get()
  const legacy = Array.isArray(settings.directVpnCachedProfiles)
    ? settings.directVpnCachedProfiles
    : []
  if (!legacy.length) return

  const migrated: ServerProfile[] = legacy
    .filter((profile: any) => profile && profile.outbound && typeof profile.outbound === 'object')
    .map((profile: any) => ({
      id: randomUUID(),
      name: profile.name || (profile.protocol ? String(profile.protocol).toUpperCase() : 'Profile'),
      protocol: profile.protocol || 'vless',
      server: profile.outbound.server || '',
      port: typeof profile.outbound.server_port === 'number' ? profile.outbound.server_port : 0,
      country: undefined,
      ping: null,
      status: 'unknown' as const,
      lastChecked: undefined,
      outbound: profile.outbound
    }))

  if (!migrated.length) return

  saveProfiles(migrated)
  // Activate whichever index used to be selected, clamped to range.
  const idx = Math.max(0, Math.min(settings.directVpnSelectedIndex || 0, migrated.length - 1))
  store.set('activeProfileId', migrated[idx].id)

  logEvent('info', 'server-picker', 'migrated legacy directVpnCachedProfiles', {
    count: migrated.length,
    activeIndex: idx
  })
}

/**
 * Backfills missing `outbound` blocks on existing picker entries. An older
 * build of the app saved profiles without the `outbound` field, which makes
 * the VPN unstartable for those entries (we have no sing-box outbound to
 * dial). We try to recover the outbound from the legacy
 * settings.directVpnCachedProfiles list by matching on host+port+protocol.
 *
 * Runs every startup. Cheap when nothing needs fixing.
 */
export function backfillMissingOutbounds(): void {
  const profiles = getProfiles()
  if (!profiles.length) return
  const needFix = profiles.filter(p => !p.outbound || typeof p.outbound !== 'object')
  if (!needFix.length) return

  const settings = settingsStore.get()
  const legacy = Array.isArray(settings.directVpnCachedProfiles)
    ? settings.directVpnCachedProfiles
    : []

  let fixed = 0
  const updated = profiles.map(profile => {
    if (profile.outbound && typeof profile.outbound === 'object') return profile

    // Match on host:port (the most reliable identity even when names diverge),
    // falling back to name comparison.
    const candidate = legacy.find((cached: any) => {
      if (!cached || !cached.outbound || typeof cached.outbound !== 'object') return false
      const cachedHost = String(cached.outbound.server || '').trim()
      const cachedPort = Number(cached.outbound.server_port || 0)
      return cachedHost === profile.server && cachedPort === profile.port
    }) || legacy.find((cached: any) =>
      cached && typeof cached.name === 'string' && cached.name === profile.name && cached.outbound
    )

    if (candidate && candidate.outbound) {
      fixed++
      return { ...profile, outbound: candidate.outbound }
    }
    return profile
  })

  if (fixed > 0) {
    saveProfiles(updated)
    logEvent('info', 'server-picker', 'backfilled missing outbounds', {
      total: profiles.length,
      missing: needFix.length,
      recovered: fixed,
      stillMissing: needFix.length - fixed
    })
  } else {
    logEvent('warn', 'server-picker', 'profiles missing outbound and no recovery source', {
      missing: needFix.length
    })
  }
}

/**
 * One-time migration that ensures every picker entry belongs to a sensible
 * group, reconstructing subscription metadata from settings/SNI when
 * possible.
 *
 * Why this is more than just "assign a groupId": earlier builds dumped
 * every profile (including ones that came from a subscription URL) into a
 * generic `manual` group called "Импортированные". That made the user
 * unable to refresh the subscription, hid the panel's traffic / expiry
 * metadata, and produced confusing duplicates whenever the user re-pasted
 * the URL. This migration tries hard to recover the original origin so
 * the new groups-aware UI works correctly for upgraded users.
 *
 * Strategy (in order of confidence):
 *
 *   1. **Recover subscription URL from settings.** Older builds cached the
 *      last-imported URL in `settings.directVpnCachedInput` along with
 *      every parsed profile's outbound. If we can match picker profiles
 *      by host:port:protocol against that cache, those profiles came from
 *      that subscription — fold them into a `subscription` group with the
 *      cached URL as `sourceUrl`. `happ://add/…` inputs are unwrapped to
 *      the underlying `https://…` so the resulting group is refreshable.
 *
 *   2. **Detect a panel by common SNI suffix.** Real VPN providers reuse a
 *      single panel domain across all their VLESS-Reality keys (e.g.
 *      `feodorn.com`, `cloudrynth.com`). When ≥80% of unrouted profiles
 *      share the same last-2-segments SNI suffix, that's almost
 *      certainly one provider — bucket them into a `subscription` group
 *      named after the suffix, with `sourceUrl` left undefined. The user
 *      can fix the URL via the rename dialog; meanwhile the keys are
 *      grouped sensibly instead of dumped into "Импортированные".
 *
 *   3. **Fall back to "Ручные ключи".** Anything that doesn't fit a
 *      detected subscription lands in the singleton manual group. We
 *      stop creating "Импортированные" — that name confused users who
 *      had no idea why they had two manual buckets.
 *
 * Idempotent: re-running with the same store state produces the same
 * groups. If a previous run of this migration already created the
 * "Импортированные" group, we'll find its profiles dangling under a
 * `manual` group whose sole purpose is to hold legacy data, and re-run
 * the splitting logic on them. When that succeeds we also delete the now
 * empty "Импортированные" group so it stops cluttering the UI.
 */
export function migrateProfilesIntoGroups(): void {
  const profiles = getProfiles()
  if (!profiles.length) return

  const groups = serverGroups.getGroups()
  const groupIdSet = new Set(groups.map(g => g.id))

  // Treat the legacy "Импортированные" manual group as a "to-be-resorted"
  // bucket: profiles inside it weren't truly manual, just dumped there
  // because the previous migration had no better idea. Re-run the split
  // logic on them.
  const LEGACY_DUMP_NAME = 'Импортированные'
  const legacyDumpGroup = groups.find(
    g => g.source === 'manual' && g.name === LEGACY_DUMP_NAME
  )

  // Profiles needing classification = profiles with no group OR with the
  // legacy dump group. Everything else (already in a real subscription
  // group, or already in "Ручные ключи") stays put.
  const needsClassification = profiles.filter(
    p =>
      !p.groupId ||
      !groupIdSet.has(p.groupId) ||
      (legacyDumpGroup && p.groupId === legacyDumpGroup.id)
  )
  if (!needsClassification.length) return

  // Map of groupId → array of profile-ids classified into it. We keep
  // ids (not full profile objects) and write the assignments back in one
  // pass at the end so partial state is never persisted.
  const assignments = new Map<string, string[]>()
  const stillUnclassified: ServerProfile[] = []

  // ── Tier 1: subscription URL recovery from settings ────────────────────
  //
  // Older builds (pre-groups) stored the most-recently-imported
  // subscription verbatim in settings.directVpnCachedInput plus every
  // parsed profile's outbound in directVpnCachedProfiles. If the picker
  // profiles' host:port:protocol triplet matches one of those cached
  // outbounds, the profile demonstrably came from that subscription URL.
  let cachedInput = ''
  let cachedProfiles: any[] = []
  try {
    const settings = settingsStore.get()
    cachedInput = String(settings.directVpnCachedInput || '').trim()
    cachedProfiles = Array.isArray(settings.directVpnCachedProfiles)
      ? settings.directVpnCachedProfiles
      : []
  } catch {
    /* settings unavailable; skip tier 1 */
  }

  // Canonicalise the cached input — happ://add/… inputs unwrap to the
  // underlying https URL so the resulting group is refreshable. Falls
  // back to the original input unchanged when there's nothing to unwrap.
  const canonicalCachedUrl = cachedInput ? canonicalizeSubscriptionUrl(cachedInput) : ''
  const isUsableSubscriptionUrl = /^https?:\/\//i.test(canonicalCachedUrl)

  let subscriptionGroupId: string | undefined
  if (isUsableSubscriptionUrl && cachedProfiles.length) {
    // Build a quick lookup of (host|port|protocol) tuples that the cached
    // settings vouch for. We use protocol-tolerant matching (legacy cache
    // sometimes capitalises protocol differently from what we now store).
    const cachedKeys = new Set<string>()
    for (const c of cachedProfiles) {
      if (!c || !c.outbound) continue
      const host = String(c.outbound.server || '').toLowerCase()
      const port = Number(c.outbound.server_port || 0)
      const protocol = String(c.protocol || '').toLowerCase()
      if (host && port) cachedKeys.add(`${host}|${port}|${protocol}`)
    }

    const matched: ServerProfile[] = []
    const unmatched: ServerProfile[] = []
    for (const p of needsClassification) {
      const key = `${(p.server || '').toLowerCase()}|${p.port}|${(p.protocol || '').toLowerCase()}`
      if (cachedKeys.has(key)) matched.push(p)
      else unmatched.push(p)
    }

    if (matched.length) {
      // Reuse an existing subscription group with the same URL when
      // possible, so re-running the migration doesn't create duplicates.
      // (Canonicalisation makes happ://add/… and the unwrapped https://…
      // form resolve to the same group.)
      const existing = findGroupBySourceUrl(canonicalCachedUrl)
      let group = existing
      if (!group) {
        group = serverGroups.createGroup({
          name: deriveSubscriptionGroupName(canonicalCachedUrl),
          source: 'subscription',
          sourceUrl: canonicalCachedUrl,
          importedAt: Date.now(),
          status: 'unknown'
        })
      }
      assignments.set(group.id, matched.map(p => p.id))
      stillUnclassified.push(...unmatched)
      subscriptionGroupId = group.id
    } else {
      stillUnclassified.push(...needsClassification)
    }
  } else {
    stillUnclassified.push(...needsClassification)
  }

  // ── Tier 2: (REMOVED) SNI-suffix splitting ────────────────────────────
  //
  // We used to split unclassified profiles into separate "subscription"
  // groups by their Reality/TLS server_name suffix, assuming a provider
  // reuses ONE panel domain across all keys. That assumption is WRONG for
  // modern Reality: each key deliberately camouflages as a DIFFERENT famous
  // site (vk.com, ozone.ru, x5.ru, userapi.com, amd.com, …). The result was
  // a single real subscription getting shattered into a dozen bogus
  // domain-named "groups" — exactly the mess the user reported.
  //
  // Correct behaviour: anything we can't tie to a real subscription URL
  // (Tier 1) belongs together in the single "Ручные ключи" bucket (Tier 3).
  // No SNI-based grouping. extractSniSuffix is retained only for the
  // consolidation pass that repairs already-shattered installs.

  // ── Tier 3: fall back to "Ручные ключи" ───────────────────────────────
  if (stillUnclassified.length) {
    const manualId = ensureManualKeysGroup()
    const arr = assignments.get(manualId) ?? []
    for (const p of stillUnclassified) arr.push(p.id)
    assignments.set(manualId, arr)
  }

  // Apply assignments to the picker store in one pass.
  const pidToGroup = new Map<string, string>()
  for (const [groupId, pids] of assignments) {
    for (const pid of pids) pidToGroup.set(pid, groupId)
  }
  const updated = profiles.map(p => {
    const newGroupId = pidToGroup.get(p.id)
    return newGroupId ? { ...p, groupId: newGroupId } : p
  })
  saveProfiles(updated)

  // Drop the legacy "Импортированные" group iff every one of its profiles
  // got reassigned to a smarter bucket. If anything remains (e.g. a
  // future bug leaves entries behind), keep the group around so we don't
  // orphan profiles.
  if (legacyDumpGroup) {
    const stillInLegacy = updated.some(p => p.groupId === legacyDumpGroup.id)
    if (!stillInLegacy) {
      serverGroups.deleteGroup(legacyDumpGroup.id)
    }
  }

  logEvent('info', 'server-picker', 'migrated-profiles-into-groups', {
    total: profiles.length,
    classified: needsClassification.length,
    intoSubscription: subscriptionGroupId ? assignments.get(subscriptionGroupId)?.length ?? 0 : 0,
    intoManual: stillUnclassified.length,
    droppedLegacyDump: Boolean(
      legacyDumpGroup && !updated.some(p => p.groupId === legacyDumpGroup.id)
    )
  })
}

/**
 * One-time repair for installs already shattered by the old Tier-2 SNI-suffix
 * splitter: it created bogus `source:'subscription'` groups named after a
 * Reality camouflage domain (vk.com, ozone.ru, x5.ru, userapi.com, amd.com,
 * sub.dinoadd.online, …) with NO `sourceUrl`. One real subscription ended up
 * as a dozen fake groups.
 *
 * We can't recover the original subscription URL (it was never stored on those
 * groups), so the honest repair is to fold every such bogus group back into
 * the single "Ручные ключи" bucket — keys from a subscription whose URL we
 * lost still belong together, not scattered by camouflage domain. Real
 * subscription groups (those WITH a sourceUrl) and the manual group are left
 * untouched.
 *
 * Heuristic for "bogus": source==='subscription' AND no sourceUrl. A genuine
 * subscription group always has a sourceUrl (set by addFromInput / Tier-1).
 * Idempotent: after the first run there are no sourceUrl-less subscription
 * groups left, so re-running is a no-op.
 *
 * Run AFTER migrateProfilesIntoGroups on startup.
 */
export function consolidateBogusSniGroups(): void {
  const groups = serverGroups.getGroups()
  const bogus = groups.filter(g => g.source === 'subscription' && !g.sourceUrl)
  if (!bogus.length) return

  const bogusIds = new Set(bogus.map(g => g.id))
  const manualId = ensureManualKeysGroup()

  // Re-point every profile in a bogus group to the manual bucket.
  const profiles = getProfiles()
  let moved = 0
  const updated = profiles.map(p => {
    if (p.groupId && bogusIds.has(p.groupId)) {
      moved++
      return { ...p, groupId: manualId }
    }
    return p
  })
  if (moved > 0) saveProfiles(updated)

  // Delete the now-empty bogus groups.
  for (const id of bogusIds) serverGroups.deleteGroup(id)

  logEvent('info', 'server-picker', 'consolidated bogus SNI groups into manual', {
    bogusGroups: bogus.length,
    profilesMoved: moved
  })
}

/**
 * Backfills the `sourceUri` field on every picker profile that has an
 * `outbound` block but no URI yet. This is purely a metadata recovery
 * pass — it does not change which profiles exist or which group they
 * belong to.
 *
 * Why: the dedupe key in `serverGroups.refreshGroup` (and the import
 * dedupe in this file) prefer `sourceUri` when present. Without it we
 * fall back to (host, port, protocol), which collides whenever a
 * provider issues two keys on the same endpoint with different UUIDs.
 * Reconstructing the URI via `exportOutboundToUri` gives us a
 * credential-unique identity for those legacy profiles, so future
 * refreshes correctly preserve their stable IDs instead of re-creating
 * them on every fetch.
 *
 * Idempotent: profiles that already have a `sourceUri`, or whose
 * outbound shape isn't representable as a single-line URI (custom
 * sing-box JSON), are left alone.
 *
 * Run this AFTER `migrateProfilesIntoGroups` from `index.ts` startup.
 */
export function backfillProfileSourceUris(): void {
  const profiles = getProfiles()
  if (!profiles.length) return

  let recovered = 0
  let skippedUnsupported = 0
  const updated = profiles.map(p => {
    if (p.sourceUri) return p
    if (!p.outbound || typeof p.outbound !== 'object') return p
    try {
      const uri = exportOutboundToUri({
        name: p.name,
        protocol: p.protocol,
        outbound: p.outbound
      })
      if (uri) {
        recovered++
        return { ...p, sourceUri: uri }
      }
      skippedUnsupported++
      return p
    } catch {
      // exportOutboundToUri shouldn't throw, but if it does we just
      // skip the profile — better to lose one URI than crash the
      // backfill for everyone.
      return p
    }
  })

  if (recovered > 0) {
    saveProfiles(updated)
    logEvent('info', 'server-picker', 'backfilled profile sourceUris', {
      total: profiles.length,
      recovered,
      skippedUnsupported
    })
  }
}

/**
 * One-time cleanup of stored ping/status/lastChecked fields.
 *
 * Earlier builds of `pingAll` (pre-D6.5) stamped the tunnel-RTT (~2 ms when
 * yandex.ru responds fast through Reality) onto the ACTIVE profile's stored
 * `ping`, then left that value in place even after the tunnel went down.
 * Result: the dropdown row in ProfileSelectorInline and any other UI that
 * reads `profile.ping` would proudly show "2 ms" for the active profile
 * forever — the "выбранный всё равно криво, остальные норм" symptom.
 *
 * The fix to pingAll only prevents NEW poisoning. This sweep wipes any
 * stale data so the user sees a clean "—" until they (or the next offline
 * pingAll sweep) measure for real. Cheap idempotent operation: O(N) over
 * the saved profile list, runs once on app startup before the renderer
 * even asks for the first list.
 */
export function clearStaleStoredPings(): void {
  const profiles = getProfiles()
  if (!profiles.length) return
  let changed = 0
  const cleaned = profiles.map(p => {
    if (p.ping == null && p.status === 'unknown' && p.lastChecked == null) {
      return p
    }
    changed++
    const cleanedProfile: ServerProfile = { ...p, ping: null, status: 'unknown' }
    delete cleanedProfile.lastChecked
    return cleanedProfile
  })
  if (changed > 0) {
    saveProfiles(cleaned)
    logEvent('info', 'server-picker', 'cleared stale stored pings on startup', {
      total: profiles.length,
      cleared: changed
    })
  }
}

function getProfiles(): ServerProfile[] {
  return store.get('profiles') ?? []
}

function saveProfiles(profiles: ServerProfile[]): void {
  store.set('profiles', profiles)
}

function getActiveProfileId(): string | null {
  return store.get('activeProfileId') ?? null
}

/**
 * Sets the active profile by ID. Auto-selects the first available profile if
 * none is currently active and at least one profile exists.
 */
export function selectProfile(id: string): void {
  const profiles = getProfiles()
  const exists = profiles.some((p) => p.id === id)
  if (!exists) {
    logEvent('warn', 'server-picker', 'selectProfile: profile not found', { id })
    return
  }
  store.set('activeProfileId', id)
  logEvent('info', 'server-picker', 'profile selected', { id })
}

/**
 * Returns the currently active profile (the one VPN dials when started).
 * If no profile was explicitly selected but profiles exist, falls back to
 * the first one. Returns null only when there are no profiles at all.
 */
export function getActiveProfile(): ServerProfile | null {
  const profiles = getProfiles()
  if (!profiles.length) return null
  const activeId = getActiveProfileId()
  const found = activeId ? profiles.find((p) => p.id === activeId) : null
  return found ?? profiles[0]
}

/**
 * Removes a profile by ID.
 */
function removeProfile(id: string): void {
  const profiles = getProfiles()
  const filtered = profiles.filter((p) => p.id !== id)
  if (filtered.length === profiles.length) {
    logEvent('warn', 'server-picker', 'removeProfile: profile not found', { id })
    return
  }
  saveProfiles(filtered)

  // Clear active profile if it was removed
  if (getActiveProfileId() === id) {
    store.set('activeProfileId', null)
  }

  logEvent('info', 'server-picker', 'profile removed', { id })
}

// ─── Subscription / Link Parsing ─────────────────────────────────────────────

/**
 * Converts a VpnProfile (from vpnProfiles module) to a ServerProfile.
 *
 * Newly-imported profiles always carry a `groupId` — every entry in the
 * picker store belongs to exactly one {@link ServerGroup}. The optional
 * `sourceUri` is the lossless representation of the VPN URI we parsed
 * (when the user pasted a single key) so we can re-export it later
 * without re-deriving it from the outbound shape.
 */
function vpnProfileToServerProfile(
  vpnProfile: VpnProfile,
  groupId: string,
  sourceUri?: string
): ServerProfile {
  const outbound = vpnProfile.outbound || {}
  return {
    id: randomUUID(),
    name: vpnProfile.name || vpnProfile.protocol.toUpperCase(),
    protocol: vpnProfile.protocol,
    server: outbound.server || '',
    port: outbound.server_port || 0,
    country: undefined,
    ping: null,
    status: 'unknown',
    lastChecked: undefined,
    outbound,
    groupId,
    sourceUri,
    lastSeenInSubscriptionAt: Date.now(),
    enabled: true
  }
}

/**
 * Stable identity for dedupe. Two profiles are "the same" when:
 *   1. They share an exact `sourceUri` (lossless, survives renames), OR
 *   2. They share `(server, port, protocol)`.
 *
 * The first wins because it's strictly more specific — two providers can
 * legitimately use the same `1.2.3.4:443/vless` triplet for different
 * UUIDs, but a re-pasted URI is unambiguously the same key.
 */
function isSameServerProfile(a: ServerProfile, b: ServerProfile): boolean {
  if (a.sourceUri && b.sourceUri) return a.sourceUri === b.sourceUri
  return a.server === b.server && a.port === b.port && a.protocol === b.protocol
}

/**
 * Derive a group name from a subscription URL. Prefers the panel's
 * advertised `webPageUrl` (the user's browser-facing dashboard) and falls
 * back to the subscription URL host. Capped at 60 chars so the UI doesn't
 * have to truncate aggressively.
 */
function deriveSubscriptionGroupName(input: string, webPageUrl?: string): string {
  const candidates: Array<string | undefined> = [webPageUrl, input]
  for (const candidate of candidates) {
    if (!candidate) continue
    try {
      const host = new URL(candidate).host
      if (host) return host.slice(0, 60)
    } catch {
      // Not a URL — try the next candidate.
    }
  }
  // Last-resort fallback: a sanitised slice of the raw input. We never
  // want to leave a group with an empty name.
  return input.replace(/\s+/g, ' ').trim().slice(0, 60) || 'Подписка'
}

/**
 * Append a batch of resolved {@link VpnProfile}s to a group, deduping
 * against the existing picker store. Returns the freshly-created
 * {@link ServerProfile} entries (not the duplicates).
 *
 * Shared between {@link addFromInput} and {@link addFromInputToGroup} so
 * both paths get identical merge semantics.
 */
function appendProfilesToGroup(
  vpnProfiles: VpnProfile[],
  groupId: string,
  sourceUriPerProfile: (vp: VpnProfile, index: number) => string | undefined
): ServerProfile[] {
  const existingProfiles = getProfiles()
  const newProfiles: ServerProfile[] = []

  vpnProfiles.forEach((vpnProfile, index) => {
    const sourceUri = sourceUriPerProfile(vpnProfile, index)
    const candidate = vpnProfileToServerProfile(vpnProfile, groupId, sourceUri)
    const isDuplicate =
      existingProfiles.some(p => isSameServerProfile(p, candidate)) ||
      newProfiles.some(p => isSameServerProfile(p, candidate))
    if (!isDuplicate) newProfiles.push(candidate)
  })

  if (newProfiles.length > 0) {
    saveProfiles([...existingProfiles, ...newProfiles])
    if (!getActiveProfileId()) {
      store.set('activeProfileId', newProfiles[0].id)
    }
  }
  return newProfiles
}

/**
 * Adds profiles from a subscription URL or a single protocol link.
 *
 * Behaviour by input type:
 *
 * - Subscription URL the user has already imported: treat as a refresh of
 *   the existing group. Same dedupe-merge semantics as `groups:refresh` —
 *   keep stable IDs, leave previously-seen-but-now-missing keys in place.
 * - New subscription URL: create a fresh `subscription` group, name it
 *   from the panel's webPageUrl or the URL host, store the new profiles
 *   under that group.
 * - Single VPN URI: ensure the shared "Ручные ключи" group exists and
 *   append the parsed profile under it. The raw URI is stored as
 *   `sourceUri` for lossless re-export.
 */
export async function addFromInput(input: string): Promise<ServerProfile[]> {
  const trimmed = input.trim()
  if (!trimmed) {
    throw new Error('Введите ссылку подписки или VPN-ссылку')
  }

  // Canonicalise once up front: a `happ://add/<base64-encoded-https-url>`
  // input becomes `https://…`, an `https://…` input passes through
  // unchanged. We use the canonical form for both the duplicate-group
  // check and the `sourceUrl` we store on a freshly-created group, so a
  // user pasting the same logical subscription in two different forms
  // (raw URL on one device, happ link on another) hits the existing
  // group on the second paste instead of creating a duplicate.
  const canonical = canonicalizeSubscriptionUrl(trimmed)
  const isSubscriptionUrl = /^https?:\/\//i.test(canonical)

  if (isSubscriptionUrl) {
    // If the user re-pasted a subscription they've already imported, we
    // funnel the request through the same merge logic the refresh button
    // uses. No duplicate group, no surprise data loss. Lookup is canonical
    // so happ:// and https:// forms of the same URL collide correctly.
    const existing = findGroupBySourceUrl(canonical)
    if (existing) {
      const beforeIds = new Set(getProfiles().map(p => p.id))
      const result = await refreshSubscriptionGroup(existing.id)
      if (!result.ok) {
        throw new Error(result.error)
      }
      const after = getProfiles()
      const newlyAdded = after.filter(p => !beforeIds.has(p.id))
      logEvent('info', 'server-picker', 'profiles refreshed via re-paste', {
        groupId: existing.id,
        added: result.addedCount,
        updated: result.updatedCount
      })
      void geolocateAll().catch(() => undefined)
      return newlyAdded
    }

    // First-time subscription import — fetch + create the group + persist.
    let proxyAddr: string | undefined
    let proxyType: 'socks5' | 'http' | undefined
    try {
      const settings = settingsStore.get()
      proxyAddr = settings.proxyOverride?.trim() || undefined
      proxyType = settings.proxyType
    } catch {
      /* fall through with no proxy override */
    }

    // We hand the resolver the original (possibly happ://) input because
    // `resolveVpnProfiles` already knows how to unwrap it; reusing that
    // single code path avoids drift between two unwrap implementations.
    const resolved = await resolveVpnProfiles(trimmed, { proxyAddr, proxyType })
    if (!resolved.profiles.length) {
      throw new Error('Не найдено поддерживаемых профилей в указанном источнике')
    }

    const now = Date.now()
    const userInfo = resolved.userInfo
    // Honor an already-expired trial at import time too (same rule the
    // refresh path uses): if the panel reports expiresAt in the past, the
    // group is 'expired' ("источник истёк, ключи могут работать"), not
    // 'active'. expiresAt is stored in ms.
    const importExpiresAt = userInfo?.expiresAt
    const importTrialExpired =
      typeof importExpiresAt === 'number' && Number.isFinite(importExpiresAt) && importExpiresAt > 0 && importExpiresAt < now
    const group = serverGroups.createGroup({
      // `sourceUrl` is stored in canonical (https://) form so future
      // `findGroupBySourceUrl` lookups match cleanly with both forms.
      name: deriveSubscriptionGroupName(canonical, userInfo?.webPageUrl),
      source: 'subscription',
      sourceUrl: canonical,
      importedAt: now,
      lastFetchedAt: now,
      lastFetchAttemptAt: now,
      lastFetchError: null,
      status: importTrialExpired ? 'expired' : 'active',
      lastRefreshProfilesCount: resolved.profiles.length,
      trafficUploadBytes: userInfo?.trafficUploadBytes ?? undefined,
      trafficDownloadBytes: userInfo?.trafficDownloadBytes ?? undefined,
      trafficUsedBytes: userInfo?.trafficUsedBytes ?? undefined,
      trafficTotalBytes: userInfo?.trafficTotalBytes ?? undefined,
      expiresAt: userInfo?.expiresAt ?? undefined,
      refreshIntervalSeconds: userInfo?.refreshIntervalSeconds ?? undefined,
      webPageUrl: userInfo?.webPageUrl ?? undefined
    })

    const newProfiles = appendProfilesToGroup(
      resolved.profiles,
      group.id,
      // We don't have per-profile URIs from a subscription resolver
      // (the upstream feed often omits them), so leave `sourceUri`
      // unset and let the connection-tuple do the dedupe work.
      () => undefined
    )

    logEvent('info', 'server-picker', 'profiles added from subscription', {
      groupId: group.id,
      count: newProfiles.length
    })
    void geolocateAll().catch(() => undefined)
    return newProfiles
  }

  // Single VPN URI path. We need the parsed profile AND the original line
  // so we can store it as sourceUri.
  const resolved = await resolveVpnProfiles(trimmed)
  if (!resolved.profiles.length) {
    throw new Error('Не найдено поддерживаемых профилей в указанном источнике')
  }

  const groupId = ensureManualKeysGroup()
  // Pasting one key returns one profile, but a multi-line paste of single
  // URIs is technically valid too — we keep the lossless URI for the
  // first profile only, since we can't reliably split a multi-line paste
  // back into per-profile lines from here. Single-key (the dominant case)
  // gets the source URI; bulk paste falls back to undefined.
  const newProfiles = appendProfilesToGroup(
    resolved.profiles,
    groupId,
    (_vp, index) => (resolved.profiles.length === 1 && index === 0 ? trimmed : undefined)
  )

  logEvent('info', 'server-picker', 'profile added from URI', {
    groupId,
    count: newProfiles.length
  })
  void geolocateAll().catch(() => undefined)
  return newProfiles
}

/**
 * Append `input` to the named group regardless of input type. Used by the
 * "paste an extra key under this subscription" flow in the UI — the user
 * already chose the group, so we never auto-create or auto-route.
 *
 * Subscription URLs append the full set of resolved profiles. Single
 * URIs append one profile with `sourceUri = trimmed`.
 */
export async function addFromInputToGroup(input: string, groupId: string): Promise<ServerProfile[]> {
  const trimmed = input.trim()
  if (!trimmed) throw new Error('Введите ссылку подписки или VPN-ссылку')

  const target = serverGroups.getGroup(groupId)
  if (!target) throw new Error('Группа не найдена')

  let proxyAddr: string | undefined
  let proxyType: 'socks5' | 'http' | undefined
  try {
    const settings = settingsStore.get()
    proxyAddr = settings.proxyOverride?.trim() || undefined
    proxyType = settings.proxyType
  } catch {
    /* fall through */
  }

  const resolved = await resolveVpnProfiles(trimmed, { proxyAddr, proxyType })
  if (!resolved.profiles.length) {
    throw new Error('Не найдено поддерживаемых профилей в указанном источнике')
  }

  const isSubscriptionUrl = /^https?:\/\//i.test(trimmed)
  const newProfiles = appendProfilesToGroup(
    resolved.profiles,
    groupId,
    (_vp, index) =>
      !isSubscriptionUrl && resolved.profiles.length === 1 && index === 0 ? trimmed : undefined
  )

  logEvent('info', 'server-picker', 'profiles appended to existing group', {
    groupId,
    count: newProfiles.length,
    source: isSubscriptionUrl ? 'subscription' : 'uri'
  })
  void geolocateAll().catch(() => undefined)
  return newProfiles
}

// ─── Grouping ────────────────────────────────────────────────────────────────

/**
 * Groups profiles by their protocol field.
 * Returns a record where keys are protocol names and values are arrays of profiles.
 */
export function groupByProtocol(
  profiles: ServerProfile[]
): Record<string, ServerProfile[]> {
  const groups: Record<string, ServerProfile[]> = {}

  for (const profile of profiles) {
    const key = profile.protocol || 'unknown'
    if (!groups[key]) {
      groups[key] = []
    }
    groups[key].push(profile)
  }

  return groups
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

function handleLogged<T>(
  channel: string,
  listener: (event: IpcMainInvokeEvent, ...args: any[]) => Promise<T> | T
): void {
  ipcMain.handle(channel, async (event, ...args) => {
    const started = Date.now()
    logEvent('debug', 'ipc', `${channel} started`, { args })
    try {
      const result = await listener(event, ...args)
      logEvent('debug', 'ipc', `${channel} finished`, { ms: Date.now() - started })
      return result
    } catch (err) {
      logEvent('error', 'ipc', `${channel} failed`, err)
      throw err
    }
  })
}

/**
 * Registers all server picker IPC handlers.
 * Should be called once during app initialization.
 */
export function registerServerPickerHandlers(): void {
  handleLogged('servers:list', async () => {
    return getProfiles()
  })

  handleLogged('servers:select', async (_event, id: string) => {
    selectProfile(id)
  })

  handleLogged('servers:get-active', async () => {
    const profile = getActiveProfile()
    return { profile, activeId: getActiveProfileId() }
  })

  handleLogged('servers:ping-all', async () => {
    return await pingAll()
  })

  // Ping a single host:port. Used by the dashboard "ping selected" button to
  // measure latency to whatever profile the user currently has chosen, without
  // forcing a full pingAll across every saved server.
  handleLogged('servers:ping-one', async (_event, host: string, port: number) => {
    return await pingServer(host, port)
  })

  handleLogged('servers:add', async (_event, input: string) => {
    return await addFromInput(input)
  })

  // Append profiles to a specific group. When `groupId` is null, fall back
  // to the same defaults as `servers:add`: subscription URLs create their
  // own group; single URIs land in "Ручные ключи".
  handleLogged('servers:add-to-group', async (_event, input: string, groupId: string | null) => {
    if (groupId) return await addFromInputToGroup(input, groupId)
    return await addFromInput(input)
  })

  handleLogged('servers:remove', async (_event, id: string) => {
    removeProfile(id)
  })

  // Export an entry back to its scheme URI (vless://, trojan://, …) so the
  // user can move the key to another device or another client. Returns
  // {ok: true, uri, profile} on success, or {ok: false, reason} when the
  // outbound shape isn't representable as a single-line URI (custom
  // sing-box JSON profiles fall in that bucket).
  handleLogged('servers:export-key', async (_event, id: string) => {
    const profile = getProfiles().find(p => p.id === id)
    if (!profile) return { ok: false as const, reason: 'profile-not-found' }
    if (!profile.outbound || typeof profile.outbound !== 'object') {
      return { ok: false as const, reason: 'no-outbound' }
    }
    const uri = exportOutboundToUri({
      name: profile.name,
      protocol: profile.protocol,
      outbound: profile.outbound
    })
    if (!uri) return { ok: false as const, reason: 'unsupported-protocol', protocol: profile.protocol }
    return { ok: true as const, uri, name: profile.name, protocol: profile.protocol }
  })

  // Save the exported URI to a .txt file via the OS save dialog. Used when
  // the user wants to keep a backup, store keys in a password manager, or
  // share the key out-of-band — clipboard is fine for one-shot paste, but
  // a file is what people actually archive. Returns:
  //   {ok: true, path}            — file written
  //   {ok: false, cancelled: true} — user dismissed the dialog
  //   {ok: false, reason}          — anything else (no profile, write failed, …)
  handleLogged('servers:export-key-file', async (_event, id: string) => {
    const profile = getProfiles().find(p => p.id === id)
    if (!profile) return { ok: false as const, reason: 'profile-not-found' }
    if (!profile.outbound || typeof profile.outbound !== 'object') {
      return { ok: false as const, reason: 'no-outbound' }
    }
    const uri = exportOutboundToUri({
      name: profile.name,
      protocol: profile.protocol,
      outbound: profile.outbound
    })
    if (!uri) return { ok: false as const, reason: 'unsupported-protocol', protocol: profile.protocol }

    // Pick a sane default filename: "<protocol>-<sanitised-name>.txt".
    // Stripping non-filename characters makes the dialog suggestion usable on
    // Windows without the user having to retype.
    const safeName = (profile.name || profile.protocol)
      .replace(/[<>:"/\\|?*\u0000-\u001F]/g, '')
      .replace(/\s+/g, '-')
      .slice(0, 60) || profile.protocol
    const defaultFileName = `${profile.protocol}-${safeName}.txt`

    const choice = await dialog.showSaveDialog({
      title: 'Сохранить ключ VPN',
      defaultPath: join(app.getPath('desktop'), defaultFileName),
      filters: [
        { name: 'Текстовый файл', extensions: ['txt'] },
        { name: 'Все файлы', extensions: ['*'] }
      ]
    })

    if (choice.canceled || !choice.filePath) {
      return { ok: false as const, cancelled: true as const }
    }

    try {
      // We persist just the URI on a single line plus a trailing newline.
      // Most clients accept extra leading/trailing whitespace, but minimum
      // surprise is "the file is exactly the URI".
      await writeFile(choice.filePath, uri + '\n', 'utf8')
      return { ok: true as const, path: choice.filePath, uri, name: profile.name, protocol: profile.protocol }
    } catch (err: any) {
      logEvent('warn', 'server-picker', 'export-key-file write failed', {
        path: choice.filePath,
        error: err?.message || String(err)
      })
      return { ok: false as const, reason: 'write-failed', error: err?.message || String(err) }
    }
  })

  // Bulk export: dump every saved profile (one URI per line) into a single
  // .txt file via the OS save dialog. Profiles that don't have a single-line
  // representation (custom sing-box JSON, missing outbound) are skipped and
  // their count is returned so the UI can mention them.
  //
  // Returns the same shape as the single-key handler, plus counts:
  //   {ok: true, path, total, exported, skipped}
  //   {ok: false, cancelled: true}
  //   {ok: false, reason: 'no-profiles' | 'unsupported-all' | 'write-failed'}
  handleLogged('servers:export-all-keys-file', async () => {
    const profiles = getProfiles()
    if (!profiles.length) return { ok: false as const, reason: 'no-profiles' }

    const lines: string[] = []
    let skipped = 0
    for (const profile of profiles) {
      if (!profile.outbound || typeof profile.outbound !== 'object') { skipped++; continue }
      const uri = exportOutboundToUri({
        name: profile.name,
        protocol: profile.protocol,
        outbound: profile.outbound
      })
      if (!uri) { skipped++; continue }
      lines.push(uri)
    }

    if (!lines.length) {
      return { ok: false as const, reason: 'unsupported-all' }
    }

    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    const defaultFileName = `vpn-keys-${stamp}.txt`

    const choice = await dialog.showSaveDialog({
      title: 'Сохранить все ключи VPN',
      defaultPath: join(app.getPath('desktop'), defaultFileName),
      filters: [
        { name: 'Текстовый файл', extensions: ['txt'] },
        { name: 'Все файлы', extensions: ['*'] }
      ]
    })

    if (choice.canceled || !choice.filePath) {
      return { ok: false as const, cancelled: true as const }
    }

    // Header comments so future-you remembers what this file is. Most VPN
    // clients (Happ / v2RayN / sing-box) ignore '#' lines on import.
    const header = [
      `# VPN keys exported by VPN Tunnel Enforcer`,
      `# Profiles: ${lines.length} exported, ${skipped} skipped`,
      `# Generated: ${new Date().toISOString()}`,
      ''
    ].join('\n')

    try {
      await writeFile(choice.filePath, header + lines.join('\n') + '\n', 'utf8')
      logEvent('info', 'server-picker', 'export-all-keys-file', {
        path: choice.filePath,
        total: profiles.length,
        exported: lines.length,
        skipped
      })
      return {
        ok: true as const,
        path: choice.filePath,
        total: profiles.length,
        exported: lines.length,
        skipped
      }
    } catch (err: any) {
      logEvent('warn', 'server-picker', 'export-all-keys-file write failed', {
        path: choice.filePath,
        error: err?.message || String(err)
      })
      return { ok: false as const, reason: 'write-failed', error: err?.message || String(err) }
    }
  })
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export const serverPicker = {
  getProfiles,
  getActiveProfileId,
  getActiveProfile,
  selectProfile,
  removeProfile,
  pingServer,
  pingAll,
  addFromInput,
  addFromInputToGroup,
  groupByProtocol,
  migrateLegacyDirectVpnProfiles,
  backfillMissingOutbounds,
  migrateProfilesIntoGroups,
  consolidateBogusSniGroups,
  backfillProfileSourceUris,
  clearStaleStoredPings,
  geolocateAll,
  registerHandlers: registerServerPickerHandlers
}
