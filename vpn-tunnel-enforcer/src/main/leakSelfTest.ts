/**
 * Active "is the kill-switch ACTUALLY blocking?" probe.
 *
 * Background: the user reported that with the firewall kill-switch + TUN
 * both up, Yandex Browser still showed the original Beeline IP. The app's
 * own `getPublicIp()` correctly showed the VPN IP because it goes through
 * the TUN. So we need a probe that mimics what the leaking app is doing —
 * binding to the physical adapter directly and seeing if it can reach the
 * outside.
 *
 * How: use `curl.exe --interface <physical-ip> https://1.1.1.1` with a
 * 4-second connect timeout. A returned public IP is positive egress evidence.
 * A connect failure or timeout measures unreachability in this probe only;
 * other failures are inconclusive and cannot prove firewall enforcement.
 *
 * Also: pull the public IP via TUN and via every physical adapter
 * separately and log all of them so we can see at a glance whether any
 * adapter sees a different external IP than the TUN.
 *
 * Result is logged AND fed back to the renderer so the UI can show a giant
 * red banner "УТЕЧКА: kill-switch не блокирует Wi-Fi".
 *
 * ─── Cancellation ─────────────────────────────────────────────────────────
 * Concurrent `runLeakSelfTest()` callers share the same in-flight run instead
 * of cancelling each other. Each subscriber has its own cancellation/deadline;
 * the last cancellation or global stop kills physical children. Admission is
 * retained until child close, native reads and forensic imports have drained.
 */
import { execFile as execFileCb, type ChildProcess } from 'child_process'
import { randomUUID } from 'node:crypto'
import { networkInterfaces } from 'os'
import { logEvent } from './appLogger'
import { nativePhysicalIpv4Sources } from './native/nativeNetworkReads'
import { operations } from './operations'
import type { OperationLease } from './operationRegistry'
import type { OperationOwner } from '../shared/operation'
import { IpcFault } from '../shared/ipc-result'
import { isLeakProbeIpv4, leakSelfTestMessage, leakSelfTestVerdict, type LeakSelfTestResult, type LeakSelfTestAdapter as AdapterReach } from '../shared/leak-self-test'
export type { LeakSelfTestResult, LeakSelfTestAdapter as AdapterReach } from '../shared/leak-self-test'

async function recordForensicLeakSelfTestEvent(event: string, details: Record<string, unknown>, session: number, signal: AbortSignal): Promise<void> {
  await import('./trafficForensics')
    .then(async ({ recordTrafficForensicsAppEvent }) => {
      if (session !== activeSessionId || signal.aborted) return
      await recordTrafficForensicsAppEvent({
        source: 'leak-self-test',
        event,
        details
      }, () => { if (session !== activeSessionId || signal.aborted) throw new IpcFault('cancelled') })
    })
    .catch(() => undefined)
}

/** No shell: kill addresses the owned curl/PowerShell process itself. Callback
 * completion is retained through close even if a provider settles it early. */
async function runProbeProcess(file: string, args: string[], timeout: number, signal: AbortSignal): Promise<{ stdout: string; stderr: string }> {
  if (signal.aborted) throw new IpcFault('cancelled')
  let child: ChildProcess | undefined, closed = Promise.resolve()
  const stop = () => { try { child?.kill() } catch { /* retain ownership until close */ } }
  const completion = new Promise<{ stdout: string; stderr: string }>((yes, no) => {
    const spawned = execFileCb(file, args, { windowsHide: true, timeout, encoding: 'utf8' }, (error, stdout, stderr) =>
      error ? no(Object.assign(error, { stdout, stderr })) : yes({ stdout, stderr }))
    child = spawned
    closed = new Promise<void>(done => { spawned.once('close', () => done()) })
    signal.addEventListener('abort', stop, { once: true })
    if (signal.aborted) stop()
  })
  try { return await completion }
  finally { await closed; signal.removeEventListener('abort', stop) }
}

const PROBE_URL = 'https://1.1.1.1'
const IP_ENDPOINT = 'https://api.ipify.org'
const DNS_TRACE_ENDPOINTS = [
  'https://cloudflare.com/cdn-cgi/trace',
  'https://one.one.one.one/cdn-cgi/trace',
  'https://icanhazip.com'
]

// Bumped on every new run AND every explicit cancel. In-flight runs snapshot
// the value at start (`mySession`) and bail at every await boundary if the
// global has moved past them.
let activeSessionId = 0
interface SharedLeakRun {
  session: number
  controller: AbortController
  subscribers: Set<OperationLease>
  completion: Promise<LeakSelfTestResult>
  finished: boolean
}
let inFlightLeakTest: SharedLeakRun | null = null
let inFlightSessionId = 0

function cancelledResult(): LeakSelfTestResult {
  return {
    ts: Date.now(),
    physicalAdapterReached: false,
    publicIpMismatch: false,
    defaultRoutePublicIp: null,
    perAdapter: [],
    summary: 'Тест отменён (защита остановлена)',
    cancelled: true,
    physicalAdapterInspectionComplete: false
  }
}

function parseIp(stdout: string): string | null {
  const trimmed = String(stdout).trim()
  const trace = trimmed.match(/^ip=(\S+)/m)?.[1]?.trim()
  const candidate = trace || trimmed
  if (isLeakProbeIpv4(candidate)) return candidate
  return null
}

async function fetchDnsTracePublicIp(signal: AbortSignal): Promise<string | null> {
  for (const endpoint of DNS_TRACE_ENDPOINTS) {
    try {
      const { stdout } = await runProbeProcess('curl.exe', ['-4', '-sS', '--max-time', '4', '--connect-timeout', '4', endpoint], 6000, signal)
      const ip = parseIp(stdout)
      if (ip) return ip
    } catch {
      if (signal.aborted) return null
      // try next endpoint
    }
  }
  return null
}

async function curlBound(ip: string, url: string, signal: AbortSignal, timeoutSec = 4): Promise<{ stdout: string; exitCode: number; stderr: string }> {
  // We want curl to succeed (stdout = result) OR fail cleanly. We capture
  // both so we can log details. The `--interface` flag forces the TCP source
  // IP, which is what we want for testing physical adapter reachability.
  // execFile (argv-style, no cmd.exe shell) so the adapter IP / url are passed
  // as literal arguments — no shell-metacharacter surface.
  const args = ['-4', '--interface', ip, '-sS', '--max-time', String(timeoutSec), '--connect-timeout', String(timeoutSec), url]
  try {
    const { stdout, stderr } = await runProbeProcess('curl.exe', args, (timeoutSec + 2) * 1000, signal)
    return { stdout, exitCode: 0, stderr: stderr || '' }
  } catch (err: any) {
    return {
      stdout: err?.stdout?.toString() || '',
      exitCode: typeof err?.code === 'number' ? err.code : -1,
      stderr: err?.stderr?.toString() || err?.message || ''
    }
  }
}

async function listPhysicalAdaptersWithIPv4(signal: AbortSignal): Promise<{ adapters: { alias: string; ipv4: string }[]; complete: boolean }> {
  if (process.platform !== 'win32') return { adapters: [], complete: true }
  // Native iphlpapi read first (no powershell.exe spawn). It throws on ANY
  // error or implausible enumeration; we then use the PowerShell path below,
  // never an empty "nothing to test" answer.
  try {
    const rows = await nativePhysicalIpv4Sources()
    if (signal.aborted) return { adapters: [], complete: false }
    // An empty native answer is not proof that there is nothing to test (it filters differently
    // from PowerShell, e.g. address DAD state): ask PowerShell before reporting "no adapters".
    if (rows.length > 0) return { adapters: rows.map(r => ({ alias: r.alias, ipv4: r.ipv4 })), complete: true }
    logEvent('debug', 'leak-test', 'native adapter read returned no sources, using PowerShell')
  } catch (err) {
    if (signal.aborted) return { adapters: [], complete: false }
    logEvent('debug', 'leak-test', 'native adapter read unavailable, using PowerShell', { err: (err as Error).message })
  }
  // Mirror the lockdown filter — keep them consistent so the leak test
  // tests every adapter that the lockdown is responsible for. The UTF-8
  // prefix is mandatory: without it the alias comes back as CP866-mojibake
  // on Russian Windows and the alias-based curl probe would target a
  // non-existent adapter.
  const script = `
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$OutputEncoding=[System.Text.Encoding]::UTF8
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()
$adapters = Get-NetAdapter | Where-Object {
  $_.Status -eq 'Up' -and
  $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth' -and
  $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00'
}
foreach ($a in $adapters) {
  $cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
  if ($cfg -and $cfg.IPv4Address -and $cfg.IPv4Address.Count -gt 0) {
    foreach ($ip in $cfg.IPv4Address) {
      if ($ip.IPAddress -and $ip.IPAddress -notlike '169.254.*') {
        $rows += [pscustomobject]@{ Alias = $a.Name; Ipv4 = $ip.IPAddress }
      }
    }
  }
}
$rows | ConvertTo-Json -Compress
`
  const encoded = Buffer.from(script, 'utf-16le').toString('base64')
  try {
    const { stdout } = await runProbeProcess('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], 10000, signal)
    const text = String(stdout).trim()
    if (!text || text === 'null') return { adapters: [], complete: true }
    const parsed = JSON.parse(text)
    const arr = Array.isArray(parsed) ? parsed : [parsed]
    return {
      adapters: arr.map((r: any) => ({ alias: String(r.Alias), ipv4: String(r.Ipv4) })),
      complete: true
    }
  } catch (err) {
    if (signal.aborted) return { adapters: [], complete: false }
    logEvent('warn', 'leak-test', 'failed to list physical adapters', { err: (err as Error).message })
    return { adapters: [], complete: false }
  }
}

export async function runLeakSelfTest(options: { signal?: AbortSignal; onOperation?: (lease: OperationLease) => void; owner?: OperationOwner; timeoutMs?: number } = {}): Promise<LeakSelfTestResult> {
  let subscribed: SharedLeakRun | undefined
  try {
    return await operations.run('leak-check', async lease => {
      options.onOperation?.(lease)
      lease.assertActive()
      let run = inFlightLeakTest
      if (run?.controller.signal.aborted) throw new IpcFault('conflict')
      if (!run) {
        inFlightSessionId = ++activeSessionId
        const created: SharedLeakRun = { session: activeSessionId, controller: new AbortController(), subscribers: new Set(), finished: false,
          completion: Promise.resolve(cancelledResult()) }
        inFlightLeakTest = run = created
        created.completion = Promise.resolve().then(() => runLeakSelfTestOnce(created.session, created.controller.signal)).finally(() => {
          created.finished = true
          if (inFlightLeakTest === created) inFlightLeakTest = null
        })
      }
      subscribed = run
      const shared = run
      shared.subscribers.add(lease)
      const detach = () => {
        shared.subscribers.delete(lease)
        if (!shared.subscribers.size && !shared.finished) shared.controller.abort()
      }
      lease.signal.addEventListener('abort', detach, { once: true })
      try { return structuredClone(await lease.wait(shared.completion)) }
      finally { lease.signal.removeEventListener('abort', detach); detach() }
    }, { signal: options.signal, owner: options.owner, timeoutMs: options.timeoutMs, resource: `leak-subscriber:${randomUUID()}` })
  } catch (error) {
    // Preserve the legacy global-stop view; per-request cancel/deadline stay typed.
    if (subscribed && subscribed.session !== activeSessionId && error instanceof IpcFault && error.category === 'cancelled') return cancelledResult()
    throw error
  }
}

async function runLeakSelfTestOnce(mySession: number, signal: AbortSignal): Promise<LeakSelfTestResult> {
  const ts = Date.now()

  // 1. Public IP via the default route (which should be the TUN). Use plain
  //    curl with no --interface so the OS picks the default route.
  let defaultRoutePublicIp: string | null = null
  try {
    const { stdout } = await runProbeProcess('curl.exe', ['-4', '-sS', '--max-time', '6', '--connect-timeout', '6', IP_ENDPOINT], 8000, signal)
    if (mySession !== activeSessionId || signal.aborted) return cancelledResult()
    defaultRoutePublicIp = parseIp(stdout)
  } catch {
    if (mySession !== activeSessionId || signal.aborted) return cancelledResult()
    defaultRoutePublicIp = null
  }

  // 2. Per physical adapter: try to reach 1.1.1.1 directly bypassing the
  //    default route. If curl succeeds while TUN+kill-switch are up, that's a
  //    leak.
  const adapterList = await listPhysicalAdaptersWithIPv4(signal)
  if (mySession !== activeSessionId || signal.aborted) return cancelledResult()
  const adapters = adapterList.adapters
  const physicalAdapterInspectionComplete = adapterList.complete

  const perAdapter: AdapterReach[] = []
  for (const a of adapters) {
    const res = await curlBound(a.ipv4, IP_ENDPOINT, signal)
    if (mySession !== activeSessionId || signal.aborted) return cancelledResult()
    perAdapter.push({
      alias: a.alias,
      ipv4: a.ipv4,
      publicIpViaThisAdapter: parseIp(res.stdout),
      curlExitCode: res.exitCode,
      curlStderrTail: (res.stderr || '').slice(-200) || null
    })
  }

  // Cancellation check before computing the verdict — we don't want to log
  // a "leak" against a user who has already torn the tunnel down.
  if (mySession !== activeSessionId || signal.aborted) return cancelledResult()

  const physicalAdapterReached = perAdapter.some((a) => isLeakProbeIpv4(a.publicIpViaThisAdapter))
  const publicIpMismatch = perAdapter.some(
    (a) => a.publicIpViaThisAdapter !== null && a.publicIpViaThisAdapter !== defaultRoutePublicIp
  )

  // 3. DNS/IP side-channel. This is useful evidence, but not a standalone
  //    leak verdict: different public-IP services can disagree because of
  //    anycast, CDN routing, cached routes, or split rules. A real red leak
  //    still requires the physical-adapter probe above to reach the outside.
  let dnsLeakDetected = false
  let dnsLeakDetail: string | null = null
  try {
    const cfIp = await fetchDnsTracePublicIp(signal)
    if (mySession !== activeSessionId || signal.aborted) return cancelledResult()
    if (cfIp && defaultRoutePublicIp && cfIp !== defaultRoutePublicIp) {
      dnsLeakDetail = `Cloudflare видит ${cfIp}, default-route отдаёт ${defaultRoutePublicIp}`
    }
  } catch {
    // Silent — adding a DNS-leak probe should never break the existing test.
  }

  const result: LeakSelfTestResult = {
    ts, physicalAdapterReached, publicIpMismatch, defaultRoutePublicIp, perAdapter,
    summary: '', dnsLeakDetected, dnsLeakDetail: dnsLeakDetail ?? undefined, physicalAdapterInspectionComplete
  }
  const verdict = leakSelfTestVerdict(result)
  let summary: string
  if (physicalAdapterReached && publicIpMismatch) {
    const leakedIp = perAdapter.find((a) => a.publicIpViaThisAdapter)?.publicIpViaThisAdapter
    summary = `УТЕЧКА: физический адаптер виден из интернета как ${leakedIp} (TUN отдаёт ${defaultRoutePublicIp ?? 'неизвестно'})`
  } else if (physicalAdapterReached) {
    summary = `УТЕЧКА: kill-switch не блокирует физический адаптер (curl до 1.1.1.1 прошёл)`
  } else if (verdict === 'ok') {
    summary = dnsLeakDetail
      ? `OK: в IPv4-проверке утечек не обнаружено, IP через TUN ${defaultRoutePublicIp} (IP-проверки расходятся: ${dnsLeakDetail})`
      : `OK: в IPv4-проверке утечек не обнаружено, IP через TUN ${defaultRoutePublicIp}`
  } else {
    summary = leakSelfTestMessage(result)
  }
  result.summary = summary

  // Final cancellation check before any side effects (logEvent + callback).
  // Without this, a stop-tun that finishes between adapter probes and here
  // would still emit a misleading "УТЕЧКА" log line and trigger the
  // renderer leak banner.
  if (mySession !== activeSessionId || signal.aborted) return cancelledResult()

  await recordForensicLeakSelfTestEvent('leak-self-test-result', {
    physicalAdapterReached,
    publicIpMismatch,
    dnsLeakDetected,
    dnsLeakDetail,
    defaultRoutePublicIp,
    perAdapter,
    summary
  }, mySession, signal)

  if (mySession !== activeSessionId || signal.aborted) return cancelledResult()
  logEvent(verdict === 'ok' ? 'info' : 'warn', 'leak-test', summary, {
    physicalAdapterReached,
    publicIpMismatch,
    dnsLeakDetected,
    dnsLeakDetail,
    defaultRoutePublicIp,
    perAdapter
  })
  return result
}

let periodicLeakTimer: ReturnType<typeof setInterval> | null = null
let onLeakDetectedCb: ((r: LeakSelfTestResult) => void) | null = null
let onLeakSelfTestCompletedCb: ((r: LeakSelfTestResult) => void) | null = null
let transitionSuppressUntil = 0
let backgroundLeakTestGate: () => boolean = () => true

/** Main supplies current protection evidence; manual diagnostics remain available while disconnected. */
export function setBackgroundLeakTestGate(gate: () => boolean): void {
  backgroundLeakTestGate = gate
}

function backgroundLeakTestAllowed(): boolean {
  try { return backgroundLeakTestGate() } catch { return false }
}

export function setLeakDetectedCallback(cb: (r: LeakSelfTestResult) => void): void {
  onLeakDetectedCb = cb
}

export function setLeakSelfTestCompletedCallback(cb: ((r: LeakSelfTestResult) => void) | null): void {
  onLeakSelfTestCompletedCb = cb
}

/**
 * Cancel every subscriber, kill physical children and fence late publications.
 * Owned effects keep draining after the prompt sanitized reply.
 * Periodic ticks scheduled after this call get a fresh
 * session id of their own and run normally — call `stopPeriodicLeakTest()`
 * if you want them to stop firing entirely.
 */
export function cancelLeakSelfTest(): void {
  activeSessionId += 1
  const run = inFlightLeakTest
  run?.controller.abort()
  for (const lease of run?.subscribers ?? []) lease.cancel()
}

export function resetLeakTestThrottlesForTest(): void {
  transitionSuppressUntil = 0
  lastTriggerAt = 0
}

export function suppressLeakSelfTestsFor(ms: number, reason: string): void {
  const until = Date.now() + Math.max(0, ms)
  if (until > transitionSuppressUntil) transitionSuppressUntil = until
  cancelLeakSelfTest()
  logEvent('debug', 'leak-test', 'suppressing event leak checks during network transition', {
    reason,
    ms,
    until: transitionSuppressUntil
  })
}

function isTransitionSuppressed(now = Date.now()): boolean {
  return now < transitionSuppressUntil
}

/**
 * Run the leak self-test asynchronously, regardless of the periodic timer.
 * Used by network-change handlers and tunnel-status transitions to catch
 * leaks the moment something interesting happens.
 *
 * Coalesced: if a check is already in flight (or was triggered <5s ago),
 * this is a no-op. Without that guard, fast network flapping (re-associating
 * to Wi-Fi) would queue up a dozen redundant checks.
 */
let lastTriggerAt = 0
export function triggerLeakCheckNow(reason: string): void {
  if (!backgroundLeakTestAllowed()) return
  const now = Date.now()
  if (isTransitionSuppressed(now)) {
    logEvent('debug', 'leak-test', 'event-triggered run suppressed during transition', {
      reason,
      remainingMs: transitionSuppressUntil - now
    })
    return
  }
  if (now - lastTriggerAt < 5_000) return
  lastTriggerAt = now
  logEvent('debug', 'leak-test', 'event-triggered run', { reason })
  const run = runLeakSelfTest({ owner: 'adaptive-retry' })
  const runSession = inFlightSessionId
  run
    .then((r) => {
      if (runSession !== activeSessionId || !backgroundLeakTestAllowed()) return
      if (r.physicalAdapterReached || r.publicIpMismatch || r.dnsLeakDetected) {
        onLeakDetectedCb?.(r)
      } else if (leakSelfTestVerdict(r) === 'ok') {
        onLeakSelfTestCompletedCb?.(r)
      }
    })
    .catch((err) => { if (runSession === activeSessionId) logEvent('warn', 'leak-test', 'event-triggered run threw', { err: (err as Error).message, reason }) })
}

// Network-change detection. Windows raises NetworkInformation.NetworkAdapter
// events via WMI but Electron exposes a simpler signal: we poll
// os.networkInterfaces() every 8s and compare against the last snapshot.
// On any add/remove/IP change, fire triggerLeakCheckNow. Good enough — a
// real network change always moves at least one IPv4 address.
let lastNetSignature = ''
let netWatchTimer: ReturnType<typeof setInterval> | null = null
let netChangeGraceTimer: ReturnType<typeof setTimeout> | null = null
let onNetworkChangeCb: ((info: { oldRowCount: number; newRowCount: number }) => void) | null = null

/** Notified whenever the physical network signature changes while the watcher runs. */
export function setNetworkChangeCallback(
  cb: ((info: { oldRowCount: number; newRowCount: number }) => void) | null
): void {
  onNetworkChangeCb = cb
}

function buildNetSignature(): string {
  const nics = networkInterfaces()
  const rows: string[] = []
  for (const [name, addrs] of Object.entries(nics)) {
    if (!addrs) continue
    for (const a of addrs) {
      if (a.internal) continue
      rows.push(`${name}|${a.family}|${a.address}|${a.cidr}`)
    }
  }
  return rows.sort().join(';')
}

export function startNetworkChangeWatcher(): void {
  stopNetworkChangeWatcher()
  lastNetSignature = buildNetSignature()
  netWatchTimer = setInterval(() => {
    const sig = buildNetSignature()
    if (sig !== lastNetSignature) {
      const old = lastNetSignature
      lastNetSignature = sig
      const oldRowCount = old.split(';').filter(Boolean).length
      const newRowCount = sig.split(';').filter(Boolean).length
      logEvent('info', 'leak-test', 'network change detected', { oldRowCount, newRowCount })
      try { onNetworkChangeCb?.({ oldRowCount, newRowCount }) } catch { /* non-critical */ }
      // Tiny grace period so the new interface fully comes up before we
      // probe — otherwise the curl --interface call can fail with "no such
      // address" and falsely report "physical adapter unreachable".
      if (netChangeGraceTimer) clearTimeout(netChangeGraceTimer)
      netChangeGraceTimer = setTimeout(() => {
        netChangeGraceTimer = null
        triggerLeakCheckNow('network-change')
      }, 1500)
    }
  }, 8_000)
}

export function stopNetworkChangeWatcher(): void {
  if (netChangeGraceTimer) clearTimeout(netChangeGraceTimer)
  netChangeGraceTimer = null
  if (netWatchTimer) {
    clearInterval(netWatchTimer)
    netWatchTimer = null
  }
}

/**
 * Start the periodic leak self-test loop.
 *
 * @param intervalMs  How often to run the probe.
 * @param shouldRun   Optional gate evaluated on every tick BEFORE
 *                    scheduling the run. If it returns false, the tick is
 *                    skipped (without stopping the timer). Use this to
 *                    gate the test on TUN status without ripping the
 *                    timer down on every transition. Defaults to
 *                    `() => true` for backward compatibility with callers
 *                    that don't care about gating.
 */
export function startPeriodicLeakTest(
  intervalMs = 30_000,
  shouldRun: () => boolean = () => true
): void {
  stopPeriodicLeakTest()
  periodicLeakTimer = setInterval(() => {
    if (!backgroundLeakTestAllowed() || !shouldRun()) return
    if (isTransitionSuppressed()) return
    const run = runLeakSelfTest({ owner: 'adaptive-retry' })
    const runSession = inFlightSessionId
    run
      .then((r) => {
        // Only fire the leak callback if the run we kicked off is still the
        // active one. A stop-tun that bumps activeSessionId between scheduling
        // and resolution must not trigger the renderer leak banner.
        if (runSession !== activeSessionId || !backgroundLeakTestAllowed() || !shouldRun()) return
        if (r.physicalAdapterReached || r.publicIpMismatch || r.dnsLeakDetected) {
          onLeakDetectedCb?.(r)
        } else if (leakSelfTestVerdict(r) === 'ok') {
          onLeakSelfTestCompletedCb?.(r)
        }
      })
      .catch((err) => { if (runSession === activeSessionId) logEvent('warn', 'leak-test', 'periodic test threw', { err: (err as Error).message }) })
  }, intervalMs)
}

export function stopPeriodicLeakTest(): void {
  if (periodicLeakTimer) {
    clearInterval(periodicLeakTimer)
    periodicLeakTimer = null
  }
  cancelLeakSelfTest()
}
