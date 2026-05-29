/**
 * Capture every piece of network state we'd want to see when debugging "the
 * app says VPN is up but my browser still shows real IP". This is the
 * single thing the user can hand to support — it captures EVERYTHING and is
 * cheap to run frequently.
 *
 * Capture triggers:
 *   - app start (one-shot)
 *   - immediately before TUN start (so we can compare to "after")
 *   - immediately after TUN start
 *   - every 60s while TUN is running (rolling)
 *   - manually when the user clicks "Send logs"
 *
 * Output: %APPDATA%/<app>/snapshots/snapshot-<ISO ts>-<reason>.json
 *
 * The diagnostics ZIP picks up the `snapshots/` directory whole.
 *
 * Each snapshot is one JSON file. Failures inside the snapshot don't abort
 * the whole snapshot — every section is independently captured with try/catch
 * and any failure is recorded as `{ error: ... }` for that section.
 */
import { app } from 'electron'
import { mkdir, readdir, stat, unlink, writeFile } from 'fs/promises'
import { existsSync } from 'fs'
import { networkInterfaces, hostname, release, type as osType, totalmem, freemem } from 'os'
import { join } from 'path'
import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { logEvent } from './appLogger'

const exec = promisify(execCb)

const SNAPSHOTS_DIRNAME = 'snapshots'
const MAX_SNAPSHOTS_RETAINED = 60

export type SnapshotReason =
  | 'app-start'
  | 'tun-pre-start'
  | 'tun-post-start'
  | 'tun-start-failed'
  | 'tun-post-stop'
  | 'periodic'
  | 'manual'
  | 'leak-detected'

export interface SystemSnapshot {
  reason: SnapshotReason
  ts: string
  hostname: string
  osType: string
  osRelease: string
  appVersion: string
  isElevated: boolean | null
  memMB: { total: number; free: number }
  // OS-level networking dumps (PowerShell). Each is the raw stdout (or
  // {error: ...} on failure). Kept as text — the user/support can grep.
  netAdapters?: string | { error: string }
  netIPConfiguration?: string | { error: string }
  netRouteIPv4?: string | { error: string }
  netRouteIPv6?: string | { error: string }
  dnsClientServerAddresses?: string | { error: string }
  dnsClientNrptRules?: string | { error: string }
  dnsClientCache?: string | { error: string }
  netAdapterBindingsIPv6?: string | { error: string }
  firewallVpnteRules?: string | { error: string }
  firewallProfile?: string | { error: string }
  netshWinhttp?: string | { error: string }
  // Inferred app state.
  jsNetworkInterfaces: ReturnType<typeof networkInterfaces>
  manifests: {
    baseline: object | null
    killSwitch: object | null
    adapterLockdown: object | null
  }
  // Process owner of likely upstream proxy ports (10808 SOCKS, 10809 HTTP).
  // The PS commands wrap their bodies in try/catch so "no listener" produces
  // an explicit { empty: true } marker rather than a noisy { error: ... }
  // (which is the common case when nothing is listening on that port).
  proxyOwnersPort10808?: string | { empty: true } | { error: string }
  proxyOwnersPort10809?: string | { empty: true } | { error: string }
  // Active sing-box state. Uses tasklist directly (yes/no semantics) so this
  // never reports an error in normal operation.
  singboxRunning?: { running: boolean; pid?: number } | { error: string }
}

function snapshotsDir(): string {
  return join(app.getPath('userData'), SNAPSHOTS_DIRNAME)
}

async function ensureSnapshotsDir(): Promise<string> {
  const dir = snapshotsDir()
  if (!existsSync(dir)) await mkdir(dir, { recursive: true })
  return dir
}

async function tryPS(script: string, timeoutMs = 15000): Promise<string | { error: string }> {
  if (process.platform !== 'win32') return { error: 'platform is not Windows' }
  try {
    // Force UTF-8 output regardless of system locale. On Russian Windows the
    // default Console.OutputEncoding is CP866 (OEM cyrillic), which gives us
    // mojibake for adapter names like "Беспроводная сеть" and breaks downstream
    // commands that try to use those names. The prefix below is mandatory for
    // any PS we run that might emit non-ASCII text.
    // Also suppress the "preparing modules for first use" progress XML which
    // otherwise contaminates stdout when stdout is redirected and breaks
    // ConvertTo-Json output / makes exec() think there's an error.
    const utf8Prefix =
      "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;$OutputEncoding=[System.Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"
    const encoded = Buffer.from(utf8Prefix + script, 'utf-16le').toString('base64')
    const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encoded}`
    const { stdout } = await exec(cmd, { windowsHide: true, timeout: timeoutMs, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 })
    return String(stdout).trim()
  } catch (err: any) {
    return { error: err?.message ?? String(err) }
  }
}

async function tryReadJsonFile(path: string): Promise<object | null> {
  try {
    if (!existsSync(path)) return null
    const { readFile } = await import('fs/promises')
    return JSON.parse(await readFile(path, 'utf-8'))
  } catch (err) {
    logEvent('warn', 'snapshot', 'manifest read failed', { path, err: (err as Error).message })
    return null
  }
}

/**
 * Marker emitted by proxy-port PS scripts when nothing is listening on the
 * target port. The script wraps its body in try/catch so a "no rows"
 * outcome produces this explicit token instead of a non-zero exit (which
 * tryPS would otherwise turn into { error: 'Command failed: ...' }, the
 * noisy false-positive we used to see in every snapshot).
 */
const PS_EMPTY_MARKER = '__VPNTE_EMPTY__'

/**
 * Run a PS script that's expected to either emit the empty marker or some
 * stdout. Returns:
 *   - { empty: true } when the script reported no rows (common case).
 *   - the trimmed stdout string otherwise.
 *   - { error } if the PS process itself failed (rare — only for unrelated
 *     issues like timeout or missing cmdlet).
 */
async function tryProxyOwnersPS(port: number): Promise<string | { empty: true } | { error: string }> {
  const script = `
try {
  $rows = Get-NetTCPConnection -State Listen -LocalPort ${port} -ErrorAction Stop |
    ForEach-Object {
      $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
      [pscustomobject]@{Port=$_.LocalPort; LocalAddress=$_.LocalAddress; Pid=$_.OwningProcess; Process=$p.ProcessName; Path=$p.Path}
    }
  if (-not $rows) {
    Write-Output '${PS_EMPTY_MARKER}'
  } else {
    $rows | Format-List | Out-String
  }
} catch {
  Write-Output '${PS_EMPTY_MARKER}'
}
`
  const result = await tryPS(script)
  if (typeof result !== 'string') return result
  const trimmed = result.trim()
  if (!trimmed || trimmed === PS_EMPTY_MARKER || trimmed.includes(PS_EMPTY_MARKER)) {
    return { empty: true }
  }
  return trimmed
}

/**
 * Tasklist-based check for our owned sing-box runtime. Returns a structured
 * { running, pid? } object so consumers don't have to grep raw text. We
 * use tasklist (not PS) because the previous PS-based approach was brittle
 * — Get-Process throws when no match, which tryPS turned into an error
 * even though "nothing running" is a perfectly valid yes/no answer.
 */
async function tryGetSingboxRunning(): Promise<{ running: boolean; pid?: number } | { error: string }> {
  if (process.platform !== 'win32') return { error: 'platform is not Windows' }
  try {
    const { stdout } = await exec(
      'tasklist /FI "IMAGENAME eq vpnte-sing-box.exe" /FO CSV /NH',
      { windowsHide: true, timeout: 5000, encoding: 'utf8', maxBuffer: 1024 * 1024 }
    )
    const text = String(stdout || '')
    // tasklist with /NH on no-match prints either an empty result or
    // 'INFO: No tasks are running...' to stdout depending on Windows
    // build. CSV rows for matches look like:
    //   "vpnte-sing-box.exe","1234","Console","1","12,345 K"
    const match = text.match(/^"vpnte-sing-box\.exe","(\d+)"/im)
    if (match) {
      return { running: true, pid: Number(match[1]) }
    }
    return { running: false }
  } catch (err: any) {
    return { error: err?.message ?? String(err) }
  }
}

/**
 * The Windows-y bits. We pull EVERYTHING here so support has zero questions
 * to ask back. Each PS command is independent — one failure (e.g. missing
 * cmdlet on an old Windows version) never blocks the rest.
 */
async function capturePlatformDumps(): Promise<Partial<SystemSnapshot>> {
  if (process.platform !== 'win32') {
    return {
      netAdapters: { error: 'not Windows' },
      netIPConfiguration: { error: 'not Windows' }
    }
  }

  // We run them in parallel. Each tryPS catches its own errors so we don't
  // need a try/catch around Promise.all.
  const [
    netAdapters,
    netIPConfiguration,
    netRouteIPv4,
    netRouteIPv6,
    dnsClientServerAddresses,
    dnsClientNrptRules,
    dnsClientCache,
    netAdapterBindingsIPv6,
    firewallVpnteRules,
    firewallProfile,
    netshWinhttp,
    proxyOwnersPort10808,
    proxyOwnersPort10809,
    singboxRunning
  ] = await Promise.all([
    tryPS('Get-NetAdapter | Format-Table -AutoSize -Wrap | Out-String -Width 4096'),
    tryPS('Get-NetIPConfiguration -All -Detailed | Out-String -Width 4096'),
    tryPS('Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object InterfaceMetric | Format-Table -AutoSize -Wrap | Out-String -Width 4096'),
    tryPS('Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | Sort-Object InterfaceMetric | Format-Table -AutoSize -Wrap | Out-String -Width 4096'),
    tryPS('Get-DnsClientServerAddress | Format-Table -AutoSize -Wrap | Out-String -Width 4096'),
    tryPS('Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Format-List | Out-String -Width 4096'),
    tryPS('Get-DnsClientCache -ErrorAction SilentlyContinue | Format-Table -AutoSize -Wrap | Out-String -Width 4096'),
    tryPS('Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Format-Table -AutoSize -Wrap | Out-String -Width 4096'),
    tryPS("Get-NetFirewallRule -DisplayName 'VPNTE-*' -ErrorAction SilentlyContinue | Format-List Name, DisplayName, Enabled, Direction, Action, Profile, EdgeTraversalPolicy, InterfaceType, Description | Out-String -Width 4096"),
    tryPS('Get-NetFirewallProfile | Format-Table -AutoSize -Wrap | Out-String -Width 4096'),
    tryPS('netsh winhttp show proxy 2>&1 | Out-String'),
    tryProxyOwnersPS(10808),
    tryProxyOwnersPS(10809),
    tryGetSingboxRunning()
  ])

  return {
    netAdapters,
    netIPConfiguration,
    netRouteIPv4,
    netRouteIPv6,
    dnsClientServerAddresses,
    dnsClientNrptRules,
    dnsClientCache,
    netAdapterBindingsIPv6,
    firewallVpnteRules,
    firewallProfile,
    netshWinhttp,
    proxyOwnersPort10808,
    proxyOwnersPort10809,
    singboxRunning
  }
}

async function isElevated(): Promise<boolean | null> {
  if (process.platform !== 'win32') return null
  const result = await tryPS('([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)', 5000)
  if (typeof result === 'string') return /true/i.test(result.trim())
  return null
}

/**
 * Take one snapshot. Always succeeds (errors are recorded as fields).
 * Returns the absolute path of the file written, or null if writing failed.
 */
export async function captureSnapshot(reason: SnapshotReason): Promise<string | null> {
  const ts = new Date().toISOString().replace(/[:.]/g, '-')
  const fileName = `snapshot-${ts}-${reason}.json`

  const userData = app.getPath('userData')
  const [platform, elevated, baseline, killSwitch, adapterLockdown] = await Promise.all([
    capturePlatformDumps(),
    isElevated(),
    // Network baseline manifest lives under network-backups/ (systemNetwork.ts),
    // not the userData root — the old path was always null.
    tryReadJsonFile(join(userData, 'network-backups', 'latest-tun-network-baseline.json')),
    // The kill-switch manifest lives under firewall-killswitch/manifest.json
    // (see firewallKillSwitch.ts), NOT latest-firewall-killswitch.json in the
    // userData root — that file never existed, so this section was always null.
    tryReadJsonFile(join(userData, 'firewall-killswitch', 'manifest.json')),
    tryReadJsonFile(join(userData, 'latest-physical-adapter-lockdown.json'))
  ])

  const snap: SystemSnapshot = {
    reason,
    ts: new Date().toISOString(),
    hostname: hostname(),
    osType: osType(),
    osRelease: release(),
    appVersion: app.getVersion(),
    isElevated: elevated,
    memMB: {
      total: Math.round(totalmem() / 1024 / 1024),
      free: Math.round(freemem() / 1024 / 1024)
    },
    jsNetworkInterfaces: networkInterfaces(),
    manifests: {
      baseline,
      killSwitch,
      adapterLockdown
    },
    ...platform
  }

  try {
    const dir = await ensureSnapshotsDir()
    const path = join(dir, fileName)
    await writeFile(path, JSON.stringify(snap, null, 2), 'utf-8')
    await pruneOldSnapshots()
    logEvent('debug', 'snapshot', 'wrote snapshot', { reason, path })
    return path
  } catch (err) {
    logEvent('warn', 'snapshot', 'failed to write snapshot', { reason, err: (err as Error).message })
    return null
  }
}

/**
 * Keep the snapshots directory bounded. We retain the latest
 * MAX_SNAPSHOTS_RETAINED files; older ones are deleted. This is critical
 * because the periodic snapshot runs every 60s and would otherwise eat disk.
 */
async function pruneOldSnapshots(): Promise<void> {
  try {
    const dir = snapshotsDir()
    if (!existsSync(dir)) return
    const names = await readdir(dir)
    if (names.length <= MAX_SNAPSHOTS_RETAINED) return
    const withMtimes = await Promise.all(
      names.map(async (n) => {
        try {
          const s = await stat(join(dir, n))
          return { n, mtime: s.mtimeMs }
        } catch {
          return { n, mtime: 0 }
        }
      })
    )
    withMtimes.sort((a, b) => b.mtime - a.mtime)
    const stale = withMtimes.slice(MAX_SNAPSHOTS_RETAINED)
    await Promise.all(
      stale.map((entry) =>
        unlink(join(dir, entry.n)).catch(() => undefined)
      )
    )
  } catch (err) {
    logEvent('debug', 'snapshot', 'prune failed', { err: (err as Error).message })
  }
}

let periodicTimer: ReturnType<typeof setInterval> | null = null

export function startPeriodicSnapshots(intervalMs = 60_000): void {
  stopPeriodicSnapshots()
  periodicTimer = setInterval(() => {
    captureSnapshot('periodic').catch(() => undefined)
  }, intervalMs)
}

export function stopPeriodicSnapshots(): void {
  if (periodicTimer) {
    clearInterval(periodicTimer)
    periodicTimer = null
  }
}

export function getSnapshotsDir(): string {
  return snapshotsDir()
}
