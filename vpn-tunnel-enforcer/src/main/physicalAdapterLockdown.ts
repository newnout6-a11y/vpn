/**
 * Hard lockdown of the physical adapter while TUN is up.
 *
 * The motivating bug: even with `auto_route: true` + `strict_route: true` +
 * the firewall kill-switch, real users are seeing leaks where the browser
 * shows the original Beeline IP and DNS resolves through the ISP. Possible
 * causes we observed in the wild:
 *
 *   1. Browser-side DNS-over-HTTPS that bypasses NRPT + uses the system
 *      default route (which still has a small fallback scope to the physical
 *      adapter when the OS is "uncertain" about the TUN's reachability).
 *   2. IPv6 traffic getting routed through the physical adapter because the
 *      OS picked the lower-metric IPv6 default route from the physical NIC
 *      over our TUN's split-default IPv6 routes.
 *   3. The Windows DHCP-pushed DNS servers staying configured on the
 *      physical adapter and being queried for `getaddrinfo()` calls that
 *      happened to bind to that interface.
 *
 * This module's nuke-from-orbit response: on TUN start, disable IPv6 on every
 * physical adapter and optionally force their IPv4 DNS to point to the TUN's
 * resolver. On TUN stop / rollback, restore exactly what was there before.
 *
 * Wintun adapters are excluded by name and InterfaceType. Tailscale and other
 * "RemoteAccess" adapters are also excluded — we only touch real Wi-Fi /
 * Ethernet.
 *
 * Persistence: the rollback manifest lives in `userData/latest-physical-adapter-lockdown.json`.
 * If the app crashes / is killed while lockdown is active, the next startup
 * (in `index.ts`) reads the manifest and rolls back, just like baseline +
 * kill-switch.
 */
import { app } from 'electron'
import { existsSync } from 'fs'
import { readFile, writeFile, unlink } from 'fs/promises'
import { join } from 'path'
import { execElevated } from './admin'
import { logEvent } from './appLogger'
import { TUN_ADAPTER_ALIAS, TUN_IPV4_GATEWAY, TUN_IPV4_RESOLVER } from './tunAdapter'

const MANIFEST_BASENAME = 'latest-physical-adapter-lockdown.json'

interface AdapterSnapshot {
  // Stable adapter identifier on Windows.
  ifIndex: number
  alias: string
  // What we found before we touched it. We restore exactly these.
  ipv6Enabled: boolean
  ipv4DnsServers: string[]
  // What we set it to (or null if we left it alone for that field).
  forcedDnsTo: string[] | null
  forcedIpv6Off: boolean
}

interface TransitionAdapterSnapshot {
  teredoType: string | null
  sixToFourState: string | null
  isatapState: string | null
}

interface LockdownManifest {
  appliedAt: number
  tunDnsIpv4: string
  forceDns?: boolean
  adapters: AdapterSnapshot[]
  transitionAdapters?: TransitionAdapterSnapshot
}

interface LockdownOptions {
  forceDns?: boolean
}

interface RollbackOptions {
  resetDnsToDhcp?: boolean
}

export interface PhysicalAdapterDnsSource {
  ifIndex: number
  alias: string
  ipv4DnsServers: string[]
}

function manifestPath(): string {
  return join(app.getPath('userData'), MANIFEST_BASENAME)
}

async function readManifest(): Promise<LockdownManifest | null> {
  try {
    if (!existsSync(manifestPath())) return null
    const raw = await readFile(manifestPath(), 'utf-8')
    return JSON.parse(raw) as LockdownManifest
  } catch {
    return null
  }
}

function sanitizeDnsServers(values: unknown): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of Array.isArray(values) ? values : []) {
    const value = String(raw ?? '').trim()
    if (!value || value === TUN_IPV4_GATEWAY || value === TUN_IPV4_RESOLVER) continue
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

function summarizeDnsSources(adapters: AdapterSnapshot[]): PhysicalAdapterDnsSource[] {
  return adapters
    .map((adapter) => ({
      ifIndex: adapter.ifIndex,
      alias: adapter.alias,
      ipv4DnsServers: sanitizeDnsServers(adapter.ipv4DnsServers)
    }))
    .filter((adapter) => adapter.ipv4DnsServers.length > 0)
}

async function writeManifest(m: LockdownManifest): Promise<void> {
  await writeFile(manifestPath(), JSON.stringify(m, null, 2), 'utf-8')
}

async function deleteManifest(): Promise<void> {
  try {
    if (existsSync(manifestPath())) await unlink(manifestPath())
  } catch (err) {
    logEvent('warn', 'phys-lockdown', 'manifest delete failed', err)
  }
}

function psSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`
}

async function runPS(script: string, timeoutMs = 30000): Promise<string> {
  // CRITICAL: force UTF-8 output. On Russian Windows the default
  // Console.OutputEncoding is CP866, which gives us mojibake for adapter
  // names like "Беспроводная сеть". When we then pipe that mojibake string
  // back into Set-DnsClientServerAddress / Disable-NetAdapterBinding as
  // -InterfaceAlias, those cmdlets cannot find a matching adapter and the
  // lockdown silently fails (we observed this on a real user's machine —
  // forcedDnsTo was null and forcedIpv6Off was false because the per-adapter
  // commands all errored out with "не удалось обнаружить соответствующие объекты").
  // The prefix below makes both stdout encoding and pipeline encoding UTF-8
  // so the alias survives round-tripping JSON.parse → JS string → next PS call.
  // ProgressPreference suppresses the "Preparing modules for first use"
  // CLIXML that otherwise pollutes stdout when stdout is redirected.
  const utf8Prefix =
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;$OutputEncoding=[System.Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"
  const encoded = Buffer.from(utf8Prefix + script, 'utf-16le').toString('base64')
  const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encoded}`
  const { stdout } = await execElevated(cmd, { timeout: timeoutMs })
  return stdout.toString()
}

/**
 * Snapshot every "real" physical adapter (Ethernet / Wi-Fi) that is currently
 * up. We INTENTIONALLY exclude:
 *   - Wintun (our TUN — VPNTE-TUN)
 *   - Tailscale (also Wintun-based)
 *   - WireGuard / OpenVPN tap drivers
 *   - Loopback
 *   - Hyper-V virtual switches (vEthernet)
 *
 * The shape we get back from PowerShell:
 *   [{ifIndex, alias, ipv6Enabled, ipv4DnsServers}]
 *
 * Note: PS arrays of single objects deserialize as the object itself, so we
 * normalize that on the JS side.
 */
async function snapshotPhysicalAdapters(): Promise<AdapterSnapshot[]> {
  // We DON'T filter by HardwareInterface=$true because some real Wi-Fi
  // adapters (especially on laptops with funky drivers) report it as $false
  // and we'd otherwise skip them and leak. Instead we filter by adapter
  // description against the known virtual/loopback families. If a real
  // adapter has a description matching one of those, we want it skipped
  // anyway. We additionally require a physical MAC address (LinkLayerAddress
  // present and not all-zeros) to dodge purely-software adapters.
  const script = `
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()
$adapters = Get-NetAdapter |
  Where-Object {
    $_.Status -eq 'Up' -and
    $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth' -and
    $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00'
  }
foreach ($a in $adapters) {
  $bind6 = Get-NetAdapterBinding -InterfaceAlias $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
  $dns4 = (Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
  if ($null -eq $dns4) { $dns4 = @() }
  $rows += [pscustomobject]@{
    ifIndex      = [int]$a.ifIndex
    alias        = [string]$a.Name
    ipv6Enabled  = [bool]($bind6 -and $bind6.Enabled)
    ipv4Dns      = @($dns4)
  }
}
$rows | ConvertTo-Json -Compress -Depth 4
`
  const stdout = await runPS(script, 20000)
  const text = stdout.trim()
  if (!text || text === 'null') return []
  let parsed: any
  try {
    parsed = JSON.parse(text)
  } catch (err) {
    logEvent('warn', 'phys-lockdown', 'snapshot parse failed', { err: (err as Error).message, raw: text.slice(0, 200) })
    return []
  }
  const arr = Array.isArray(parsed) ? parsed : [parsed]
  return arr.map((row: any) => ({
    ifIndex: Number(row.ifIndex),
    alias: String(row.alias),
    ipv6Enabled: Boolean(row.ipv6Enabled),
    ipv4DnsServers: Array.isArray(row.ipv4Dns) ? row.ipv4Dns.map((x: any) => String(x)) : [],
    forcedDnsTo: null,
    forcedIpv6Off: false
  }))
}

function netshValue(raw: string, label: string): string | null {
  const line = raw.split(/\r?\n/).find(x => x.trim().toLowerCase().startsWith(label.toLowerCase()))
  if (!line) return null
  const value = line.split(':').slice(1).join(':').trim()
  return value ? value.split(/\s+/)[0].toLowerCase() : null
}

async function snapshotTransitionAdapters(): Promise<TransitionAdapterSnapshot> {
  const script = `
$teredo = netsh interface teredo show state
$sixToFour = netsh interface 6to4 show state
$isatap = netsh interface isatap show state
[pscustomobject]@{
  teredo = ($teredo -join [Environment]::NewLine)
  sixToFour = ($sixToFour -join [Environment]::NewLine)
  isatap = ($isatap -join [Environment]::NewLine)
} | ConvertTo-Json -Compress
`
  try {
    const raw = (await runPS(script, 15000)).trim()
    const parsed = JSON.parse(raw)
    return {
      teredoType: netshValue(String(parsed.teredo ?? ''), 'Type'),
      sixToFourState: netshValue(String(parsed.sixToFour ?? ''), '6to4 Service State'),
      isatapState: netshValue(String(parsed.isatap ?? ''), 'ISATAP State')
    }
  } catch (err) {
    logEvent('warn', 'phys-lockdown', 'transition adapter snapshot failed', err)
    return { teredoType: null, sixToFourState: null, isatapState: null }
  }
}

async function applyTransitionAdapterLockdown(snapshot: TransitionAdapterSnapshot): Promise<string[]> {
  const warnings: string[] = []
  try {
    const out = await runPS(`
$ErrorActionPreference = 'Continue'
try { netsh interface teredo set state type=disabled | Out-Null; Write-Host 'teredo:disabled' } catch { Write-Host "teredo:err: $_" }
try { netsh interface 6to4 set state state=disabled | Out-Null; Write-Host '6to4:disabled' } catch { Write-Host "6to4:err: $_" }
try { netsh interface isatap set state state=disabled | Out-Null; Write-Host 'isatap:disabled' } catch { Write-Host "isatap:err: $_" }
`, 15000)
    for (const line of out.trim().split(/\r?\n/).filter(x => /err/.test(x))) warnings.push(line)
    logEvent('info', 'phys-lockdown', 'transition adapters disabled', { snapshot, out: out.trim() })
  } catch (err: any) {
    warnings.push(err?.message ?? String(err))
    logEvent('warn', 'phys-lockdown', 'transition adapter lockdown failed', err)
  }
  return warnings
}

function netshState(value: string | null, fallback = 'default'): string {
  const normalized = (value || fallback).toLowerCase()
  return /^[a-z]+$/.test(normalized) ? normalized : fallback
}

async function restoreTransitionAdapters(snapshot: TransitionAdapterSnapshot, reason: string): Promise<void> {
  const teredoType = netshState(snapshot.teredoType)
  const sixToFourState = netshState(snapshot.sixToFourState)
  const isatapState = netshState(snapshot.isatapState)
  try {
    const out = await runPS(`
$ErrorActionPreference = 'Continue'
try { netsh interface teredo set state type=${teredoType} | Out-Null; Write-Host 'teredo:restore' } catch { Write-Host "teredo:err: $_" }
try { netsh interface 6to4 set state state=${sixToFourState} | Out-Null; Write-Host '6to4:restore' } catch { Write-Host "6to4:err: $_" }
try { netsh interface isatap set state state=${isatapState} | Out-Null; Write-Host 'isatap:restore' } catch { Write-Host "isatap:err: $_" }
`, 15000)
    logEvent('info', 'phys-lockdown', 'transition adapters restored', { reason, snapshot, out: out.trim() })
  } catch (err) {
    logEvent('warn', 'phys-lockdown', 'transition adapter restore failed', err)
  }
}

/**
 * Apply the lockdown: disable IPv6 on each physical adapter and, unless public
 * Wi-Fi compatibility is enabled, force IPv4 DNS to the TUN's resolver. Each
 * step is logged separately so a partial failure is recoverable.
 */
export async function applyPhysicalAdapterLockdown(tunDnsIpv4: string, options: LockdownOptions = {}): Promise<{ applied: boolean; adapters: number; warnings: string[] }> {
  if (process.platform !== 'win32') {
    return { applied: false, adapters: 0, warnings: ['platform is not Windows'] }
  }
  const forceDns = options.forceDns !== false
  const existing = await readManifest()
  if (existing) {
    logEvent('info', 'phys-lockdown', 'lockdown already applied — skipping (idempotent)', {
      adapters: existing.adapters.length
    })
    return { applied: true, adapters: existing.adapters.length, warnings: [] }
  }

  const [adapters, transitionAdapters] = await Promise.all([
    snapshotPhysicalAdapters(),
    snapshotTransitionAdapters()
  ])
  if (adapters.length === 0) {
    logEvent('warn', 'phys-lockdown', 'no physical adapters to lock down — nothing to do')
    const transitionWarnings = await applyTransitionAdapterLockdown(transitionAdapters)
    await writeManifest({
      appliedAt: Date.now(),
      tunDnsIpv4,
      forceDns,
      adapters,
      transitionAdapters
    })
    return { applied: true, adapters: 0, warnings: ['no physical adapters found', ...transitionWarnings] }
  }

  // Write a PENDING manifest BEFORE we touch any adapter. If the app crashes
  // mid-loop, startup crash-recovery (rollbackPhysicalAdapterLockdownIfApplied)
  // still finds a manifest and can re-enable IPv6 / restore DNS. Without this
  // pre-write, a crash between the first Disable-NetAdapterBinding and the
  // final writeManifest() left IPv6 disabled on physical adapters with NO
  // record to roll back from — the user's IPv6 stayed broken until they
  // manually re-enabled it. We mark each adapter with the change we're ABOUT
  // to make (forcedIpv6Off when it currently has IPv6 on; forcedDnsTo when
  // forceDns) so rollback restores exactly what we intend to change.
  const pendingAdapters: AdapterSnapshot[] = adapters.map((a) => ({
    ...a,
    forcedIpv6Off: a.ipv6Enabled,
    forcedDnsTo: forceDns ? [tunDnsIpv4] : null
  }))
  await writeManifest({
    appliedAt: Date.now(),
    tunDnsIpv4,
    forceDns,
    adapters: pendingAdapters,
    transitionAdapters
  })

  const warnings: string[] = []
  const adapterTasks = adapters.map(async (a) => {
    try {
      const dnsLine = forceDns
        ? `try { Set-DnsClientServerAddress -InterfaceAlias ${psSingleQuote(a.alias)} -ServerAddresses ${psSingleQuote(tunDnsIpv4)} -ErrorAction Stop; Write-Host 'dns:set' } catch { Write-Host "dns:err: $_" }`
        : `Write-Host 'dns:skip'`
      const script = `
$ErrorActionPreference = 'Stop'
try { Disable-NetAdapterBinding -InterfaceAlias ${psSingleQuote(a.alias)} -ComponentID ms_tcpip6 -ErrorAction Stop; Write-Host 'ipv6:off' } catch { Write-Host "ipv6:err: $_" }
${dnsLine}
try { Clear-DnsClientCache -ErrorAction Stop; Write-Host 'cache:clear' } catch {}
`
      const out = await runPS(script, 15000)
      const ipv6Off = /ipv6:off/.test(out)
      const dnsSet = /dns:set/.test(out)
      const dnsSkipped = /dns:skip/.test(out)
      a.forcedIpv6Off = ipv6Off
      a.forcedDnsTo = dnsSet ? [tunDnsIpv4] : null
      if (!ipv6Off || (forceDns && !dnsSet)) {
        warnings.push(`${a.alias}: ${out.trim().split('\n').filter((l) => /err/.test(l)).join('; ') || 'partial'}`)
      }
      logEvent('info', 'phys-lockdown', `locked down ${a.alias}`, { ipv6Off, dnsSet, dnsSkipped })
    } catch (err: any) {
      warnings.push(`${a.alias}: ${err?.message ?? String(err)}`)
      logEvent('warn', 'phys-lockdown', `lockdown failed for ${a.alias}`, err)
    }
  })
  const transitionTask = applyTransitionAdapterLockdown(transitionAdapters).then(w => warnings.push(...w))
  await Promise.all([...adapterTasks, transitionTask])

  // Overwrite the pending manifest with the ACTUAL outcome per adapter (some
  // may have only partially applied). Rollback now restores exactly what was
  // really changed.
  const manifest: LockdownManifest = {
    appliedAt: Date.now(),
    tunDnsIpv4,
    forceDns,
    adapters,
    transitionAdapters
  }
  await writeManifest(manifest)
  return { applied: true, adapters: adapters.length, warnings }
}

/**
 * Roll back exactly what we changed. We re-enable IPv6 only if we forced it
 * off (so we don't accidentally turn ON IPv6 on an adapter that the user had
 * deliberately disabled). DNS is restored to the exact list we snapshotted —
 * empty list means "back to DHCP", which is what `Set-DnsClientServerAddress
 * -ResetServerAddresses` does.
 */
export async function rollbackPhysicalAdapterLockdownIfApplied(reason: string, options: RollbackOptions = {}): Promise<{ rolledBack: boolean }> {
  if (process.platform !== 'win32') return { rolledBack: false }
  const m = await readManifest()
  if (!m) return { rolledBack: false }

  const rollbackTasks = m.adapters.map(async (a) => {
    try {
      const shouldTouchDns = Array.isArray(a.forcedDnsTo) && a.forcedDnsTo.length > 0
      const dnsRestoreLine = !shouldTouchDns
        ? `Write-Host 'dns:noop'`
        : (options.resetDnsToDhcp || a.ipv4DnsServers.length === 0)
          ? `try { Set-DnsClientServerAddress -InterfaceAlias ${psSingleQuote(a.alias)} -ResetServerAddresses -ErrorAction Stop; Write-Host 'dns:reset' } catch { Write-Host "dns:err: $_" }`
          : `try { Set-DnsClientServerAddress -InterfaceAlias ${psSingleQuote(a.alias)} -ServerAddresses ${a.ipv4DnsServers.map(psSingleQuote).join(',')} -ErrorAction Stop; Write-Host 'dns:restore' } catch { Write-Host "dns:err: $_" }`
      const ipv6RestoreLine = a.forcedIpv6Off && a.ipv6Enabled
        ? `try { Enable-NetAdapterBinding -InterfaceAlias ${psSingleQuote(a.alias)} -ComponentID ms_tcpip6 -ErrorAction Stop; Write-Host 'ipv6:on' } catch { Write-Host "ipv6:err: $_" }`
        : `Write-Host 'ipv6:noop'`
      const script = `
$ErrorActionPreference = 'Continue'
${ipv6RestoreLine}
${dnsRestoreLine}
try { Clear-DnsClientCache -ErrorAction Stop } catch {}
`
      const out = await runPS(script, 15000)
      logEvent('info', 'phys-lockdown', `rolled back ${a.alias}`, { reason, out: out.trim() })
    } catch (err) {
      logEvent('warn', 'phys-lockdown', `rollback failed for ${a.alias}`, err)
    }
  })
  const tasks: Promise<void>[] = [...rollbackTasks]
  if (m.transitionAdapters) {
    tasks.push(restoreTransitionAdapters(m.transitionAdapters, reason))
  }
  await Promise.all(tasks)

  await deleteManifest()
  return { rolledBack: true }
}

export async function repairOrphanedPhysicalAdapterDns(reason: string): Promise<{ repaired: boolean; adapters: string[] }> {
  if (process.platform !== 'win32') return { repaired: false, adapters: [] }
  if (await readManifest()) return { repaired: false, adapters: [] }

  const script = `
$ErrorActionPreference = 'SilentlyContinue'
$vpnteDns = @('${TUN_IPV4_GATEWAY}', '${TUN_IPV4_RESOLVER}')
$tunUp = Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.Status -eq 'Up' -and ($_.Name -eq '${TUN_ADAPTER_ALIAS}' -or $_.InterfaceDescription -match 'VPNTE') } |
  Select-Object -First 1
if ($tunUp) {
  [pscustomobject]@{ skipped = 'tun-up'; adapters = @() } | ConvertTo-Json -Compress
  exit 0
}
$fixed = @()
$adapters = Get-NetAdapter |
  Where-Object {
    $_.Status -eq 'Up' -and
    $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth' -and
    $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00'
  }
foreach ($a in $adapters) {
  $dns4 = @((Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
  if ($dns4 | Where-Object { $vpnteDns -contains $_ }) {
    try {
      Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses -ErrorAction Stop
      $fixed += [pscustomobject]@{ alias = [string]$a.Name; oldDns = @($dns4) }
    } catch {}
  }
}
try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
[pscustomobject]@{ skipped = $null; adapters = @($fixed) } | ConvertTo-Json -Compress -Depth 4
`
  try {
    const raw = (await runPS(script, 20000)).trim()
    const parsed = raw ? JSON.parse(raw) : { adapters: [] }
    const adaptersRaw = Array.isArray(parsed.adapters) ? parsed.adapters : parsed.adapters ? [parsed.adapters] : []
    const adapters = adaptersRaw.map((row: any) => String(row.alias || '')).filter(Boolean)
    if (adapters.length) {
      logEvent('warn', 'phys-lockdown', 'repaired orphaned VPNTE DNS on physical adapters', { reason, adapters })
      return { repaired: true, adapters }
    }
  } catch (err) {
    logEvent('warn', 'phys-lockdown', 'orphaned DNS repair failed', { reason, err: (err as Error).message })
  }
  return { repaired: false, adapters: [] }
}

export async function isPhysicalAdapterLockdownApplied(): Promise<boolean> {
  return (await readManifest()) !== null
}

export async function getPhysicalAdapterDnsSources(): Promise<PhysicalAdapterDnsSource[]> {
  if (process.platform !== 'win32') return []
  const manifest = await readManifest()
  if (manifest?.adapters?.length) {
    return summarizeDnsSources(manifest.adapters)
  }
  const snapshot = await snapshotPhysicalAdapters()
  return summarizeDnsSources(snapshot)
}
