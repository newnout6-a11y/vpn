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
import { readFile, writeFile, unlink, rename } from 'fs/promises'
import { join } from 'path'
import { execElevated } from './admin'
import { execElevatedPs, isElevatedPsHelperRunning } from './elevatedPsHelper'
import { logEvent } from './appLogger'
import { LEGACY_TUN_IPV4_PREFIX, TUN_ADAPTER_ALIAS, TUN_IPV4_GATEWAY, TUN_IPV4_PREFIX, TUN_IPV4_RESOLVER } from './tunAdapter'

const MANIFEST_BASENAME = 'latest-physical-adapter-lockdown.json'

interface AdapterSnapshot {
  // Stable adapter identifier on Windows.
  ifIndex: number
  alias: string
  // What we found before we touched it. We restore exactly these.
  ipv6Enabled: boolean
  ipv4DnsServers: string[]
  ipv4DnsSource?: 'dhcp' | 'static' | 'unknown'
  // What we set it to (or null if we left it alone for that field).
  forcedDnsTo: string[] | null
  forcedIpv6Off: boolean
}

interface TransitionAdapterSnapshot {
  teredoType: string | null
  sixToFourState: string | null
  isatapState: string | null
}

interface RegistryValueSnapshot {
  exists: boolean
  type?: string
  data?: string
}

interface DnsRegistryPolicySnapshot {
  smartNameResolution: RegistryValueSnapshot
  parallelAandAAAA: RegistryValueSnapshot
}

interface LockdownManifest {
  appliedAt: number
  tunDnsIpv4: string
  forceDns?: boolean
  adapters: AdapterSnapshot[]
  transitionAdapters?: TransitionAdapterSnapshot
  dnsRegistryPolicy?: DnsRegistryPolicySnapshot
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
  const tmp = manifestPath() + '.tmp'
  await writeFile(tmp, JSON.stringify(m, null, 2), 'utf-8')
  await rename(tmp, manifestPath())
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
  // Use persistent PS helper if available — avoids 300-800ms
  // powershell.exe startup overhead per call.
  if (isElevatedPsHelperRunning()) {
    try {
      const result = await execElevatedPs(utf8Prefix + script, timeoutMs, 'physical-adapter-lockdown')
      return result.stdout
    } catch {
      // PS helper failed — fall back to execElevated
    }
  }
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
let snapshotPromise: Promise<AdapterSnapshot[]> | null = null
let snapshotPromiseTime = 0

async function snapshotPhysicalAdapters(): Promise<AdapterSnapshot[]> {
  if (snapshotPromise && Date.now() - snapshotPromiseTime < 10000) {
    return snapshotPromise
  }

  snapshotPromiseTime = Date.now()
  snapshotPromise = (async () => {
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
  $nameServer = ''
  try {
    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($a.InterfaceGuid)"
    $nameServer = [string]((Get-ItemProperty -Path $regPath -Name NameServer -ErrorAction SilentlyContinue).NameServer)
  } catch {}
  $rows += [pscustomobject]@{
    ifIndex      = [int]$a.ifIndex
    alias        = [string]$a.Name
    ipv6Enabled  = [bool]($bind6 -and $bind6.Enabled)
    ipv4Dns      = @($dns4)
    ipv4DnsSource = $(if ([string]::IsNullOrWhiteSpace($nameServer)) { 'dhcp' } else { 'static' })
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
    ipv4DnsSource: row.ipv4DnsSource === 'static' || row.ipv4DnsSource === 'dhcp' ? row.ipv4DnsSource : 'unknown',
    forcedDnsTo: null,
    forcedIpv6Off: false
  }))
  })()

  try {
    return await snapshotPromise
  } catch (err) {
    snapshotPromise = null
    throw err
  }
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
try { netsh interface teredo set state type=disabled | Out-Null; Write-Output 'teredo:disabled' } catch { Write-Output "teredo:err: $_" }
try { netsh interface 6to4 set state state=disabled | Out-Null; Write-Output '6to4:disabled' } catch { Write-Output "6to4:err: $_" }
try { netsh interface isatap set state state=disabled | Out-Null; Write-Output 'isatap:disabled' } catch { Write-Output "isatap:err: $_" }
`, 15000)
    for (const line of out.trim().split(/\r?\n/).filter(x => /err/.test(x))) warnings.push(line)
    logEvent('info', 'phys-lockdown', 'transition adapters disabled', { snapshot, out: out.trim() })
  } catch (err: any) {
    warnings.push(err?.message ?? String(err))
    logEvent('warn', 'phys-lockdown', 'transition adapter lockdown failed', err)
  }
  return warnings
}

function netshState(value: string | null): string | null {
  const normalized = String(value || '').trim().toLowerCase()
  return /^[a-z]+$/.test(normalized) ? normalized : null
}

function netshRestoreLine(tag: string, command: string, value: string | null): string {
  const state = netshState(value)
  if (!state) return `Write-Output '${tag}:unknown'`
  return `try { ${command}${state} | Out-Null; Write-Output '${tag}:restore' } catch { Write-Output "${tag}_err: $_" }`
}

function registryRestoreLine(tag: string, key: string, name: string, snapshot?: RegistryValueSnapshot): string {
  if (snapshot?.exists && snapshot.type && snapshot.data) {
    return `try { reg add ${psSingleQuote(key)} /v ${psSingleQuote(name)} /t ${psSingleQuote(snapshot.type)} /d ${psSingleQuote(snapshot.data)} /f | Out-Null; Write-Output '${tag}:restore' } catch { Write-Output "${tag}_err: $_" }`
  }
  return `try { reg delete ${psSingleQuote(key)} /v ${psSingleQuote(name)} /f 2>$null | Out-Null; Write-Output '${tag}:delete' } catch { Write-Output "${tag}_err: $_" }`
}

async function snapshotDnsRegistryPolicy(): Promise<DnsRegistryPolicySnapshot> {
  const script = `
function Read-RegValue([string]$key, [string]$name, [string]$tag) {
  $out = & reg query $key /v $name 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $out) {
    [PSCustomObject]@{ tag=$tag; exists=$false; type=$null; data=$null }
    return
  }
  $line = @($out) | Where-Object { $_ -match "\\s$name\\s+" } | Select-Object -First 1
  if (-not $line) {
    [PSCustomObject]@{ tag=$tag; exists=$false; type=$null; data=$null }
    return
  }
  $parts = $line.Trim() -split '\\s+', 3
  [PSCustomObject]@{
    tag=$tag
    exists=$true
    type= if ($parts.Length -ge 2) { $parts[1] } else { $null }
    data= if ($parts.Length -ge 3) { $parts[2] } else { $null }
  }
}
@(
  Read-RegValue 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' 'DisableSmartNameResolution' 'smartNameResolution'
  Read-RegValue 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' 'DisableParallelAandAAAA' 'parallelAandAAAA'
) | ConvertTo-Json -Compress`
  try {
    const out = await runPS(script, 15000)
    const rows = JSON.parse(out.trim() || '[]')
    const list = Array.isArray(rows) ? rows : [rows]
    const byTag = new Map<string, any>(list.map((row) => [String(row?.tag || ''), row]))
    const read = (tag: string): RegistryValueSnapshot => {
      const row = byTag.get(tag)
      return {
        exists: row?.exists === true,
        type: typeof row?.type === 'string' && row.type ? row.type : undefined,
        data: typeof row?.data === 'string' && row.data ? row.data : undefined
      }
    }
    return {
      smartNameResolution: read('smartNameResolution'),
      parallelAandAAAA: read('parallelAandAAAA')
    }
  } catch (err) {
    logEvent('warn', 'phys-lockdown', 'DNS registry policy snapshot failed; rollback will delete app policy keys only', err)
    return {
      smartNameResolution: { exists: false },
      parallelAandAAAA: { exists: false }
    }
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
  let existing = await readManifest()
  if (existing && (existing.tunDnsIpv4 !== tunDnsIpv4 || (existing.forceDns !== false) !== forceDns)) {
    logEvent('warn', 'phys-lockdown', 'existing lockdown options differ; rolling back before reapply', {
      existingTunDnsIpv4: existing.tunDnsIpv4,
      requestedTunDnsIpv4: tunDnsIpv4,
      existingForceDns: existing.forceDns !== false,
      requestedForceDns: forceDns
    })
    const rollback = await rollbackPhysicalAdapterLockdownIfApplied('lockdown options changed before reapply')
    if (!rollback.rolledBack) {
      return {
        applied: true,
        adapters: existing.adapters.length,
        warnings: ['existing lockdown options differ but rollback did not complete']
      }
    }
    existing = null
  }
  if (existing) {
    logEvent('info', 'phys-lockdown', 'lockdown already applied — skipping (idempotent)', {
      adapters: existing.adapters.length
    })
    return { applied: true, adapters: existing.adapters.length, warnings: [] }
  }

  const [adapters, transitionAdapters, dnsRegistryPolicy] = await Promise.all([
    snapshotPhysicalAdapters(),
    snapshotTransitionAdapters(),
    snapshotDnsRegistryPolicy()
  ])
  if (adapters.length === 0) {
    logEvent('warn', 'phys-lockdown', 'no physical adapters to lock down — nothing to do')
    const transitionWarnings = await applyTransitionAdapterLockdown(transitionAdapters)
    await writeManifest({
      appliedAt: Date.now(),
      tunDnsIpv4,
      forceDns,
      adapters,
      transitionAdapters,
      dnsRegistryPolicy
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
    transitionAdapters,
    dnsRegistryPolicy
  })

  const warnings: string[] = []
  
  let combinedScript = `$ErrorActionPreference = 'Continue'\n`
  for (let i = 0; i < adapters.length; i++) {
    const a = adapters[i]
    const dnsLine = forceDns
      ? `try { Set-DnsClientServerAddress -InterfaceAlias ${psSingleQuote(a.alias)} -ServerAddresses ${psSingleQuote(tunDnsIpv4)} -ErrorAction Stop; Write-Output "A${i}_dns:set" } catch { Write-Output "A${i}_dns_err: $_" }`
      : `Write-Output "A${i}_dns:skip"`
    combinedScript += `
try { Disable-NetAdapterBinding -InterfaceAlias ${psSingleQuote(a.alias)} -ComponentID ms_tcpip6 -ErrorAction Stop; Write-Output "A${i}_ipv6:off" } catch { Write-Output "A${i}_ipv6_err: $_" }
${dnsLine}
`
  }

  // Also include the transition adapters in the same script
  combinedScript += `
try { netsh interface teredo set state type=disabled | Out-Null; Write-Output 'TRANS_teredo:disabled' } catch { Write-Output "TRANS_teredo_err: $_" }
try { netsh interface 6to4 set state state=disabled | Out-Null; Write-Output 'TRANS_6to4:disabled' } catch { Write-Output "TRANS_6to4_err: $_" }
try { netsh interface isatap set state state=disabled | Out-Null; Write-Output 'TRANS_isatap:disabled' } catch { Write-Output "TRANS_isatap_err: $_" }
try { reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f | Out-Null; Write-Output 'DNS_SMNR:off' } catch { Write-Output "DNS_SMNR_err: $_" }
try { reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f | Out-Null; Write-Output 'DNS_PARALLEL:off' } catch { Write-Output "DNS_PARALLEL_err: $_" }
try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
`

  try {
    const out = await runPS(combinedScript, 30000)
    
    // Parse results for physical adapters
    for (let i = 0; i < adapters.length; i++) {
      const a = adapters[i]
      try {
        const ipv6Off = new RegExp(`A${i}_ipv6:off`).test(out)
        const dnsSet = new RegExp(`A${i}_dns:set`).test(out)
        const dnsSkipped = new RegExp(`A${i}_dns:skip`).test(out)
        
        a.forcedIpv6Off = ipv6Off
        a.forcedDnsTo = dnsSet ? [tunDnsIpv4] : null
        
        if (!ipv6Off || (forceDns && !dnsSet)) {
          const errs = out.trim().split(/\r?\n/).filter(l => new RegExp(`A${i}_.*err:`).test(l)).join('; ')
          warnings.push(`${a.alias}: ${errs || 'partial'}`)
        }
        logEvent('info', 'phys-lockdown', `locked down ${a.alias}`, { ipv6Off, dnsSet, dnsSkipped })
      } catch (err: any) {
        warnings.push(`${a.alias}: ${err?.message ?? String(err)}`)
        logEvent('warn', 'phys-lockdown', `lockdown failed for ${a.alias}`, err)
      }
    }

    // Parse results for transition adapters
    for (const line of out.trim().split(/\r?\n/).filter(x => /TRANS_.*_err/.test(x))) {
      warnings.push(line)
    }
    for (const line of out.trim().split(/\r?\n/).filter(x => /DNS_.*_err/.test(x))) {
      warnings.push(line)
    }
    logEvent('info', 'phys-lockdown', 'transition adapters disabled', { snapshot: transitionAdapters, out: out.trim() })
  } catch (err: any) {
    warnings.push(`Batch PS error: ${err?.message ?? String(err)}`)
    logEvent('warn', 'phys-lockdown', 'batch lockdown failed', err)
    // CRITICAL: Do NOT overwrite the pending manifest with unmutated adapters.
    // The PS script may have partially executed (e.g., adapter 0 got
    // Disable-NetAdapterBinding before timeout). If we overwrite the manifest
    // with "nothing changed", rollback will do nothing and the user's IPv6
    // stays disabled + DNS pinned to dead TUN resolver.
    // Instead, keep the pending manifest (which assumes all changes were made)
    // so rollback will attempt to restore everything.
    return { applied: true, adapters: adapters.length, warnings }
  }

  // Only overwrite the pending manifest if the PS script completed
  // successfully — we can trust the parsed markers to reflect actual state.
  const manifest: LockdownManifest = {
    appliedAt: Date.now(),
    tunDnsIpv4,
    forceDns,
    adapters,
    transitionAdapters,
    dnsRegistryPolicy
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

  let combinedScript = `$ErrorActionPreference = 'Continue'\n`
  
  for (let i = 0; i < m.adapters.length; i++) {
    const a = m.adapters[i]
    const shouldTouchDns = Array.isArray(a.forcedDnsTo) && a.forcedDnsTo.length > 0
    const dnsRestoreLine = !shouldTouchDns
      ? `Write-Output 'A${i}_dns:noop'`
      : (options.resetDnsToDhcp || a.ipv4DnsSource !== 'static')
        ? `try { Set-DnsClientServerAddress -InterfaceAlias ${psSingleQuote(a.alias)} -ResetServerAddresses -ErrorAction Stop; Write-Output 'A${i}_dns:reset' } catch { Write-Output "A${i}_dns_err: $_" }`
        : `try { Set-DnsClientServerAddress -InterfaceAlias ${psSingleQuote(a.alias)} -ServerAddresses ${a.ipv4DnsServers.map(psSingleQuote).join(',')} -ErrorAction Stop; Write-Output 'A${i}_dns:restore' } catch { Write-Output "A${i}_dns_err: $_" }`
    const ipv6RestoreLine = a.forcedIpv6Off && a.ipv6Enabled
      ? `try { Enable-NetAdapterBinding -InterfaceAlias ${psSingleQuote(a.alias)} -ComponentID ms_tcpip6 -ErrorAction Stop; Write-Output 'A${i}_ipv6:on' } catch { Write-Output "A${i}_ipv6_err: $_" }`
      : `Write-Output 'A${i}_ipv6:noop'`
    combinedScript += `
${ipv6RestoreLine}
${dnsRestoreLine}
`
  }

  if (m.transitionAdapters) {
    combinedScript += `
${netshRestoreLine('TRANS_teredo', 'netsh interface teredo set state type=', m.transitionAdapters.teredoType)}
${netshRestoreLine('TRANS_6to4', 'netsh interface 6to4 set state state=', m.transitionAdapters.sixToFourState)}
${netshRestoreLine('TRANS_isatap', 'netsh interface isatap set state state=', m.transitionAdapters.isatapState)}
`
  }
  combinedScript += `
${registryRestoreLine('DNS_SMNR', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient', 'DisableSmartNameResolution', m.dnsRegistryPolicy?.smartNameResolution)}
${registryRestoreLine('DNS_PARALLEL', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters', 'DisableParallelAandAAAA', m.dnsRegistryPolicy?.parallelAandAAAA)}
try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}`

  let rollbackSuccess = true
  try {
    const out = await runPS(combinedScript, 30000)
    for (let i = 0; i < m.adapters.length; i++) {
      const a = m.adapters[i]
      const ipv6Ok = new RegExp(`A${i}_ipv6:on|A${i}_ipv6:noop`).test(out)
      const dnsOk = new RegExp(`A${i}_dns:restore|A${i}_dns:reset|A${i}_dns:noop`).test(out)
      if (!ipv6Ok || !dnsOk) {
        logEvent('warn', 'phys-lockdown', `partial rollback failure for ${a.alias}`, { reason, ipv6Ok, dnsOk })
        rollbackSuccess = false
      } else {
        logEvent('info', 'phys-lockdown', `rolled back ${a.alias}`, { reason })
      }
    }
    if (m.transitionAdapters) {
      const teredoUnknown = /TRANS_teredo:unknown/.test(out)
      const sixTo4Unknown = /TRANS_6to4:unknown/.test(out)
      const isatapUnknown = /TRANS_isatap:unknown/.test(out)
      const teredoOk = /TRANS_teredo:restore/.test(out) || teredoUnknown
      const sixTo4Ok = /TRANS_6to4:restore/.test(out) || sixTo4Unknown
      const isatapOk = /TRANS_isatap:restore/.test(out) || isatapUnknown
      if (!teredoOk || !sixTo4Ok || !isatapOk) {
        logEvent('warn', 'phys-lockdown', 'partial transition adapter rollback', { reason, teredoOk, sixTo4Ok, isatapOk })
        rollbackSuccess = false
      } else if (teredoUnknown || sixTo4Unknown || isatapUnknown) {
        logEvent('warn', 'phys-lockdown', 'transition adapter prior state unknown; left disabled instead of restoring default', { reason, teredoUnknown, sixTo4Unknown, isatapUnknown })
      } else {
        logEvent('info', 'phys-lockdown', 'transition adapters restored', { reason })
      }
    }
    const dnsSmnrOk = /DNS_SMNR:restore|DNS_SMNR:delete/.test(out)
    const dnsParallelOk = /DNS_PARALLEL:restore|DNS_PARALLEL:delete/.test(out)
    if (!dnsSmnrOk || !dnsParallelOk) {
      logEvent('warn', 'phys-lockdown', 'partial DNS registry policy rollback', { reason, dnsSmnrOk, dnsParallelOk })
      rollbackSuccess = false
    }
  } catch (err) {
    logEvent('warn', 'phys-lockdown', `batch rollback failed`, err)
    rollbackSuccess = false
  }

  if (rollbackSuccess) {
    await deleteManifest()
  } else {
    logEvent('warn', 'phys-lockdown', 'manifest kept for retry on next startup — rollback was incomplete', { reason })
  }
  return { rolledBack: rollbackSuccess }
}

export async function repairOrphanedPhysicalAdapterDns(reason: string): Promise<{ repaired: boolean; adapters: string[] }> {
  if (process.platform !== 'win32') return { repaired: false, adapters: [] }
  if (await readManifest()) return { repaired: false, adapters: [] }

  const script = `
$ErrorActionPreference = 'SilentlyContinue'
$vpnteDns = @('${TUN_IPV4_GATEWAY}', '${TUN_IPV4_RESOLVER}')
$vpnteDnsPrefixes = @('${TUN_IPV4_PREFIX}', '${LEGACY_TUN_IPV4_PREFIX}')
$tunUp = Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.Status -eq 'Up' -and ($_.Name -eq '${TUN_ADAPTER_ALIAS}' -or $_.InterfaceDescription -match 'VPNTE') } |
  Select-Object -First 1
if ($tunUp) {
  [pscustomobject]@{ skipped = 'tun-up'; adapters = @() } | ConvertTo-Json -Compress
  return
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
  $nameServer = ''
  try {
    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($a.InterfaceGuid)"
    $nameServer = [string]((Get-ItemProperty -Path $regPath -Name NameServer -ErrorAction SilentlyContinue).NameServer)
  } catch {}
  $staleVpnteDns = @($dns4 | Where-Object {
    $addr = [string]$_
    ($vpnteDns -contains $addr) -or (($vpnteDnsPrefixes | Where-Object { $addr.StartsWith($_) }).Count -gt 0)
  })
  $manualVpnteDns = @($nameServer -split '[, ]+' | Where-Object {
    $addr = [string]$_
    ($vpnteDns -contains $addr) -or (($vpnteDnsPrefixes | Where-Object { $addr.StartsWith($_) }).Count -gt 0)
  })
  if ($staleVpnteDns.Count -gt 0 -and $manualVpnteDns.Count -gt 0) {
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

let dnsSourcesCache: { value: PhysicalAdapterDnsSource[]; at: number } | null = null
const DNS_SOURCES_CACHE_MS = 60000

export async function getPhysicalAdapterDnsSources(): Promise<PhysicalAdapterDnsSource[]> {
  if (process.platform !== 'win32') return []
  // Cache for 60s — adapter DNS sources don't change frequently and the
  // PowerShell snapshot takes ~1-2s. This is only used for smart-RU split
  // routing config generation, not for the actual lockdown.
  if (dnsSourcesCache && Date.now() - dnsSourcesCache.at < DNS_SOURCES_CACHE_MS) {
    return dnsSourcesCache.value
  }
  const manifest = await readManifest()
  if (manifest?.adapters?.length) {
    const result = summarizeDnsSources(manifest.adapters)
    dnsSourcesCache = { value: result, at: Date.now() }
    return result
  }
  const snapshot = await snapshotPhysicalAdapters()
  const result = summarizeDnsSources(snapshot)
  dnsSourcesCache = { value: result, at: Date.now() }
  return result
}
