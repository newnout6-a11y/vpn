import { recoveryManifestPath, readRecoveryManifest, writeRecoveryManifest, removeRecoveryManifest } from './recoveryManifest'
import { executeRecoveryOperation, RecoveryWorkerError } from './recoveryPsWorker'
import { DNS_POLICY_SNAPSHOT_SCRIPT } from './recoveryPsProtocol'
import { PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT } from './physicalAdapterSnapshot'
import { isIP } from 'net'
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
import { readFile, writeFile, unlink, rename, mkdir } from 'fs/promises'
import { join } from 'path'
import { execElevated } from './admin'
import { execElevatedPs, isElevatedPsHelperRunning } from './elevatedPsHelper'
import { logEvent } from './appLogger'
import { ensureElevatedRuntimeDirHardened } from './runtimeDirSecurity'
import { ALL_KNOWN_ALIASES, LEGACY_TUN_IPV4_PREFIX, TUN_ADAPTER_ALIAS, TUN_IPV4_GATEWAY, TUN_IPV4_PREFIX, TUN_IPV4_RESOLVER, getTunAdapterAlias } from './tunAdapter'

const MANIFEST_BASENAME = 'latest-physical-adapter-lockdown.json'

interface AdapterSnapshot {
  // Stable adapter identifier on Windows.
  ifIndex: number
  interfaceGuid?: string
  alias: string
  description?: string
  // What we found before we touched it. We restore exactly these.
  ipv6Enabled: boolean
  ipv4DnsServers: string[]
  ipv4DnsSource?: 'dhcp' | 'static' | 'unknown'
  isCellularOrTethering?: boolean
  // What we set it to (or null if we left it alone for that field).
  forcedDnsTo: string[] | null
  forcedIpv6Off: boolean
}

export function isTetheringSubnetIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string' || isIP(ip.trim()) !== 4) return false
  const trimmed = ip.trim()
  return /^192\.168\.(43|137|225|8)\./.test(trimmed) || /^172\.20\.10\./.test(trimmed)
}

/**
 * Checks whether a network adapter is a cellular modem, USB RNDIS tethering,
 * mobile hotspot, or mobile device adapter. Disabling IPv6 on these adapters breaks 464XLAT /
 * CLAT (cellular carrier NAT64) and kills mobile hotspot connectivity.
 */
export function isCellularOrTetheringAdapter(
  alias: string,
  description = '',
  dnsServers: string[] = [],
  gateways: string[] = [],
  networkProfiles: string[] = []
): boolean {
  const pattern = /\b(rndis|cellular|mobile|wwan|lte|[345]g|modem|tether|tethering)\b|remote ndis|apple mobile device/i
  if (pattern.test(alias) || pattern.test(description)) return true
  if (dnsServers.some((ip) => isTetheringSubnetIp(ip))) return true
  if (gateways.some((ip) => isTetheringSubnetIp(ip))) return true
  // Current Android hotspots may use arbitrary 10/8 DHCP subnets. A private
  // address alone cannot identify tethering; use the connected profile name.
  if (networkProfiles.some(name => /\b(galaxy|iphone|pixel|android|redmi|poco|oneplus)\b|\bmobile hotspot\b|\bточка доступа\b/i.test(name))) return true
  return false
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
  schemaVersion?: 1
  owner?: 'VPNTE'
  appliedAt: number
  tunDnsIpv4: string
  forceDns?: boolean
  adapters: AdapterSnapshot[]
  transitionAdapters?: TransitionAdapterSnapshot
  dnsRegistryPolicy?: DnsRegistryPolicySnapshot
}

interface LockdownOptions {
  forceDns?: boolean
  signal?: AbortSignal
}

interface RollbackOptions {
  resetDnsToDhcp?: boolean
}

export interface PhysicalAdapterDnsSource {
  ifIndex: number
  alias: string
  ipv4DnsServers: string[]
}

function getProgramDataPath(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (app as any).getPath('programData')
  } catch {
    return process.env.ProgramData || 'C:\\ProgramData'
  }
}

export function getLockdownManifestPaths(): { programData: string; userData: string } {
  const programDataDir = recoveryManifestPath(MANIFEST_BASENAME)
  return {
    programData: programDataDir,
    userData: join(app.getPath('userData'), MANIFEST_BASENAME)
  }
}

function manifestPath(): string {
  return getLockdownManifestPaths().userData
}

function programDataManifestPath(): string {
  return getLockdownManifestPaths().programData
}

export function validateLockdownManifest(value: unknown): LockdownManifest {
  const v = value as any
  if (!v || v.schemaVersion !== 1 || v.owner !== 'VPNTE' || !Number.isSafeInteger(v.appliedAt) ||
      !isIP(v.tunDnsIpv4) || !Array.isArray(v.adapters) || v.adapters.length > 256) throw new Error('Invalid lockdown manifest')
  for (const a of v.adapters) {
    if (!a || !Number.isInteger(a.ifIndex) || a.ifIndex <= 0 || typeof a.alias !== 'string' || a.alias.length > 256 ||
        /[\x00-\x1f]/.test(a.alias) || typeof a.ipv6Enabled !== 'boolean' || typeof a.forcedIpv6Off !== 'boolean' ||
        typeof a.interfaceGuid !== 'string' || !/^\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?$/i.test(a.interfaceGuid) ||
        !['dhcp','static','unknown'].includes(a.ipv4DnsSource) ||
        !Array.isArray(a.ipv4DnsServers) || a.ipv4DnsServers.some((ip: unknown) => typeof ip !== 'string' || !isIP(ip)) ||
        !(a.forcedDnsTo === null || (Array.isArray(a.forcedDnsTo) && a.forcedDnsTo.every((ip: string) => isIP(ip))))) throw new Error('Invalid adapter snapshot')
  }
  if (v.transitionAdapters) {
    for (const [key, values] of Object.entries({
      teredoType: ['disabled','default','client','enterpriseclient','natclient','server'],
      sixToFourState: ['disabled','default','enabled'], isatapState: ['disabled','default','enabled']
    })) {
      const state = v.transitionAdapters[key]
      if (state !== null && !values.includes(state)) throw new Error('Invalid transition snapshot')
    }
  }
  if (!v.dnsRegistryPolicy) throw new Error('Missing DNS policy snapshot')
  for (const key of ['smartNameResolution','parallelAandAAAA']) {
    const r = v.dnsRegistryPolicy[key]
    if (!r || typeof r.exists !== 'boolean' || (r.exists && (r.type !== 'REG_DWORD' || typeof r.data !== 'string' || !/^(?:0x[a-f0-9]{1,8}|[0-9]{1,10})$/i.test(r.data) || Number(r.data) > 0xffffffff))) throw new Error('Invalid DNS registry snapshot')
  }
  return v
}
async function readManifest(): Promise<LockdownManifest | null> {
  return readRecoveryManifest(MANIFEST_BASENAME, validateLockdownManifest)
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
  await writeRecoveryManifest(MANIFEST_BASENAME, { ...m, schemaVersion: 1, owner: 'VPNTE' }, validateLockdownManifest)
  // Diagnostic-only copy; it is NEVER consumed by elevated rollback.
  const target = manifestPath()
  await writeFile(target, JSON.stringify(m, null, 2), 'utf8').catch(error => logEvent('warn', 'phys-lockdown', 'diagnostic copy failed', error))
}
async function deleteManifest(): Promise<void> {
  await removeRecoveryManifest(MANIFEST_BASENAME)
  await unlink(manifestPath()).catch((error: any) => { if (error?.code !== 'ENOENT') throw error })
}

function psSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`
}

async function runPS(script: string, timeoutMs = 30000, signal?: AbortSignal): Promise<string> {
  const checkCancellation = () => {
    if (signal?.aborted) throw Object.assign(new Error('Adapter apply cancelled before dispatch'), {
      code: 'physical-lockdown-cancelled-before-dispatch'
    })
  }
  checkCancellation()
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
    let result: Awaited<ReturnType<typeof execElevatedPs>> | undefined
    try {
      result = await execElevatedPs(utf8Prefix + script, timeoutMs, 'physical-adapter-lockdown')
    } catch (err: any) {
      // A lost reply may follow native effects. Only a known rejection before
      // dispatch permits replay through the fallback transport.
      if (!['elevated-helper-script-rejected', 'elevated-helper-script-too-large', 'elevated-helper-unavailable'].includes(err?.code)) throw err
      logEvent('debug', 'phys-lockdown', 'helper fallback', { code: err.code })
    }
    if (result) {
      if (result.exitCode) throw new Error(result.stderr || `Adapter command failed (exit ${result.exitCode})`)
      return result.stdout
    }
  }
  checkCancellation()
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
let cachedAdaptersSnapshot: AdapterSnapshot[] | null = null
let cachedAdaptersSnapshotTime = 0
let snapshotPromise: Promise<AdapterSnapshot[]> | null = null

export function clearPhysicalAdaptersSnapshotCache(): void {
  cachedAdaptersSnapshot = null
  cachedAdaptersSnapshotTime = 0
  snapshotPromise = null
}

async function snapshotPhysicalAdapters(): Promise<AdapterSnapshot[]> {
  // Return the fresh snapshot if taken within 10s to avoid expensive PS reruns.
  if (cachedAdaptersSnapshot && Date.now() - cachedAdaptersSnapshotTime < 10000) {
    return cachedAdaptersSnapshot
  }
  // Return the in-flight promise directly so concurrent callers share one PS run.
  if (snapshotPromise) {
    return snapshotPromise
  }

  snapshotPromise = (async () => {
    let stdout: string
    try {
      stdout = await executeRecoveryOperation({ op: 'inspect-physical-adapters' }, 20000)
    } catch (error) {
      // Only unavailability before dispatch permits another transport.
      if (!(error instanceof RecoveryWorkerError) || error.code !== 'unavailable') throw error
      stdout = await runPS(PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT, 20000)
    }
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
    const result = arr.map((row: any) => {
      const alias = String(row.alias || '')
      const description = String(row.description || '')
      const dnsServers = Array.isArray(row.ipv4Dns) ? row.ipv4Dns.map((x: any) => String(x)) : []
      const gateways = Array.isArray(row.gateways) ? row.gateways.map(String) : []
      const profiles = Array.isArray(row.networkProfiles) ? row.networkProfiles.map(String) : []
      const nativeMobile = Boolean(row.isCellularOrTethering)
      const knownMobile = isCellularOrTetheringAdapter(alias, description, dnsServers, gateways)
      const profileMobile = isCellularOrTetheringAdapter('', '', [], [], profiles)
      const isCellularOrTethering = nativeMobile || knownMobile || profileMobile
      logEvent('info', 'phys-lockdown', 'physical uplink classification', {
        ifIndex: Number(row.ifIndex),
        mobile: isCellularOrTethering,
        method: knownMobile ? 'device-or-subnet' : nativeMobile ? 'native-media-or-v6-only' : profileMobile ? 'mobile-network-profile' : 'ordinary-network',
        v6EnabledBefore: Boolean(row.ipv6Enabled),
        v4DefaultCount: gateways.length,
        configuredResolverCount: dnsServers.length,
        resolverSource: row.ipv4DnsSource
      })
      return {
        ifIndex: Number(row.ifIndex),
        interfaceGuid: String(row.interfaceGuid || ''),
        alias,
        description,
        ipv6Enabled: Boolean(row.ipv6Enabled),
        ipv4DnsServers: dnsServers,
        ipv4DnsSource: row.ipv4DnsSource === 'static' || row.ipv4DnsSource === 'dhcp' ? row.ipv4DnsSource : 'unknown',
        isCellularOrTethering,
        forcedDnsTo: null,
        forcedIpv6Off: false
      }
    })
    cachedAdaptersSnapshot = result
    cachedAdaptersSnapshotTime = Date.now()
    return result
  })().finally(() => {
    snapshotPromise = null
  })

  try {
    return await snapshotPromise
  } catch (err) {
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
  return `try { ${command}${state} | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'native command failed' }; Write-Output '${tag}:restore' } catch { Write-Output "${tag}_err: $_" }`
}

function registryRestoreLine(tag: string, key: string, name: string, snapshot?: RegistryValueSnapshot): string {
  if (!snapshot) return `Write-Output '${tag}_err: missing ownership snapshot'`
  const keyPath = psSingleQuote(key.replace(/^HKLM\\/, ''))
  const valueName = psSingleQuote(name)
  const expected = Number(snapshot.data || 0) | 0
  return `
$key = $null
try {
  $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(${keyPath})
  ${snapshot.exists ? `$key.SetValue(${valueName},[int]${expected},[Microsoft.Win32.RegistryValueKind]::DWord)` : `$key.DeleteValue(${valueName},$false)`}
  $present = @($key.GetValueNames()) -contains ${valueName}
  if ($present -ne $${snapshot.exists ? 'true' : 'false'}) { throw 'Registry presence read-back mismatch' }
  ${snapshot.exists ? `if ($key.GetValueKind(${valueName}) -ne [Microsoft.Win32.RegistryValueKind]::DWord -or [int]$key.GetValue(${valueName}) -ne ${expected}) { throw 'Registry value read-back mismatch' }` : ''}
  Write-Output '${tag}:${snapshot.exists ? 'restore' : 'delete'}'
} catch { Write-Output "${tag}_err: $_" }
finally { if ($key) { $key.Close() } }
`
}

function registryApplyLine(tag: string, key: string, name: string): string {
  return `
$key = $null
try {
  $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(${psSingleQuote(key.replace(/^HKLM\\/, ''))})
  $alreadyOff = @($key.GetValueNames()) -contains ${psSingleQuote(name)}
  if ($alreadyOff) { $alreadyOff = $key.GetValueKind(${psSingleQuote(name)}) -eq [Microsoft.Win32.RegistryValueKind]::DWord -and [int]$key.GetValue(${psSingleQuote(name)}) -eq 1 }
  if (-not $alreadyOff) { $key.SetValue(${psSingleQuote(name)},[int]1,[Microsoft.Win32.RegistryValueKind]::DWord) }
  if ($key.GetValueKind(${psSingleQuote(name)}) -ne [Microsoft.Win32.RegistryValueKind]::DWord -or [int]$key.GetValue(${psSingleQuote(name)}) -ne 1) { throw 'Registry value read-back mismatch' }
  if ($alreadyOff) { Write-Output '${tag}:already-off' }
  Write-Output '${tag}:off'
} catch { Write-Output "${tag}_err: $_" }
finally { if ($key) { $key.Close() } }
`
}

async function snapshotDnsRegistryPolicy(): Promise<DnsRegistryPolicySnapshot> {
  try {
    let out: string
    try { out = await executeRecoveryOperation({ op: 'inspect-dns-policy' }) }
    catch (error) {
      // Only unavailability before admission allows the existing fixed fallback.
      if (!(error instanceof RecoveryWorkerError) || error.code !== 'unavailable') throw error
      out = await runPS(DNS_POLICY_SNAPSHOT_SCRIPT, 15000)
    }
    const list = JSON.parse(out.trim())
    if (!Array.isArray(list) || list.length !== 2) throw new Error('Incomplete DNS registry snapshot')
    const tags = new Set(['smartNameResolution', 'parallelAandAAAA'])
    for (const row of list) {
      if (!row || typeof row !== 'object' || Object.keys(row).sort().join(',') !== 'data,exists,tag,type'
        || !tags.delete(row.tag) || typeof row.exists !== 'boolean') throw new Error('Invalid DNS registry snapshot')
      if (row.exists ? row.type !== 'REG_DWORD' || typeof row.data !== 'string' || !/^0x[0-9a-f]{1,8}$/i.test(row.data)
        : row.type !== null || row.data !== null) throw new Error('Unsupported DNS registry snapshot value')
    }
    const byTag = new Map<string, any>(list.map(row => [row.tag, row]))
    const read = (tag: string): RegistryValueSnapshot => {
      const row = byTag.get(tag)
      if (!row || typeof row.exists !== 'boolean') throw new Error('Incomplete DNS registry snapshot')
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
    logEvent('error', 'phys-lockdown', 'DNS registry snapshot failed; refusing mutation without baseline', err)
    throw new Error('DNS registry baseline could not be verified')
  }
}

/**
 * Apply the lockdown: disable IPv6 on each physical adapter and, unless public
 * Wi-Fi compatibility is enabled, force IPv4 DNS to the TUN's resolver. Each
 * step is logged separately so a partial failure is recoverable.
 */
export async function applyPhysicalAdapterLockdown(tunDnsIpv4: string, options: LockdownOptions = {}): Promise<{ applied: boolean; adapters: number; warnings: string[]; cancelled?: boolean }> {
  if (process.platform !== 'win32') {
    return { applied: false, adapters: 0, warnings: ['platform is not Windows'] }
  }
  const cancelled = (phase: string, applied = false, adapters = 0) => {
    logEvent('info', 'phys-lockdown', 'lockdown cancelled before native apply', { phase, pendingRecovery: applied })
    return { applied, adapters, warnings: [] as string[], cancelled: true }
  }
  if (options.signal?.aborted) return cancelled('entry')
  const forceDns = options.forceDns !== false
  const verifyAdapterSet = async (expected: AdapterSnapshot[]) => {
    clearPhysicalAdaptersSnapshotCache()
    let warning = 'physical adapter set changed; lockdown coverage is not verified'
    try {
      const current = await snapshotPhysicalAdapters()
      const identity = (a: AdapterSnapshot) => (a.interfaceGuid || '').replace(/[{}]/g, '').toLowerCase()
      const expectedIds = new Set(expected.map(identity))
      if (current.length > 0 && current.length === expected.length && expectedIds.size === expected.length &&
          !expectedIds.has('') && new Set(current.map(identity)).size === current.length && current.every(a => expectedIds.has(identity(a)))) return null
    } catch (err) {
      warning = `physical adapter set could not be verified: ${String(err)}`
    }
    logEvent('warn', 'phys-lockdown', warning)
    let rolledBack = false
    try { rolledBack = (await rollbackPhysicalAdapterLockdownIfApplied(warning)).rolledBack } catch (err) {
      logEvent('warn', 'phys-lockdown', 'adapter coverage rollback failed', err)
    }
    return { applied: !rolledBack, adapters: expected.length, warnings: [warning, ...(!rolledBack ? ['adapter coverage rollback did not complete; recovery journal retained'] : [])] }
  }
  let existing = await readManifest()
  // Reading a baseline is safe to finish; cancellation must prevent the next
  // mutation. An existing journal still belongs to lifecycle compensation.
  if (options.signal?.aborted) return cancelled('manifest-read', !!existing, existing?.adapters.length ?? 0)
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
    if (options.signal?.aborted) return cancelled('previous-rollback')
  }
  if (existing) {
    const coverageFailure = await verifyAdapterSet(existing.adapters)
    if (coverageFailure) return coverageFailure
    logEvent('info', 'phys-lockdown', 'lockdown already applied — skipping (idempotent)', {
      adapters: existing.adapters.length
    })
    return { applied: true, adapters: existing.adapters.length, warnings: [] }
  }

  clearPhysicalAdaptersSnapshotCache()
  const [adapters, transitionAdapters, dnsRegistryPolicy] = await Promise.all([
    snapshotPhysicalAdapters(),
    snapshotTransitionAdapters(),
    snapshotDnsRegistryPolicy()
  ])
  if (options.signal?.aborted) return cancelled('snapshot')
  if (adapters.length === 0) {
    logEvent('error', 'phys-lockdown', 'lockdown not checked: no physical adapters were discovered')
    return { applied: false, adapters: 0, warnings: ['no physical adapters found; lockdown was not applied'] }
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
    forcedIpv6Off: a.isCellularOrTethering ? false : a.ipv6Enabled,
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
  // Once the durable journal exists, keep it for the normal recovery owner.
  // Never interrupt an admitted native batch or race its compensation.
  if (options.signal?.aborted) return cancelled('pending-manifest', true, adapters.length)

  const warnings: string[] = []
  
  let combinedScript = `$ErrorActionPreference = 'Continue'\n`
  for (let i = 0; i < adapters.length; i++) {
    const a = adapters[i]
    const dnsLine = forceDns
      ? `try { Set-DnsClientServerAddress -InterfaceAlias $ownedAdapter.Name -ServerAddresses ${psSingleQuote(tunDnsIpv4)} -ErrorAction Stop; if (@((Get-DnsClientServerAddress -InterfaceAlias $ownedAdapter.Name -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses) -join ',' -ne ${psSingleQuote(tunDnsIpv4)}) { throw 'DNS read-back mismatch' }; Write-Output "A${i}_dns:set" } catch { Write-Output "A${i}_dns_err: $_" }`
      : `Write-Output "A${i}_dns:skip"`
    const ipv6Line = a.isCellularOrTethering
      ? `Write-Output "A${i}_ipv6:skip"`
      : `try {
  $binding = @(Get-NetAdapterBinding -InterfaceAlias $ownedAdapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop)
  if ($binding.Count -ne 1 -or $binding[0].Enabled -isnot [bool]) { throw 'IPv6 binding not verified' }
  if ($binding[0].Enabled) {
    Disable-NetAdapterBinding -InterfaceAlias $ownedAdapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop
    $binding = @(Get-NetAdapterBinding -InterfaceAlias $ownedAdapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop)
    if ($binding.Count -ne 1 -or $binding[0].Enabled -isnot [bool] -or $binding[0].Enabled) { throw 'IPv6 read-back mismatch' }
    Write-Output "A${i}_ipv6:changed"
  } else { Write-Output "A${i}_ipv6:already-off" }
  Write-Output "A${i}_ipv6:off"
} catch { Write-Output "A${i}_ipv6_err: $_" }`
    combinedScript += `
$ownedAdapter = @(Get-NetAdapter -ErrorAction Stop | Where-Object { [string]$_.InterfaceGuid -eq ${psSingleQuote(a.interfaceGuid || '')} })
if ($ownedAdapter.Count -eq 1) {
  $ownedAdapter = $ownedAdapter[0]
${ipv6Line}
${dnsLine}
} else { Write-Output 'A${i}_ipv6_err: ownership mismatch'; Write-Output 'A${i}_dns_err: ownership mismatch' }
`
  }

  // Also include the transition adapters in the same script
  combinedScript += `
${transitionAdapters.teredoType ? `try { netsh interface teredo set state type=disabled | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'native command failed' }; Write-Output 'TRANS_teredo:disabled' } catch { Write-Output "TRANS_teredo_err: $_" }` : "Write-Output 'TRANS_teredo:absent'"}
${transitionAdapters.sixToFourState ? `try { netsh interface 6to4 set state state=disabled | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'native command failed' }; Write-Output 'TRANS_6to4:disabled' } catch { Write-Output "TRANS_6to4_err: $_" }` : "Write-Output 'TRANS_6to4:absent'"}
${transitionAdapters.isatapState ? `try { netsh interface isatap set state state=disabled | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'native command failed' }; Write-Output 'TRANS_isatap:disabled' } catch { Write-Output "TRANS_isatap_err: $_" }` : "Write-Output 'TRANS_isatap:absent'"}
${registryApplyLine('DNS_SMNR', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient', 'DisableSmartNameResolution')}
${registryApplyLine('DNS_PARALLEL', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters', 'DisableParallelAandAAAA')}
try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
`

  try {
    const out = await runPS(combinedScript, 30000, options.signal)
    
    // Parse results for physical adapters
    for (let i = 0; i < adapters.length; i++) {
      const a = adapters[i]
      try {
        const ipv6Off = new RegExp(`A${i}_ipv6:off`).test(out)
        const ipv6AlreadyOff = new RegExp(`A${i}_ipv6:already-off`).test(out)
        const ipv6Skipped = new RegExp(`A${i}_ipv6:skip`).test(out)
        const dnsSet = new RegExp(`A${i}_dns:set`).test(out)
        const dnsSkipped = new RegExp(`A${i}_dns:skip`).test(out)
        
        a.forcedIpv6Off = ipv6Off
        a.forcedDnsTo = dnsSet ? [tunDnsIpv4] : null
        
        if ((!a.isCellularOrTethering && !ipv6Off) || (forceDns && !dnsSet)) {
          const errs = out.trim().split(/\r?\n/).filter(l => new RegExp(`A${i}_.*err:`).test(l)).join('; ')
          warnings.push(`${a.alias}: ${errs || 'partial'}`)
        }
        logEvent('info', 'phys-lockdown', `locked down ${a.alias}`, { ipv6Off, ipv6AlreadyOff, ipv6Skipped, dnsSet, dnsSkipped, isCellularOrTethering: a.isCellularOrTethering })
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
    for (const tag of ['DNS_SMNR', 'DNS_PARALLEL']) {
      if (!out.trim().split(/\r?\n/).includes(`${tag}:off`) && !warnings.some(line => line.startsWith(`${tag}_err:`))) {
        warnings.push(`${tag}_err: policy not verified`)
      }
    }
    logEvent('info', 'phys-lockdown', 'transition adapters disabled', { snapshot: transitionAdapters, out: out.trim() })
    // A failed read-back can follow a successful mutation. Preserve the
    // conservative journal rather than replacing it with missing markers.
    if (warnings.length > 0) {
      clearPhysicalAdaptersSnapshotCache()
      return { applied: true, adapters: adapters.length, warnings }
    }
  } catch (err: any) {
    if (err?.code === 'physical-lockdown-cancelled-before-dispatch') return cancelled('native-dispatch', true, adapters.length)
    warnings.push(`Batch PS error: ${err?.message ?? String(err)}`)
    logEvent('warn', 'phys-lockdown', 'batch lockdown failed', err)
    // CRITICAL: Do NOT overwrite the pending manifest with unmutated adapters.
    // The PS script may have partially executed (e.g., adapter 0 got
    // Disable-NetAdapterBinding before timeout). If we overwrite the manifest
    // with "nothing changed", rollback will do nothing and the user's IPv6
    // stays disabled + DNS pinned to dead TUN resolver.
    // Instead, keep the pending manifest (which assumes all changes were made)
    // so rollback will attempt to restore everything.
    clearPhysicalAdaptersSnapshotCache()
    return { applied: true, adapters: adapters.length, warnings }
  }

  // Only overwrite the pending manifest if the PS script completed
  // successfully — we can trust the parsed markers to reflect actual state.
  const coverageFailure = await verifyAdapterSet(adapters)
  if (coverageFailure) return coverageFailure
  const manifest: LockdownManifest = {
    appliedAt: Date.now(),
    tunDnsIpv4,
    forceDns,
    adapters,
    transitionAdapters,
    dnsRegistryPolicy
  }
  await writeManifest(manifest)
  clearPhysicalAdaptersSnapshotCache()
  return { applied: true, adapters: adapters.length, warnings }
}

/**
 * Roll back exactly what we changed. We re-enable IPv6 only if we forced it
 * off (so we don't accidentally turn ON IPv6 on an adapter that the user had
 * deliberately disabled). DNS is restored to the exact list we snapshotted —
 * empty list means "back to DHCP", which is what `Set-DnsClientServerAddress
 * -ResetServerAddresses` does.
 */
export async function rollbackPhysicalAdapterLockdownIfApplied(reason: string, options: RollbackOptions = {}): Promise<{ rolledBack: boolean; skipped?: boolean }> {
  if (process.platform !== 'win32') return { rolledBack: false, skipped: true }
  const m = await readManifest()
  // Only a successful trusted read proving absence is a no-op. Trust errors
  // propagate; incomplete rollback still returns rolledBack:false without skip.
  if (!m) return { rolledBack: false, skipped: true }

  let combinedScript = `$ErrorActionPreference = 'Continue'\n`
  
  for (let i = 0; i < m.adapters.length; i++) {
    const a = m.adapters[i]
    const shouldTouchDns = Array.isArray(a.forcedDnsTo) && a.forcedDnsTo.length > 0
    const dnsRestoreLine = !shouldTouchDns
      ? `Write-Output 'A${i}_dns:noop'`
      : (options.resetDnsToDhcp || a.ipv4DnsSource !== 'static')
        ? `try { Set-DnsClientServerAddress -InterfaceAlias $ownedAdapter.Name -ResetServerAddresses -ErrorAction Stop; Write-Output 'A${i}_dns:reset' } catch { Write-Output "A${i}_dns_err: $_" }`
        : `try { Set-DnsClientServerAddress -InterfaceAlias $ownedAdapter.Name -ServerAddresses ${a.ipv4DnsServers.map(psSingleQuote).join(',')} -ErrorAction Stop; if ((@((Get-DnsClientServerAddress -InterfaceAlias $ownedAdapter.Name -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses) -join ',') -ne ${psSingleQuote(a.ipv4DnsServers.join(','))}) { throw 'DNS read-back mismatch' }; Write-Output 'A${i}_dns:restore' } catch { Write-Output "A${i}_dns_err: $_" }`
    const ipv6RestoreLine = a.forcedIpv6Off && a.ipv6Enabled
      ? `try { Enable-NetAdapterBinding -InterfaceAlias $ownedAdapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop; if (-not (Get-NetAdapterBinding -InterfaceAlias $ownedAdapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop).Enabled) { throw 'IPv6 read-back mismatch' }; Write-Output 'A${i}_ipv6:on' } catch { Write-Output "A${i}_ipv6_err: $_" }`
      : `Write-Output 'A${i}_ipv6:noop'`
    combinedScript += `
$ownedAdapter = @(Get-NetAdapter -ErrorAction Stop | Where-Object { [string]$_.InterfaceGuid -eq ${psSingleQuote(a.interfaceGuid || '')} })
if ($ownedAdapter.Count -eq 1) {
  $ownedAdapter = $ownedAdapter[0]
${ipv6RestoreLine}
${dnsRestoreLine}
} else { Write-Output 'A${i}_ipv6_err: ownership mismatch'; Write-Output 'A${i}_dns_err: ownership mismatch' }
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
  clearPhysicalAdaptersSnapshotCache()
  return { rolledBack: rollbackSuccess }
}

export async function repairOrphanedPhysicalAdapterDns(reason: string): Promise<{ repaired: boolean; adapters: string[] }> {
  if (process.platform !== 'win32') return { repaired: false, adapters: [] }
  // A private resolver address is not proof that VPNTE changed an adapter.
  // Automatic restoration needs the exact trusted ownership/baseline snapshot.
  const manifest = await readManifest()
  if (manifest) {
    const result = await rollbackPhysicalAdapterLockdownIfApplied(reason)
    return { repaired: result.rolledBack, adapters: result.rolledBack ? manifest.adapters.map(a => a.alias) : [] }
  }
  logEvent('warn', 'phys-lockdown', 'DNS recovery not verified: no owned adapter baseline; foreign settings preserved', { reason })
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
