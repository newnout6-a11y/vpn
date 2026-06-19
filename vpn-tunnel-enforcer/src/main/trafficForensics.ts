import { app } from 'electron'
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process'
import { existsSync } from 'fs'
import { appendFile, cp, mkdir, readdir, readFile, rm, writeFile } from 'fs/promises'
import { release as osRelease, type as osType, version as osVersion } from 'os'
import { dirname, join } from 'path'
import { execElevated } from './admin'
import { logEvent } from './appLogger'
import { settingsStore } from './settings'
import {
  MANIFEST_SCHEMA_VERSION,
  generateTrafficForensicsSummary,
  listTrafficForensicsArtifacts,
  type TrafficForensicsArtifactFile,
  type TrafficForensicsSummaryManifest
} from './trafficForensicsSummary'

export type TrafficForensicsEngine = 'pktmon' | 'netsh'

export interface TrafficForensicsStatus {
  enabled: boolean
  running: boolean
  engine: TrafficForensicsEngine | null
  sessionId: string | null
  sessionDir: string | null
  mode: 'localProxy' | 'directVpn' | null
  target: string | null
  startedAt: number | null
  stoppedAt: number | null
  maxSizeMb: number
  retainSessions: number
  stopReason: string | null
  lastError: string | null
  schemaVersion: number | null
  summaryPath: string | null
  summaryGeneratedAt: number | null
  summary: {
    verdicts?: Record<string, boolean>
    counts?: Record<string, number>
    parserErrors?: string[]
  } | null
  sidecar: SessionManifest['sidecar'] | null
  artifactFiles: TrafficForensicsArtifactFile[]
  health: {
    artifactCount: number
    etlBytes: number
    liveEtlBytes: number
    eventsBytes: number
    liveSnapshotAt: number | null
    sidecarEvents: number
    sidecarDataEvents: number
    sidecarOnlyLifecycle: boolean
    sidecarWarmingUp: boolean
    pktmonStatusBytes: number
    pktmonLiveCountersBytes: number
    sidecarEngine: string | null
    sidecarCategoryCounts: Record<string, number>
    sidecarWfpBlocks: number
    sidecarTopDomains: Array<{ name: string; count: number }>
    sidecarTopRemotes: Array<{ address: string; count: number }>
    sidecarLastEventAt: number | null
    warnings: string[]
  }
}

type SessionManifest = TrafficForensicsSummaryManifest

const NETSH_SESSION_NAME = 'VPNTrafficForensics'
const DEFAULT_MAX_SIZE_MB = 512
const DEFAULT_RETAIN_SESSIONS = 3
const PKTMON_TCPIP_KEYWORDS = '0x7FFFFFFFFFFFFFFF'
const PKTMON_WFP_KEYWORDS = '0x7FFFFFFFFFFFFFFF'
const PKTMON_AFD_KEYWORDS = '0x3FFFFFFFFFFF'
const PKTMON_WEBIO_KEYWORDS = '0xFFFFFFFFFFFFFFFF'
const PKTMON_TCPIP_LEVEL = 17
const PKTMON_WFP_LEVEL = 255
const PKTMON_AFD_LEVEL = 255
const PKTMON_WEBIO_LEVEL = 255
let runtimeState: SessionManifest | null = null
let sidecarProcess: ChildProcessWithoutNullStreams | null = null

// When this main process started. A persisted session whose `startedAt` predates
// this is a leftover from a previous app run (or survives an app reinstall, since
// userData is not removed on uninstall). We must not surface such a session's old
// events.ndjson as live diagnostics — see getTrafficForensicsStatus.
const PROCESS_START_MS = Date.now()

export interface TrafficForensicsAppEventInput {
  source: string
  event: string
  details?: Record<string, unknown>
  timestamp?: number
}

function quoted(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

function cmdQuoted(value: string): string {
  return `"${value.replace(/"/g, '\\"')}"`
}

function encodedPowerShell(script: string): string {
  const prelude =
    '$ProgressPreference="SilentlyContinue";' +
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '[Console]::InputEncoding=[System.Text.UTF8Encoding]::new();'
  return Buffer.from(prelude + script, 'utf16le').toString('base64')
}

function powershellCommand(script: string): string {
  return `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encodedPowerShell(script)}`
}

function bestEffortPowerShellScript(errorPath: string, commands: Array<{ label: string; command: string }>): string {
  const invoke = [
    '$ErrorActionPreference = "Continue"',
    `function Invoke-VpnteBestEffort { param([scriptblock]$Action, [string]$Label)`,
    '$global:LASTEXITCODE = 0',
    'try { & $Action } catch { Add-Content -LiteralPath ' + quoted(errorPath) + ' -Value ("[" + $Label + "] " + $_.Exception.Message) -Encoding UTF8 }',
    'if ($LASTEXITCODE -ne 0) { Add-Content -LiteralPath ' + quoted(errorPath) + ' -Value ("[" + $Label + "] exit=" + $LASTEXITCODE) -Encoding UTF8; $global:LASTEXITCODE = 0 }',
    '}'
  ].join('; ')

  return [
    invoke,
    ...commands.map(({ label, command }) => `Invoke-VpnteBestEffort { ${command} } ${quoted(label)}`),
    '$global:LASTEXITCODE = 0',
    'exit 0'
  ].join('; ')
}

export function telemetrySnapshotCommands(sessionDir: string): string[] {
  const tcpPath = join(sessionDir, 'nettcp-live.txt')
  const udpPath = join(sessionDir, 'netudp-live.txt')
  const ipConfigPath = join(sessionDir, 'ipconfig-live.txt')
  const routesPath = join(sessionDir, 'routes-live.txt')
  const routePrintPath = join(sessionDir, 'route-print-live.txt')
  const arpPath = join(sessionDir, 'arp-live.txt')
  const dnsCachePath = join(sessionDir, 'dns-cache-live.txt')
  const netstatPath = join(sessionDir, 'netstat-live.txt')
  const adaptersPath = join(sessionDir, 'adapters-live.txt')
  const adapterStatsPath = join(sessionDir, 'adapter-stats-live.txt')
  const interfacePath = join(sessionDir, 'interfaces-live.txt')
  const dnsClientServerPath = join(sessionDir, 'dns-client-servers-live.txt')
  const dnsClientPath = join(sessionDir, 'dns-client-live.txt')
  const firewallPath = join(sessionDir, 'firewall-rules-live.txt')
  const firewallProfilePath = join(sessionDir, 'firewall-profiles-live.txt')
  const dnsEventsPath = join(sessionDir, 'dnsclient-events-live.txt')
  const tcpEventsPath = join(sessionDir, 'tcpip-events-live.txt')
  const chromeNetPath = join(sessionDir, 'chromium-policy-live.txt')

  return [
    `Get-NetTCPConnection | Sort-Object State, RemotePort, RemoteAddress | ConvertTo-Json -Depth 4 | Out-File -FilePath ${quoted(tcpPath)} -Encoding utf8`,
    `Get-NetUDPEndpoint | Sort-Object LocalPort, LocalAddress | ConvertTo-Json -Depth 4 | Out-File -FilePath ${quoted(udpPath)} -Encoding utf8`,
    `ipconfig /all | Out-File -FilePath ${quoted(ipConfigPath)} -Encoding utf8`,
    `Get-NetRoute -AddressFamily IPv4,IPv6 | Sort-Object ifIndex, DestinationPrefix, RouteMetric | ConvertTo-Json -Depth 5 | Out-File -FilePath ${quoted(routesPath)} -Encoding utf8`,
    `route print | Out-File -FilePath ${quoted(routePrintPath)} -Encoding utf8`,
    `arp -a | Out-File -FilePath ${quoted(arpPath)} -Encoding utf8`,
    `Get-DnsClientCache | Sort-Object Entry, Type, Status | ConvertTo-Json -Depth 5 | Out-File -FilePath ${quoted(dnsCachePath)} -Encoding utf8`,
    `netstat -abno | Out-File -FilePath ${quoted(netstatPath)} -Encoding utf8`,
    `Get-NetAdapter -IncludeHidden | Sort-Object ifIndex | ConvertTo-Json -Depth 5 | Out-File -FilePath ${quoted(adaptersPath)} -Encoding utf8`,
    `Get-NetAdapterStatistics -IncludeHidden | Sort-Object Name | ConvertTo-Json -Depth 5 | Out-File -FilePath ${quoted(adapterStatsPath)} -Encoding utf8`,
    `Get-NetIPInterface -AddressFamily IPv4,IPv6 | Sort-Object InterfaceIndex, AddressFamily | ConvertTo-Json -Depth 5 | Out-File -FilePath ${quoted(interfacePath)} -Encoding utf8`,
    `Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Sort-Object InterfaceIndex, AddressFamily | ConvertTo-Json -Depth 5 | Out-File -FilePath ${quoted(dnsClientServerPath)} -Encoding utf8`,
    `Get-DnsClient | Sort-Object InterfaceIndex | ConvertTo-Json -Depth 5 | Out-File -FilePath ${quoted(dnsClientPath)} -Encoding utf8`,
    `Get-NetFirewallProfile | ConvertTo-Json -Depth 4 | Out-File -FilePath ${quoted(firewallProfilePath)} -Encoding utf8`,
    `Get-NetFirewallRule | Sort-Object DisplayName | Select-Object DisplayName, Direction, Action, Enabled, Profile, Program, Service, PolicyStoreSourceType | ConvertTo-Json -Depth 4 | Out-File -FilePath ${quoted(firewallPath)} -Encoding utf8`,
    `Get-WinEvent -LogName 'Microsoft-Windows-DNS-Client/Operational' -MaxEvents 400 | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Depth 4 | Out-File -FilePath ${quoted(dnsEventsPath)} -Encoding utf8`,
    `Get-WinEvent -LogName 'Microsoft-Windows-TCPIP/Operational' -MaxEvents 400 | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Depth 4 | Out-File -FilePath ${quoted(tcpEventsPath)} -Encoding utf8`,
    `Get-ItemProperty -Path 'HKCU:\\Software\\Policies\\Google\\Chrome' -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4 | Out-File -FilePath ${quoted(chromeNetPath)} -Encoding utf8`
  ]
}

function getSettings() {
  const settings = settingsStore.get()
  return {
    enabled: settings.deepTrafficInspectionEnabled !== false,
    maxSizeMb: Math.min(2048, Math.max(128, Math.floor(Number(settings.deepTrafficInspectionMaxSizeMb) || DEFAULT_MAX_SIZE_MB))),
    retainSessions: Math.min(10, Math.max(1, Math.floor(Number(settings.deepTrafficInspectionRetainSessions) || DEFAULT_RETAIN_SESSIONS)))
  }
}

function getRootDir(): string {
  return join(app.getPath('userData'), 'traffic-forensics')
}

function getSessionsDir(): string {
  return join(getRootDir(), 'sessions')
}

function getLatestManifestPath(): string {
  return join(getRootDir(), 'latest-session.json')
}

function appVersion(): string | null {
  try {
    return typeof app.getVersion === 'function' ? app.getVersion() : null
  } catch {
    return null
  }
}

function osSnapshot(): SessionManifest['os'] {
  return {
    platform: process.platform,
    type: osType(),
    release: osRelease(),
    version: osVersion?.() ?? null
  }
}

function defaultSidecarState(eventsPath: string | null = null): SessionManifest['sidecar'] {
  return {
    available: false,
    running: false,
    executablePath: null,
    eventsPath,
    startedAt: null,
    stoppedAt: null,
    pid: null,
    lastError: null
  }
}

export function createManifest(
  input: Omit<SessionManifest,
    | 'schemaVersion'
    | 'appVersion'
    | 'os'
    | 'normalizedArtifacts'
    | 'summaryPath'
    | 'summaryGeneratedAt'
    | 'parserErrors'
    | 'sidecar'
  >
): SessionManifest {
  return {
    ...input,
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    appVersion: appVersion(),
    os: osSnapshot(),
    normalizedArtifacts: [],
    summaryPath: null,
    summaryGeneratedAt: null,
    parserErrors: [],
    sidecar: defaultSidecarState(input.sessionDir ? join(input.sessionDir, 'events.ndjson') : null)
  }
}

function normalizeManifest(manifest: SessionManifest): SessionManifest {
  return {
    ...manifest,
    schemaVersion: manifest.schemaVersion ?? MANIFEST_SCHEMA_VERSION,
    appVersion: manifest.appVersion ?? appVersion(),
    os: manifest.os ?? osSnapshot(),
    normalizedArtifacts: manifest.normalizedArtifacts ?? [],
    summaryPath: manifest.summaryPath ?? null,
    summaryGeneratedAt: manifest.summaryGeneratedAt ?? null,
    parserErrors: manifest.parserErrors ?? [],
    sidecar: manifest.sidecar ?? defaultSidecarState(manifest.sessionDir ? join(manifest.sessionDir, 'events.ndjson') : null)
  }
}

async function ensureLayout(): Promise<void> {
  await mkdir(getSessionsDir(), { recursive: true })
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, JSON.stringify(value, null, 2), 'utf-8')
}

async function readJson<T>(path: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(path, 'utf-8')) as T
  } catch {
    return null
  }
}

async function readSummaryForStatus(path: string | null | undefined): Promise<TrafficForensicsStatus['summary']> {
  if (!path) return null
  const summary = await readJson<any>(path)
  if (!summary) return null
  return {
    verdicts: summary.verdicts && typeof summary.verdicts === 'object' ? summary.verdicts : undefined,
    counts: summary.counts && typeof summary.counts === 'object' ? summary.counts : undefined,
    parserErrors: Array.isArray(summary.parserErrors) ? summary.parserErrors : undefined
  }
}

async function writeManifest(manifest: SessionManifest): Promise<void> {
  const normalized = normalizeManifest(manifest)
  runtimeState = normalized
  await ensureLayout()
  if (normalized.sessionDir) {
    await writeJson(join(normalized.sessionDir, 'session-manifest.json'), normalized)
  }
  await writeJson(getLatestManifestPath(), normalized)
}

export async function recordTrafficForensicsAppEvent(input: TrafficForensicsAppEventInput): Promise<boolean> {
  const manifest = await readLatestManifest()
  if (!manifest?.running || !manifest.sessionDir) return false
  const row = {
    timestamp: input.timestamp ?? Date.now(),
    source: input.source,
    event: input.event,
    details: input.details ?? {}
  }
  try {
    await appendFile(join(manifest.sessionDir, 'app-events-source.ndjson'), JSON.stringify(row) + '\n', 'utf-8')
    return true
  } catch (err: any) {
    logEvent('warn', 'traffic-forensics', 'failed to record app forensic event', {
      sessionId: manifest.sessionId,
      event: input.event,
      error: err?.message || String(err)
    })
    return false
  }
}

async function readLatestManifest(): Promise<SessionManifest | null> {
  if (runtimeState) return runtimeState
  const manifest = await readJson<SessionManifest>(getLatestManifestPath())
  return manifest ? normalizeManifest(manifest) : null
}

function artifactSize(files: TrafficForensicsArtifactFile[], name: string): number {
  return files.find(file => file.name === name)?.size ?? 0
}

function artifactMtime(files: TrafficForensicsArtifactFile[], name: string): number | null {
  return files.find(file => file.name === name)?.mtimeMs ?? null
}

interface SidecarEventProbe {
  events: number
  dataEvents: number
  engine: string | null
  categoryCounts: Record<string, number>
  wfpBlocks: number
  topDomains: Array<{ name: string; count: number }>
  topRemotes: Array<{ address: string; count: number }>
  lastDataEventAt: number | null
}

function emptySidecarEventProbe(): SidecarEventProbe {
  return {
    events: 0,
    dataEvents: 0,
    engine: null,
    categoryCounts: {},
    wfpBlocks: 0,
    topDomains: [],
    topRemotes: [],
    lastDataEventAt: null
  }
}

async function readSidecarEventProbe(sessionDir: string | null | undefined): Promise<SidecarEventProbe> {
  if (!sessionDir) return emptySidecarEventProbe()
  try {
    const text = await readFile(join(sessionDir, 'events.ndjson'), 'utf-8')
    let events = 0
    let dataEvents = 0
    let wfpBlocks = 0
    let engine: string | null = null
    let lastDataEventAt: number | null = null
    const categoryCounts: Record<string, number> = {}
    const domainCounts = new Map<string, number>()
    const remoteCounts = new Map<string, number>()
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim()
      if (!trimmed) continue
      events++
      let row: any
      try {
        row = JSON.parse(trimmed)
      } catch {
        dataEvents++
        continue
      }
      const category = typeof row?.category === 'string' ? row.category : undefined
      if (category === 'lifecycle') {
        if (typeof row?.engine === 'string' && row.engine) engine = row.engine
        continue
      }
      if (category === 'health') continue
      dataEvents++
      const key = category || 'other'
      categoryCounts[key] = (categoryCounts[key] ?? 0) + 1
      if (category === 'wfp' && (row?.event === 'block' || row?.action === 'block' || row?.action === 'drop')) {
        wfpBlocks++
      }
      if (typeof row?.queryName === 'string' && row.queryName) {
        domainCounts.set(row.queryName, (domainCounts.get(row.queryName) ?? 0) + 1)
      }
      if (typeof row?.remoteAddress === 'string' && row.remoteAddress) {
        const addr = row?.remotePort ? `${row.remoteAddress}:${row.remotePort}` : row.remoteAddress
        remoteCounts.set(addr, (remoteCounts.get(addr) ?? 0) + 1)
      }
      if (typeof row?.ts === 'string') {
        const parsed = Date.parse(row.ts)
        if (Number.isFinite(parsed)) lastDataEventAt = parsed
      }
    }
    const topDomains = Array.from(domainCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => ({ name, count }))
    const topRemotes = Array.from(remoteCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([address, count]) => ({ address, count }))
    return { events, dataEvents, engine, categoryCounts, wfpBlocks, topDomains, topRemotes, lastDataEventAt }
  } catch {
    return emptySidecarEventProbe()
  }
}

function hasStopArtifacts(files: TrafficForensicsArtifactFile[]): boolean {
  const names = new Set(files.map(file => file.name))
  return (
    names.has('pktmon-stop.ps1') ||
    names.has('pktmon-stop.txt') ||
    names.has('netsh-stop.ps1') ||
    names.has('netsh-stop.txt') ||
    names.has('pktmon-trace.txt') ||
    names.has('pktmon-trace.pcapng')
  )
}

async function reconcileStoppedCaptureManifest(
  manifest: SessionManifest | null,
  files: TrafficForensicsArtifactFile[]
): Promise<SessionManifest | null> {
  if (!manifest?.running || !manifest.sessionDir) return manifest
  if (!hasStopArtifacts(files)) return manifest
  const stoppedAt = Math.max(...files.map(file => file.mtimeMs).filter(Number.isFinite), Date.now())
  const sidecar = manifest.sidecar ?? defaultSidecarState(join(manifest.sessionDir, 'events.ndjson'))
  const next = normalizeManifest({
    ...manifest,
    running: false,
    stoppedAt: manifest.stoppedAt ?? stoppedAt,
    stopReason: manifest.stopReason ?? 'status-reconciled-stop',
    sidecar: {
      ...sidecar,
      running: false,
      stoppedAt: sidecar.stoppedAt ?? stoppedAt,
      pid: null
    }
  })
  await writeManifest(next)
  logEvent('warn', 'traffic-forensics', 'reconciled running manifest with stop artifacts during status read', {
    sessionId: next.sessionId,
    engine: next.engine
  })
  return next
}

function emptyHealth(): TrafficForensicsStatus['health'] {
  return {
    artifactCount: 0,
    etlBytes: 0,
    liveEtlBytes: 0,
    eventsBytes: 0,
    liveSnapshotAt: null,
    sidecarEvents: 0,
    sidecarDataEvents: 0,
    sidecarOnlyLifecycle: false,
    sidecarWarmingUp: false,
    pktmonStatusBytes: 0,
    pktmonLiveCountersBytes: 0,
    sidecarEngine: null,
    sidecarCategoryCounts: {},
    sidecarWfpBlocks: 0,
    sidecarTopDomains: [],
    sidecarTopRemotes: [],
    sidecarLastEventAt: null,
    warnings: []
  }
}

function buildTrafficForensicsHealth(
  files: TrafficForensicsArtifactFile[],
  summary: TrafficForensicsStatus['summary'],
  sidecar: SessionManifest['sidecar'] | null,
  sidecarProbe: SidecarEventProbe,
  startedAt: number | null | undefined
): TrafficForensicsStatus['health'] {
  const sidecarEvents = Math.max(Number(summary?.counts?.sidecarEvents ?? 0), sidecarProbe.events)
  const sidecarDataEvents = sidecarProbe.dataEvents
  const etlBytes = artifactSize(files, 'pktmon.etl')
  const liveEtlBytes = artifactSize(files, 'pktmon-live.etl')
  const eventsBytes = artifactSize(files, 'events.ndjson')
  const liveSnapshotAt = artifactMtime(files, 'pktmon-live-status.txt')
  const warnings: string[] = []
  const ageMs = startedAt ? Date.now() - startedAt : Number.POSITIVE_INFINITY
  const sidecarWarmingUp = Boolean(sidecar?.running && sidecarDataEvents === 0 && ageMs < 30000)
  const sidecarOnlyLifecycle = Boolean(sidecar?.running && sidecarDataEvents === 0 && !sidecarWarmingUp)
  if (sidecarOnlyLifecycle) {
    warnings.push('sidecar is running but has no TCP/DNS/WFP data events')
  }
  if (etlBytes === 0 && liveEtlBytes === 0) {
    warnings.push('pktmon ETL artifact is empty or missing')
  }
  return {
    artifactCount: files.length,
    etlBytes,
    liveEtlBytes,
    eventsBytes,
    liveSnapshotAt,
    sidecarEvents,
    sidecarOnlyLifecycle,
    sidecarWarmingUp,
    pktmonStatusBytes: artifactSize(files, 'pktmon-live-status.txt'),
    pktmonLiveCountersBytes: artifactSize(files, 'pktmon-live-counters.json'),
    sidecarDataEvents,
    sidecarEngine: sidecarProbe.engine,
    sidecarCategoryCounts: sidecarProbe.categoryCounts,
    sidecarWfpBlocks: sidecarProbe.wfpBlocks,
    sidecarTopDomains: sidecarProbe.topDomains,
    sidecarTopRemotes: sidecarProbe.topRemotes,
    sidecarLastEventAt: sidecarProbe.lastDataEventAt,
    warnings
  }
}

export function sidecarExecutableCandidates(): string[] {
  const names = [
    'vpnte-etw-sidecar.exe',
    'traffic-forensics-sidecar.exe',
    'vpnte-etw-sidecar.cmd',
    'vpnte-etw-sidecar.ps1'
  ]
  const roots = app.isPackaged
    ? [process.resourcesPath, dirname(process.execPath)]
    : [
        join(process.cwd(), 'resources'),
        join(process.cwd(), 'build'),
        join(dirname(process.execPath), 'resources')
      ]
  return roots.flatMap(root => names.map(name => join(root, name)))
}

function findSidecarExecutable(): string | null {
  const override = process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR
  if (override === '0') return null
  if (override && override !== '1') return existsSync(override) ? override : null
  return sidecarExecutableCandidates().find(candidate => existsSync(candidate)) ?? null
}

const SIDECAR_PROVIDERS = 'Microsoft-Windows-TCPIP,Microsoft-Windows-DNS-Client,Microsoft-Windows-WFP,Microsoft-Windows-Winsock-AFD,Microsoft-Windows-WebIO'

export function sidecarArgs(eventsPath: string, sessionId: string, powerShellStyle: boolean): string[] {
  return powerShellStyle
    ? ['-Events', eventsPath, '-Session', sessionId, '-Providers', SIDECAR_PROVIDERS]
    : ['--events', eventsPath, '--session', sessionId, '--providers', SIDECAR_PROVIDERS]
}

function persistSidecarState(state: SessionManifest): void {
  writeManifest(preserveObservedSidecarStop(state)).catch(err => {
    logEvent('warn', 'traffic-forensics', 'failed to persist sidecar state', { err: (err as Error)?.message })
  })
}

function preserveObservedSidecarStop(manifest: SessionManifest): SessionManifest {
  const observed = runtimeState
  if (!observed?.sidecar || !manifest.sidecar || observed.sessionId !== manifest.sessionId) return manifest
  const sameSidecarStart =
    observed.sidecar.startedAt !== null &&
    observed.sidecar.startedAt === manifest.sidecar.startedAt
  if (sameSidecarStart && manifest.sidecar.running && !observed.sidecar.running) {
    return normalizeManifest({
      ...manifest,
      sidecar: observed.sidecar
    })
  }
  return manifest
}

function hasManagedSidecarProcess(): boolean {
  return Boolean(sidecarProcess && sidecarProcess.exitCode === null && !sidecarProcess.killed)
}

async function reconcileStaleRunningManifest(manifest: SessionManifest | null): Promise<SessionManifest | null> {
  if (!manifest?.running || !manifest.sidecar?.running || hasManagedSidecarProcess()) return manifest
  const stoppedAt = Date.now()
  const sidecar = manifest.sidecar ?? defaultSidecarState(manifest.sessionDir ? join(manifest.sessionDir, 'events.ndjson') : null)
  const next = normalizeManifest({
    ...manifest,
    running: false,
    stoppedAt: manifest.stoppedAt ?? stoppedAt,
    stopReason: manifest.stopReason ?? 'zombie-recovery',
    sidecar: {
      ...sidecar,
      running: false,
      stoppedAt: sidecar.stoppedAt ?? stoppedAt,
      pid: null,
      lastError: sidecar.lastError ?? 'orphaned traffic forensics sidecar after app restart or installer update'
    }
  })
  await writeManifest(next)
  logEvent('warn', 'traffic-forensics', 'recovered stale running manifest during status read', {
    sessionId: next.sessionId,
    engine: next.engine
  })
  return next
}

async function startSidecar(manifest: SessionManifest): Promise<SessionManifest['sidecar']> {
  if (!manifest.sessionDir) return defaultSidecarState(null)
  const eventsPath = join(manifest.sessionDir, 'events.ndjson')
  const executablePath = findSidecarExecutable()
  if (!executablePath) {
    return {
      ...defaultSidecarState(eventsPath),
      lastError: 'ETW sidecar executable not found'
    }
  }

  try {
    const args = sidecarArgs(eventsPath, manifest.sessionId, false)
    const powerShellArgs = sidecarArgs(eventsPath, manifest.sessionId, true)
    let command = executablePath
    let commandArgs = args
    if (/\.ps1$/i.test(executablePath)) {
      command = 'powershell.exe'
      commandArgs = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', executablePath, ...powerShellArgs]
    } else if (/\.(cmd|bat)$/i.test(executablePath)) {
      command = 'cmd.exe'
      commandArgs = ['/d', '/s', '/c', 'call', executablePath, ...powerShellArgs]
    }
    const launchedProcess = spawn(command, commandArgs, {
      cwd: manifest.sessionDir,
      windowsHide: true
    })
    sidecarProcess = launchedProcess
    const startedSidecar: SessionManifest['sidecar'] = {
      available: true,
      running: true,
      executablePath,
      eventsPath,
      startedAt: Date.now(),
      stoppedAt: null,
      pid: launchedProcess.pid ?? null,
      lastError: null
    }
    runtimeState = normalizeManifest({
      ...(runtimeState?.sessionId === manifest.sessionId ? runtimeState : manifest),
      sidecar: startedSidecar
    })
    const stdoutPath = join(manifest.sessionDir, 'sidecar-stdout.log')
    const stderrPath = join(manifest.sessionDir, 'sidecar-stderr.log')
    launchedProcess.stdout.on('data', chunk => {
      appendFile(stdoutPath, chunk).catch(() => {})
    })
    launchedProcess.stderr.on('data', chunk => {
      appendFile(stderrPath, chunk).catch(() => {})
    })
    launchedProcess.once('error', err => {
      if (sidecarProcess === launchedProcess) sidecarProcess = null
      const current = runtimeState?.sessionId === manifest.sessionId
        ? runtimeState
        : normalizeManifest({ ...manifest, sidecar: startedSidecar })
      const next = normalizeManifest({
        ...current,
        sidecar: {
          ...current.sidecar,
          running: false,
          stoppedAt: Date.now(),
          pid: null,
          lastError: err?.message || String(err)
        }
      })
      runtimeState = next
      persistSidecarState(next)
    })
    launchedProcess.once('exit', (code, signal) => {
      if (sidecarProcess === launchedProcess) sidecarProcess = null
      const current = runtimeState?.sessionId === manifest.sessionId
        ? runtimeState
        : normalizeManifest({ ...manifest, sidecar: startedSidecar })
      const next = normalizeManifest({
        ...current,
        sidecar: {
          ...current.sidecar,
          running: false,
          stoppedAt: Date.now(),
          pid: null,
          lastError: code === 0 ? current.sidecar.lastError : `sidecar exited code=${code ?? 'null'} signal=${signal ?? 'null'}`
        }
      })
      runtimeState = next
      persistSidecarState(next)
    })
    return startedSidecar
  } catch (err: any) {
    sidecarProcess = null
    return {
      available: true,
      running: false,
      executablePath,
      eventsPath,
      startedAt: null,
      stoppedAt: Date.now(),
      pid: null,
      lastError: err?.message || String(err)
    }
  }
}

function stopSidecar(manifest: SessionManifest, reason: string): SessionManifest['sidecar'] {
  const current = manifest.sidecar ?? defaultSidecarState(manifest.sessionDir ? join(manifest.sessionDir, 'events.ndjson') : null)
  if (!sidecarProcess) {
    return {
      ...current,
      running: false,
      stoppedAt: current.stoppedAt ?? Date.now(),
      pid: null
    }
  }
  try {
    sidecarProcess.kill()
    return {
      ...current,
      running: false,
      stoppedAt: Date.now(),
      pid: null,
      lastError: current.lastError
    }
  } catch (err: any) {
    return {
      ...current,
      running: false,
      stoppedAt: Date.now(),
      pid: null,
      lastError: `failed to stop sidecar (${reason}): ${err?.message || String(err)}`
    }
  } finally {
    sidecarProcess = null
  }
}

async function pruneOldSessions(keep: number, currentSessionId?: string | null): Promise<void> {
  await ensureLayout()
  const entries = await readdir(getSessionsDir(), { withFileTypes: true })
  const dirs = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort((a, b) => b.localeCompare(a))

  const removable = dirs.filter((name) => name !== currentSessionId).slice(Math.max(0, keep - (currentSessionId ? 1 : 0)))
  await Promise.all(removable.map((name) => rm(join(getSessionsDir(), name), { recursive: true, force: true })))
}

export function buildPktmonStartScript(etlPath: string, sizeMb: number): string {
  return [
    '$ErrorActionPreference = "Stop"',
    'try { pktmon stop | Out-Null } catch {}',
    'try { pktmon filter remove | Out-Null } catch {}',
    'try { pktmon reset | Out-Null } catch {}',
    [
      'pktmon start --capture --trace',
      '--comp nics',
      '--pkt-size 0',
      '--flags 0x01A',
      `--provider Microsoft-Windows-TCPIP --keywords ${PKTMON_TCPIP_KEYWORDS} --level ${PKTMON_TCPIP_LEVEL}`,
      `--provider Microsoft-Windows-WFP --keywords ${PKTMON_WFP_KEYWORDS} --level ${PKTMON_WFP_LEVEL}`,
      `--provider Microsoft-Windows-Winsock-AFD --keywords ${PKTMON_AFD_KEYWORDS} --level ${PKTMON_AFD_LEVEL}`,
      `--provider Microsoft-Windows-WebIO --keywords ${PKTMON_WEBIO_KEYWORDS} --level ${PKTMON_WEBIO_LEVEL}`,
      `--file-name ${quoted(etlPath)}`,
      `--file-size ${sizeMb}`,
      '--log-mode circular'
    ].join(' ')
  ].join('; ')
}

export function buildPktmonStopScript(sessionDir: string, etlPath: string): string {
  const statusPath = join(sessionDir, 'pktmon-status.txt')
  const countersPath = join(sessionDir, 'pktmon-counters.json')
  const dropsPath = join(sessionDir, 'pktmon-drop-counters.json')
  const stopPath = join(sessionDir, 'pktmon-stop.txt')
  const txtPath = join(sessionDir, 'pktmon-trace.txt')
  const pcapPath = join(sessionDir, 'pktmon-trace.pcapng')
  const wfpEventsPath = join(sessionDir, 'wfp-netevents.xml')
  const wfpStatePath = join(sessionDir, 'wfp-state.xml')
  const errorsPath = join(sessionDir, 'traffic-forensics-stop-errors.txt')

  return bestEffortPowerShellScript(errorsPath, [
    { label: 'pktmon-status', command: `pktmon status | Out-File -FilePath ${quoted(statusPath)} -Encoding utf8` },
    { label: 'pktmon-counters', command: `pktmon counters --json | Out-File -FilePath ${quoted(countersPath)} -Encoding utf8` },
    { label: 'pktmon-drop-counters', command: `pktmon counters --json --drop-reason | Out-File -FilePath ${quoted(dropsPath)} -Encoding utf8` },
    { label: 'pktmon-stop', command: `$pktmonStop = pktmon stop 2>&1 | Out-String; Set-Content -Path ${quoted(stopPath)} -Value $pktmonStop -Encoding UTF8` },
    { label: 'pktmon-etl2txt', command: `if (Test-Path ${quoted(etlPath)}) { pktmon etl2txt ${quoted(etlPath)} --out ${quoted(txtPath)} --timestamp --metadata | Out-Null }` },
    { label: 'pktmon-etl2pcap', command: `if (Test-Path ${quoted(etlPath)}) { pktmon etl2pcap ${quoted(etlPath)} --out ${quoted(pcapPath)} | Out-Null }` },
    { label: 'wfp-netevents', command: `netsh wfp show netevents file=${quoted(wfpEventsPath)} timewindow=900 | Out-Null` },
    { label: 'wfp-state', command: `netsh wfp show state file=${quoted(wfpStatePath)} | Out-Null` },
    ...telemetrySnapshotCommands(sessionDir).map((command, index) => ({ label: `telemetry-${index + 1}`, command }))
  ])
}

export function buildPktmonLiveSnapshotScript(sessionDir: string, etlPath: string): string {
  const statusPath = join(sessionDir, 'pktmon-live-status.txt')
  const countersPath = join(sessionDir, 'pktmon-live-counters.json')
  const dropsPath = join(sessionDir, 'pktmon-live-drop-counters.json')
  const snapshotEtlPath = join(sessionDir, 'pktmon-live.etl')
  const wfpEventsPath = join(sessionDir, 'wfp-live-netevents.xml')
  const wfpStatePath = join(sessionDir, 'wfp-live-state.xml')
  const errorsPath = join(sessionDir, 'traffic-forensics-live-errors.txt')

  return bestEffortPowerShellScript(errorsPath, [
    { label: 'pktmon-live-status', command: `pktmon status | Out-File -FilePath ${quoted(statusPath)} -Encoding utf8` },
    { label: 'pktmon-live-counters', command: `pktmon counters --json | Out-File -FilePath ${quoted(countersPath)} -Encoding utf8` },
    { label: 'pktmon-live-drop-counters', command: `pktmon counters --json --drop-reason | Out-File -FilePath ${quoted(dropsPath)} -Encoding utf8` },
    { label: 'pktmon-live-etl-copy', command: `if (Test-Path ${quoted(etlPath)}) { Copy-Item -LiteralPath ${quoted(etlPath)} -Destination ${quoted(snapshotEtlPath)} -Force }` },
    { label: 'wfp-live-netevents', command: `netsh wfp show netevents file=${quoted(wfpEventsPath)} timewindow=900 | Out-Null` },
    { label: 'wfp-live-state', command: `netsh wfp show state file=${quoted(wfpStatePath)} | Out-Null` },
    ...telemetrySnapshotCommands(sessionDir).map((command, index) => ({ label: `telemetry-live-${index + 1}`, command }))
  ])
}

function buildNetshStartCommand(etlPath: string, sizeMb: number): string {
  return [
    'netsh trace start',
    `sessionname=${NETSH_SESSION_NAME}`,
    'scenario=InternetClient',
    'capture=yes',
    'capturetype=physical',
    'report=disabled',
    'persistent=no',
    `maxSize=${sizeMb}`,
    'fileMode=circular',
    'overwrite=yes',
    `traceFile=${cmdQuoted(etlPath)}`
  ].join(' ')
}

function buildNetshStopScript(sessionDir: string): string {
  const stopPath = join(sessionDir, 'netsh-trace-stop.txt')
  const wfpEventsPath = join(sessionDir, 'wfp-netevents.xml')
  const wfpStatePath = join(sessionDir, 'wfp-state.xml')
  const errorsPath = join(sessionDir, 'traffic-forensics-stop-errors.txt')
  return bestEffortPowerShellScript(errorsPath, [
    { label: 'netsh-trace-stop', command: `$netshStop = netsh trace stop sessionname=${NETSH_SESSION_NAME} 2>&1 | Out-String; Set-Content -Path ${quoted(stopPath)} -Value $netshStop -Encoding UTF8` },
    { label: 'wfp-netevents', command: `netsh wfp show netevents file=${quoted(wfpEventsPath)} timewindow=900 | Out-Null` },
    { label: 'wfp-state', command: `netsh wfp show state file=${quoted(wfpStatePath)} | Out-Null` }
  ])
}

function buildNetshLiveSnapshotScript(sessionDir: string, etlPath: string): string {
  const snapshotEtlPath = join(sessionDir, 'netsh-live.etl')
  const wfpEventsPath = join(sessionDir, 'wfp-live-netevents.xml')
  const wfpStatePath = join(sessionDir, 'wfp-live-state.xml')
  const errorsPath = join(sessionDir, 'traffic-forensics-live-errors.txt')
  return bestEffortPowerShellScript(errorsPath, [
    { label: 'netsh-live-etl-copy', command: `if (Test-Path ${quoted(etlPath)}) { Copy-Item -LiteralPath ${quoted(etlPath)} -Destination ${quoted(snapshotEtlPath)} -Force }` },
    { label: 'wfp-live-netevents', command: `netsh wfp show netevents file=${quoted(wfpEventsPath)} timewindow=900 | Out-Null` },
    { label: 'wfp-live-state', command: `netsh wfp show state file=${quoted(wfpStatePath)} | Out-Null` }
  ])
}

async function refreshTrafficForensicsArtifacts(): Promise<void> {
  const manifest = await readLatestManifest()
  if (!manifest?.running || !manifest.engine || !manifest.sessionDir || !manifest.etlPath) return

  try {
    const scriptPath = join(manifest.sessionDir, 'live-snapshot.ps1')
    let scriptBody = ''
    if (manifest.engine === 'pktmon') {
      scriptBody = buildPktmonLiveSnapshotScript(manifest.sessionDir, manifest.etlPath)
    } else {
      scriptBody = buildNetshLiveSnapshotScript(manifest.sessionDir, manifest.etlPath)
    }
    await writeFile(scriptPath, Buffer.from('\uFEFF' + scriptBody, 'utf8'))
    await execElevated(`powershell -NoProfile -ExecutionPolicy Bypass -File ${cmdQuoted(scriptPath)}`, {
      timeout: 90000,
      maxBuffer: 1024 * 1024 * 16
    })
    logEvent('info', 'traffic-forensics', 'refreshed live traffic artifacts', {
      sessionId: manifest.sessionId,
      engine: manifest.engine
    })
  } catch (err: any) {
    logEvent('warn', 'traffic-forensics', 'failed to refresh live traffic artifacts', {
      sessionId: manifest.sessionId,
      engine: manifest.engine,
      error: err?.message || String(err)
    })
  }
}

async function finalizeManifest(
  manifest: SessionManifest,
  updates: Partial<SessionManifest>
): Promise<TrafficForensicsStatus> {
  let next: SessionManifest = normalizeManifest({ ...manifest, ...updates })
  if (next.sessionDir) {
    try {
      next = await generateTrafficForensicsSummary(next)
    } catch (err: any) {
      next = {
        ...next,
        parserErrors: [
          ...(next.parserErrors ?? []),
          `summary generation failed: ${err?.message || String(err)}`
        ]
      }
    }
  }
  next = preserveObservedSidecarStop(next)
  await writeManifest(next)
  return getTrafficForensicsStatus()
}

export async function startTrafficForensicsSession(
  context: { mode: 'localProxy' | 'directVpn'; target: string }
): Promise<TrafficForensicsStatus> {
  const settings = getSettings()
  if (process.platform !== 'win32' || !settings.enabled) {
    return {
      enabled: settings.enabled,
      running: false,
      engine: null,
      sessionId: null,
      sessionDir: null,
      mode: null,
      target: null,
      startedAt: null,
      stoppedAt: null,
      maxSizeMb: settings.maxSizeMb,
      retainSessions: settings.retainSessions,
      stopReason: null,
      lastError: process.platform === 'win32' ? null : 'Windows-only capture backend',
      schemaVersion: null,
      summaryPath: null,
      summaryGeneratedAt: null,
      summary: null,
      sidecar: null,
      artifactFiles: [],
      health: emptyHealth()
    }
  }

  const current = await readLatestManifest()
  if (current?.running) {
    if (!hasManagedSidecarProcess()) {
      logEvent('warn', 'traffic-forensics', 'found zombie session (running=true but no sidecar), force-stopping')
      await stopTrafficForensicsSession('zombie-recovery')
    } else {
      return getTrafficForensicsStatus()
    }
  }

  await ensureLayout()
  const sessionId = new Date().toISOString().replace(/[:.]/g, '-')
  const sessionDir = join(getSessionsDir(), sessionId)
  await mkdir(sessionDir, { recursive: true })

  const pktmonEtlPath = join(sessionDir, 'pktmon.etl')
  const manifest: SessionManifest = createManifest({
    sessionId,
    enabled: true,
    running: false,
    engine: null,
    mode: context.mode,
    target: context.target,
    startedAt: Date.now(),
    stoppedAt: null,
    maxSizeMb: settings.maxSizeMb,
    retainSessions: settings.retainSessions,
    stopReason: null,
    lastError: null,
    sessionDir,
    etlPath: pktmonEtlPath
  })

  await writeManifest(manifest)

  try {
    const scriptPath = join(sessionDir, 'pktmon-start.ps1')
    await writeFile(scriptPath, Buffer.from('\uFEFF' + buildPktmonStartScript(pktmonEtlPath, settings.maxSizeMb), 'utf8'))
    await execElevated(`powershell -NoProfile -ExecutionPolicy Bypass -File ${cmdQuoted(scriptPath)}`, {
      timeout: 45000,
      maxBuffer: 1024 * 1024 * 8
    })
    logEvent('info', 'traffic-forensics', 'started deep traffic capture', {
      engine: 'pktmon',
      mode: context.mode,
      target: context.target,
      sessionId,
      sizeMb: settings.maxSizeMb
    })
    await pruneOldSessions(settings.retainSessions, sessionId)
    const runningManifest = normalizeManifest({ ...manifest, running: true, engine: 'pktmon' })
    const sidecar = await startSidecar(runningManifest)
    return finalizeManifest(runningManifest, { sidecar })
  } catch (pktmonErr: any) {
    const netshEtlPath = join(sessionDir, 'netsh-trace.etl')
    try {
      await execElevated(buildNetshStartCommand(netshEtlPath, settings.maxSizeMb), {
        timeout: 45000,
        maxBuffer: 1024 * 1024 * 8
      })
      logEvent('warn', 'traffic-forensics', 'pktmon start failed, fell back to netsh trace', {
        sessionId,
        mode: context.mode,
        target: context.target,
        pktmonError: pktmonErr?.message || String(pktmonErr)
      })
      await pruneOldSessions(settings.retainSessions, sessionId)
      const runningManifest = normalizeManifest({
        ...manifest,
        running: true,
        engine: 'netsh',
        etlPath: netshEtlPath,
        lastError: `pktmon start failed: ${pktmonErr?.message || String(pktmonErr)}`
      })
      const sidecar = await startSidecar(runningManifest)
      return finalizeManifest(runningManifest, { sidecar })
    } catch (netshErr: any) {
      const lastError = [
        `pktmon: ${pktmonErr?.message || String(pktmonErr)}`,
        `netsh: ${netshErr?.message || String(netshErr)}`
      ].join(' | ')
      logEvent('error', 'traffic-forensics', 'failed to start deep traffic capture', {
        sessionId,
        mode: context.mode,
        target: context.target,
        lastError
      })
      return finalizeManifest(manifest, {
        running: false,
        engine: null,
        stoppedAt: Date.now(),
        stopReason: 'start-failed',
        lastError
      })
    }
  }
}

export async function stopTrafficForensicsSession(reason: string): Promise<TrafficForensicsStatus> {
  const manifest = await readLatestManifest()
  if (!manifest) return getTrafficForensicsStatus()

  if (!manifest.running || !manifest.engine || !manifest.sessionDir) {
    if (manifest.stopReason !== reason || manifest.stoppedAt === null) {
      const sidecar = stopSidecar(manifest, reason)
      return finalizeManifest(manifest, {
        running: false,
        stoppedAt: manifest.stoppedAt ?? Date.now(),
        stopReason: manifest.stopReason ?? reason,
        sidecar
      })
    }
    return getTrafficForensicsStatus()
  }

  const sidecar = stopSidecar(manifest, reason)

  try {
    if (manifest.engine === 'pktmon' && manifest.etlPath) {
      const scriptPath = join(manifest.sessionDir, 'pktmon-stop.ps1')
      await writeFile(scriptPath, Buffer.from('\uFEFF' + buildPktmonStopScript(manifest.sessionDir, manifest.etlPath), 'utf8'))
      await execElevated(`powershell -NoProfile -ExecutionPolicy Bypass -File ${cmdQuoted(scriptPath)}`, {
        timeout: 90000,
        maxBuffer: 1024 * 1024 * 16
      })
    } else if (manifest.engine === 'netsh') {
      const scriptPath = join(manifest.sessionDir, 'netsh-stop.ps1')
      await writeFile(scriptPath, Buffer.from('\uFEFF' + buildNetshStopScript(manifest.sessionDir), 'utf8'))
      await execElevated(`powershell -NoProfile -ExecutionPolicy Bypass -File ${cmdQuoted(scriptPath)}`, {
        timeout: 90000,
        maxBuffer: 1024 * 1024 * 16
      })
    }
  } catch (err: any) {
    logEvent('warn', 'traffic-forensics', 'deep traffic capture stop hit an error', {
      sessionId: manifest.sessionId,
      engine: manifest.engine,
      reason,
      error: err?.message || String(err)
    })
    return finalizeManifest(manifest, {
      running: false,
      stoppedAt: Date.now(),
      stopReason: reason,
      lastError: err?.message || String(err),
      sidecar
    })
  }

  logEvent('info', 'traffic-forensics', 'stopped deep traffic capture', {
    sessionId: manifest.sessionId,
    engine: manifest.engine,
    reason
  })
  await pruneOldSessions(manifest.retainSessions, manifest.sessionId)
  return finalizeManifest(manifest, {
    running: false,
    stoppedAt: Date.now(),
    stopReason: reason,
    sidecar
  })
}

export async function getTrafficForensicsStatus(): Promise<TrafficForensicsStatus> {
  const settings = getSettings()
  let manifest = await reconcileStaleRunningManifest(await readLatestManifest())
  const artifactFiles = await listTrafficForensicsArtifacts(manifest?.sessionDir ?? null)
  manifest = await reconcileStoppedCaptureManifest(manifest, artifactFiles)
  const summary = await readSummaryForStatus(manifest?.summaryPath)
  const sidecar = manifest?.sidecar ?? null
  // Only surface the live ETW digest (categories, top domains/endpoints, data
  // counts) for the session that belongs to this run. A stopped session left
  // over from a previous launch/reinstall must not show its stale events.ndjson
  // as if it were current — the persisted summary still carries finalized counts.
  const isCurrentSession =
    Boolean(manifest?.running) ||
    (typeof manifest?.startedAt === 'number' && manifest.startedAt >= PROCESS_START_MS)
  const sidecarProbe = isCurrentSession
    ? await readSidecarEventProbe(manifest?.sessionDir)
    : emptySidecarEventProbe()
  return {
    enabled: settings.enabled,
    running: Boolean(manifest?.running),
    engine: manifest?.engine ?? null,
    sessionId: manifest?.sessionId ?? null,
    sessionDir: manifest?.sessionDir ?? null,
    mode: manifest?.mode ?? null,
    target: manifest?.target ?? null,
    startedAt: manifest?.startedAt ?? null,
    stoppedAt: manifest?.stoppedAt ?? null,
    maxSizeMb: settings.maxSizeMb,
    retainSessions: settings.retainSessions,
    stopReason: manifest?.stopReason ?? null,
    lastError: manifest?.lastError ?? null,
    schemaVersion: manifest?.schemaVersion ?? null,
    summaryPath: manifest?.summaryPath ?? null,
    summaryGeneratedAt: manifest?.summaryGeneratedAt ?? null,
    summary,
    sidecar,
    artifactFiles,
    health: buildTrafficForensicsHealth(artifactFiles, summary, sidecar, sidecarProbe, manifest?.startedAt)
  }
}

export async function stageTrafficForensicsArtifacts(stageDir: string): Promise<boolean> {
  const rootDir = getRootDir()
  if (!existsSync(rootDir)) return false
  await refreshTrafficForensicsArtifacts()
  const manifest = await readLatestManifest()
  if (manifest?.sessionDir) {
    const next = await generateTrafficForensicsSummary(manifest).catch((err: any) => ({
      ...manifest,
      parserErrors: [
        ...(manifest.parserErrors ?? []),
        `summary generation failed during stage: ${err?.message || String(err)}`
      ]
    }))
    await writeManifest(next)
  }
  await mkdir(stageDir, { recursive: true })
  await cp(rootDir, join(stageDir, 'traffic-forensics'), {
    recursive: true,
    force: true
  })
  return true
}
