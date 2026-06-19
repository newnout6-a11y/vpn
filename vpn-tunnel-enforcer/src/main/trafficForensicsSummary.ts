import { existsSync } from 'fs'
import * as fsp from 'fs/promises'
import { join } from 'path'

export type TrafficForensicsSummaryEngine = 'pktmon' | 'netsh'

export interface TrafficForensicsArtifactFile {
  name: string
  size: number
  mtimeMs: number
}

export interface TrafficForensicsSummaryManifest {
  schemaVersion: number
  appVersion: string | null
  os: {
    platform: NodeJS.Platform
    type: string
    release: string
    version: string | null
  }
  sessionId: string
  enabled: boolean
  running: boolean
  engine: TrafficForensicsSummaryEngine | null
  mode: 'localProxy' | 'directVpn' | null
  target: string | null
  startedAt: number | null
  stoppedAt: number | null
  maxSizeMb: number
  retainSessions: number
  stopReason: string | null
  lastError: string | null
  sessionDir: string | null
  etlPath: string | null
  normalizedArtifacts: string[]
  summaryPath: string | null
  summaryGeneratedAt: number | null
  parserErrors: string[]
  sidecar: {
    available: boolean
    running: boolean
    executablePath: string | null
    eventsPath: string | null
    startedAt: number | null
    stoppedAt: number | null
    pid: number | null
    lastError: string | null
  }
}

type SummaryVerdictKey =
  | 'trafficLeakDetected'
  | 'dnsLeakDetected'
  | 'tunPathConfirmed'
  | 'killSwitchBlockedTraffic'
  | 'windowsFirewallBlockedTraffic'
  | 'remoteResetLikely'
  | 'localResetLikely'
  | 'timeoutOrPacketLossLikely'
  | 'mtuIssueLikely'
  | 'singBoxFailureLikely'
  | 'insufficientEvidence'

interface EvidenceRef {
  artifact: string
  reason: string
  match?: string
  flowId?: string
}

interface TimelineEvent {
  timestamp: number
  category: string
  action: string
  artifact?: string
  details?: Record<string, unknown>
}

interface DropRecord {
  timestamp: number
  source: 'pktmon' | 'wfp' | 'firewall' | 'app'
  reason: string
  artifact: string
  match?: string
  flowId?: string
}

interface DnsRecord {
  timestamp: number
  source: 'dns-client' | 'snapshot'
  artifact: string
  verdict: 'observed-unclassified'
  queryName?: string
  resolver?: string
  evidence?: string
  linkedFlowIds?: string[]
}

interface TcpHealthRecord {
  timestamp: number
  source: 'tcpip'
  artifact: string
  reason: 'reset-observed' | 'timeout-or-retransmit-observed' | 'mtu-or-fragmentation-observed'
  match: string
  flowId?: string
}

interface AppEventRecord {
  timestamp: number
  source: 'traffic-forensics'
  event: string
  details: Record<string, unknown>
}

interface PacketMetricRecord {
  timestamp: number
  source: 'pktmon'
  artifact: string
  path: string
  name: string
  value: number
  category: 'packet' | 'byte' | 'drop' | 'error' | 'counter'
  labels?: Record<string, string | number | boolean>
}

interface SidecarEventRecord {
  timestamp?: number
  ts?: string
  provider?: string
  event?: string
  category?: string
  action?: string
  protocol?: 'tcp' | 'udp' | string
  localAddress?: string | null
  localPort?: number | string | null
  remoteAddress?: string | null
  remotePort?: number | string | null
  processId?: number | string | null
  queryName?: string
  resultAddresses?: string[]
  resolver?: string
  interfaceIndex?: number | string
  direction?: string
  reason?: string
  verdict?: string
  droppedEvents?: number
  bufferPressure?: number
  details?: Record<string, unknown>
  raw?: unknown
}

interface SourceAppEvent {
  timestamp?: number
  ts?: string
  source?: string
  event?: string
  details?: Record<string, unknown>
}

interface FlowRecord {
  id: string
  timestamp: number
  source: 'tcp-snapshot' | 'udp-snapshot'
  protocol: 'tcp' | 'udp'
  localAddress: string | null
  localPort: number | null
  remoteAddress: string | null
  remotePort: number | null
  state: string | null
  owningProcess: number | null
  artifact: string
  dnsNames: string[]
  verdict: 'observed-unclassified'
  evidence: EvidenceRef[]
}

interface LeakSignal {
  key: Extract<SummaryVerdictKey, 'trafficLeakDetected' | 'dnsLeakDetected'>
  ref: EvidenceRef
}

export const MANIFEST_SCHEMA_VERSION = 2
const SUMMARY_SCHEMA_VERSION = 1

export const NORMALIZED_ARTIFACTS = [
  'summary.json',
  'timeline.ndjson',
  'flows.ndjson',
  'dns.ndjson',
  'drops.ndjson',
  'tcp-health.ndjson',
  'packet-metrics.ndjson',
  'route-snapshots.json',
  'app-events.ndjson'
]

const GENERATED_ARTIFACTS = [
  ...NORMALIZED_ARTIFACTS
]

const PKTMON_EXPECTED_ARTIFACTS = [
  'pktmon.etl',
  'pktmon-trace.txt',
  'pktmon-trace.pcapng',
  'pktmon-status.txt',
  'pktmon-counters.json',
  'pktmon-drop-counters.json',
  'wfp-netevents.xml',
  'wfp-state.xml'
]

const PKTMON_LIVE_EXPECTED_ARTIFACTS = [
  'pktmon.etl',
  'pktmon-live-status.txt',
  'pktmon-live-counters.json',
  'pktmon-live-drop-counters.json',
  'wfp-live-netevents.xml',
  'wfp-live-state.xml'
]

const NETSH_EXPECTED_ARTIFACTS = [
  'netsh-trace.etl',
  'netsh-trace-stop.txt',
  'wfp-netevents.xml',
  'wfp-state.xml'
]

async function readTextIfExists(path: string): Promise<string | null> {
  try {
    if (!existsSync(path)) return null
    return await fsp.readFile(path, 'utf-8')
  } catch {
    return null
  }
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await fsp.writeFile(path, JSON.stringify(value, null, 2), 'utf-8')
}

async function writeNdjson(path: string, rows: unknown[]): Promise<void> {
  await fsp.writeFile(path, rows.map(row => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : ''), 'utf-8')
}

function addEvidence(
  evidence: Partial<Record<SummaryVerdictKey, EvidenceRef[]>>,
  key: SummaryVerdictKey,
  ref: EvidenceRef
): void {
  evidence[key] = [...(evidence[key] ?? []), ref]
}

function firstLineMatch(text: string, patterns: RegExp[]): string | undefined {
  const lines = text.split(/\r?\n/)
  return lines.find(line => patterns.some(pattern => pattern.test(line)))
}

function looksTunnel(value: string): boolean {
  return /wintun|wireguard|tun\b|tunnel|vpn|sing-box|vpnte/i.test(value)
}

function looksPhysical(value: string): boolean {
  return /ethernet|wi-?fi|wireless|realtek|intel|qualcomm|mediatek|killer|physical|lan/i.test(value) && !looksTunnel(value)
}

function parseSnapshotRows(text: string): any[] {
  const rows = parseJsonArray(text)
  if (rows.length) return rows
  return text.split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => ({ raw: line }))
}

function recordValues(record: any): string {
  if (record?.raw) return String(record.raw)
  return Object.values(record ?? {})
    .map(value => {
      if (value === null || value === undefined) return ''
      if (typeof value === 'object') return JSON.stringify(value)
      return String(value)
    })
    .join(' ')
}

function extractLeakSignals(artifact: string, text: string, timestamp: number): LeakSignal[] {
  const signals: LeakSignal[] = []
  const rows = parseSnapshotRows(text)
  for (const row of rows) {
    const values = recordValues(row)
    const lowerArtifact = artifact.toLowerCase()
    const isDnsArtifact = lowerArtifact.includes('dns-client-servers') || lowerArtifact.includes('dns-client') || lowerArtifact.includes('ipconfig')
    const isRouteArtifact = lowerArtifact.includes('routes') || lowerArtifact.includes('route-print') || lowerArtifact.includes('interfaces')
    if (isDnsArtifact && (lowerArtifact.includes('dns-client-servers') || /server|resolver|dns/i.test(values)) && looksPhysical(values)) {
      signals.push({
        key: 'dnsLeakDetected',
        ref: {
          artifact,
          reason: 'DNS resolver is bound to a physical/non-tunnel interface',
          match: values.slice(0, 500)
        }
      })
    }
    if (isRouteArtifact && /0\.0\.0\.0\/0|::\/0|default|destinationprefix/i.test(values) && looksPhysical(values)) {
      signals.push({
        key: 'trafficLeakDetected',
        ref: {
          artifact,
          reason: 'default route prefers a physical/non-tunnel interface during VPN session',
          match: values.slice(0, 500)
        }
      })
    }
    if (isRouteArtifact && /0\.0\.0\.0\/0|::\/0|default|destinationprefix/i.test(values) && looksTunnel(values)) {
      signals.push({
        key: 'trafficLeakDetected',
        ref: {
          artifact,
          reason: 'default route observed on tunnel interface; no bypass verdict from this row',
          match: values.slice(0, 500)
        }
      })
    }
  }
  return signals.filter(signal => {
    if (signal.key === 'trafficLeakDetected' && signal.ref.reason.startsWith('default route observed on tunnel')) return false
    return true
  })
}

function parseNdjson(text: string): any[] {
  const rows: any[] = []
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed) continue
    try {
      rows.push(JSON.parse(trimmed))
    } catch {
      rows.push({ raw: trimmed })
    }
  }
  return rows
}

function eventTimestamp(event: SourceAppEvent, fallback: number): number {
  if (typeof event.timestamp === 'number' && Number.isFinite(event.timestamp)) return event.timestamp
  if (event.ts) {
    const parsed = Date.parse(event.ts)
    if (Number.isFinite(parsed)) return parsed
  }
  return fallback
}

function extractSourceAppEvents(artifact: string, text: string, timestamp: number): AppEventRecord[] {
  if (!/app-events-source/i.test(artifact)) return []
  return parseNdjson(text).map((event) => ({
    timestamp: eventTimestamp(event, timestamp),
    source: 'traffic-forensics',
    event: String(event.event || 'app-event'),
    details: {
      source: event.source || 'app',
      artifact,
      ...(event.details && typeof event.details === 'object' ? event.details : { raw: event.raw ?? event })
    }
  }))
}

function extractSidecarEvents(artifact: string, text: string): SidecarEventRecord[] {
  if (artifact !== 'events.ndjson') return []
  return parseNdjson(text).map((event) => ({
    ...event,
    details: event.details && typeof event.details === 'object' ? event.details : undefined
  }))
}

function sidecarText(event: SidecarEventRecord): string {
  return JSON.stringify(event)
}

function sidecarKind(event: SidecarEventRecord): string {
  return [
    event.provider,
    event.category,
    event.event,
    event.action,
    event.reason,
    event.verdict
  ].filter(Boolean).join(' ').toLowerCase()
}

function sidecarTimestamp(event: SidecarEventRecord, fallback: number): number {
  return eventTimestamp(event, fallback)
}

function isSidecarDnsEvent(event: SidecarEventRecord): boolean {
  const kind = sidecarKind(event)
  return /dns/.test(kind) || Boolean(event.queryName)
}

function isSidecarDropEvent(event: SidecarEventRecord): boolean {
  const kind = sidecarKind(event)
  return /wfp|firewall|drop|block|blocked|discard/.test(kind)
}

function isSidecarTcpHealthEvent(event: SidecarEventRecord): boolean {
  const kind = sidecarKind(event)
  return /tcp|reset|rst|timeout|retrans|loss|mtu|fragment/.test(kind)
}

function sidecarTcpReason(event: SidecarEventRecord): TcpHealthRecord['reason'] | null {
  const text = sidecarText(event)
  if (/mtu|fragment|packet too big/i.test(text)) return 'mtu-or-fragmentation-observed'
  if (/timeout|retrans|retransmit|loss/i.test(text)) return 'timeout-or-retransmit-observed'
  if (/reset|\brst\b/i.test(text)) return 'reset-observed'
  return null
}

function sidecarDropSource(event: SidecarEventRecord): DropRecord['source'] {
  const kind = sidecarKind(event)
  if (/firewall/.test(kind)) return 'firewall'
  if (/wfp/.test(kind)) return 'wfp'
  return 'pktmon'
}

function sidecarEventName(event: SidecarEventRecord): string {
  return String(event.event || event.action || event.category || 'sidecar-event')
}

function isSingBoxFailureEvent(event: AppEventRecord): boolean {
  const text = JSON.stringify(event)
  return /sing-?box/i.test(text) && /(fail|failed|error|crash|crashed|exit|exited|timeout|did not start|не старт|не запуст|упал)/i.test(text)
}

function isTrafficLeakAppEvent(event: AppEventRecord): boolean {
  const details = event.details as Record<string, any>
  if (event.event === 'leak-self-test-result') {
    return details.physicalAdapterReached === true || details.publicIpMismatch === true
  }
  if (event.event === 'leak-diagnostics-result') {
    const items = Array.isArray(details.items) ? details.items : []
    return items.some((item: any) => item?.status === 'fail' && /direct-public|ipv4|proxy/i.test(String(item?.id ?? '')))
  }
  return false
}

function isDnsLeakAppEvent(event: AppEventRecord): boolean {
  const details = event.details as Record<string, any>
  if (event.event === 'leak-self-test-result') return details.dnsLeakDetected === true
  if (event.event === 'leak-diagnostics-result') {
    const items = Array.isArray(details.items) ? details.items : []
    return items.some((item: any) => item?.status === 'fail' && /dns/i.test(String(item?.id ?? item?.label ?? '')))
  }
  return false
}

function appEventEvidenceReason(event: AppEventRecord): string {
  if (event.event === 'leak-self-test-result') return 'app leak self-test reported leak signal'
  if (event.event === 'leak-diagnostics-result') return 'app leak diagnostics reported failing leak check'
  return 'app lifecycle event reported network failure'
}

function extractDnsRecords(artifact: string, text: string, timestamp: number): DnsRecord[] {
  const lower = text.toLowerCase()
  if (!lower.includes('dns')) return []
  const records: DnsRecord[] = []
  const domainMatches = text.match(/\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,}\b/gi) ?? []
  const uniqueDomains = Array.from(new Set(domainMatches)).slice(0, 50)
  for (const domain of uniqueDomains) {
    const evidenceLine = firstLineMatch(text, [new RegExp(domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')])
    records.push({
      timestamp,
      source: artifact.includes('dnsclient-events') ? 'dns-client' : 'snapshot',
      artifact,
      verdict: 'observed-unclassified',
      queryName: domain,
      evidence: evidenceLine ?? domain
    })
  }
  if (!records.length) {
    records.push({
      timestamp,
      source: artifact.includes('dnsclient-events') ? 'dns-client' : 'snapshot',
      artifact,
      verdict: 'observed-unclassified',
      evidence: firstLineMatch(text, [/dns/i])
    })
  }
  return records
}

function extractTcpHealthRecords(artifact: string, text: string, timestamp: number): TcpHealthRecord[] {
  const records: TcpHealthRecord[] = []
  const checks: Array<{ reason: TcpHealthRecord['reason']; patterns: RegExp[] }> = [
    { reason: 'reset-observed', patterns: [/reset/i, /\brst\b/i] },
    { reason: 'timeout-or-retransmit-observed', patterns: [/timeout/i, /retrans/i, /retransmit/i, /loss/i] },
    { reason: 'mtu-or-fragmentation-observed', patterns: [/mtu/i, /fragment/i, /packet too big/i] }
  ]
  for (const check of checks) {
    const match = firstLineMatch(text, check.patterns)
    if (match) {
      records.push({
        timestamp,
        source: 'tcpip',
        artifact,
        reason: check.reason,
        match
      })
    }
  }
  return records
}

function asArray(value: unknown): any[] {
  if (Array.isArray(value)) return value
  if (value && typeof value === 'object') return [value]
  return []
}

function parseJsonArray(text: string): any[] {
  try {
    return asArray(JSON.parse(text))
  } catch {
    return []
  }
}

function parseJsonValue(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function numberOrNull(value: unknown): number | null {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : null
}

function stringOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null
  const text = String(value)
  return text.length ? text : null
}

function packetMetricCategory(name: string, artifact: string): PacketMetricRecord['category'] {
  const text = `${artifact} ${name}`
  if (/drop|dropped|discard/i.test(text)) return 'drop'
  if (/byte|octet/i.test(text)) return 'byte'
  if (/packet|frame|pkt/i.test(text)) return 'packet'
  if (/error|fail|lost|loss/i.test(text)) return 'error'
  return 'counter'
}

function packetMetricLabels(pathParts: string[], valueKey: string): Record<string, string | number | boolean> | undefined {
  const labels: Record<string, string | number | boolean> = {}
  const parts = pathParts.slice(0, -1)
  parts.forEach((part, index) => {
    if (/^\d+$/.test(part)) return
    labels[`level${index + 1}`] = part
  })
  if (valueKey && valueKey !== pathParts[pathParts.length - 1]) {
    labels.valueKey = valueKey
  }
  return Object.keys(labels).length ? labels : undefined
}

function extractPacketMetricRecords(artifact: string, text: string, timestamp: number): PacketMetricRecord[] {
  if (!/pktmon.*counter/i.test(artifact)) return []
  const root = parseJsonValue(text)
  if (root === null || root === undefined) return []
  const records: PacketMetricRecord[] = []
  const visit = (value: unknown, pathParts: string[]): void => {
    if (typeof value === 'number' && Number.isFinite(value)) {
      const name = pathParts[pathParts.length - 1] || 'value'
      records.push({
        timestamp,
        source: 'pktmon',
        artifact,
        path: pathParts.join('.'),
        name,
        value,
        category: packetMetricCategory(name, artifact),
        labels: packetMetricLabels(pathParts, name)
      })
      return
    }
    if (!value || typeof value !== 'object') return
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, [...pathParts, String(index)]))
      return
    }
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      visit(child, [...pathParts, key])
    }
  }
  visit(root, [])
  return records
}

function flowId(protocol: string, localAddress: string | null, localPort: number | null, remoteAddress: string | null, remotePort: number | null, owningProcess: number | null): string {
  return [protocol, localAddress ?? '', localPort ?? '', remoteAddress ?? '', remotePort ?? '', owningProcess ?? ''].join('|')
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(new Set(values.map(value => String(value ?? '').trim()).filter(Boolean)))
}

function ipsFromText(text: string | undefined): string[] {
  if (!text) return []
  const ipv4 = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []
  const ipv6 = text.match(/\b(?:[a-f0-9]{0,4}:){2,}[a-f0-9]{0,4}\b/gi) ?? []
  return uniqueStrings([...ipv4, ...ipv6])
}

function bestFlowForText(flows: FlowRecord[], text: string | undefined): FlowRecord | null {
  const ips = new Set(ipsFromText(text))
  if (!ips.size) return null
  return flows.find(flow => {
    if (flow.remoteAddress && ips.has(flow.remoteAddress)) return true
    if (flow.localAddress && ips.has(flow.localAddress)) return true
    return false
  }) ?? null
}

function correlateRecordsToFlows(
  flows: FlowRecord[],
  dnsRecords: DnsRecord[],
  dropRecords: DropRecord[],
  tcpHealthRecords: TcpHealthRecord[],
  evidence: Partial<Record<SummaryVerdictKey, EvidenceRef[]>>
): void {
  for (const dns of dnsRecords) {
    const matchingFlows = flows.filter(flow => {
      if (dns.queryName && flow.dnsNames.includes(dns.queryName)) return true
      const evidenceIps = new Set(ipsFromText(dns.evidence))
      return Boolean(flow.remoteAddress && evidenceIps.has(flow.remoteAddress))
    })
    if (matchingFlows.length) {
      dns.linkedFlowIds = uniqueStrings(matchingFlows.map(flow => flow.id))
      for (const flow of matchingFlows) {
        flow.evidence.push({
          artifact: dns.artifact,
          reason: dns.queryName ? `DNS record linked query ${dns.queryName}` : 'DNS record linked by address evidence',
          match: dns.evidence
        })
      }
    }
  }

  for (const drop of dropRecords) {
    const flow = bestFlowForText(flows, drop.match)
    if (flow) {
      drop.flowId = flow.id
      flow.evidence.push({
        artifact: drop.artifact,
        reason: drop.reason,
        match: drop.match
      })
    }
  }

  for (const tcp of tcpHealthRecords) {
    const flow = bestFlowForText(flows, tcp.match)
    if (flow) {
      tcp.flowId = flow.id
      flow.evidence.push({
        artifact: tcp.artifact,
        reason: tcp.reason,
        match: tcp.match
      })
    }
  }

  for (const refs of Object.values(evidence)) {
    for (const ref of refs ?? []) {
      if (ref.flowId) continue
      const flow = bestFlowForText(flows, ref.match)
      if (flow) ref.flowId = flow.id
    }
  }
}

function buildDnsIndex(records: DnsRecord[]): Map<string, string[]> {
  const index = new Map<string, string[]>()
  for (const record of records) {
    if (!record.queryName) continue
    const values = record.evidence?.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []
    for (const value of values) {
      const current = index.get(value) ?? []
      if (!current.includes(record.queryName)) {
        index.set(value, [...current, record.queryName])
      }
    }
  }
  return index
}

function extractFlowRecords(artifact: string, text: string, timestamp: number, dnsIndex: Map<string, string[]>): FlowRecord[] {
  const rows = parseJsonArray(text)
  if (!rows.length) return []
  const protocol: FlowRecord['protocol'] = /udp/i.test(artifact) ? 'udp' : 'tcp'
  return rows.map((row) => {
    const localAddress = stringOrNull(row.LocalAddress ?? row.localAddress)
    const remoteAddress = protocol === 'udp'
      ? null
      : stringOrNull(row.RemoteAddress ?? row.remoteAddress)
    const localPort = numberOrNull(row.LocalPort ?? row.localPort)
    const remotePort = protocol === 'udp'
      ? null
      : numberOrNull(row.RemotePort ?? row.remotePort)
    const owningProcess = numberOrNull(row.OwningProcess ?? row.owningProcess)
    const state = protocol === 'udp' ? null : stringOrNull(row.State ?? row.state)
    const dnsNames = remoteAddress ? (dnsIndex.get(remoteAddress) ?? []) : []
    return {
      id: flowId(protocol, localAddress, localPort, remoteAddress, remotePort, owningProcess),
      timestamp,
      source: protocol === 'udp' ? 'udp-snapshot' : 'tcp-snapshot',
      protocol,
      localAddress,
      localPort,
      remoteAddress,
      remotePort,
      state,
      owningProcess,
      artifact,
      dnsNames,
      verdict: 'observed-unclassified',
      evidence: [{
        artifact,
        reason: `${protocol.toUpperCase()} endpoint snapshot`
      }]
    }
  })
}

function extractDropRecords(artifact: string, text: string, timestamp: number): DropRecord[] {
  const records: DropRecord[] = []
  const checks: Array<{ source: DropRecord['source']; reason: string; patterns: RegExp[] }> = [
    { source: 'pktmon', reason: 'pktmon-drop-or-counter-observed', patterns: [/drop/i, /dropped/i, /discard/i] },
    { source: 'wfp', reason: 'wfp-block-observed', patterns: [/block/i, /blocked/i, /5152/, /FWPM|FWPS/] },
    { source: 'firewall', reason: 'firewall-block-rule-observed', patterns: [/firewall/i, /action.*block/i, /block/i] }
  ]
  for (const check of checks) {
    const match = firstLineMatch(text, check.patterns)
    if (match) {
      records.push({
        timestamp,
        source: check.source,
        reason: check.reason,
        artifact,
        match
      })
    }
  }
  return records
}

function expectedArtifactsFor(manifest: TrafficForensicsSummaryManifest): string[] {
  if (manifest.engine === 'netsh') return NETSH_EXPECTED_ARTIFACTS
  if (manifest.engine === 'pktmon') return manifest.running ? PKTMON_LIVE_EXPECTED_ARTIFACTS : PKTMON_EXPECTED_ARTIFACTS
  return []
}

function pushParserError(errors: string[], message: string): void {
  if (!errors.includes(message)) errors.push(message)
}

export async function listTrafficForensicsArtifacts(sessionDir: string | null): Promise<TrafficForensicsArtifactFile[]> {
  if (!sessionDir || !existsSync(sessionDir)) return []
  const entries = await fsp.readdir(sessionDir, { withFileTypes: true })
  const files = await Promise.all(entries
    .filter((entry) => entry.isFile())
    .map(async (entry) => {
      const info = await fsp.stat(join(sessionDir, entry.name))
      return {
        name: entry.name,
        size: info.size,
        mtimeMs: info.mtimeMs
      }
    }))
  return files.sort((a, b) => a.name.localeCompare(b.name))
}

export async function generateTrafficForensicsSummary(manifest: TrafficForensicsSummaryManifest): Promise<TrafficForensicsSummaryManifest> {
  if (!manifest.sessionDir || !existsSync(manifest.sessionDir)) return manifest

  const generatedAt = Date.now()
  const parserErrors = [...(manifest.parserErrors ?? [])]
  const timeline: TimelineEvent[] = []
  const dnsRecords: DnsRecord[] = []
  const dropRecords: DropRecord[] = []
  const tcpHealthRecords: TcpHealthRecord[] = []
  const packetMetricRecords: PacketMetricRecord[] = []
  const appEvents: AppEventRecord[] = []
  let flowRecords: FlowRecord[] = []
  let sidecarEventCount = 0
  const evidence: Partial<Record<SummaryVerdictKey, EvidenceRef[]>> = {}

  appEvents.push({
    timestamp: manifest.startedAt ?? generatedAt,
    source: 'traffic-forensics',
    event: 'session-started',
    details: {
      mode: manifest.mode,
      target: manifest.target,
      engine: manifest.engine
    }
  })
  timeline.push({
    timestamp: manifest.startedAt ?? generatedAt,
    category: 'traffic-forensics',
    action: 'session-started',
    details: {
      mode: manifest.mode,
      target: manifest.target,
      engine: manifest.engine
    }
  })
  if (manifest.stoppedAt) {
    appEvents.push({
      timestamp: manifest.stoppedAt,
      source: 'traffic-forensics',
      event: 'session-stopped',
      details: {
        stopReason: manifest.stopReason,
        lastError: manifest.lastError
      }
    })
    timeline.push({
      timestamp: manifest.stoppedAt,
      category: 'traffic-forensics',
      action: 'session-stopped',
      details: {
        stopReason: manifest.stopReason
      }
    })
  }
  if (manifest.stopReason === 'killswitch-active' || manifest.stopReason?.includes('killswitch')) {
    addEvidence(evidence, 'killSwitchBlockedTraffic', {
      artifact: 'session-manifest.json',
      reason: `stop reason is ${manifest.stopReason}`
    })
  }

  const files = await listTrafficForensicsArtifacts(manifest.sessionDir)
  const artifactNames = new Set(files.map(file => file.name))
  for (const expected of expectedArtifactsFor(manifest)) {
    if (!artifactNames.has(expected)) {
      pushParserError(parserErrors, `missing expected artifact: ${expected}`)
    }
  }

  for (const artifact of files) {
    if (GENERATED_ARTIFACTS.includes(artifact.name) || artifact.name === 'session-manifest.json') continue
    timeline.push({
      timestamp: artifact.mtimeMs || generatedAt,
      category: 'artifact',
      action: 'observed',
      artifact: artifact.name,
      details: {
        size: artifact.size
      }
    })

    const text = await readTextIfExists(join(manifest.sessionDir, artifact.name))
    if (!text) continue

    const sidecarEvents = extractSidecarEvents(artifact.name, text)
    sidecarEventCount += sidecarEvents.length
    for (const event of sidecarEvents) {
      const eventTime = sidecarTimestamp(event, artifact.mtimeMs || generatedAt)
      const eventName = sidecarEventName(event)
      const match = sidecarText(event).slice(0, 500)
      timeline.push({
        timestamp: eventTime,
        category: String(event.category || event.provider || 'sidecar'),
        action: eventName,
        artifact: artifact.name,
        details: event as Record<string, unknown>
      })
      appEvents.push({
        timestamp: eventTime,
        source: 'traffic-forensics',
        event: `sidecar:${eventName}`,
        details: {
          artifact: artifact.name,
          provider: event.provider,
          category: event.category,
          action: event.action,
          event: event.event,
          droppedEvents: event.droppedEvents,
          bufferPressure: event.bufferPressure
        }
      })
      if (typeof event.droppedEvents === 'number' && event.droppedEvents > 0) {
        parserErrors.push(`sidecar reported ${event.droppedEvents} dropped ETW events`)
        addEvidence(evidence, 'insufficientEvidence', {
          artifact: artifact.name,
          reason: 'sidecar reported dropped ETW events',
          match
        })
      }
      if (typeof event.bufferPressure === 'number' && event.bufferPressure > 0.8) {
        parserErrors.push(`sidecar reported high buffer pressure: ${event.bufferPressure}`)
      }
      if (isSidecarDnsEvent(event)) {
        dnsRecords.push({
          timestamp: eventTime,
          source: 'dns-client',
          artifact: artifact.name,
          verdict: 'observed-unclassified',
          queryName: event.queryName,
          resolver: event.resolver,
          evidence: match
        })
        if (/leak|physical|non-tunnel|outside/i.test(match)) {
          addEvidence(evidence, 'dnsLeakDetected', {
            artifact: artifact.name,
            reason: 'sidecar DNS event reports resolver outside tunnel policy',
            match
          })
        }
      }
      if (isSidecarDropEvent(event)) {
        const reason = event.reason || (sidecarDropSource(event) === 'wfp' ? 'wfp-block-observed' : 'pktmon-drop-or-counter-observed')
        const drop: DropRecord = {
          timestamp: eventTime,
          source: sidecarDropSource(event),
          reason,
          artifact: artifact.name,
          match
        }
        dropRecords.push(drop)
        if (drop.source === 'wfp' || drop.source === 'firewall') {
          addEvidence(evidence, 'windowsFirewallBlockedTraffic', {
            artifact: artifact.name,
            reason,
            match
          })
        }
      }
      const tcpReason = isSidecarTcpHealthEvent(event) ? sidecarTcpReason(event) : null
      if (tcpReason) {
        tcpHealthRecords.push({
          timestamp: eventTime,
          source: 'tcpip',
          artifact: artifact.name,
          reason: tcpReason,
          match
        })
        if (tcpReason === 'reset-observed') {
          addEvidence(evidence, 'remoteResetLikely', { artifact: artifact.name, reason: tcpReason, match })
        } else if (tcpReason === 'timeout-or-retransmit-observed') {
          addEvidence(evidence, 'timeoutOrPacketLossLikely', { artifact: artifact.name, reason: tcpReason, match })
        } else if (tcpReason === 'mtu-or-fragmentation-observed') {
          addEvidence(evidence, 'mtuIssueLikely', { artifact: artifact.name, reason: tcpReason, match })
        }
      }
    }

    const sourceEvents = extractSourceAppEvents(artifact.name, text, artifact.mtimeMs || generatedAt)
    for (const event of sourceEvents) {
      appEvents.push(event)
      timeline.push({
        timestamp: event.timestamp,
        category: 'app',
        action: event.event,
        artifact: artifact.name,
        details: event.details
      })
      if (isSingBoxFailureEvent(event)) {
        addEvidence(evidence, 'singBoxFailureLikely', {
          artifact: artifact.name,
          reason: 'app lifecycle event reports sing-box failure',
          match: JSON.stringify(event).slice(0, 500)
        })
      }
      if (isTrafficLeakAppEvent(event)) {
        addEvidence(evidence, 'trafficLeakDetected', {
          artifact: artifact.name,
          reason: appEventEvidenceReason(event),
          match: JSON.stringify(event).slice(0, 500)
        })
      }
      if (isDnsLeakAppEvent(event)) {
        addEvidence(evidence, 'dnsLeakDetected', {
          artifact: artifact.name,
          reason: appEventEvidenceReason(event),
          match: JSON.stringify(event).slice(0, 500)
        })
      }
    }

    for (const signal of extractLeakSignals(artifact.name, text, artifact.mtimeMs || generatedAt)) {
      addEvidence(evidence, signal.key, signal.ref)
      appEvents.push({
        timestamp: artifact.mtimeMs || generatedAt,
        source: 'traffic-forensics',
        event: signal.key === 'dnsLeakDetected' ? 'dns-leak-signal' : 'traffic-leak-signal',
        details: {
          artifact: signal.ref.artifact,
          reason: signal.ref.reason,
          match: signal.ref.match
        }
      })
    }

    if (/dns/i.test(artifact.name)) {
      dnsRecords.push(...extractDnsRecords(artifact.name, text, artifact.mtimeMs || generatedAt))
    }

    if (/drop|wfp|firewall|pktmon.*counter/i.test(artifact.name)) {
      const drops = extractDropRecords(artifact.name, text, artifact.mtimeMs || generatedAt)
      dropRecords.push(...drops)
      for (const drop of drops) {
        if (drop.source === 'wfp' || drop.source === 'firewall') {
          appEvents.push({
            timestamp: drop.timestamp,
            source: 'traffic-forensics',
            event: 'windows-block-signal',
            details: {
              artifact: drop.artifact,
              reason: drop.reason,
              match: drop.match
            }
          })
          addEvidence(evidence, 'windowsFirewallBlockedTraffic', {
            artifact: artifact.name,
            reason: drop.reason,
            match: drop.match
          })
        }
      }
    }

    const packetMetrics = extractPacketMetricRecords(artifact.name, text, artifact.mtimeMs || generatedAt)
    packetMetricRecords.push(...packetMetrics)
    for (const metric of packetMetrics.filter(record => record.value !== 0)) {
      timeline.push({
        timestamp: metric.timestamp,
        category: 'packet-metric',
        action: metric.category,
        artifact: metric.artifact,
        details: {
          path: metric.path,
          name: metric.name,
          value: metric.value,
          labels: metric.labels
        }
      })
      if (metric.category === 'drop' || metric.category === 'error') {
        addEvidence(evidence, 'timeoutOrPacketLossLikely', {
          artifact: metric.artifact,
          reason: `pktmon ${metric.category} counter is non-zero`,
          match: `${metric.path}=${metric.value}`
        })
      }
    }

    if (/tcp|pktmon-trace/i.test(artifact.name)) {
      const tcp = extractTcpHealthRecords(artifact.name, text, artifact.mtimeMs || generatedAt)
      tcpHealthRecords.push(...tcp)
      for (const record of tcp) {
        if (record.reason === 'reset-observed') {
          appEvents.push({
            timestamp: record.timestamp,
            source: 'traffic-forensics',
            event: 'tcp-reset-signal',
            details: {
              artifact: record.artifact,
              match: record.match
            }
          })
          addEvidence(evidence, 'remoteResetLikely', {
            artifact: artifact.name,
            reason: record.reason,
            match: record.match
          })
        }
        if (record.reason === 'timeout-or-retransmit-observed') {
          appEvents.push({
            timestamp: record.timestamp,
            source: 'traffic-forensics',
            event: 'tcp-loss-signal',
            details: {
              artifact: record.artifact,
              match: record.match
            }
          })
          addEvidence(evidence, 'timeoutOrPacketLossLikely', {
            artifact: artifact.name,
            reason: record.reason,
            match: record.match
          })
        }
        if (record.reason === 'mtu-or-fragmentation-observed') {
          appEvents.push({
            timestamp: record.timestamp,
            source: 'traffic-forensics',
            event: 'mtu-fragmentation-signal',
            details: {
              artifact: record.artifact,
              match: record.match
            }
          })
          addEvidence(evidence, 'mtuIssueLikely', {
            artifact: artifact.name,
            reason: record.reason,
            match: record.match
          })
        }
      }
    }
  }

  const dnsIndex = buildDnsIndex(dnsRecords)
  for (const artifact of files) {
    if (!/nettcp|netudp/i.test(artifact.name)) continue
    const text = await readTextIfExists(join(manifest.sessionDir, artifact.name))
    if (!text) continue
    flowRecords = [
      ...flowRecords,
      ...extractFlowRecords(artifact.name, text, artifact.mtimeMs || generatedAt, dnsIndex)
    ]
  }

  flowRecords = Array.from(new Map(flowRecords.map(flow => [flow.id, flow])).values())
  correlateRecordsToFlows(flowRecords, dnsRecords, dropRecords, tcpHealthRecords, evidence)

  if (manifest.engine && artifactNames.has(manifest.engine === 'pktmon' ? 'pktmon.etl' : 'netsh-trace.etl')) {
    addEvidence(evidence, 'tunPathConfirmed', {
      artifact: manifest.engine === 'pktmon' ? 'pktmon.etl' : 'netsh-trace.etl',
      reason: `${manifest.engine} capture artifact exists`
    })
  }

  const verdictKeys: SummaryVerdictKey[] = [
    'trafficLeakDetected',
    'dnsLeakDetected',
    'tunPathConfirmed',
    'killSwitchBlockedTraffic',
    'windowsFirewallBlockedTraffic',
    'remoteResetLikely',
    'localResetLikely',
    'timeoutOrPacketLossLikely',
    'mtuIssueLikely',
    'singBoxFailureLikely',
    'insufficientEvidence'
  ]
  const verdicts = Object.fromEntries(verdictKeys.map(key => [key, Boolean(evidence[key]?.length)])) as Record<SummaryVerdictKey, boolean>
  verdicts.localResetLikely = false
  verdicts.insufficientEvidence = Object.values(verdicts).every(value => value === false) || parserErrors.length > 0

  const routeSnapshots = {
    generatedAt,
    artifacts: files
      .filter(file => /route|interface|adapter|dns-client|ipconfig/i.test(file.name))
      .map(file => ({
        name: file.name,
        size: file.size,
        mtimeMs: file.mtimeMs
      }))
  }

  timeline.sort((a, b) => a.timestamp - b.timestamp)
  appEvents.sort((a, b) => a.timestamp - b.timestamp)

  await writeNdjson(join(manifest.sessionDir, 'timeline.ndjson'), timeline)
  await writeNdjson(join(manifest.sessionDir, 'dns.ndjson'), dnsRecords)
  await writeNdjson(join(manifest.sessionDir, 'drops.ndjson'), dropRecords)
  await writeNdjson(join(manifest.sessionDir, 'tcp-health.ndjson'), tcpHealthRecords)
  await writeNdjson(join(manifest.sessionDir, 'packet-metrics.ndjson'), packetMetricRecords)
  await writeNdjson(join(manifest.sessionDir, 'flows.ndjson'), flowRecords)
  await writeNdjson(join(manifest.sessionDir, 'app-events.ndjson'), appEvents)
  await writeJson(join(manifest.sessionDir, 'route-snapshots.json'), routeSnapshots)

  const summaryPath = join(manifest.sessionDir, 'summary.json')
  await writeJson(summaryPath, {
    schemaVersion: SUMMARY_SCHEMA_VERSION,
    generatedAt,
    sessionId: manifest.sessionId,
    mode: manifest.mode,
    target: manifest.target,
    engine: manifest.engine,
    verdicts,
    evidence,
    counts: {
      artifacts: files.length,
      timelineEvents: timeline.length,
      appEvents: appEvents.length,
      flows: flowRecords.length,
      dnsRecords: dnsRecords.length,
      dropRecords: dropRecords.length,
      tcpHealthRecords: tcpHealthRecords.length,
      packetMetrics: packetMetricRecords.length,
      sidecarEvents: sidecarEventCount,
      parserErrors: parserErrors.length
    },
    parserErrors
  })

  return {
    ...manifest,
    normalizedArtifacts: NORMALIZED_ARTIFACTS,
    summaryPath,
    summaryGeneratedAt: generatedAt,
    parserErrors
  }
}
