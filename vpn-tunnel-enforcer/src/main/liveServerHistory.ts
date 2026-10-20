import { app } from 'electron'
import { join } from 'path'
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, renameSync, rmSync, openSync, closeSync, fsyncSync } from 'fs'
import { createHash, randomUUID } from 'crypto'
import { classifyIpcError, IpcFault } from '../shared/ipc-result'
import { StoreSchemaError } from './storeSchema'
import { logEvent } from './appLogger'
import { ioFailureDetails } from './ioFailureDiagnostics'
import { isStoredLiveCheck } from './liveServerHistorySchema'
import { redactSensitiveText } from './vpnProfiles'
import type {
  LiveServerCheck,
  LiveServerCheckHistoryDiff
} from '../shared/ipc-types'

export const MAX_HISTORY_PER_TARGET = 20
const HISTORY_FILE_NAME = 'live-server-checks.json'
// Plain JSON keeps its target-map layout; v1 adds diagnostic action provenance.
export const LIVE_HISTORY_SCHEMA_VERSION = 1
export const LIVE_HISTORY_MIGRATIONS = [{ id: 'live-history-provenance-v1', from: 0, to: 1 }] as const
type HistoryMigration = typeof LIVE_HISTORY_MIGRATIONS[number] & { checksum: string }
interface DecodedHistory {
  history: Map<string, LiveServerCheck[]>
  valid: boolean
  version?: number
  migration?: HistoryMigration
}

function isHistoryMigration(value: unknown): value is HistoryMigration {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const marker = value as Record<string, unknown>
  return Object.keys(marker).length === 4 && LIVE_HISTORY_MIGRATIONS.some(step =>
    marker.id === step.id && marker.from === step.from && marker.to === step.to)
    && typeof marker.checksum === 'string' && /^[0-9a-f]{64}$/.test(marker.checksum)
}

function assertHistoryVersion(value: unknown): void {
  if (!value || typeof value !== 'object' || !Object.hasOwn(value, 'schemaVersion')) return
  const version = (value as Record<string, unknown>).schemaVersion
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 0) throw new StoreSchemaError('STORE_SCHEMA_INVALID')
  if (version > LIVE_HISTORY_SCHEMA_VERSION) throw new StoreSchemaError('STORE_SCHEMA_FUTURE')
}

/**
 * Strips any sensitive credentials, tokens, or private keys from a check result
 * before it is saved into persistent storage or returned to callers.
 */
export function sanitizeLiveCheckForStorage(check: LiveServerCheck): LiveServerCheck {
  // Preserve structure and booleans (e.g. TLS authorized), redact every text leaf.
  const sanitized: LiveServerCheck = JSON.parse(JSON.stringify(check, (_key, value) =>
    typeof value === 'string'
      ? redactSensitiveText(value.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '[REDACTED_UUID]'))
      : value))
  // These are main-generated receipt/profile identities, not credential UUIDs.
  for (const key of ['id', 'profileId', 'operationKey', 'correlationId'] as const) {
    if (check[key] !== undefined) sanitized[key] = check[key]
  }
  const evidence = [...sanitized.findings.map(finding => finding.evidence), sanitized.handshake?.evidence]
  for (const fields of evidence) {
    if (!fields) continue
    for (const key of Object.keys(fields)) {
      if (/uuid|secret|password|key|short.?id|token|uri|auth|cookie|header/i.test(key)) {
        delete (fields as Record<string, unknown>)[key]
      }
    }
  }
  return sanitized
}

class LiveServerHistoryManager {
  private history: Map<string, LiveServerCheck[]> = new Map()
  private initialized = false
  private storageFilePath: string | null = null

  private getStoragePath(): string | null {
    if (this.storageFilePath) return this.storageFilePath
    try {
      if (app && typeof app.getPath === 'function') {
        const userData = app.getPath('userData')
        this.storageFilePath = join(userData, HISTORY_FILE_NAME)
      }
    } catch {
      // Running in unit test or non-electron environment
    }
    return this.storageFilePath
  }

  public init(customPath?: string): void {
    if (customPath) {
      this.storageFilePath = customPath
    }
    this.initialized = false
    this.history = this.loadFromDisk()
    this.initialized = true
  }

  private read(filePath: string): string | undefined {
    try { return readFileSync(filePath, 'utf8') }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
      throw error
    }
  }

  private decode(raw: string): DecodedHistory {
    let parsed: unknown
    try { parsed = JSON.parse(raw) }
    catch {
      logEvent('error', 'live-server-history', 'history.corrupted', { reason: 'invalid-json' })
      return { history: new Map(), valid: false }
    }
    // Admission precedes corruption repair or any write, including clear().
    assertHistoryVersion(parsed)
    const history = new Map<string, LiveServerCheck[]>()
    let rejectedEntries = 0
    let version: number | undefined, migration: HistoryMigration | undefined
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) rejectedEntries++
    else {
      const root = parsed as Record<string, unknown>
      version = typeof root.schemaVersion === 'number' ? root.schemaVersion : 0
      if (version === 1 && root.migration !== undefined) {
        if (isHistoryMigration(root.migration)) migration = root.migration
        else rejectedEntries++
      }
      for (const [key, items] of Object.entries(root)) {
        if (key === 'schemaVersion') continue
        if (key === 'migration' && version === 1) continue
        if (!Array.isArray(items) || !(key === 'global' || /^(profile|host):.+/.test(key))) { rejectedEntries++; continue }
        const valid: LiveServerCheck[] = []
        for (const item of items) {
          if (isStoredLiveCheck(item) && (key === 'global' || key === this.targetKey(item.profileId, item.host))) valid.push(sanitizeLiveCheckForStorage(item))
          else rejectedEntries++
        }
        history.set(key, valid.slice(0, MAX_HISTORY_PER_TARGET))
      }
    }
    if (rejectedEntries) logEvent('error', 'live-server-history', 'history.corrupted', { reason: 'invalid-schema', rejectedEntries })
    return { history, valid: rejectedEntries === 0, version, migration }
  }

  private loadFromDisk(): Map<string, LiveServerCheck[]> {
    const filePath = this.getStoragePath()
    if (!filePath) return new Map()
    try {
      const raw = this.read(filePath)
      const loaded = raw === undefined ? { history: new Map<string, LiveServerCheck[]>(), valid: false } : this.decode(raw)
      if (!loaded.valid && ![...loaded.history.values()].some(items => items.length)) {
        const backup = this.read(filePath + '.bak')
        if (backup !== undefined) {
          const recovered = this.decode(backup)
          if (recovered.valid) {
            logEvent('warn', 'live-server-history', 'history.recovered', { source: 'backup' })
            return recovered.history
          }
        }
      }
      return loaded.history
    } catch (error) {
      logEvent('error', 'live-server-history', 'history.unavailable', ioFailureDetails(error))
      throw error instanceof StoreSchemaError ? error : new IpcFault(classifyIpcError(error))
    }
  }

  private writeAtomic(filePath: string, content: string, copyFrom?: string): void {
    const temporary = `${filePath}.${randomUUID()}.tmp`
    let created = false
    try {
      const reserved = openSync(temporary, 'wx')
      created = true
      closeSync(reserved)
      if (copyFrom) copyFileSync(copyFrom, temporary)
      else writeFileSync(temporary, content, 'utf8')
      const fd = openSync(temporary, 'r+')
      try { fsyncSync(fd) } finally { closeSync(fd) }
      renameSync(temporary, filePath)
    } finally {
      try { if (created) rmSync(temporary, { force: true }) }
      catch (error) { logEvent('warn', 'live-server-history', 'history.cleanup-failed', ioFailureDetails(error)) }
    }
  }

  private saveToDisk(next: Map<string, LiveServerCheck[]>, clearing = false): void {
    const filePath = this.getStoragePath()
    try {
      if (!filePath) throw new IpcFault('internal')
      // Recheck even after init: a newer app can replace the file while open.
      const raw = this.read(filePath)
      const existing = raw === undefined ? undefined : this.decode(raw)
      // A newer reader may also have left a future-format backup.
      const backup = this.read(filePath + '.bak')
      const backupHistory = backup === undefined ? undefined : this.decode(backup)
      const origin = existing?.version === undefined ? backupHistory : existing
      const originRaw = existing?.version === undefined ? backup : raw
      const migrated = origin?.version === 0 && originRaw !== undefined
      const migration: HistoryMigration | undefined = migrated
        ? { ...LIVE_HISTORY_MIGRATIONS[0], checksum: createHash('sha256').update(originRaw).digest('hex') }
        : origin?.migration
      const parentDir = join(filePath, '..')
      mkdirSync(parentDir, { recursive: true })
      const data: Record<string, LiveServerCheck[] | number | HistoryMigration> = {
        schemaVersion: LIVE_HISTORY_SCHEMA_VERSION, ...(migration ? { migration } : {})
      }
      for (const [key, items] of next.entries()) {
        data[key] = items
      }
      // Never replace a usable backup with the corrupt file we recovered from.
      const content = JSON.stringify(data, null, 2)
      // An explicit clear must not resurrect the deleted rows from backup.
      if (clearing) this.writeAtomic(filePath + '.bak', content)
      else if (existing?.valid) this.writeAtomic(filePath + '.bak', '', filePath)
      this.writeAtomic(filePath, content)
      if (migrated) {
        // The durable marker remains authoritative if an observer fails.
        try { logEvent('info', 'live-server-history', 'history.migrated', migration) } catch { /* Do not undo a committed write. */ }
      }
    } catch (error) {
      logEvent('error', 'live-server-history', 'history.write-failed', ioFailureDetails(error))
      throw error instanceof StoreSchemaError ? error : new IpcFault(classifyIpcError(error))
    }
  }

  private targetKey(profileId?: string, host?: string): string {
    if (profileId) return `profile:${profileId}`
    if (host) return `host:${host.toLowerCase().trim()}`
    return 'global'
  }

  public addCheck(check: LiveServerCheck): void {
    if (!this.initialized) this.init()
    if (!isStoredLiveCheck(check)) throw new IpcFault('validation')
    const sanitized = sanitizeLiveCheckForStorage(check)
    const key = this.targetKey(sanitized.profileId, sanitized.host)

    const next = new Map(this.history)
    next.set(key, [sanitized, ...(this.history.get(key) || [])].slice(0, MAX_HISTORY_PER_TARGET))
    this.saveToDisk(next)
    this.history = next
  }

  public getHistory(filter?: { profileId?: string; host?: string }): LiveServerCheck[] {
    if (!this.initialized) this.init()
    if (!filter || (!filter.profileId && !filter.host)) {
      // Combine all recent checks sorted by finishedAt descending
      const all: LiveServerCheck[] = []
      for (const items of this.history.values()) {
        all.push(...items)
      }
      return all
        .sort((a, b) => new Date(b.finishedAt).getTime() - new Date(a.finishedAt).getTime())
        .slice(0, MAX_HISTORY_PER_TARGET)
        .map(sanitizeLiveCheckForStorage)
    }

    const key = this.targetKey(filter.profileId, filter.host)
    return (this.history.get(key) || []).map(sanitizeLiveCheckForStorage)
  }

  public getPreviousSuccessfulCheck(profileId?: string, host?: string, port?: number): LiveServerCheck | null {
    const history = this.getHistory({ profileId, host })
    for (const check of history) {
      if (check.cancelled || (port !== undefined && check.port !== port)) continue
      if (check.reachability?.status === 'ok' || check.dns?.status === 'ok') {
        return check
      }
    }
    return null
  }

  public clearHistory(): void {
    if (!this.initialized) this.init()
    const next = new Map<string, LiveServerCheck[]>()
    this.saveToDisk(next, true)
    this.history = next
  }
}

export const liveServerHistory = new LiveServerHistoryManager()

/**
 * Computes difference between current check and previous check.
 */
export function computeHistoryDiff(
  current: LiveServerCheck,
  previous: LiveServerCheck | null
): LiveServerCheckHistoryDiff | undefined {
  if (!previous) return undefined

  const currIps = [...(current.dns?.a || []), ...(current.dns?.aaaa || [])].sort()
  const prevIps = [...(previous.dns?.a || []), ...(previous.dns?.aaaa || [])].sort()

  const ipChanged =
    currIps.length > 0 &&
    prevIps.length > 0 &&
    (currIps.length !== prevIps.length || currIps.some((ip, idx) => ip !== prevIps[idx]))

  const prevFingerprint = previous.tls?.fingerprint
  const currFingerprint = current.tls?.fingerprint
  const tlsCertChanged = Boolean(
    prevFingerprint && currFingerprint && prevFingerprint !== currFingerprint
  )

  const prevAsn = previous.asn?.asn
  const currAsn = current.asn?.asn
  const asnChanged = Boolean(prevAsn && currAsn && prevAsn !== currAsn)

  const prevCountry = previous.asn?.country
  const currCountry = current.asn?.country
  const countryChanged = Boolean(
    prevCountry && currCountry && prevCountry.toLowerCase() !== currCountry.toLowerCase()
  )

  const prevAvg = previous.latency?.avg
  const currAvg = current.latency?.avg
  const latencySpike = Boolean(
    prevAvg !== undefined &&
    currAvg !== undefined &&
    currAvg > prevAvg * 1.5 &&
    currAvg - prevAvg > 50
  )

  const currentTestedPorts = new Map((current.openPorts || []).map(p => [p.port, p]))
  const previousTestedPorts = new Map((previous.openPorts || []).map(p => [p.port, p]))

  const closedPorts: number[] = []
  const newOpenPorts: number[] = []

  for (const [port, prevP] of previousTestedPorts.entries()) {
    const currP = currentTestedPorts.get(port)
    if (currP !== undefined) {
      if (prevP.open && currP.state === 'closed') {
        closedPorts.push(port)
      } else if (!prevP.open && currP.open) {
        newOpenPorts.push(port)
      }
    }
  }

  const portsChanged = closedPorts.length > 0 || newOpenPorts.length > 0

  const prevHandshake = previous.handshake?.status
  const currHandshake = current.handshake?.status
  const handshakeChanged = Boolean(prevHandshake && currHandshake && prevHandshake !== currHandshake)

  const prevExit = previous.egress?.exitIpv4
  const currExit = current.egress?.exitIpv4
  const prevExit6 = previous.egress?.exitIpv6
  const currExit6 = current.egress?.exitIpv6
  const egressChanged = Boolean(
    (prevExit && currExit && prevExit !== currExit) ||
    (prevExit6 && currExit6 && prevExit6 !== currExit6)
  )

  const prevPmtuObj = previous.pmtu
  const currPmtuObj = current.pmtu
  const isPmtuComparable = Boolean(
    prevPmtuObj &&
    currPmtuObj &&
    typeof prevPmtuObj.pmtu === 'number' &&
    typeof currPmtuObj.pmtu === 'number' &&
    prevPmtuObj.family === currPmtuObj.family &&
    prevPmtuObj.method === currPmtuObj.method &&
    (!prevPmtuObj.destination || !currPmtuObj.destination || prevPmtuObj.destination === currPmtuObj.destination)
  )
  const prevPmtu = isPmtuComparable ? prevPmtuObj!.pmtu : undefined
  const currPmtu = isPmtuComparable ? currPmtuObj!.pmtu : undefined
  const pmtuChanged = Boolean(isPmtuComparable && prevPmtu !== currPmtu)

  const prevThroughput = previous.throughput?.medianMbps
  const currThroughput = current.throughput?.medianMbps
  const throughputChanged = Boolean(
    prevThroughput !== undefined &&
    currThroughput !== undefined &&
    currThroughput < prevThroughput * 0.65
  )

  return {
    previousStartedAt: previous.startedAt,
    ipChanged,
    previousIps: prevIps,
    currentIps: currIps,
    tlsCertChanged,
    previousTlsFingerprint: prevFingerprint,
    currentTlsFingerprint: currFingerprint,
    asnChanged,
    previousAsn: prevAsn,
    currentAsn: currAsn,
    countryChanged,
    previousCountry: prevCountry,
    currentCountry: currCountry,
    latencySpike,
    previousAvgLatency: prevAvg,
    currentAvgLatency: currAvg,
    portsChanged,
    closedPorts,
    newOpenPorts,
    handshakeChanged,
    previousHandshakeStatus: prevHandshake,
    currentHandshakeStatus: currHandshake,
    egressChanged,
    previousExitIp: prevExit,
    currentExitIp: currExit,
    pmtuChanged,
    previousPmtu: prevPmtu,
    currentPmtu: currPmtu,
    throughputChanged,
    previousMedianThroughput: prevThroughput,
    currentMedianThroughput: currThroughput
  }
}
