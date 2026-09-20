import { app } from 'electron'
import { join } from 'path'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs'
import type {
  LiveServerCheck,
  LiveServerCheckHistoryDiff
} from '../shared/ipc-types'

export const MAX_HISTORY_PER_TARGET = 20
const HISTORY_FILE_NAME = 'live-server-checks.json'

/**
 * Strips any sensitive credentials, tokens, or private keys from a check result
 * before it is saved into persistent storage or returned to callers.
 */
export function sanitizeLiveCheckForStorage(check: LiveServerCheck): LiveServerCheck {
  // Deep clone to ensure immutability
  const sanitized: LiveServerCheck = JSON.parse(JSON.stringify(check))

  // Clean evidence in findings: remove any potential secret keys
  if (Array.isArray(sanitized.findings)) {
    for (const finding of sanitized.findings) {
      if (finding.evidence) {
        for (const key of Object.keys(finding.evidence)) {
          const lower = key.toLowerCase()
          if (
            lower.includes('uuid') ||
            lower.includes('secret') ||
            lower.includes('password') ||
            lower.includes('key') ||
            lower.includes('shortid') ||
            lower.includes('token') ||
            lower.includes('uri')
          ) {
            delete finding.evidence[key]
          }
        }
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
    this.history.clear()
    this.loadFromDisk()
    this.initialized = true
  }

  private loadFromDisk(): void {
    const filePath = this.getStoragePath()
    if (!filePath || !existsSync(filePath)) return

    try {
      const raw = readFileSync(filePath, 'utf8')
      const parsed = JSON.parse(raw) as Record<string, LiveServerCheck[]>
      if (parsed && typeof parsed === 'object') {
        for (const [key, items] of Object.entries(parsed)) {
          if (Array.isArray(items)) {
            this.history.set(
              key,
              items.slice(0, MAX_HISTORY_PER_TARGET).map(sanitizeLiveCheckForStorage)
            )
          }
        }
      }
    } catch {
      // Ignore corrupted history file
    }
  }

  private saveToDisk(): void {
    const filePath = this.getStoragePath()
    if (!filePath) return

    try {
      const parentDir = join(filePath, '..')
      if (!existsSync(parentDir)) {
        mkdirSync(parentDir, { recursive: true })
      }
      const data: Record<string, LiveServerCheck[]> = {}
      for (const [key, items] of this.history.entries()) {
        data[key] = items
      }
      writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8')
    } catch {
      // Non-fatal if persistence fails
    }
  }

  private targetKey(profileId?: string, host?: string): string {
    if (profileId) return `profile:${profileId}`
    if (host) return `host:${host.toLowerCase().trim()}`
    return 'global'
  }

  public addCheck(check: LiveServerCheck): void {
    if (!this.initialized) this.init()
    const sanitized = sanitizeLiveCheckForStorage(check)
    const key = this.targetKey(sanitized.profileId, sanitized.host)

    const list = this.history.get(key) || []
    // Prepend newest first
    list.unshift(sanitized)
    if (list.length > MAX_HISTORY_PER_TARGET) {
      list.length = MAX_HISTORY_PER_TARGET
    }
    this.history.set(key, list)
    this.saveToDisk()
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
    }

    const key = this.targetKey(filter.profileId, filter.host)
    return this.history.get(key) || []
  }

  public getPreviousSuccessfulCheck(profileId?: string, host?: string): LiveServerCheck | null {
    const history = this.getHistory({ profileId, host })
    for (const check of history) {
      if (check.reachability?.status === 'ok' || check.dns?.status === 'ok') {
        return check
      }
    }
    return null
  }

  public clearHistory(): void {
    this.history.clear()
    const filePath = this.getStoragePath()
    if (filePath && existsSync(filePath)) {
      try {
        writeFileSync(filePath, JSON.stringify({}), 'utf8')
      } catch {}
    }
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

  const prevPorts = (previous.openPorts || []).filter(p => p.open).map(p => p.port)
  const currPorts = (current.openPorts || []).filter(p => p.open).map(p => p.port)

  const closedPorts = prevPorts.filter(p => !currPorts.includes(p))
  const newOpenPorts = currPorts.filter(p => !prevPorts.includes(p))
  const portsChanged = closedPorts.length > 0 || newOpenPorts.length > 0

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
    newOpenPorts
  }
}
