/**
 * Traffic History Service — parses sing-box logs to extract a list of
 * domains the user accessed while VPN was active.
 *
 * Sing-box logs entries like:
 *   2026/05/16 12:34:56 INFO [N] inbound/tun-in: connection from 10.x.x.x to api.example.com:443
 *   2026/05/16 12:34:57 INFO [N] dns: lookup example.com -> 1.2.3.4
 *
 * We tail the log file, grep for these patterns, and aggregate by domain.
 */

import { ipcMain, app, BrowserWindow } from 'electron'
import { open, stat } from 'fs/promises'
import { join } from 'path'
import { logEvent } from './appLogger'
import { domainEnrichmentService, buildEnrichmentProxyRules, type DomainEnrichment } from './domainEnrichment'
import { settingsStore } from './settings'
import { tunController } from './tunController'

export interface TrafficHistoryEntry {
  domain: string
  firstSeen: number
  lastSeen: number
  count: number
  // The user's public IP at the time of the session (best-effort)
  vpnIp: string | null
  enrichment?: DomainEnrichment
}

export interface TrafficHistorySession {
  startedAt: number
  endedAt: number | null
  vpnIp: string | null
  domains: TrafficHistoryEntry[]
}

type ParsedTrafficHistoryEntry = Omit<TrafficHistoryEntry, 'vpnIp' | 'enrichment'>

interface CachedLog {
  mtimeMs: number
  // Byte offset successfully consumed from the file. This lets polling read
  // only appended log data instead of reparsing the whole file.
  size: number
  entries: Map<string, ParsedTrafficHistoryEntry>
  trailingFragment: string
  discardUntilNewline: boolean
}

const MAX_LOG_READ_BYTES = 1024 * 1024
const MAX_TRAILING_FRAGMENT_BYTES = 64 * 1024

const DOMAIN_PATTERN = '([a-zA-Z0-9_][a-zA-Z0-9_.-]*\\.[a-zA-Z]{2,})'
const LOG_DOMAIN_PATTERNS: readonly RegExp[] = [
  // sing-box 1.13 DNS exchange (request and response)
  new RegExp(`\\bdns:\\s+exchanged?\\s+${DOMAIN_PATTERN}\\b`, 'i'),
  // generic resolver phrases
  new RegExp(`\\b(?:lookup|query)\\s+${DOMAIN_PATTERN}\\b`, 'i'),
  // explicit destination after "to" or in "target=" — the only way to reach
  // a real hostname for an HTTP/TLS connection rather than a resolved IP
  new RegExp(`(?:to|target=)\\s+${DOMAIN_PATTERN}(?::\\d+)?`),
  // SNI / Host: header sniffed by router/inbound
  new RegExp(`\\b(?:sni|host|hostname)[=:]\\s*${DOMAIN_PATTERN}\\b`, 'i')
]
const IP_ONLY_DOMAIN_PATTERN = /^[\d.]+$/
const LOCAL_DOMAIN_PATTERN = /^localhost$|\.local$|\.internal$|\.lan$/i
const REVERSE_DNS_DOMAIN_PATTERN = /\.in-addr\.arpa$|\.ip6\.arpa$/i
const SERVICE_DISCOVERY_DOMAIN_PATTERN = /(^|\.)_/
const LOG_TIMESTAMP_PATTERN = /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/

const logCache = new Map<string, CachedLog>()
let enrichmentUpdateRegistered = false
let backgroundEnrichmentTimer: ReturnType<typeof setInterval> | null = null
let backgroundEnrichmentInFlight = false

function getSingboxLogPath(): string {
  return join(app.getPath('userData'), 'tun-runtime', 'sing-box.log')
}

function getPrevSingboxLogPath(): string {
  return join(app.getPath('userData'), 'tun-runtime', 'sing-box.prev.log')
}

/**
 * Parse a single sing-box log line. Returns the domain if found, otherwise null.
 *
 * Sing-box 1.13 log format examples (lines below are real samples from a debug
 * level log on a TUN run):
 *   "+0300 2026-05-16 12:34:56 INFO [123 0ms] inbound/tun-in[connection]: connection from 10.x.x.x:port to example.com:443"
 *   "+0300 2026-05-16 12:34:56 DEBUG [124 0ms] dns: exchange example.com. IN A"
 *   "+0300 2026-05-16 12:34:56 DEBUG [124 873ms] dns: exchanged example.com NOERROR 20"
 *
 * Older / generic shapes also handled:
 *   "lookup example.com -> A 1.2.3.4"
 *   "query example.com"
 *   "outbound connection to example.com:443"
 */
export function parseSingboxLogLine(line: string): { domain: string; timestamp: number } | null {
  if (!line || typeof line !== 'string') return null



  let domain: string | null = null
  for (const rx of LOG_DOMAIN_PATTERNS) {
    const match = rx.exec(line)
    if (match) {
      domain = match[1]
      break
    }
  }

  if (!domain) return null

  // Strip trailing dot from FQDNs (sing-box logs often include it).
  domain = domain.replace(/\.+$/, '')

  // Filter out IP-only "domains" (from earlier regex match on IPs).
  // Real domain has at least one letter in the TLD.
  if (IP_ONLY_DOMAIN_PATTERN.test(domain)) return null
  // Filter out localhost and reserved
  if (LOCAL_DOMAIN_PATTERN.test(domain)) return null
  // Filter out reverse-DNS queries — they're noise, not browsing data.
  if (REVERSE_DNS_DOMAIN_PATTERN.test(domain)) return null
  // Filter out service-discovery / AD names (`_ldap._tcp.dc._msdcs.foo.bar`)
  // since they pollute the list and aren't user-visible navigation.
  if (SERVICE_DISCOVERY_DOMAIN_PATTERN.test(domain)) return null

  // Try to parse timestamp from line start
  const tsMatch = LOG_TIMESTAMP_PATTERN.exec(line)
  let timestamp = Date.now()
  if (tsMatch) {
    const parsed = Date.parse(tsMatch[1].replace(' ', 'T') + 'Z')
    if (!isNaN(parsed)) timestamp = parsed
  }

  return { domain: domain.toLowerCase(), timestamp }
}

/**
 * Read and parse the sing-box log to extract domain access entries.
 * Aggregates by domain — first/last seen, count.
 */
async function readLogSlice(path: string, offset: number, length: number): Promise<{ content: string; bytesRead: number }> {
  const handle = await open(path, 'r')
  try {
    const buffer = Buffer.allocUnsafe(length)
    const { bytesRead } = await handle.read(buffer, 0, length, offset)
    return { content: buffer.subarray(0, bytesRead).toString('utf8'), bytesRead }
  } finally {
    await handle.close()
  }
}

function updateEntries(cache: CachedLog, lines: string): void {
  for (const line of lines.split('\n')) {
    const parsed = parseSingboxLogLine(line)
    if (!parsed) continue

    const existing = cache.entries.get(parsed.domain)
    if (existing) {
      existing.count++
      existing.lastSeen = parsed.timestamp
      continue
    }
    cache.entries.set(parsed.domain, {
      domain: parsed.domain,
      firstSeen: parsed.timestamp,
      lastSeen: parsed.timestamp,
      count: 1
    })
  }
}

function appendLogChunk(cache: CachedLog, content: string, discardLeadingFragment: boolean): void {
  let chunk = cache.trailingFragment + content
  cache.trailingFragment = ''

  if (discardLeadingFragment || cache.discardUntilNewline) {
    const newline = chunk.indexOf('\n')
    if (newline === -1) {
      cache.discardUntilNewline = true
      return
    }
    chunk = chunk.slice(newline + 1)
    cache.discardUntilNewline = false
  }

  const lastNewline = chunk.lastIndexOf('\n')
  if (lastNewline === -1) {
    if (chunk.length <= MAX_TRAILING_FRAGMENT_BYTES) {
      cache.trailingFragment = chunk
    } else {
      cache.discardUntilNewline = true
    }
    return
  }

  updateEntries(cache, chunk.slice(0, lastNewline))
  const trailingFragment = chunk.slice(lastNewline + 1)
  if (trailingFragment.length <= MAX_TRAILING_FRAGMENT_BYTES) {
    cache.trailingFragment = trailingFragment
  } else {
    cache.discardUntilNewline = true
  }
}

function cachedEntries(cache: CachedLog, vpnIp: string | null): TrafficHistoryEntry[] {
  return Array.from(cache.entries.values())
    .sort((a, b) => b.lastSeen - a.lastSeen)
    .map(entry => ({ ...entry, vpnIp }))
}

async function parseLog(path: string, vpnIp: string | null): Promise<TrafficHistoryEntry[]> {
  let fileInfo
  try {
    fileInfo = await stat(path)
  } catch {
    return []
  }

  let cache = logCache.get(path)
  let reset = !cache ||
    fileInfo.size < cache.size ||
    (fileInfo.size === cache.size && fileInfo.mtimeMs !== cache.mtimeMs)
  let offset = cache?.size ?? 0

  if (reset || fileInfo.size - offset > MAX_LOG_READ_BYTES) {
    reset = true
    offset = Math.max(0, fileInfo.size - MAX_LOG_READ_BYTES)
    cache = {
      mtimeMs: fileInfo.mtimeMs,
      size: offset,
      entries: new Map(),
      trailingFragment: '',
      discardUntilNewline: false
    }
  }

  if (cache && fileInfo.size === cache.size && fileInfo.mtimeMs === cache.mtimeMs) {
    logCache.set(path, cache)
    return cachedEntries(cache, vpnIp)
  }

  try {
    const { content, bytesRead } = await readLogSlice(path, offset, fileInfo.size - offset)
    appendLogChunk(cache!, content, reset && offset > 0)
    cache!.size = offset + bytesRead
    cache!.mtimeMs = fileInfo.mtimeMs
    logCache.set(path, cache!)
    return cachedEntries(cache!, vpnIp)
  } catch (err) {
    logEvent('warn', 'traffic-history', 'failed to read sing-box log', err)
    return []
  }
}

/**
 * Get the current traffic history (combines current and previous sing-box logs).
 */
export async function getTrafficHistory(
  vpnIp: string | null = null,
  scheduleEnrichment = false
): Promise<TrafficHistoryEntry[]> {
  const [current, prev] = await Promise.all([
    parseLog(getSingboxLogPath(), vpnIp),
    parseLog(getPrevSingboxLogPath(), vpnIp)
  ])

  // Merge: if same domain in both, use the latest counts
  const merged = new Map<string, TrafficHistoryEntry>()
  for (const entry of [...prev, ...current]) {
    const existing = merged.get(entry.domain)
    if (existing) {
      existing.count += entry.count
      existing.firstSeen = Math.min(existing.firstSeen, entry.firstSeen)
      existing.lastSeen = Math.max(existing.lastSeen, entry.lastSeen)
    } else {
      merged.set(entry.domain, { ...entry })
    }
  }

  const entries = Array.from(merged.values()).sort((a, b) => b.lastSeen - a.lastSeen)
  const settings = settingsStore.get()
  if (!settings.domainEnrichmentEnabled) return entries

  const status = tunController.getStatus()
  const proxyRules = settings.connectionMode === 'localProxy'
    ? buildEnrichmentProxyRules(status.proxyAddr || settings.proxyOverride, status.proxyType || settings.proxyType)
    : status.running
      ? 'direct://'
      : null
  if (!proxyRules) return entries

  if (scheduleEnrichment) {
    domainEnrichmentService.queueDomains(entries.map(entry => entry.domain), proxyRules)
  }
  return entries.map(entry => ({
    ...entry,
    enrichment: domainEnrichmentService.get(entry.domain)
  }))
}

/** Keep enrichment independent from the Traffic page lifecycle. */
async function refreshBackgroundEnrichment(): Promise<void> {
  const settings = settingsStore.get()
  if (backgroundEnrichmentInFlight || !settings.domainEnrichmentEnabled) return
  const tun = tunController.getStatus()
  if (!tun.running && settings.connectionMode !== 'localProxy') return

  backgroundEnrichmentInFlight = true
  try {
    await getTrafficHistory(null, true)
  } catch (err) {
    logEvent('debug', 'traffic-history', 'background enrichment refresh failed', err)
  } finally {
    backgroundEnrichmentInFlight = false
  }
}

export function startBackgroundTrafficHistory(): void {
  if (backgroundEnrichmentTimer) return
  void refreshBackgroundEnrichment()
  backgroundEnrichmentTimer = setInterval(() => {
    void refreshBackgroundEnrichment()
  }, 15_000)
}

export function stopBackgroundTrafficHistory(): void {
  if (!backgroundEnrichmentTimer) return
  clearInterval(backgroundEnrichmentTimer)
  backgroundEnrichmentTimer = null
}

/**
 * Clear traffic history by truncating the sing-box log files.
 * (We don't actually delete them — they get rotated naturally on next start.)
 */
export async function clearTrafficHistory(): Promise<void> {
  const { writeFile, unlink } = await import('fs/promises')
  for (const path of [getSingboxLogPath(), getPrevSingboxLogPath()]) {
    try {
      // Try to truncate first; if locked (sing-box running), skip
      await writeFile(path, '', 'utf-8').catch(async () => {
        await unlink(path).catch(() => undefined)
      })
    } catch {}
    logCache.delete(path)
  }
  domainEnrichmentService.clear()
  logEvent('info', 'traffic-history', 'traffic history cleared')
}

export function registerTrafficHistoryIpcHandlers(): void {
  ipcMain.handle('traffic-history:list', async (_event, vpnIp?: string, scheduleEnrichment?: boolean) => {
    return getTrafficHistory(vpnIp ?? null, scheduleEnrichment === true)
  })

  ipcMain.handle('traffic-history:clear', async () => {
    await clearTrafficHistory()
    return { success: true }
  })

  if (!enrichmentUpdateRegistered) {
    enrichmentUpdateRegistered = true
    domainEnrichmentService.onUpdate(() => {
      for (const win of BrowserWindow.getAllWindows()) {
        if (!win.isDestroyed()) win.webContents.send('traffic-history:enrichment-updated')
      }
    })
  }

  startBackgroundTrafficHistory()
}
