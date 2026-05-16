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

import { ipcMain, app } from 'electron'
import { readFile, stat } from 'fs/promises'
import { join } from 'path'
import { logEvent } from './appLogger'

export interface TrafficHistoryEntry {
  domain: string
  firstSeen: number
  lastSeen: number
  count: number
  // The user's public IP at the time of the session (best-effort)
  vpnIp: string | null
}

export interface TrafficHistorySession {
  startedAt: number
  endedAt: number | null
  vpnIp: string | null
  domains: TrafficHistoryEntry[]
}

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

  const domainPattern = '([a-zA-Z0-9_][a-zA-Z0-9_.-]*\\.[a-zA-Z]{2,})'

  // Source patterns ranked by reliability. The first hit wins.
  const patterns: RegExp[] = [
    // sing-box 1.13 DNS exchange (request and response)
    new RegExp(`\\bdns:\\s+exchanged?\\s+${domainPattern}\\b`, 'i'),
    // generic resolver phrases
    new RegExp(`\\b(?:lookup|query)\\s+${domainPattern}\\b`, 'i'),
    // explicit destination after "to" or in "target=" — the only way to reach
    // a real hostname for an HTTP/TLS connection rather than a resolved IP
    new RegExp(`(?:to|target=)\\s+${domainPattern}(?::\\d+)?`),
    // SNI / Host: header sniffed by router/inbound
    new RegExp(`\\b(?:sni|host|hostname)[=:]\\s*${domainPattern}\\b`, 'i')
  ]

  let domain: string | null = null
  for (const rx of patterns) {
    const match = line.match(rx)
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
  if (/^[\d.]+$/.test(domain)) return null
  // Filter out localhost and reserved
  if (/^localhost$|\.local$|\.internal$|\.lan$/i.test(domain)) return null
  // Filter out reverse-DNS queries — they're noise, not browsing data.
  if (/\.in-addr\.arpa$|\.ip6\.arpa$/i.test(domain)) return null
  // Filter out service-discovery / AD names (`_ldap._tcp.dc._msdcs.foo.bar`)
  // since they pollute the list and aren't user-visible navigation.
  if (/(^|\.)_/.test(domain)) return null

  // Try to parse timestamp from line start
  const tsMatch = line.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/)
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
async function parseLog(path: string, vpnIp: string | null): Promise<TrafficHistoryEntry[]> {
  try {
    await stat(path)
  } catch {
    return []
  }

  let content: string
  try {
    content = await readFile(path, 'utf-8')
  } catch (err) {
    logEvent('warn', 'traffic-history', 'failed to read sing-box log', err)
    return []
  }

  const map = new Map<string, TrafficHistoryEntry>()
  const lines = content.split(/\r?\n/)

  for (const line of lines) {
    const parsed = parseSingboxLogLine(line)
    if (!parsed) continue

    const existing = map.get(parsed.domain)
    if (existing) {
      existing.count++
      existing.lastSeen = parsed.timestamp
    } else {
      map.set(parsed.domain, {
        domain: parsed.domain,
        firstSeen: parsed.timestamp,
        lastSeen: parsed.timestamp,
        count: 1,
        vpnIp
      })
    }
  }

  return Array.from(map.values()).sort((a, b) => b.lastSeen - a.lastSeen)
}

/**
 * Get the current traffic history (combines current and previous sing-box logs).
 */
export async function getTrafficHistory(vpnIp: string | null = null): Promise<TrafficHistoryEntry[]> {
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

  return Array.from(merged.values()).sort((a, b) => b.lastSeen - a.lastSeen)
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
  }
  logEvent('info', 'traffic-history', 'traffic history cleared')
}

export function registerTrafficHistoryIpcHandlers(): void {
  ipcMain.handle('traffic-history:list', async (_event, vpnIp?: string) => {
    return getTrafficHistory(vpnIp ?? null)
  })

  ipcMain.handle('traffic-history:clear', async () => {
    await clearTrafficHistory()
    return { success: true }
  })
}
