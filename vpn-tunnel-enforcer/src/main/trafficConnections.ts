/**
 * Traffic Connections Sampler — records the domains the user actually reaches
 * while the tunnel is up.
 *
 * Why this exists: trafficHistory.ts parses the sing-box log, but the log level
 * is pinned to `info` (a deliberate choice — `debug` floods the runtime log and
 * the renderer re-parses it). At `info`, sing-box 1.13 logs only its OWN named
 * dials — the DoH resolver (`cloudflare-dns.com`) and the proxy server
 * (`no.savethis.cloud`) — never the per-request DNS lookups (those are `debug`)
 * nor the real destination of tunnelled flows (they arrive as already-resolved
 * IP packets; the sniffed SNI only appears in `debug`). So the log alone yields
 * ~2 infrastructure domains and nothing the user recognises.
 *
 * Instead we poll sing-box's Clash API `/connections` (already exposed on
 * 127.0.0.1 with a per-run secret — see tunController `clash_api`). Every live
 * connection carries `metadata.host` = the sniffed domain plus cumulative byte
 * counters. We accumulate unique domains into a persistent electron-store so the
 * history survives a disconnect (the sing-box log is wiped/rotated on stop).
 */

import Store from 'electron-store'
import axios from 'axios'
import { isIP } from 'node:net'
import { logEvent } from './appLogger'

export interface TrafficDomainRecord {
  domain: string
  firstSeen: number
  lastSeen: number
  /** number of distinct connections observed to this domain */
  count: number
  bytesUp: number
  bytesDown: number
}

interface TrafficDomainsStoreSchema {
  domains: Record<string, TrafficDomainRecord>
}

const MAX_DOMAINS = 2000
// 1.5s: the /connections snapshot only lists *currently open* flows, so a faster
// cadence catches more short-lived HTTPS requests before they close. The call is
// a tiny localhost GET and writes are debounced separately (FLUSH_INTERVAL_MS).
const POLL_INTERVAL_MS = 1500
const FLUSH_INTERVAL_MS = 10_000
const CONNECTIONS_TIMEOUT_MS = 4000

const store = new Store<TrafficDomainsStoreSchema>({
  name: 'traffic-domains',
  defaults: { domains: {} }
})

// ─── pure helpers (exported for tests) ───────────────────────────────────────

/**
 * Well-known DoH / DoT resolver hostnames. sing-box dials these directly for its
 * own DNS transport; they are never a site the user "visited". The active VPN
 * server host is added dynamically in getInfraHosts().
 */
export const DOH_INFRA_HOSTS: ReadonlySet<string> = new Set([
  'cloudflare-dns.com',
  'mozilla.cloudflare-dns.com',
  'one.one.one.one',
  'dns.google',
  'dns.google.com',
  'dns.quad9.net',
  'dns9.quad9.net',
  'dns10.quad9.net',
  'dns11.quad9.net',
  'dns.adguard-dns.com',
  'unfiltered.adguard-dns.com',
  'family.adguard-dns.com',
  'doh.opendns.com',
  'dns.nextdns.io',
  'doh.cleanbrowsing.org',
  'security.cloudflare-dns.com',
  'dns.controld.com',
  'freedns.controld.com'
])

const LOCAL_HOST_RX = /^localhost$|\.local$|\.internal$|\.lan$|\.home$|\.arpa$/i
const SERVICE_DISCOVERY_RX = /(^|\.)_/

/** Lowercase, strip a trailing dot, drop a trailing `:port`, unwrap `[ipv6]`. */
export function normalizeHost(raw: string | null | undefined): string | null {
  if (!raw || typeof raw !== 'string') return null
  let host = raw.trim().toLowerCase()
  if (!host) return null
  if (host.startsWith('[')) {
    const close = host.indexOf(']')
    if (close !== -1) host = host.slice(1, close)
  } else {
    const lastColon = host.lastIndexOf(':')
    if (lastColon > 0 && /^\d{1,5}$/.test(host.slice(lastColon + 1))) {
      host = host.slice(0, lastColon)
    }
  }
  host = host.replace(/\.+$/, '')
  return host || null
}

/**
 * Returns the normalised hostname if it should be recorded as a visited domain,
 * or null if it is infrastructure / noise (an IP literal, localhost, a reverse
 * lookup, a DoH resolver, the VPN server itself).
 */
export function shouldRecordHost(
  raw: string | null | undefined,
  infraHosts: ReadonlySet<string> = DOH_INFRA_HOSTS
): string | null {
  const host = normalizeHost(raw)
  if (!host) return null
  if (isIP(host) !== 0) return null
  if (!host.includes('.')) return null
  if (LOCAL_HOST_RX.test(host)) return null
  if (SERVICE_DISCOVERY_RX.test(host)) return null
  if (DOH_INFRA_HOSTS.has(host)) return null
  if (infraHosts.has(host)) return null
  return host
}

interface ClashConnectionMetadata {
  host?: string
  sniffHost?: string
  destinationIP?: string
}
interface ClashConnection {
  id?: string
  metadata?: ClashConnectionMetadata
  upload?: number
  download?: number
}
export interface ClashConnectionsSnapshot {
  connections?: ClashConnection[] | null
}

/** Per-connection bytes already attributed, so re-polls only add the delta. */
export type SamplerSeen = Map<string, { up: number; down: number }>

/**
 * Fold one `/connections` snapshot into the domain map. Mutates `domains` and
 * `seen` in place. A connection id seen for the first time bumps its domain's
 * `count`; repeat sightings only accrue the byte delta. Connections that have
 * dropped out of the snapshot are pruned from `seen`.
 */
export function mergeConnectionSample(
  domains: Record<string, TrafficDomainRecord>,
  snapshot: ClashConnectionsSnapshot | null | undefined,
  seen: SamplerSeen,
  infraHosts: ReadonlySet<string>,
  now: number
): { changed: boolean } {
  let changed = false
  const live = new Set<string>()

  for (const conn of snapshot?.connections ?? []) {
    if (!conn || typeof conn.id !== 'string' || !conn.id) continue
    const host = shouldRecordHost(conn.metadata?.host ?? conn.metadata?.sniffHost, infraHosts)
    if (!host) continue
    live.add(conn.id)

    const up = Number.isFinite(conn.upload) ? Math.max(0, conn.upload as number) : 0
    const down = Number.isFinite(conn.download) ? Math.max(0, conn.download as number) : 0

    let rec = domains[host]
    if (!rec) {
      rec = { domain: host, firstSeen: now, lastSeen: now, count: 0, bytesUp: 0, bytesDown: 0 }
      domains[host] = rec
    }

    const prev = seen.get(conn.id)
    if (!prev) {
      rec.count += 1
      rec.firstSeen = Math.min(rec.firstSeen, now)
      rec.lastSeen = now
      rec.bytesUp += up
      rec.bytesDown += down
      seen.set(conn.id, { up, down })
      changed = true
    } else {
      const dUp = Math.max(0, up - prev.up)
      const dDown = Math.max(0, down - prev.down)
      if (dUp || dDown) {
        rec.bytesUp += dUp
        rec.bytesDown += dDown
        rec.lastSeen = now
        prev.up = up
        prev.down = down
        changed = true
      }
    }
  }

  for (const id of seen.keys()) {
    if (!live.has(id)) seen.delete(id)
  }
  return { changed }
}

/** Trim the map to the `max` most-recently-seen domains. Mutates in place. */
export function pruneDomains(
  domains: Record<string, TrafficDomainRecord>,
  max: number = MAX_DOMAINS
): Record<string, TrafficDomainRecord> {
  const keys = Object.keys(domains)
  if (keys.length <= max) return domains
  keys.sort((a, b) => domains[a].lastSeen - domains[b].lastSeen)
  for (const k of keys.slice(0, keys.length - max)) delete domains[k]
  return domains
}

// ─── infra host set ─────────────────────────────────────────────────────────

let infraHostsCache: { at: number; set: ReadonlySet<string> } | null = null
const INFRA_HOSTS_TTL_MS = 30_000

/**
 * DoH resolvers + every configured VPN server host. Lazy-requires serverPicker
 * to avoid a load-order cycle (serverPicker → … → trafficConnections). Cached
 * for a short TTL — it is consulted on every poll and every history read.
 */
export function getInfraHosts(): ReadonlySet<string> {
  const now = Date.now()
  if (infraHostsCache && now - infraHostsCache.at < INFRA_HOSTS_TTL_MS) {
    return infraHostsCache.set
  }
  const hosts = new Set(DOH_INFRA_HOSTS)
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { serverPicker } = require('./serverPicker') as typeof import('./serverPicker')
    for (const profile of serverPicker.getProfiles()) {
      const host = normalizeHost(profile?.server)
      if (host) hosts.add(host)
    }
  } catch (err) {
    logEvent('debug', 'traffic-history', 'getInfraHosts: serverPicker unavailable', {
      error: (err as Error)?.message
    })
  }
  infraHostsCache = { at: now, set: hosts }
  return hosts
}

// ─── runtime ────────────────────────────────────────────────────────────────

let pollTimer: ReturnType<typeof setInterval> | null = null
let seen: SamplerSeen = new Map()
let working: Record<string, TrafficDomainRecord> | null = null
let lastFlush = 0
let polling = false

function loadWorking(): Record<string, TrafficDomainRecord> {
  if (!working) working = { ...store.get('domains') }
  return working
}

function flush(force: boolean): void {
  if (!working) return
  const now = Date.now()
  if (!force && now - lastFlush < FLUSH_INTERVAL_MS) return
  pruneDomains(working, MAX_DOMAINS)
  try {
    store.set('domains', working)
    lastFlush = now
  } catch (err) {
    logEvent('warn', 'traffic-history', 'failed to persist traffic domains', {
      error: (err as Error)?.message
    })
  }
}

async function pollOnce(): Promise<void> {
  if (polling) return
  let info: { port: number; secret: string } | null = null
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    info = (require('./tunController') as typeof import('./tunController')).getClashApiInfo()
  } catch {
    return
  }
  if (!info) return

  polling = true
  try {
    const resp = await axios.get<ClashConnectionsSnapshot>(
      `http://127.0.0.1:${info.port}/connections`,
      {
        headers: { Authorization: `Bearer ${info.secret}` },
        timeout: CONNECTIONS_TIMEOUT_MS,
        // Never route this loopback call through a system/env proxy — the app
        // itself may have set one while the tunnel is up.
        proxy: false,
        validateStatus: () => true
      }
    )
    if (resp.status !== 200 || !resp.data || typeof resp.data !== 'object') return
    const { changed } = mergeConnectionSample(
      loadWorking(),
      resp.data,
      seen,
      getInfraHosts(),
      Date.now()
    )
    if (changed) flush(false)
  } catch (err) {
    logEvent('debug', 'traffic-history', 'clash /connections poll failed', {
      error: (err as Error)?.message
    })
  } finally {
    polling = false
  }
}

export function startTrafficConnectionSampler(): void {
  if (pollTimer) return
  seen = new Map()
  void pollOnce()
  pollTimer = setInterval(() => void pollOnce(), POLL_INTERVAL_MS)
}

export function stopTrafficConnectionSampler(): void {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
  seen.clear()
  flush(true)
}

/** Newest-first snapshot of every recorded domain. */
export function getRecordedTrafficDomains(): TrafficDomainRecord[] {
  const src = working ?? store.get('domains')
  return Object.values(src).sort((a, b) => b.lastSeen - a.lastSeen)
}

export function clearRecordedTrafficDomains(): void {
  working = {}
  seen.clear()
  lastFlush = 0
  try {
    store.set('domains', {})
  } catch (err) {
    logEvent('warn', 'traffic-history', 'failed to clear traffic domains', {
      error: (err as Error)?.message
    })
  }
}
