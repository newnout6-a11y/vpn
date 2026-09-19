import { BrowserWindow } from 'electron'
import Store from 'electron-store'
import { randomUUID } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { EventEmitter } from 'node:events'
import { isIP } from 'node:net'
import { getDomain } from 'tldts'

const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000
const FAILURE_TTL_MS = 24 * 60 * 60 * 1000
const MAX_CACHE_ENTRIES = 1000
const MAX_CONCURRENT_REQUESTS = 2
// Keep background lookups bounded, but refill the queue after every result.
const MAX_PENDING_JOBS = 8
const REQUEST_TIMEOUT_MS = 8000

export interface DomainEnrichment {
  status: 'pending' | 'ready' | 'unavailable'
  source: 'website'
  siteName: string | null
  title: string | null
  description: string | null
  canonicalUrl: string | null
  faviconUrl: string | null
  fetchedAt: number
}

interface DomainEnrichmentStore {
  entries: Record<string, DomainEnrichment>
}

interface EnrichmentJob {
  domain: string
  proxyRules: string
}

interface PageMetadata {
  finalUrl: string
  siteName: string
  title: string
  description: string
  canonicalUrl: string
  faviconUrl: string
}

const cacheStore = new Store<DomainEnrichmentStore>({
  name: 'domain-intelligence',
  defaults: { entries: {} }
})

function cleanText(value: unknown, maxLength: number): string | null {
  if (typeof value !== 'string') return null
  const clean = value.replace(/\s+/g, ' ').trim()
  return clean ? clean.slice(0, maxLength) : null
}

export function normalizeEnrichmentDomain(input: string): string | null {
  const raw = input.trim().replace(/\.$/, '')
  if (!raw || raw.includes('/') || raw.includes('@')) return null

  try {
    const hostname = new URL(`https://${raw}`).hostname.toLowerCase()
    if (
      !hostname.includes('.') ||
      isIP(hostname) !== 0 ||
      hostname === 'localhost' ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal') ||
      hostname.endsWith('.lan')
    ) {
      return null
    }
    return hostname
  } catch {
    return null
  }
}

export function registrableEnrichmentDomain(input: string): string | null {
  const hostname = normalizeEnrichmentDomain(input)
  if (!hostname) return null
  return getDomain(hostname, { allowPrivateDomains: true }) ?? hostname
}

export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = rawIp.trim().toLowerCase()
  if (!ip) return true

  // Handle IPv4-mapped IPv6 addresses (::ffff:127.0.0.1)
  if (ip.startsWith('::ffff:')) {
    const rest = ip.slice(7)
    if (rest.includes('.')) {
      return isPrivateOrReservedIp(rest)
    }
  }

  const kind = isIP(ip)
  if (kind === 4) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255)) {
      return true
    }
    const [b0, b1, b2] = parts

    // 0.0.0.0/8 (Current network)
    if (b0 === 0) return true

    // 10.0.0.0/8 (Private-Use RFC 1918)
    if (b0 === 10) return true

    // 100.64.0.0/10 (Shared Address Space / CGNAT RFC 6598: 100.64.0.0 - 100.127.255.255)
    if (b0 === 100 && b1 >= 64 && b1 <= 127) return true

    // 127.0.0.0/8 (Loopback RFC 1122)
    if (b0 === 127) return true

    // 169.254.0.0/16 (Link Local RFC 3927, includes cloud metadata 169.254.169.254)
    if (b0 === 169 && b1 === 254) return true

    // 172.16.0.0/12 (Private-Use RFC 1918: 172.16.0.0 - 172.31.255.255)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true

    // 192.0.0.0/24 (IETF Protocol Assignments)
    if (b0 === 192 && b1 === 0 && b2 === 0) return true

    // 192.0.2.0/24 (TEST-NET-1)
    if (b0 === 192 && b1 === 0 && b2 === 2) return true

    // 192.168.0.0/16 (Private-Use RFC 1918)
    if (b0 === 192 && b1 === 168) return true

    // 198.18.0.0/15 (Benchmark RFC 2544: 198.18.0.0 - 198.19.255.255)
    if (b0 === 198 && (b1 === 18 || b1 === 19)) return true

    // 198.51.100.0/24 (TEST-NET-2)
    if (b0 === 198 && b1 === 51 && b2 === 100) return true

    // 203.0.113.0/24 (TEST-NET-3)
    if (b0 === 203 && b1 === 0 && b2 === 113) return true

    // 224.0.0.0/4 (Multicast RFC 5771: 224.0.0.0 - 239.255.255.255)
    if (b0 >= 224 && b0 <= 239) return true

    // 240.0.0.0/4 (Reserved RFC 1112) and 255.255.255.255 (Broadcast)
    if (b0 >= 240) return true

    return false
  }

  if (kind === 6) {
    // Loopback & unspecified: ::1, ::
    if (ip === '::1' || ip === '::' || ip === '0:0:0:0:0:0:0:1' || ip === '0:0:0:0:0:0:0:0') {
      return true
    }

    // Unique Local Addresses (fc00::/7 -> fc00:: - fdff::)
    if (/^f[cd][0-9a-f]{2}:/i.test(ip)) return true

    // Link-Local Unicast (fe80::/10 -> fe80:: - febf::)
    if (/^fe[89ab][0-9a-f]:/i.test(ip)) return true

    // Multicast (ff00::/8)
    if (/^ff[0-9a-f]{2}:/i.test(ip)) return true

    // Documentation (2001:db8::/32)
    if (/^2001:0?db8:/i.test(ip)) return true

    // Discard prefix (100::/64)
    if (/^(0?100::|0?100:0:)/i.test(ip)) return true

    return false
  }

  return true
}

export async function resolveAllDomainIps(hostname: string): Promise<string[]> {
  try {
    const results = await lookup(hostname, { all: true, verbatim: true })
    return results.map((r) => r.address)
  } catch {
    return []
  }
}

export async function isSafePublicDomain(
  domain: string,
  resolver: (hostname: string) => Promise<string[]> = resolveAllDomainIps
): Promise<boolean> {
  const normalized = normalizeEnrichmentDomain(domain)
  if (!normalized) return false

  try {
    const ips = await resolver(normalized)
    if (!ips || ips.length === 0) return false

    for (const ip of ips) {
      if (isPrivateOrReservedIp(ip)) {
        return false
      }
    }
    return true
  } catch {
    return false
  }
}

export function isAllowedMetadataUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return (
      url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      (!url.port || url.port === '443') &&
      normalizeEnrichmentDomain(url.hostname) !== null
    )
  } catch {
    return false
  }
}

export function buildEnrichmentProxyRules(
  address: string | null | undefined,
  type: 'socks5' | 'http'
): string | null {
  if (!address?.trim()) return null

  try {
    const supplied = address.trim()
    const url = new URL(supplied.includes('://') ? supplied : `${type}://${supplied}`)
    const expectedProtocol = `${type}:`
    if (
      url.protocol !== expectedProtocol ||
      !url.hostname ||
      !url.port ||
      url.username ||
      url.password ||
      (url.pathname && url.pathname !== '/') ||
      url.search ||
      url.hash
    ) {
      return null
    }
    return `${type}://${url.host}`
  } catch {
    return null
  }
}

export function sanitizePageMetadata(value: PageMetadata): Omit<DomainEnrichment, 'status' | 'source' | 'fetchedAt'> {
  const finalUrl = isAllowedMetadataUrl(value.finalUrl) ? value.finalUrl : null
  const canonicalUrl = isAllowedMetadataUrl(value.canonicalUrl) ? value.canonicalUrl : null
  const faviconUrl = isAllowedMetadataUrl(value.faviconUrl) ? value.faviconUrl : null
  const siteName = cleanText(value.siteName, 120)
  const title = cleanText(value.title, 180)
  const description = cleanText(value.description, 360)

  return {
    siteName: siteName ?? title,
    title,
    description,
    canonicalUrl: canonicalUrl ?? finalUrl,
    faviconUrl
  }
}

export async function inspectWebsite(
  domain: string,
  proxyRules: string,
  windows: Set<BrowserWindow>,
  resolver: (hostname: string) => Promise<string[]> = resolveAllDomainIps
): Promise<PageMetadata | null> {
  const requestedUrl = `https://${domain}`
  if (!isAllowedMetadataUrl(requestedUrl)) return null

  // Ensure initial domain resolves strictly to public, non-reserved IPs
  const isInitialSafe = await isSafePublicDomain(domain, resolver)
  if (!isInitialSafe) return null

  const safeDomains = new Set<string>([domain.toLowerCase()])

  return new Promise((resolve) => {
    const win = new BrowserWindow({
      show: false,
      webPreferences: {
        offscreen: true,
        partition: `domain-intelligence-${randomUUID()}`,
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webSecurity: true
      }
    })
    windows.add(win)
    win.webContents.setUserAgent('VPN Tunnel Enforcer Domain Intelligence/1.0')
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))

    const session = win.webContents.session
    session.webRequest.onBeforeRequest({ urls: ['*://*/*'] }, (details, callback) => {
      const isDocument = details.resourceType === 'mainFrame'
      if (!isDocument || !isAllowedMetadataUrl(details.url)) {
        callback({ cancel: true })
        return
      }
      try {
        const host = new URL(details.url).hostname.toLowerCase()
        if (!safeDomains.has(host)) {
          callback({ cancel: true })
          return
        }
      } catch {
        callback({ cancel: true })
        return
      }
      callback({ cancel: false })
    })

    let settled = false
    let redirects = 0
    const finish = (result: PageMetadata | null) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      windows.delete(win)
      try { if (!win.isDestroyed()) win.destroy() } catch { /* ignored */ }
      resolve(result)
    }
    const timeout = setTimeout(() => finish(null), REQUEST_TIMEOUT_MS)

    const blockUnsafeNavigation = (event: Electron.Event, url: string) => {
      if (!isAllowedMetadataUrl(url) || ++redirects > 4) {
        event.preventDefault()
        finish(null)
        return
      }
      try {
        const targetHost = new URL(url).hostname.toLowerCase()
        if (safeDomains.has(targetHost)) return

        event.preventDefault()
        void (async () => {
          const safe = await isSafePublicDomain(targetHost, resolver)
          if (safe && !settled) {
            safeDomains.add(targetHost)
            void win.loadURL(url).catch(() => finish(null))
          } else {
            finish(null)
          }
        })()
      } catch {
        event.preventDefault()
        finish(null)
      }
    }
    win.webContents.on('will-navigate', blockUnsafeNavigation)
    win.webContents.on('will-redirect', blockUnsafeNavigation)
    win.webContents.on('did-fail-load', (_event, errorCode, _description, _url, isMainFrame) => {
      if (isMainFrame && errorCode !== -3) finish(null)
    })
    win.webContents.on('did-finish-load', () => {
      void (async () => {
        try {
          const data = await win.webContents.executeJavaScript(`(() => {
            const content = (selector) => document.querySelector(selector)?.getAttribute('content') || ''
            const href = (selector) => document.querySelector(selector)?.href || ''
            return {
              finalUrl: location.href,
              siteName: content('meta[property="og:site_name"]'),
              title: content('meta[property="og:title"]') || document.title || '',
              description: content('meta[property="og:description"]') || content('meta[name="description"]'),
              canonicalUrl: href('link[rel="canonical"]'),
              faviconUrl: href('link[rel~="icon"]')
            }
          })()`)
          finish(data as PageMetadata)
        } catch {
          finish(null)
        }
      })()
    })

    void session
      .setProxy({ proxyRules })
      .then(() => win.loadURL(requestedUrl))
      .catch(() => finish(null))
  })
}

class DomainEnrichmentService {
  private events = new EventEmitter()
  private queue: EnrichmentJob[] = []
  private pending = new Set<string>()
  private windows = new Set<BrowserWindow>()
  private active = 0
  private generation = 0

  get(domain: string): DomainEnrichment | undefined {
    const key = registrableEnrichmentDomain(domain)
    if (!key) return undefined
    if (this.pending.has(key)) {
      return {
        status: 'pending',
        source: 'website',
        siteName: null,
        title: null,
        description: null,
        canonicalUrl: null,
        faviconUrl: null,
        fetchedAt: Date.now()
      }
    }

    const entry = cacheStore.get('entries')[key]
    if (!entry) return undefined
    const ttl = entry.status === 'ready' ? CACHE_TTL_MS : FAILURE_TTL_MS
    return Date.now() - entry.fetchedAt < ttl ? entry : undefined
  }

  queueDomains(domains: string[], proxyRules: string): void {
    const capacity = MAX_PENDING_JOBS - this.pending.size
    if (capacity <= 0) return

    let queued = 0
    for (const domain of domains) {
      if (queued >= capacity) break
      const key = registrableEnrichmentDomain(domain)
      if (!key || this.pending.has(key) || this.get(key)) continue
      this.pending.add(key)
      this.queue.push({ domain: key, proxyRules })
      queued++
    }
    this.drain()
  }

  setEnabled(enabled: boolean): void {
    if (enabled) return
    this.generation++
    this.queue = []
    this.pending.clear()
    for (const win of this.windows) {
      try { if (!win.isDestroyed()) win.destroy() } catch { /* ignored */ }
    }
    this.windows.clear()
  }

  clear(): void {
    this.setEnabled(false)
    cacheStore.set('entries', {})
    this.events.emit('updated')
  }

  onUpdate(listener: () => void): () => void {
    this.events.on('updated', listener)
    return () => this.events.off('updated', listener)
  }

  private drain(): void {
    while (this.active < MAX_CONCURRENT_REQUESTS && this.queue.length > 0) {
      const job = this.queue.shift()
      if (!job) return
      this.active++
      const generation = this.generation
      void this.run(job, generation).finally(() => {
        this.active--
        this.drain()
      })
    }
  }

  private async run(job: EnrichmentJob, generation: number): Promise<void> {
    try {
      const page = await inspectWebsite(job.domain, job.proxyRules, this.windows)
      if (generation !== this.generation) return
      const now = Date.now()
      const metadata = page ? sanitizePageMetadata(page) : null
      const hasMetadata = Boolean(metadata?.siteName || metadata?.title || metadata?.description)
      const entry: DomainEnrichment = hasMetadata && metadata
        ? { status: 'ready', source: 'website', fetchedAt: now, ...metadata }
        : {
            status: 'unavailable',
            source: 'website',
            siteName: null,
            title: null,
            description: null,
            canonicalUrl: null,
            faviconUrl: null,
            fetchedAt: now
          }
      this.save(job.domain, entry)
    } finally {
      this.pending.delete(job.domain)
    }
  }

  private save(domain: string, entry: DomainEnrichment): void {
    const entries = { ...cacheStore.get('entries'), [domain]: entry }
    const kept = Object.entries(entries)
      .sort(([, a], [, b]) => b.fetchedAt - a.fetchedAt)
      .slice(0, MAX_CACHE_ENTRIES)
    cacheStore.set('entries', Object.fromEntries(kept))
    this.events.emit('updated')
  }
}

export const domainEnrichmentService = new DomainEnrichmentService()
