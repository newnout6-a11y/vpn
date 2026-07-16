import { BrowserWindow } from 'electron'
import Store from 'electron-store'
import { randomUUID } from 'node:crypto'
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

async function inspectWebsite(domain: string, proxyRules: string, windows: Set<BrowserWindow>): Promise<PageMetadata | null> {
  const requestedUrl = `https://${domain}`
  if (!isAllowedMetadataUrl(requestedUrl)) return null

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
      callback({ cancel: !isDocument || !isAllowedMetadataUrl(details.url) })
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
      if (!isAllowedMetadataUrl(url) || ++redirects > 4) event.preventDefault()
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
