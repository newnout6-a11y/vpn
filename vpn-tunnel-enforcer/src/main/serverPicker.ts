/**
 * Server Picker Service — profile management, ping measurement, and selection.
 *
 * Responsibilities:
 * - Store and manage server profiles in electron-store
 * - Measure latency (ping) to each server via TCP connection timing
 * - Ping all servers concurrently with a concurrency limit
 * - Parse subscription links (ss://, vmess://, vless://, trojan://) and URLs
 * - Group profiles by protocol
 * - Register IPC handlers for all ServerChannels
 */

import { app, dialog, ipcMain, type IpcMainInvokeEvent } from 'electron'
import { Socket } from 'net'
import { promises as dns } from 'dns'
import { writeFile } from 'fs/promises'
import { join } from 'path'
import axios from 'axios'
import { randomUUID } from 'crypto'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import { resolveVpnProfiles, exportOutboundToUri, type VpnProfile } from './vpnProfiles'
import { settingsStore } from './settings'
import { tunController } from './tunController'
import {
  serverGroups,
  ensureManualKeysGroup,
  findGroupBySourceUrl,
  refreshGroup as refreshSubscriptionGroup
} from './serverGroups'
import type { ServerProfile } from '../shared/ipc-types'

// ─── Persistent Store ────────────────────────────────────────────────────────

interface ServerPickerStore {
  profiles: ServerProfile[]
  activeProfileId: string | null
}

const store = new Store<ServerPickerStore>({
  name: 'server-picker',
  defaults: {
    profiles: [],
    activeProfileId: null
  }
})

// ─── Constants ───────────────────────────────────────────────────────────────

const PING_TIMEOUT_MS = 5000
const PING_CONCURRENCY = 5

// Neutral "is the tunnel responsive" probe targets. Cloudflare's trace
// endpoint returns ~30 bytes of plain text, has no rate limiting, and is
// allow-listed pretty much everywhere — including on Reality fronts that
// would loop on a bare SNI to our own VPN endpoint. gstatic.com/generate_204
// is a backup with the same guarantees but goes through Google.
const TUNNEL_PROBE_URLS = [
  'https://1.1.1.1/cdn-cgi/trace',
  'https://www.gstatic.com/generate_204'
] as const

// Cache the last successful tunnel-probe result for a few seconds. Without
// this, a "Ping all" sweep over N profiles fires N identical HTTP requests
// to the same CDN within milliseconds (since the tunnel itself is the
// bottleneck — every profile would return the same number anyway). The
// cache is intentionally short so the user still sees a fresh number when
// they explicitly click "ping" twice in a row.
const TUNNEL_PROBE_CACHE_MS = 2500
let tunnelProbeCache: { value: number | null; at: number } | null = null

// ─── Ping Measurement ────────────────────────────────────────────────────────

/**
 * Measures latency to a server, with two paths:
 *
 *   1. VPN OFF → plain TCP connect (SYN/SYN-ACK only). Real network RTT.
 *      We deliberately do NOT do a TLS handshake here: that would put the
 *      server_name on the wire in clear text and Russian TSPU / similar
 *      DPI boxes blackhole the IP for several minutes after seeing a
 *      known VPN-front SNI. The Ping button used to literally kill the
 *      user's internet for ~10 minutes.
 *
 *   2. VPN ON → connect, then send one byte and wait for the first kernel
 *      response (data, FIN, or RST). Plain `connect()` returns instantly
 *      when sing-box hijacks the SYN locally, which made every server
 *      look like 1 ms. The first-byte trip happens entirely inside the
 *      already-encrypted vless flow, so DPI sees only the regular
 *      shielded traffic — no extra fingerprint.
 *
 * Returns latency in ms or null if the server is fully unreachable.
 */
export function pingServer(host: string, port: number): Promise<number | null> {
  return tunController.getStatus().running
    ? tunnelHttpProbe()
    : plainTcpPing(host, port)
}

/**
 * Tunnel-aware RTT measurement via HTTPS GET to a neutral CDN.
 *
 * The Node `axios` request goes through the OS kernel network stack,
 * which — with TUN strict_route + auto_route active — is captured by
 * sing-box and dispatched through `proxy-out`. So whatever number this
 * function returns is the real round-trip cost of the *tunnel* (TLS
 * handshake + GET request + response from the CDN), not just a fake
 * "connect" event from sing-box's local SYN hijack.
 *
 * Why we no longer probe `host:port` of the picker entry through the
 * tunnel: when `host` is the active VPN endpoint (the most common case
 * — users ping the server they're connected to), the connection turns
 * into a self-loop. sing-box dispatches the connect via vless to the
 * same upstream IP, vless tries to dial that IP locally, and the chain
 * stalls until our 5 s timeout. Confirmed in user diagnostics: every
 * ping during an active tunnel returned `ms: 5000` followed by
 * `Пинг … не прошёл`.
 *
 * Tries each probe URL in order. Caches the result for a couple of
 * seconds so a `pingAll` sweep over N profiles doesn't fire N parallel
 * requests (the tunnel is the bottleneck — every profile would return
 * the same number anyway).
 */
export async function tunnelHttpProbe(): Promise<number | null> {
  const cached = tunnelProbeCache
  if (cached && Date.now() - cached.at < TUNNEL_PROBE_CACHE_MS) {
    return cached.value
  }

  for (const url of TUNNEL_PROBE_URLS) {
    const start = Date.now()
    try {
      // Any non-5xx = successful round-trip. generate_204 returns 204,
      // the trace endpoint returns 200; both count.
      await axios.get(url, {
        timeout: PING_TIMEOUT_MS,
        validateStatus: status => status < 500,
        // Connection: close so each ping measures a fresh round-trip
        // rather than the warmth of a pooled TLS session.
        headers: { 'Cache-Control': 'no-cache', Connection: 'close' }
      })
      const ms = Date.now() - start
      tunnelProbeCache = { value: ms, at: Date.now() }
      return ms
    } catch {
      // Try the next URL. If both fail, the tunnel is genuinely
      // unreachable (or the user is on a network where both Cloudflare
      // and Google are blocked) — nothing useful to measure either way.
      continue
    }
  }

  tunnelProbeCache = { value: null, at: Date.now() }
  return null
}

function plainTcpPing(host: string, port: number): Promise<number | null> {
  return new Promise((resolve) => {
    const socket = new Socket()
    const start = Date.now()
    let done = false
    const finish = (value: number | null) => {
      if (done) return
      done = true
      socket.removeAllListeners()
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(PING_TIMEOUT_MS)
    socket.once('connect', () => finish(Date.now() - start))
    socket.once('timeout', () => finish(null))
    socket.once('error', () => finish(null))
    socket.connect(port, host)
  })
}

/**
 * Pings all servers concurrently with a concurrency limit.
 * Updates ping/status/lastChecked fields for each profile.
 */
export async function pingAll(): Promise<ServerProfile[]> {
  const profiles = getProfiles()
  const now = Date.now()

  // Process in batches of PING_CONCURRENCY
  for (let i = 0; i < profiles.length; i += PING_CONCURRENCY) {
    const batch = profiles.slice(i, i + PING_CONCURRENCY)
    const results = await Promise.all(
      batch.map((profile) => pingServer(profile.server, profile.port))
    )

    for (let j = 0; j < batch.length; j++) {
      const idx = i + j
      const latency = results[j]
      profiles[idx] = {
        ...profiles[idx],
        ping: latency,
        status: latency !== null ? 'online' : 'offline',
        lastChecked: now
      }
    }
  }

  saveProfiles(profiles)
  return profiles
}

// ─── Geolocation ────────────────────────────────────────────────────────────

const GEOLOCATE_CONCURRENCY = 3
const GEOLOCATE_DELAY_MS = 1100 // ipapi.co allows ~1 req/sec on free tier

/**
 * Resolve a hostname to its first IPv4 address. Returns null on any failure;
 * we don't want geolocation hiccups to throw out of the picker pipeline.
 */
async function resolveHostIp(host: string): Promise<string | null> {
  if (!host) return null
  // Already an IPv4 — skip DNS.
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return host
  try {
    const records = await dns.resolve4(host)
    return records[0] || null
  } catch {
    try {
      const lookup = await dns.lookup(host, { family: 4 })
      return lookup.address || null
    } catch {
      return null
    }
  }
}

/**
 * Look up the country (and ISO-2) for a single IP via ipapi.co. Free tier
 * is rate-limited to ~1k/day with no API key, hence the small delay between
 * sequential lookups in {@link geolocateAll}.
 *
 * Returns null on any failure — caller leaves country empty so the next
 * background pass can retry.
 */
async function fetchCountryForIp(ip: string): Promise<string | null> {
  try {
    const resp = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 6000 })
    if (resp.data && !resp.data.error) {
      const country = (resp.data.country_name || resp.data.country || '').toString().trim()
      return country || null
    }
  } catch {
    // Silent — we'll retry on the next geolocate pass.
  }
  return null
}

/**
 * Background pass that fills in `country` for every picker profile that
 * doesn't have one yet. Idempotent: if all profiles are tagged it returns
 * immediately. Saves to the store as soon as a single lookup completes so
 * the user sees country labels populating live.
 *
 * Why we do this server-side (in main) and not via a client probe:
 *   1. The Servers page already issues ad-hoc probes per row, but the
 *      Dashboard side panel never does — country labels there were always
 *      empty for subscriptions whose names don't include a country word
 *      (e.g. "feodorn LTE 12 | не гарант").
 *   2. Keeping the lookup behind the picker store means every UI that reads
 *      `profile.country` gets the populated value uniformly.
 *
 * Triggered after addFromInput() and on app start.
 */
let geolocateInFlight = false
export async function geolocateAll(opts: { force?: boolean } = {}): Promise<void> {
  if (geolocateInFlight) return
  geolocateInFlight = true
  try {
    const todo = getProfiles().filter(p => opts.force || !p.country)
    if (!todo.length) return

    logEvent('info', 'server-picker', 'geolocate pass started', {
      total: getProfiles().length,
      pending: todo.length,
      force: Boolean(opts.force)
    })

    let updated = 0
    for (let i = 0; i < todo.length; i += GEOLOCATE_CONCURRENCY) {
      const batch = todo.slice(i, i + GEOLOCATE_CONCURRENCY)
      const results = await Promise.all(
        batch.map(async profile => {
          const ip = await resolveHostIp(profile.server)
          if (!ip) return { id: profile.id, country: null as string | null }
          const country = await fetchCountryForIp(ip)
          return { id: profile.id, country }
        })
      )
      // Re-read current store before writing — pingAll/select can mutate
      // concurrently while we're working through the batch.
      const current = getProfiles()
      let dirty = false
      for (const r of results) {
        if (!r.country) continue
        const idx = current.findIndex(p => p.id === r.id)
        if (idx === -1) continue
        if (current[idx].country !== r.country) {
          current[idx] = { ...current[idx], country: r.country }
          dirty = true
          updated++
        }
      }
      if (dirty) saveProfiles(current)

      // Pace to stay under the free-tier limit. The last batch doesn't need
      // to sleep.
      if (i + GEOLOCATE_CONCURRENCY < todo.length) {
        await new Promise(r => setTimeout(r, GEOLOCATE_DELAY_MS))
      }
    }

    logEvent('info', 'server-picker', 'geolocate pass finished', {
      pending: todo.length,
      updated
    })
  } catch (err) {
    logEvent('warn', 'server-picker', 'geolocate pass failed', err)
  } finally {
    geolocateInFlight = false
  }
}

// ─── Profile Management ──────────────────────────────────────────────────────

/**
 * One-time migration from the legacy "directVpnCachedProfiles" stored in
 * settings.json into the server-picker store. Runs only when the picker is
 * empty AND legacy profiles exist, so it is safe to call on every startup.
 *
 * Why: V2 unifies server management around the server-picker store; the
 * Settings page no longer ingests subscriptions. Without this migration,
 * users upgrading from a previous build would see an empty Servers page
 * and have to re-import their subscription manually.
 */
export function migrateLegacyDirectVpnProfiles(): void {
  const existing = getProfiles()
  if (existing.length > 0) return

  const settings = settingsStore.get()
  const legacy = Array.isArray(settings.directVpnCachedProfiles)
    ? settings.directVpnCachedProfiles
    : []
  if (!legacy.length) return

  const migrated: ServerProfile[] = legacy
    .filter((profile: any) => profile && profile.outbound && typeof profile.outbound === 'object')
    .map((profile: any) => ({
      id: randomUUID(),
      name: profile.name || (profile.protocol ? String(profile.protocol).toUpperCase() : 'Profile'),
      protocol: profile.protocol || 'vless',
      server: profile.outbound.server || '',
      port: typeof profile.outbound.server_port === 'number' ? profile.outbound.server_port : 0,
      country: undefined,
      ping: null,
      status: 'unknown' as const,
      lastChecked: undefined,
      outbound: profile.outbound
    }))

  if (!migrated.length) return

  saveProfiles(migrated)
  // Activate whichever index used to be selected, clamped to range.
  const idx = Math.max(0, Math.min(settings.directVpnSelectedIndex || 0, migrated.length - 1))
  store.set('activeProfileId', migrated[idx].id)

  logEvent('info', 'server-picker', 'migrated legacy directVpnCachedProfiles', {
    count: migrated.length,
    activeIndex: idx
  })
}

/**
 * Backfills missing `outbound` blocks on existing picker entries. An older
 * build of the app saved profiles without the `outbound` field, which makes
 * the VPN unstartable for those entries (we have no sing-box outbound to
 * dial). We try to recover the outbound from the legacy
 * settings.directVpnCachedProfiles list by matching on host+port+protocol.
 *
 * Runs every startup. Cheap when nothing needs fixing.
 */
export function backfillMissingOutbounds(): void {
  const profiles = getProfiles()
  if (!profiles.length) return
  const needFix = profiles.filter(p => !p.outbound || typeof p.outbound !== 'object')
  if (!needFix.length) return

  const settings = settingsStore.get()
  const legacy = Array.isArray(settings.directVpnCachedProfiles)
    ? settings.directVpnCachedProfiles
    : []

  let fixed = 0
  const updated = profiles.map(profile => {
    if (profile.outbound && typeof profile.outbound === 'object') return profile

    // Match on host:port (the most reliable identity even when names diverge),
    // falling back to name comparison.
    const candidate = legacy.find((cached: any) => {
      if (!cached || !cached.outbound || typeof cached.outbound !== 'object') return false
      const cachedHost = String(cached.outbound.server || '').trim()
      const cachedPort = Number(cached.outbound.server_port || 0)
      return cachedHost === profile.server && cachedPort === profile.port
    }) || legacy.find((cached: any) =>
      cached && typeof cached.name === 'string' && cached.name === profile.name && cached.outbound
    )

    if (candidate && candidate.outbound) {
      fixed++
      return { ...profile, outbound: candidate.outbound }
    }
    return profile
  })

  if (fixed > 0) {
    saveProfiles(updated)
    logEvent('info', 'server-picker', 'backfilled missing outbounds', {
      total: profiles.length,
      missing: needFix.length,
      recovered: fixed,
      stillMissing: needFix.length - fixed
    })
  } else {
    logEvent('warn', 'server-picker', 'profiles missing outbound and no recovery source', {
      missing: needFix.length
    })
  }
}

/**
 * One-time migration that backfills `groupId` on every picker entry.
 *
 * Why: introducing groups means every profile must belong to exactly one,
 * but the picker store predates groups. Without this migration, the
 * Servers page would show all pre-existing profiles as "ungrouped",
 * which is not useful — the user has no idea where they came from
 * either, and the refresh / health-check buttons need a group context to
 * work.
 *
 * Heuristic:
 *   1. If every profile already has a valid groupId, no-op.
 *   2. Otherwise, ensure an "Импортированные" `manual` group exists and
 *      assign every dangling/orphaned profile to it.
 *
 * Idempotent: subsequent calls are no-ops once profiles have valid
 * groupIds. We pick `manual` rather than `subscription` because we have
 * no upstream URL to refresh against — these keys came from a previous
 * version of the app that didn't track origin.
 */
export function migrateProfilesIntoGroups(): void {
  const profiles = getProfiles()
  if (!profiles.length) return

  const groups = serverGroups.getGroups()
  const groupIds = new Set(groups.map(g => g.id))

  const dangling = profiles.filter(p => !p.groupId || !groupIds.has(p.groupId))
  if (!dangling.length) return

  // Look for an existing "Импортированные" manual group first; if absent,
  // create one. This keeps re-running the migration idempotent in the
  // pathological case where a group somehow gets deleted but profiles
  // remain.
  const IMPORTED_NAME = 'Импортированные'
  let importedGroup = groups.find(
    g => g.source === 'manual' && g.name === IMPORTED_NAME
  )
  if (!importedGroup) {
    importedGroup = serverGroups.createGroup({
      name: IMPORTED_NAME,
      source: 'manual',
      importedAt: Date.now(),
      status: 'unknown'
    })
  }

  const updated = profiles.map(p =>
    !p.groupId || !groupIds.has(p.groupId)
      ? { ...p, groupId: importedGroup!.id }
      : p
  )
  saveProfiles(updated)

  logEvent('info', 'server-picker', 'migrated-profiles-into-groups', {
    total: profiles.length,
    migrated: dangling.length,
    groupId: importedGroup.id
  })
}

function getProfiles(): ServerProfile[] {
  return store.get('profiles') ?? []
}

function saveProfiles(profiles: ServerProfile[]): void {
  store.set('profiles', profiles)
}

function getActiveProfileId(): string | null {
  return store.get('activeProfileId') ?? null
}

/**
 * Sets the active profile by ID. Auto-selects the first available profile if
 * none is currently active and at least one profile exists.
 */
export function selectProfile(id: string): void {
  const profiles = getProfiles()
  const exists = profiles.some((p) => p.id === id)
  if (!exists) {
    logEvent('warn', 'server-picker', 'selectProfile: profile not found', { id })
    return
  }
  store.set('activeProfileId', id)
  logEvent('info', 'server-picker', 'profile selected', { id })
}

/**
 * Returns the currently active profile (the one VPN dials when started).
 * If no profile was explicitly selected but profiles exist, falls back to
 * the first one. Returns null only when there are no profiles at all.
 */
export function getActiveProfile(): ServerProfile | null {
  const profiles = getProfiles()
  if (!profiles.length) return null
  const activeId = getActiveProfileId()
  const found = activeId ? profiles.find((p) => p.id === activeId) : null
  return found ?? profiles[0]
}

/**
 * Removes a profile by ID.
 */
function removeProfile(id: string): void {
  const profiles = getProfiles()
  const filtered = profiles.filter((p) => p.id !== id)
  if (filtered.length === profiles.length) {
    logEvent('warn', 'server-picker', 'removeProfile: profile not found', { id })
    return
  }
  saveProfiles(filtered)

  // Clear active profile if it was removed
  if (getActiveProfileId() === id) {
    store.set('activeProfileId', null)
  }

  logEvent('info', 'server-picker', 'profile removed', { id })
}

// ─── Subscription / Link Parsing ─────────────────────────────────────────────

/**
 * Converts a VpnProfile (from vpnProfiles module) to a ServerProfile.
 *
 * Newly-imported profiles always carry a `groupId` — every entry in the
 * picker store belongs to exactly one {@link ServerGroup}. The optional
 * `sourceUri` is the lossless representation of the VPN URI we parsed
 * (when the user pasted a single key) so we can re-export it later
 * without re-deriving it from the outbound shape.
 */
function vpnProfileToServerProfile(
  vpnProfile: VpnProfile,
  groupId: string,
  sourceUri?: string
): ServerProfile {
  const outbound = vpnProfile.outbound || {}
  return {
    id: randomUUID(),
    name: vpnProfile.name || vpnProfile.protocol.toUpperCase(),
    protocol: vpnProfile.protocol,
    server: outbound.server || '',
    port: outbound.server_port || 0,
    country: undefined,
    ping: null,
    status: 'unknown',
    lastChecked: undefined,
    outbound,
    groupId,
    sourceUri,
    lastSeenInSubscriptionAt: Date.now(),
    enabled: true
  }
}

/**
 * Stable identity for dedupe. Two profiles are "the same" when:
 *   1. They share an exact `sourceUri` (lossless, survives renames), OR
 *   2. They share `(server, port, protocol)`.
 *
 * The first wins because it's strictly more specific — two providers can
 * legitimately use the same `1.2.3.4:443/vless` triplet for different
 * UUIDs, but a re-pasted URI is unambiguously the same key.
 */
function isSameServerProfile(a: ServerProfile, b: ServerProfile): boolean {
  if (a.sourceUri && b.sourceUri) return a.sourceUri === b.sourceUri
  return a.server === b.server && a.port === b.port && a.protocol === b.protocol
}

/**
 * Derive a group name from a subscription URL. Prefers the panel's
 * advertised `webPageUrl` (the user's browser-facing dashboard) and falls
 * back to the subscription URL host. Capped at 60 chars so the UI doesn't
 * have to truncate aggressively.
 */
function deriveSubscriptionGroupName(input: string, webPageUrl?: string): string {
  const candidates: Array<string | undefined> = [webPageUrl, input]
  for (const candidate of candidates) {
    if (!candidate) continue
    try {
      const host = new URL(candidate).host
      if (host) return host.slice(0, 60)
    } catch {
      // Not a URL — try the next candidate.
    }
  }
  // Last-resort fallback: a sanitised slice of the raw input. We never
  // want to leave a group with an empty name.
  return input.replace(/\s+/g, ' ').trim().slice(0, 60) || 'Подписка'
}

/**
 * Append a batch of resolved {@link VpnProfile}s to a group, deduping
 * against the existing picker store. Returns the freshly-created
 * {@link ServerProfile} entries (not the duplicates).
 *
 * Shared between {@link addFromInput} and {@link addFromInputToGroup} so
 * both paths get identical merge semantics.
 */
function appendProfilesToGroup(
  vpnProfiles: VpnProfile[],
  groupId: string,
  sourceUriPerProfile: (vp: VpnProfile, index: number) => string | undefined
): ServerProfile[] {
  const existingProfiles = getProfiles()
  const newProfiles: ServerProfile[] = []

  vpnProfiles.forEach((vpnProfile, index) => {
    const sourceUri = sourceUriPerProfile(vpnProfile, index)
    const candidate = vpnProfileToServerProfile(vpnProfile, groupId, sourceUri)
    const isDuplicate =
      existingProfiles.some(p => isSameServerProfile(p, candidate)) ||
      newProfiles.some(p => isSameServerProfile(p, candidate))
    if (!isDuplicate) newProfiles.push(candidate)
  })

  if (newProfiles.length > 0) {
    saveProfiles([...existingProfiles, ...newProfiles])
    if (!getActiveProfileId()) {
      store.set('activeProfileId', newProfiles[0].id)
    }
  }
  return newProfiles
}

/**
 * Adds profiles from a subscription URL or a single protocol link.
 *
 * Behaviour by input type:
 *
 * - Subscription URL the user has already imported: treat as a refresh of
 *   the existing group. Same dedupe-merge semantics as `groups:refresh` —
 *   keep stable IDs, leave previously-seen-but-now-missing keys in place.
 * - New subscription URL: create a fresh `subscription` group, name it
 *   from the panel's webPageUrl or the URL host, store the new profiles
 *   under that group.
 * - Single VPN URI: ensure the shared "Ручные ключи" group exists and
 *   append the parsed profile under it. The raw URI is stored as
 *   `sourceUri` for lossless re-export.
 */
export async function addFromInput(input: string): Promise<ServerProfile[]> {
  const trimmed = input.trim()
  if (!trimmed) {
    throw new Error('Введите ссылку подписки или VPN-ссылку')
  }

  const isSubscriptionUrl = /^https?:\/\//i.test(trimmed)

  if (isSubscriptionUrl) {
    // If the user re-pasted a subscription they've already imported, we
    // funnel the request through the same merge logic the refresh button
    // uses. No duplicate group, no surprise data loss.
    const existing = findGroupBySourceUrl(trimmed)
    if (existing) {
      const beforeIds = new Set(getProfiles().map(p => p.id))
      const result = await refreshSubscriptionGroup(existing.id)
      if (!result.ok) {
        throw new Error(result.error)
      }
      const after = getProfiles()
      const newlyAdded = after.filter(p => !beforeIds.has(p.id))
      logEvent('info', 'server-picker', 'profiles refreshed via re-paste', {
        groupId: existing.id,
        added: result.addedCount,
        updated: result.updatedCount
      })
      void geolocateAll().catch(() => undefined)
      return newlyAdded
    }

    // First-time subscription import — fetch + create the group + persist.
    let proxyAddr: string | undefined
    let proxyType: 'socks5' | 'http' | undefined
    try {
      const settings = settingsStore.get()
      proxyAddr = settings.proxyOverride?.trim() || undefined
      proxyType = settings.proxyType
    } catch {
      /* fall through with no proxy override */
    }

    const resolved = await resolveVpnProfiles(trimmed, { proxyAddr, proxyType })
    if (!resolved.profiles.length) {
      throw new Error('Не найдено поддерживаемых профилей в указанном источнике')
    }

    const now = Date.now()
    const userInfo = resolved.userInfo
    const group = serverGroups.createGroup({
      name: deriveSubscriptionGroupName(trimmed, userInfo?.webPageUrl),
      source: 'subscription',
      sourceUrl: trimmed,
      importedAt: now,
      lastFetchedAt: now,
      lastFetchAttemptAt: now,
      lastFetchError: null,
      status: 'active',
      lastRefreshProfilesCount: resolved.profiles.length,
      trafficUploadBytes: userInfo?.trafficUploadBytes ?? undefined,
      trafficDownloadBytes: userInfo?.trafficDownloadBytes ?? undefined,
      trafficUsedBytes: userInfo?.trafficUsedBytes ?? undefined,
      trafficTotalBytes: userInfo?.trafficTotalBytes ?? undefined,
      expiresAt: userInfo?.expiresAt ?? undefined,
      refreshIntervalSeconds: userInfo?.refreshIntervalSeconds ?? undefined,
      webPageUrl: userInfo?.webPageUrl ?? undefined
    })

    const newProfiles = appendProfilesToGroup(
      resolved.profiles,
      group.id,
      // We don't have per-profile URIs from a subscription resolver
      // (the upstream feed often omits them), so leave `sourceUri`
      // unset and let the connection-tuple do the dedupe work.
      () => undefined
    )

    logEvent('info', 'server-picker', 'profiles added from subscription', {
      groupId: group.id,
      count: newProfiles.length
    })
    void geolocateAll().catch(() => undefined)
    return newProfiles
  }

  // Single VPN URI path. We need the parsed profile AND the original line
  // so we can store it as sourceUri.
  const resolved = await resolveVpnProfiles(trimmed)
  if (!resolved.profiles.length) {
    throw new Error('Не найдено поддерживаемых профилей в указанном источнике')
  }

  const groupId = ensureManualKeysGroup()
  // Pasting one key returns one profile, but a multi-line paste of single
  // URIs is technically valid too — we keep the lossless URI for the
  // first profile only, since we can't reliably split a multi-line paste
  // back into per-profile lines from here. Single-key (the dominant case)
  // gets the source URI; bulk paste falls back to undefined.
  const newProfiles = appendProfilesToGroup(
    resolved.profiles,
    groupId,
    (_vp, index) => (resolved.profiles.length === 1 && index === 0 ? trimmed : undefined)
  )

  logEvent('info', 'server-picker', 'profile added from URI', {
    groupId,
    count: newProfiles.length
  })
  void geolocateAll().catch(() => undefined)
  return newProfiles
}

/**
 * Append `input` to the named group regardless of input type. Used by the
 * "paste an extra key under this subscription" flow in the UI — the user
 * already chose the group, so we never auto-create or auto-route.
 *
 * Subscription URLs append the full set of resolved profiles. Single
 * URIs append one profile with `sourceUri = trimmed`.
 */
export async function addFromInputToGroup(input: string, groupId: string): Promise<ServerProfile[]> {
  const trimmed = input.trim()
  if (!trimmed) throw new Error('Введите ссылку подписки или VPN-ссылку')

  const target = serverGroups.getGroup(groupId)
  if (!target) throw new Error('Группа не найдена')

  let proxyAddr: string | undefined
  let proxyType: 'socks5' | 'http' | undefined
  try {
    const settings = settingsStore.get()
    proxyAddr = settings.proxyOverride?.trim() || undefined
    proxyType = settings.proxyType
  } catch {
    /* fall through */
  }

  const resolved = await resolveVpnProfiles(trimmed, { proxyAddr, proxyType })
  if (!resolved.profiles.length) {
    throw new Error('Не найдено поддерживаемых профилей в указанном источнике')
  }

  const isSubscriptionUrl = /^https?:\/\//i.test(trimmed)
  const newProfiles = appendProfilesToGroup(
    resolved.profiles,
    groupId,
    (_vp, index) =>
      !isSubscriptionUrl && resolved.profiles.length === 1 && index === 0 ? trimmed : undefined
  )

  logEvent('info', 'server-picker', 'profiles appended to existing group', {
    groupId,
    count: newProfiles.length,
    source: isSubscriptionUrl ? 'subscription' : 'uri'
  })
  void geolocateAll().catch(() => undefined)
  return newProfiles
}

// ─── Grouping ────────────────────────────────────────────────────────────────

/**
 * Groups profiles by their protocol field.
 * Returns a record where keys are protocol names and values are arrays of profiles.
 */
export function groupByProtocol(
  profiles: ServerProfile[]
): Record<string, ServerProfile[]> {
  const groups: Record<string, ServerProfile[]> = {}

  for (const profile of profiles) {
    const key = profile.protocol || 'unknown'
    if (!groups[key]) {
      groups[key] = []
    }
    groups[key].push(profile)
  }

  return groups
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

function handleLogged<T>(
  channel: string,
  listener: (event: IpcMainInvokeEvent, ...args: any[]) => Promise<T> | T
): void {
  ipcMain.handle(channel, async (event, ...args) => {
    const started = Date.now()
    logEvent('debug', 'ipc', `${channel} started`, { args })
    try {
      const result = await listener(event, ...args)
      logEvent('debug', 'ipc', `${channel} finished`, { ms: Date.now() - started })
      return result
    } catch (err) {
      logEvent('error', 'ipc', `${channel} failed`, err)
      throw err
    }
  })
}

/**
 * Registers all server picker IPC handlers.
 * Should be called once during app initialization.
 */
export function registerServerPickerHandlers(): void {
  handleLogged('servers:list', async () => {
    return getProfiles()
  })

  handleLogged('servers:select', async (_event, id: string) => {
    selectProfile(id)
  })

  handleLogged('servers:get-active', async () => {
    const profile = getActiveProfile()
    return { profile, activeId: getActiveProfileId() }
  })

  handleLogged('servers:ping-all', async () => {
    return await pingAll()
  })

  // Ping a single host:port. Used by the dashboard "ping selected" button to
  // measure latency to whatever profile the user currently has chosen, without
  // forcing a full pingAll across every saved server.
  handleLogged('servers:ping-one', async (_event, host: string, port: number) => {
    return await pingServer(host, port)
  })

  handleLogged('servers:add', async (_event, input: string) => {
    return await addFromInput(input)
  })

  // Append profiles to a specific group. When `groupId` is null, fall back
  // to the same defaults as `servers:add`: subscription URLs create their
  // own group; single URIs land in "Ручные ключи".
  handleLogged('servers:add-to-group', async (_event, input: string, groupId: string | null) => {
    if (groupId) return await addFromInputToGroup(input, groupId)
    return await addFromInput(input)
  })

  handleLogged('servers:remove', async (_event, id: string) => {
    removeProfile(id)
  })

  // Export an entry back to its scheme URI (vless://, trojan://, …) so the
  // user can move the key to another device or another client. Returns
  // {ok: true, uri, profile} on success, or {ok: false, reason} when the
  // outbound shape isn't representable as a single-line URI (custom
  // sing-box JSON profiles fall in that bucket).
  handleLogged('servers:export-key', async (_event, id: string) => {
    const profile = getProfiles().find(p => p.id === id)
    if (!profile) return { ok: false as const, reason: 'profile-not-found' }
    if (!profile.outbound || typeof profile.outbound !== 'object') {
      return { ok: false as const, reason: 'no-outbound' }
    }
    const uri = exportOutboundToUri({
      name: profile.name,
      protocol: profile.protocol,
      outbound: profile.outbound
    })
    if (!uri) return { ok: false as const, reason: 'unsupported-protocol', protocol: profile.protocol }
    return { ok: true as const, uri, name: profile.name, protocol: profile.protocol }
  })

  // Save the exported URI to a .txt file via the OS save dialog. Used when
  // the user wants to keep a backup, store keys in a password manager, or
  // share the key out-of-band — clipboard is fine for one-shot paste, but
  // a file is what people actually archive. Returns:
  //   {ok: true, path}            — file written
  //   {ok: false, cancelled: true} — user dismissed the dialog
  //   {ok: false, reason}          — anything else (no profile, write failed, …)
  handleLogged('servers:export-key-file', async (_event, id: string) => {
    const profile = getProfiles().find(p => p.id === id)
    if (!profile) return { ok: false as const, reason: 'profile-not-found' }
    if (!profile.outbound || typeof profile.outbound !== 'object') {
      return { ok: false as const, reason: 'no-outbound' }
    }
    const uri = exportOutboundToUri({
      name: profile.name,
      protocol: profile.protocol,
      outbound: profile.outbound
    })
    if (!uri) return { ok: false as const, reason: 'unsupported-protocol', protocol: profile.protocol }

    // Pick a sane default filename: "<protocol>-<sanitised-name>.txt".
    // Stripping non-filename characters makes the dialog suggestion usable on
    // Windows without the user having to retype.
    const safeName = (profile.name || profile.protocol)
      .replace(/[<>:"/\\|?*\u0000-\u001F]/g, '')
      .replace(/\s+/g, '-')
      .slice(0, 60) || profile.protocol
    const defaultFileName = `${profile.protocol}-${safeName}.txt`

    const choice = await dialog.showSaveDialog({
      title: 'Сохранить ключ VPN',
      defaultPath: join(app.getPath('desktop'), defaultFileName),
      filters: [
        { name: 'Текстовый файл', extensions: ['txt'] },
        { name: 'Все файлы', extensions: ['*'] }
      ]
    })

    if (choice.canceled || !choice.filePath) {
      return { ok: false as const, cancelled: true as const }
    }

    try {
      // We persist just the URI on a single line plus a trailing newline.
      // Most clients accept extra leading/trailing whitespace, but minimum
      // surprise is "the file is exactly the URI".
      await writeFile(choice.filePath, uri + '\n', 'utf8')
      return { ok: true as const, path: choice.filePath, uri, name: profile.name, protocol: profile.protocol }
    } catch (err: any) {
      logEvent('warn', 'server-picker', 'export-key-file write failed', {
        path: choice.filePath,
        error: err?.message || String(err)
      })
      return { ok: false as const, reason: 'write-failed', error: err?.message || String(err) }
    }
  })

  // Bulk export: dump every saved profile (one URI per line) into a single
  // .txt file via the OS save dialog. Profiles that don't have a single-line
  // representation (custom sing-box JSON, missing outbound) are skipped and
  // their count is returned so the UI can mention them.
  //
  // Returns the same shape as the single-key handler, plus counts:
  //   {ok: true, path, total, exported, skipped}
  //   {ok: false, cancelled: true}
  //   {ok: false, reason: 'no-profiles' | 'unsupported-all' | 'write-failed'}
  handleLogged('servers:export-all-keys-file', async () => {
    const profiles = getProfiles()
    if (!profiles.length) return { ok: false as const, reason: 'no-profiles' }

    const lines: string[] = []
    let skipped = 0
    for (const profile of profiles) {
      if (!profile.outbound || typeof profile.outbound !== 'object') { skipped++; continue }
      const uri = exportOutboundToUri({
        name: profile.name,
        protocol: profile.protocol,
        outbound: profile.outbound
      })
      if (!uri) { skipped++; continue }
      lines.push(uri)
    }

    if (!lines.length) {
      return { ok: false as const, reason: 'unsupported-all' }
    }

    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    const defaultFileName = `vpn-keys-${stamp}.txt`

    const choice = await dialog.showSaveDialog({
      title: 'Сохранить все ключи VPN',
      defaultPath: join(app.getPath('desktop'), defaultFileName),
      filters: [
        { name: 'Текстовый файл', extensions: ['txt'] },
        { name: 'Все файлы', extensions: ['*'] }
      ]
    })

    if (choice.canceled || !choice.filePath) {
      return { ok: false as const, cancelled: true as const }
    }

    // Header comments so future-you remembers what this file is. Most VPN
    // clients (Happ / v2RayN / sing-box) ignore '#' lines on import.
    const header = [
      `# VPN keys exported by VPN Tunnel Enforcer`,
      `# Profiles: ${lines.length} exported, ${skipped} skipped`,
      `# Generated: ${new Date().toISOString()}`,
      ''
    ].join('\n')

    try {
      await writeFile(choice.filePath, header + lines.join('\n') + '\n', 'utf8')
      logEvent('info', 'server-picker', 'export-all-keys-file', {
        path: choice.filePath,
        total: profiles.length,
        exported: lines.length,
        skipped
      })
      return {
        ok: true as const,
        path: choice.filePath,
        total: profiles.length,
        exported: lines.length,
        skipped
      }
    } catch (err: any) {
      logEvent('warn', 'server-picker', 'export-all-keys-file write failed', {
        path: choice.filePath,
        error: err?.message || String(err)
      })
      return { ok: false as const, reason: 'write-failed', error: err?.message || String(err) }
    }
  })
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export const serverPicker = {
  getProfiles,
  getActiveProfileId,
  getActiveProfile,
  selectProfile,
  removeProfile,
  pingServer,
  pingAll,
  addFromInput,
  addFromInputToGroup,
  groupByProtocol,
  migrateLegacyDirectVpnProfiles,
  backfillMissingOutbounds,
  migrateProfilesIntoGroups,
  geolocateAll,
  registerHandlers: registerServerPickerHandlers
}
