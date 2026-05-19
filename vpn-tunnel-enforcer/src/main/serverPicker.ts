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
    ? roundTripPing(host, port)
    : plainTcpPing(host, port)
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
 * Tunnel-aware RTT measurement.
 *
 * After `connect()` returns (which is immediate when sing-box terminates
 * the SYN locally) we send a single \r\n and start the timer. The timer
 * stops on the first sign of life from the far side: bytes returned,
 * a graceful FIN, or an RST. Any of those guarantees a full round-trip
 * over the encrypted tunnel.
 *
 * For VPN-front servers on :443 our junk byte triggers an immediate TLS
 * alert / RST from the upstream — which is exactly what we want, since
 * the alert itself crosses the tunnel. Worst-case the server is silent
 * and we time out (returning null), but in practice every Reality /
 * standard TLS endpoint we tested replies within tens of ms.
 */
function roundTripPing(host: string, port: number): Promise<number | null> {
  return new Promise((resolve) => {
    const socket = new Socket()
    const connectStart = Date.now()
    let probeStart = 0
    let done = false
    const finish = (value: number | null) => {
      if (done) return
      done = true
      socket.removeAllListeners()
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(PING_TIMEOUT_MS)

    socket.once('connect', () => {
      probeStart = Date.now()
      try {
        // Either a tiny readable HTTP-ish probe so the server fast-path
        // its response, or just an empty newline. Either yields a quick
        // RST/FIN/data from the far side.
        socket.write('\r\n')
      } catch {
        // Write failed (already torn down) — fall back to connect time so
        // we still return *something* sensible rather than null.
        finish(Date.now() - connectStart)
      }
    })

    socket.once('data', () => finish(Date.now() - probeStart))
    socket.once('end', () => finish(Date.now() - probeStart))
    socket.once('close', () => {
      // Some servers close without ever emitting 'data' or 'end' — fall
      // back to whichever clock we have, preferring the post-connect
      // measurement when available.
      finish(probeStart ? Date.now() - probeStart : Date.now() - connectStart)
    })
    socket.once('timeout', () => finish(null))
    socket.once('error', () => {
      // RST counts as a real round-trip too. Same reasoning.
      finish(probeStart ? Date.now() - probeStart : null)
    })

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
 */
function vpnProfileToServerProfile(vpnProfile: VpnProfile): ServerProfile {
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
    outbound
  }
}

/**
 * Adds profiles from a subscription URL or a single protocol link.
 *
 * - If input is a URL (starts with http), fetches and parses the subscription
 * - If input is a single protocol link (ss://, vmess://, vless://, trojan://), parses it directly
 * - Returns the newly added ServerProfile entries
 */
export async function addFromInput(input: string): Promise<ServerProfile[]> {
  const trimmed = input.trim()
  if (!trimmed) {
    throw new Error('Введите ссылку подписки или VPN-ссылку')
  }

  // Use the existing vpnProfiles resolver which handles both URLs and protocol links
  const { profiles: vpnProfiles } = await resolveVpnProfiles(trimmed)

  if (!vpnProfiles.length) {
    throw new Error('Не найдено поддерживаемых профилей в указанном источнике')
  }

  const existingProfiles = getProfiles()
  const newProfiles: ServerProfile[] = []

  for (const vpnProfile of vpnProfiles) {
    const serverProfile = vpnProfileToServerProfile(vpnProfile)

    // Skip duplicates (same server + port + protocol)
    const isDuplicate = existingProfiles.some(
      (p) =>
        p.server === serverProfile.server &&
        p.port === serverProfile.port &&
        p.protocol === serverProfile.protocol
    )

    if (!isDuplicate) {
      newProfiles.push(serverProfile)
    }
  }

  if (newProfiles.length > 0) {
    const allProfiles = [...existingProfiles, ...newProfiles]
    saveProfiles(allProfiles)
    // If the user has no active profile yet, auto-select the first one we
    // just imported. Without this the dashboard shows "no servers" until
    // they manually click one, even though the list is populated.
    if (!getActiveProfileId()) {
      store.set('activeProfileId', newProfiles[0].id)
    }
    logEvent('info', 'server-picker', 'profiles added from input', {
      count: newProfiles.length,
      source: /^https?:\/\//i.test(trimmed) ? 'subscription' : 'link'
    })
    // Kick off geolocation in the background. We don't await — the import
    // call should return as soon as profiles are saved, and the UI will
    // poll/listen for country fields populating over the next few seconds.
    void geolocateAll().catch(() => undefined)
  }

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
  groupByProtocol,
  migrateLegacyDirectVpnProfiles,
  backfillMissingOutbounds,
  geolocateAll,
  registerHandlers: registerServerPickerHandlers
}
