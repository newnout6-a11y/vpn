/**
 * Server Groups Service — origin tracking for server profiles.
 *
 * Today the picker stores a flat list of {@link ServerProfile} entries.
 * That made the UI lossy as soon as a user imported more than one
 * subscription: subscription A's keys and subscription B's keys ended up
 * jumbled together, and there was no way to refresh just one of them.
 *
 * This module owns the {@link ServerGroup} side of the model:
 *
 *   - Each subscription URL becomes one group with `source: 'subscription'`.
 *   - Loose VPN URIs the user pastes share a single "Ручные ключи" group.
 *   - When a subscription URL stops returning profiles (panel gone, trial
 *     expired, …) the group is marked `expired` instead of being deleted.
 *     The profiles themselves are LEFT in place because post-trial keys
 *     routinely keep working for hours/days after the panel disappears.
 *
 * The actual profile-side wiring (creating/reusing groups during
 * `addFromInput`, the migration that backfills `groupId`) lives in
 * `serverPicker.ts`. This file owns the group store and the `groups:*`
 * IPC surface only.
 */

import { ipcMain, type IpcMainInvokeEvent } from 'electron'
import { randomUUID } from 'crypto'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import {
  applyClientDeviceToOutbound,
  clientFingerprintForDevice,
  normalizeClientDevice,
  resolveVpnProfiles,
  type VpnProfile
} from './vpnProfiles'
import { settingsStore } from './settings'
import type { ClientDevice, ServerGroup, ServerProfile } from '../shared/ipc-types'

// ─── Persistent Store ────────────────────────────────────────────────────────

interface ServerGroupsStore {
  groups: ServerGroup[]
}

interface RefreshGroupOptions {
  clientDevice?: ClientDevice
}

const store = new Store<ServerGroupsStore>({
  name: 'server-groups',
  defaults: {
    groups: []
  }
})

// Auto-created default group names. We keep them as constants so the
// picker-side code that creates them on demand uses the exact same string.
const MANUAL_KEYS_GROUP_NAME = 'Ручные ключи'

// ─── CRUD ───────────────────────────────────────────────────────────────────

function expireGroupByClock(group: ServerGroup, now = Date.now()): ServerGroup {
  if (
    group.source === 'subscription' &&
    group.expiresAt &&
    group.expiresAt > 0 &&
    group.expiresAt < now &&
    group.status !== 'expired'
  ) {
    return { ...group, status: 'expired' }
  }
  return group
}

function getGroups(): ServerGroup[] {
  const groups = store.get('groups') ?? []
  let changed = false
  const normalized = groups.map((group) => {
    const next = expireGroupByClock(group)
    if (next !== group) changed = true
    return next
  })
  if (changed) saveGroups(normalized)
  return normalized
}

function saveGroups(groups: ServerGroup[]): void {
  store.set('groups', groups)
}

function getGroup(id: string): ServerGroup | null {
  return getGroups().find(g => g.id === id) ?? null
}

function updateGroup(id: string, patch: Partial<ServerGroup>): ServerGroup | null {
  const groups = getGroups()
  const idx = groups.findIndex(g => g.id === id)
  if (idx === -1) return null
  // Spread `patch` LAST so caller-supplied undefineds explicitly clear the
  // field. The `lastFetchError: null` reset on a successful refresh is the
  // canonical example: we want to overwrite the previous error string.
  const next: ServerGroup = { ...groups[idx], ...patch, id }
  groups[idx] = next
  saveGroups(groups)
  return next
}

function deleteGroupRecord(id: string): boolean {
  const groups = getGroups()
  const filtered = groups.filter(g => g.id !== id)
  if (filtered.length === groups.length) return false
  saveGroups(filtered)
  return true
}

/**
 * Insert a brand-new group. The caller MUST NOT pass an `id` — we generate
 * one and return the persisted record (which is what the rest of the code
 * actually wants).
 */
function createGroup(input: Omit<ServerGroup, 'id'>): ServerGroup {
  const group: ServerGroup = { id: randomUUID(), ...input }
  const groups = getGroups()
  groups.push(group)
  saveGroups(groups)
  return group
}

/**
 * Canonicalises a subscription input to its underlying https URL.
 *
 * VPN providers (Sosa / Marzban / 3X-UI panels) hand users a `happ://add/…`
 * deep-link whose payload encodes the real https subscription URL — either
 * URL-encoded, base64-encoded, or sometimes embedded raw. Different copies
 * of the same logical subscription can therefore arrive in radically
 * different string forms:
 *
 *   - `https://example.com/sub/abc`
 *   - `happ://add/https://example.com/sub/abc`
 *   - `happ://add/https%3A%2F%2Fexample.com%2Fsub%2Fabc`
 *   - `happ://add/aHR0cHM6Ly9leGFtcGxlLmNvbS9zdWIvYWJj`
 *
 * All four mean the same subscription. Without this canonicalisation step,
 * a user re-pasting the same key (e.g. by sharing it across two devices)
 * would create a fresh duplicate group every time. With canonicalisation,
 * `findGroupBySourceUrl` correctly hits the existing group regardless of
 * the form the user pasted.
 *
 * NOTE: We intentionally inline the unwrap rather than re-using
 * `unwrapHappAddLink` from `vpnProfiles.ts` — that function is not
 * exported, and pulling it in would force `serverGroups.ts` to depend on
 * `vpnProfiles.ts` strictly for a 15-line decoder. Easier to maintain a
 * self-contained, narrowly-scoped helper here.
 *
 * Returns the unwrapped https URL when the input is a `happ://add/…` link
 * with an https payload, the trimmed input otherwise. Never throws.
 */
export function canonicalizeSubscriptionUrl(input: string): string {
  const trimmed = String(input || '').trim()
  if (!trimmed) return trimmed

  const happAddMatch = trimmed.match(/^happ:\/\/add\/(.*)$/i)
  if (!happAddMatch) return trimmed
  const rest = happAddMatch[1] ?? ''
  if (!rest) return trimmed

  const candidates: string[] = []

  // Form 1: happ://add/https://… — payload is the URL itself.
  if (/^https?:\/\//i.test(rest)) candidates.push(rest)

  // Form 2: URL-encoded — happ://add/https%3A%2F%2F…
  try {
    const decoded = decodeURIComponent(rest)
    if (decoded && decoded !== rest) candidates.push(decoded.trim())
  } catch {
    /* not URL-encoded; fall through */
  }

  // Form 3: base64-url — happ://add/aHR0cHM6Ly…
  // base64url uses '-' / '_' for the URL-safe alphabet; convert to '+' / '/'.
  const base64Url = rest.replace(/-/g, '+').replace(/_/g, '/')
  if (base64Url.length >= 4 && /^[A-Za-z0-9+/]+={0,2}$/.test(base64Url)) {
    try {
      const decoded = Buffer.from(base64Url, 'base64').toString('utf8').trim()
      if (decoded) candidates.push(decoded)
    } catch {
      /* not base64; fall through */
    }
  }

  for (const candidate of candidates) {
    if (/^https?:\/\//i.test(candidate)) {
      // Final sanity check: must parse as a real URL. Otherwise we'd
      // accidentally treat malformed payloads as canonical.
      try {
        // eslint-disable-next-line no-new
        new URL(candidate)
        return candidate
      } catch {
        /* keep trying other candidates */
      }
    }
  }

  // Couldn't unwrap to an https URL — return the input unchanged so the
  // caller still gets a sensible "best-effort" identity for matching.
  return trimmed
}

/**
 * Find an existing group whose `sourceUrl` matches the given URL. Used to
 * dedupe "user re-pasted the same subscription" — we treat that as a
 * refresh of the existing group rather than creating a duplicate.
 *
 * Matching is canonical: a stored `https://…` URL and a user-pasted
 * `happ://add/<base64-of-the-same-https-url>` resolve to the same group.
 * That covers the common case where one device shares the happ link and
 * another device pastes the raw URL (or vice versa).
 */
function findGroupBySourceUrl(url: string): ServerGroup | null {
  const trimmed = url.trim()
  if (!trimmed) return null
  const canonical = canonicalizeSubscriptionUrl(trimmed)
  return getGroups().find(g => {
    if (g.source !== 'subscription' || !g.sourceUrl) return false
    // Cheap exact-match path first — avoids the canonicalisation cost on
    // the dominant case (user pastes the same raw https URL twice).
    if (g.sourceUrl === trimmed) return true
    if (g.sourceUrl === canonical) return true
    // Final pass: stored URL might itself be a happ:// link from an
    // older build that didn't canonicalise on save. Canonicalise both
    // sides for the comparison.
    return canonicalizeSubscriptionUrl(g.sourceUrl) === canonical
  }) ?? null
}

/**
 * Returns the id of the singleton "Ручные ключи" group, creating it if
 * needed. We keep one shared bucket for all hand-pasted single keys
 * because individual VPN URIs don't have a meaningful "origin" — they
 * weren't fetched from anywhere.
 */
function ensureManualKeysGroup(): string {
  const existing = getGroups().find(
    g => g.source === 'manual' && g.name === MANUAL_KEYS_GROUP_NAME
  )
  if (existing) return existing.id
  const created = createGroup({
    name: MANUAL_KEYS_GROUP_NAME,
    source: 'manual',
    importedAt: Date.now(),
    status: 'unknown'
  })
  logEvent('info', 'server-groups', 'auto-created Ручные ключи group', {
    id: created.id
  })
  return created.id
}

// ─── Refresh helper ──────────────────────────────────────────────────────────

/**
 * Connection-tuple-only key for a stored ServerProfile. Used by
 * refreshGroup() to match stored profiles against freshly-resolved
 * subscription profiles, which only have a tuple to offer. Keeping both
 * sides on the same key space prevents the "every refresh duplicates the
 * sourceUri-bearing keys" bug — we deliberately do NOT consult `sourceUri`
 * here because the fresh side never has a per-line URI at this point.
 */
function profileTupleKey(p: { server: string; port: number; protocol: string }): string {
  return `tuple:${p.server}|${p.port}|${p.protocol}`
}

/** Connection-tuple-only key for a freshly-resolved VpnProfile. */
function vpnProfileTupleKey(p: VpnProfile): string {
  const ob = p.outbound || {}
  return `tuple:${ob.server || ''}|${Number(ob.server_port || 0)}|${p.protocol}`
}

/**
 * Convert a freshly-resolved {@link VpnProfile} into a {@link ServerProfile}
 * for storage. Used by the refresh path; the import path in
 * `serverPicker.ts` has its own copy because it also handles the
 * `addFromInput` legacy mapping.
 */
function vpnProfileToServerProfile(
  vpnProfile: VpnProfile,
  groupId: string,
  sourceUri: string | undefined,
  now: number,
  options: RefreshGroupOptions = {}
): ServerProfile {
  const clientDevice = normalizeClientDevice(options.clientDevice)
  const outbound = applyClientDeviceToOutbound(vpnProfile.outbound || {}, clientDevice)
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
    clientDevice,
    clientFingerprint: outbound.tls && typeof outbound.tls === 'object'
      ? clientFingerprintForDevice(clientDevice)
      : undefined,
    groupId,
    sourceUri,
    lastSeenInSubscriptionAt: now,
    enabled: true
  }
}

/**
 * Picker-store accessor, scoped to this module only. We deliberately do
 * NOT import {@link serverPicker} (would be a circular import) — the
 * picker store has the same `name: 'server-picker'` schema it always did,
 * so we can read/write it directly from here.
 *
 * Mirror of {@link ServerPickerStore} from `serverPicker.ts`.
 */
interface PickerStoreShape {
  profiles: ServerProfile[]
  activeProfileId: string | null
}
const pickerStore = new Store<PickerStoreShape>({
  name: 'server-picker',
  defaults: { profiles: [], activeProfileId: null }
})

function getPickerProfiles(): ServerProfile[] {
  return pickerStore.get('profiles') ?? []
}

function savePickerProfiles(profiles: ServerProfile[]): void {
  pickerStore.set('profiles', profiles)
}

/**
 * Refresh logic shared between the `groups:refresh` IPC handler and the
 * picker-side `addFromInput` (when a subscription URL is re-pasted, we
 * want exactly the same merge semantics as a manual refresh).
 *
 * Returns the same shape as the IPC channel envelope.
 */
export async function refreshGroup(
  groupId: string,
  options: RefreshGroupOptions = {}
): Promise<
  | { ok: true; group: ServerGroup; addedCount: number; updatedCount: number; removedCount: number }
  | { ok: false; error: string }
> {
  const group = getGroup(groupId)
  if (!group) return { ok: false, error: 'Группа не найдена' }
  if (group.source !== 'subscription' || !group.sourceUrl) {
    return { ok: false, error: 'Группа без подписки — обновлять нечего' }
  }

  const now = Date.now()
  // Fetching may go through the user's local proxy — pull it from settings
  // the same way `addFromInput` does. Defensive: if `settingsStore.get()`
  // throws (it shouldn't, but it touches disk), we just fetch directly.
  let proxyAddr: string | undefined
  let proxyType: 'socks5' | 'http' | undefined
  let bootstrapRouteMode: 'auto' | 'direct' | 'localProxy' | undefined
  try {
    const settings = settingsStore.get()
    proxyAddr = settings.proxyOverride?.trim() || undefined
    proxyType = settings.proxyType
    bootstrapRouteMode = settings.bootstrapRouteMode
  } catch {
    /* fall through with no proxy override */
  }

  const existing = getPickerProfiles()
  const inGroupExisting = existing.filter(p => p.groupId === groupId)
  const outOfGroup = existing.filter(p => p.groupId !== groupId)
  const existingDevices = Array.from(new Set(
    inGroupExisting.map(p => normalizeClientDevice(p.clientDevice))
  ))
  const refreshDevices = options.clientDevice
    ? [normalizeClientDevice(options.clientDevice)]
    : existingDevices.length
      ? existingDevices
      : ['pc' as ClientDevice]

  const resolvedByDevice = new Map<ClientDevice, Awaited<ReturnType<typeof resolveVpnProfiles>>>()
  let primaryDevice = refreshDevices[0]
  try {
    for (const device of refreshDevices) {
      const resolvedForDevice = await resolveVpnProfiles(group.sourceUrl, { proxyAddr, proxyType, clientDevice: device, bootstrapRouteMode })
      resolvedByDevice.set(device, resolvedForDevice)
      const currentPrimary = resolvedByDevice.get(primaryDevice)
      if ((!currentPrimary || !currentPrimary.profiles.length) && resolvedForDevice.profiles.length) {
        primaryDevice = device
      }
    }
  } catch (err: any) {
    const message = err?.message || String(err)
    // Network errors (DNS, TCP, TLS) usually indicate the user is offline
    // rather than the panel being gone. We still mark expired because the
    // user-facing meaning is the same: "we couldn't get fresh keys".
    updateGroup(groupId, {
      status: /resolve|ENOTFOUND|ECONNREFUSED|EAI/i.test(message) ? 'unreachable' : 'expired',
      lastFetchAttemptAt: now,
      lastFetchError: message
    })
    logEvent('warn', 'server-groups', 'refresh failed', { id: groupId, error: message })
    const refreshed = getGroup(groupId)
    if (!refreshed) return { ok: false, error: 'Группа исчезла во время обновления' }
    return { ok: true, group: refreshed, addedCount: 0, updatedCount: 0, removedCount: 0 }
  }

  const primaryResolved = resolvedByDevice.get(primaryDevice) ?? Array.from(resolvedByDevice.values())[0]
  if (!primaryResolved) {
    return { ok: false, error: 'No subscription response' }
  }
  const resolvedProfilesCount = Array.from(resolvedByDevice.values()).reduce((sum, item) => sum + item.profiles.length, 0)

  if (!resolvedProfilesCount) {
    // Soft-expired: the panel returned 200 but the body has zero keys. This
    // is the classic "trial period over" signal from Marzban/3X-UI.
    updateGroup(groupId, {
      status: 'expired',
      lastFetchAttemptAt: now,
      lastFetchError: 'Подписка вернула пустой список профилей'
    })
    const refreshed = getGroup(groupId)!
    return { ok: true, group: refreshed, addedCount: 0, updatedCount: 0, removedCount: 0 }
  }

  // Read userInfo defensively. Agent C may add more fields to
  // {@link SubscriptionUserInfo} later; we only touch what we already
  // know about and fall back to `undefined` when a panel didn't publish a
  // particular header.
  const userInfo = primaryResolved.userInfo

  const freshByDeviceAndKey = new Map<string, VpnProfile>()
  const freshEntries: Array<{ device: ClientDevice; key: string; profile: VpnProfile }> = []
  for (const [device, resolvedForDevice] of resolvedByDevice) {
    for (const fresh of resolvedForDevice.profiles) {
      const key = vpnProfileTupleKey(fresh)
      const deviceKey = `${device}|${key}`
      freshByDeviceAndKey.set(deviceKey, fresh)
      freshEntries.push({ device, key, profile: fresh })
    }
  }

  // Dedupe-merge against the existing profiles. We keep stable IDs for
  // anything we recognise (so the user's "active profile" pointer doesn't
  // jump after a refresh), and append new profiles unchanged.
  const existingByDeviceAndKey = new Map<string, ServerProfile>()
  const existingByKey = new Map<string, ServerProfile[]>()
  // IMPORTANT: index existing profiles by their CONNECTION TUPLE, not by
  // profileKey(). profileKey() prefers `uri:<sourceUri>` when a profile has a
  // sourceUri, but the fresh profiles coming back from a subscription refresh
  // have no per-line URI here, so vpnProfileKey(fresh) always produces a
  // `tuple:` key. Mixing the two key spaces means every profile that carries a
  // sourceUri (now common, since backfillProfileSourceUris populates it) fails
  // to match its fresh counterpart → the refresh re-adds it as a duplicate and
  // keeps the stale copy. Keying both sides by the tuple keeps the match
  // symmetric.
  for (const p of inGroupExisting) {
    const profileDevice = normalizeClientDevice(p.clientDevice)
    existingByDeviceAndKey.set(`${profileDevice}|${profileTupleKey(p)}`, p)
    const tupleKey = profileTupleKey(p)
    existingByKey.set(tupleKey, [...(existingByKey.get(tupleKey) ?? []), p])
  }

  let addedCount = 0
  let updatedCount = 0
  const merged: ServerProfile[] = []
  const seenDeviceKeys = new Set<string>()
  const addedNewKeys = new Set<string>()

  for (const { device, key, profile: fresh } of freshEntries) {
    // The resolver doesn't give us per-profile sourceUris back, but for
    // single-key inputs we could backfill from the input itself. The
    // subscription-URL case has no per-line URI handy here, so we rely on
    // the connection-tuple key — same behaviour as the legacy code.
    const deviceKey = `${device}|${key}`
    if (seenDeviceKeys.has(deviceKey)) continue
    seenDeviceKeys.add(deviceKey)

    const prior = existingByDeviceAndKey.get(deviceKey)
    if (prior) {
      const profileDevice = normalizeClientDevice(options.clientDevice ?? prior.clientDevice ?? device)
      const deviceFresh = freshByDeviceAndKey.get(`${profileDevice}|${key}`) ?? fresh
      const outbound = applyClientDeviceToOutbound(deviceFresh.outbound || {}, profileDevice)
      // Found a match — keep its id, update only the fields the upstream
      // can legitimately change. We deliberately do NOT touch user-edited
      // fields like `enabled`, `country`, or `ping`.
      const updated: ServerProfile = {
        ...prior,
        // Refresh outbound: providers occasionally rotate Reality keys or
        // switch transports.
        outbound,
        clientDevice: profileDevice,
        clientFingerprint: outbound.tls && typeof outbound.tls === 'object'
          ? clientFingerprintForDevice(profileDevice)
          : undefined,
        protocol: deviceFresh.protocol,
        server: deviceFresh.outbound?.server || prior.server,
        port: deviceFresh.outbound?.server_port || prior.port,
        // Update the human-readable name only if the upstream now has one
        // and the user hasn't overridden it (we have no way to know if
        // they did, so we conservatively only overwrite when our prior
        // name was the default protocol-uppercase fallback).
        name:
          prior.name && prior.name !== prior.protocol.toUpperCase()
            ? prior.name
            : deviceFresh.name || prior.name,
        groupId,
        lastSeenInSubscriptionAt: now,
        enabled: prior.enabled ?? true
      }
      merged.push(updated)
      updatedCount++
    } else if (!existingByKey.has(key) && !addedNewKeys.has(key)) {
      addedNewKeys.add(key)
      merged.push(vpnProfileToServerProfile(fresh, groupId, undefined, now, { clientDevice: device }))
      addedCount++
    } else {
      // The same connection tuple already exists in this group under another
      // device identity. Refresh the existing records in place, but avoid
      // materializing extra cross-device duplicates during a group refresh.
    }
  }

  // Profiles that were in the group but the upstream no longer lists.
  // Per spec: leave them alone (don't disable, don't delete, don't update
  // lastSeenInSubscriptionAt). We just count them for telemetry.
  let removedCount = 0
  for (const prior of inGroupExisting) {
    const key = profileTupleKey(prior)
    const profileDevice = normalizeClientDevice(options.clientDevice ?? prior.clientDevice ?? primaryDevice)
    const deviceKey = `${profileDevice}|${key}`
    if (seenDeviceKeys.has(deviceKey)) continue
    merged.push(prior)
    removedCount++
  }

  savePickerProfiles([...outOfGroup, ...merged])

  // The subscription answered with usable data. Default status is `active`,
  // but if the panel told us the trial already expired we honor that — the
  // UI must not say "Активна" while showing "Триал истёк 9 дней назад"
  // right next to it. Saved keys frequently keep working past the trial
  // boundary (providers don't revoke immediately), so `expired` is the
  // correct signal: "источник истёк, ключи могут работать".
  const expiresAt = userInfo?.expiresAt
  const trialAlreadyExpired =
    typeof expiresAt === 'number' && Number.isFinite(expiresAt) && expiresAt > 0 && expiresAt < now
  updateGroup(groupId, {
    status: trialAlreadyExpired ? 'expired' : 'active',
    lastFetchedAt: now,
    lastFetchAttemptAt: now,
    lastFetchError: null,
    lastRefreshProfilesCount: primaryResolved.profiles.length,
    trafficUploadBytes: userInfo?.trafficUploadBytes ?? undefined,
    trafficDownloadBytes: userInfo?.trafficDownloadBytes ?? undefined,
    trafficUsedBytes: userInfo?.trafficUsedBytes ?? undefined,
    trafficTotalBytes: userInfo?.trafficTotalBytes ?? undefined,
    expiresAt: userInfo?.expiresAt ?? undefined,
    refreshIntervalSeconds: userInfo?.refreshIntervalSeconds ?? undefined,
    webPageUrl: userInfo?.webPageUrl ?? undefined
  })

  logEvent('info', 'server-groups', 'group refreshed', {
    id: groupId,
    added: addedCount,
    updated: updatedCount,
    untouched: removedCount,
    total: primaryResolved.profiles.length
  })

  const refreshed = getGroup(groupId)!
  return { ok: true, group: refreshed, addedCount, updatedCount, removedCount }
}

// ─── Delete handler ─────────────────────────────────────────────────────────

/**
 * Removes a group, optionally also removing every profile that points to
 * it. When `deleteServers === false` we simply detach the profiles
 * (`groupId` cleared) — they end up "ungrouped" and the user can
 * re-assign them later.
 */
function deleteGroupAndProfiles(id: string, deleteServers: boolean): boolean {
  const group = getGroup(id)
  if (!group) return false

  const profiles = getPickerProfiles()
  const activeId = pickerStore.get('activeProfileId') ?? null
  let nextProfiles: ServerProfile[]

  if (deleteServers) {
    nextProfiles = profiles.filter(p => p.groupId !== id)
    // If the active profile was inside this group, drop the selection so
    // the picker auto-selects whatever's left on next read.
    if (activeId) {
      const activeStillExists = nextProfiles.some(p => p.id === activeId)
      if (!activeStillExists) pickerStore.set('activeProfileId', null)
    }
  } else {
    nextProfiles = profiles.map(p =>
      p.groupId === id ? { ...p, groupId: undefined } : p
    )
  }

  savePickerProfiles(nextProfiles)
  if (deleteServers && group.source === 'subscription' && group.sourceUrl) {
    try {
      const settings = settingsStore.get()
      const cached = settings.directVpnCachedInput?.trim()
      if (cached && canonicalizeSubscriptionUrl(cached) === canonicalizeSubscriptionUrl(group.sourceUrl)) {
        settingsStore.save({
          directVpnCachedInput: '',
          directVpnCachedSource: '',
          directVpnCachedAt: null,
          directVpnCachedProfiles: []
        })
      }
    } catch {
      /* best-effort legacy cache cleanup */
    }
  }
  deleteGroupRecord(id)

  logEvent('info', 'server-groups', 'group deleted', {
    id,
    deletedServers: deleteServers,
    affected: profiles.filter(p => p.groupId === id).length
  })
  return true
}

// ─── IPC handlers ───────────────────────────────────────────────────────────

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

export function registerServerGroupsHandlers(): void {
  handleLogged('groups:list', async () => {
    return getGroups()
  })

  handleLogged('groups:get', async (_event, id: string) => {
    return getGroup(id)
  })

  handleLogged('groups:rename', async (_event, id: string, name: string) => {
    const trimmed = String(name || '').trim().slice(0, 60)
    if (!trimmed) return null
    return updateGroup(id, { name: trimmed })
  })

  handleLogged('groups:delete', async (_event, id: string, deleteServers: boolean) => {
    const ok = deleteGroupAndProfiles(id, Boolean(deleteServers))
    return { ok }
  })

  handleLogged('groups:refresh', async (_event, id: string) => {
    return await refreshGroup(id)
  })

  // Health-check delegates to keyHealthChecker. Static `await import()`
  // so the bundler includes the module — earlier dynamic require() got
  // tree-shaken out by electron-vite and exploded in production with
  // "Cannot find module".
  //
  // checkGroupHealth ALREADY returns a discriminated union
  // ({ ok: true, results } | { ok: false, error }), so we forward it
  // verbatim. The renderer expects exactly that shape; double-wrapping
  // it makes `result.results` undefined on the renderer side and crashes
  // the React tree (black window).
  handleLogged('groups:check-health', async (_event, id: string) => {
    try {
      const { checkGroupHealth } = await import('./keyHealthChecker')
      if (typeof checkGroupHealth !== 'function') {
        return { ok: false as const, error: 'health checker недоступен' }
      }
      return await checkGroupHealth(id)
    } catch (err: any) {
      logEvent('warn', 'server-groups', 'check-health failed', err)
      return { ok: false as const, error: err?.message || 'health checker недоступен' }
    }
  })
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export const serverGroups = {
  getGroups,
  saveGroups,
  getGroup,
  updateGroup,
  deleteGroup: deleteGroupRecord,
  createGroup,
  findGroupBySourceUrl,
  ensureManualKeysGroup,
  refreshGroup,
  registerHandlers: registerServerGroupsHandlers
}

export {
  getGroups,
  getGroup,
  updateGroup,
  createGroup,
  findGroupBySourceUrl,
  ensureManualKeysGroup
}


