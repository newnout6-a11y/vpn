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
import { resolveVpnProfiles, type VpnProfile } from './vpnProfiles'
import { settingsStore } from './settings'
import type { ServerGroup, ServerProfile } from '../shared/ipc-types'

// ─── Persistent Store ────────────────────────────────────────────────────────

interface ServerGroupsStore {
  groups: ServerGroup[]
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

function getGroups(): ServerGroup[] {
  return store.get('groups') ?? []
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
 * Find an existing group whose `sourceUrl` matches the given URL. Used to
 * dedupe "user re-pasted the same subscription" — we treat that as a
 * refresh of the existing group rather than creating a duplicate.
 */
function findGroupBySourceUrl(url: string): ServerGroup | null {
  const trimmed = url.trim()
  if (!trimmed) return null
  return getGroups().find(
    g => g.source === 'subscription' && g.sourceUrl === trimmed
  ) ?? null
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
 * Stable identity key for dedupe-merging across refreshes. We prefer the
 * exact `sourceUri` (lossless, survives panel-side renames) and fall back
 * to the connection tuple when the source URI isn't available — the latter
 * happens for legacy profiles imported before we started tracking
 * `sourceUri`.
 */
function profileKey(p: { sourceUri?: string; server: string; port: number; protocol: string }): string {
  if (p.sourceUri) return `uri:${p.sourceUri}`
  return `tuple:${p.server}|${p.port}|${p.protocol}`
}

function vpnProfileKey(p: VpnProfile, uri?: string): string {
  if (uri) return `uri:${uri}`
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
  now: number
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
  groupId: string
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
  try {
    const settings = settingsStore.get()
    proxyAddr = settings.proxyOverride?.trim() || undefined
    proxyType = settings.proxyType
  } catch {
    /* fall through with no proxy override */
  }

  let resolved: Awaited<ReturnType<typeof resolveVpnProfiles>>
  try {
    resolved = await resolveVpnProfiles(group.sourceUrl, { proxyAddr, proxyType })
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

  if (!resolved.profiles.length) {
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
  const userInfo = resolved.userInfo

  // Dedupe-merge against the existing profiles. We keep stable IDs for
  // anything we recognise (so the user's "active profile" pointer doesn't
  // jump after a refresh), and append new profiles unchanged.
  const existing = getPickerProfiles()
  const inGroupExisting = existing.filter(p => p.groupId === groupId)
  const outOfGroup = existing.filter(p => p.groupId !== groupId)
  const existingByKey = new Map<string, ServerProfile>()
  for (const p of inGroupExisting) existingByKey.set(profileKey(p), p)

  let addedCount = 0
  let updatedCount = 0
  const merged: ServerProfile[] = []
  const seenKeys = new Set<string>()

  for (const fresh of resolved.profiles) {
    // The resolver doesn't give us per-profile sourceUris back, but for
    // single-key inputs we could backfill from the input itself. The
    // subscription-URL case has no per-line URI handy here, so we rely on
    // the connection-tuple key — same behaviour as the legacy code.
    const key = vpnProfileKey(fresh)
    if (seenKeys.has(key)) continue
    seenKeys.add(key)

    const prior = existingByKey.get(key)
    if (prior) {
      // Found a match — keep its id, update only the fields the upstream
      // can legitimately change. We deliberately do NOT touch user-edited
      // fields like `enabled`, `country`, or `ping`.
      const updated: ServerProfile = {
        ...prior,
        // Refresh outbound: providers occasionally rotate Reality keys or
        // switch transports.
        outbound: fresh.outbound,
        protocol: fresh.protocol,
        server: fresh.outbound?.server || prior.server,
        port: fresh.outbound?.server_port || prior.port,
        // Update the human-readable name only if the upstream now has one
        // and the user hasn't overridden it (we have no way to know if
        // they did, so we conservatively only overwrite when our prior
        // name was the default protocol-uppercase fallback).
        name:
          prior.name && prior.name !== prior.protocol.toUpperCase()
            ? prior.name
            : fresh.name || prior.name,
        groupId,
        lastSeenInSubscriptionAt: now,
        enabled: prior.enabled ?? true
      }
      merged.push(updated)
      updatedCount++
    } else {
      merged.push(vpnProfileToServerProfile(fresh, groupId, undefined, now))
      addedCount++
    }
  }

  // Profiles that were in the group but the upstream no longer lists.
  // Per spec: leave them alone (don't disable, don't delete, don't update
  // lastSeenInSubscriptionAt). We just count them for telemetry.
  let removedCount = 0
  for (const prior of inGroupExisting) {
    if (!seenKeys.has(profileKey(prior))) {
      merged.push(prior)
      removedCount++
    }
  }

  savePickerProfiles([...outOfGroup, ...merged])

  updateGroup(groupId, {
    status: 'active',
    lastFetchedAt: now,
    lastFetchAttemptAt: now,
    lastFetchError: null,
    lastRefreshProfilesCount: resolved.profiles.length,
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
    total: resolved.profiles.length
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

  // Health-check delegates to keyHealthChecker (Agent C). The require() is
  // wrapped in try/catch so we don't crash if Agent C's branch hasn't been
  // merged yet — the UI just gets a friendly error.
  handleLogged('groups:check-health', async (_event, id: string) => {
    try {
      // Dynamic require so a missing module doesn't blow up app startup.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require('./keyHealthChecker') as {
        checkGroupHealth?: (
          groupId: string
        ) => Promise<Array<{ profileId: string; online: boolean; latencyMs: number | null; reason?: string }>>
      }
      if (typeof mod.checkGroupHealth !== 'function') {
        return { ok: false as const, error: 'health checker недоступен' }
      }
      const results = await mod.checkGroupHealth(id)
      return { ok: true as const, results }
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
