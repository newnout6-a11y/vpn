/**
 * Profile Rotation Service — timer-based automatic profile cycling.
 *
 * Responsibilities:
 * - Cycle through VPN profiles on a configurable timer interval
 * - Clamp interval to [5, 1440] minutes
 * - Support sequential and random rotation order
 * - Skip unavailable profiles and find the next available one
 * - Persist rotation config in electron-store
 * - Register IPC handlers for all RotationChannels
 *
 * Exports pure functions `clampInterval` and `getNextAvailableProfile` for testing.
 */

import { ipcMain, type IpcMainInvokeEvent } from 'electron'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import { serverPicker, pingServer } from './serverPicker'
import type { RotationConfig } from '../shared/ipc-types'

// ─── Constants ───────────────────────────────────────────────────────────────

const MIN_INTERVAL_MINUTES = 5
const MAX_INTERVAL_MINUTES = 1440

// ─── Pure Functions (exported for testing) ───────────────────────────────────

/**
 * Clamps a rotation interval value to the valid range [5, 1440] minutes.
 * Values below 5 become 5, values above 1440 become 1440, values within range
 * are preserved unchanged.
 */
export function clampInterval(value: number): number {
  if (!Number.isFinite(value)) return MIN_INTERVAL_MINUTES
  if (value < MIN_INTERVAL_MINUTES) return MIN_INTERVAL_MINUTES
  if (value > MAX_INTERVAL_MINUTES) return MAX_INTERVAL_MINUTES
  return value
}

/**
 * Finds the next available profile based on the rotation config and availability map.
 *
 * In sequential mode: returns the nearest available profile after the current index
 * (wrapping around the list). In random mode: picks a random available profile
 * different from the current one.
 *
 * Returns the profile ID if found, or null if no profiles are available.
 */
export function getNextAvailableProfile(
  config: RotationConfig,
  availabilityMap: Record<string, boolean>
): string | null {
  const { profileIds, currentIndex, order } = config

  if (!profileIds || profileIds.length === 0) return null

  if (order === 'sequential') {
    // Try each profile starting from the one after currentIndex, wrapping around
    const len = profileIds.length
    for (let offset = 1; offset <= len; offset++) {
      const idx = (currentIndex + offset) % len
      const profileId = profileIds[idx]
      if (availabilityMap[profileId]) {
        return profileId
      }
    }
    return null
  }

  // Random order: pick a random available profile different from current
  const currentProfileId = profileIds[currentIndex] ?? null
  const availableIds = profileIds.filter(
    (id) => availabilityMap[id] && id !== currentProfileId
  )

  if (availableIds.length === 0) {
    // If only the current profile is available, allow it
    if (currentProfileId && availabilityMap[currentProfileId]) {
      return currentProfileId
    }
    return null
  }

  const randomIdx = Math.floor(Math.random() * availableIds.length)
  return availableIds[randomIdx]
}

// ─── Persistent Store ────────────────────────────────────────────────────────

interface RotationStore {
  rotation: RotationConfig
}

const defaultConfig: RotationConfig = {
  enabled: false,
  intervalMinutes: 30,
  order: 'sequential',
  profileIds: [],
  currentIndex: 0,
  nextRotationAt: null
}

const store = new Store<RotationStore>({
  name: 'profile-rotation',
  defaults: {
    rotation: defaultConfig
  }
})

// ─── Timer State ─────────────────────────────────────────────────────────────

let rotationTimer: ReturnType<typeof setTimeout> | null = null

// ─── Config Access ───────────────────────────────────────────────────────────

function getConfig(): RotationConfig {
  const config = store.get('rotation') ?? defaultConfig
  return {
    ...defaultConfig,
    ...config,
    intervalMinutes: clampInterval(config.intervalMinutes ?? defaultConfig.intervalMinutes)
  }
}

function saveConfig(config: RotationConfig): void {
  store.set('rotation', config)
}

// ─── Availability Check ──────────────────────────────────────────────────────

/**
 * Builds an availability map for the given profile IDs by pinging each server.
 */
async function buildAvailabilityMap(profileIds: string[]): Promise<Record<string, boolean>> {
  const profiles = serverPicker.getProfiles()
  const map: Record<string, boolean> = {}

  for (const id of profileIds) {
    const profile = profiles.find((p) => p.id === id)
    if (!profile) {
      map[id] = false
      continue
    }

    // Use cached status if recently checked (within last 2 minutes)
    if (profile.lastChecked && Date.now() - profile.lastChecked < 120_000) {
      map[id] = profile.status === 'online'
      continue
    }

    // Ping the server
    const latency = await pingServer(profile.server, profile.port)
    map[id] = latency !== null
  }

  return map
}

// ─── Rotation Logic ──────────────────────────────────────────────────────────

/**
 * Performs the actual rotation: finds the next available profile and switches to it.
 */
async function performRotation(): Promise<{ success: boolean; newProfile: string }> {
  const config = getConfig()

  if (config.profileIds.length === 0) {
    logEvent('warn', 'profile-rotation', 'no profiles configured for rotation')
    return { success: false, newProfile: '' }
  }

  const availabilityMap = await buildAvailabilityMap(config.profileIds)
  const nextProfileId = getNextAvailableProfile(config, availabilityMap)

  if (!nextProfileId) {
    logEvent('warn', 'profile-rotation', 'no available profiles for rotation')
    scheduleNextRotation(config)
    return { success: false, newProfile: '' }
  }

  // Update current index
  const newIndex = config.profileIds.indexOf(nextProfileId)
  const updatedConfig: RotationConfig = {
    ...config,
    currentIndex: newIndex >= 0 ? newIndex : config.currentIndex
  }

  // Switch the active profile using serverPicker
  serverPicker.selectProfile(nextProfileId)

  logEvent('info', 'profile-rotation', 'rotated to new profile', {
    profileId: nextProfileId,
    index: updatedConfig.currentIndex
  })

  // Schedule next rotation
  scheduleNextRotation(updatedConfig)
  saveConfig(updatedConfig)

  return { success: true, newProfile: nextProfileId }
}

// ─── Timer Management ────────────────────────────────────────────────────────

function stopTimer(): void {
  if (rotationTimer !== null) {
    clearTimeout(rotationTimer)
    rotationTimer = null
  }
}

function scheduleNextRotation(config: RotationConfig): void {
  stopTimer()

  if (!config.enabled || config.profileIds.length === 0) {
    const updatedConfig = { ...config, nextRotationAt: null }
    saveConfig(updatedConfig)
    return
  }

  const intervalMs = clampInterval(config.intervalMinutes) * 60 * 1000
  const nextRotationAt = Date.now() + intervalMs

  const updatedConfig = { ...config, nextRotationAt }
  saveConfig(updatedConfig)

  rotationTimer = setTimeout(async () => {
    await performRotation()
  }, intervalMs)

  logEvent('debug', 'profile-rotation', 'next rotation scheduled', {
    intervalMinutes: config.intervalMinutes,
    nextRotationAt: new Date(nextRotationAt).toISOString()
  })
}

/**
 * Starts or restarts the rotation timer based on current config.
 */
function startRotation(): void {
  const config = getConfig()
  if (config.enabled) {
    scheduleNextRotation(config)
  } else {
    stopTimer()
  }
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
 * Registers all profile rotation IPC handlers.
 * Should be called once during app initialization.
 */
export function registerRotationHandlers(): void {
  handleLogged('rotation:get-config', async () => {
    return getConfig()
  })

  handleLogged('rotation:set-config', async (_event, partial: Partial<RotationConfig>) => {
    const current = getConfig()
    const updated: RotationConfig = {
      ...current,
      ...partial,
      // Always clamp the interval
      intervalMinutes: clampInterval(
        partial.intervalMinutes ?? current.intervalMinutes
      )
    }

    saveConfig(updated)

    // Restart timer if enabled state or interval changed
    if (
      partial.enabled !== undefined ||
      partial.intervalMinutes !== undefined ||
      partial.profileIds !== undefined
    ) {
      if (updated.enabled) {
        scheduleNextRotation(updated)
      } else {
        stopTimer()
        saveConfig({ ...updated, nextRotationAt: null })
      }
    }

    logEvent('info', 'profile-rotation', 'config updated', {
      enabled: updated.enabled,
      intervalMinutes: updated.intervalMinutes,
      order: updated.order,
      profileCount: updated.profileIds.length
    })

    return getConfig()
  })

  handleLogged('rotation:rotate-now', async () => {
    return await performRotation()
  })
}

// ─── Initialization ──────────────────────────────────────────────────────────

/**
 * Initializes the profile rotation service.
 * Starts the timer if rotation is enabled.
 */
export function initProfileRotation(): void {
  startRotation()
  logEvent('info', 'profile-rotation', 'service initialized', {
    enabled: getConfig().enabled
  })
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export const profileRotation = {
  getConfig,
  initProfileRotation,
  registerHandlers: registerRotationHandlers,
  stopTimer
}
