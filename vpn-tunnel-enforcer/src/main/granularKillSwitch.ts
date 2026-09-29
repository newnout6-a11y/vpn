/**
 * Granular Kill-Switch Service
 *
 * Extends the existing firewallKillSwitch with three levels:
 *  - off: no blocking, kill-switch disabled
 *  - standard: block all traffic when VPN drops (existing behavior)
 *  - strict: block all non-VPN traffic always, regardless of VPN state
 *
 * Also manages an exception list (app paths and IP/CIDR ranges) that are
 * allowed through even when the kill-switch is active.
 *
 * Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5
 */

import { ipcMain, BrowserWindow, dialog, type IpcMainInvokeEvent } from 'electron'
import Store from 'electron-store'
import { randomUUID } from 'crypto'
import { access, realpath } from 'fs/promises'
import { constants as fsConstants } from 'fs'
import { isIP } from 'net'
import {
  enableKillSwitch,
  disableKillSwitchIfActive,
  isKillSwitchActive
} from './firewallKillSwitch'
import { logEvent } from './appLogger'
import { requireEnum, requirePlainObject, requireString } from './ipcValidation'
import { notify } from './notifications'
import { settingsStore } from './settings'
import { tunController } from './tunController'
import type { KillSwitchLevel, KillSwitchException } from '../shared/ipc-types'

// ─── Persistent Store ────────────────────────────────────────────────────────

interface GranularKillSwitchStore {
  killSwitchLevel: KillSwitchLevel
  killSwitchExceptions: KillSwitchException[]
}

const store = new Store<GranularKillSwitchStore>({
  name: 'granular-kill-switch',
  defaults: {
    killSwitchLevel: 'off',
    killSwitchExceptions: []
  }
})

// ─── State ───────────────────────────────────────────────────────────────────

let currentLevel: KillSwitchLevel = store.get('killSwitchLevel', 'off')
let exceptions: KillSwitchException[] = store.get('killSwitchExceptions', [])
let vpnConnected = false
let singboxExePath: string | null = null
let initialized = false
let exceptionMutationQueue: Promise<unknown> = Promise.resolve()

function isVpnConnected(): boolean {
  if (vpnConnected) return true
  if (tunController && typeof tunController.getStatus === 'function') {
    try {
      return Boolean(tunController.getStatus().running)
    } catch {
      // fallback
    }
  }
  return false
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getMainWindow(): BrowserWindow | null {
  const focused = BrowserWindow.getFocusedWindow?.()
  if (focused && !focused.isDestroyed()) return focused
  return BrowserWindow.getAllWindows().find((win) => !win.isDestroyed()) ?? null
}

function sendNotification(reason: string, steps: string): void {
  // Send to renderer for in-app notification
  const win = getMainWindow()
  if (win && !win.isDestroyed()) {
    try {
      win.webContents.send('kill-switch:traffic-blocked', { reason, steps })
    } catch {
      // Window might be closing
    }
  }

  // Also send a system notification
  notify('warn', 'Kill-Switch: трафик заблокирован', `${reason}\n${steps}`, 'connectionError')
}

function getExceptionAppPaths(): string[] {
  return exceptions
    .filter((e) => e.type === 'app')
    .map((e) => e.value)
}

function getExceptionIpCidrs(): string[] {
  return exceptions
    .filter((e) => e.type === 'ip')
    .map((e) => e.value)
}

export async function validateKillSwitchException(
  exception: Omit<KillSwitchException, 'id'>
): Promise<Omit<KillSwitchException, 'id'>> {
  const label = String(exception.label ?? '').trim()
  if (!label || label.length > 200) throw new Error('exception.label must contain 1-200 characters')
  const raw = String(exception.value ?? '').trim()
  if (!raw || raw.length > 2048) throw new Error('exception.value must contain 1-2048 characters')

  if (exception.type === 'ip') {
    const [address, prefix, extra] = raw.split('/')
    if (extra !== undefined || !isIP(address)) throw new Error('exception.value must be a valid IP or CIDR')
    if (prefix !== undefined) {
      if (!/^\d+$/.test(prefix)) throw new Error('exception.value contains an invalid CIDR prefix')
      const bits = Number(prefix)
      const maximum = isIP(address) === 4 ? 32 : 128
      if (bits < 0 || bits > maximum) throw new Error(`exception.value CIDR prefix must be 0-${maximum}`)
    }
    return { type: 'ip', value: prefix === undefined ? address : `${address}/${Number(prefix)}`, label }
  }

  if (exception.type !== 'app') throw new Error('exception.type must be app or ip')
  if (!/\.exe$/i.test(raw)) throw new Error('exception.value must point to an .exe file')
  if (process.platform === 'win32' && !/^(?:[a-z]:\\|\\\\)/i.test(raw)) {
    throw new Error('exception.value must be an absolute Windows path')
  }
  await access(raw, fsConstants.R_OK)
  const canonical = await realpath(raw)
  if (!/\.exe$/i.test(canonical)) throw new Error('canonical exception path must point to an .exe file')
  return { type: 'app', value: canonical, label }
}

function serializeExceptionMutation<T>(operation: () => Promise<T>): Promise<T> {
  const next = exceptionMutationQueue.then(operation, operation)
  exceptionMutationQueue = next.then(() => undefined, () => undefined)
  return next
}

// ─── Core Logic ──────────────────────────────────────────────────────────────

/**
 * Engage the firewall kill-switch based on current level and VPN state.
 * Returns true if the kill-switch was successfully engaged.
 */
async function engageKillSwitch(reason: string): Promise<boolean> {
  if (!singboxExePath) {
    logEvent('warn', 'granular-kill-switch', 'cannot engage kill-switch: singboxExePath not set')
    throw new Error('Cannot engage kill-switch before sing-box path is initialized')
  }

  const appExceptions = getExceptionAppPaths()
  const ipExceptions = getExceptionIpCidrs()

  const result = await enableKillSwitch({
    singboxExePath,
    proxyOwnerProgramPaths: appExceptions.length > 0 ? appExceptions : undefined,
    extraAllowedRemoteCidrs: ipExceptions.length > 0 ? ipExceptions : undefined
  })

  if (result.success) {
    logEvent('info', 'granular-kill-switch', `kill-switch engaged: ${reason}`, {
      level: currentLevel,
      exceptions: exceptions.length
    })

    sendNotification(
      reason,
      currentLevel === 'strict'
        ? 'Строгий режим: весь трафик вне VPN заблокирован. Подключите VPN или переключите kill-switch в стандартный/выключенный режим.'
        : 'Стандартный режим: трафик заблокирован из-за обрыва VPN. Переподключите VPN или отключите kill-switch.'
    )
    return true
  }

  logEvent('error', 'granular-kill-switch', `failed to engage kill-switch: ${result.message}`, {
    details: result.details
  })
  throw new Error(`Failed to engage kill-switch: ${result.message}`)
}

/**
 * Disengage the firewall kill-switch.
 */
async function disengageKillSwitch(reason: string): Promise<boolean> {
  const result = await disableKillSwitchIfActive(reason)
  if (result.success) {
    logEvent('info', 'granular-kill-switch', `kill-switch disengaged: ${reason}`)
    return true
  }
  logEvent('error', 'granular-kill-switch', `failed to disengage kill-switch: ${result.message}`)
  return false
}

/**
 * Apply the kill-switch policy based on current level and VPN state.
 * Called when level changes or VPN state changes.
 */
async function applyPolicy(): Promise<void> {
  switch (currentLevel) {
    case 'off':
      // Disable kill-switch if it's currently active
      await disengageKillSwitch('level set to off')
      break

    case 'standard':
      if (isVpnConnected()) {
        // VPN is connected — no need for kill-switch in standard mode
        // (it will be engaged by onVpnDisconnected when VPN drops)
        // But if it's currently active from a previous strict mode, disengage
        if (await isKillSwitchActive()) {
          await disengageKillSwitch('standard mode: VPN is connected')
        }
      } else {
        // VPN is not connected — engage kill-switch
        await engageKillSwitch('VPN-соединение отсутствует (стандартный режим)')
      }
      break

    case 'strict':
      if (isVpnConnected()) {
        // VPN is connected — in strict mode, traffic goes through VPN anyway
        // The kill-switch should still be active to prevent any bypass
        if (!(await isKillSwitchActive())) {
          await engageKillSwitch('Строгий режим: блокировка трафика вне VPN')
        }
      } else {
        // VPN is not connected — block everything
        await engageKillSwitch('Строгий режим: VPN не подключён, весь трафик заблокирован')
      }
      break
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const granularKillSwitch = {
  /**
   * Initialize the service. Must be called once at app startup.
   * @param exePath Path to the sing-box executable
   */
  init(exePath: string): void {
    singboxExePath = exePath
    initialized = true
    currentLevel = store.get('killSwitchLevel', 'off')
    exceptions = store.get('killSwitchExceptions', [])

    // Sync with legacy setting on startup. If they disagree, the legacy
    // setting wins (because that's what tunController.start() reads).
    // Only happens when user upgraded from a version that only had the
    // legacy boolean.
    try {
      const legacyEnabled = settingsStore.get().firewallKillSwitch
      const granularEnabled = currentLevel !== 'off'
      if (legacyEnabled !== granularEnabled) {
        currentLevel = legacyEnabled ? 'standard' : 'off'
        store.set('killSwitchLevel', currentLevel)
        logEvent('info', 'granular-kill-switch', 'synced level from legacy setting', {
          legacyEnabled, newLevel: currentLevel
        })
      }
    } catch (err) {
      logEvent('warn', 'granular-kill-switch', 'startup sync failed', err)
    }

    logEvent('info', 'granular-kill-switch', 'initialized', {
      level: currentLevel,
      exceptions: exceptions.length,
      singboxExePath: exePath
    })
  },

  setVpnConnected(connected: boolean): void {
    vpnConnected = connected
  },

  isVpnConnected(): boolean {
    return isVpnConnected()
  },

  /**
   * Get the current kill-switch level.
   */
  getLevel(): KillSwitchLevel {
    return currentLevel
  },

  /**
   * Re-read level + exceptions from the store into the in-memory cache. Used
   * after a settings import overwrites the granular-kill-switch store so the
   * live service reflects the imported values without an app restart.
   */
  reloadFromStore(): void {
    currentLevel = store.get('killSwitchLevel', 'off')
    exceptions = store.get('killSwitchExceptions', [])
    logEvent('info', 'granular-kill-switch', 'reloaded from store after import', {
      level: currentLevel,
      exceptions: exceptions.length
    })
  },

  /**
   * Set the kill-switch level and apply the policy.
   */
  async setLevel(level: KillSwitchLevel): Promise<void> {
    if (!initialized && level !== 'off') {
      throw new Error('Cannot enable kill-switch before sing-box path is initialized')
    }
    const previousLevel = currentLevel
    currentLevel = level
    store.set('killSwitchLevel', level)

    // Sync the legacy boolean in app settings so tunController.start() picks
    // up the change. 'off' → false, anything else → true.
    try {
      settingsStore.save({ firewallKillSwitch: level !== 'off' })
    } catch (err) {
      logEvent('warn', 'granular-kill-switch', 'failed to sync legacy firewallKillSwitch setting', err)
    }

    logEvent('info', 'granular-kill-switch', `level changed: ${previousLevel} → ${level}`)
    try {
      await applyPolicy()
    } catch (err) {
      currentLevel = previousLevel
      store.set('killSwitchLevel', previousLevel)
      try {
        settingsStore.save({ firewallKillSwitch: previousLevel !== 'off' })
      } catch (rollbackErr) {
        logEvent('warn', 'granular-kill-switch', 'failed to roll back legacy firewallKillSwitch setting', rollbackErr)
      }
      logEvent('error', 'granular-kill-switch', `level change rolled back: failed to apply ${level}`, err)
      throw err
    }
  },

  /**
   * Get the current exception list.
   */
  getExceptions(): KillSwitchException[] {
    return [...exceptions]
  },

  /**
   * Add an exception to the list.
   */
  async addException(exception: Omit<KillSwitchException, 'id'>): Promise<KillSwitchException> {
    return serializeExceptionMutation(async () => {
      const validated = await validateKillSwitchException(exception)
      const duplicate = exceptions.find(item =>
        item.type === validated.type &&
        item.value.toLowerCase() === validated.value.toLowerCase()
      )
      if (duplicate) throw new Error('An equivalent kill-switch exception already exists')
      const previous = [...exceptions]
      const entry: KillSwitchException = { id: randomUUID(), ...validated }
      exceptions = [...exceptions, entry]
      store.set('killSwitchExceptions', exceptions)
      try {
        if (await isKillSwitchActive()) await engageKillSwitch('active exception list updated')
      } catch (error) {
        exceptions = previous
        store.set('killSwitchExceptions', exceptions)
        throw error
      }
      logEvent('info', 'granular-kill-switch', 'exception added and synchronized', {
        id: entry.id, type: entry.type, value: entry.value, label: entry.label
      })
      return entry
    })
  },

  /**
   * Remove an exception from the list by ID.
   */
  async removeException(id: string): Promise<void> {
    return serializeExceptionMutation(async () => {
      const index = exceptions.findIndex((e) => e.id === id)
      if (index === -1) throw new Error(`Kill-switch exception not found: ${id}`)
      const previous = [...exceptions]
      const removed = exceptions[index]
      exceptions = exceptions.filter(item => item.id !== id)
      store.set('killSwitchExceptions', exceptions)
      try {
        if (await isKillSwitchActive()) await engageKillSwitch('active exception list updated')
      } catch (error) {
        exceptions = previous
        store.set('killSwitchExceptions', exceptions)
        throw error
      }
      logEvent('info', 'granular-kill-switch', 'exception removed and synchronized', {
        id: removed.id, type: removed.type, value: removed.value
      })
    })
  }
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

function compactForLog(value: unknown): string {
  try {
    const raw = JSON.stringify(value)
    if (!raw) return ''
    return raw.length > 2000 ? `${raw.slice(0, 2000)}...<truncated>` : raw
  } catch {
    return String(value)
  }
}

function handleLogged<T>(
  channel: string,
  listener: (event: IpcMainInvokeEvent, ...args: any[]) => Promise<T> | T
): void {
  ipcMain.handle(channel, async (event, ...args) => {
    const started = Date.now()
    logEvent('debug', 'ipc', `${channel} started`, { args: compactForLog(args) })
    try {
      const result = await listener(event, ...args)
      logEvent('debug', 'ipc', `${channel} finished`, {
        ms: Date.now() - started,
        result: compactForLog(result)
      })
      return result
    } catch (err) {
      logEvent('error', 'ipc', `${channel} failed`, err)
      throw err
    }
  })
}

/**
 * Register all IPC handlers for KillSwitchChannels.
 * Should be called once during app initialization.
 */
export function registerKillSwitchIpc(): void {
  handleLogged('kill-switch:get-level', async () => {
    return granularKillSwitch.getLevel()
  })

  handleLogged('kill-switch:set-level', async (_e, level: KillSwitchLevel) => {
    level = requireEnum(level, 'level', ['off', 'standard', 'strict'])
    await granularKillSwitch.setLevel(level)
    return { success: true, level }
  })

  handleLogged('kill-switch:get-exceptions', async () => {
    return granularKillSwitch.getExceptions()
  })

  handleLogged('kill-switch:add-exception', async (_e, exception: Omit<KillSwitchException, 'id'>) => {
    const raw = requirePlainObject(exception, 'exception')
    return await granularKillSwitch.addException({
      type: requireEnum(raw.type, 'exception.type', ['app', 'ip']),
      value: requireString(raw.value, 'exception.value', { maxLength: 2048 }),
      label: requireString(raw.label, 'exception.label', { maxLength: 200 })
    })
  })

  handleLogged('kill-switch:remove-exception', async (_e, id: string) => {
    id = requireString(id, 'id', { maxLength: 200 })
    await granularKillSwitch.removeException(id)
    return { success: true }
  })

  handleLogged('kill-switch:browse-app', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog({
      title: 'Select executable',
      filters: [{ name: 'Executables', extensions: ['exe'] }],
      properties: ['openFile']
    })
    if (canceled || filePaths.length === 0) return null
    const filePath = filePaths[0]
    const name = filePath.split(/[\\/]/).pop()?.replace(/\.exe$/i, '') || filePath
    return { path: filePath, name }
  })
}
