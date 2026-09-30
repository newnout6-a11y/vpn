import { persistRecoveryPolicy } from './recoveryManifest'
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
import {
  enableKillSwitch,
  disableKillSwitchIfActive,
  isKillSwitchActive,
  updateKillSwitchExceptions,
  canonicalizeExceptionAppPath,
  isValidIpOrCidr
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
let committedLevel = currentLevel
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
    if (!isValidIpOrCidr(raw)) throw new Error('exception.value must be a valid IP/CIDR; wildcard /0 and unspecified addresses are forbidden')
    const [address, prefix] = raw.split('/')
    return { type: 'ip', value: prefix === undefined ? address : `${address}/${Number(prefix)}`, label }
  }
  if (exception.type !== 'app') throw new Error('exception.type must be app or ip')
  return { type: 'app', value: await canonicalizeExceptionAppPath(raw), label }
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

  const result = await isKillSwitchActive()
    ? await updateKillSwitchExceptions(appExceptions, ipExceptions, currentLevel === 'strict')
    : await enableKillSwitch({
    singboxExePath,
    strictMode: currentLevel === 'strict',
    appExceptionPaths: appExceptions,
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
  throw new Error(`Failed to disengage kill-switch: ${result.message}`)
}

/**
 * Apply the kill-switch policy based on current level and VPN state.
 * Called when level changes or VPN state changes.
 */
async function applyPolicy(): Promise<void> {
  if (currentLevel === 'off') {
    await disengageKillSwitch('level set to off')
  } else {
    // Keep protection active while connected too: the next unexpected drop must
    // not race firewall activation, and strict->standard must not remove it.
    await engageKillSwitch(currentLevel === 'strict' ? 'Строгая защита вне VPN' : 'Стандартная защита при разрыве VPN')
  }
}
async function applyExceptionSet(next: KillSwitchException[]): Promise<boolean> {
  if (!(await isKillSwitchActive())) return false
  const result = await updateKillSwitchExceptions(next.filter(e => e.type === 'app').map(e => e.value), next.filter(e => e.type === 'ip').map(e => e.value), currentLevel === 'strict')
  if (!result.success) throw new Error(result.message)
  return true
}
async function commitExceptionSet(next: KillSwitchException[]): Promise<void> {
  const previous = exceptions
  const applied = await applyExceptionSet(next)
  try { store.set('killSwitchExceptions', next) }
  catch (error) {
    if (applied) {
      try { await applyExceptionSet(previous) }
      catch { sendNotification('Обновление и компенсация исключений не подтверждены', 'Core-защита сохранена. Проверьте firewall и повторите операцию.'); throw new Error('Exception persistence and system compensation failed') }
    }
    throw error
  }
  exceptions = next
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
    committedLevel = currentLevel
    exceptions = store.get('killSwitchExceptions', [])

    // Sync with legacy setting on startup. If they disagree, the legacy
    // setting wins (because that's what tunController.start() reads).
    // Only happens when user upgraded from a version that only had the
    // legacy boolean.
    try {
      const legacyEnabled = settingsStore.get().firewallKillSwitch
      const granularEnabled = currentLevel !== 'off'
      if (currentLevel !== 'strict' && legacyEnabled !== granularEnabled) {
        currentLevel = legacyEnabled ? 'standard' : 'off'
        store.set('killSwitchLevel', currentLevel)
        logEvent('info', 'granular-kill-switch', 'synced level from legacy setting', {
          legacyEnabled, newLevel: currentLevel
        })
      }
    } catch (err) {
      logEvent('warn', 'granular-kill-switch', 'startup sync failed', err)
    }

    committedLevel = currentLevel
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
    return committedLevel
  },

  /**
   * Re-read level + exceptions from the store into the in-memory cache. Used
   * after a settings import overwrites the granular-kill-switch store so the
   * live service reflects the imported values without an app restart.
   */
  reloadFromStore(): void {
    currentLevel = store.get('killSwitchLevel', 'off')
    committedLevel = currentLevel
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
    return serializeExceptionMutation(async () => {
      if (!['off','standard','strict'].includes(level)) throw new Error('Invalid kill-switch level')
      if (!initialized && level !== 'off') throw new Error('Cannot enable kill-switch before sing-box path is initialized')
      const previousLevel = currentLevel
      // Enter strict before privileged effects; leave it only after success.
      if (process.platform === 'win32' && level === 'strict') await persistRecoveryPolicy(true)
      currentLevel = level
      try {
        await applyPolicy()
        settingsStore.save({ firewallKillSwitch: level !== 'off' })
        store.set('killSwitchLevel', level)
        if (process.platform === 'win32') await persistRecoveryPolicy(level === 'strict')
        committedLevel = level
        logEvent('info', 'granular-kill-switch', 'level committed after verified firewall operation', { previousLevel, level })
      } catch (error) {
        currentLevel = previousLevel
        const failures: string[] = []
        // Independent compensation: a failing system step cannot suppress store
        // restoration or hide the fact that strict protection is uncertain.
        try { await applyPolicy() } catch { failures.push('firewall compensation') }
        try { store.set('killSwitchLevel', previousLevel) } catch { failures.push('level persistence') }
        try { settingsStore.save({ firewallKillSwitch: previousLevel !== 'off' }) } catch { failures.push('legacy setting persistence') }
        if (process.platform === 'win32') {
          try { await persistRecoveryPolicy(previousLevel === 'strict' || failures.length > 0) } catch { failures.push('trusted recovery policy') }
        }
        if (failures.length) sendNotification('Изменение уровня защиты не подтверждено', failures.join(', '))
        logEvent('error', 'granular-kill-switch', 'level transition failed', { failures })
        throw error
      }
    })
  },

  /**
   * Get the current exception list.
   */
  getExceptions(): KillSwitchException[] {
    return exceptions.map(e => ({ ...e }))
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
      const entry: KillSwitchException = { id: randomUUID(), ...validated }
      await commitExceptionSet([...exceptions, entry])
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
      const removed = exceptions[index]
      await commitExceptionSet(exceptions.filter(item => item.id !== id))
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
