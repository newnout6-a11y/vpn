/**
 * Notification Preferences Service — main process module for managing notification settings.
 *
 * Responsibilities:
 * - Stores NotificationPreferences in electron-store with sensible defaults
 * - Provides `shouldNotify(prefs, eventType)` — pure function checking if a given event is enabled
 * - Provides `dispatchNotification(eventType, title, body)` — sends notification respecting prefs:
 *   - 'system' → Windows toast via existing notifications.ts
 *   - 'inapp' → IPC event to renderer for in-app toast
 *   - 'both' → does both
 * - Registers IPC handlers for NotificationChannels:
 *   - 'notifications:get-prefs' → returns current preferences
 *   - 'notifications:set-prefs' → updates preferences (partial merge)
 *
 * Requirements: 17.1, 17.2, 17.3, 17.4, 17.5
 */

import { ipcMain, BrowserWindow } from 'electron'
import Store from 'electron-store'
import { notify } from './notifications'
import type { NotificationPreferences } from '../shared/ipc-types'

// ─── Event type mapping ──────────────────────────────────────────────────────

/** All supported notification event types */
export type NotificationEventType =
  | 'vpnConnect'
  | 'vpnDisconnect'
  | 'leakDetected'
  | 'profileRotation'
  | 'scheduleTriggered'
  | 'connectionError'

// ─── Defaults ────────────────────────────────────────────────────────────────

const DEFAULT_PREFS: NotificationPreferences = {
  vpnConnect: true,
  vpnDisconnect: true,
  leakDetected: true,
  profileRotation: true,
  scheduleTriggered: true,
  connectionError: true,
  method: 'system',
  sound: true
}

// ─── Store ───────────────────────────────────────────────────────────────────

interface NotificationPrefsStoreSchema {
  notificationPrefs: NotificationPreferences
}

const prefsStore = new Store<NotificationPrefsStoreSchema>({
  name: 'notification-prefs',
  defaults: {
    notificationPrefs: DEFAULT_PREFS
  }
})

// ─── Pure functions (exported for property testing) ──────────────────────────

/**
 * Pure function: checks whether a notification should be sent for the given event type.
 * Returns true if the preference for that event type is enabled.
 */
export function shouldNotify(prefs: NotificationPreferences, eventType: NotificationEventType): boolean {
  return Boolean(prefs[eventType])
}

// ─── Internal helpers ────────────────────────────────────────────────────────

function getPrefs(): NotificationPreferences {
  const stored = prefsStore.get('notificationPrefs')
  // Merge with defaults to handle any missing keys from older versions
  return { ...DEFAULT_PREFS, ...stored }
}

function setPrefs(partial: Partial<NotificationPreferences>): NotificationPreferences {
  const current = getPrefs()
  const updated: NotificationPreferences = { ...current, ...partial }
  prefsStore.set('notificationPrefs', updated)
  return updated
}

// ─── Dispatch logic ──────────────────────────────────────────────────────────

/**
 * Dispatches a notification for the given event type, respecting user preferences.
 * - If the event type is disabled in preferences, does nothing.
 * - Uses the configured method ('system', 'inapp', or 'both') to deliver.
 */
export function dispatchNotification(
  eventType: NotificationEventType,
  title: string,
  body: string
): void {
  const prefs = getPrefs()

  if (!shouldNotify(prefs, eventType)) {
    return
  }

  const method = prefs.method

  if (method === 'system' || method === 'both') {
    // Use existing notifications.ts for Windows toast notifications.
    // Map event types to notification levels for appropriate urgency.
    const level = eventType === 'leakDetected' || eventType === 'connectionError' ? 'error' : 'info'
    notify(level, title, body)
  }

  if (method === 'inapp' || method === 'both') {
    // Send IPC event to renderer for in-app toast display
    for (const win of BrowserWindow.getAllWindows()) {
      if (!win.isDestroyed()) {
        win.webContents.send('notification:inapp', {
          eventType,
          title,
          body,
          sound: prefs.sound,
          timestamp: Date.now()
        })
      }
    }
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const notificationPrefsService = {
  getPrefs,
  setPrefs,
  dispatchNotification,
  shouldNotify
}

// ─── IPC Registration ────────────────────────────────────────────────────────

export function registerNotificationPrefsIpcHandlers(): void {
  ipcMain.handle('notifications:get-prefs', () => {
    return getPrefs()
  })

  ipcMain.handle('notifications:set-prefs', (_event, partial: Partial<NotificationPreferences>) => {
    return setPrefs(partial)
  })
}
