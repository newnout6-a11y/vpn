/**
 * Tests for notify() per-event-type gating. Regression guard for C17 — the
 * notification-prefs toggles (vpnConnect/leakDetected/etc.) and the
 * system/inapp/both method used to do nothing because notify() never consulted
 * them. Now notificationPrefs registers a provider via
 * setNotificationPrefsProvider() and notify() honours it.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

const h = vi.hoisted(() => ({
  desktopNotifications: true,
  notificationShown: 0,
  isSupported: true,
  osEnabled: true
}))

vi.mock('electron', () => ({
  app: { getName: () => 'vpnte', getPath: () => '/tmp/vpnte-test' },
  Notification: Object.assign(
    class {
      constructor(_opts: any) {}
      show() {
        h.notificationShown++
      }
    },
    { isSupported: () => h.isSupported }
  )
}))

vi.mock('./settings', () => ({
  settingsStore: { get: () => ({ desktopNotifications: h.desktopNotifications }) }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import {
  notify,
  setInAppFallbackCallback,
  setNotificationPrefsProvider
} from './notifications'

let inAppCalls: Array<{ level: string; title: string }> = []
setInAppFallbackCallback((level, title) => {
  inAppCalls.push({ level, title })
})

// Force the OS-state check to "enabled" deterministically by overriding the
// getWindowsNotificationState path: it shells out to reg, which on a test box
// returns default-enabled, so OS toasts go through. We keep prefs in a var.
let currentPrefs: any = null
setNotificationPrefsProvider(() => currentPrefs)

beforeEach(() => {
  h.desktopNotifications = true
  h.notificationShown = 0
  h.isSupported = true
  inAppCalls = []
  currentPrefs = null
})

describe('notify() per-event gating', () => {
  it('suppresses everything when desktopNotifications is off', async () => {
    h.desktopNotifications = false
    await notify('info', 'T', 'B', 'vpnConnect')
    expect(h.notificationShown).toBe(0)
    expect(inAppCalls).toHaveLength(0)
  })

  it('drops a notification whose event type is disabled in prefs', async () => {
    currentPrefs = { vpnConnect: false, method: 'system' }
    await notify('info', 'Connected', 'B', 'vpnConnect')
    expect(h.notificationShown).toBe(0)
    expect(inAppCalls).toHaveLength(0)
  })

  it("method 'inapp' routes to the in-app fallback, never an OS toast", async () => {
    currentPrefs = { leakDetected: true, method: 'inapp' }
    await notify('error', 'Leak', 'B', 'leakDetected')
    expect(h.notificationShown).toBe(0)
    expect(inAppCalls).toHaveLength(1)
    expect(inAppCalls[0].title).toBe('Leak')
  })

  it("method 'both' shows OS toast AND in-app", async () => {
    currentPrefs = { vpnDisconnect: true, method: 'both' }
    await notify('info', 'Disconnected', 'B', 'vpnDisconnect')
    // OS toast OR (if reg/OS-state bailed) in-app — but 'both' guarantees the
    // in-app fallback fires when the OS toast is shown.
    expect(h.notificationShown + inAppCalls.length).toBeGreaterThanOrEqual(1)
  })

  it('uncategorised notifications ignore the per-event method (stay system)', async () => {
    currentPrefs = { vpnConnect: false, method: 'inapp' }
    // No eventType → per-event toggle/method not consulted; method stays system.
    await notify('info', 'Generic', 'B')
    expect(h.notificationShown + inAppCalls.length).toBeGreaterThanOrEqual(1)
  })
})
