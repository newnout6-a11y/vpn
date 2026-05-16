/**
 * Unit tests for notificationPrefs pure functions.
 */

import { describe, it, expect } from 'vitest'
import { shouldNotify } from './notificationPrefs'
import type { NotificationPreferences } from '../shared/ipc-types'

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

describe('shouldNotify', () => {
  it('returns true when the event type is enabled', () => {
    expect(shouldNotify(DEFAULT_PREFS, 'vpnConnect')).toBe(true)
    expect(shouldNotify(DEFAULT_PREFS, 'vpnDisconnect')).toBe(true)
    expect(shouldNotify(DEFAULT_PREFS, 'leakDetected')).toBe(true)
    expect(shouldNotify(DEFAULT_PREFS, 'profileRotation')).toBe(true)
    expect(shouldNotify(DEFAULT_PREFS, 'scheduleTriggered')).toBe(true)
    expect(shouldNotify(DEFAULT_PREFS, 'connectionError')).toBe(true)
  })

  it('returns false when the event type is disabled', () => {
    const prefs: NotificationPreferences = {
      ...DEFAULT_PREFS,
      vpnConnect: false,
      leakDetected: false
    }
    expect(shouldNotify(prefs, 'vpnConnect')).toBe(false)
    expect(shouldNotify(prefs, 'leakDetected')).toBe(false)
    // Others still enabled
    expect(shouldNotify(prefs, 'vpnDisconnect')).toBe(true)
    expect(shouldNotify(prefs, 'connectionError')).toBe(true)
  })

  it('returns false when all events are disabled', () => {
    const prefs: NotificationPreferences = {
      vpnConnect: false,
      vpnDisconnect: false,
      leakDetected: false,
      profileRotation: false,
      scheduleTriggered: false,
      connectionError: false,
      method: 'system',
      sound: true
    }
    expect(shouldNotify(prefs, 'vpnConnect')).toBe(false)
    expect(shouldNotify(prefs, 'vpnDisconnect')).toBe(false)
    expect(shouldNotify(prefs, 'leakDetected')).toBe(false)
    expect(shouldNotify(prefs, 'profileRotation')).toBe(false)
    expect(shouldNotify(prefs, 'scheduleTriggered')).toBe(false)
    expect(shouldNotify(prefs, 'connectionError')).toBe(false)
  })

  it('is independent of method and sound settings', () => {
    const prefsInapp: NotificationPreferences = { ...DEFAULT_PREFS, method: 'inapp', sound: false }
    const prefsBoth: NotificationPreferences = { ...DEFAULT_PREFS, method: 'both', sound: true }

    expect(shouldNotify(prefsInapp, 'vpnConnect')).toBe(true)
    expect(shouldNotify(prefsBoth, 'vpnConnect')).toBe(true)

    const disabledInapp: NotificationPreferences = { ...prefsInapp, vpnConnect: false }
    expect(shouldNotify(disabledInapp, 'vpnConnect')).toBe(false)
  })
})
