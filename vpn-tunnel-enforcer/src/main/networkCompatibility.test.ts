import { describe, expect, it } from 'vitest'

import {
  DEFAULT_TUN_MTU,
  PUBLIC_WIFI_TUN_MTU,
  STEALTH_TUN_MTU,
  selectTunMtu
} from './networkCompatibility'

describe('selectTunMtu', () => {
  it('keeps the default MTU outside compatibility modes', () => {
    expect(selectTunMtu()).toBe(DEFAULT_TUN_MTU)
    expect(selectTunMtu({ publicWifiCompatibility: false, stealthMode: false })).toBe(DEFAULT_TUN_MTU)
  })

  it('uses a lower MTU for public Wi-Fi and mobile hotspot compatibility', () => {
    expect(selectTunMtu({ publicWifiCompatibility: true })).toBe(PUBLIC_WIFI_TUN_MTU)
  })

  it('lets stealth mode win with the most conservative MTU', () => {
    expect(selectTunMtu({ publicWifiCompatibility: true, stealthMode: true })).toBe(STEALTH_TUN_MTU)
  })
})
