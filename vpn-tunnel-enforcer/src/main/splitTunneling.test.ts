/**
 * Unit tests for the split tunneling service.
 * Tests the core logic: route rule generation, app management, and config persistence.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock electron modules
vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  dialog: { showOpenDialog: vi.fn() },
  app: { getPath: () => '/tmp/test' }
}))

vi.mock('electron-store', () => {
  const data: Record<string, any> = {
    splitTunnelApps: [],
    splitTunnelEnabled: true
  }
  return {
    default: class MockStore {
      constructor() {}
      get(key: string) {
        return data[key]
      }
      set(key: string, value: any) {
        data[key] = value
      }
    }
  }
})

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({ running: false }),
    stop: vi.fn().mockResolvedValue({ success: true })
  }
}))

// Import after mocks
import {
  generateSplitTunnelRouteRules,
  getDirectProcessNames,
  getVpnProcessNames
} from './splitTunneling'

describe('splitTunneling', () => {
  describe('generateSplitTunnelRouteRules', () => {
    it('returns empty array when no apps have rules', () => {
      const rules = generateSplitTunnelRouteRules()
      expect(rules).toEqual([])
    })
  })

  describe('getDirectProcessNames', () => {
    it('returns empty array when no apps have direct rule', () => {
      const names = getDirectProcessNames()
      expect(names).toEqual([])
    })
  })

  describe('getVpnProcessNames', () => {
    it('returns empty array when no apps have vpn rule', () => {
      const names = getVpnProcessNames()
      expect(names).toEqual([])
    })
  })
})
