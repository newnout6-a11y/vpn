/**
 * Unit tests for profileRotation pure functions.
 */

import { describe, it, expect } from 'vitest'
import { clampInterval, getNextAvailableProfile } from './profileRotation'
import type { RotationConfig } from '../shared/ipc-types'

describe('clampInterval', () => {
  it('returns MIN (5) for values below 5', () => {
    expect(clampInterval(0)).toBe(5)
    expect(clampInterval(-10)).toBe(5)
    expect(clampInterval(4)).toBe(5)
    expect(clampInterval(1)).toBe(5)
  })

  it('returns MAX (1440) for values above 1440', () => {
    expect(clampInterval(1441)).toBe(1440)
    expect(clampInterval(9999)).toBe(1440)
    expect(clampInterval(100000)).toBe(1440)
  })

  it('preserves values within [5, 1440]', () => {
    expect(clampInterval(5)).toBe(5)
    expect(clampInterval(30)).toBe(30)
    expect(clampInterval(60)).toBe(60)
    expect(clampInterval(1440)).toBe(1440)
    expect(clampInterval(720)).toBe(720)
  })

  it('returns MIN for NaN and Infinity', () => {
    expect(clampInterval(NaN)).toBe(5)
    expect(clampInterval(Infinity)).toBe(5)
    expect(clampInterval(-Infinity)).toBe(5)
  })
})

describe('getNextAvailableProfile', () => {
  const baseConfig: RotationConfig = {
    enabled: true,
    intervalMinutes: 30,
    order: 'sequential',
    profileIds: ['a', 'b', 'c', 'd'],
    currentIndex: 0,
    nextRotationAt: null
  }

  describe('sequential order', () => {
    it('returns the next available profile after current index', () => {
      const config = { ...baseConfig, currentIndex: 0 }
      const availability = { a: true, b: true, c: true, d: true }
      expect(getNextAvailableProfile(config, availability)).toBe('b')
    })

    it('skips unavailable profiles', () => {
      const config = { ...baseConfig, currentIndex: 0 }
      const availability = { a: true, b: false, c: true, d: true }
      expect(getNextAvailableProfile(config, availability)).toBe('c')
    })

    it('wraps around the list', () => {
      const config = { ...baseConfig, currentIndex: 3 }
      const availability = { a: true, b: true, c: true, d: true }
      expect(getNextAvailableProfile(config, availability)).toBe('a')
    })

    it('wraps around skipping unavailable', () => {
      const config = { ...baseConfig, currentIndex: 2 }
      const availability = { a: false, b: true, c: true, d: false }
      expect(getNextAvailableProfile(config, availability)).toBe('b')
    })

    it('returns null when no profiles are available', () => {
      const config = { ...baseConfig, currentIndex: 0 }
      const availability = { a: false, b: false, c: false, d: false }
      expect(getNextAvailableProfile(config, availability)).toBeNull()
    })

    it('returns null for empty profileIds', () => {
      const config = { ...baseConfig, profileIds: [], currentIndex: 0 }
      const availability = {}
      expect(getNextAvailableProfile(config, availability)).toBeNull()
    })
  })

  describe('random order', () => {
    it('returns an available profile different from current', () => {
      const config = { ...baseConfig, order: 'random' as const, currentIndex: 0 }
      const availability = { a: true, b: true, c: true, d: true }
      const result = getNextAvailableProfile(config, availability)
      expect(result).not.toBeNull()
      expect(result).not.toBe('a') // should not be current
      expect(['b', 'c', 'd']).toContain(result)
    })

    it('returns the only other available profile', () => {
      const config = { ...baseConfig, order: 'random' as const, currentIndex: 0 }
      const availability = { a: true, b: false, c: true, d: false }
      expect(getNextAvailableProfile(config, availability)).toBe('c')
    })

    it('returns current profile if it is the only one available', () => {
      const config = { ...baseConfig, order: 'random' as const, currentIndex: 0 }
      const availability = { a: true, b: false, c: false, d: false }
      expect(getNextAvailableProfile(config, availability)).toBe('a')
    })

    it('returns null when no profiles are available', () => {
      const config = { ...baseConfig, order: 'random' as const, currentIndex: 0 }
      const availability = { a: false, b: false, c: false, d: false }
      expect(getNextAvailableProfile(config, availability)).toBeNull()
    })
  })
})
