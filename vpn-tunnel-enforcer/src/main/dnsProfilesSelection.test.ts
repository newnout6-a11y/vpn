import { describe, it, expect, vi } from 'vitest'
import { dnsProfiles } from './dnsProfiles'

describe('dnsProfiles selection and isSelected flag', () => {
  it('returns builtin profiles with isSelected boolean flag', () => {
    const profiles = dnsProfiles.getAllProfiles()
    expect(profiles.length).toBeGreaterThanOrEqual(4)
    for (const p of profiles) {
      expect(typeof p.isSelected).toBe('boolean')
    }
  })

  it('exposes registerHandlers and getActiveDnsProfile', () => {
    expect(typeof dnsProfiles.registerHandlers).toBe('function')
    expect(typeof dnsProfiles.getActiveDnsProfile).toBe('function')
  })
})
