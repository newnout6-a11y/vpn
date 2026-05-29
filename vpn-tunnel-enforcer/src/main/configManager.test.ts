/**
 * Unit tests for configManager.ts pure functions.
 */

import { describe, it, expect } from 'vitest'
import {
  validateImportData,
  detectConflicts,
  applySelectiveImport,
  CONFIG_VERSION,
  type ConfigExportData,
  type ConfigSection
} from './configManager'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeEmptyConfig(): ConfigExportData {
  return {
    version: CONFIG_VERSION,
    exportedAt: Date.now(),
    profiles: [],
    serverGroups: [],
    schedules: [],
    splitTunnel: [],
    dns: [],
    domainRouting: [],
    themes: [],
    widgets: [],
    rotation: {
      enabled: false,
      intervalMinutes: 30,
      order: 'sequential',
      profileIds: [],
      currentIndex: 0,
      nextRotationAt: null
    },
    killSwitch: {
      level: 'off',
      exceptions: []
    },
    notifications: {
      vpnConnect: true,
      vpnDisconnect: true,
      leakDetected: true,
      profileRotation: true,
      scheduleTriggered: true,
      connectionError: true,
      method: 'system',
      sound: true
    }
  }
}

function makeProfile(id: string) {
  return {
    id,
    name: `Profile ${id}`,
    protocol: 'vless',
    server: '1.2.3.4',
    port: 443,
    status: 'unknown' as const,
    ping: null
  }
}

function makeSchedule(id: string) {
  return {
    id,
    name: `Schedule ${id}`,
    enabled: true,
    days: [1, 2, 3],
    startTime: '09:00',
    endTime: '17:00',
    profileId: 'p1',
    mode: 'hard' as const
  }
}

// ─── validateImportData ──────────────────────────────────────────────────────

describe('validateImportData', () => {
  it('rejects null', () => {
    const result = validateImportData(null)
    expect(result.valid).toBe(false)
    expect(result.error).toContain('expected a JSON object')
  })

  it('rejects non-object', () => {
    expect(validateImportData('string').valid).toBe(false)
    expect(validateImportData(42).valid).toBe(false)
    expect(validateImportData([]).valid).toBe(false)
  })

  it('rejects missing version field', () => {
    const result = validateImportData({ profiles: [] })
    expect(result.valid).toBe(false)
    expect(result.error).toContain('version')
  })

  it('rejects incompatible version', () => {
    const result = validateImportData({ version: '1.0', profiles: [] })
    expect(result.valid).toBe(false)
    expect(result.error).toContain('Incompatible version')
  })

  it('rejects when no recognized sections present', () => {
    const result = validateImportData({ version: CONFIG_VERSION, foo: 'bar' })
    expect(result.valid).toBe(false)
    expect(result.error).toContain('No recognized')
  })

  it('rejects invalid type for array section', () => {
    const result = validateImportData({ version: CONFIG_VERSION, profiles: 'not-array' })
    expect(result.valid).toBe(false)
    expect(result.error).toContain('expected array')
  })

  it('rejects invalid type for object section (rotation)', () => {
    const result = validateImportData({ version: CONFIG_VERSION, rotation: 'not-object' })
    expect(result.valid).toBe(false)
    expect(result.error).toContain('expected object')
  })

  it('accepts valid config with all sections', () => {
    const config = makeEmptyConfig()
    const result = validateImportData(config)
    expect(result.valid).toBe(true)
    expect(result.sections).toContain('profiles')
    expect(result.sections).toContain('schedules')
    expect(result.sections).toContain('rotation')
    expect(result.sections).toContain('killSwitch')
    expect(result.sections).toContain('notifications')
  })

  it('accepts valid config with partial sections', () => {
    const result = validateImportData({
      version: CONFIG_VERSION,
      profiles: [makeProfile('p1')],
      dns: []
    })
    expect(result.valid).toBe(true)
    expect(result.sections).toContain('profiles')
    expect(result.sections).toContain('dns')
    expect(result.sections).not.toContain('schedules')
  })

  it('recognizes the serverGroups section', () => {
    const result = validateImportData({
      version: CONFIG_VERSION,
      serverGroups: [{ id: 'g1', name: 'g1', source: 'manual', importedAt: 0, status: 'unknown' }]
    })
    expect(result.valid).toBe(true)
    expect(result.sections).toContain('serverGroups')
  })

  it('rejects a non-array serverGroups section', () => {
    const result = validateImportData({ version: CONFIG_VERSION, serverGroups: {} })
    expect(result.valid).toBe(false)
    expect(result.error).toContain('expected array')
  })
})

// ─── detectConflicts ─────────────────────────────────────────────────────────

describe('detectConflicts', () => {
  it('returns empty array when both configs are empty', () => {
    const existing = makeEmptyConfig()
    const incoming = makeEmptyConfig()
    expect(detectConflicts(existing, incoming)).toEqual([])
  })

  it('returns empty array when only incoming has data', () => {
    const existing = makeEmptyConfig()
    const incoming = { ...makeEmptyConfig(), profiles: [makeProfile('p1')] }
    expect(detectConflicts(existing, incoming)).toEqual([])
  })

  it('returns empty array when only existing has data', () => {
    const existing = { ...makeEmptyConfig(), profiles: [makeProfile('p1')] }
    const incoming = makeEmptyConfig()
    expect(detectConflicts(existing, incoming)).toEqual([])
  })

  it('detects conflict when both have profiles', () => {
    const existing = { ...makeEmptyConfig(), profiles: [makeProfile('p1')] }
    const incoming = { ...makeEmptyConfig(), profiles: [makeProfile('p2')] }
    expect(detectConflicts(existing, incoming)).toContain('profiles')
  })

  it('detects conflict when both have serverGroups', () => {
    const grp = (id: string) => ({ id, name: id, source: 'manual' as const, importedAt: 0, status: 'unknown' as const })
    const existing = { ...makeEmptyConfig(), serverGroups: [grp('g1')] }
    const incoming = { ...makeEmptyConfig(), serverGroups: [grp('g2')] }
    expect(detectConflicts(existing, incoming)).toContain('serverGroups')
  })

  it('detects conflict when both have schedules', () => {
    const existing = { ...makeEmptyConfig(), schedules: [makeSchedule('s1')] }
    const incoming = { ...makeEmptyConfig(), schedules: [makeSchedule('s2')] }
    expect(detectConflicts(existing, incoming)).toContain('schedules')
  })

  it('detects rotation conflict when both have non-default rotation', () => {
    const existing = {
      ...makeEmptyConfig(),
      rotation: { ...makeEmptyConfig().rotation, enabled: true, profileIds: ['p1'] }
    }
    const incoming = {
      ...makeEmptyConfig(),
      rotation: { ...makeEmptyConfig().rotation, enabled: true, profileIds: ['p2'] }
    }
    expect(detectConflicts(existing, incoming)).toContain('rotation')
  })

  it('detects killSwitch conflict when both have non-default values', () => {
    const existing = {
      ...makeEmptyConfig(),
      killSwitch: { level: 'standard' as const, exceptions: [] }
    }
    const incoming = {
      ...makeEmptyConfig(),
      killSwitch: { level: 'strict' as const, exceptions: [] }
    }
    expect(detectConflicts(existing, incoming)).toContain('killSwitch')
  })
})

// ─── applySelectiveImport ────────────────────────────────────────────────────

describe('applySelectiveImport', () => {
  it('replaces array section in replace mode', () => {
    const existing = { ...makeEmptyConfig(), profiles: [makeProfile('p1')] }
    const incoming = { ...makeEmptyConfig(), profiles: [makeProfile('p2')] }

    const result = applySelectiveImport(existing, incoming, ['profiles'], 'replace')
    expect(result.profiles).toHaveLength(1)
    expect(result.profiles[0].id).toBe('p2')
  })

  it('merges array section in merge mode (deduplicates by id)', () => {
    const existing = { ...makeEmptyConfig(), profiles: [makeProfile('p1')] }
    const incoming = { ...makeEmptyConfig(), profiles: [makeProfile('p2')] }

    const result = applySelectiveImport(existing, incoming, ['profiles'], 'merge')
    expect(result.profiles).toHaveLength(2)
    expect(result.profiles.map((p) => p.id)).toContain('p1')
    expect(result.profiles.map((p) => p.id)).toContain('p2')
  })

  it('incoming wins on duplicate id in merge mode', () => {
    const existing = { ...makeEmptyConfig(), profiles: [{ ...makeProfile('p1'), name: 'Old' }] }
    const incoming = { ...makeEmptyConfig(), profiles: [{ ...makeProfile('p1'), name: 'New' }] }

    const result = applySelectiveImport(existing, incoming, ['profiles'], 'merge')
    expect(result.profiles).toHaveLength(1)
    expect(result.profiles[0].name).toBe('New')
  })

  it('does not modify unselected sections', () => {
    const existing = {
      ...makeEmptyConfig(),
      profiles: [makeProfile('p1')],
      schedules: [makeSchedule('s1')]
    }
    const incoming = {
      ...makeEmptyConfig(),
      profiles: [makeProfile('p2')],
      schedules: [makeSchedule('s2')]
    }

    const result = applySelectiveImport(existing, incoming, ['profiles'], 'replace')
    // profiles replaced
    expect(result.profiles).toHaveLength(1)
    expect(result.profiles[0].id).toBe('p2')
    // schedules unchanged
    expect(result.schedules).toHaveLength(1)
    expect(result.schedules[0].id).toBe('s1')
  })

  it('replaces rotation in replace mode', () => {
    const existing = makeEmptyConfig()
    const incoming = {
      ...makeEmptyConfig(),
      rotation: { ...makeEmptyConfig().rotation, enabled: true, intervalMinutes: 60 }
    }

    const result = applySelectiveImport(existing, incoming, ['rotation'], 'replace')
    expect(result.rotation.enabled).toBe(true)
    expect(result.rotation.intervalMinutes).toBe(60)
  })

  it('merges rotation in merge mode', () => {
    const existing = {
      ...makeEmptyConfig(),
      rotation: { ...makeEmptyConfig().rotation, profileIds: ['p1'], currentIndex: 0 }
    }
    const incoming = {
      ...makeEmptyConfig(),
      rotation: { ...makeEmptyConfig().rotation, enabled: true, intervalMinutes: 15 }
    }

    const result = applySelectiveImport(existing, incoming, ['rotation'], 'merge')
    expect(result.rotation.enabled).toBe(true)
    expect(result.rotation.intervalMinutes).toBe(15)
  })

  it('replaces notifications in replace mode', () => {
    const existing = makeEmptyConfig()
    const incoming = {
      ...makeEmptyConfig(),
      notifications: { ...makeEmptyConfig().notifications, sound: false, method: 'inapp' as const }
    }

    const result = applySelectiveImport(existing, incoming, ['notifications'], 'replace')
    expect(result.notifications.sound).toBe(false)
    expect(result.notifications.method).toBe('inapp')
  })

  it('handles multiple sections at once', () => {
    const existing = {
      ...makeEmptyConfig(),
      profiles: [makeProfile('p1')],
      schedules: [makeSchedule('s1')]
    }
    const incoming = {
      ...makeEmptyConfig(),
      profiles: [makeProfile('p2')],
      schedules: [makeSchedule('s2')]
    }

    const result = applySelectiveImport(
      existing,
      incoming,
      ['profiles', 'schedules'],
      'replace'
    )
    expect(result.profiles[0].id).toBe('p2')
    expect(result.schedules[0].id).toBe('s2')
  })
})
