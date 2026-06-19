import { describe, expect, it, vi } from 'vitest'
import type { ServerProfile } from '../shared/ipc-types'

vi.mock('electron', () => ({
  app: {
    getPath: () => '/tmp/vpnte-test',
    getAppPath: () => '/tmp/vpnte-test/app',
    isPackaged: false
  }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

vi.mock('./serverPicker', () => ({
  serverPicker: {
    getProfiles: vi.fn(() => []),
    getActiveProfileId: vi.fn(() => null),
    getActiveProfile: vi.fn(() => null),
    selectProfile: vi.fn()
  }
}))

import {
  buildExternalProxyConfig,
  isExternalProxyMutationPath,
  isValidExternalProxyControlToken
} from './externalProxy'

function sampleProfile(): ServerProfile {
  return {
    id: 'profile-1',
    name: 'sample',
    country: 'Netherlands',
    protocol: 'vless',
    server: '203.0.113.10',
    port: 443,
    status: 'unknown',
    outbound: {
      type: 'vless',
      tag: 'original-tag',
      server: '203.0.113.10',
      server_port: 443,
      uuid: '00000000-0000-4000-8000-000000000000',
      tls: { enabled: true }
    }
  } as ServerProfile
}

describe('buildExternalProxyConfig', () => {
  it('uses sing-box 1.13 sniff route actions instead of legacy inbound sniff fields', () => {
    const config = buildExternalProxyConfig(sampleProfile(), 17990) as any
    const inbound = config.inbounds.find((item: any) => item.tag === 'external-mixed-in')

    expect(inbound).toMatchObject({
      type: 'mixed',
      listen: '127.0.0.1',
      listen_port: 17990
    })
    expect(inbound).not.toHaveProperty('sniff')
    expect(inbound).not.toHaveProperty('sniff_override_destination')
    expect(config.route.rules[0]).toEqual({ action: 'sniff' })
    expect(config.route.final).toBe('proxy-out')
    expect(config.outbounds[0].tag).toBe('proxy-out')
  })
})

describe('external proxy control auth helpers', () => {
  it('classifies state-changing control paths', () => {
    expect(isExternalProxyMutationPath('/start')).toBe(true)
    expect(isExternalProxyMutationPath('/rotate')).toBe(true)
    expect(isExternalProxyMutationPath('/connect')).toBe(true)
    expect(isExternalProxyMutationPath('/trigger')).toBe(true)
    expect(isExternalProxyMutationPath('/stop')).toBe(true)
    expect(isExternalProxyMutationPath('/status')).toBe(false)
    expect(isExternalProxyMutationPath('/list')).toBe(false)
  })

  it('requires an exact session token for protected control calls', () => {
    expect(isValidExternalProxyControlToken('abc123', 'abc123')).toBe(true)
    expect(isValidExternalProxyControlToken('abc123', 'abc124')).toBe(false)
    expect(isValidExternalProxyControlToken('abc123', '')).toBe(false)
    expect(isValidExternalProxyControlToken(null, 'abc123')).toBe(false)
  })
})
