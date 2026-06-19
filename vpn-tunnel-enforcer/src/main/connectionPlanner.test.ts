import { describe, expect, it, vi } from 'vitest'

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>()
  const exec = Object.assign(
    (_command: string, _options: unknown, callback: (error: Error | null, stdout: string, stderr: string) => void) => {
      callback(null, '', '')
    },
    {
      [Symbol.for('nodejs.util.promisify.custom')]: () => Promise.resolve({ stdout: '', stderr: '' })
    }
  )

  return { ...actual, exec, default: { ...actual, exec } }
})

const settingsGet = vi.hoisted(() => vi.fn(() => ({
  connectionMode: 'directVpn',
  proxyOverride: '127.0.0.1:10808',
  proxyType: 'socks5'
})))

vi.mock('./settings', () => ({
  settingsStore: {
    get: settingsGet
  }
}))

const getStatus = vi.hoisted(() => vi.fn(() => ({ running: false })))
const parseProxyAddress = vi.hoisted(() => vi.fn(() => ({ host: '127.0.0.1', port: 10808 })))
const probeTcp = vi.hoisted(() => vi.fn(async () => false))

vi.mock('./tunController', () => ({
  tunController: { getStatus },
  parseProxyAddress,
  probeTcp
}))

const getActiveProfile = vi.hoisted(() => vi.fn(() => ({
  id: 'profile-1',
  name: 'poland1',
  protocol: 'vless',
  server: '144.31.1.75',
  port: 443,
  status: 'unknown',
  outbound: {
    type: 'vless',
    server: '144.31.1.75',
    server_port: 443
  }
})))

vi.mock('./serverPicker', () => ({
  getActiveProfile
}))

vi.mock('./happDetector', () => ({
  happDetector: {
    detect: vi.fn(async () => null)
  }
}))

import { getRoutingPlan } from './connectionPlanner'

describe('getRoutingPlan', () => {
  it('does not block directVpn on an unused local proxy override', async () => {
    const plan = await getRoutingPlan()

    expect(plan.status).toBe('ready')
    expect(plan.recommendedMode).toBe('hard')
    expect(plan.title).toContain('Direct VPN')
    expect(plan.canStartHard).toBe(true)
    expect(plan.blockers).toEqual([])
    expect(plan.steps.some(step => step.label.includes('Direct VPN'))).toBe(true)
    expect(probeTcp).not.toHaveBeenCalled()
  })
})
