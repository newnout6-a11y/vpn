import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./managedChildProcess', () => ({
  cleanupManagedChildPidDirs: vi.fn(async () => undefined),
  removeManagedChildPidFile: vi.fn(async () => undefined),
  writeManagedChildPidFile: vi.fn(async () => undefined)
}))
vi.mock('./physicalAdapterLockdown', () => ({
  getPhysicalAdapterDnsSources: vi.fn(async () => [{
    ifIndex: 0,
    alias: process.env.VPNTE_LIVE_INTERFACE || 'Wi-Fi',
    ipv4DnsServers: []
  }])
}))
vi.mock('./sharedStores', () => ({
  serverPickerStore: { get: vi.fn(), set: vi.fn() },
  serverGroupsStore: { get: vi.fn(), set: vi.fn() }
}))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) },
  getDirectProxyPort: () => null,
  getBundledResource: (name: string) => join(process.cwd(), 'resources', name),
  pickFreeLocalPort: async () => {
    const { createServer } = await import('node:net')
    return await new Promise<number>((resolve, reject) => {
      const server = createServer()
      server.once('error', reject)
      server.listen(0, '127.0.0.1', () => {
        const address = server.address()
        const port = address && typeof address === 'object' ? address.port : 0
        server.close(error => error ? reject(error) : resolve(port))
      })
    })
  },
  sanitizeProxyOutbound: (outbound: Record<string, any>) => ({
    outbound,
    needsBootstrapDns: false
  })
}))

import { checkProfileHealth } from './keyHealthChecker'
import type { ServerProfile } from '../shared/ipc-types'

const runLive = process.env.VPNTE_RUN_KEY_HEALTH_LIVE === '1'

function loadLiveProfile(): ServerProfile {
  const appData = process.env.APPDATA
  if (!appData) throw new Error('APPDATA is not set')
  const store = JSON.parse(readFileSync(join(appData, 'vpn-tunnel-enforcer', 'server-picker.json'), 'utf8'))
  const profiles = Array.isArray(store.profiles) ? store.profiles as ServerProfile[] : []
  const active = profiles.find(profile => profile.id === store.activeProfileId && profile.outbound)
  const profile = active ?? profiles.find(candidate => candidate.outbound && /^\d+\.\d+\.\d+\.\d+$/.test(candidate.server))
  if (!profile) throw new Error('no stored profile with outbound found')
  return profile
}

describe.skipIf(!runLive)('key health live outbound probe', () => {
  it('passes real traffic through the active stored key', async () => {
    const result = await checkProfileHealth(loadLiveProfile())
    expect(result, `probe failed: ${result.reason || 'unknown'}`).toMatchObject({ online: true })
  }, 20_000)

  it('rejects the same endpoint when its credential is replaced', async () => {
    const profile = structuredClone(loadLiveProfile())
    if (!profile.outbound) throw new Error('profile has no outbound')
    if (typeof profile.outbound.uuid === 'string') profile.outbound.uuid = randomUUID()
    else if (typeof profile.outbound.password === 'string') profile.outbound.password += '-invalid'
    else throw new Error(`unsupported credential field for ${profile.protocol}`)

    const result = await checkProfileHealth(profile)
    expect(result).toMatchObject({ online: false })
  }, 20_000)
})
