import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  stores: {} as Record<string, Record<string, any>>,
  failOnEncryptCall: 0,
  encryptCalls: 0
}))

vi.mock('electron', () => ({
  safeStorage: {
    isEncryptionAvailable: () => true,
    encryptString: (value: string) => {
      state.encryptCalls += 1
      if (state.failOnEncryptCall === state.encryptCalls) throw new Error('injected safeStorage failure')
      return Buffer.from(`encrypted:${value}`, 'utf8')
    },
    decryptString: (value: Buffer) => value.toString('utf8').replace(/^encrypted:/, '')
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private name: string
    constructor(options: { name: string; defaults?: Record<string, any> }) {
      this.name = options.name
      state.stores[this.name] ??= { ...(options.defaults ?? {}) }
    }
    get(key: string, fallback?: unknown) {
      return state.stores[this.name][key] ?? fallback
    }
    set(key: string, value: unknown) {
      state.stores[this.name][key] = value
    }
    get path() {
      return `/path-that-does-not-exist/${this.name}.json`
    }
    get store() {
      return state.stores[this.name]
    }
    set store(value: Record<string, any>) {
      state.stores[this.name] = value
    }
  }
}))

function plaintextProfile(id: string) {
  return {
    id,
    name: id,
    protocol: 'vless',
    server: 'vpn.example',
    port: 443,
    status: 'unknown',
    sourceUri: `vless://${id}@vpn.example:443`,
    outbound: { type: 'vless', uuid: id, server: 'vpn.example', server_port: 443 }
  }
}

describe('server profile safeStorage migration (AT-01-001)', () => {
  beforeEach(() => {
    vi.resetModules()
    state.encryptCalls = 0
    state.failOnEncryptCall = 0
    state.stores = {
      'server-picker': {
        schemaVersion: 1,
        profiles: [plaintextProfile('FAKE-UUID-1'), plaintextProfile('FAKE-UUID-2')],
        activeProfileId: 'FAKE-UUID-1'
      }
    }
  })

  it('atomically replaces plaintext profiles with SecretRef values', async () => {
    const { serverPickerStore } = await import('./sharedStores')
    const profiles = serverPickerStore.get('profiles')
    expect(profiles[0].outbound?.uuid).toBe('FAKE-UUID-1')
    const raw = JSON.stringify(state.stores['server-picker'])
    expect(raw).not.toContain('vless://')
    expect(raw).not.toContain('"uuid":"FAKE-UUID-1"')
    expect(raw).toContain('vpnte-safe-storage-v1')
  })

  it('leaves the entire legacy store unchanged after an injected encryption failure', async () => {
    const before = JSON.stringify(state.stores['server-picker'])
    state.failOnEncryptCall = 3
    const { serverPickerStore } = await import('./sharedStores')
    expect(() => serverPickerStore.get('profiles')).toThrow(/injected safeStorage failure/)
    expect(JSON.stringify(state.stores['server-picker'])).toBe(before)
  })
})