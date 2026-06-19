import { describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({
  app: {
    getPath: () => '/tmp/vpnte-test',
    getAppPath: () => '/tmp/vpnte-test/app',
    isPackaged: false
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private data: Record<string, any>

    constructor(options?: { defaults?: Record<string, any> }) {
      this.data = { ...(options?.defaults ?? {}) }
    }

    get(key?: string) {
      if (!key) return this.data
      return this.data[key]
    }

    set(key: string, value: any) {
      this.data[key] = value
    }
  }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import { chooseSmartRouteRuleSetSource } from './ruleSetManager'

describe('chooseSmartRouteRuleSetSource', () => {
  it('uses bundled rule-sets in bundled mode even when managed cache is complete', () => {
    expect(chooseSmartRouteRuleSetSource({ smartRuRuleSetMode: 'bundled' }, true)).toBe('bundled')
  })

  it('falls back to bundled rule-sets when managed cache is incomplete', () => {
    expect(chooseSmartRouteRuleSetSource({ smartRuRuleSetMode: 'managed' }, false)).toBe('bundled')
  })

  it('uses managed rule-sets only when managed mode is selected and cache is complete', () => {
    expect(chooseSmartRouteRuleSetSource({ smartRuRuleSetMode: 'managed' }, true)).toBe('managed')
  })
})
