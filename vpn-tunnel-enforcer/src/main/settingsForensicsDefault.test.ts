/**
 * Deep-traffic-inspection must resolve to OFF for anything that is not an
 * explicit `true`.
 *
 * WHY THIS HAS ITS OWN TEST. `normalizeSettings` coerces most booleans with the
 * `merged.X !== false` idiom, which reads as "anything but an explicit false
 * means on". That is correct for the flags whose default is `true`
 * (firewallKillSwitch, autoRestartOnCrash, desktopNotifications,
 * publicWifiCompatibility, strictAdapterLockdown) — the idiom matches their
 * default. `deepTrafficInspectionEnabled` defaults to `false` and switching it
 * on starts writing packet captures to disk, so the same idiom was actively
 * wrong for it: it only resolved to `false` because `merged` pre-fills from the
 * defaults object. An explicit `undefined` arriving through `save()` — which is
 * exactly what a renderer sending a partial settings patch produces — bypassed
 * that and silently enabled forensics.
 *
 * The contrast test below is the load-bearing one: it pins that the two idioms
 * differ ON PURPOSE, so nobody "fixes" the inconsistency by making them match.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

const storeState = vi.hoisted(() => ({ data: {} as Record<string, any> }))

vi.mock('electron', () => ({
  app: {
    isPackaged: true,
    setLoginItemSettings: vi.fn(),
    getPath: () => '/tmp/vpnte-test'
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private defaults: Record<string, any>
    constructor(opts: { defaults?: Record<string, any> }) {
      this.defaults = opts.defaults ?? {}
    }
    get(key: string) {
      return storeState.data[key] ?? this.defaults[key]
    }
    set(key: string, value: any) {
      storeState.data[key] = value
    }
  }
}))

vi.mock('./admin', () => ({
  execElevated: vi.fn(async () => ({ stdout: '', stderr: '' }))
}))

describe('deepTrafficInspectionEnabled default', () => {
  beforeEach(() => {
    storeState.data = {}
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    vi.resetModules()
  })

  it('is off on a fresh store', async () => {
    const { settingsStore } = await import('./settings')

    expect(settingsStore.get().deepTrafficInspectionEnabled).toBe(false)
  })

  it('stays off when the key arrives as an explicit undefined', async () => {
    // The regression. A renderer patch that mentions the key without a value
    // used to read as "not false" and turn packet capture on.
    const { settingsStore } = await import('./settings')

    const saved = settingsStore.save({ deepTrafficInspectionEnabled: undefined })

    expect(saved.deepTrafficInspectionEnabled).toBe(false)
    expect(settingsStore.get().deepTrafficInspectionEnabled).toBe(false)
  })

  it('stays off for truthy-but-not-true values', async () => {
    const { settingsStore } = await import('./settings')

    const saved = settingsStore.save({ deepTrafficInspectionEnabled: 'yes' as any })

    expect(saved.deepTrafficInspectionEnabled).toBe(false)
  })

  it('turns on only for an explicit true, and survives a reload', async () => {
    const { settingsStore } = await import('./settings')

    expect(settingsStore.save({ deepTrafficInspectionEnabled: true }).deepTrafficInspectionEnabled).toBe(true)
    expect(settingsStore.get().deepTrafficInspectionEnabled).toBe(true)
  })

  it('does NOT weaken the default-on safety flags, which use the opposite idiom', async () => {
    // firewallKillSwitch defaults to true: an absent value must stay ON, or a
    // partial patch would quietly disable the kill switch. Same reasoning in
    // reverse — hence two different idioms in one function.
    const { settingsStore } = await import('./settings')

    const saved = settingsStore.save({ firewallKillSwitch: undefined })

    expect(saved.firewallKillSwitch).toBe(true)
    expect(saved.autoRestartOnCrash).toBe(true)
    expect(saved.strictAdapterLockdown).toBe(true)
    // ...while forensics went the other way on the very same call.
    expect(saved.deepTrafficInspectionEnabled).toBe(false)
  })
})
