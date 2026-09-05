import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { renderHook, act } from '@testing-library/react'
import { changedSettingKeys, useSettingsDraft } from './Settings'
import type { AppSettings } from '../store'

const source = readFileSync(join(process.cwd(), 'src/renderer/pages/Settings.tsx'), 'utf8')

const asSettings = (o: Record<string, unknown>) => o as unknown as AppSettings

describe('changedSettingKeys', () => {
  it('reports nothing when draft equals baseline', () => {
    const s = { a: 1, b: 'x', c: true }
    expect(changedSettingKeys(s, { ...s })).toEqual([])
  })

  it('reports only the keys that actually differ', () => {
    expect(changedSettingKeys({ a: 1, b: 'x', c: true }, { a: 1, b: 'y', c: false }).sort()).toEqual(['b', 'c'])
  })

  it('treats a key present on only one side as changed', () => {
    expect(changedSettingKeys({ a: 1 }, { a: 1, b: 2 })).toEqual(['b'])
  })

  it('is null/undefined safe', () => {
    expect(changedSettingKeys(null, undefined)).toEqual([])
    expect(changedSettingKeys(undefined, { a: 1 })).toEqual(['a'])
  })

  it('uses Object.is semantics (no false positive on NaN baseline)', () => {
    expect(changedSettingKeys({ a: NaN }, { a: NaN })).toEqual([])
  })
})

describe('useSettingsDraft', () => {
  it('starts clean and flips dirty on an edit', () => {
    const store = asSettings({ strictAdapterLockdown: false, checkInterval: 30000 })
    const { result } = renderHook(({ s }) => useSettingsDraft(s), { initialProps: { s: store } })

    expect(result.current.isDirty).toBe(false)
    expect(result.current.changedKeys).toEqual([])

    act(() => result.current.update({ strictAdapterLockdown: true }))

    expect(result.current.isDirty).toBe(true)
    expect(result.current.changedKeys).toEqual(['strictAdapterLockdown'])
    expect(result.current.draft.strictAdapterLockdown).toBe(true)
  })

  it('reset() restores every edited value and clears the dirty flag', () => {
    const store = asSettings({ strictAdapterLockdown: false, stealthMode: false })
    const { result } = renderHook(({ s }) => useSettingsDraft(s), { initialProps: { s: store } })

    act(() => result.current.update({ strictAdapterLockdown: true, stealthMode: true }))
    expect(result.current.isDirty).toBe(true)

    act(() => result.current.reset())

    expect(result.current.isDirty).toBe(false)
    expect(result.current.draft.strictAdapterLockdown).toBe(false)
    expect(result.current.draft.stealthMode).toBe(false)
  })

  it('commit() advances the baseline and keeps the saved value (no stale-store stomp)', () => {
    // Regression: the old effect keyed on `isDirty` and force-synced the draft
    // back to `storeSettings` the instant an edit was committed/reverted — the
    // path by which the save bar could vanish before it ever rendered.
    const store = asSettings({ stealthMode: false })
    const { result } = renderHook(({ s }) => useSettingsDraft(s), { initialProps: { s: store } })

    act(() => result.current.update({ stealthMode: true }))
    act(() => result.current.commit(asSettings({ stealthMode: true })))

    expect(result.current.isDirty).toBe(false)
    expect(result.current.draft.stealthMode).toBe(true)
  })

  it('commitPartial() moves draft and baseline together for an out-of-band apply', () => {
    const store = asSettings({ locationPrivacyEnabled: false, stealthMode: false })
    const { result } = renderHook(({ s }) => useSettingsDraft(s), { initialProps: { s: store } })

    act(() => result.current.update({ stealthMode: true }))
    act(() => result.current.commitPartial({ locationPrivacyEnabled: true }))

    // stealthMode edit is still pending; the location toggle is not counted
    expect(result.current.changedKeys).toEqual(['stealthMode'])
    expect(result.current.draft.locationPrivacyEnabled).toBe(true)
  })

  it('adopts a genuine external store change while the draft is clean', () => {
    const { result, rerender } = renderHook(({ s }) => useSettingsDraft(s), {
      initialProps: { s: asSettings({ checkInterval: 30000 }) },
    })
    rerender({ s: asSettings({ checkInterval: 45000 }) })
    expect(result.current.draft.checkInterval).toBe(45000)
    expect(result.current.isDirty).toBe(false)
  })

  it('keeps the user\'s edit when an external store change lands mid-edit', () => {
    const { result, rerender } = renderHook(({ s }) => useSettingsDraft(s), {
      initialProps: { s: asSettings({ checkInterval: 30000 }) },
    })

    act(() => result.current.update({ checkInterval: 60000 }))
    rerender({ s: asSettings({ checkInterval: 45000 }) })

    expect(result.current.draft.checkInterval).toBe(60000)
    expect(result.current.isDirty).toBe(true)
  })

})

describe('settings save bar', () => {
  it('is gated purely on the dirty flag', () => {
    expect(source).toContain('{isDirty && (')
    expect(source).toContain('const settings = draft')
  })

  it('does not use framer layout on the sticky bar (breaks position: sticky projection)', () => {
    const barStart = source.indexOf('key="settings-save-bar"')
    const barEnd = source.indexOf('</AnimatePresence>', barStart)
    const bar = source.slice(barStart, barEnd)
    expect(bar).not.toMatch(/^\s*layout\s*$/m)
  })

  it('reset button calls the draft reset, not a raw store setter', () => {
    expect(source).toContain('onClick={resetDraft}')
    expect(source).not.toContain('onClick={() => setDraft(storeSettings)}')
  })

  it('stays scroll-aware (docks at the end, eases while moving)', () => {
    expect(source).toContain('useSaveBarDock()')
    expect(source).toContain('style={{ bottom: docked ? 4 : 16 }}')
    expect(source).toContain('!docked && moving')
  })
})
