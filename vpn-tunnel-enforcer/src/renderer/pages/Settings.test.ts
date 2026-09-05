import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { changedSettingKeys } from './Settings'

const source = readFileSync(join(process.cwd(), 'src/renderer/pages/Settings.tsx'), 'utf8')

describe('changedSettingKeys', () => {
  it('reports nothing when draft equals baseline', () => {
    const s = { a: 1, b: 'x', c: true }
    expect(changedSettingKeys(s, { ...s })).toEqual([])
  })

  it('reports only the keys that actually differ', () => {
    const baseline = { a: 1, b: 'x', c: true }
    const draft = { a: 1, b: 'y', c: false }
    expect(changedSettingKeys(baseline, draft).sort()).toEqual(['b', 'c'])
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

describe('settings save bar wiring', () => {
  it('resets the draft to the saved baseline, not to a store reference', () => {
    expect(source).toContain('const resetDraft = useCallback(() => setDraft(baseline)')
    expect(source).toContain('onClick={resetDraft}')
    // The old bug: reset targeted a possibly-stale store ref.
    expect(source).not.toContain('onClick={() => setDraft(storeSettings)}')
  })

  it('advances the baseline on every persist path so applied changes stop counting as dirty', () => {
    // explicit save, rule-set refresh, and the instant-apply location toggle
    expect(source.match(/setBaseline\(/g)?.length ?? 0).toBeGreaterThanOrEqual(4)
  })

  it('drives the dirty state from the baseline diff', () => {
    expect(source).toContain('const isDirty = changedKeys.length > 0')
    expect(source).toContain('changedSettingKeys(baseline, draft)')
  })

  it('makes the save bar scroll-aware (docks at the end, eases while moving)', () => {
    expect(source).toContain('useSaveBarDock()')
    expect(source).toContain('style={{ bottom: docked ? 8 : 16 }}')
    expect(source).toContain('!docked && moving')
  })
})
