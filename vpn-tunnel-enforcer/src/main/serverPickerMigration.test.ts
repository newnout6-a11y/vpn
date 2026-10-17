// AT-09-014: inspection drafts must not become accepted profiles on restart.
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { cacheInspectionResult } from './vpnInspectionCache'

const source = ts.createSourceFile('serverPicker.ts', readFileSync('src/main/serverPicker.ts', 'utf8'), ts.ScriptTarget.Latest, true)
const migration = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'migrateLegacyDirectVpnProfiles')!
const compiled = ts.transpileModule(migration.getText(source).replace(/^export /, '') + '\nreturn migrateLegacyDirectVpnProfiles;', {
  compilerOptions: { target: ts.ScriptTarget.ES2022 }
}).outputText

function harness(acceptedInput = '') {
  const settings = {
    directVpnInput: acceptedInput, directVpnSelectedIndex: 0,
    directVpnCachedInput: '', directVpnCachedProfiles: [] as any[]
  }
  let profiles: any[] = []
  const picker = { set: vi.fn() }
  const saveProfiles = vi.fn((value: any[]) => { profiles = value })
  const settingsStore = { get: () => settings, save: (patch: object) => Object.assign(settings, patch) }
  const restart = new Function('settingsStore', 'getProfiles', 'saveProfiles', 'store', 'randomUUID', 'normalizeServerPort', 'logEvent', compiled)(
    settingsStore, () => profiles, saveProfiles, picker, () => 'migrated-id',
    (port: number, fallback: number) => port || fallback, vi.fn()
  ) as () => void
  const inspect = (input: string) => cacheInspectionResult(settingsStore.save, input, {
    profiles: [{ name: 'Preview', protocol: 'vless', outbound: { type: 'vless', server: 'example.invalid', server_port: 443 } }],
    source: 'text'
  })
  return { settings, picker, saveProfiles, restart, inspect, profiles: () => profiles }
}

describe('legacy picker migration — AT-09-014', () => {
  it('does not add or select an inspected key after it was discarded in the wizard', () => {
    const h = harness()
    h.inspect('draft-key')
    // Editing the wizard text or skipping it leaves directVpnInput empty.
    h.restart()
    expect(h.profiles()).toEqual([])
    expect(h.picker.set).not.toHaveBeenCalled()
    expect(h.saveProfiles).not.toHaveBeenCalled()
  })

  it('does not replace an accepted input with profiles from another inspection', () => {
    const h = harness('accepted-key')
    h.inspect('discarded-key')
    h.restart()
    expect(h.settings.directVpnInput).toBe('accepted-key')
    expect(h.profiles()).toEqual([])
    expect(h.picker.set).not.toHaveBeenCalled()
  })

  it('still migrates the explicitly accepted key once and selects its profile', () => {
    const h = harness()
    h.inspect(' accepted-key ')
    h.settings.directVpnInput = ' accepted-key '
    h.restart()
    h.restart()
    expect(h.profiles()).toMatchObject([{ id: 'migrated-id', name: 'Preview', server: 'example.invalid' }])
    expect(h.saveProfiles).toHaveBeenCalledTimes(1)
    expect(h.picker.set).toHaveBeenCalledExactlyOnceWith('activeProfileId', 'migrated-id')
    expect(h.settings.directVpnCachedProfiles).toEqual([])
  })
})
