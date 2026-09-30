import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ manifest: null as any, writes: [] as any[], scripts: [] as string[],
  snapshot: ['Domain','Private','Public'].map(name => ({ name, defaultOutbound: 'Block' })),
  failWrite: false, failApply: false, failRestore: false, invalidRead: false }))
vi.mock('electron', () => ({ app: { getPath: () => 'C:\\VPNTE' },
  BrowserWindow: { getAllWindows: () => [] }, dialog: { showMessageBox: vi.fn(async () => ({})) } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./recoveryManifest', () => ({
  getRecoveryManifestDir: () => 'C:\\ProgramData\\VPNTE\\manifests',
  recoveryManifestPath: (name: string) => `C:\\ProgramData\\VPNTE\\manifests\\${name}`,
  readRecoveryManifest: async (_name: string, validate: Function) => {
    if (state.invalidRead) throw new Error('untrusted ACL')
    return state.manifest ? validate(state.manifest) : null
  },
  writeRecoveryManifest: async (_name: string, value: unknown, validate: Function) => {
    if (state.failWrite) throw new Error('disk full')
    state.manifest = validate(value); state.writes.push(structuredClone(state.manifest))
  },
  writeRecoveryArtifact: vi.fn(async () => {}),
  removeRecoveryManifest: async () => { state.manifest = null }
}))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./elevatedPsHelper', () => ({ isElevatedPsHelperRunning: () => true,
  execElevatedPs: async (script: string) => {
    state.scripts.push(script)
    if (script.includes('SNAPSHOT:')) return { stdout: 'SNAPSHOT:' + JSON.stringify(state.snapshot), stderr: '' }
    if (script.includes('# --- Step 2:')) {
      if (!state.manifest || state.manifest.phase !== 'prepared') throw new Error('mutated without a durable snapshot')
      if (state.failApply) throw new Error('apply failed')
      return { stdout: 'RULES:VPNTE-killswitch-allow-app', stderr: '' }
    }
    if (script.includes("Write-Output 'RESTORED'")) {
      if (state.failRestore) throw new Error('restore failed')
      return { stdout: 'RESTORED', stderr: '' }
    }
    return { stdout: '0', stderr: '' }
  }
}))
import { enableKillSwitch, disableKillSwitch } from './firewallKillSwitch'
const originalPlatform = process.platform
const options = { singboxExePath: 'C:\\VPNTE\\sing-box.exe' }
beforeEach(() => {
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
  state.manifest = null; state.writes = []; state.scripts = []
  state.failWrite = false; state.failApply = false; state.failRestore = false; state.invalidRead = false
})
afterEach(() => { Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true }) })
describe('firewall transaction fault injection (AT-03-003/004/007; F-030, F-186)', () => {
  it('commits the real original Block policies BEFORE mutation', async () => {
    expect((await enableKillSwitch(options)).success).toBe(true)
    expect(state.writes.map(value => value.phase)).toEqual(['prepared','active'])
    expect(state.manifest.savedProfiles).toEqual(state.snapshot)
  })
  it('preserves the first snapshot on a repeated enable', async () => {
    await enableKillSwitch(options)
    state.snapshot = state.snapshot.map(value => ({ ...value, defaultOutbound: 'Allow' }))
    await enableKillSwitch(options)
    expect(state.manifest.savedProfiles.every((p: any) => p.defaultOutbound === 'Block')).toBe(true)
    state.snapshot = state.snapshot.map(value => ({ ...value, defaultOutbound: 'Block' }))
  })
  it('does not mutate firewall when the prepared manifest cannot be persisted', async () => {
    state.failWrite = true
    expect((await enableKillSwitch(options)).success).toBe(false)
    expect(state.scripts.some(s => s.includes('New-NetFirewallRule'))).toBe(false)
  })
  it('refuses to overwrite an untrusted recovery source', async () => {
    state.invalidRead = true
    expect((await enableKillSwitch(options)).state).toBe('unknown')
    expect(state.scripts).toHaveLength(0)
  })
  it('retains the snapshot after failed rollback rather than claiming success', async () => {
    await enableKillSwitch(options); state.failRestore = true
    expect((await disableKillSwitch('test')).success).toBe(false)
    expect(state.manifest).not.toBeNull()
  })
  it('restores all policies and clears the snapshot only after read-back', async () => {
    await enableKillSwitch(options)
    expect((await disableKillSwitch('test')).success).toBe(true)
    expect(state.scripts.at(-1)).toContain('Policy read-back mismatch')
    expect(state.scripts.at(-1)).toContain("-DefaultOutboundAction Block")
    expect(state.manifest).toBeNull()
  })
})
