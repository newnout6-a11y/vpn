import { execFileSync } from 'child_process'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ manifest: null as any, writes: [] as any[], scripts: [] as string[],
  snapshot: ['Domain','Private','Public'].map(name => ({ name, defaultOutbound: 'Block' })),
  failWrite: false, failApply: false, failRestore: false, invalidRead: false,
  liveFailures: 0, liveMissingMarker: false, failCommit: false }))
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
    if (state.failCommit && (value as any).exceptionPolicy && !(value as any).pendingExceptionPolicy) { state.failCommit = false; throw new Error('disk full') }
    state.manifest = validate(value); state.writes.push(structuredClone(state.manifest))
  },
  writeRecoveryArtifact: vi.fn(async () => {}),
  removeRecoveryManifest: async () => { state.manifest = null }
}))
vi.mock('./admin', () => ({ execElevated: vi.fn(async () => { throw new Error('Fallback boundary refused') }) }))
vi.mock('./elevatedPsHelper', () => ({ isElevatedPsHelperRunning: () => true,
  execElevatedPs: async (script: string) => {
    state.scripts.push(script)
    if (script.includes("Write-Output 'EXCEPTIONS_VERIFIED'")) {
      if (!state.manifest?.pendingExceptionPolicy) throw new Error('Live effects without durable journal')
      if (state.liveFailures > 0) { state.liveFailures--; throw new Error('injected live failure') }
      if (state.liveMissingMarker) { state.liveMissingMarker = false; return { stdout: '', stderr: '' } }
      return { stdout: 'EXCEPTIONS_VERIFIED', stderr: '' }
    }
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
import { enableKillSwitch, disableKillSwitch, updateKillSwitchExceptions } from './firewallKillSwitch'
const originalPlatform = process.platform
const options = { singboxExePath: 'C:\\VPNTE\\sing-box.exe' }
beforeEach(() => {
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
  state.manifest = null; state.writes = []; state.scripts = []
  state.failWrite = false; state.failApply = false; state.failRestore = false; state.invalidRead = false
  state.liveFailures = 0; state.liveMissingMarker = false; state.failCommit = false
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


describe('differential live firewall fault injection (AT-03-008/009)', () => {
  async function active() {
    await enableKillSwitch(options)
    state.manifest.ruleNames.push('VPNTE-killswitch-allow-xray', 'VPNTE-killswitch-allow-happ')
    state.manifest.exceptionPolicy = { apps: [], cidrs: ['192.0.2.1'] }
    state.writes = []; state.scripts = []
  }
  it('preserves upstream/core rules and original profiles without setting Allow', async () => {
    await active()
    const baseline = structuredClone(state.manifest.savedProfiles)
    expect((await updateKillSwitchExceptions([], ['198.51.100.2'])).success).toBe(true)
    expect(state.manifest.savedProfiles).toEqual(baseline)
    expect(state.manifest.ruleNames).toContain('VPNTE-killswitch-allow-xray')
    expect(state.manifest.ruleNames).toContain('VPNTE-killswitch-allow-happ')
    expect(state.writes[0].pendingExceptionPolicy).toEqual({ apps: [], cidrs: ['198.51.100.2'] })
    expect(state.manifest.pendingExceptionPolicy).toBeUndefined()
    expect(state.scripts[0]).not.toContain('Set-NetFirewallProfile')
    expect(state.scripts[0]).not.toContain("-DisplayName 'VPNTE-killswitch*'")
    expect(state.scripts[0]).toContain('Program filter read-back mismatch')
    expect(state.scripts[0]).toContain('Remote filter read-back mismatch')
  })
  it('does not perform effects after a journal persistence failure', async () => {
    await active(); state.failWrite = true
    await expect(updateKillSwitchExceptions([], ['198.51.100.2'])).rejects.toThrow('disk full')
    expect(state.scripts).toEqual([])
  })
  it.each(['script', 'marker', 'commit'])('compensates the exact previous exception policy after %s failure', async failure => {
    await active()
    if (failure === 'script') state.liveFailures = 1
    if (failure === 'marker') state.liveMissingMarker = true
    if (failure === 'commit') state.failCommit = true
    const result = await updateKillSwitchExceptions([], ['198.51.100.2'])
    expect(result.success).toBe(false)
    expect(state.manifest.exceptionPolicy).toEqual({ apps: [], cidrs: ['192.0.2.1'] })
    expect(state.manifest.pendingExceptionPolicy).toBeUndefined()
    expect(result.state).toBeUndefined()
    expect(state.scripts).toHaveLength(2)
    expect(state.scripts.every(s => !s.includes('Set-NetFirewallProfile'))).toBe(true)
  })
  it('retains the pending recovery journal and reports unknown if compensation fails', async () => {
    await active(); state.liveFailures = 2
    const result = await updateKillSwitchExceptions([], ['198.51.100.2'])
    expect(result.state).toBe('unknown')
    expect(state.manifest.pendingExceptionPolicy).toEqual({ apps: [], cidrs: ['198.51.100.2'] })
    expect(state.manifest.savedProfiles).toEqual(state.snapshot)
  })
  it('rejects unsafe values before persistence or native calls', async () => {
    await active()
    await expect(updateKillSwitchExceptions([], ['0.0.0.0/0'])).rejects.toThrow()
    await expect(updateKillSwitchExceptions(['\\\\server\\evil.exe'], [])).rejects.toThrow('local')
    await expect(updateKillSwitchExceptions(['C:\\app\\..\\evil.exe'], [])).rejects.toThrow('local')
    expect(state.writes).toEqual([])
    expect(state.scripts).toEqual([])
  })
  it('serializes 50 concurrent policy replacements with a durable commit for each', async () => {
    await active()
    const results = await Promise.all(Array.from({ length: 50 }, (_, i) => updateKillSwitchExceptions([], [`192.0.2.${i+2}`])))
    expect(results.every(result => result.success)).toBe(true)
    expect(state.writes).toHaveLength(100)
    expect(state.manifest.exceptionPolicy.cidrs).toEqual(['192.0.2.51'])
  })
  it.skipIf(!process.env.VPNTE_PWSH)('parses actual live scripts with PowerShell', async () => {
    await active(); await updateKillSwitchExceptions([], ['198.51.100.2'])
    const encoded = Buffer.from(state.scripts[0]).toString('base64')
    const command = `$tokens=$null;$errors=$null;$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'));[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|Out-String|Write-Output;exit 1}`
    expect(() => execFileSync(process.env.VPNTE_PWSH!, ['-NoProfile','-NonInteractive','-Command',command], { encoding: 'utf8' })).not.toThrow()
  })
})
