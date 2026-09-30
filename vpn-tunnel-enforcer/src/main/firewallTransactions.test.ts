import { execFileSync } from 'child_process'
import { mkdirSync, mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from 'fs'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ manifest: null as any, writes: [] as any[], scripts: [] as string[],
  snapshot: ['Domain','Private','Public'].map(name => ({ name, defaultOutbound: 'Block' })),
  failWrite: false, failApply: false, failRestore: false, invalidRead: false,
  liveFailures: 0, liveMissingMarker: false, failCommit: false,
  artifacts: [] as string[], helperAvailable: true, helperFailure: null as any, helperExitCode: 0,
  fileProbe: vi.fn((..._args: any[]) => '0'),
  fallback: vi.fn(async (..._args: any[]) => ({ stdout: 'SNAPSHOT:[]', stderr: '' })) }))
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
  writeRecoveryArtifact: vi.fn(async (name: string) => { state.artifacts.push(name) }),
  removeRecoveryManifest: async () => { state.manifest = null }
}))
vi.mock('./admin', () => ({ execElevated: (...args: any[]) => state.fallback(...args), isProcessElevated: async () => false }))
vi.mock('child_process', async importOriginal => {
  const actual = await importOriginal<typeof import('child_process')>()
  const execFile = (...args: any[]) => {
    const callback = args.pop()
    callback(null, { stdout: state.fileProbe(...args), stderr: '' })
  }
  return { ...actual, execFile, default: { ...actual, execFile } }
})
vi.mock('./elevatedPsHelper', () => ({ isElevatedPsHelperRunning: () => state.helperAvailable,
  execElevatedPs: async (script: string) => {
    state.scripts.push(script)
    if (state.helperFailure) throw state.helperFailure
    if (state.helperExitCode) return { stdout: '', stderr: 'native command failed', exitCode: state.helperExitCode }
    if (script.includes('# --- Step 2:')) {
      if (!state.manifest || state.manifest.phase !== 'prepared') throw new Error('mutated without a durable snapshot')
      if (state.failApply) throw new Error('apply failed')
      const withExceptions = script.includes("Write-Output 'EXCEPTIONS_VERIFIED'")
      if (withExceptions && !state.manifest.pendingExceptionPolicy) throw new Error('Initial effects without journal')
      if (withExceptions && state.liveFailures > 0) { state.liveFailures--; throw new Error('initial exceptions failed') }
      const marker = withExceptions && !state.liveMissingMarker ? 'EXCEPTIONS_VERIFIED\n' : ''
      return { stdout: marker + 'RULES:VPNTE-killswitch-allow-app', stderr: '', exitCode: 0 }
    }
    if (script.includes("Write-Output 'EXCEPTIONS_VERIFIED'")) {
      if (!state.manifest?.pendingExceptionPolicy) throw new Error('Live effects without durable journal')
      if (state.liveFailures > 0) { state.liveFailures--; throw new Error('injected live failure') }
      if (state.liveMissingMarker) { state.liveMissingMarker = false; return { stdout: '', stderr: '' } }
      return { stdout: 'EXCEPTIONS_VERIFIED', stderr: '' }
    }
    if (script.includes('SNAPSHOT:')) return { stdout: 'SNAPSHOT:' + JSON.stringify(state.snapshot), stderr: '' }
    if (script.includes("Write-Output 'RESTORED'")) {
      if (state.failRestore) throw new Error('restore failed')
      return { stdout: 'RESTORED', stderr: '' }
    }
    return { stdout: '0', stderr: '' }
  }
}))
import { enableKillSwitch, disableKillSwitch, isKillSwitchActive, updateKillSwitchExceptions } from './firewallKillSwitch'
const originalPlatform = process.platform
const options = { singboxExePath: 'C:\\VPNTE\\sing-box.exe' }
beforeEach(() => {
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
  state.manifest = null; state.writes = []; state.scripts = []
  state.failWrite = false; state.failApply = false; state.failRestore = false; state.invalidRead = false
  state.liveFailures = 0; state.liveMissingMarker = false; state.failCommit = false
  state.artifacts = []; state.helperAvailable = true; state.helperFailure = null; state.helperExitCode = 0
  state.fallback.mockReset().mockRejectedValue(new Error('Fallback boundary refused'))
  state.fileProbe.mockReset().mockReturnValue('0')
})
afterEach(() => { Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true }) })
describe('firewall transaction fault injection (AT-03-003/004/007; F-030, F-186)', () => {
  it('prepares in parallel but waits for verified TUN before applying policy (AT-03-004)', async () => {
    let confirm!: (ready: boolean) => void
    const tunAdapterReady = new Promise<boolean>(resolve => { confirm = resolve })
    const pending = enableKillSwitch({ ...options, tunAdapterReady, extraAllowedRemoteCidrs: ['192.0.2.1'] })
    await vi.waitFor(() => expect(state.manifest?.phase).toBe('prepared'))
    expect(state.scripts.some(s => s.includes('# --- Step 2:'))).toBe(false)
    confirm(true)
    expect((await pending).success).toBe(true)
    const script = state.scripts.find(s => s.includes('# --- Step 2:'))!
    expect(script).not.toContain('Get-NetAdapter')
    expect(script).not.toContain('Start-Sleep')
    expect(script).not.toMatch(/New-NetFirewallRule\s+`\s+-DisplayName 'VPNTE-killswitch-allow-extra-ip'/)
    // Use the actual helper policy validator, with elevation unavailable, so
    // accepted means it reached startup; no process or OS mutation is possible.
    const helper = await vi.importActual<typeof import('./elevatedPsHelper')>('./elevatedPsHelper')
    await expect(helper.execElevatedPs(script, 1000, 'firewall-killswitch')).rejects.toMatchObject({ code: 'elevated-helper-unavailable' })
  })
  it.each(['cancelled', 'rejected'])('does not apply policy after adapter readiness is %s (AT-03-007)', async reason => {
    const tunAdapterReady = reason === 'cancelled' ? Promise.resolve(false) : Promise.reject(new Error('ownership failed'))
    expect((await enableKillSwitch({ ...options, tunAdapterReady })).success).toBe(false)
    expect(state.scripts.some(s => s.includes('# --- Step 2:'))).toBe(false)
    expect(state.scripts.some(s => s.includes("Write-Output 'RESTORED'"))).toBe(true)
    expect(state.manifest).toBeNull()
  })
  it('retains the bounded native wait for callers without an ownership barrier (AT-03-004)', async () => {
    await enableKillSwitch(options)
    const script = state.scripts.find(s => s.includes('# --- Step 2:'))!
    expect(script).toContain('Get-NetAdapter')
    expect(script).toContain('$i -lt 150')
    const helper = await vi.importActual<typeof import('./elevatedPsHelper')>('./elevatedPsHelper')
    await expect(helper.execElevatedPs(script, 1000, 'firewall-killswitch')).rejects.toMatchObject({ code: 'elevated-helper-script-rejected' })
  })
  it('executes successful helper commands without persisting fallback scripts (AT-03-004)', async () => {
    expect((await enableKillSwitch(options)).success).toBe(true)
    expect(state.artifacts).toEqual([])
    expect(state.fallback).not.toHaveBeenCalled()
  })
  it('uses a live helper for inactive-firewall read-only probes without a file or cold process (AT-03-004)', async () => {
    expect(await isKillSwitchActive()).toBe(false)
    expect(state.scripts).toHaveLength(1)
    expect(state.artifacts).toEqual([])
    expect(state.fileProbe).not.toHaveBeenCalled()
  })
  it('retains the trusted-file read-only fallback when no helper is running (AT-03-004)', async () => {
    state.helperAvailable = false
    expect(await isKillSwitchActive()).toBe(false)
    expect(state.scripts).toEqual([])
    expect(state.artifacts).toHaveLength(1)
    expect(state.fileProbe).toHaveBeenCalledOnce()
  })
  it.each([
    { code: 'elevated-helper-script-rejected', fallback: true },
    { code: 'elevated-helper-unavailable', fallback: true },
    { code: 'elevated-helper-timeout', fallback: false },
    { code: 'elevated-helper-exited', fallback: false },
    { code: undefined, fallback: false }
  ])('only falls back before any helper effects: $code (AT-03-007)', async ({ code, fallback }) => {
    state.helperFailure = Object.assign(new Error('transport failure'), { code })
    await expect(enableKillSwitch(options)).rejects.toThrow()
    expect(state.artifacts.length > 0).toBe(fallback)
    expect(state.fallback.mock.calls.length > 0).toBe(fallback)
  })
  it('treats a failed native helper reply as failure without replaying effects (AT-03-007)', async () => {
    state.helperExitCode = 1
    await expect(enableKillSwitch(options)).rejects.toThrow('native command failed')
    expect(state.artifacts).toEqual([])
    expect(state.fallback).not.toHaveBeenCalled()
  })
  it.each([[], ['192.0.2.1'], ['192.0.2.1', '198.51.100.2']])('verifies initial exceptions in one prepared transaction: %j (AT-03-008)', async (...cidrs: string[]) => {
    expect((await enableKillSwitch({ ...options, appExceptionPaths: [], extraAllowedRemoteCidrs: cidrs })).success).toBe(true)
    expect(state.writes.map(value => value.phase)).toEqual(['prepared', 'active'])
    expect(state.writes[0].pendingExceptionPolicy).toEqual({ apps: [], cidrs })
    expect(state.manifest.exceptionPolicy).toEqual({ apps: [], cidrs })
    expect(state.manifest.pendingExceptionPolicy).toBeUndefined()
    expect(state.scripts.filter(s => s.includes("Write-Output 'EXCEPTIONS_VERIFIED'"))).toHaveLength(1)
    expect(state.artifacts).toEqual([])
  })
  it.each(['script', 'marker', 'commit'])('rolls back the initial transaction after exception %s failure (AT-03-007)', async failure => {
    if (failure === 'script') state.liveFailures = 1
    if (failure === 'marker') state.liveMissingMarker = true
    if (failure === 'commit') state.failCommit = true
    const result = await enableKillSwitch({ ...options, appExceptionPaths: [], extraAllowedRemoteCidrs: ['192.0.2.1'] })
    expect(result.success).toBe(false)
    expect(state.scripts.some(s => s.includes("Write-Output 'RESTORED'"))).toBe(true)
    expect(state.manifest).toBeNull()
    expect(state.fallback).not.toHaveBeenCalled()
  })
  it('retains the prepared initial policy if compensation cannot be verified (AT-03-007)', async () => {
    state.liveFailures = 1; state.failRestore = true
    expect((await enableKillSwitch({ ...options, extraAllowedRemoteCidrs: ['192.0.2.1'] })).success).toBe(false)
    expect(state.manifest.phase).toBe('prepared')
    expect(state.manifest.pendingExceptionPolicy.cidrs).toEqual(['192.0.2.1'])
  })
  it.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH).each([
    { cidrs: [], ready: false }, { cidrs: ['192.0.2.1'], ready: false }, { cidrs: ['192.0.2.1', '198.51.100.2'], ready: false },
    { cidrs: [], ready: true }, { cidrs: ['192.0.2.1'], ready: true }, { cidrs: ['192.0.2.1', '198.51.100.2'], ready: true }
  ])('executes the merged production transaction in native PowerShell: $cidrs / barrier $ready (AT-03-008)', async ({ cidrs, ready }) => {
    await enableKillSwitch({ ...options, appExceptionPaths: [], extraAllowedRemoteCidrs: cidrs, ...(ready ? { tunAdapterReady: Promise.resolve(true) } : {}) })
    const transaction = state.scripts.find(s => s.includes('# --- Step 2:'))!
    // Cmdlets are fixtures; this never writes Windows policy or recovery files.
    const script = `
$script:fixtureRules=@{};$script:outbound='Allow'
function Get-NetAdapter { [pscustomobject]@{Status='Up'} }
function Get-NetFirewallProfile { 'Domain','Private','Public' | ForEach-Object { [pscustomobject]@{DefaultOutboundAction=$script:outbound} } }
function Set-NetFirewallProfile { param($Profile,$DefaultOutboundAction) $script:outbound=$DefaultOutboundAction }
function Get-NetFirewallRule { param($DisplayName) @($script:fixtureRules.Values) | Where-Object { $_.DisplayName -like $DisplayName } }
function Remove-NetFirewallRule { param([Parameter(ValueFromPipeline=$true)]$Rule) process { if($Rule){$script:fixtureRules.Remove($Rule.DisplayName)} } }
function New-NetFirewallRule { param($DisplayName,$Description,$Direction,$Action,$Profile,$Enabled,$Program,$RemoteAddress,$LocalAddress,$InterfaceAlias,$Protocol,$RemotePort)
  $script:fixtureRules[$DisplayName]=[pscustomobject]@{DisplayName=$DisplayName;Direction=$Direction;Action=$Action;Enabled=$Enabled;Program=$Program;RemoteAddress=$RemoteAddress}
}
function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline=$true)]$Rule) process { [pscustomobject]@{RemoteAddress=$Rule.RemoteAddress} } }
function Get-NetFirewallApplicationFilter { param([Parameter(ValueFromPipeline=$true)]$Rule) process { [pscustomobject]@{Program=$Rule.Program} } }
${transaction}
Write-Output ('RESULT:' + (@($script:fixtureRules.Values | Where-Object {$_.DisplayName -like 'VPNTE-killswitch-user-*'} | ForEach-Object { $_.RemoteAddress }) | ConvertTo-Json -Compress))
`
    const temporaryRoot = join(process.cwd(), '.tmp')
    mkdirSync(temporaryRoot, { recursive: true })
    const temporary = mkdtempSync(join(temporaryRoot, 'firewall-initial-'))
    const scriptPath = join(temporary, 'harness.ps1')
    let output: string
    try {
      writeFileSync(scriptPath, '\ufeff' + script)
      output = execFileSync(process.env.VPNTE_PWSH || 'powershell.exe',
        ['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File', scriptPath],
        { encoding: 'utf8', timeout: 15000, stdio: ['ignore','pipe','pipe'] })
    } finally { unlinkSync(scriptPath); rmdirSync(temporary) }
    expect(output).toContain('EXCEPTIONS_VERIFIED')
    expect(output).toContain('RULES:VPNTE-killswitch-allow-singbox')
    const raw = output.split(/\r?\n/).find(line => line.startsWith('RESULT:'))!.slice(7)
    const values = raw ? JSON.parse(raw) : []
    expect((Array.isArray(values) ? values : [values]).sort()).toEqual([...cidrs].sort())
  }, 20000)
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

  it.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH).each([
    { cidrs: [] }, { cidrs: ['192.0.2.1'] }, { cidrs: ['192.0.2.1', '198.51.100.2'] }
  ])('executes the production live script for native JSON policy $cidrs (AT-03-008)', async ({ cidrs }) => {
    await active()
    await updateKillSwitchExceptions([], cidrs)
    // In-memory cmdlets only: no Windows firewall or recovery files are touched.
    const script = `
$script:rules=@{}
function Get-NetFirewallProfile { 'Domain','Private','Public' | ForEach-Object { [pscustomobject]@{DefaultOutboundAction='Block'} } }
function Get-NetFirewallRule { param($DisplayName) $script:rules.Values | Where-Object { $_.DisplayName -like $DisplayName } }
function Remove-NetFirewallRule { param([Parameter(ValueFromPipeline=$true)]$Rule) process { if($Rule){$script:rules.Remove($Rule.DisplayName)} } }
function New-NetFirewallRule { param($DisplayName,$Direction,$Action,$Profile,$Enabled,$Program,$RemoteAddress)
  if($DisplayName -isnot [string] -or -not $DisplayName){throw 'Invalid scalar rule name'}
  $script:rules[$DisplayName]=[pscustomobject]@{DisplayName=$DisplayName;Direction=$Direction;Action=$Action;Enabled=$Enabled;Program=$Program;RemoteAddress=$RemoteAddress}
}
function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline=$true)]$Rule) process { [pscustomobject]@{RemoteAddress=$Rule.RemoteAddress} } }
function Get-NetFirewallApplicationFilter { param([Parameter(ValueFromPipeline=$true)]$Rule) process { [pscustomobject]@{Program=$Rule.Program} } }
${state.scripts[0]}
Write-Output ('RESULT:' + (@($script:rules.Values | ForEach-Object { $_.RemoteAddress }) | ConvertTo-Json -Compress))
`
    const output = execFileSync(process.env.VPNTE_PWSH || 'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { encoding: 'utf8', timeout: 15000, stdio: ['ignore','pipe','pipe'] })
    expect(output).toContain('EXCEPTIONS_VERIFIED')
    const raw = output.split(/\r?\n/).find(line => line.startsWith('RESULT:'))!.slice(7)
    const values = raw ? JSON.parse(raw) : []
    expect((Array.isArray(values) ? values : [values]).sort()).toEqual([...cidrs].sort())
  }, 20000)
})
