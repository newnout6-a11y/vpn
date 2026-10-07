import { execFileSync } from 'child_process'
import { mkdirSync, mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from 'fs'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { FIREWALL_RULES_API_PS } from './firewallRulesApi'
import { FIREWALL_RULES_BOUNDARY_FIXTURE_PS } from './testFixtures/firewallRulesBoundary'
const state = vi.hoisted(() => ({ manifest: null as any, writes: [] as any[], scripts: [] as string[],
  snapshot: ['Domain','Private','Public'].map(name => ({ name, defaultOutbound: 'Block' })),
  failWrite: false, failApply: false, failRestore: false, invalidRead: false, readError: null as Error | null,
  quarantines: [] as string[], failQuarantine: false, ownedRules: false,
  wfpCalls: [] as string[], wfpActive: false, wfpFailApply: 0, wfpFailRemove: false, wfpFailVerify: false,
  manifestReads: 0,
  liveFailures: 0, liveMissingMarker: false, failCommit: false,
  artifacts: [] as string[], helperAvailable: true, helperFailure: null as any, helperExitCode: 0, longApps: false,
  nativeTimings: '', fileProbe: vi.fn((..._args: any[]) => '0'),
  fallback: vi.fn(async (..._args: any[]) => ({ stdout: 'SNAPSHOT:[]', stderr: '' })) }))
vi.mock('electron', () => ({ app: { getPath: () => 'C:\\VPNTE' },
  BrowserWindow: { getAllWindows: () => [] }, dialog: { showMessageBox: vi.fn(async () => ({})) } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./wfpIpv6', async importOriginal => ({
  ...await importOriginal<typeof import('./wfpIpv6')>(),
  prepareWfpIpv6Policy: async (opts: { signal?: AbortSignal }) => { state.wfpCalls.push('prepare'); opts.signal?.throwIfAborted(); return { schemaVersion: 1, rules: ['connect','accept','boot'].map((layer, i) => ({ id: `00000000-0000-0000-0000-00000000000${i + 1}`, role: 'block', appId: '', remote: '', luid: '', originalApp: false, inbound: layer === 'accept', boot: layer === 'boot' })) } },
  prepareWfpIpv6Exceptions: async (previous: unknown) => previous,
  applyWfpIpv6Policy: async () => {
    state.wfpCalls.push('apply')
    if (!state.manifest?.ipv6Policy) throw new Error('WFP effects without recovery journal')
    if (state.wfpFailApply > 0) { state.wfpFailApply--; throw new Error('WFP apply failure') }
    state.wfpActive = true
  },
  verifyWfpIpv6Policy: async () => { state.wfpCalls.push('verify'); if (state.wfpFailVerify) throw new Error('WFP coverage changed') },
  removeWfpIpv6Protection: async () => { state.wfpCalls.push('remove'); if (state.wfpFailRemove) throw new Error('WFP remove failure'); state.wfpActive = false },
  hasWfpIpv6Protection: async () => state.wfpActive
}))
vi.mock('fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('fs/promises')>()
  const api = { ...actual,
    access: (...args: Parameters<typeof actual.access>) => state.longApps ? Promise.resolve() : actual.access(...args),
    realpath: (...args: Parameters<typeof actual.realpath>) => state.longApps ? Promise.resolve(args[0]) : actual.realpath(...args),
    stat: (...args: Parameters<typeof actual.stat>) => state.longApps ? Promise.resolve({ isFile: () => true }) : actual.stat(...args)
  }
  return { ...api, default: api }
})
vi.mock('./recoveryManifest', async importOriginal => ({
  ...await importOriginal<typeof import('./recoveryManifest')>(),
  getRecoveryManifestDir: () => 'C:\\ProgramData\\VPNTE\\manifests',
  recoveryManifestPath: (name: string) => `C:\\ProgramData\\VPNTE\\manifests\\${name}`,
  readRecoveryManifest: async (_name: string, validate: Function) => {
    state.manifestReads++
    if (state.readError) throw state.readError
    if (state.invalidRead) throw new Error('untrusted ACL')
    return state.manifest ? validate(state.manifest) : null
  },
  writeRecoveryManifest: async (_name: string, value: unknown, validate: Function) => {
    if (state.failWrite) throw new Error('disk full')
    if (state.failCommit && (value as any).exceptionPolicy && !(value as any).pendingExceptionPolicy) { state.failCommit = false; throw new Error('disk full') }
    state.manifest = validate(value); state.writes.push(structuredClone(state.manifest))
  },
  writeRecoveryArtifact: vi.fn(async (name: string) => { state.artifacts.push(name) }),
  removeRecoveryManifest: async () => { state.manifest = null },
  strictRecoveryRequired: async () => false,
  quarantineRecoveryManifest: async (name: string) => { if (state.failQuarantine) throw new Error('quarantine refused'); state.quarantines.push(name) }
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
    if (script.length > 64 * 1024) {
      // Exercise the real helper's pre-dispatch size guard; no native process.
      const helper = await vi.importActual<typeof import('./elevatedPsHelper')>('./elevatedPsHelper')
      return helper.execElevatedPs(script, 1000, 'firewall-killswitch')
    }
    if (state.helperExitCode) return { stdout: '', stderr: 'native command failed', exitCode: state.helperExitCode }
    if (script.includes('# --- Step 2:')) {
      if (!state.manifest || state.manifest.phase !== 'prepared') throw new Error('mutated without a durable snapshot')
      if (state.failApply) throw new Error('apply failed')
      const withExceptions = script.includes("Write-Output 'EXCEPTIONS_VERIFIED'")
      if (withExceptions && !state.manifest.pendingExceptionPolicy) throw new Error('Initial effects without journal')
      if (withExceptions && state.liveFailures > 0) { state.liveFailures--; throw new Error('initial exceptions failed') }
      const marker = withExceptions && !state.liveMissingMarker ? 'EXCEPTIONS_VERIFIED\n' : ''
      return { stdout: state.nativeTimings + marker + 'RULES:VPNTE-killswitch-allow-app', stderr: '', exitCode: 0 }
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
    return { stdout: state.ownedRules && script.includes('Get-VpnteFirewallRuleNames') ? '1' : '0', stderr: '' }
  }
}))
import { enableKillSwitch, disableKillSwitch, isKillSwitchActive, killSwitchManifestExists, updateKillSwitchExceptions, recoverStaleKillSwitch } from './firewallKillSwitch'
import { RecoveryManifestReadError } from './recoveryManifest'
import { logEvent } from './appLogger'
const originalPlatform = process.platform
const options = { singboxExePath: 'C:\\VPNTE\\sing-box.exe' }
function executeNativeFixture(script: string, productionApi = false): string {
  const temporaryRoot = join(process.cwd(), '.tmp')
  mkdirSync(temporaryRoot, { recursive: true })
  const temporary = mkdtempSync(join(temporaryRoot, 'firewall-transaction-'))
  const scriptPath = join(temporary, 'harness.ps1')
  try {
    writeFileSync(scriptPath, '\ufeff' + (productionApi ? script : FIREWALL_RULES_BOUNDARY_FIXTURE_PS + script.replace(FIREWALL_RULES_API_PS, '')))
    return execFileSync(process.env.VPNTE_PWSH || 'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath],
      { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] })
  } finally { unlinkSync(scriptPath); rmdirSync(temporary) }
}
beforeEach(() => {
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
  state.manifest = null; state.writes = []; state.scripts = []
  state.failWrite = false; state.failApply = false; state.failRestore = false; state.invalidRead = false
  state.readError = null; state.quarantines = []; state.failQuarantine = false; state.ownedRules = false
  state.wfpCalls = []; state.wfpActive = false; state.wfpFailApply = 0; state.wfpFailRemove = false; state.wfpFailVerify = false
  state.manifestReads = 0
  state.liveFailures = 0; state.liveMissingMarker = false; state.failCommit = false
  state.artifacts = []; state.helperAvailable = true; state.helperFailure = null; state.helperExitCode = 0
  state.longApps = false
  state.nativeTimings = ''; vi.mocked(logEvent).mockClear()
  state.fallback.mockReset().mockRejectedValue(new Error('Fallback boundary refused'))
  state.fileProbe.mockReset().mockReturnValue('0')
})
afterEach(() => { Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true }) })
describe('firewall transaction fault injection (AT-03-003/004/007; F-030, F-186)', () => {
  it('does not journal or mutate an already cancelled startup (AT-03-007)', async () => {
    const controller = new AbortController(); controller.abort()
    await expect(enableKillSwitch({ ...options, signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' })
    expect(state.writes).toEqual([])
    expect(state.wfpCalls).toEqual([])
    expect(state.scripts).toEqual([])
  })
  it('stops before IPv6 preparation when cancelled during the adapter barrier (AT-03-007)', async () => {
    const controller = new AbortController()
    let ready!: (value: boolean) => void
    const barrier = new Promise<boolean>(resolve => { ready = resolve })
    const pending = enableKillSwitch({ ...options, tunAdapterReady: barrier, signal: controller.signal })
    await vi.waitFor(() => expect(state.manifestReads).toBeGreaterThan(0))
    controller.abort(); ready(true)
    const result = await pending
    expect(result.success).toBe(false)
    expect(state.writes).toEqual([])
    expect(state.wfpCalls).toEqual(['prepare'])
    expect(state.scripts).toEqual([])
  })
  it('still removes owned WFP protection after firewall rollback fails (AT-03-007)', async () => {
    await enableKillSwitch(options); state.failRestore = true
    expect((await disableKillSwitch('independent rollback')).success).toBe(false)
    expect(state.wfpActive).toBe(false)
    expect(state.wfpCalls).toContain('remove')
    expect(state.manifest).not.toBeNull()
  })
  it('does not quarantine from concurrent read-only probes (AT-03-003/012)', async () => {
    state.readError = new RecoveryManifestReadError('invalid-content', 'corrupt JSON')
    await expect(killSwitchManifestExists()).rejects.toThrow('corrupt JSON')
    await expect(isKillSwitchActive()).rejects.toThrow('corrupt JSON')
    expect(state.quarantines).toEqual([])
    expect(state.scripts).toEqual([])
  })
  it('rejects a future IPv6 journal without quarantine or native effects (AT-03-003)', async () => {
    await enableKillSwitch(options); state.manifest.ipv6Policy.schemaVersion = 2; state.scripts = []; state.wfpCalls = []
    expect((await disableKillSwitch('future nested schema')).success).toBe(false)
    expect(state.quarantines).toEqual([])
    expect(state.scripts).toEqual([])
    expect(state.wfpCalls).toEqual([])
  })
  it('does not engage firewall or commit active state after WFP failure (AT-03-010)', async () => {
    state.wfpFailApply = 1
    expect((await enableKillSwitch(options)).success).toBe(false)
    expect(state.scripts.some(script => script.includes('# --- Step 2:'))).toBe(false)
    expect(state.wfpCalls).toEqual(['prepare','apply','remove'])
    expect(state.manifest).toBeNull()
  })
  it('preserves the recovery journal when WFP removal cannot be verified (AT-03-007)', async () => {
    expect((await enableKillSwitch(options)).success).toBe(true)
    state.wfpFailRemove = true
    expect((await disableKillSwitch('WFP removal failure')).success).toBe(false)
    expect(state.manifest).not.toBeNull()
    expect(state.wfpActive).toBe(true)
  })
  it('checks existing native IPv6 coverage before idempotent activation (AT-03-010)', async () => {
    await enableKillSwitch(options)
    state.scripts = []; state.wfpFailVerify = true
    expect(await enableKillSwitch(options)).toMatchObject({ success: false, state: 'unknown' })
    expect(state.scripts).toEqual([])
    expect(state.manifest.phase).toBe('active')
  })
  it('detects orphan WFP protection and cleans only owned filters without changing foreign profiles (AT-03-003)', async () => {
    state.wfpActive = true
    expect(await isKillSwitchActive()).toBe(true)
    expect((await disableKillSwitch('orphan WFP')).success).toBe(false)
    expect(state.wfpActive).toBe(false)
    expect(state.scripts.some(script => script.includes('Set-NetFirewallProfile'))).toBe(false)
  })
  it.each(['unsupported-version', 'untrusted', 'quarantine-failure'])('does not change owned firewall rules after %s recovery rejection (AT-03-003/012)', async mode => {
    state.readError = mode === 'untrusted' ? new Error('untrusted ACL') : new RecoveryManifestReadError(mode === 'unsupported-version' ? mode : 'invalid-content', 'fixture invalid manifest')
    state.failQuarantine = mode === 'quarantine-failure'
    state.ownedRules = true
    state.fileProbe.mockReturnValue('1')
    expect((await disableKillSwitch('rejected snapshot')).success).toBe(false)
    await recoverStaleKillSwitch(async () => false)
    expect(state.scripts).toEqual([])
    expect(state.quarantines).toEqual([])
  })
  it('quarantines corrupt trusted firewall data before unknown Allow fallback (AT-03-003)', async () => {
    state.readError = new RecoveryManifestReadError('invalid-content', 'corrupt JSON')
    state.ownedRules = true
    state.fileProbe.mockReturnValue('1')
    expect((await disableKillSwitch('corrupt snapshot')).success).toBe(true)
    expect(state.quarantines).toEqual(['firewall.json'])
    expect(state.scripts.some(script => script.includes("-DefaultOutboundAction Allow"))).toBe(true)
    expect(logEvent).toHaveBeenCalledWith('error', 'firewall-killswitch', expect.stringContaining('CRITICAL_SECURITY_EVENT'), expect.anything())
  })
  it('logs only bounded unique native phases without treating them as security proof (AT-00-005/AT-03-007)', async () => {
    state.nativeTimings = [
      'VPNTE_FW_TIMING:initial-stale-cleanup:240',
      'VPNTE_FW_TIMING:initial-create-allows:00025',
      'VPNTE_FW_TIMING:initial-set-block:0',
      'VPNTE_FW_TIMING:initial-exceptions:30', 'VPNTE_FW_TIMING:initial-exceptions:31',
      'VPNTE_FW_TIMING:restore-profiles:60001',
      'VPNTE_FW_TIMING:restore-remove-rules:-1',
      'VPNTE_FW_TIMING:private-server.example:42',
      'VPNTE_FW_TIMING:initial-stale-cleanup:999999',
      'VPNTE_FW_TIMING:restore-profiles:NaN'
    ].join('\n') + '\n'
    expect((await enableKillSwitch({ ...options, appExceptionPaths: [], tunAdapterReady: Promise.resolve(true) })).success).toBe(true)
    expect(vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'native phase timing')).toEqual([
      ['debug', 'firewall-killswitch', 'native phase timing', { phase: 'initial-stale-cleanup', durationMs: 240 }],
      ['debug', 'firewall-killswitch', 'native phase timing', { phase: 'initial-create-allows', durationMs: 25 }],
      ['debug', 'firewall-killswitch', 'native phase timing', { phase: 'initial-set-block', durationMs: 0 }]
    ])
    expect(vi.mocked(logEvent).mock.calls.flatMap(call => call.slice(2)).join(' ')).not.toContain('private-server.example')
    const backends = vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'command timing').map(call => (call[3] as any)?.ruleBackend)
    expect(new Set(backends)).toEqual(new Set(['netsecurity', 'com']))
  })
  it('refuses an unverified exception result even with well-formed native timings (AT-03-007)', async () => {
    state.nativeTimings = 'VPNTE_FW_TIMING:initial-exceptions:1\n'; state.liveMissingMarker = true
    expect((await enableKillSwitch({ ...options, appExceptionPaths: [], tunAdapterReady: Promise.resolve(true) })).success).toBe(false)
    expect(state.manifest).toBeNull()
    expect(state.scripts.some(script => script.includes("Write-Output 'RESTORED'"))).toBe(true)
  })
  it('uses the protected-file fallback for oversized initial and live exception policies (AT-03-007/008/009)', async () => {
    state.longApps = true
    const paths = Array.from({ length: 36 }, (_, i) => `C:\\${('a'.repeat(200) + '\\').repeat(8)}app-${i}.exe`)
    expect(paths.every(path => path.length <= 2048)).toBe(true)
    state.fallback.mockResolvedValue({ stdout: 'EXCEPTIONS_VERIFIED\nRULES:VPNTE-killswitch-allow-app', stderr: '' })
    expect((await enableKillSwitch({ ...options, appExceptionPaths: paths, tunAdapterReady: Promise.resolve(true) })).success).toBe(true)
    expect(state.artifacts).toHaveLength(1)
    expect(state.manifest.exceptionPolicy.apps).toEqual(paths)
    expect((await updateKillSwitchExceptions(paths, [])).success).toBe(true)
    expect(state.artifacts).toHaveLength(2)
    expect(state.fallback).toHaveBeenCalledTimes(2)
    expect(state.scripts.filter(script => script.length > 64 * 1024)).toHaveLength(2)
    expect(state.manifest.pendingExceptionPolicy).toBeUndefined()
  })
  it('waits for verified TUN before preparing IPv6 scopes or applying policy (AT-03-004)', async () => {
    let confirm!: (ready: boolean) => void
    const tunAdapterReady = new Promise<boolean>(resolve => { confirm = resolve })
    const pending = enableKillSwitch({ ...options, tunAdapterReady, extraAllowedRemoteCidrs: ['192.0.2.1'] })
    await vi.waitFor(() => expect(state.manifestReads).toBeGreaterThan(0))
    expect(state.manifest).toBeNull()
    expect(state.wfpCalls).toEqual([])
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
    expect(state.scripts).toEqual([])
    expect(state.wfpCalls).toEqual([])
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
    { code: 'elevated-helper-script-too-large', fallback: true },
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
    const output = executeNativeFixture(script)
    expect(output).toContain('EXCEPTIONS_VERIFIED')
    expect(output).toContain('RULES:VPNTE-killswitch-allow-singbox')
    const timings = [...output.matchAll(/^VPNTE_FW_TIMING:([a-z-]+):(\d+)\r?$/gm)]
    expect(timings.map(match => match[1])).toEqual(['initial-stale-cleanup', 'initial-create-allows', 'initial-set-block', 'initial-exceptions'])
    expect(timings.every(match => Number.isSafeInteger(Number(match[2])) && Number(match[2]) >= 0)).toBe(true)
    const raw = output.split(/\r?\n/).find(line => line.startsWith('RESULT:'))!.slice(7)
    const values = raw ? JSON.parse(raw) : []
    expect((Array.isArray(values) ? values : [values]).sort()).toEqual([...cidrs].sort())
  }, 20000)
  it.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH).each(['valid', 'set-error', 'readback-error', 'com-error'])(
    'preserves independent native restore/readbacks with timings: %s (AT-03-004/007)', async mode => {
      await enableKillSwitch(options)
      await disableKillSwitch('native fixture')
      const restore = state.scripts.find(script => script.includes("Write-Output 'RESTORED'"))!
      const output = executeNativeFixture(`
$script:profiles=@{Domain='Allow';Private='Allow';Public='Allow'};$script:attempts=New-Object 'Collections.Generic.List[string]'
$script:rules=@{own=[pscustomobject]@{DisplayName='VPNTE-killswitch-allow-app'};foreign=[pscustomobject]@{DisplayName='foreign-app'}}
function Set-NetFirewallProfile { param($Profile,$DefaultOutboundAction)
  $script:attempts.Add($Profile)
  if($Profile -eq 'Private' -and '${mode}' -eq 'set-error'){throw 'Fixture set failed'}
  $script:profiles[$Profile]=$DefaultOutboundAction
}
function Get-NetFirewallProfile { param($Profile)
  $value=$script:profiles[$Profile]
  if($Profile -eq 'Private' -and '${mode}' -eq 'readback-error'){$value='Allow'}
  [pscustomobject]@{DefaultOutboundAction=$value}
}
function Get-NetFirewallRule { param($DisplayName) @($script:rules.Values)|Where-Object{$_.DisplayName -like $DisplayName} }
function Remove-NetFirewallRule { param([Parameter(ValueFromPipeline=$true)]$Rule) process { if($Rule){$script:rules.Remove('own')} } }
${mode === 'com-error' ? "function New-Object { param($ComObject) throw 'Fixture COM unavailable' }" : ''}
$success=$false
try {${restore}
$success=$true
}catch{}
Write-Output ('RESULT:'+(@{success=$success;attempts=$script:attempts.ToArray();ownRemains=$script:rules.ContainsKey('own');foreignRemains=$script:rules.ContainsKey('foreign')}|ConvertTo-Json -Compress))
`, mode === 'com-error')
      const result = JSON.parse(output.split(/\r?\n/).find(line => line.startsWith('RESULT:'))!.slice(7))
      expect(result).toEqual({ success: mode === 'valid', attempts: ['Domain', 'Private', 'Public'], ownRemains: mode === 'com-error', foreignRemains: true })
      expect([...output.matchAll(/^VPNTE_FW_TIMING:([a-z-]+):(\d+)\r?$/gm)].map(match => match[1])).toEqual(['restore-profiles', 'restore-remove-rules'])
      expect(output.includes('RESTORED')).toBe(mode === 'valid')
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
  it('compensates firewall exceptions even if WFP update and compensation both fail (AT-03-007/008)', async () => {
    await active(); state.wfpFailApply = 2
    expect(await updateKillSwitchExceptions([], ['198.51.100.2'])).toMatchObject({ success: false, state: 'unknown' })
    expect(state.scripts).toHaveLength(1)
    expect(state.scripts[0]).toContain('EXCEPTIONS_VERIFIED')
    expect(state.manifest.pendingExceptionPolicy).toBeDefined()
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
${FIREWALL_RULES_BOUNDARY_FIXTURE_PS}
${state.scripts[0].replace(FIREWALL_RULES_API_PS, '')}
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
