// AT-00-006, F-074: real backup/manifest files; native effects stay in the fixture.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { writeFileSync } from 'node:fs'

const state = vi.hoisted(() => ({ root: '', denied: '', values: {} as Record<string, string>, native: vi.fn(), elevated: vi.fn(), spawn: vi.fn() }))
vi.mock('fs/promises', async original => {
  const actual = await original<typeof import('fs/promises')>()
  return { ...actual, readFile: (...args: Parameters<typeof actual.readFile>) => {
    if (String(args[0]) === state.denied) throw Object.assign(new Error('fixture read denied'), { code: 'EACCES' })
    return actual.readFile(...args)
  } }
})
vi.mock('electron', () => ({ app: {
  getPath: (name: string) => join(state.root, name), getVersion: () => 'fixture', isPackaged: false
} }))
vi.mock('os', async original => ({ ...await original<typeof import('os')>(), homedir: () => join(state.root, 'home') }))
vi.mock('child_process', () => ({
  execFile: (file: string, args: string[], options: unknown, callback: (error: Error | null, result?: unknown) => void) => {
    state.native(file, args, options)
    const key = args[args.indexOf('/v') + 1]
    if (file === 'setx') state.values[args[0]] = args[1]
    if (file === 'reg' && args[0] === 'delete') delete state.values[key]
    if (file === 'reg' && args[0] === 'query' && !Object.hasOwn(state.values, key)) {
      callback(Object.assign(new Error('unable to find the specified registry key or value'), { code: 1 })); return
    }
    const stdout = file === 'git' && args.includes('--get') ? 'http://configured-proxy'
      : file === 'reg' && args[0] === 'query' ? `    ${key}    REG_SZ    ${state.values[key]}\r\n` : ''
    callback(null, { stdout, stderr: '' })
  }, spawn: state.spawn
}))
vi.mock('./admin', () => ({ execElevated: state.elevated }))
vi.mock('./autoconfig/androidStudio', () => ({ androidStudio: { name: 'fixture IDE', isApplied: async () => false } }))
vi.mock('./autoconfig/gradle', () => ({ gradle: { name: 'fixture Gradle', isApplied: async () => false } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ deepTrafficInspectionEnabled: true }) } }))
vi.mock('./runtimePaths', () => ({ getPrivilegedRuntimeDir: (name: string) => join(state.root, 'privileged', name) }))
vi.mock('./runtimeDirSecurity', () => ({
  ensureElevatedRuntimeDirHardened: vi.fn(async () => ({ hardened: true })),
  verifyDirectoryHardened: vi.fn(async () => ({ hardened: true }))
}))

const forensicRoot = () => join(state.root, 'privileged', 'traffic-forensics')
const files = {
  git: () => join(state.root, 'home', '.vpnte', 'git-proxy-backup.json'),
  env: () => join(state.root, 'home', '.vpnte', 'env-proxy-backup.json'),
  browser: () => join(state.root, 'userData', 'browser-hardening', 'latest-browser-hardening.json'),
  location: () => join(state.root, 'programData', 'VPN-Tunnel-Enforcer', 'privacy-backups', 'latest-location-backup.json'),
  forensics: () => join(forensicRoot(), 'latest-session.json')
}
type Kind = keyof typeof files
const kinds = Object.keys(files) as Kind[]
function legacy(kind: Kind) {
  if (kind === 'git') return { createdAt: 1, httpProxy: 'original-http', httpsProxy: null }
  if (kind === 'env') return { createdAt: 1, httpProxy: 'original-http', httpsProxy: null, allProxy: null, noProxy: '' }
  if (kind === 'browser') return { createdAt: 1, registryBackups: [], fileBackups: [] }
  if (kind === 'location') return { createdAt: 1, hkcuBackup: null, hkcuKeyExisted: false, hklmBackup: null, hklmKeyExisted: false }
  return { sessionId: 'fixture', sessionDir: join(forensicRoot(), 'sessions', 'fixture'), running: false, enabled: true }
}
async function save(kind: Kind, value: unknown) {
  const file = files[kind]()
  await mkdir(dirname(file), { recursive: true })
  await writeFile(file, JSON.stringify(value))
  return createHash('sha256').update(await readFile(file)).digest('hex')
}
const hash = async (kind: Kind) => createHash('sha256').update(await readFile(files[kind]())).digest('hex')
async function invoke(kind: Kind, action: 'apply' | 'rollback' | 'status') {
  if (kind === 'git' || kind === 'env') {
    const { autoconfig } = await import('./autoconfig')
    if (action === 'status') return autoconfig.getStatus()
    return action === 'apply' ? autoconfig.apply([kind], '127.0.0.1:10808') : autoconfig.rollback([kind])
  }
  if (kind === 'browser') {
    const module = await import('./browserHardening')
    return action === 'apply' ? module.applyBrowserLeakProtection() : module.rollbackBrowserLeakProtection()
  }
  if (kind === 'location') {
    const module = await import('./locationPrivacy')
    return action === 'apply' ? module.applyLocationPrivacy() : module.rollbackLocationPrivacy()
  }
  const module = await import('./trafficForensics')
  return action === 'apply' ? module.startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    : action === 'rollback' ? module.stopTrafficForensicsSession('fixture') : module.getTrafficForensicsStatus()
}
beforeEach(async () => {
  vi.resetModules(); vi.clearAllMocks(); state.values = {}; state.denied = ''
  await mkdir(resolve('.tmp'), { recursive: true })
  state.root = await mkdtemp(resolve('.tmp/document-schema-'))
  vi.stubEnv('LOCALAPPDATA', join(state.root, 'local'))
  vi.stubEnv('APPDATA', join(state.root, 'roaming'))
  vi.stubEnv('VPNTE_TRAFFIC_FORENSICS_SIDECAR', '0')
  for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY']) vi.stubEnv(key, 'fixture-original')
  await mkdir(join(state.root, 'local', 'Google', 'Chrome', 'User Data'), { recursive: true })
  state.elevated.mockResolvedValue({ stdout: 'VPNTE_CAPTURE_STOPPED:pktmon', stderr: '' })
})
afterEach(async () => {
  vi.unstubAllEnvs()
  expect(dirname(state.root)).toBe(resolve('.tmp'))
  await rm(state.root, { recursive: true, force: true })
})

describe('JSON document admission', () => {
  it('keeps the forensic reader and document inventory on the released schema', async () => {
    const { DOCUMENT_SCHEMA_VERSIONS } = await import('./storeSchema')
    const { MANIFEST_SCHEMA_VERSION } = await import('./trafficForensicsSummary')
    expect(DOCUMENT_SCHEMA_VERSIONS['traffic-forensics']).toBe(MANIFEST_SCHEMA_VERSION)
  })
  it.each(kinds.flatMap(kind => (['apply', 'rollback'] as const).map(action => ({ kind, action }))))(
    'refuses future $kind on $action before native effects and preserves bytes', async ({ kind, action }) => {
      const before = await save(kind, { ...legacy(kind), schemaVersion: kind === 'forensics' ? 3 : 1 })
      await expect(invoke(kind, action)).rejects.toMatchObject({ code: 'STORE_SCHEMA_FUTURE', category: 'conflict' })
      expect(await hash(kind)).toBe(before)
      expect(state.native).not.toHaveBeenCalled(); expect(state.elevated).not.toHaveBeenCalled(); expect(state.spawn).not.toHaveBeenCalled()
      if (kind === 'env') expect(await readdir(dirname(files.env()))).toEqual(['env-proxy-backup.json'])
      expect(process.env.HTTP_PROXY).toBe('fixture-original')
    }
  )
  it.each(kinds.flatMap(kind => ['3', null, -1, 0.5, Number.MAX_SAFE_INTEGER + 1].map(version => ({ kind, version }))))(
    'rejects malformed $kind schema version $version without touching its file', async ({ kind, version }) => {
      const before = await save(kind, { ...legacy(kind), schemaVersion: version })
      await expect(invoke(kind, kind === 'forensics' ? 'status' : 'rollback')).rejects.toMatchObject({ code: 'STORE_SCHEMA_INVALID', category: 'validation' })
      expect(await hash(kind)).toBe(before)
      expect(state.native).not.toHaveBeenCalled(); expect(state.elevated).not.toHaveBeenCalled()
    }
  )
  it.each(['git', 'env', 'forensics'] as const)('refuses future %s during status inspection', async kind => {
    const before = await save(kind, { ...legacy(kind), schemaVersion: kind === 'forensics' ? 3 : 1 })
    await expect(invoke(kind, 'status')).rejects.toMatchObject({ code: 'STORE_SCHEMA_FUTURE' })
    expect(await hash(kind)).toBe(before)
  })
  it.each(['corrupt', 'unreadable'])('reads actual Git status with a %s backup and refuses unsafe apply', async damage => {
    await mkdir(dirname(files.git()), { recursive: true })
    await writeFile(files.git(), '{')
    if (damage === 'unreadable') state.denied = files.git()
    const { autoconfig } = await import('./autoconfig')
    expect((await autoconfig.getStatus()).find(target => target.id === 'git')?.applied).toBe(true)
    vi.clearAllMocks()
    expect(await autoconfig.apply(['git'], '127.0.0.1:10808')).toEqual({ git: false })
    state.denied = ''
    expect(await readFile(files.git(), 'utf8')).toBe('{')
    expect(state.native).not.toHaveBeenCalled()
  })
  it.each(['git', 'env', 'browser', 'location'] as const)('rechecks %s before writing a prepared backup', async kind => {
    await mkdir(dirname(files[kind]()), { recursive: true })
    const future = JSON.stringify({ ...legacy(kind), schemaVersion: 1 })
    state.native.mockImplementationOnce(() => { writeFileSync(files[kind](), future) })
    await expect(invoke(kind, 'apply')).rejects.toMatchObject({ code: 'STORE_SCHEMA_FUTURE' })
    expect(await readFile(files[kind](), 'utf8')).toBe(future)
    expect(state.native.mock.calls.some(([file, args]) => file === 'setx' || args[0] === 'add' || (file === 'git' && !args.includes('--get')))).toBe(false)
    expect(state.elevated).not.toHaveBeenCalled()
  })
  it.each(['git', 'env', 'browser', 'location'] as const)('writes an explicit released schema for a new %s backup', async kind => {
    await invoke(kind, 'apply')
    expect(JSON.parse(await readFile(files[kind](), 'utf8')).schemaVersion).toBe(0)
  })
  it.each((['git', 'env', 'browser', 'location'] as const).flatMap(kind => [undefined, 0].map(version => ({ kind, version }))))(
    'restores historical $kind version $version with the existing rollback policy', async ({ kind, version }) => {
      await save(kind, { ...legacy(kind), ...(version === undefined ? {} : { schemaVersion: version }) })
      const result = await invoke(kind, 'rollback')
      if (kind === 'git' || kind === 'env') expect(result).toEqual({ [kind]: true })
      if (kind === 'browser') expect(result).toMatchObject({ success: true })
      await expect(readFile(files[kind]())).rejects.toMatchObject({ code: 'ENOENT' })
      if (kind === 'git') expect(state.native).toHaveBeenCalledWith('git', ['config', '--global', 'http.proxy', 'original-http'], expect.anything())
      if (kind === 'env') expect(process.env.HTTP_PROXY).toBe('original-http')
    }
  )
  it.each([undefined, 0, 1, 2])('reads historical forensics version %s without an implicit rewrite', async version => {
    const before = await save('forensics', { ...legacy('forensics'), ...(version === undefined ? {} : { schemaVersion: version }) })
    expect(await invoke('forensics', 'status')).toMatchObject({ sessionId: 'fixture', schemaVersion: version ?? 2 })
    expect(await hash('forensics')).toBe(before)
    expect(state.elevated).not.toHaveBeenCalled()
  })
  it.each((['latest', 'session'] as const).flatMap(target => ['future', 'invalid', 'unreadable'].map(damage => ({ target, damage }))))('stops owned capture with a $damage $target manifest without replacing it', async ({ target, damage }) => {
    const module = await import('./trafficForensics')
    const started = await module.startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    expect(started.sessionDir).toBeTruthy()
    const path = target === 'latest' ? files.forensics() : join(started.sessionDir!, 'session-manifest.json')
    const future = JSON.stringify({ ...JSON.parse(await readFile(path, 'utf8')), schemaVersion: damage === 'invalid' ? 'newer' : damage === 'future' ? 3 : 2 })
    await writeFile(path, future)
    const snapshots = await Promise.all([files.forensics(), join(started.sessionDir!, 'session-manifest.json')].map(file => readFile(file, 'utf8')))
    if (damage === 'unreadable') state.denied = path
    vi.clearAllMocks()
    const stopped = await module.stopTrafficForensicsSession('future-refusal')
    expect(stopped).toMatchObject({ running: false, lastError: expect.stringContaining('CaptureStoppedArtifactsUnavailable:') })
    expect(state.elevated).toHaveBeenCalledOnce()
    expect(state.elevated.mock.calls[0][0]).toContain('-EncodedCommand')
    const stopScript = Buffer.from(state.elevated.mock.calls[0][0].split('-EncodedCommand ')[1], 'base64').toString('utf16le')
    expect(stopScript).toMatch(/'pktmon\.exe'\)\) stop/)
    expect(stopScript).not.toContain(started.sessionDir!)
    await expect(module.recordTrafficForensicsAppEvent({ source: 'fixture', event: 'refused' })).rejects.toMatchObject({ code: damage === 'unreadable' ? 'EACCES' : damage === 'future' ? 'STORE_SCHEMA_FUTURE' : 'STORE_SCHEMA_INVALID' })
    state.denied = ''
    expect(await Promise.all([files.forensics(), join(started.sessionDir!, 'session-manifest.json')].map(file => readFile(file, 'utf8')))).toEqual(snapshots)
    expect(state.spawn).not.toHaveBeenCalled()
  })
  it('cleans up an owned capture before refusing restart against a newer document', async () => {
    const module = await import('./trafficForensics')
    await module.startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    const future = JSON.stringify({ ...JSON.parse(await readFile(files.forensics(), 'utf8')), schemaVersion: 3 })
    await writeFile(files.forensics(), future); vi.clearAllMocks()
    await expect(module.restartTrafficForensicsSession()).rejects.toMatchObject({ code: 'STORE_SCHEMA_FUTURE' })
    expect(state.elevated).toHaveBeenCalledOnce()
    expect(await readFile(files.forensics(), 'utf8')).toBe(future)
    expect(state.spawn).not.toHaveBeenCalled()
  })
  it('does not grant stop authority to an unreadable foreign manifest', async () => {
    await save('forensics', { ...legacy('forensics'), running: true, engine: 'pktmon' })
    state.denied = files.forensics()
    const module = await import('./trafficForensics')
    await expect(module.stopTrafficForensicsSession('foreign-refused')).rejects.toMatchObject({ code: 'EACCES' })
    expect(state.elevated).not.toHaveBeenCalled(); expect(state.spawn).not.toHaveBeenCalled()
  })
})
