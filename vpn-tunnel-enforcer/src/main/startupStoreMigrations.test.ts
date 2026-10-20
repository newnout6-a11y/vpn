// AT-00-006/005, F-074/F-143: ordered production startup registry, actual
// profile transformations and Conf files; network/OS boundaries are controlled.
import { beforeEach, afterEach, expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const state = vi.hoisted(() => ({ dir: '', rows: [] as Array<{ message: string; details: any; correlationId?: string; metadata: unknown }> }))
vi.mock('electron', () => ({ app: { isPackaged: false, getPath: () => state.dir, getAppPath: () => state.dir }, dialog: {}, ipcMain: { handle: vi.fn() } }))
vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) { super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' }) }
  } }
})
vi.mock('./appLogger', async () => {
  const { currentCorrelationId, currentActionMetadata } = await import('./actionCorrelation')
  return { logEvent: (_level: string, _source: string, message: string, details: unknown) => {
  state.rows.push({ message, details, correlationId: currentCorrelationId(), metadata: currentActionMetadata() })
  } }
})
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) }, getDirectProxyPort: () => null }))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./domainEnrichment', () => ({ domainEnrichmentService: { setEnabled: vi.fn() } }))
vi.mock('./recoveryManifest', () => ({ readBootRecoveryReport: vi.fn() }))

const methods = ['migrateLegacyDirectVpnProfiles', 'backfillMissingOutbounds', 'migrateProfilesIntoGroups',
  'consolidateBogusSniGroups', 'backfillProfileSourceUris', 'backfillProfileCountriesFromNames', 'clearStaleStoredPings'] as const
beforeEach(() => {
  vi.resetModules(); state.rows = []
  mkdirSync('.tmp', { recursive: true })
  state.dir = mkdtempSync(join(process.cwd(), '.tmp', 'startup-migrations-'))
})
afterEach(() => rmSync(state.dir, { recursive: true, force: true }))

it('runs every registered startup step in order and records a single private-safe action', async () => {
  const { runStartupStoreMigrations } = await import('./storeMigrations')
  const calls: string[] = []
  const target = Object.fromEntries(methods.map(method => [method, () => { calls.push(method) }])) as Record<typeof methods[number], () => void>
  runStartupStoreMigrations(target)
  expect(calls).toEqual(methods)
  const rows = state.rows.filter(row => row.message.startsWith('startup store step'))
  expect(rows.map(row => row.details.status)).toEqual(methods.flatMap(() => ['started', 'success']))
  expect(new Set(rows.map(row => row.correlationId)).size).toBe(1)
  expect(rows[0].correlationId).toMatch(/^op_[a-f0-9]{32}$/)
  expect(rows.every(row => JSON.stringify(row.metadata) === JSON.stringify({ source: 'lifecycle', owner: 'recovery' }))).toBe(true)
  expect(rows.every(row => row.details.applied === undefined)).toBe(true) // completed check need not mutate a store
})

it('stops at a failed step, records its category and leaves later steps untouched', async () => {
  const { runStartupStoreMigrations } = await import('./storeMigrations')
  const calls: string[] = []
  const failure = Object.assign(new Error('SECRET at C:\\private\\profiles.json'), { code: 'EACCES' })
  const target = Object.fromEntries(methods.map((method, index) => [method, () => { calls.push(method); if (index === 2) throw failure }])) as Record<typeof methods[number], () => void>
  expect(() => runStartupStoreMigrations(target)).toThrow(failure)
  expect(calls).toEqual(methods.slice(0, 3))
  expect(state.rows.at(-1)?.details).toMatchObject({ status: 'error', category: 'permission' })
  expect(JSON.stringify(state.rows)).not.toMatch(/SECRET|C:\\private|at /)
})

it.each(['validation', 'permission', 'network', 'conflict', 'internal', 'timeout', 'cancelled'] as const)(
  'preserves %s failures, method receivers and closes the action scope', async category => {
    const { runStartupStoreMigrations } = await import('./storeMigrations')
    const { IpcFault } = await import('../shared/ipc-result')
    const { currentCorrelationId, currentActionMetadata } = await import('./actionCorrelation')
    const failure = new IpcFault(category)
    const calls: string[] = []
    const failedIndex = ['validation', 'permission', 'network', 'conflict', 'internal', 'timeout', 'cancelled'].indexOf(category)
    const target = Object.fromEntries(methods.map((method, index) => [method, function (this: unknown) {
      expect(this).toBe(target)
      calls.push(method)
      if (index === failedIndex) throw failure
    }])) as Record<typeof methods[number], () => void>
    expect(() => runStartupStoreMigrations(target)).toThrow(failure)
    expect(calls).toEqual(methods.slice(0, failedIndex + 1))
    expect(state.rows.at(-1)?.details).toMatchObject({ migrationStep: methods[failedIndex], status: 'error', category })
    expect(currentCorrelationId()).toBeUndefined()
    expect(currentActionMetadata()).toBeUndefined()
  }
)

it('runs real legacy profile and group repairs on disk and is idempotent across restart', async () => {
  const legacy = { name: 'Germany fixture', protocol: 'vless', outbound: { type: 'vless', server: 'vpn.example.test', server_port: 443, uuid: 'PRIVATE-FIXTURE-KEY' } }
  writeFileSync(join(state.dir, 'settings.json'), JSON.stringify({ settings: {
    directVpnInput: 'accepted-key', directVpnCachedInput: 'accepted-key', directVpnCachedProfiles: [legacy], directVpnSelectedIndex: 0
  } }))
  const { runStartupStoreMigrations } = await import('./storeMigrations')
  const { serverPicker } = await import('./serverPicker')
  const { serverGroups } = await import('./serverGroups')
  runStartupStoreMigrations(serverPicker)
  const profiles = serverPicker.getProfiles()
  expect(profiles).toHaveLength(1)
  expect(profiles[0]).toMatchObject({ name: legacy.name, server: 'vpn.example.test', outbound: legacy.outbound, status: 'unknown', ping: null })
  expect(serverGroups.getGroups().some(group => group.id === profiles[0].groupId)).toBe(true)
  const names = ['settings', 'server-picker', 'server-groups']
  const before = names.map(name => readFileSync(join(state.dir, `${name}.json`), 'utf8'))
  expect(before.join('')).not.toContain('PRIVATE-FIXTURE-KEY')
  vi.resetModules()
  const restarted = await import('./serverPicker')
  const runner = await import('./storeMigrations')
  runner.runStartupStoreMigrations(restarted.serverPicker)
  expect(restarted.serverPicker.getProfiles()).toEqual(profiles)
  expect(names.map(name => readFileSync(join(state.dir, `${name}.json`), 'utf8'))).toEqual(before)
  expect(JSON.stringify(state.rows)).not.toContain('PRIVATE-FIXTURE-KEY')
})
