// AT-00-005, F-143: actual diagnostic producer and JSONL logger, with native readers replaced by fixtures.
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import type { SystemDiagnosticItem, SystemDiagnosticResult } from '../shared/diagnostics'

const state = vi.hoisted(() => ({ directory: '' }))
vi.mock('electron', () => ({ app: { getPath: () => state.directory }, shell: { openPath: vi.fn() } }))
vi.mock('./runtimePaths', () => ({ getPrivilegedRuntimeDir: () => join(state.directory, 'unused-runtime') }))
let logger: typeof import('./appLogger')

beforeEach(async () => {
  await mkdir('.tmp', { recursive: true })
  state.directory = await mkdtemp(join(process.cwd(), '.tmp', 'diagnostic-logging-'))
  vi.resetModules()
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
  logger = await import('./appLogger')
})
afterEach(async () => {
  await logger.flushAppLog()
  vi.restoreAllMocks()
  await rm(state.directory, { recursive: true, force: true })
})

async function harness(readItems: () => Promise<SystemDiagnosticItem[]>) {
  // Execute the production functions unchanged; only OS/network readers are injected.
  const source = ts.createSourceFile('systemDiagnostics.ts', readFileSync('src/main/systemDiagnostics.ts', 'utf8'), ts.ScriptTarget.Latest, true)
  const names = ['runSystemDiagnostics', 'combineStatus', 'item', 'getLogSummary', 'isBenignAppLogWarning', 'isBenignSingBoxLogNoise']
  const functions = source.statements.filter(node => ts.isFunctionDeclaration(node) && names.includes(node.name?.text ?? ''))
  expect(functions).toHaveLength(names.length)
  const js = ts.transpileModule(functions.map(node => node.getText(source).replace(/^export /, '')).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const { redactSensitiveText } = await import('./vpnProfiles')
  const dependencies = {
    logEvent: logger.logEvent, readFile, stat, redactSensitiveText,
    getRuntimeItems: readItems,
    ...Object.fromEntries(['getBinaryItems', 'getProxyItems', 'getWindowsNetworkItems', 'getProcessAndListenerItems', 'getEndpointItems', 'getServiceItems', 'getEventLogItem', 'getLogItems', 'getTrafficForensicsItems', 'getSmartRouteRuleSetItems', 'buildActiveProfileDiagnosticItems', 'getRoutingItems'].map(name => [name, async () => []])),
    getBootRecoveryRegistrationStatus: () => ({ status: 'verified', message: 'fixture verified' }),
    readBootRecoveryReport: async () => ({ status: 'restored', messages: [] })
  }
  return new Function(...Object.keys(dependencies), js + '\nreturn { runSystemDiagnostics, getLogSummary };')(...Object.values(dependencies)) as {
    runSystemDiagnostics: (assertActive?: () => void) => Promise<SystemDiagnosticResult>
    getLogSummary: (path: string, options: { structuredApp: boolean }) => Promise<{ errors: string[] }>
  }
}
const check = (id: string, status: SystemDiagnosticItem['status'], value: string, details?: string): SystemDiagnosticItem =>
  ({ id, category: 'Network', label: `Check ${id}`, status, value, details })
async function logged() {
  await logger.flushAppLog()
  return (await readFile(logger.getAppLogPath(), 'utf8')).trim().split('\n').map(line => JSON.parse(line))
}

it('persists every late warn/fail with its cause and correlation despite IPC summary truncation', async () => {
  const input = [...Array.from({ length: 35 }, (_, i) => check(`info-${i}`, 'info', 'x'.repeat(200))),
    check('dns-resolve', 'warn', 'DNS reply unavailable', 'resolver timed out token=PRIVATE-TOKEN'),
    check('endpoint', 'fail', 'TLS handshake failed', 'certificate rejected vless://8093a2ec-f028-4e3c-96a7-b301efaf23dd@example.test:443')]
  const { runSystemDiagnostics } = await harness(async () => input)
  const { withCorrelation } = await import('./actionCorrelation')
  const { compactForIpcLog } = await import('./ipcLogging')
  const correlationId = 'ipc_3d49f22af56f4eb795812df333b9aa55'
  const result = await withCorrelation(correlationId, () => runSystemDiagnostics(), { source: 'ipc', owner: 'manual' })
  expect(result.items.slice(0, input.length)).toEqual(input)
  expect(compactForIpcLog(result)).not.toContain('TLS handshake failed')
  const rows = await logged(), findings = rows.filter(row => row.message === 'system diagnostic finding')
  expect(findings.map(row => row.details)).toEqual([
    expect.objectContaining({ check: 'dns-resolve', status: 'warn', value: 'DNS reply unavailable', details: expect.stringContaining('resolver timed out') }),
    expect.objectContaining({ check: 'endpoint', status: 'fail', value: 'TLS handshake failed', details: expect.stringContaining('certificate rejected') })
  ])
  expect(rows.every(row => row.correlationId === correlationId && row.owner === 'manual')).toBe(true)
  expect(JSON.stringify(rows)).not.toMatch(/PRIVATE-TOKEN|8093a2ec|example\.test/)
})

it('keeps a long finding bounded without making subsequent health checks report their own findings', async () => {
  const { runSystemDiagnostics, getLogSummary } = await harness(async () => [check('large', 'warn', 'read timeout', 'token=PRIVATE-TOKEN ' + 'x'.repeat(9000))])
  await runSystemDiagnostics()
  const rows = await logged(), finding = rows.find(row => row.message === 'system diagnostic finding')
  expect(JSON.stringify(finding)).toContain('read timeout')
  expect(JSON.stringify(finding.details).length).toBeLessThan(4500)
  expect(JSON.stringify(finding)).not.toContain('PRIVATE-TOKEN')
  expect((await getLogSummary(logger.getAppLogPath(), { structuredApp: true })).errors).toEqual([])
  logger.logEvent('warn', 'transport', 'independent native fault')
  await logger.flushAppLog()
  expect((await getLogSummary(logger.getAppLogPath(), { structuredApp: true })).errors).toEqual([expect.stringContaining('independent native fault')])
})

it('does not duplicate healthy items as findings', async () => {
  const { runSystemDiagnostics } = await harness(async () => [check('healthy', 'ok', 'reachable')])
  expect((await runSystemDiagnostics()).summary).toBe('ok')
  expect((await logged()).filter(row => row.message === 'system diagnostic finding')).toHaveLength(0)
})

it('does not log late findings or completion after cancellation', async () => {
  let release!: (items: SystemDiagnosticItem[]) => void, cancelled = false
  const { runSystemDiagnostics } = await harness(() => new Promise(resolve => { release = resolve }))
  const task = runSystemDiagnostics(() => { if (cancelled) throw new Error('cancelled') })
  cancelled = true
  release([check('late', 'fail', 'late failure')])
  await expect(task).rejects.toThrow('cancelled')
  expect((await logged()).map(row => row.message)).toEqual(['full system diagnostics started'])
})
