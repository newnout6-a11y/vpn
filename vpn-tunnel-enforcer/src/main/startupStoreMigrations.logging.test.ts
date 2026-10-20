// AT-00-005/006, F-074/F-143: actual startup runner, logger, JSONL and
// diagnostic redactor. Only Electron paths are replaced with an owned fixture.
import { expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'

const state = vi.hoisted(() => ({ dir: '' }))
vi.mock('electron', () => ({ app: { isPackaged: true, getPath: () => state.dir }, shell: {} }))

it('keeps two startup actions distinct through persisted and diagnostic log redaction', async () => {
  mkdirSync('.tmp', { recursive: true })
  state.dir = mkdtempSync(join(process.cwd(), '.tmp', 'startup-migration-logs-'))
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
  const { logEvent, flushAppLog, getAppLogPath, getFullLogs } = await import('./appLogger')
  try {
    const { runStartupStoreMigrations, STARTUP_STORE_MIGRATIONS } = await import('./storeMigrations')
    const { currentCorrelationId } = await import('./actionCorrelation')
    const ids: string[] = []
    const failure = Object.assign(new Error('PRIVATE-FAILURE at C:\\private\\profiles.json'), { code: 'EACCES' })
    for (const fail of [false, true]) {
      const target = Object.fromEntries(STARTUP_STORE_MIGRATIONS.map((method, index) => [method, () => {
        if (index === 0) {
          ids.push(currentCorrelationId()!)
          logEvent('info', 'fixture', 'secret masking check', {
            password: 'PRIVATE-STARTUP-PASSWORD', credential: '8093a2ec-f028-4e3c-96a7-b301efaf23dd'
          })
        }
        if (fail && index === 2) throw failure
      }])) as Record<typeof STARTUP_STORE_MIGRATIONS[number], () => void>
      if (fail) expect(() => runStartupStoreMigrations(target)).toThrow(failure)
      else runStartupStoreMigrations(target)
    }
    await flushAppLog()
    const raw = readFileSync(getAppLogPath(), 'utf8')
    const allRows = raw.trim().split('\n').map(line => JSON.parse(line))
    const rows = allRows.filter(row => row.message.startsWith('startup store step'))
    expect(new Set(ids).size).toBe(2)
    expect(ids.every(id => /^op_[a-f0-9]{32}$/.test(id))).toBe(true)
    expect(new Set(rows.map(row => row.correlationId))).toEqual(new Set(ids))
    expect(allRows.every(row => row.source === 'lifecycle' && row.owner === 'recovery')).toBe(true)
    expect(allRows.every(row => Number.isFinite(row.monotonicMs))).toBe(true)
    expect(allRows.map(row => row.monotonicMs)).toEqual(allRows.map(row => row.monotonicMs).sort((a, b) => a - b))
    expect(rows.filter(row => row.correlationId === ids[0]).map(row => [row.details.migrationStep, row.details.status])).toEqual(
      STARTUP_STORE_MIGRATIONS.flatMap(method => [[method, 'started'], [method, 'success']])
    )
    expect(rows.filter(row => row.correlationId === ids[1]).map(row => row.details.status)).toEqual(
      ['started', 'success', 'started', 'success', 'started', 'error']
    )
    expect(rows.at(-1).details).toMatchObject({ migrationStep: STARTUP_STORE_MIGRATIONS[2], category: 'permission' })
    expect(raw).not.toMatch(/PRIVATE-|8093a2ec|C:\\private|profiles\.json/)
    const diagnostic = (await getFullLogs()).find(file => file.path === getAppLogPath())!
    expect(diagnostic.exists).toBe(true)
    expect(diagnostic.content.trim().split('\n').map(line => JSON.parse(line))).toEqual(allRows)
    expect(diagnostic.content).not.toMatch(/PRIVATE-|8093a2ec|C:\\private|profiles\.json/)
  } finally {
    await flushAppLog()
    vi.restoreAllMocks()
    rmSync(state.dir, { recursive: true, force: true })
  }
})
