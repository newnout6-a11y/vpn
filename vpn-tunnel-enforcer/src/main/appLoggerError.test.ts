// AT-01-002/010/011, F-001/F-004/F-132: real logger and redactors, synthetic secrets only.
import { mkdtempSync, readFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

let directory: string
vi.mock('electron', () => ({ app: { getPath: () => directory }, shell: { openPath: vi.fn() } }))
vi.mock('./settings', () => ({ settingsStore: { get: vi.fn() } }))
vi.mock('./sharedStores', () => ({ serverPickerStore: { get: vi.fn() }, serverGroupsStore: { get: vi.fn() } }))
import { startupFailureDetail } from './secureStartup'

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'vpnte-log-error-'))
  vi.resetModules()
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})
afterEach(() => {
  vi.restoreAllMocks()
  rmSync(directory, { recursive: true, force: true })
})

async function readLoggedDetail(path: string): Promise<unknown> {
  let detail: unknown
  await vi.waitFor(() => {
    detail = JSON.parse(readFileSync(path, 'utf8')).details
    expect(detail).toBeDefined()
  })
  return detail
}

const uri = 'trojan://FAKE-CREDENTIAL@credential.test:443'
const errorWithSecrets = () => {
  const error = new Error(`FAKE-MESSAGE ${uri}`)
  error.name = 'FAKE-ERROR-NAME'
  error.stack = `FAKE-STACK ${uri}\n at FAKE-STACK-FRAME`
  Object.assign(error, { code: 'FAKE-CODE' })
  return error
}

describe('appLogger Error details', () => {
  it.each(['secure-store-preflight', 'startup'] as const)('logs only bounded code/type for %s refusal, in file and console', async stage => {
    const { logEvent, getAppLogPath } = await import('./appLogger')
    const expected = { code: stage === 'startup' ? 'STARTUP_FAILED' : 'SECURE_STORE_PREFLIGHT_FAILED', type: 'Error' }
    logEvent('error', 'security', 'startup refused', startupFailureDetail(errorWithSecrets(), stage))
    const detail = await readLoggedDetail(getAppLogPath())
    expect(detail).toEqual(expected)
    expect(console.error).toHaveBeenCalledExactlyOnceWith('[security] startup refused', expected)
    for (const output of [readFileSync(getAppLogPath(), 'utf8'), JSON.stringify(vi.mocked(console.error).mock.calls)]) {
      expect(output).not.toContain('FAKE-')
      expect(output).not.toContain(uri)
      expect(output).not.toContain('credential.test')
      expect(output).not.toContain('stack')
      expect(output).not.toContain('message":"FAKE')
    }
  })

  it('still redacts credential URIs in ordinary Error details before file and console output', async () => {
    const { logEvent, getAppLogPath } = await import('./appLogger')
    logEvent('error', 'test', 'ordinary failure', new Error(`Failed ${uri}`))
    const detail = await readLoggedDetail(getAppLogPath())
    expect(JSON.stringify(detail)).toContain('<redacted-vpn-uri>')
    expect(JSON.stringify(detail)).not.toContain(uri)
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain('FAKE-CREDENTIAL')
  })

  it('applies the existing 4000-character bound to redacted Error fields in file and console', async () => {
    const { logEvent, getAppLogPath } = await import('./appLogger')
    const error = new Error(`Failed ${uri} ${'x'.repeat(8000)}`)
    error.stack = `Stack ${uri} ${'y'.repeat(8000)}`
    logEvent('error', 'test', 'bounded failure', error)
    const detail = await readLoggedDetail(getAppLogPath())
    expect(typeof detail).toBe('string')
    expect((detail as string).length).toBe(4000 + '...<truncated>'.length)
    expect(detail).toContain('<redacted-vpn-uri>')
    expect(detail).not.toContain('FAKE-CREDENTIAL')
    expect(console.error).toHaveBeenCalledExactlyOnceWith('[test] bounded failure', detail)
  })
})
