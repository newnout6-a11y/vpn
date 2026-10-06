// WP-0: preserves collection of AT-* checks across environments and modes;
// AT-03-012 native and AT-11-002 integration oracles must remain runnable.
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'

const script = join(process.cwd(), 'scripts/check-vitest-config.mjs')
type CollectedFile = {
  path: string
  environment: string
  isolate: boolean
  globals: boolean
  maxWorkers: number
}
type ModeReport = { maxWorkers: number; files: CollectedFile[]; expected: string[] }
let report: { normal: ModeReport; integration: ModeReport }

beforeAll(() => {
  const result = spawnSync(process.execPath, [script], { encoding: 'utf8', windowsHide: true, timeout: 15000 })
  expect(result.error).toBeUndefined()
  expect(result.status, result.stderr).toBe(0)
  report = JSON.parse(result.stdout)
}, 20000)

describe('test execution preserves acceptance coverage', () => {
  it('collects every unit/native and integration file once with its required environment', () => {
    expect(report.normal.files.length).toBeGreaterThan(0)
    expect(report.integration.files.length).toBeGreaterThan(0)
  })

  it.each([
    { kind: 'missing', error: 'missing or unexpected test files' },
    { kind: 'duplicate', error: 'duplicate test files' },
    { kind: 'native-environment', error: 'wrong environment:' },
    { kind: 'integration-environment', error: 'wrong environment:' },
    { kind: 'isolation', error: 'isolation disabled:' },
    { kind: 'worker-limit', error: 'worker limit overridden:' }
  ])('rejects configuration regression: $kind', ({ kind, error }) => {
    const changed = structuredClone(report)
    if (kind === 'missing') changed.normal.files.pop()
    if (kind === 'duplicate') changed.normal.files.push(changed.normal.files[0])
    if (kind === 'native-environment') changed.normal.files.find(file => file.path === 'src/main/recoveryManifestStorage.test.ts')!.environment = 'node'
    if (kind === 'integration-environment') changed.integration.files[0].environment = 'jsdom'
    if (kind === 'isolation') changed.normal.files[0].isolate = false
    if (kind === 'worker-limit') changed.normal.files[0].maxWorkers = 15
    const result = spawnSync(process.execPath, [script, '--validate'], { input: JSON.stringify(changed), encoding: 'utf8', windowsHide: true, timeout: 5000 })
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(1)
    expect(result.stderr).toContain(error)
  })
})
