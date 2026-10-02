// @vitest-environment node
// AT-00-003 / AT-02-004: real ChildProcess signal/exit on Windows, Node fixture only.
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { runXrayConfigPreflight, stopXrayPreflights } from './xrayPreflight'
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

let runtime: string
const tempRoot = resolve(process.cwd(), '.tmp')
beforeEach(async () => {
  await mkdir(tempRoot, { recursive: true })
  runtime = await mkdtemp(join(tempRoot, 'xray-preflight-native-'))
  // Node treats "run" as the script; -test/-c are script args. No VPN binary starts.
  await writeFile(join(runtime, 'run'), "require('node:fs').writeFileSync(process.argv[4], String(process.pid)); setInterval(()=>{}, 1000);\n")
})
afterEach(async () => {
  await stopXrayPreflights()
  if (dirname(runtime) !== tempRoot || !basename(runtime).startsWith('xray-preflight-native-')) throw new Error('Unexpected fixture cleanup target')
  await rm(runtime, { recursive: true, force: true })
})
async function ready(marker: string) {
  const deadline = performance.now() + 4000
  while (performance.now() < deadline) {
    const pid = await readFile(marker, 'utf8').then(Number).catch(() => null)
    if (pid && Number.isInteger(pid) && pid > 0) return pid
    await new Promise(done => setTimeout(done, 10))
  }
  throw new Error('Native fixture did not become ready')
}
function expectExited(pid: number) {
  expect(() => process.kill(pid, 0)).toThrow()
}

describe('native Windows preflight child (no network effects)', () => {
  it('cancels a real running child and confirms its PID exited within one second', async () => {
    const marker = join(runtime, 'ready.pid')
    const owner = new AbortController()
    const pending = runXrayConfigPreflight(process.execPath, runtime, marker, owner.signal)
    const cancelled = expect(pending).rejects.toThrow('cancelled')
    const pid = await ready(marker)
    const started = performance.now()
    owner.abort()
    await cancelled
    expect(performance.now() - started).toBeLessThan(1000)
    expectExited(pid)
  }, 10000)
  it('kills a real hung validation at the five-second deadline and confirms exit', async () => {
    const marker = join(runtime, 'ready.pid')
    const started = performance.now()
    const pending = runXrayConfigPreflight(process.execPath, runtime, marker)
    const timedOut = expect(pending).rejects.toThrow('timed out after 5000 ms')
    const pid = await ready(marker)
    await timedOut
    expect(performance.now() - started).toBeGreaterThanOrEqual(4900)
    expect(performance.now() - started).toBeLessThan(6500)
    expectExited(pid)
  }, 10000)
})
