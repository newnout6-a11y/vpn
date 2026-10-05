// AT-02-005/009: execute the production teardown boundary without native mutation.
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

const source = readFileSync('src/main/tunController.ts', 'utf8')
const start = source.indexOf('    stopProxyWatchdog()', source.indexOf('  async stop(options:'))
const end = source.indexOf('\n    currentStatus = {', start)
if (start < 0 || end < 0) throw new Error('Missing production teardown boundary')
const body = ts.transpileModule(source.slice(start, end), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText

function harness(running = true) {
  const calls: string[] = []
  const dependencies = {
    currentStatus: { running },
    timedStop: async (_phase: string, run: () => Promise<unknown>) => run(),
    stopProxyWatchdog: () => {},
    stopXray: vi.fn(async () => { calls.push('xray') }),
    isOwnedTunRuntimeRunning: vi.fn(async () => false),
    killOwnedRuntimeProcesses: vi.fn(async () => { calls.push('sing-box') }),
    waitForOwnedRuntimeToExit: vi.fn(async () => { calls.push('exit-proof'); return true }),
    rememberCleanupError: vi.fn(), cleanupErrors: [] as string[], logEvent: vi.fn()
  }
  const run = new Function(...Object.keys(dependencies), `return async () => {${body}}`)(...Object.values(dependencies)) as () => Promise<void>
  return { ...dependencies, calls, run }
}

describe('upstream teardown order', () => {
  it('keeps Xray alive until sing-box exit proof settles', async () => {
    const h = harness()
    let release!: (value: boolean) => void
    h.waitForOwnedRuntimeToExit.mockImplementation(() => new Promise(resolve => { release = resolve }))
    const pending = h.run()
    await vi.waitFor(() => expect(h.waitForOwnedRuntimeToExit).toHaveBeenCalledOnce())
    expect(h.stopXray).not.toHaveBeenCalled()
    release(true); await pending
    expect(h.calls).toEqual(['sing-box', 'xray'])
  })
  it('stops the consumer before its upstream', async () => {
    const h = harness(); await h.run()
    expect(h.calls).toEqual(['sing-box', 'exit-proof', 'xray'])
  })
  it('still cleans up Xray if native termination fails and records the failure', async () => {
    const h = harness()
    h.killOwnedRuntimeProcesses.mockRejectedValueOnce(new Error('native denied'))
    await h.run()
    expect(h.rememberCleanupError).toHaveBeenCalledWith('runtime process stop', expect.any(Error))
    expect(h.stopXray).toHaveBeenCalledOnce()
  })
  it('requires a fresh absence proof before skipping a never-started consumer', async () => {
    const h = harness(false); await h.run()
    expect(h.isOwnedTunRuntimeRunning).toHaveBeenCalledWith(true)
    expect(h.killOwnedRuntimeProcesses).not.toHaveBeenCalled()
    expect(h.stopXray).toHaveBeenCalledOnce()
  })
})
