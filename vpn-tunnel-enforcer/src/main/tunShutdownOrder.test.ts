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
    currentStatus: { running, pid: 123, warning: null },
    timedStop: async (_phase: string, run: () => Promise<unknown>) => run(),
    stopProxyWatchdog: () => {},
    stopXray: vi.fn(async () => { calls.push('xray') }),
    isOwnedTunRuntimeRunning: vi.fn(async () => false),
    killOwnedRuntimeProcesses: vi.fn(async () => { calls.push('sing-box') }),
    waitForOwnedRuntimeToExit: vi.fn(async () => { calls.push('exit-proof'); return true }),
    rememberCleanupError: vi.fn((label: string, error: Error) => dependencies.cleanupErrors.push(`${label}: ${error.message}`)),
    cleanupErrors: [] as string[], logEvent: vi.fn(),
    notifyStatus: vi.fn(), networkCleanup: { baseline: false, firewall: false, adapters: false }
  }
  const run = new Function(...Object.keys(dependencies), `return async () => {${body}}`)(...Object.values(dependencies)) as () => Promise<{ success: boolean; error: string; networkCleanup: unknown } | undefined>
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
  it.each(['stop denied', 'exit timeout', 'exit query failed'])('preserves upstream and protection on %s', async failure => {
    const h = harness()
    if (failure === 'stop denied') h.killOwnedRuntimeProcesses.mockRejectedValueOnce(new Error('native denied'))
    if (failure === 'exit timeout') h.waitForOwnedRuntimeToExit.mockResolvedValueOnce(false)
    if (failure === 'exit query failed') h.waitForOwnedRuntimeToExit.mockRejectedValueOnce(new Error('query denied'))
    expect(await h.run()).toMatchObject({ success: false, networkCleanup: { baseline: false, firewall: false, adapters: false } })
    expect(h.stopXray).not.toHaveBeenCalled()
    expect(h.currentStatus).toMatchObject({ running: true, pid: 123, warning: expect.any(String) })
    expect(h.notifyStatus).toHaveBeenCalledWith('error')
  })
  it('allows a failed stop to be retried once runtime exit is proved', async () => {
    const h = harness()
    h.killOwnedRuntimeProcesses.mockRejectedValueOnce(new Error('native denied'))
    await h.run(); await h.run()
    expect(h.stopXray).toHaveBeenCalledOnce()
    expect(h.calls).toEqual(['sing-box', 'exit-proof', 'xray'])
  })
  it('requires a fresh absence proof before skipping a never-started consumer', async () => {
    const h = harness(false); await h.run()
    expect(h.isOwnedTunRuntimeRunning).toHaveBeenCalledWith(true)
    expect(h.killOwnedRuntimeProcesses).not.toHaveBeenCalled()
    expect(h.stopXray).toHaveBeenCalledOnce()
  })
})
