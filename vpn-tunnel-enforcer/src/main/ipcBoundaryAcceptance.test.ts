// AT-01-003/004, F-139…145: dispatch through the production process-wide guard.
// The mutation budget applies to every preload-invokable channel. This proves
// envelope rejection; per-channel valid-envelope schema cases are separate.
import { readFileSync } from 'fs'
import { resolve } from 'path'
import { performance } from 'perf_hooks'
import { describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ handlers: new Map<string, Function>() }))
vi.mock('electron', () => ({ app: { isPackaged: true }, ipcMain: {
  handle: (channel: string, handler: Function) => state.handlers.set(channel, handler)
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { installTrustedIpcBoundary, registerTrustedRenderer, IpcValidationError } from './ipcSecurity'
import { logEvent } from './appLogger'
const url = 'file:///C:/app/out/renderer/index.html'
function owner() {
  const mainFrame = { url }
  const sender = { id: 17, mainFrame, isDestroyed: () => false }
  registerTrustedRenderer(sender as any, url)
  return { sender, senderFrame: mainFrame }
}
describe('guarded handler acceptance', () => {
  it('rejects foreign/missing/navigated frames before effects and audits a bounded source', async () => {
    installTrustedIpcBoundary()
    const effects = vi.fn(); const { ipcMain } = await import('electron')
    ipcMain.handle('acceptance:side-effect', effects)
    const event = owner()
    for (const bad of [{ ...event, senderFrame: null }, { ...event, senderFrame: { url } },
      { ...event, sender: { ...event.sender } }]) {
      await expect(state.handlers.get('acceptance:side-effect')!(bad)).rejects.toThrow('Rejected IPC')
    }
    event.sender.mainFrame.url = 'https://evil.test/FAKE-SECRET'
    await expect(state.handlers.get('acceptance:side-effect')!(event)).rejects.toThrow('Rejected IPC')
    expect(effects).not.toHaveBeenCalled()
    expect(logEvent).toHaveBeenCalledWith('warn', 'ipc-security', 'IPC request rejected', expect.objectContaining({
      correlationId: expect.any(String), senderId: 17, status: 'error'
    }))
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-SECRET')
  })
  it('rejects mutation payloads on every preload channel with zero effects (AT-01-004)', async () => {
    installTrustedIpcBoundary()
    const preload = readFileSync(resolve(__dirname, '../preload/index.ts'), 'utf8')
    const channels = [...new Set([...preload.matchAll(/invoke\('([^']+)'/g)].map(match => match[1]))]
    const { ipcMain } = await import('electron')
    const event = owner(); let effects = 0, rejected = 0
    for (const channel of channels) ipcMain.handle(channel, () => { effects++ })
    let deep: unknown = 'leaf'; for (let i = 0; i < 14; i++) deep = { child: deep }
    const bad = [NaN, Infinity, -Infinity, JSON.parse('{"__proto__":{"polluted":true}}'),
      { constructor: 'FAKE-CREDENTIAL' }, 'x'.repeat(2 * 1024 * 1024 + 1), deep,
      new Date()]
    // Full acceptance budget is opt-in to keep routine regression runs short.
    const budget = process.env.VPNTE_WP1_FUZZ === '1' ? 100_000 : 100
    // Quantize every duration upwards to milliseconds. A bounded histogram
        // avoids retaining millions of doubles and still proves the 50ms p99 limit.
        const histogram = new Uint32Array(52)
        let timedCases = 0
        const p99UpperBound = (buckets: Uint32Array, count: number) => {
          let seen = 0
          for (let ms = 0; ms < buckets.length; ms++) {
            seen += buckets[ms]
            if (seen >= Math.ceil(count * 0.99)) return ms
          }
          throw new Error('Missing timing observations')
        }
        let maxChannelP99Ms = 0
    // Do not retain millions of audit mock calls during a fuzz run.
    vi.mocked(logEvent).mockImplementation(() => {})
    for (const channel of channels) {
      const handler = state.handlers.get(channel)!
      const channelHistogram = new Uint32Array(52)
      for (let iteration = 0; iteration < budget; iteration++) {
        const started = performance.now()
        try { await handler(event, { [`field_${iteration}`]: bad[iteration % bad.length], sequence: iteration }); throw new Error('Invalid payload accepted') }
        catch (error) { if (!(error instanceof IpcValidationError)) throw error; rejected++ }
        const bucket = Math.min(51, Math.ceil(performance.now() - started))
        histogram[bucket]++; channelHistogram[bucket]++; timedCases++
        vi.mocked(logEvent).mockClear()
      }
      const channelP99 = p99UpperBound(channelHistogram, budget)
      maxChannelP99Ms = Math.max(maxChannelP99Ms, channelP99)
      expect(channelP99, channel).toBeLessThanOrEqual(50)
    }
    expect(timedCases).toBe(channels.length * budget)
    expect(effects).toBe(0); expect(rejected).toBe(channels.length * budget)
    console.log('WP1_IPC_FUZZ', JSON.stringify({ seed: 1004, channels: channels.length, perChannel: budget,
      rejected, effects, timedCases, p99UpperBoundMs: p99UpperBound(histogram, timedCases), maxChannelP99Ms }))
  }, 1_200_000)
})
