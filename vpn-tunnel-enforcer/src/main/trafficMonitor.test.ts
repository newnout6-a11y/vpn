/**
 * Tests for the explicit compatibility reader; native coverage is below.
 *
 * When native reads are explicitly disabled, the monitor keeps ONE long-lived
 * powershell.exe alive and reads a counter sample per second off its stdout,
 * instead of spawning a fresh powershell.exe every second. These tests pin
 * that behaviour (single spawn, killed on stop) and the bps math.
 */
import { EventEmitter } from 'events'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }))
const { nativeMock } = vi.hoisted(() => ({ nativeMock: vi.fn() }))
vi.mock('./native/nativeHost', () => ({ callNativeHost: nativeMock }))
// trafficMonitor is the only module in this import chain that touches
// child_process, so a full manual mock (rather than importOriginal) is enough
// and avoids the named-binding pitfalls of partially mocking a node builtin.
vi.mock('child_process', () => ({
  __esModule: true,
  spawn: spawnMock,
  default: { spawn: spawnMock }
}))

// A stand-in for the powershell child process.
class FakeProc extends EventEmitter {
  stdout = new (class extends EventEmitter {
    setEncoding() {}
  })()
  kill = vi.fn()
  emitLine(obj: Record<string, unknown>) {
    this.stdout.emit('data', JSON.stringify(obj) + '\n')
  }
}

import { calculateBurstiness, smoothTrafficRate, trafficMonitor } from './trafficMonitor'

const realPlatform = process.platform
const previousDisableNative = process.env.VPNTE_DISABLE_NATIVE_NET
function setPlatform(p: string) {
  Object.defineProperty(process, 'platform', { value: p, configurable: true })
}

describe('trafficMonitor persistent reader', () => {
  let proc: FakeProc

  beforeEach(() => {
    setPlatform('win32')
    process.env.VPNTE_DISABLE_NATIVE_NET = '1'
    spawnMock.mockReset()
    proc = new FakeProc()
    spawnMock.mockReturnValue(proc)
  })

  afterEach(() => {
    trafficMonitor.stop()
    if (previousDisableNative === undefined) delete process.env.VPNTE_DISABLE_NATIVE_NET
    else process.env.VPNTE_DISABLE_NATIVE_NET = previousDisableNative
    setPlatform(realPlatform)
  })

  it('spawns exactly one powershell reader on start (not one per sample)', () => {
    trafficMonitor.start('VPNTE-TUN')
    proc.emitLine({ Found: true, Name: 'VPNTE-TUN', ReceivedBytes: 1000, SentBytes: 500 })
    proc.emitLine({ Found: true, Name: 'VPNTE-TUN', ReceivedBytes: 2000, SentBytes: 800 })
    proc.emitLine({ Found: true, Name: 'VPNTE-TUN', ReceivedBytes: 3000, SentBytes: 900 })
    expect(spawnMock).toHaveBeenCalledTimes(1)
    expect(spawnMock.mock.calls[0][0]).toBe('powershell')
  })

  it('start() is idempotent — a second start does not spawn another reader', () => {
    trafficMonitor.start('VPNTE-TUN')
    trafficMonitor.start('VPNTE-TUN')
    expect(spawnMock).toHaveBeenCalledTimes(1)
  })

  it('computes download/upload bps from successive samples', () => {
    const seen: Array<{
      downloadBps: number
      uploadBps: number
      smoothedDownloadBps: number
      downloadBurstinessPct: number
      adapterFound: boolean
    }> = []
    const off = trafficMonitor.onStatsChange((s) =>
      seen.push({
        downloadBps: s.downloadBps,
        uploadBps: s.uploadBps,
        smoothedDownloadBps: s.smoothedDownloadBps,
        downloadBurstinessPct: s.downloadBurstinessPct,
        adapterFound: s.adapterFound
      })
    )
    trafficMonitor.start('VPNTE-TUN')
    // First found sample establishes the baseline (bps still 0).
    proc.emitLine({ Found: true, Name: 'VPNTE-TUN', ReceivedBytes: 1_000_000, SentBytes: 500_000 })
    // Second sample 1s-ish later produces a positive rate.
    proc.emitLine({ Found: true, Name: 'VPNTE-TUN', ReceivedBytes: 2_000_000, SentBytes: 700_000 })
    off()

    const last = seen.at(-1)!
    expect(last.adapterFound).toBe(true)
    expect(last.downloadBps).toBeGreaterThan(0)
    expect(last.uploadBps).toBeGreaterThan(0)
    expect(last.smoothedDownloadBps).toBe(last.downloadBps)
    expect(last.downloadBurstinessPct).toBe(0)
  })

  it('smooths an isolated burst without changing the raw rate', () => {
    expect(smoothTrafficRate(10, 100, 0.35)).toBeCloseTo(41.5)
    expect(smoothTrafficRate(0, 100, 0.35)).toBe(100)
  })

  it('reports relative variation of recent counter deltas', () => {
    expect(calculateBurstiness([100, 100, 100])).toBe(0)
    expect(calculateBurstiness([50, 100, 150])).toBe(41)
    expect(calculateBurstiness([0, 0])).toBe(0)
  })

  it('kills the reader process on stop()', () => {
    trafficMonitor.start('VPNTE-TUN')
    trafficMonitor.stop()
    expect(proc.kill).toHaveBeenCalledTimes(1)
  })

  it('respawns the reader if it exits unexpectedly while running', () => {
    vi.useFakeTimers()
    try {
      trafficMonitor.start('VPNTE-TUN')
      expect(spawnMock).toHaveBeenCalledTimes(1)
      // Simulate the reader dying; the monitor should schedule a respawn.
      proc.emit('exit', 1, null)
      vi.advanceTimersByTime(3000)
      expect(spawnMock).toHaveBeenCalledTimes(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('publishes a neutral non-running fallback on non-Windows dev hosts', () => {
    const seen: Array<{ running: boolean; adapterFound: boolean }> = []
    const off = trafficMonitor.onStatsChange((s) =>
      seen.push({ running: s.running, adapterFound: s.adapterFound })
    )

    setPlatform('linux')
    trafficMonitor.start('VPNTE-TUN')
    off()

    expect(spawnMock).not.toHaveBeenCalled()
    expect(seen.at(-1)).toEqual({ running: false, adapterFound: false })
  })
})

describe('native traffic sampling (AT-07-009 / AT-07-012)', () => {
  const sample = (receivedBytes = '1000', sentBytes = '500', identity = 'a'.repeat(32)) => ({ found: true, name: 'VPNTE-TUN', identity, receivedBytes, sentBytes })
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(100000)
    setPlatform('win32')
    delete process.env.VPNTE_DISABLE_NATIVE_NET
    spawnMock.mockClear()
    nativeMock.mockReset().mockResolvedValue(sample())
  })
  afterEach(async () => {
    trafficMonitor.stop()
    await Promise.resolve()
    vi.useRealTimers()
    setPlatform(realPlatform)
    if (previousDisableNative === undefined) delete process.env.VPNTE_DISABLE_NATIVE_NET
    else process.env.VPNTE_DISABLE_NATIVE_NET = previousDisableNative
  })
  it('uses the utility host with no PowerShell process and keeps uint64 deltas exact above 2^53', async () => {
    nativeMock.mockResolvedValueOnce(sample('9007199254740993', '4294967297'))
      .mockResolvedValueOnce(sample('9007199254740994', '4294967299'))
    trafficMonitor.start('VPNTE-TUN')
    await vi.advanceTimersByTimeAsync(1000)
    expect(nativeMock).toHaveBeenCalledWith('traffic-counters', { adapterName: 'VPNTE-TUN' }, 1500)
    expect(spawnMock).not.toHaveBeenCalled()
    expect(trafficMonitor.getCurrentStats()).toMatchObject({ adapterFound: true, downloadBps: 1, uploadBps: 2, sessionDownloadBytes: 1, sessionUploadBytes: 2 })
  })
  it('does not overlap pending reads or publish after stop, then drains before a successor samples', async () => {
    let finish!: (value: ReturnType<typeof sample>) => void
    nativeMock.mockReturnValueOnce(new Promise(resolve => { finish = resolve }))
      .mockResolvedValueOnce(sample('2000'))
    trafficMonitor.start('VPNTE-TUN')
    await vi.advanceTimersByTimeAsync(5000)
    expect(nativeMock).toHaveBeenCalledTimes(1)
    trafficMonitor.stop()
    trafficMonitor.start('VPNTE-TUN')
    expect(nativeMock).toHaveBeenCalledTimes(1)
    finish(sample('99999'))
    await vi.advanceTimersByTimeAsync(0)
    expect(nativeMock).toHaveBeenCalledTimes(2)
    expect(trafficMonitor.getCurrentStats()).toMatchObject({ totalDownloadBytes: 2000, sessionDownloadBytes: 0 })
    trafficMonitor.stop()
    await vi.advanceTimersByTimeAsync(10000)
    expect(nativeMock).toHaveBeenCalledTimes(2)
  })
  it.each(['unavailable', 'read-refused', 'timeout', 'protocol'])('never replays %s through PowerShell and clears stale healthy status', async kind => {
    nativeMock.mockResolvedValueOnce(sample()).mockRejectedValueOnce(Object.assign(new Error('fixture'), { kind }))
    trafficMonitor.start('VPNTE-TUN')
    await vi.advanceTimersByTimeAsync(0)
    expect(trafficMonitor.getCurrentStats().adapterFound).toBe(true)
    await vi.advanceTimersByTimeAsync(1000)
    expect(trafficMonitor.getCurrentStats()).toMatchObject({ running: true, adapterFound: false, downloadBps: 0, uploadBps: 0 })
    expect(spawnMock).not.toHaveBeenCalled()
  })
  it('resets the baseline when the adapter is recreated or its counters reset', async () => {
    nativeMock.mockResolvedValueOnce(sample('10000')).mockResolvedValueOnce(sample('20000', '500', 'b'.repeat(32)))
      .mockResolvedValueOnce(sample('1', '1', 'b'.repeat(32)))
    trafficMonitor.start('VPNTE-TUN')
    await vi.advanceTimersByTimeAsync(2000)
    expect(trafficMonitor.getCurrentStats()).toMatchObject({ adapterFound: true, sessionDownloadBytes: 0, downloadBps: 0, totalDownloadBytes: 1 })
  })
  it('rejects malformed or out-of-range counters instead of displaying a successful sample', async () => {
    nativeMock.mockResolvedValueOnce(sample('18446744073709551616'))
    trafficMonitor.start('VPNTE-TUN')
    await vi.advanceTimersByTimeAsync(0)
    expect(trafficMonitor.getCurrentStats().adapterFound).toBe(false)
    expect(spawnMock).not.toHaveBeenCalled()
  })
})
