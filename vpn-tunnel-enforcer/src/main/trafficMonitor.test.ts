/**
 * Tests for trafficMonitor's persistent-reader design.
 *
 * The point of the rewrite is that the monitor keeps ONE long-lived
 * powershell.exe alive and reads a counter sample per second off its stdout,
 * instead of spawning a fresh powershell.exe every second. These tests pin
 * that behaviour (single spawn, killed on stop) and the bps math.
 */
import { EventEmitter } from 'events'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }))
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

import { trafficMonitor } from './trafficMonitor'

const realPlatform = process.platform
function setPlatform(p: string) {
  Object.defineProperty(process, 'platform', { value: p, configurable: true })
}

describe('trafficMonitor persistent reader', () => {
  let proc: FakeProc

  beforeEach(() => {
    setPlatform('win32')
    spawnMock.mockReset()
    proc = new FakeProc()
    spawnMock.mockReturnValue(proc)
  })

  afterEach(() => {
    trafficMonitor.stop()
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
    const seen: Array<{ downloadBps: number; uploadBps: number; adapterFound: boolean }> = []
    const off = trafficMonitor.onStatsChange((s) =>
      seen.push({ downloadBps: s.downloadBps, uploadBps: s.uploadBps, adapterFound: s.adapterFound })
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
})
