import { beforeEach, describe, expect, it, vi } from 'vitest'

const execMock = vi.hoisted(() => vi.fn())
const execFileMock = vi.hoisted(() => vi.fn())
const logEventMock = vi.hoisted(() => vi.fn())

vi.mock('child_process', async () => {
  const { EventEmitter } = await import('node:events')
  const execFile = (file: string, args: string[], options: unknown, callback: (error: Error | null, stdout: string, stderr: string) => void) => {
    const child = Object.assign(new EventEmitter(), { kill: vi.fn(() => true) })
    const finished = (error: (Error & { stdout?: string; stderr?: string }) | null, stdout = '', stderr = '') => queueMicrotask(() => {
      callback(error, stdout || error?.stdout || '', stderr || error?.stderr || '')
      child.emit('close', error ? 1 : 0)
    })
    if (args.includes('--interface')) execFileMock(file, args, options, finished)
    else execMock([file, ...args].join(' '), options, finished)
    return child
  }
  return {
    default: { exec: execMock, execFile },
    exec: execMock,
    execFile
  }
})
vi.mock('./trafficForensics', () => ({ recordTrafficForensicsAppEvent: vi.fn() }))

vi.mock('./appLogger', () => ({
  logEvent: logEventMock
}))

// AT-07-002 / AT-07-012: the native iphlpapi path is mocked; by default it is "unavailable" so the
// legacy PowerShell path below stays covered. Individual tests flip it to prove both directions.
const nativeSourcesMock = vi.hoisted(() => vi.fn())
vi.mock('./native/nativeNetworkReads', () => ({ nativePhysicalIpv4Sources: nativeSourcesMock }))

function mockExecSuccesses(): void {
  execMock.mockImplementation((cmd: string, _opts: unknown, cb: (err: Error | null, stdout: string, stderr: string) => void) => {
    setTimeout(() => {
      if (cmd.includes('Get-NetAdapter') || cmd.includes('EncodedCommand')) cb(null, '[]', '')
      else if (cmd.includes('cloudflare.com/cdn-cgi/trace')) cb(null, 'ip=1.2.3.4\n', '')
      else cb(null, '1.2.3.4', '')
    }, 5)
    return {}
  })
}

describe('runLeakSelfTest coalescing', () => {
  beforeEach(async () => {
    vi.resetModules()
    execMock.mockReset()
    execFileMock.mockReset()
    logEventMock.mockReset()
    nativeSourcesMock.mockReset()
    nativeSourcesMock.mockImplementation(() => { throw new Error('native unavailable') })
    mockExecSuccesses()
    const { resetLeakTestThrottlesForTest } = await import('./leakSelfTest')
    resetLeakTestThrottlesForTest()
  })

  it('shares an in-flight probe between concurrent callers', async () => {
    const { runLeakSelfTest } = await import('./leakSelfTest')

    const [a, b] = await Promise.all([runLeakSelfTest(), runLeakSelfTest()])

    expect(a.summary).toBe(b.summary)
    expect(execMock).toHaveBeenCalledTimes(process.platform === 'win32' ? 3 : 2)
  })

  it('tries another DNS trace endpoint when the first one fails', async () => {
    execMock.mockImplementation((cmd: string, _opts: unknown, cb: (err: Error | null, stdout: string, stderr: string) => void) => {
      setTimeout(() => {
        if (cmd.includes('Get-NetAdapter') || cmd.includes('EncodedCommand')) cb(null, '[]', '')
        else if (cmd.includes('cloudflare.com/cdn-cgi/trace')) cb(new Error('blocked'), '', 'blocked')
        else if (cmd.includes('one.one.one.one/cdn-cgi/trace')) cb(null, 'ip=1.2.3.4\n', '')
        else cb(null, '1.2.3.4', '')
      }, 5)
      return {}
    })
    const { runLeakSelfTest } = await import('./leakSelfTest')

    const result = await runLeakSelfTest()

    expect(result.dnsLeakDetected).toBe(false)
    expect(execMock.mock.calls.map(([cmd]) => String(cmd))).toEqual(
      expect.arrayContaining([
        expect.stringContaining('cloudflare.com/cdn-cgi/trace'),
        expect.stringContaining('one.one.one.one/cdn-cgi/trace')
      ])
    )
  })

  it('does not report a DNS leak from a DNS trace IP mismatch alone', async () => {
    execMock.mockImplementation((cmd: string, _opts: unknown, cb: (err: Error | null, stdout: string, stderr: string) => void) => {
      setTimeout(() => {
        if (cmd.includes('Get-NetAdapter') || cmd.includes('EncodedCommand')) cb(null, '[]', '')
        else if (cmd.includes('cloudflare.com/cdn-cgi/trace')) cb(null, 'ip=5.6.7.8\n', '')
        else cb(null, '1.2.3.4', '')
      }, 5)
      return {}
    })
    const { runLeakSelfTest } = await import('./leakSelfTest')

    const result = await runLeakSelfTest()

    expect(result.physicalAdapterReached).toBe(false)
    expect(result.publicIpMismatch).toBe(false)
    expect(result.dnsLeakDetected).toBe(false)
    expect(result.dnsLeakDetail).toContain('5.6.7.8')
    expect(result.summary).toContain('OK:')
  })

  it('suppresses event-triggered leak checks during TUN start transitions', async () => {
    vi.useFakeTimers()
    try {
      const { suppressLeakSelfTestsFor, triggerLeakCheckNow } = await import('./leakSelfTest')

      suppressLeakSelfTestsFor(20_000, 'test-start')
      triggerLeakCheckNow('network-change')

      expect(execMock).not.toHaveBeenCalled()
      expect(logEventMock).toHaveBeenCalledWith(
        'debug',
        'leak-test',
        'event-triggered run suppressed during transition',
        expect.objectContaining({ reason: 'network-change' })
      )
    } finally {
      vi.useRealTimers()
      const { resetLeakTestThrottlesForTest } = await import('./leakSelfTest')
      resetLeakTestThrottlesForTest()
    }
  })

  it('notifies onLeakSelfTestCompletedCb when a triggered check finishes cleanly with zero leaks', async () => {
    const { setLeakSelfTestCompletedCallback, triggerLeakCheckNow, resetLeakTestThrottlesForTest } = await import('./leakSelfTest')
    resetLeakTestThrottlesForTest()
    const completedCb = vi.fn()
    setLeakSelfTestCompletedCallback(completedCb)

    triggerLeakCheckNow('test-clean')
    await vi.waitFor(() => {
      expect(completedCb).toHaveBeenCalledWith(
        expect.objectContaining({
          physicalAdapterReached: false,
          publicIpMismatch: false,
          dnsLeakDetected: false,
          defaultRoutePublicIp: '1.2.3.4',
          physicalAdapterInspectionComplete: true
        })
      )
    })
  })

  it('marks physicalAdapterInspectionComplete as false and does not notify completedCb when adapter enumeration fails', async () => {
    execMock.mockImplementation((cmd: string, _opts: unknown, cb: (err: Error | null, stdout: string, stderr: string) => void) => {
      setTimeout(() => {
        if (cmd.includes('Get-NetAdapter') || cmd.includes('EncodedCommand')) cb(new Error('WMI query failed'), '', 'WMI error')
        else if (cmd.includes('cloudflare.com/cdn-cgi/trace')) cb(null, 'ip=1.2.3.4\n', '')
        else cb(null, '1.2.3.4', '')
      }, 5)
      return {}
    })
    const { setLeakSelfTestCompletedCallback, triggerLeakCheckNow, runLeakSelfTest } = await import('./leakSelfTest')
    const completedCb = vi.fn()
    setLeakSelfTestCompletedCallback(completedCb)

    const result = await runLeakSelfTest()
    expect(result.defaultRoutePublicIp).toBe('1.2.3.4')
    expect(result.physicalAdapterInspectionComplete).toBe(false)
    expect(result.physicalAdapterReached).toBe(false)

    triggerLeakCheckNow('test-failed-enum')
    await new Promise((r) => setTimeout(r, 50))
    expect(completedCb).not.toHaveBeenCalled()
  })

  it.skipIf(process.platform !== 'win32')('uses the native adapter read without spawning PowerShell and keeps inspection complete', async () => {
    nativeSourcesMock.mockReturnValue([{ alias: 'Wi-Fi', ipv4: '192.168.0.10' }])
    // Per-adapter curl --interface probe runs through execFile: make it fail cleanly (blocked = no leak).
    execFileMock.mockImplementation((...args: unknown[]) => {
      const cb = args[args.length - 1] as (err: Error | null, out?: { stdout: string; stderr: string }) => void
      cb(Object.assign(new Error('Could not connect'), { code: 7, stdout: '', stderr: 'blocked' }))
      return {}
    })
    const { runLeakSelfTest } = await import('./leakSelfTest')

    const result = await runLeakSelfTest()

    expect(result.physicalAdapterInspectionComplete).toBe(true)
    const commands = execMock.mock.calls.map(([cmd]) => String(cmd))
    expect(commands.some(c => c.includes('EncodedCommand'))).toBe(false)
    expect(execFileMock.mock.calls.some(([, args]) => Array.isArray(args) && args.includes('192.168.0.10'))).toBe(true)
  })

  it.skipIf(process.platform !== 'win32')('falls back to PowerShell when the native read throws', async () => {
    const { runLeakSelfTest } = await import('./leakSelfTest')

    await runLeakSelfTest()

    expect(nativeSourcesMock).toHaveBeenCalled()
    expect(execMock.mock.calls.map(([cmd]) => String(cmd)).some(c => c.includes('EncodedCommand'))).toBe(true)
  })

  it.skipIf(process.platform !== 'win32')('does not treat an empty native answer as "nothing to test": asks PowerShell', async () => {
    nativeSourcesMock.mockReturnValue([])
    const { runLeakSelfTest } = await import('./leakSelfTest')

    await runLeakSelfTest()

    expect(execMock.mock.calls.map(([cmd]) => String(cmd)).some(c => c.includes('EncodedCommand'))).toBe(true)
  })

  it('marks physicalAdapterInspectionComplete as false on cancellation', async () => {
    const { cancelLeakSelfTest, runLeakSelfTest } = await import('./leakSelfTest')
    const inFlight = runLeakSelfTest()
    cancelLeakSelfTest()
    const result = await inFlight
    expect(result.physicalAdapterInspectionComplete).toBe(false)
    expect(result.summary).toContain('отменён')
  })
})
