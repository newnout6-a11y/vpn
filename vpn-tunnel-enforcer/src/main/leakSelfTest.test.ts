import { beforeEach, describe, expect, it, vi } from 'vitest'

const execMock = vi.hoisted(() => vi.fn())
const execFileMock = vi.hoisted(() => vi.fn())
const logEventMock = vi.hoisted(() => vi.fn())

;(execMock as any)[Symbol.for('nodejs.util.promisify.custom')] = (cmd: string, opts: unknown) =>
  new Promise((resolve, reject) => {
    execMock(cmd, opts, (err: Error | null, stdout: string, stderr: string) => {
      if (err) {
        reject(Object.assign(err, { stdout, stderr }))
        return
      }
      resolve({ stdout, stderr })
    })
  })

vi.mock('child_process', () => ({
  default: { exec: execMock, execFile: execFileMock },
  exec: execMock,
  execFile: execFileMock
}))

vi.mock('./appLogger', () => ({
  logEvent: logEventMock
}))

function mockExecSuccesses(): void {
  execMock.mockImplementation((cmd: string, _opts: unknown, cb: (err: Error | null, stdout: string, stderr: string) => void) => {
    setTimeout(() => {
      if (cmd.includes('Get-NetAdapter')) cb(null, '[]', '')
      else if (cmd.includes('cloudflare.com/cdn-cgi/trace')) cb(null, 'ip=1.2.3.4\n', '')
      else cb(null, '1.2.3.4', '')
    }, 5)
    return {}
  })
}

describe('runLeakSelfTest coalescing', () => {
  beforeEach(() => {
    vi.resetModules()
    execMock.mockReset()
    execFileMock.mockReset()
    logEventMock.mockReset()
    mockExecSuccesses()
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
        if (cmd.includes('Get-NetAdapter')) cb(null, '[]', '')
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
        if (cmd.includes('Get-NetAdapter')) cb(null, '[]', '')
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
    }
  })
})
