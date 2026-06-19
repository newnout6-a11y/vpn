import { beforeEach, describe, expect, it, vi } from 'vitest'

const execMock = vi.hoisted(() => vi.fn())
const execFileMock = vi.hoisted(() => vi.fn())
const logEventMock = vi.hoisted(() => vi.fn())

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
})
