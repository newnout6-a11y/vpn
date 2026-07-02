import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('./admin', () => ({
  isProcessElevated: vi.fn(async () => Boolean((globalThis as any).__elevatedPsHelperMock?.elevated))
}))

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

vi.mock('child_process', () => ({
  default: {
    spawn: vi.fn(() => ({
      killed: false,
      exitCode: null,
      stdin: {
        write: vi.fn(),
        end: vi.fn()
      },
      stdout: { on: vi.fn() },
      stderr: { on: vi.fn() },
      on: vi.fn()
    }))
  },
  spawn: vi.fn(() => ({
    killed: false,
    exitCode: null,
    stdin: {
      write: vi.fn(),
      end: vi.fn()
    },
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
    on: vi.fn()
  }))
}))

describe('elevated PS helper errors', () => {
  beforeEach(() => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: false }
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    vi.resetModules()
  })

  it('fails immediately with a typed unavailable error when helper cannot start', async () => {
    const { execElevatedPs, ElevatedPsHelperError } = await import('./elevatedPsHelper')

    await expect(execElevatedPs('Get-NetFirewallProfile', 30000, 'firewall-killswitch')).rejects.toMatchObject({
      name: 'ElevatedPsHelperError',
      code: 'elevated-helper-unavailable'
    })
    await expect(execElevatedPs('Get-NetFirewallProfile', 30000, 'firewall-killswitch')).rejects.toBeInstanceOf(ElevatedPsHelperError)
  })

  it('rejects pending commands with a typed stopped error on shutdown', async () => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: true }
    const { execElevatedPs, startElevatedPsHelper, stopElevatedPsHelper } = await import('./elevatedPsHelper')

    await startElevatedPsHelper()
    const pending = execElevatedPs('Get-NetFirewallRule', 5000, 'firewall-killswitch')
    stopElevatedPsHelper()

    await expect(pending).rejects.toMatchObject({
      name: 'ElevatedPsHelperError',
      code: 'elevated-helper-stopped'
    })
  })

  it('rejects scripts outside the selected helper policy', async () => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: true }
    const { execElevatedPs } = await import('./elevatedPsHelper')

    await expect(
      execElevatedPs('Invoke-WebRequest https://example.com', 5000, 'firewall-killswitch')
    ).rejects.toMatchObject({
      name: 'ElevatedPsHelperError',
      code: 'elevated-helper-script-rejected'
    })
  })
})
