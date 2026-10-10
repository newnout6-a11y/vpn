import { beforeEach, describe, expect, it, vi } from 'vitest'
const wfpLoader = vi.hoisted(() => "$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition 'PINNED_TEST_SOURCE'\n")
vi.mock('./wfpIpv6', () => ({ wfpPrelude: async () => wfpLoader }))

vi.mock('./admin', () => ({
  isProcessElevated: vi.fn(async () => Boolean((globalThis as any).__elevatedPsHelperMock?.elevated))
}))

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

const mockKill = vi.fn()
const mockChildren: any[] = []
const mockExecFile = vi.fn((_cmd: string, _args: string[], _opts: any, cb?: any) => {
  if (typeof cb === 'function') cb(null, '', '')
})

vi.mock('child_process', () => {
  const makeChild = () => {
    const child = {
    pid: 9999,
    killed: false,
    exitCode: null,
    kill: mockKill,
    stdin: {
      write: vi.fn(),
      end: vi.fn()
    },
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
    on: vi.fn()
    }
    mockChildren.push(child)
    return child
  }

  return {
    default: {
      spawn: vi.fn(() => makeChild()),
      execFile: mockExecFile
    },
    spawn: vi.fn(() => makeChild()),
    execFile: mockExecFile
  }
})

describe('elevated PS helper errors', () => {
  beforeEach(() => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: false }
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    vi.resetModules()
  })

  it('classifies oversized scripts before dispatch (AT-03-007/009)', async () => {
    const { execElevatedPs } = await import('./elevatedPsHelper')
    const prefix = 'Get-NetFirewallProfile;#'
    const boundary = prefix + 'x'.repeat(64 * 1024 - prefix.length)
    await expect(execElevatedPs(boundary, 1000, 'firewall-killswitch')).rejects.toMatchObject({ code: 'elevated-helper-unavailable' })
    await expect(execElevatedPs(boundary + 'x', 1000, 'firewall-killswitch')).rejects.toMatchObject({ code: 'elevated-helper-script-too-large' })
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
  it('accepts only the pinned WFP loader and keeps arbitrary Add-Type blocked (AT-03-012)', async () => {
    const { execElevatedPs } = await import('./elevatedPsHelper')
    const body = '$engine=New-Object VPNTE.IPv6.NativeEngine; $engine.ReadOwned()'
    await expect(execElevatedPs(wfpLoader + body, 1000, 'wfp-ipv6')).rejects.toMatchObject({ code: 'elevated-helper-unavailable' })
    for (const script of [body, wfpLoader.replace('PINNED_TEST_SOURCE', 'CHANGED') + body, wfpLoader + body + '; Add-Type -TypeDefinition evil', wfpLoader + body + '; Set-NetFirewallProfile -DefaultOutboundAction Allow', wfpLoader + body + '; Disable-NetAdapterBinding -ComponentID ms_tcpip6']) {
      await expect(execElevatedPs(script, 1000, 'wfp-ipv6')).rejects.toMatchObject({ code: 'elevated-helper-script-rejected' })
    }
    await expect(execElevatedPs(wfpLoader + body, 1000, 'firewall-killswitch')).rejects.toMatchObject({ code: 'elevated-helper-script-rejected' })
  })

  it('keeps the fixed registry reader outside arbitrary physical-adapter scripts (AT-03-012)', async () => {
    const { execElevatedPs } = await import('./elevatedPsHelper')
    const { DNS_POLICY_SNAPSHOT_SCRIPT } = await import('./recoveryPsProtocol')
    await expect(execElevatedPs(DNS_POLICY_SNAPSHOT_SCRIPT, 15000, 'physical-adapter-lockdown'))
      .rejects.toMatchObject({ code: 'elevated-helper-script-rejected' })
  })

  it('does not let physical-adapter commands authorize firewall reset payloads', async () => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: true }
    const { execElevatedPs } = await import('./elevatedPsHelper')

    await expect(
      execElevatedPs('Get-NetAdapter; netsh advfirewall reset', 5000, 'physical-adapter-lockdown')
    ).rejects.toMatchObject({
      name: 'ElevatedPsHelperError',
      code: 'elevated-helper-script-rejected'
    })
  })

  it('does not let firewall commands authorize HKLM Run persistence payloads', async () => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: true }
    const { execElevatedPs } = await import('./elevatedPsHelper')

    await expect(
      execElevatedPs('Get-NetFirewallRule; reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d calc.exe /f', 5000, 'firewall-killswitch')
    ).rejects.toMatchObject({
      name: 'ElevatedPsHelperError',
      code: 'elevated-helper-script-rejected'
    })
  })

  it('rejects PowerShell call/chaining operators before helper execution', async () => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: true }
    const { execElevatedPs } = await import('./elevatedPsHelper')

    for (const script of [
      'Get-NetFirewallRule; & calc.exe',
      'Get-NetFirewallRule && Get-Process',
      'Get-NetFirewallRule || Get-Process',
      'Get-NetFirewallRule | powershell.exe -NoProfile'
    ]) {
      await expect(execElevatedPs(script, 5000, 'firewall-killswitch')).rejects.toMatchObject({
        name: 'ElevatedPsHelperError',
        code: 'elevated-helper-script-rejected'
      })
    }
  })

  it('still allows the firewall policy to use native PowerShell pipelines', async () => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: false }
    const { execElevatedPs } = await import('./elevatedPsHelper')

    await expect(execElevatedPs(
      "Get-NetFirewallRule -DisplayName 'VPNTE*' | Remove-NetFirewallRule -ErrorAction SilentlyContinue",
      5000,
      'firewall-killswitch'
    )).rejects.toMatchObject({
      name: 'ElevatedPsHelperError',
      code: 'elevated-helper-unavailable'
    })
  })

  it('terminates the hung process on timeout and rejects with elevated-helper-timeout', async () => {
    vi.useFakeTimers()
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: true }
    mockKill.mockClear()
    mockExecFile.mockClear()
    const { execElevatedPs, startElevatedPsHelper, isElevatedPsHelperRunning } = await import('./elevatedPsHelper')

    await startElevatedPsHelper()
    expect(isElevatedPsHelperRunning()).toBe(true)

    const promise = execElevatedPs('Get-NetFirewallRule', 2000, 'firewall-killswitch')

    vi.advanceTimersByTime(2001)

    await expect(promise).rejects.toMatchObject({
      name: 'ElevatedPsHelperError',
      code: 'elevated-helper-timeout'
    })

    expect(mockKill).toHaveBeenCalledWith('SIGKILL')
    expect(isElevatedPsHelperRunning()).toBe(false)
    vi.useRealTimers()
  })

  it('rejects queued pending commands when a hung helper process is killed', async () => {
    vi.useFakeTimers()
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: true }
    const { execElevatedPs, startElevatedPsHelper } = await import('./elevatedPsHelper')

    await startElevatedPsHelper()

    const p1 = execElevatedPs('Get-NetFirewallRule', 1000, 'firewall-killswitch')
    const p2 = execElevatedPs('Get-NetFirewallProfile', 5000, 'firewall-killswitch')

    vi.advanceTimersByTime(1001)

    await expect(p1).rejects.toMatchObject({
      code: 'elevated-helper-timeout'
    })
    await expect(p2).rejects.toMatchObject({
      code: 'elevated-helper-exited'
    })

    vi.useRealTimers()
  })

  it.each([20, undefined, -1, '20', 10000])('records safe helper timing with executionMs=%s (AT-00-005)', async executionMs => {
    ;(globalThis as any).__elevatedPsHelperMock = { elevated: true }
    const { execElevatedPs, startElevatedPsHelper, stopElevatedPsHelper } = await import('./elevatedPsHelper')
    const { logEvent } = await import('./appLogger')
    const logger = vi.mocked(logEvent)
    logger.mockClear()
    await startElevatedPsHelper()
    const child = mockChildren.at(-1)!
    const receive = child.stdout.on.mock.calls.find((call: any[]) => call[0] === 'data')[1]
    const clock = vi.spyOn(performance, 'now').mockReturnValue(100)
    try {
      const pending = execElevatedPs('Get-NetFirewallProfile # private-source', 5000, 'firewall-killswitch')
      const { id } = JSON.parse(child.stdin.write.mock.calls.at(-1)[0])
      clock.mockReturnValue(150)
      receive(Buffer.from(JSON.stringify({ id, stdout: 'private-output', stderr: 'private-error', exitCode: 0, executionMs }) + '\n'))
      expect(await pending).toEqual({ stdout: 'private-output', stderr: 'private-error', exitCode: 0 })
      const timing = logger.mock.calls.find(call => call[1] === 'ps-helper' && call[2] === 'command timing')![3]
      expect(timing).toMatchObject({ policy: 'firewall-killswitch', roundtripMs: 50 })
      if (executionMs === 20) expect(timing).toMatchObject({ executionMs: 20, transportOverheadMs: 30 })
      else {
        expect(timing).not.toHaveProperty('executionMs')
        expect(timing).not.toHaveProperty('transportOverheadMs')
      }
      expect(JSON.stringify(timing)).not.toContain('private')
    } finally {
      clock.mockRestore()
      stopElevatedPsHelper()
    }
  })
})
