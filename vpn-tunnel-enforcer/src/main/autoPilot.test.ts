import { describe, expect, it, vi, beforeEach } from 'vitest'
import axios from 'axios'
import { SocksClient } from 'socks'

const {
  mockLogEvent,
  mockSettings,
  mockSettingsSave,
  mockTunStatus,
  mockTunStop,
  mockTunStart,
  mockProbeTcp,
  mockRoutingPlan,
  mockGetRoutingPlan,
  mockApplyBaseline,
  mockRollbackBaseline
} = vi.hoisted(() => {
  const mockSettings = {
    proxyOverride: '',
    proxyType: 'socks5',
    autoNetworkBaseline: false,
    firewallKillSwitch: true,
    strictAdapterLockdown: true,
    stealthMode: false
  }
  const mockRoutingPlan: any = {
    status: 'ready',
    title: 'All Good',
    proxy: null,
    activeTunnels: [],
    proxyListeners: []
  }
  return {
    mockLogEvent: vi.fn(),
    mockSettings,
    mockSettingsSave: vi.fn(),
    mockTunStatus: { running: false },
    mockTunStop: vi.fn(async (): Promise<{ success: boolean; error?: string }> => ({ success: true })),
    mockTunStart: vi.fn(async (_opts?: any): Promise<{ success: boolean; error?: string }> => ({ success: true })),
    mockProbeTcp: vi.fn(async (_host?: string, _port?: number, _timeout?: number) => true),
    mockRoutingPlan,
    mockGetRoutingPlan: vi.fn(async () => ({ ...mockRoutingPlan })),
    mockApplyBaseline: vi.fn(async () => ({ success: true, message: 'ok' })),
    mockRollbackBaseline: vi.fn(async (_reason?: string) => ({ rolledBack: true }))
  }
})

vi.mock('./appLogger', () => ({ logEvent: mockLogEvent }))

vi.mock('./settings', () => ({
  settingsStore: {
    get: () => ({ ...mockSettings }),
    save: (patch: any) => {
      Object.assign(mockSettings, patch)
      mockSettingsSave(patch)
    }
  }
}))

vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({ ...mockTunStatus }),
    stop: () => mockTunStop(),
    start: (opts: any) => mockTunStart(opts)
  },
  probeTcp: (host: string, port: number, timeout: number) => mockProbeTcp(host, port, timeout)
}))

vi.mock('./connectionPlanner', () => ({
  getRoutingPlan: () => mockGetRoutingPlan()
}))

vi.mock('./systemNetwork', () => ({
  applyTunNetworkBaseline: () => mockApplyBaseline(),
  rollbackTunNetworkBaselineIfApplied: (reason: string) => mockRollbackBaseline(reason)
}))

vi.mock('./tunAdapter', () => ({
  TUN_ADAPTER_ALIAS: 'Ethernet 5'
}))

vi.mock('axios')
vi.mock('socks')

import {
  listenerHost,
  probeSocks5,
  probeHttp,
  verifyListener,
  pickWorkingProxy,
  runAutoPilot,
  isAutoPilotRunning
} from './autoPilot'

describe('autoPilot', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockTunStatus.running = false
    mockRoutingPlan.activeTunnels = []
    mockRoutingPlan.proxyListeners = []
    mockRoutingPlan.proxy = null
    mockSettings.autoNetworkBaseline = false
    mockTunStop.mockResolvedValue({ success: true })
    mockTunStart.mockResolvedValue({ success: true })
    mockProbeTcp.mockResolvedValue(true)
  })

  describe('listenerHost', () => {
    it('normalizes wildcards and ipv6 loopback to 127.0.0.1', () => {
      expect(listenerHost({ host: '::', port: 1080, process: 'xray', pid: 1 })).toBe('127.0.0.1')
      expect(listenerHost({ host: '::1', port: 1080, process: 'xray', pid: 1 })).toBe('127.0.0.1')
      expect(listenerHost({ host: '0.0.0.0', port: 1080, process: 'xray', pid: 1 })).toBe('127.0.0.1')
      expect(listenerHost({ host: '', port: 1080, process: 'xray', pid: 1 })).toBe('127.0.0.1')
      expect(listenerHost({ host: '192.168.1.100', port: 1080, process: 'xray', pid: 1 })).toBe('192.168.1.100')
    })
  })

  describe('probeSocks5 & probeHttp', () => {
    it('probeSocks5 destroys socket and returns true on success', async () => {
      const mockSocket = { destroy: vi.fn() }
      vi.mocked(SocksClient.createConnection).mockResolvedValueOnce({ socket: mockSocket } as any)

      const result = await probeSocks5('127.0.0.1', 10808, 1000)
      expect(result).toBe(true)
      expect(mockSocket.destroy).toHaveBeenCalled()
    })

    it('probeSocks5 returns false and cleans up on rejection', async () => {
      vi.mocked(SocksClient.createConnection).mockRejectedValueOnce(new Error('connection refused'))

      const result = await probeSocks5('127.0.0.1', 10808, 1000)
      expect(result).toBe(false)
    })

    it('probeSocks5 destroys late-connecting socket if timeout elapsed', async () => {
      let resolveConnection!: (val: any) => void
      const mockSocket = { destroy: vi.fn() }
      vi.mocked(SocksClient.createConnection).mockImplementationOnce(() => {
        return new Promise((resolve) => {
          resolveConnection = resolve
        })
      })

      const probePromise = probeSocks5('127.0.0.1', 10808, 50)
      await new Promise(r => setTimeout(r, 80))
      const result = await probePromise
      expect(result).toBe(false)

      // Late resolution arrives after timeout:
      resolveConnection({ socket: mockSocket })
      await new Promise(r => setTimeout(r, 10))
      expect(mockSocket.destroy).toHaveBeenCalled()
    })

    it('probeHttp returns true on 200 response and false on error', async () => {
      vi.mocked(axios.get).mockResolvedValueOnce({ data: { ip: '1.2.3.4' } } as any)
      expect(await probeHttp('127.0.0.1', 8080, 1000)).toBe(true)

      vi.mocked(axios.get).mockRejectedValueOnce(new Error('network error'))
      expect(await probeHttp('127.0.0.1', 8080, 1000)).toBe(false)
    })
  })

  describe('verifyListener & pickWorkingProxy', () => {
    it('returns null if TCP port is unreachable', async () => {
      mockProbeTcp.mockResolvedValueOnce(false)
      const res = await verifyListener({ host: '127.0.0.1', port: 10808, process: 'xray', pid: 100 })
      expect(res).toBeNull()
    })

    it('prioritizes socks5 for known VPN/proxy process names', async () => {
      mockProbeTcp.mockResolvedValue(true)
      const mockSocket = { destroy: vi.fn() }
      vi.mocked(SocksClient.createConnection).mockResolvedValueOnce({ socket: mockSocket } as any)

      const res = await verifyListener({ host: '127.0.0.1', port: 10808, process: 'Xray-core', pid: 100 })
      expect(res).toEqual({ host: '127.0.0.1', port: 10808, type: 'socks5' })
    })

    it('pickWorkingProxy uses verified proxy from plan if available', async () => {
      mockRoutingPlan.proxy = { host: '10.0.0.1', port: 1080, type: 'socks5', verified: true }
      const res = await pickWorkingProxy(mockRoutingPlan)
      expect(res).toEqual({ host: '10.0.0.1', port: 1080, type: 'socks5' })
    })
  })

  describe('runAutoPilot lifecycle & concurrency', () => {
    it('prevents parallel concurrent execution with a warning result', async () => {
      // Simulate a long-running plan
      mockGetRoutingPlan.mockImplementationOnce(async () => {
        await new Promise(r => setTimeout(r, 100))
        return { ...mockRoutingPlan }
      })

      const first = runAutoPilot()
      expect(isAutoPilotRunning()).toBe(true)

      const second = await runAutoPilot()
      expect(second.summary).toBe('warn')
      expect(second.title).toBe('Автопилот уже выполняется')

      await first
      expect(isAutoPilotRunning()).toBe(false)
    })

    it('stops existing VPNTE tunnel if running before applying plan', async () => {
      mockTunStatus.running = true
      mockTunStop.mockResolvedValueOnce({ success: true })

      mockRoutingPlan.proxyListeners = [{ host: '127.0.0.1', port: 10808, process: 'xray', pid: 123 }]
      const mockSocket = { destroy: vi.fn() }
      vi.mocked(SocksClient.createConnection).mockResolvedValueOnce({ socket: mockSocket } as any)

      const result = await runAutoPilot()
      expect(mockTunStop).toHaveBeenCalled()
      expect(result.steps.some(s => s.label.includes('VPNTE'))).toBe(true)
    })

    it('leaves foreign tunnel untouched without starting VPNTE', async () => {
      mockRoutingPlan.activeTunnels = [
        { name: 'WireGuard-Corp', description: 'WireGuard', address: '10.0.0.2', isVpnte: false }
      ]

      const result = await runAutoPilot()
      expect(result.mode).toBe('external')
      expect(mockTunStart).not.toHaveBeenCalled()
    })

    it('fails safely if no working proxy is found', async () => {
      mockRoutingPlan.proxyListeners = [{ host: '127.0.0.1', port: 9999, process: 'custom', pid: 123 }]
      mockProbeTcp.mockResolvedValueOnce(false)

      const result = await runAutoPilot()
      expect(result.summary).toBe('fail')
      expect(result.mode).toBe('off')
      expect(mockTunStart).not.toHaveBeenCalled()
    })

    it('applies baseline and starts Hard TUN when valid proxy is found', async () => {
      mockSettings.autoNetworkBaseline = true
      mockRoutingPlan.proxyListeners = [{ host: '127.0.0.1', port: 10808, process: 'xray', pid: 123 }]
      const mockSocket = { destroy: vi.fn() }
      vi.mocked(SocksClient.createConnection).mockResolvedValueOnce({ socket: mockSocket } as any)

      const result = await runAutoPilot()
      expect(mockApplyBaseline).toHaveBeenCalled()
      expect(mockTunStart).toHaveBeenCalledWith(expect.objectContaining({
        proxyAddr: '127.0.0.1:10808',
        proxyType: 'socks5'
      }))
      expect(result.summary).toBe('ok')
      expect(result.mode).toBe('hard')
    })

    it('rolls back baseline if TUN start fails', async () => {
      mockSettings.autoNetworkBaseline = true
      mockRoutingPlan.proxyListeners = [{ host: '127.0.0.1', port: 10808, process: 'xray', pid: 123 }]
      const mockSocket = { destroy: vi.fn() }
      vi.mocked(SocksClient.createConnection).mockResolvedValueOnce({ socket: mockSocket } as any)
      mockTunStart.mockResolvedValueOnce({ success: false, error: 'Wintun driver error' })

      const result = await runAutoPilot()
      expect(mockApplyBaseline).toHaveBeenCalled()
      expect(mockRollbackBaseline).toHaveBeenCalled()
      expect(result.summary).toBe('fail')
    })
  })
})
