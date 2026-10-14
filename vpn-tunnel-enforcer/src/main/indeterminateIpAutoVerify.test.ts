import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
import {
  executeIndeterminateVpnIpAutoVerify,
  resetIndeterminateAutoVerifyInFlightForTest
} from './indeterminateIpAutoVerify'

vi.mock('axios')
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { logEvent } from './appLogger'

const cleanLeakResult = (ip: string) => ({
  ts: Date.now(),
  physicalAdapterInspectionComplete: true,
  physicalAdapterReached: false,
  publicIpMismatch: false,
  dnsLeakDetected: false,
  defaultRoutePublicIp: ip,
  perAdapter: [],
  summary: 'OK'
})

describe('indeterminate IP auto-verification (AT-07-001 / AT-07-005 / AT-07-006)', () => {
  beforeEach(() => {
    resetIndeterminateAutoVerifyInFlightForTest()
  })

  describe('behavioral execution and safety gates', () => {
    it('successfully adopts verified VPN IP baseline when leak test is completely clean and matches recheck', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn().mockResolvedValue({
        ip: '13.143.214.3',
        isLeak: false,
        vpnIp: '13.143.214.3'
      })

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => ({
          ts: Date.now(),
          physicalAdapterInspectionComplete: true,
          physicalAdapterReached: false,
          publicIpMismatch: false,
          dnsLeakDetected: false,
          defaultRoutePublicIp: '13.143.214.3',
          perAdapter: [],
          summary: 'OK'
        }),
        recheck,
        onVerified
      })

      expect(recheck).toHaveBeenCalledWith(true, expect.any(Function), '13.143.214.3')
      expect(onVerified).toHaveBeenCalledWith('13.143.214.3', false)
    })

    it('rejects rebaseline when physical adapter inspection is incomplete', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn()

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => ({
          ts: Date.now(),
          physicalAdapterInspectionComplete: false,
          physicalAdapterReached: false,
          publicIpMismatch: false,
          dnsLeakDetected: false,
          defaultRoutePublicIp: '13.143.214.3',
          perAdapter: [],
          summary: 'Не удалось перечислить физические адаптеры'
        }),
        recheck,
        onVerified
      })

      expect(recheck).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('rejects rebaseline when physical adapter was reached (leak detected)', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn()

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => ({
          ts: Date.now(),
          physicalAdapterInspectionComplete: true,
          physicalAdapterReached: true,
          publicIpMismatch: false,
          dnsLeakDetected: false,
          defaultRoutePublicIp: '13.143.214.3',
          perAdapter: [],
          summary: 'УТЕЧКА: физический адаптер доступен'
        }),
        recheck,
        onVerified
      })

      expect(recheck).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('rejects rebaseline when public IP mismatch is detected', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn()

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => ({
          ts: Date.now(),
          physicalAdapterInspectionComplete: true,
          physicalAdapterReached: false,
          publicIpMismatch: true,
          dnsLeakDetected: false,
          defaultRoutePublicIp: '13.143.214.3',
          perAdapter: [],
          summary: 'УТЕЧКА: IP расходятся'
        }),
        recheck,
        onVerified
      })

      expect(recheck).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('rejects rebaseline when DNS leak is detected', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn()

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => ({
          ts: Date.now(),
          physicalAdapterInspectionComplete: true,
          physicalAdapterReached: false,
          publicIpMismatch: false,
          dnsLeakDetected: true,
          defaultRoutePublicIp: '13.143.214.3',
          perAdapter: [],
          summary: 'УТЕЧКА DNS'
        }),
        recheck,
        onVerified
      })

      expect(recheck).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('rejects rebaseline when TUN routes drop after leak test before recheck', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn()
      let callCount = 0

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => {
          callCount++
          return callCount === 1 // Route active before leak test, drops right after
        },
        runLeakTest: async () => ({
          ts: Date.now(),
          physicalAdapterInspectionComplete: true,
          physicalAdapterReached: false,
          publicIpMismatch: false,
          dnsLeakDetected: false,
          defaultRoutePublicIp: '13.143.214.3',
          perAdapter: [],
          summary: 'OK'
        }),
        recheck,
        onVerified
      })

      expect(recheck).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('rejects adoption when fresh recheck sample mismatches leak-verified IP', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn().mockResolvedValue({
        ip: '198.51.100.99',
        isLeak: false,
        vpnIp: '198.51.100.1' // not adopted
      })

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => ({
          ts: Date.now(),
          physicalAdapterInspectionComplete: true,
          physicalAdapterReached: false,
          publicIpMismatch: false,
          dnsLeakDetected: false,
          defaultRoutePublicIp: '13.143.214.3',
          perAdapter: [],
          summary: 'OK'
        }),
        recheck,
        onVerified
      })

      expect(recheck).toHaveBeenCalledWith(true, expect.any(Function), '13.143.214.3')
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('does not adopt the IP when the connection is replaced during the leak test (AT-07-005)', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn()
      let connection = 1

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getConnectionId: () => connection,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => {
          connection = 2 // reconnect: running again, but a different connection
          return cleanLeakResult('13.143.214.3')
        },
        recheck,
        onVerified
      })

      expect(recheck).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('binds the final recheck to the connection that produced the candidate (AT-07-005)', async () => {
      const onVerified = vi.fn()
      let connection = 1
      let publishAllowed: boolean | undefined
      const recheck = vi.fn(async (_rebaseline: boolean, canPublish?: () => boolean) => {
        connection = 2 // reconnect while the fresh sample is being taken
        publishAllowed = canPublish?.()
        return { ip: '13.143.214.3', isLeak: false, vpnIp: '13.143.214.3' }
      })

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getConnectionId: () => connection,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => cleanLeakResult('13.143.214.3'),
        recheck,
        onVerified
      })

      expect(recheck).toHaveBeenCalledTimes(1)
      expect(publishAllowed).toBe(false)
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('logs the candidate and verified public IPs in the clear', async () => {
      vi.mocked(logEvent).mockClear()
      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => cleanLeakResult('13.143.214.4'),
        recheck: async () => ({ ip: '13.143.214.4', isLeak: false, vpnIp: '13.143.214.4' })
      })
      const adopted = vi.mocked(logEvent).mock.calls.find(([, , message]) => String(message).includes('adopting verified VPN IP'))
      expect(adopted?.[3]).toMatchObject({ candidateIp: '13.143.214.3', verifiedIp: '13.143.214.4' })
    })

    it('aborts when TUN stops running during verification', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn()
      let running = true

      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => running,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest: async () => {
          running = false
          return {
            ts: Date.now(),
            physicalAdapterInspectionComplete: true,
            physicalAdapterReached: false,
            publicIpMismatch: false,
            dnsLeakDetected: false,
            defaultRoutePublicIp: '13.143.214.3',
            perAdapter: [],
            summary: 'OK'
          }
        },
        recheck,
        onVerified
      })

      expect(recheck).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()
    })

    it('does not latch in-flight guard when returning early on non-indeterminate verdict and allows subsequent verification', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn().mockResolvedValue({
        ip: '13.143.214.3',
        isLeak: false,
        vpnIp: '13.143.214.3'
      })
      const runLeakTest = vi.fn().mockResolvedValue({
        ts: Date.now(),
        physicalAdapterInspectionComplete: true,
        physicalAdapterReached: false,
        publicIpMismatch: false,
        dnsLeakDetected: false,
        defaultRoutePublicIp: '13.143.214.3',
        perAdapter: [],
        summary: 'OK'
      })

      let currentVerdict = 'passed'

      // First call: verdict is 'passed' -> returns early synchronously
      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => currentVerdict,
        areRoutesActive: async () => true,
        runLeakTest,
        recheck,
        onVerified
      })
      expect(runLeakTest).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()

      // Verdict transitions to 'indeterminate'
      currentVerdict = 'indeterminate'

      // Second call: must not be latched by the earlier synchronous return
      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => true,
        getVerdict: () => currentVerdict,
        areRoutesActive: async () => true,
        runLeakTest,
        recheck,
        onVerified
      })
      expect(runLeakTest).toHaveBeenCalledTimes(1)
      expect(onVerified).toHaveBeenCalledWith('13.143.214.3', false)
    })

    it('does not latch in-flight guard when returning early while TUN is not running and allows subsequent verification', async () => {
      const onVerified = vi.fn()
      const recheck = vi.fn().mockResolvedValue({
        ip: '13.143.214.3',
        isLeak: false,
        vpnIp: '13.143.214.3'
      })
      const runLeakTest = vi.fn().mockResolvedValue({
        ts: Date.now(),
        physicalAdapterInspectionComplete: true,
        physicalAdapterReached: false,
        publicIpMismatch: false,
        dnsLeakDetected: false,
        defaultRoutePublicIp: '13.143.214.3',
        perAdapter: [],
        summary: 'OK'
      })

      let isTunRunning = false

      // First call: TUN not running -> returns early synchronously
      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => isTunRunning,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest,
        recheck,
        onVerified
      })
      expect(runLeakTest).not.toHaveBeenCalled()
      expect(onVerified).not.toHaveBeenCalled()

      // TUN starts running
      isTunRunning = true

      // Second call: must execute verification cleanly
      await executeIndeterminateVpnIpAutoVerify('13.143.214.3', {
        isRunning: () => isTunRunning,
        getVerdict: () => 'indeterminate',
        areRoutesActive: async () => true,
        runLeakTest,
        recheck,
        onVerified
      })
      expect(runLeakTest).toHaveBeenCalledTimes(1)
      expect(onVerified).toHaveBeenCalledWith('13.143.214.3', false)
    })
  })

  describe('contract and wiring', () => {
    it('exports executeIndeterminateVpnIpAutoVerify with callable contracts', () => {
      expect(typeof executeIndeterminateVpnIpAutoVerify).toBe('function')
      expect(typeof resetIndeterminateAutoVerifyInFlightForTest).toBe('function')
    })
  })

  describe('ipMonitor state transitions with expected baseline validation', () => {
    let monitor: typeof import('./ipMonitor').ipMonitor

    beforeEach(async () => {
      vi.resetModules()
      vi.useFakeTimers()
      vi.mocked(axios.get).mockReset().mockResolvedValue({ data: '198.51.100.1' })
      monitor = (await import('./ipMonitor')).ipMonitor
      await monitor.recheck(true)
    })

    afterEach(() => {
      monitor.clearVpnIp()
      vi.clearAllTimers()
      vi.useRealTimers()
    })

    it('rejects baseline adoption when recheck returns an IP mismatching expectedIp', async () => {
      // IP shifts to 13.143.214.3 -> observeIp sets indeterminate
      vi.mocked(axios.get).mockResolvedValue({ data: '13.143.214.3' })
      await vi.advanceTimersByTimeAsync(30000)
      expect(monitor.getEvidence()).toEqual({ vpnIp: '198.51.100.1', verdict: 'indeterminate' })

      // Network returns 198.51.100.88 during recheck, but expectedIp was 13.143.214.3
      vi.mocked(axios.get).mockResolvedValue({ data: '198.51.100.88' })
      const recheckResult = await monitor.recheck(true, undefined, '13.143.214.3')

      expect(recheckResult.ip).toBe('198.51.100.88')
      expect(recheckResult.vpnIp).toBe('198.51.100.1') // not adopted
      expect(monitor.getEvidence()).toEqual({ vpnIp: '198.51.100.1', verdict: 'indeterminate' })
    })

    it('transitions indeterminate verdict to passed when recheck(true, undefined, expectedIp) matches', async () => {
      // 1. IP shifts to 13.143.214.3 -> observeIp sets indeterminate
      vi.mocked(axios.get).mockResolvedValue({ data: '13.143.214.3' })
      const callbackEvents: any[] = []
      monitor.onIpChange((ip, isLeak, evidence) => {
        callbackEvents.push({ ip, isLeak, ...evidence })
      })

      await vi.advanceTimersByTimeAsync(30000)
      expect(monitor.getEvidence()).toEqual({ vpnIp: '198.51.100.1', verdict: 'indeterminate' })
      expect(callbackEvents).toContainEqual({
        ip: '13.143.214.3',
        isLeak: false,
        vpnIp: '198.51.100.1',
        verdict: 'indeterminate'
      })

      // 2. Auto-verification completes and calls monitor.recheck(true, undefined, '13.143.214.3')
      const recheckResult = await monitor.recheck(true, undefined, '13.143.214.3')
      expect(recheckResult.ip).toBe('13.143.214.3')
      expect(monitor.getEvidence()).toEqual({ vpnIp: '13.143.214.3', verdict: 'passed' })
      expect(callbackEvents[callbackEvents.length - 1]).toEqual({
        ip: '13.143.214.3',
        isLeak: false,
        vpnIp: '13.143.214.3',
        verdict: 'passed'
      })
    })
  })
})
