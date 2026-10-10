import { readFileSync } from 'fs'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'

vi.mock('axios')
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

const mainIndexSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'index.ts'), 'utf8')
const leakSelfTestSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'leakSelfTest.ts'), 'utf8')

describe('indeterminate IP auto-verification (AT-07-001 / AT-07-005 / AT-07-006)', () => {
  it('wires automatic verification and rebaseline without requiring manual button click', () => {
    const source = mainIndexSource()

    // 1. verifyIndeterminateVpnIp function exists
    expect(source).toContain('async function verifyIndeterminateVpnIp(candidateIp: string)')

    // 2. Guards: requires running TUN, indeterminate verdict, and active TUN routes
    expect(source).toContain('if (!tunController.getStatus().running) return')
    expect(source).toContain("if (ipMonitor.getEvidence().verdict !== 'indeterminate') return")
    expect(source).toContain('const routesActive = await areTunRoutesActive().catch(() => false)')

    // 3. Runs active leak self-test as authoritative safety proof
    expect(source).toContain('const leakResult = await runLeakSelfTest()')

    // 4. Strict safety gate: never rebaseline if physical adapter reached or leak detected
    expect(source).toContain('leakResult.physicalAdapterReached')
    expect(source).toContain('leakResult.publicIpMismatch')
    expect(source).toContain('leakResult.dnsLeakDetected')
    expect(source).toContain('!leakResult.defaultRoutePublicIp')

    // 5. Calls recheck(true) to adopt verified VPN IP and clear warning to passed
    expect(source).toContain('const recheckInfo = await ipMonitor.recheck(true, isStillRunning)')

    // 6. onIpChange triggers verifyIndeterminateVpnIp automatically
    expect(source).toContain("else if (evidence.verdict === 'indeterminate' && tunController.getStatus().running)")
    expect(source).toContain('void verifyIndeterminateVpnIp(ip)')

    // 7. Periodic leak test completion callback triggers re-verification on clean probe
    expect(source).toContain('setLeakSelfTestCompletedCallback((r) => {')
    expect(source).toContain("if (tunController.getStatus().running && ipMonitor.getEvidence().verdict === 'indeterminate')")
  })

  it('leakSelfTest notifies completed callback on zero-leak clean probes', () => {
    const source = leakSelfTestSource()
    expect(source).toContain('export function setLeakSelfTestCompletedCallback')
    expect(source).toContain('onLeakSelfTestCompletedCb?.(r)')
  })

  describe('ipMonitor state transitions with clean rebaseline', () => {
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

    it('transitions indeterminate verdict to passed when recheck(true) is invoked', async () => {
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

      // 2. Auto-verification completes and calls monitor.recheck(true)
      const recheckResult = await monitor.recheck(true)
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
