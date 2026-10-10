import { logEvent } from './appLogger'
import { redactSensitiveText } from './vpnProfiles'
import { ipMonitor } from './ipMonitor'
import { tunController, areTunRoutesActive } from './tunController'
import { runLeakSelfTest, type LeakSelfTestResult } from './leakSelfTest'

export interface IndeterminateAutoVerifyDeps {
  isRunning?: () => boolean
  getVerdict?: () => string
  areRoutesActive?: () => Promise<boolean>
  runLeakTest?: () => Promise<LeakSelfTestResult>
  recheck?: (
    rebaseline: boolean,
    canPublish?: () => boolean,
    expectedIp?: string
  ) => Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }>
  onVerified?: (verifiedIp: string, isLeak: boolean) => Promise<void> | void
}

let indeterminateVerificationInFlight: Promise<void> | null = null

export function resetIndeterminateAutoVerifyInFlightForTest(): void {
  indeterminateVerificationInFlight = null
}

export async function executeIndeterminateVpnIpAutoVerify(
  candidateIp: string,
  deps?: IndeterminateAutoVerifyDeps
): Promise<void> {
  if (indeterminateVerificationInFlight) return indeterminateVerificationInFlight
  const run = (async () => {
    try {
      const isRunning = deps?.isRunning ?? (() => tunController.getStatus().running)
      const getVerdict = deps?.getVerdict ?? (() => ipMonitor.getEvidence().verdict)
      const areRoutesActiveFn = deps?.areRoutesActive ?? areTunRoutesActive
      const runLeakTestFn = deps?.runLeakTest ?? runLeakSelfTest
      const recheckFn = deps?.recheck ?? ipMonitor.recheck

      if (!isRunning()) return
      if (getVerdict() !== 'indeterminate') return

      const routesActive = await areRoutesActiveFn().catch(() => false)
      if (!routesActive || !isRunning()) return

      logEvent('info', 'ip-monitor', 'auto-verifying indeterminate VPN IP via leak self-test', {
        candidateIp: redactSensitiveText(candidateIp)
      })
      const leakResult = await runLeakTestFn()
      if (!isRunning()) return

      // Strict safety gate: NEVER rebaseline if physical adapter inspection was incomplete,
      // physical adapter was reached, mismatch detected, DNS leak detected, or default route IP missing.
      if (
        !leakResult.physicalAdapterInspectionComplete ||
        leakResult.physicalAdapterReached ||
        leakResult.publicIpMismatch ||
        leakResult.dnsLeakDetected ||
        !leakResult.defaultRoutePublicIp
      ) {
        logEvent('warn', 'ip-monitor', 'indeterminate IP verification failed leak self-test safety gate', {
          candidateIp: redactSensitiveText(candidateIp),
          physicalAdapterInspectionComplete: leakResult.physicalAdapterInspectionComplete,
          physicalAdapterReached: leakResult.physicalAdapterReached,
          publicIpMismatch: leakResult.publicIpMismatch,
          dnsLeakDetected: leakResult.dnsLeakDetected,
          defaultRoutePublicIp: redactSensitiveText(leakResult.defaultRoutePublicIp || '')
        })
        return
      }

      // Re-verify route ownership after the leak self-test before attempting rebaseline.
      const routesStillActive = await areRoutesActiveFn().catch(() => false)
      if (!routesStillActive || !isRunning()) {
        logEvent('warn', 'ip-monitor', 'TUN routes no longer active after leak self-test; aborting rebaseline', {
          candidateIp: redactSensitiveText(candidateIp)
        })
        return
      }

      const verifiedIp = leakResult.defaultRoutePublicIp
      logEvent('info', 'ip-monitor', 'indeterminate IP verified clean by leak self-test; adopting verified VPN IP baseline', {
        oldVpnIp: redactSensitiveText(ipMonitor.getEvidence().vpnIp || ''),
        verifiedIp: redactSensitiveText(verifiedIp),
        candidateIp: redactSensitiveText(candidateIp)
      })

      const recheckInfo = await recheckFn(true, isRunning, verifiedIp)
      if (recheckInfo.ip !== verifiedIp || recheckInfo.vpnIp !== verifiedIp || !isRunning()) {
        logEvent('warn', 'ip-monitor', 'indeterminate IP rebaseline sample mismatch; rejecting adoption', {
          candidateIp: redactSensitiveText(candidateIp),
          verifiedIp: redactSensitiveText(verifiedIp),
          recheckIp: redactSensitiveText(recheckInfo.ip || ''),
          recheckVpnIp: redactSensitiveText(recheckInfo.vpnIp || '')
        })
        return
      }

      if (deps?.onVerified) {
        await deps.onVerified(verifiedIp, recheckInfo.isLeak)
      }
    } catch (err: any) {
      logEvent('warn', 'ip-monitor', 'indeterminate IP auto-verification error', {
        error: redactSensitiveText(err?.message || String(err))
      })
    }
  })().finally(() => {
    if (indeterminateVerificationInFlight === run) {
      indeterminateVerificationInFlight = null
    }
  })

  indeterminateVerificationInFlight = run
  return run
}
