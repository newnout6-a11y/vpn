import { logEvent } from './appLogger'
import { redactSensitiveText } from './vpnProfiles'
import { ipMonitor } from './ipMonitor'
import { tunController, areTunRoutesActive } from './tunController'
import { runLeakSelfTest, type LeakSelfTestResult } from './leakSelfTest'
import { leakSelfTestVerdict } from '../shared/leak-self-test'

export interface IndeterminateAutoVerifyDeps {
  isRunning?: () => boolean
  /** Identity of the current connection; a reconnect during the check changes it. */
  getConnectionId?: () => unknown
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
      const isTunRunning = deps?.isRunning ?? (() => tunController.getStatus().running)
      const getConnectionId = deps?.getConnectionId ?? (() => tunController.getStatus().startedAt ?? null)
      // Bind every step to the connection that produced the candidate: after a stop/start (or a protected
      // restart) the tunnel is running again, but its IP belongs to another connection and must not be adopted.
      const connectionId = getConnectionId()
      const isRunning = () => isTunRunning() && getConnectionId() === connectionId
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

      // The same evidence gate as the UI: empty coverage, unknown probe failures
      // and malformed IPs cannot authorize adopting a new VPN baseline.
      if (leakSelfTestVerdict(leakResult) !== 'ok' || !leakResult.defaultRoutePublicIp) {
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
