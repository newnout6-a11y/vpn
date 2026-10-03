import { ipMonitor } from './ipMonitor'
import { logEvent } from './appLogger'

/** Manual and adaptive swaps share the same fresh, owner-scoped IP barrier. */
export async function withProtectedIpTransition<T extends { success: boolean }>(options: {
  reason: string
  restart: () => Promise<T>
  isCurrent: () => boolean
  isOwner?: () => boolean
  areRoutesActive: () => Promise<boolean>
  onRestarted?: () => void | Promise<void>
}): Promise<T> {
  const startedAt = Date.now()
  ipMonitor.deferResume()
  ipMonitor.invalidateVpnIpBaseline()
  try {
    const result = await options.restart()
    if (!result.success) {
      if ((options.isOwner ?? options.isCurrent)()) ipMonitor.clearVpnIp()
      return result
    }
    if (!options.isCurrent()) return result
    await options.onRestarted?.()
    for (let attempt = 1; attempt <= 3 && options.isCurrent(); attempt++) {
      const routesActive = await options.areRoutesActive().catch(() => false)
      if (!options.isCurrent()) return result
      if (!routesActive) break
      // One provider wave: never wait for the dead old server, never adopt a
      // cached IP, and never reject a valid shared egress merely for equality.
      const info = await ipMonitor.recheck(true, options.isCurrent)
      if (!options.isCurrent()) return result
      if (info.ip) {
        logEvent('info', 'ip-monitor', 'protected transition IP baseline refreshed', {
          reason: options.reason, attempt, elapsedMs: Date.now() - startedAt
        })
        return result
      }
      if (attempt < 3) await new Promise(resolve => setTimeout(resolve, 500))
    }
    if (options.isCurrent()) {
      ipMonitor.invalidateVpnIpBaseline()
      logEvent('warn', 'ip-monitor', 'protected transition IP baseline not checked', {
        reason: options.reason, elapsedMs: Date.now() - startedAt
      })
    }
    return result
  } catch (error) {
    if ((options.isOwner ?? options.isCurrent)()) ipMonitor.clearVpnIp()
    throw error
  } finally {
    // Callers serialize swaps; an obsolete owner finishes before the manual
    // owner begins, so this release cannot wake a newer transition.
    ipMonitor.releaseDeferredResume()
  }
}
