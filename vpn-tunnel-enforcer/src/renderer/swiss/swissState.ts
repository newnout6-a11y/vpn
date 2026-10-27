/** Which big word the «Пломба» slab shows. Deliberately Latin in every locale (see dashboard.swissWord* keys). */
export type SwissState =
  | 'cancel' | 'switch' | 'linking' | 'closing' | 'restart'
  | 'leak' | 'alert' | 'blocked' | 'degraded'
  | 'verify' | 'secure' | 'exposed'

export interface SwissStateInput {
  cancelling: boolean
  switching: boolean
  connecting: boolean
  disconnecting: boolean
  restarting: boolean
  connected: boolean
  /** A visible leak verdict (already suppressed during server switches). */
  leak: boolean
  tunnelState: string | null
  /** Connected but the proxy answers nothing: traffic is blocked. */
  proxyDown: boolean
  /** Snapshot health is degraded, or another TUN competes with ours. */
  degraded: boolean
  verdict: string | null
}

/**
 * Precedence: user-started transitions first (cancel > switch > linking >
 * closing > restart), then hazards (leak > alert > blocked > degraded), then
 * verification. SECURE needs a connected, healthy tunnel with a passed IP check.
 */
export function deriveSwissState(i: SwissStateInput): SwissState {
  if (i.cancelling) return 'cancel'
  if (i.switching) return 'switch'
  if (i.connecting) return 'linking'
  if (i.disconnecting) return 'closing'
  if (i.restarting) return 'restart'
  if (i.connected && i.leak) return 'leak'
  if (i.tunnelState === 'error' || i.tunnelState === 'blocked' || i.tunnelState === 'unknown') return 'alert'
  if (i.connected && i.proxyDown) return 'blocked'
  if (i.connected && i.degraded) return 'degraded'
  if (i.connected && i.verdict !== 'passed') return 'verify'
  if (i.connected) return 'secure'
  return 'exposed'
}
