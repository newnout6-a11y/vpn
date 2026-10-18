import type { ConnectionOperation } from './operation'

/** Stable protection state, transient operation and OS process state are separate. */
export type TunnelState = 'disconnected' | 'connected' | 'error' | 'blocked' | 'unknown'
export interface TunnelSnapshot {
  readonly version: 1
  readonly revision: number
  readonly state: TunnelState
  readonly transition: 'connecting' | 'disconnecting' | 'reconnecting' | null
  readonly health: 'ok' | 'degraded' | null
  readonly mode: 'tun' | 'soft' | null
  readonly processState: 'running' | 'stopped'
  readonly proxyStatus: 'running' | 'proxy-down' | 'stopped'
  readonly pid: number | null
  readonly startedAt: number | null
  readonly competingTun: string | null
  readonly cleanupRequired: boolean
  readonly operation: ConnectionOperation | null
}
