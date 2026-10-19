// WP-0, volume 3 §1.1: the coordinator confirms protection, never a process event.
import type { ConnectionOperation } from '../shared/operation'
import type { TunnelSnapshot, TunnelState } from '../shared/tunnel-state'

export interface TunnelEvidence { running: boolean; pid: number | null; softApplied: boolean; startedAt?: number | null }
const invalid = () => ({ success: false, code: 'FSM_INVALID_TRANSITION', category: 'conflict' } as const)

export class TunnelStateMachine {
  private current: TunnelSnapshot = {
    version: 1, revision: 0, state: 'disconnected', transition: null, health: null, mode: null,
    processState: 'stopped', proxyStatus: 'stopped', pid: null, startedAt: null, competingTun: null, cleanupRequired: false, operation: null
  }
  private faultDuringOperation = false
  private reconnectEligible = false
  private nativeGeneration = 0
  private expectedNativeGeneration: number | null = null
  private retainedSoftOperation: string | null = null
  private rotationMode: 'tun' | 'soft' | null = null
  private rotationEvidence: TunnelEvidence | null = null
  private retainedRotationOperation: string | null = null

  constructor(private readonly readEvidence: () => TunnelEvidence, private readonly onChange: (snapshot: TunnelSnapshot) => void = () => {}) {}

  get snapshot(): TunnelSnapshot {
    return { ...this.current, operation: this.current.operation ? { ...this.current.operation } : null }
  }
  canStart(): boolean { return this.current.state !== 'connected' && this.current.transition === null }
  private evidence(): TunnelEvidence | null {
    try { return this.readEvidence() } catch { return null }
  }
  canConfirmStart(): boolean {
    const e = this.evidence()
    return e !== null && !this.faultDuringOperation && ((e.running && Number.isSafeInteger(e.pid) && e.pid! > 0) || (e.softApplied && !e.running && e.pid === null))
  }
  canConfirmStop(): boolean {
    const e = this.evidence()
    return e !== null && !e.running && e.pid === null && !e.softApplied
  }
  canRotate(): boolean {
    return this.current.transition === null && (this.current.state === 'connected' || this.current.state === 'disconnected')
  }
  canConfirmRotation(): boolean {
    const e = this.evidence()
    return this.rotationMode === null ? !this.faultDuringOperation && this.canConfirmStop()
      : this.canConfirmStart() && (this.rotationMode === 'tun' ? e?.running === true : e?.softApplied === true)
  }
  confirmRetainedRotation(operationId: string) {
    if (this.current.operation?.operationId !== operationId || this.current.operation.status !== 'running'
      || this.current.operation.kind !== 'rotation' || !this.canRetainRotation()) return invalid()
    this.retainedRotationOperation = operationId
    return { success: true } as const
  }
  private canRetainRotation(): boolean {
    const e = this.evidence(), previous = this.rotationEvidence
    return !this.faultDuringOperation && !!e && !!previous && e.running === previous.running
      && e.pid === previous.pid && e.softApplied === previous.softApplied && e.startedAt === previous.startedAt
      && this.canConfirmRotation()
  }
  private canRetainSoft(): boolean {
    const e = this.evidence()
    return e !== null && !this.faultDuringOperation && e.softApplied && !e.running && e.pid === null
  }
  private commit(patch: Partial<TunnelSnapshot>): { success: true } {
    const e = this.evidence()
    this.current = { ...this.current, ...patch, revision: this.current.revision + 1,
      ...(e ? { pid: e.pid, processState: e.pid === null ? 'stopped' as const : 'running' as const,
        startedAt: e.running ? e.startedAt ?? null : null } : { state: 'unknown', mode: null, cleanupRequired: true }) }
    const nativeReady = e?.running && Number.isSafeInteger(e.pid) && e.pid! > 0
    const softReady = e?.softApplied && !e.running && e.pid === null
    if (!e || (!this.current.transition && (
      this.current.state === 'disconnected' && (e.running || e.pid !== null || e.softApplied) ||
      this.current.state === 'connected' && !(this.current.mode === 'tun' ? nativeReady : softReady)))) {
      this.faultDuringOperation = true
      this.current = { ...this.current, state: 'unknown', mode: null, cleanupRequired: true }
    }
    this.current = { ...this.current, health: this.current.state === 'connected'
      ? this.current.proxyStatus === 'proxy-down' || this.current.competingTun ? 'degraded' : 'ok' : null }
    try { this.onChange(this.snapshot) } catch { /* UI/log observers cannot strand resource cleanup. */ }
    return { success: true }
  }

  operationChanged(operation: ConnectionOperation) {
    if (operation.status === 'running') {
      if (this.current.operation?.status === 'running' && operation.kind !== 'disconnect') return invalid()
      if (operation.kind === 'rotation' && !this.canRotate()) return invalid()
      this.rotationMode = operation.kind === 'rotation' ? this.current.mode : null
      this.rotationEvidence = operation.kind === 'rotation' ? this.evidence() : null
      if (this.rotationEvidence) this.rotationEvidence = { ...this.rotationEvidence }
      this.retainedRotationOperation = null
      this.retainedSoftOperation = null
      this.faultDuringOperation = false
      this.reconnectEligible = false
      this.expectedNativeGeneration = null
      return this.commit({ operation: { ...operation }, cleanupRequired: true,
        transition: operation.kind === 'rotation' ? 'reconnecting' : operation.kind === 'connect' ? 'connecting' : 'disconnecting' })
    }
    if (this.current.operation?.operationId !== operation.operationId || this.current.operation.status !== 'running') return invalid()
    let state: TunnelState = this.current.state
    if (operation.status === 'success') state = operation.kind === 'rotation'
      ? this.canConfirmRotation() ? this.rotationMode === null ? 'disconnected' : 'connected' : 'unknown'
      : operation.kind === 'connect'
      ? this.canConfirmStart() ? 'connected' : 'unknown'
      : this.canConfirmStop() ? 'disconnected' : 'unknown'
    else if (operation.kind === 'rotation' && this.retainedRotationOperation === operation.operationId && this.canRetainRotation()) state = this.rotationMode === null ? 'disconnected' : 'connected'
    else if (operation.status === 'error' && !operation.category && this.retainedSoftOperation === operation.operationId && this.canRetainSoft()) state = 'connected'
    else if (state !== 'blocked' && state !== 'unknown') state = 'error'
    this.retainedSoftOperation = null
    this.retainedRotationOperation = null
    const e = this.evidence()
    return this.commit({ operation: { ...operation }, transition: null, state,
      mode: state === 'connected' ? e?.running ? 'tun' : 'soft' : null, cleanupRequired: state !== 'disconnected',
      proxyStatus: e?.running ? 'running' : 'stopped' })
  }

  fault(state: Extract<TunnelState, 'error' | 'blocked' | 'unknown'>) {
    this.retainedSoftOperation = null
    this.faultDuringOperation = true
    this.reconnectEligible = false
    this.expectedNativeGeneration = null
    return this.commit({ state, mode: null, cleanupRequired: true, ...(this.current.operation?.status === 'running' ? {} : { transition: null }) })
  }

  /** Main has read back the original env endpoint after a failed refresh.
   * Keep the failed action separate from the still-confirmed Soft protection. */
  confirmRetainedSoft(operationId: string) {
    if (this.current.operation?.operationId !== operationId || this.current.operation.status !== 'running'
      || this.current.operation.kind !== 'connect' || this.current.state !== 'connected' || this.current.mode !== 'soft'
      || this.current.transition !== 'connecting' || !this.canRetainSoft()) return invalid()
    this.retainedSoftOperation = operationId
    return { success: true } as const
  }

  runtimeChanged(status: string) {
    const e = this.evidence(), active = this.current.operation?.status === 'running'
    if (status === 'error' || status === 'killswitch-active') return this.fault(status === 'error' ? 'error' : 'blocked')
    if ((status === 'adapting' || status.startsWith('restarting:')) && !active) {
      if (this.current.transition !== 'reconnecting') this.expectedNativeGeneration = null
      this.reconnectEligible ||= this.current.state === 'connected'
      return this.commit({ transition: 'reconnecting', proxyStatus: e?.running ? this.current.proxyStatus : 'stopped' })
    }
    if (status === 'stopped' && !active) {
      this.reconnectEligible = false
      this.expectedNativeGeneration = null
      // A process exit alone is not a receipt for environment/network rollback.
      return this.commit({ state: 'unknown', transition: null, mode: null, proxyStatus: 'stopped', cleanupRequired: true })
    }
    if (status.startsWith('competing-tun:')) return this.commit({ competingTun: status.slice('competing-tun:'.length) })
    if (status === 'competing-tun-cleared') return this.commit({ competingTun: null })
    if (status === 'proxy-down') return this.commit({ proxyStatus: 'proxy-down' })
    if (status === 'running') return this.commit({ proxyStatus: e?.running ? 'running' : 'stopped' })
    return invalid()
  }

  nativeStartBegan(generation: number) {
    if (!Number.isSafeInteger(generation) || generation <= this.nativeGeneration) return invalid()
    this.nativeGeneration = generation
    this.expectedNativeGeneration = this.current.operation?.status !== 'running' && this.current.transition === 'reconnecting' ? generation : null
    return { success: true } as const
  }

  nativeStartFinished(result: { generation: number; success: boolean }) {
    if (this.current.operation?.status === 'running' || this.current.transition !== 'reconnecting' || result.generation !== this.expectedNativeGeneration) return invalid()
    this.expectedNativeGeneration = null
    const confirmed = result.success && this.reconnectEligible && this.canConfirmStart()
    this.reconnectEligible = false
    return this.commit({ state: confirmed ? 'connected' : result.success ? 'unknown' : 'error',
      transition: null, mode: confirmed ? 'tun' : null, proxyStatus: confirmed ? 'running' : 'stopped' })
  }
}
