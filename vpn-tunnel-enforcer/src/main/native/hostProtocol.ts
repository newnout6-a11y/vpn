// AT-07-002 / AT-08-007: messages between the main process and the native-read host (an Electron utility process).
//
// koffi calls can abort the whole process with a fatal N-API error (see the koffi.view incident), which no
// try/catch can stop. They therefore run in a separate utility process: if it dies, main survives and every
// caller falls back to PowerShell.

/** Why a native call produced no data. */
export type HostErrorKind =
  /** The host crashed, exited, timed out, could not start, or answered garbage. Caller falls back to PowerShell. */
  | 'unavailable'
  /** The read ran and refused to answer (fail-closed throws such as an empty enumeration). Caller falls back too. */
  | 'read-refused'
  /** WinINet itself returned false. Authoritative: re-thrown as WinInetCallError, never retried through PowerShell. */
  | 'wininet-false'

export class NativeHostError extends Error {
  constructor(readonly kind: HostErrorKind, message: string) {
    super(message)
    this.name = 'NativeHostError'
  }
}

export type HostOp =
  | 'adapters'
  | 'ipconfig'
  | 'routes'
  | 'physical-sources'
  | 'tunnels'
  | 'physical-snapshot'
  | 'owned-runtime-pid'
  | 'selected-route-interfaces'
  | 'wininet'
  /** Test only: implemented by nativeHostTestWorker.ts (bundled by the e2e, never shipped); the production host rejects it. */
  | 'abort-for-test'

export interface HostRequest {
  id: number
  op: HostOp
  args?: unknown
}

export type HostResponse =
  | { id: number; ok: true; value: unknown }
  | { id: number; ok: false; kind: Exclude<HostErrorKind, 'unavailable'>; message: string }

export function isHostResponse(value: unknown): value is HostResponse {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (!Number.isInteger(v.id) || typeof v.ok !== 'boolean') return false
  if (v.ok) return 'value' in v
  return (v.kind === 'read-refused' || v.kind === 'wininet-false') && typeof v.message === 'string'
}
