import axios from 'axios'

export type OutboundSlot = 'a' | 'b'
export type OutboundSwitchPhase = 'stage' | 'probe' | 'select' | 'confirm' | 'commit'
  | 'restore' | 'confirm-previous' | 'stop-candidate' | 'stop-previous' | 'ownership'
export interface OutboundSwitchFailure { phase: OutboundSwitchPhase; message: string }
export interface OutboundSwitchReceipt {
  outcome: 'success' | 'cancelled' | 'failed'
  committed: boolean
  activeSlot: OutboundSlot | null
  previousPreserved: boolean
  candidateStopped: boolean
  previousStopped: boolean
  /** The original native session or its operation owner was superseded. No teardown may target its successor. */
  ownershipLost?: true
  failures: OutboundSwitchFailure[]
}
export interface ProtectedOutboundSwitch {
  previous: OutboundSlot
  candidate: OutboundSlot
  signal: AbortSignal
  isOwner: () => boolean
  stage: (slot: OutboundSlot, signal: AbortSignal) => Promise<void>
  probe: (slot: OutboundSlot, signal: AbortSignal) => Promise<void>
  select: (slot: OutboundSlot) => Promise<void>
  confirm: (slot: OutboundSlot) => Promise<void>
  alive: (slot: OutboundSlot) => boolean
  stop: (slot: OutboundSlot) => Promise<void>
  commit: (slot: OutboundSlot) => void
}

/** Retain the working TUN and upstream until a separately staged upstream is verified. */
export async function runProtectedOutboundSwitch(options: ProtectedOutboundSwitch): Promise<OutboundSwitchReceipt> {
  const result: OutboundSwitchReceipt = { outcome: 'failed', committed: false, activeSlot: null,
    previousPreserved: false, candidateStopped: false, previousStopped: false, failures: [] }
  let phase: OutboundSwitchPhase = 'ownership'
  let staged = false
  let selected = false
  const record = (at: OutboundSwitchPhase, error: unknown) => {
    result.failures.push({ phase: at, message: error instanceof Error ? error.message : 'Outbound operation failed' })
  }
  const assertOwner = () => {
    if (!options.isOwner() || options.signal.aborted) throw new Error('Outbound switch cancelled')
  }
  const assertAlive = (slot: OutboundSlot) => {
    if (!options.alive(slot)) throw new Error(`Upstream ${slot} is no longer running`)
  }
  try {
    if (options.previous === options.candidate) throw new Error('Distinct upstream slots are required')
    assertOwner()
    assertAlive(options.previous)
    // An occupied candidate is retained for its existing owner, never overwritten or reaped.
    if (options.alive(options.candidate)) throw new Error('Candidate upstream slot is already occupied')
    phase = 'stage'
    staged = true // A rejected stage may already own a partially started child.
    await options.stage(options.candidate, options.signal)
    assertOwner(); assertAlive(options.previous); assertAlive(options.candidate)
    phase = 'probe'
    await options.probe(options.candidate, options.signal)
    assertOwner(); assertAlive(options.previous); assertAlive(options.candidate)
    phase = 'select'
    selected = true // PUT can take effect even when its response/readback fails.
    await options.select(options.candidate)
    assertOwner(); assertAlive(options.previous); assertAlive(options.candidate)
    phase = 'confirm'
    await options.confirm(options.candidate)
    assertOwner(); assertAlive(options.previous); assertAlive(options.candidate)
    phase = 'commit'
    options.commit(options.candidate)
    result.committed = true
    result.activeSlot = options.candidate
  } catch (error) {
    record(phase, error)
  }

  if (result.committed) {
    // The old slot remains owned if exit cannot be confirmed; do not roll back a published selection.
    try {
      await options.stop(options.previous)
      if (options.alive(options.previous)) throw new Error('Previous upstream exit was not confirmed')
      result.previousStopped = true
    } catch (error) { record('stop-previous', error) }
    if (!options.isOwner() || options.signal.aborted) {
      result.outcome = 'cancelled'
      result.activeSlot = null
    } else {
      result.outcome = result.previousStopped && options.alive(options.candidate) ? 'success' : 'failed'
      if (!options.alive(options.candidate)) {
        result.activeSlot = null
        record('ownership', new Error('Committed upstream is no longer running'))
      }
    }
    return result
  }

  let restored = !selected
  if (selected && options.isOwner()) {
    try {
      assertAlive(options.previous)
      await options.select(options.previous)
      if (!options.isOwner()) throw new Error('Outbound switch superseded during restoration')
      restored = true
    } catch (error) { record('restore', error) }
  }
  if (staged) {
    try {
      await options.stop(options.candidate)
      if (options.alive(options.candidate)) throw new Error('Candidate upstream exit was not confirmed')
      result.candidateStopped = true
    } catch (error) { record('stop-candidate', error) }
  } else {
    // No stage was dispatched, so this owner has no candidate child to drain.
    result.candidateStopped = !options.alive(options.candidate)
  }
  if (restored && result.candidateStopped && options.isOwner() && options.previous !== options.candidate) {
    try {
      assertAlive(options.previous)
      await options.confirm(options.previous)
      if (!options.isOwner()) throw new Error('Outbound switch superseded during verification')
      assertAlive(options.previous)
      result.previousPreserved = true
      result.activeSlot = options.previous
    } catch (error) { record('confirm-previous', error) }
  }
  result.outcome = !options.isOwner() || options.signal.aborted ? 'cancelled' : 'failed'
  return result
}

/** The controller is loopback-only and token authenticated; redirects and environment proxies are forbidden. */
export async function selectProtectedOutbound(api: { port: number; secret: string }, slot: OutboundSlot): Promise<void> {
  if (!Number.isInteger(api.port) || api.port < 1 || api.port > 65535 || !/^[a-f0-9]{32}$/i.test(api.secret)
      || (slot !== 'a' && slot !== 'b')) throw new Error('Invalid protected outbound controller')
  const name = `vpnte-upstream-${slot}`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 1000)
  const config = { proxy: false as const, maxRedirects: 0, timeout: 1000, signal: controller.signal,
    headers: { Authorization: `Bearer ${api.secret}` }, maxContentLength: 16384, maxBodyLength: 1024 }
  const url = `http://127.0.0.1:${api.port}/proxies/proxy-out`
  try {
    const written = await axios.put(url, { name }, config)
    if (written.status !== 204 && written.status !== 200) throw new Error('Selector update rejected')
    const read = await axios.get<unknown>(url, config)
    const state = read.data as { type?: unknown; now?: unknown; all?: unknown } | null
    if (read.status !== 200 || !state || typeof state !== 'object' || Array.isArray(state)
        || state.type !== 'Selector' || state.now !== name || !Array.isArray(state.all)
        || state.all.length !== 2 || new Set(state.all).size !== 2
        || !state.all.includes('vpnte-upstream-a') || !state.all.includes('vpnte-upstream-b')) {
      throw new Error('Selector readback rejected')
    }
  } catch {
    // Axios errors include request headers; never propagate the controller secret through diagnostics.
    throw new Error('Protected outbound selection was not confirmed')
  } finally { clearTimeout(timer) }
}
