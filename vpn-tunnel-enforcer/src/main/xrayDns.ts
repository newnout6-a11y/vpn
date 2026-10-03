import { promises as dns } from 'node:dns'
import { isIP } from 'node:net'
import { networkFailureCode } from './networkFailureDiagnostics'

function cancelled(): Error {
  return Object.assign(new Error('Xray DNS resolution cancelled'), { name: 'AbortError' })
}

// Only read-only DNS values may settle early. Native system mutations must
// retain ownership until their effect/compensation settles, not use this race.
function readWithAbort<T>(read: () => Promise<T>, signal?: AbortSignal, cancelRead?: () => void): Promise<T> {
  if (!signal) return read()
  if (signal.aborted) return Promise.reject(cancelled())
  return new Promise<T>((resolve, reject) => {
    let finished = false
    const finish = (error?: unknown, value?: T) => {
      if (finished) return
      finished = true
      signal.removeEventListener('abort', abort)
      if (error) reject(error)
      else resolve(value as T)
    }
    const abort = () => {
      if (finished) return
      try { cancelRead?.() } catch {}
      finish(cancelled())
    }
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) { abort(); return }
    // Both handlers stay attached to an uncancellable OS lookup so its late
    // completion/rejection is consumed without publication or fallback work.
    try { read().then(value => signal.aborted ? abort() : finish(undefined, value), error => finish(error)) }
    catch (error) { finish(error) }
  })
}

// Give the effective c-ares resolver a head start, then try Windows' resolver
// (including its DNS cache) without waiting through c-ares retransmissions.
export const XRAY_DNS_LOOKUP_DELAY_MS = 100

/** First valid IPv4 from bootstrap DNS, with operation-owned cancellation. */
export async function resolveXrayEndpoint(server: string, signal?: AbortSignal, report?: (details: Record<string, unknown>) => void): Promise<string | null> {
  if (signal?.aborted) throw cancelled()
  const trimmed = String(server || '').trim()
  if (!trimmed) return null
  if (isIP(trimmed) === 4) return trimmed
  if (isIP(trimmed) === 6) return null
  const reportStage = (details: Record<string, unknown>) => { try { report?.(details) } catch {} }
  const started = Date.now()
  return new Promise<string | null>((resolve, reject) => {
    const reads = new AbortController()
    let finished = false, primaryDone = false, lookupDone = false, lookupStarted = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const finish = (value: string | null, error?: Error) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      // Cancels only this operation's outstanding Resolver. Late getaddrinfo
      // results are consumed by readWithAbort, never logged or published.
      reads.abort()
      if (error) reject(error)
      else resolve(value)
    }
    const abort = () => finish(null, cancelled())
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) { abort(); return }
    const startLookup = async () => {
      if (finished || lookupStarted) return
      lookupStarted = true
      clearTimeout(timer)
      const began = Date.now()
      try {
        const lookup = await readWithAbort(() => dns.lookup(trimmed, { family: 4 }), reads.signal)
        if (finished) return
        const ok = Boolean(lookup?.address && isIP(lookup.address) === 4)
        reportStage({ method: 'system-lookup', ok, family: 4, hedged: !primaryDone,
          elapsedMs: Date.now() - began, totalElapsedMs: Date.now() - started })
        if (ok) { finish(lookup.address); return }
      } catch (error) {
        if (finished) return
        reportStage({ method: 'system-lookup', ok: false, code: networkFailureCode(error),
          elapsedMs: Date.now() - began, totalElapsedMs: Date.now() - started })
      }
      lookupDone = true
      if (primaryDone) finish(null)
    }
    const startPrimary = async () => {
      const began = Date.now()
      try {
        const resolver = new dns.Resolver()
        // Preserve effective global server overrides, without ever cancelling
        // the global resolver or another connection's DNS requests.
        resolver.setServers(dns.getServers())
        const ips = await readWithAbort(() => resolver.resolve4(trimmed), reads.signal, () => resolver.cancel())
        if (finished) return
        const ip = ips.find(address => isIP(address) === 4)
        reportStage({ method: 'resolve4', ok: Boolean(ip), answerCount: ips.length, family: 4,
          elapsedMs: Date.now() - began, totalElapsedMs: Date.now() - started })
        if (ip) { finish(ip); return }
      } catch (error) {
        if (finished) return
        reportStage({ method: 'resolve4', ok: false, code: networkFailureCode(error),
          elapsedMs: Date.now() - began, totalElapsedMs: Date.now() - started })
      }
      primaryDone = true
      if (lookupDone) finish(null)
      else void startLookup()
    }
    timer = setTimeout(() => { void startLookup() }, XRAY_DNS_LOOKUP_DELAY_MS)
    void startPrimary()
  })
}
