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

/** Same resolve4→IPv4 lookup bootstrap, with operation-owned cancellation. */
export async function resolveXrayEndpoint(server: string, signal?: AbortSignal, report?: (details: Record<string, unknown>) => void): Promise<string | null> {
  if (signal?.aborted) throw cancelled()
  const trimmed = String(server || '').trim()
  if (!trimmed) return null
  if (isIP(trimmed) === 4) return trimmed
  if (isIP(trimmed) === 6) return null
  const reportStage = (details: Record<string, unknown>) => { try { report?.(details) } catch {} }
  let began = Date.now()
  try {
    let ips: string[]
    if (signal) {
      const resolver = new dns.Resolver()
      // Preserve the effective global server list, including app overrides.
      resolver.setServers(dns.getServers())
      ips = await readWithAbort(() => resolver.resolve4(trimmed), signal, () => resolver.cancel())
    } else ips = await dns.resolve4(trimmed)
    if (signal?.aborted) throw cancelled()
    reportStage({ method: 'resolve4', ok: ips.length > 0, answerCount: ips.length, family: 4, elapsedMs: Date.now() - began })
    if (ips.length > 0 && ips[0]) return ips[0]
  } catch (error) {
    if (signal?.aborted) throw cancelled()
    reportStage({ method: 'resolve4', ok: false, code: networkFailureCode(error), elapsedMs: Date.now() - began })
  }
  began = Date.now()
  try {
    // getaddrinfo is not cancelled by Resolver.cancel. Discard its late value
    // and let the caller react immediately while the OS read finishes alone.
    const lookup = await readWithAbort(() => dns.lookup(trimmed, { family: 4 }), signal)
    if (signal?.aborted) throw cancelled()
    const ok = Boolean(lookup?.address && isIP(lookup.address) === 4)
    reportStage({ method: 'system-lookup', ok, family: 4, elapsedMs: Date.now() - began })
    if (ok) return lookup.address
  } catch (error) {
    if (signal?.aborted) throw cancelled()
    reportStage({ method: 'system-lookup', ok: false, code: networkFailureCode(error), elapsedMs: Date.now() - began })
  }
  return null
}
