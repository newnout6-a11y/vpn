export type BootstrapRouteMode = 'auto' | 'direct' | 'localProxy'
export type BootstrapRouteKind = 'direct' | 'localProxy'
export type BootstrapProxyType = 'socks5' | 'http'

export interface BootstrapRoutePolicy {
  mode?: BootstrapRouteMode
  proxyAddr?: string | null
  proxyType?: BootstrapProxyType
  includeWellKnownLocalProxies?: boolean
}

export interface BootstrapRouteAttempt {
  id: string
  kind: BootstrapRouteKind
  label: string
  curlArgs: string[]
  proxyAddr?: string
  proxyType?: BootstrapProxyType
}

export function normalizeBootstrapProxyAddress(raw: string | null | undefined): string | null {
  const value = (raw || '').trim().replace(/^(socks5h?|https?):\/\//i, '')
  if (!value) return null
  const sep = value.lastIndexOf(':')
  if (sep <= 0) return null
  const host = value.slice(0, sep).trim()
  const port = Number(value.slice(sep + 1))
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) return null
  return `${host}:${port}`
}

export function bootstrapProxyUrl(addr: string, type: BootstrapProxyType): string {
  return type === 'http' ? `http://${addr}` : `socks5h://${addr}`
}

export function normalizeBootstrapRouteMode(value: unknown): BootstrapRouteMode {
  return value === 'direct' || value === 'localProxy' ? value : 'auto'
}

export function buildBootstrapRouteAttempts(policy: BootstrapRoutePolicy = {}): BootstrapRouteAttempt[] {
  const mode = normalizeBootstrapRouteMode(policy.mode)
  const attempts: BootstrapRouteAttempt[] = []

  if (mode === 'auto' || mode === 'direct') {
    attempts.push({
      id: 'direct',
      kind: 'direct',
      label: 'напрямую',
      curlArgs: ['--noproxy', '*']
    })
  }

  if (mode === 'auto' || mode === 'localProxy') {
    const candidates: Array<{ addr: string | null; type: BootstrapProxyType; label: string }> = [
      {
        addr: normalizeBootstrapProxyAddress(policy.proxyAddr),
        type: policy.proxyType ?? 'socks5',
        label: 'через выбранный локальный proxy'
      }
    ]

    if (policy.includeWellKnownLocalProxies !== false) {
      candidates.push(
        { addr: '127.0.0.1:10808', type: 'socks5', label: 'через Happ SOCKS 127.0.0.1:10808' },
        { addr: '127.0.0.1:10809', type: 'http', label: 'через Happ HTTP 127.0.0.1:10809' }
      )
    }

    const seen = new Set<string>()
    for (const candidate of candidates) {
      if (!candidate.addr) continue
      const key = `${candidate.type}:${candidate.addr}`
      if (seen.has(key)) continue
      seen.add(key)
      attempts.push({
        id: key,
        kind: 'localProxy',
        label: candidate.label,
        curlArgs: ['--proxy', bootstrapProxyUrl(candidate.addr, candidate.type)],
        proxyAddr: candidate.addr,
        proxyType: candidate.type
      })
    }
  }

  return attempts
}
