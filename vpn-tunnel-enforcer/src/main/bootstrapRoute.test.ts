import { describe, expect, it } from 'vitest'
import {
  buildBootstrapRouteAttempts,
  normalizeBootstrapProxyAddress,
  normalizeBootstrapRouteMode
} from './bootstrapRoute'

describe('bootstrapRoute', () => {
  it('normalizes supported route modes', () => {
    expect(normalizeBootstrapRouteMode('direct')).toBe('direct')
    expect(normalizeBootstrapRouteMode('localProxy')).toBe('localProxy')
    expect(normalizeBootstrapRouteMode('unknown')).toBe('auto')
    expect(normalizeBootstrapRouteMode(undefined)).toBe('auto')
  })

  it('normalizes local proxy addresses with optional schemes', () => {
    expect(normalizeBootstrapProxyAddress('socks5h://127.0.0.1:10808')).toBe('127.0.0.1:10808')
    expect(normalizeBootstrapProxyAddress('http://localhost:8080')).toBe('localhost:8080')
    expect(normalizeBootstrapProxyAddress('bad-port')).toBeNull()
    expect(normalizeBootstrapProxyAddress('127.0.0.1:99999')).toBeNull()
  })

  it('builds auto attempts as direct first, then deduped local proxies', () => {
    const attempts = buildBootstrapRouteAttempts({
      mode: 'auto',
      proxyAddr: 'socks5://127.0.0.1:10808',
      proxyType: 'socks5'
    })

    expect(attempts.map((attempt) => attempt.kind)).toEqual(['direct', 'localProxy', 'localProxy'])
    expect(attempts[0].curlArgs).toEqual(['--noproxy', '*'])
    expect(attempts[1].curlArgs).toEqual(['--proxy', 'socks5h://127.0.0.1:10808'])
    expect(attempts[2].curlArgs).toEqual(['--proxy', 'http://127.0.0.1:10809'])
  })

  it('can force direct-only or local-proxy-only control-plane downloads', () => {
    expect(buildBootstrapRouteAttempts({ mode: 'direct', proxyAddr: '127.0.0.1:10808' }).map((a) => a.kind))
      .toEqual(['direct'])

    expect(buildBootstrapRouteAttempts({ mode: 'localProxy', proxyAddr: '' }).map((a) => a.kind))
      .toEqual(['localProxy', 'localProxy'])
  })
})
