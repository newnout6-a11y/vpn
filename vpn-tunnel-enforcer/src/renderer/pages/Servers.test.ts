import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { displayedServerPing, hasSuccessfulRowPing, profileStealthBadge } from './Servers'
import type { ServerProfile } from '../../shared/ipc-types'

describe('profile JSON transport fields (AT-00-001)', () => {
  const badge = (outbound: ServerProfile['outbound'], protocol = 'vless') => profileStealthBadge({
    id: 'json', name: 'JSON', server: 'vpn.example.test', port: 443, status: 'unknown', protocol, outbound
  })?.label

  it.each([
    [{ tls: { enabled: true, ech: { config: ['config'] } } }, 'ECH'],
    [{ tls: { enabled: true, reality: { enabled: true } } }, 'Reality'],
    [{ tls: { enabled: true, utls: { enabled: true, fingerprint: 'chrome' } } }, 'uTLS'],
    [{ tls: { enabled: true } }, 'TLS'],
    [{ tls: { enabled: false } }, 'Plain'],
    [{ tls: { reality: [], utls: [], ech: [] } }, 'TLS'],
    [{ tls: [] }, 'Plain'],
    [{ tls: 'invalid' }, 'Plain']
  ] satisfies Array<[ServerProfile['outbound'], string]>)('preserves configured badges and ignores malformed containers: %j', (outbound, label) => {
    expect(badge(outbound)).toBe(label)
  })

  it('keeps protocol fallback and does not claim OBFS for an array', () => {
    expect(badge({ type: 'naive' }, '')).toBe('Naive')
    expect(badge({ type: { invalid: true } }, '')).toBeUndefined()
    expect(badge({ obfs: { type: 'salamander', password: 'fixture' } }, 'hysteria2')).toBe('OBFS')
    expect(badge({ obfs: [] }, 'hysteria2')).toBeUndefined()
  })
})

const source = readFileSync(join(process.cwd(), 'src/renderer/pages/Servers.tsx'), 'utf8')

describe('displayedServerPing', () => {
  it('uses per-row server ping when present', () => {
    expect(displayedServerPing({ ping: 120 }, { ping: 80 })).toBe(80)
  })

  it('falls back to persisted profile ping', () => {
    expect(displayedServerPing({ ping: 120 })).toBe(120)
  })

  it('never receives or displays health-check latency', () => {
    const healthLatencyThatMustNotBeShown = 3
    expect(displayedServerPing({ ping: 120 }, { ping: null })).not.toBe(healthLatencyThatMustNotBeShown)
    expect(displayedServerPing({ ping: 120 }, { ping: null })).toBe(120)
  })
})

describe('hasSuccessfulRowPing', () => {
  it('treats a completed numeric ping as fresher than a cached health failure', () => {
    expect(hasSuccessfulRowPing({ ping: 105, loading: false })).toBe(true)
  })

  it('does not hide an error while the direct ping is still running or failed', () => {
    expect(hasSuccessfulRowPing({ ping: 105, loading: true })).toBe(false)
    expect(hasSuccessfulRowPing({ ping: null, loading: false })).toBe(false)
  })
})

describe('server page ping wiring', () => {
  it('uses the same ping IPC as the dashboard for per-row pings', () => {
    expect(source).toContain('const ping = await window.electronAPI.serversPingOne(host, port)')
    expect(source).not.toContain('const probe = await window.electronAPI.serverProbe(host, port)')
  })

  it('pings rows directly while the tunnel is running instead of relying on persisted pingAll', () => {
    expect(source).toContain('if (tunRunning) {')
    expect(source).toContain('await pingRow(profile.id, profile.server, profile.port)')
  })

  it('clears an obsolete health result when a direct ping succeeds', () => {
    expect(source).toContain('const { [rowKey]: _staleHealth, ...next } = prev')
    expect(source).toContain('const hasFreshPingSuccess = hasSuccessfulRowPing(perRowPing)')
  })
})

describe('subscription refresh frequency control', () => {
  it('uses the compact in-app select instead of the native white-popup select', () => {
    expect(source).toContain('<MacSelect')
    expect(source).toContain('size="sm"')
    expect(source).toContain('className="w-[96px] shrink-0"')
    expect(source).toContain('onOpenChange={setRefreshSelectOpen}')
    expect(source).toContain("refreshSelectOpen ? 'overflow-visible' : 'overflow-hidden'")
    expect(source).not.toContain('<select')
    for (const value of ['auto', '1', '5', '15', '30', '60', '360', '1440']) {
      expect(source).toContain(`value: '${value}'`)
    }
  })
})

describe('server selection error notification', () => {
  it('notifies user via addGlobalToast when server selection fails', () => {
    expect(source).toContain("addGlobalToast(")
    expect(source).toContain("'Не удалось выбрать сервер'")
  })
})

describe('verified exit IP display', () => {
  it('renders verified exit IP when countryVerifiedIp or egressIp is present', () => {
    expect(source).toContain('profile.countryVerifiedIp || profile.egressIp')
    expect(source).toContain('Выход: {profile.countryVerifiedIp || profile.egressIp}')
  })
})

