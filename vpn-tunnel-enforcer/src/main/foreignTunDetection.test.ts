// AT-02-002 / AT-03-004: production preflight with synthetic interfaces; no OS/network calls.
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { connectionFailure } from '../shared/operation'
import { findForeignTun, type TunInterfaces } from './foreignTunDetection'

const address = (ip = '172.19.0.2', family: 'IPv4' | 'IPv6' = 'IPv4', internal = false) =>
  ({ address: ip, family, internal })
const source = readFileSync('src/main/tunController.ts', 'utf8')
const ast = ts.createSourceFile('tunController.ts', source, ts.ScriptTarget.Latest, true)
const declaration = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'detectForeignTun')!
const detector = declaration.getText(ast).replace(/^export /, '')
function compile(code: string, deps: Record<string, unknown>) {
  const js = ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  return new Function(...Object.keys(deps), js)(...Object.values(deps))
}
function controller(interfaces: TunInterfaces, overrides: Record<string, unknown> = {}) {
  const deps = {
    findForeignTun, networkInterfaces: vi.fn(() => interfaces), getTunAdapterAlias: () => 'VPNTE-TUN',
    TUN_IPV4_ADDRESS_CIDR: '192.168.250.253/30',
    currentStatus: { running: true, pid: 731 }, stopRequested: false, stopInProgress: false,
    ...overrides
  }
  return { deps, detect: compile(`${detector}; return detectForeignTun;`, deps) as () => string | null }
}

describe('foreign TUN classification', () => {
  it.each(['172.19.0.2', '192.168.250.2', '192.168.250.253', '10.8.0.2'])(
    'detects Happ on %s instead of claiming shared private addresses as ours', ip => {
      expect(findForeignTun({ 'happ-xray': [address(ip)] })).toBe(`happ-xray (${ip})`)
    })
  it.each(['happ-xray', 'WireGuard Tunnel', 'sing-tun', 'Corporate VPN', 'wg0'])(
    'recognizes %s with IPv6 only', name => {
      expect(findForeignTun({ [name]: [address('fd00::2', 'IPv6')] })).toBe(`${name} (fd00::2)`)
    })
  it('ignores absent and internal-only interfaces without inventing a foreign TUN', () => {
    expect(findForeignTun({ 'happ-xray': undefined, 'WireGuard Tunnel': [], 'wg0': [address('127.0.0.1', 'IPv4', true)] })).toBeNull()
  })
  it('exempts the confirmed own dual-stack adapter while still detecting Happ on the same subnet', () => {
    const own = { alias: 'VPNTE-TUN', ipv4Address: '192.168.250.253' }
    const interfaces = { 'VPNTE-TUN': [address('fdfe::1', 'IPv6'), address(own.ipv4Address)] }
    expect(findForeignTun(interfaces, own)).toBeNull()
    expect(findForeignTun({ ...interfaces, 'happ-xray': [address('192.168.250.254')] }, own))
      .toBe('happ-xray (192.168.250.254)')
  })
  it('does not exempt another alias, another exact IPv4 address, or an unproved IPv6-only adapter', () => {
    const own = { alias: 'VPNTE-TUN', ipv4Address: '192.168.250.253' }
    expect(findForeignTun({ 'happ-xray': [address(own.ipv4Address)] }, own)).toBe(`happ-xray (${own.ipv4Address})`)
    expect(findForeignTun({ 'VPNTE-TUN': [address('192.168.250.254')] }, own)).toBe('VPNTE-TUN (192.168.250.254)')
    expect(findForeignTun({ 'VPNTE-TUN': [address('fdfe::1', 'IPv6')] }, own)).toBe('VPNTE-TUN (fdfe::1)')
  })
  it.each([
    { currentStatus: { running: false, pid: 731 } },
    { currentStatus: { running: true, pid: null } },
    { currentStatus: { running: true, pid: 0 } },
    { stopRequested: true }, { stopInProgress: true }
  ])('does not use a stale/stopping controller as an ownership receipt: %j', overrides => {
    const h = controller({ 'VPNTE-TUN': [address('192.168.250.253')] }, overrides)
    expect(h.detect()).toBe('VPNTE-TUN (192.168.250.253)')
  })
  it('keeps the synchronous caller contract and reads a fresh interface snapshot each time', () => {
    const h = controller({ 'VPNTE-TUN': [address('192.168.250.253')] })
    expect(h.detect()).toBeNull()
    h.deps.networkInterfaces.mockReturnValueOnce({ 'happ-xray': [address()] })
    expect(h.detect()).toBe('happ-xray (172.19.0.2)')
    expect(h.deps.networkInterfaces).toHaveBeenCalledTimes(2)
  })
  it('refuses Happ in the actual cold preflight before admitting WFP or subsequent startup effects', async () => {
    const h = controller({ 'happ-xray': [address()] }, { currentStatus: { running: false, pid: null } })
    const begin = source.indexOf('const foreignPreflightStarted =')
    const end = source.indexOf("mark('preflight')", begin)
    expect(begin).toBeGreaterThan(0); expect(end).toBeGreaterThan(begin)
    const effects = vi.fn()
    const result = await compile(`return (async () => { ${source.slice(begin, end)}; effects(); return {success:true} })();`, {
      detectForeignTun: h.detect, phaseStart: () => 0, endPhase: vi.fn(), logEvent: vi.fn(),
      mode: 'directVpn', proxyAddr: '', proxyType: 'socks5', finishStart: (value: unknown) => value,
      connectionFailure, wantKillSwitch: true, timeAsync: effects, reserveKillSwitchIpv6Priority: effects,
      startAbortController: new AbortController(), classifyTunError: () => 'internal', effects
    })
    expect(result).toMatchObject({ success: false, category: 'conflict' })
    expect(effects).not.toHaveBeenCalled()
  })
})
