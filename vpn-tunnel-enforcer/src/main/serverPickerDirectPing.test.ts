import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const serverPickerSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'serverPicker.ts'), 'utf8')

describe('serverPicker direct ping regressions', () => {
  it('tries source-bound TCP before any unbound fallback', () => {
    const source = serverPickerSource()
    const smartStart = source.indexOf('export async function smartEndpointPing')
    const directProbe = source.indexOf('physicalSourceTcpPing(host, port)', smartStart)
    const tcpProbe = source.indexOf('let tcp = await reliableTcpPing(host, port)', smartStart)

    expect(smartStart).toBeGreaterThanOrEqual(0)
    expect(directProbe).toBeGreaterThan(smartStart)
    expect(tcpProbe).toBeGreaterThan(directProbe)
  })

  it('binds TCP sockets to the physical adapter and takes repeated samples', () => {
    const source = serverPickerSource()

    expect(source).toContain('socket.connect({ port, host, ...(localAddress ? { localAddress } : {}) })')
    expect(source).toContain('Array.from({ length: TCP_PROBE_ATTEMPTS }')
    expect(source).toContain('if (physicalSourceLookup) return physicalSourceLookup')
  })

  it('uses the direct-out SOCKS inbound while TUN is active', () => {
    const source = serverPickerSource()

    expect(source).toContain('export async function pingServer(')
    expect(source).toContain('smartEndpointPing(host, port, tunnelRunning, getDirectProxyPort())')
    expect(source).toContain('reliableSocksTcpPing(')
    expect(source).not.toContain('const probes = [endpointProbe, tunnelHttpProbe')
  })

  it('uses the selected profile port for the stealth fallback', () => {
    const source = serverPickerSource()

    expect(source).toContain("'--resolve', `yandex.ru:${port}:${resolveIp}`")
    expect(source).toContain('`https://yandex.ru:${port}`')
    expect(source).not.toContain('void port')
  })

  it('binds ping.exe to a specific source IP', () => {
    const source = serverPickerSource()
    const pingFromSourceStart = source.indexOf('export async function pingFromSource')
    const bindArg = source.indexOf("'-S', sourceIp, host", pingFromSourceStart)

    expect(pingFromSourceStart).toBeGreaterThanOrEqual(0)
    expect(bindArg).toBeGreaterThan(pingFromSourceStart)
  })
})
