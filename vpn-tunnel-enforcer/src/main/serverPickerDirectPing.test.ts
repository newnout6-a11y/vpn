import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const serverPickerSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'serverPicker.ts'), 'utf8')

describe('serverPicker direct ping regressions', () => {
  it('tries a physical IPv4 source before the old offline ladder', () => {
    const source = serverPickerSource()
    const smartStart = source.indexOf('export async function smartOfflinePing')
    const directProbe = source.indexOf('const directPhysical = await physicalSourcePing(host)', smartStart)
    const tcpProbe = source.indexOf('let tcp = await plainTcpPing(host, port)', smartStart)

    expect(smartStart).toBeGreaterThanOrEqual(0)
    expect(directProbe).toBeGreaterThan(smartStart)
    expect(tcpProbe).toBeGreaterThan(directProbe)
  })

  it('binds ping.exe to a specific source IP', () => {
    const source = serverPickerSource()
    const pingFromSourceStart = source.indexOf('export async function pingFromSource')
    const bindArg = source.indexOf("'-S', sourceIp, host", pingFromSourceStart)

    expect(pingFromSourceStart).toBeGreaterThanOrEqual(0)
    expect(bindArg).toBeGreaterThan(pingFromSourceStart)
  })
})
