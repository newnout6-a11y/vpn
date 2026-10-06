// AT-01-009 / AT-08-005: native PowerShell semantics only; provider calls are replaced
// with harmless scriptblocks before execution. No packet capture or elevation.
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import { describe, expect, it, vi } from 'vitest'
vi.mock('electron', () => ({ app: {} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: vi.fn() } }))
import { buildCaptureProviderStopScript, buildPktmonStopScript } from './trafficForensics'

const execFile = promisify(execFileCb)
describe.skipIf(process.platform !== 'win32')('native provider stop acknowledgement', () => {
  it.each(['pktmon', 'netsh'] as const)('acknowledges %s only after native exit zero', async engine => {
    const generated = buildCaptureProviderStopScript(engine)
    const invocation = generated.split('; ').find(part => part.startsWith('& '))!
    expect(invocation).toContain('[Environment]::SystemDirectory')
    for (const code of [0, 5]) {
      const harmless = generated.replace(invocation, `& { $global:LASTEXITCODE = ${code} }`)
      expect(harmless).not.toMatch(/pktmon\.exe|netsh\.exe/)
      const result = execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(harmless, 'utf16le').toString('base64')], {
        windowsHide: true, timeout: 10000, encoding: 'utf8'
      })
      if (code === 0) {
        expect((await result).stdout.trim()).toBe(`VPNTE_CAPTURE_STOPPED:${engine}`)
      } else {
        await expect(result).rejects.toMatchObject({ code: 1 })
        await result.catch(error => expect(error.stdout).not.toContain('VPNTE_CAPTURE_STOPPED:'))
      }
    }
  }, 30000)

  it('places mandatory stop before best-effort artifact collection', () => {
    const script = buildPktmonStopScript('C:\\synthetic-fixture', 'C:\\synthetic-fixture\\pktmon.etl')
    expect(script.indexOf('VPNTE_CAPTURE_STOPPED:pktmon')).toBeLessThan(script.indexOf('Invoke-VpnteBestEffort'))
    expect(script).not.toContain("label: 'pktmon-stop'")
  })
})
