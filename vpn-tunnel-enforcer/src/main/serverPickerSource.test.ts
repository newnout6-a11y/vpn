import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const serverPickerSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'serverPicker.ts'), 'utf8')

describe('serverPicker source regressions', () => {
  it('refreshes the IP monitor baseline after a direct VPN profile switch', () => {
    const source = serverPickerSource()
    const restartStart = source.indexOf('async function restartDirectVpnForSelectedProfile')
    const stopCall = source.indexOf('tunController.stop()', restartStart)
    const startCall = source.indexOf('tunController.start', stopCall)
    const resumeCall = source.indexOf('ipMonitor.resume()', startCall)
    const rebaselineCall = source.indexOf('ipMonitor.recheck(true)', resumeCall)

    expect(restartStart).toBeGreaterThanOrEqual(0)
    expect(stopCall).toBeGreaterThan(restartStart)
    expect(startCall).toBeGreaterThan(stopCall)
    expect(resumeCall).toBeGreaterThan(startCall)
    expect(rebaselineCall).toBeGreaterThan(resumeCall)
  })
})
