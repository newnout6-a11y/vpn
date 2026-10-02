import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'

describe('xrayEngine architectural invariants', () => {
  const root = join(__dirname, '../..')
  const xrayEngineSrc = readFileSync(join(root, 'src/main/xrayEngine.ts'), 'utf8')
  const tunControllerSrc = readFileSync(join(root, 'src/main/tunController.ts'), 'utf8')
  const electronBuilderSrc = readFileSync(join(root, 'electron-builder.yml'), 'utf8')
  const installerSrc = readFileSync(join(root, 'build/installer.nsh'), 'utf8')
  const settingsSrc = readFileSync(join(root, 'src/main/settings.ts'), 'utf8')

  it('runs preflight test before launching Xray runtime', () => {
    const preflightSrc = readFileSync(join(root, 'src/main/xrayPreflight.ts'), 'utf8')
    expect(preflightSrc).toContain("['run', '-test', '-c'")
    const validation = xrayEngineSrc.indexOf("await timed('config-preflight'")
    const runtime = xrayEngineSrc.indexOf("const child = spawn(exePath, ['run', '-c'")
    expect(validation).toBeGreaterThan(0)
    expect(runtime).toBeGreaterThan(validation)
  })

  it('does not use insecure dokodemo-door inbound', () => {
    expect(xrayEngineSrc).not.toContain('dokodemo-door')
  })

  it('configures Xray logging at info level so failures are visible to the fault reader', () => {
    expect(xrayEngineSrc).toContain("loglevel: 'info'")
  })

  it('routes xray outbound through the firewall kill-switch allow-list', () => {
    expect(xrayEngineSrc).toContain('ensureKillSwitchProgramAllowed')
  })

  it('tunController includes vpnte-xray.exe in EXTERNAL_PROXY_PROCESS_NAMES', () => {
    expect(tunControllerSrc).toContain("'vpnte-xray.exe'")
  })

  it('tunController includes vpnte-xray.exe in killOwnedTunRuntimeProcesses', () => {
    expect(tunControllerSrc).toContain("'vpnte-xray.exe'")
  })

  it('electron-builder packages resources/xray.exe into extraResources', () => {
    expect(electronBuilderSrc).toContain('from: resources/xray.exe')
    expect(electronBuilderSrc).toContain('to: xray.exe')
  })

  it('installer.nsh terminates vpnte-xray.exe before installing', () => {
    expect(installerSrc).toContain('taskkill /F /IM vpnte-xray.exe /T')
  })

  it('settings.ts includes proxyEngine in AppSettings and defaults', () => {
    expect(settingsSrc).toContain("proxyEngine: 'auto' | 'sing-box' | 'xray'")
    expect(settingsSrc).toContain("proxyEngine: 'auto'")
  })
})
