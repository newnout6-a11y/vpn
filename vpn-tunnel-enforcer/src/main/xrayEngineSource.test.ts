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
    expect(xrayEngineSrc).toContain("['run', '-test', '-c'")
  })

  it('does not use insecure dokodemo-door inbound', () => {
    expect(xrayEngineSrc).not.toContain('dokodemo-door')
  })

  it('configures Xray logging level as warning', () => {
    expect(xrayEngineSrc).toContain("loglevel: 'warning'")
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
