import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const readProjectFile = (path: string) => readFileSync(join(process.cwd(), path), 'utf8')

describe('Epic EOS installer compatibility', () => {
  it('bundles and invokes the elevated compatibility script', () => {
    const builderConfig = readProjectFile('electron-builder.yml')
    const installer = readProjectFile('build/installer.nsh')

    expect(builderConfig).toContain('resources/vpnte-eos-compat.ps1')
    expect(builderConfig).toContain('to: vpnte-eos-compat.ps1')
    expect(installer).toContain('-File "$INSTDIR\\resources\\vpnte-eos-compat.ps1"')
  })

  it('prefers IPv4 localhost and excludes only the EOS helper port range', () => {
    const script = readProjectFile('resources/vpnte-eos-compat.ps1')

    expect(script).toContain('prefix=::ffff:0:0/96 precedence=60 label=4')
    expect(script).toContain('127.0.0.1 localhost $hostsMarker')
    expect(script).toContain("'codex_sandbox_offline_block_loopback_tcp'")
    expect(script).toContain("@('1-35782', '35792-65535')")
    expect(script).not.toContain('Remove-NetFirewallRule')
  })
})
