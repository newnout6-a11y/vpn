// AT-11-005 / AT-11-009, F-167: no global maintenance and owned task removal.
import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '../..')
const installer = readFileSync(join(root, 'build/installer.nsh'), 'utf8')

describe('installer maintenance contract', () => {
  it('does not run NGEN or mutate global .NET settings', () => {
    expect(installer).not.toContain('ngen.exe')
    expect(installer).not.toContain('SetEnvironmentVariable("DOTNET_NGEN_OPT"')
    expect(installer).not.toContain('-Command "try')
  })
  it('removes recovery before deleting files, preserves it on upgrades and surfaces failure', () => {
    const hook = installer.slice(installer.indexOf('!macro customUnInstall'), installer.indexOf('; Make the finish page'))
    expect(hook).toContain('${IfNot} ${isUpdated}')
    expect(hook).toContain('-UnregisterTask')
    expect(hook).toContain('SetErrorLevel 1')
    expect(hook).toContain('Abort')
  })
})
