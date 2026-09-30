// AT-03-002: installer registers mandatory recovery, never modifies foreign EOS state.
import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
const read = (path: string) => readFileSync(join(process.cwd(), path), 'utf8')
describe('installer recovery security', () => {
  it('does not ship or invoke removed EOS compatibility modifications', () => {
    expect(read('electron-builder.yml')).not.toContain('vpnte-eos-compat.ps1')
    expect(read('build/installer.nsh')).not.toContain('vpnte-eos-compat.ps1')
    expect(existsSync(join(process.cwd(), 'resources/vpnte-eos-compat.ps1'))).toBe(false)
  })
  it('requires successful registration instead of silently continuing installation', () => {
    const installer = read('build/installer.nsh')
    expect(installer).toContain('-RegisterTask')
    expect(installer).toContain('${If} $0 != 0')
    expect(installer).toContain('Abort')
    const script = read('resources/vpnte-recover.ps1')
    expect(script).toContain("-TaskName 'BootRecoveryTask' -TaskPath '\\VPNTE\\'")
    expect(script).toContain("-UserId 'SYSTEM'")
    expect(script).toContain("$task.Principal.RunLevel -ne 'Highest'")
    expect(script).toContain('RECOVERY_TASK_VERIFIED')
  })
})
