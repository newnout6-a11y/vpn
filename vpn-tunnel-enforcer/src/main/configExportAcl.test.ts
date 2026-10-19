// AT-00-003 / AT-01-008: actual Windows ACLs and production export persistence.
import { execFile, spawn } from 'node:child_process'
import { once } from 'node:events'
import { build } from 'esbuild'
import { promisify } from 'node:util'
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { OperationRegistry } from './operationRegistry'
import { writeConfigExport } from './configOperationIo'
import { createPrivateConfigExport, prepareConfigExport } from './configExportSecurity'

const quote = (value: string) => "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Buffer.from(value, 'utf8').toString('base64') + "'))"
async function powershell(script: string) {
  const { stdout } = await promisify(execFile)('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from("$ErrorActionPreference='Stop';" + script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 15_000 })
  return stdout.trim()
}
let directory: string
const registry = new OperationRegistry()
beforeEach(async () => {
  await mkdir('.tmp', { recursive: true })
  directory = await mkdtemp(join(process.cwd(), '.tmp', "config-acl-'-"))
})
afterEach(async () => { if (directory) await rm(directory, { recursive: true, force: true }) })

describe.skipIf(process.platform !== 'win32')('Windows configuration export ACL', () => {
  it('atomically creates private staging without truncating or deleting an existing path', async () => {
    const path = join(directory, 'collision.tmp')
    await writeFile(path, 'original')
    await expect(createPrivateConfigExport(path)).rejects.toMatchObject({ category: 'permission' })
    expect(await readFile(path, 'utf8')).toBe('original')
  })
  it.each(['\u2018', '\u2019', '\u201a', '\u201b'])('treats a typographic apostrophe %s in the chosen path as data', async apostrophe => {
    const path = join(directory, `Jane${apostrophe}s Documents.json`)
    expect(await registry.run('export', lease => writeConfigExport(path, 'first', lease, true, 'redacted'))).toBe(true)
    expect(await registry.run('export', lease => writeConfigExport(path, 'second', lease, true, 'redacted'))).toBe(true)
    expect(await readFile(path, 'utf8')).toBe('second')
  })

  it('preserves an existing explicit owner/group/DACL instead of inheriting parent access', async () => {
    const path = join(directory, 'existing.json')
    await writeFile(path, 'old')
    const before = await powershell(`
$path=${quote(path)}
$acl=[IO.File]::GetAccessControl($path)
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18')) {
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','Allow')))
}
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-19')),'Read','Allow')))
[IO.File]::SetAccessControl($path,$acl)
[IO.File]::GetAccessControl($path).GetSecurityDescriptorSddlForm('All')`)
    expect(await registry.run('export', lease => writeConfigExport(path, 'secret', lease, true, 'redacted'))).toBe(true)
    expect(await readFile(path, 'utf8')).toBe('secret')
    expect(await powershell(`[IO.File]::GetAccessControl(${quote(path)}).GetSecurityDescriptorSddlForm('All')`)).toBe(before)
  })

  it('creates a new export with a protected user/SYSTEM DACL before writing plaintext', async () => {
    const path = join(directory, 'new.json')
    await registry.run('export', lease => writeConfigExport(path, 'secret', lease, true, 'redacted'))
    const acl = JSON.parse(await powershell(`
$acl=[IO.File]::GetAccessControl(${quote(path)})
[ordered]@{protected=$acl.AreAccessRulesProtected;user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value})}|ConvertTo-Json -Compress`))
    expect(acl.protected).toBe(true)
    expect(acl.rules.sort()).toEqual([...new Set([acl.user, 'S-1-5-18'])].sort())
  })

  it('restricts secret staging and the final export even when the existing file grants other readers', async () => {
    const path = join(directory, 'broad.json'), temporary = join(directory, 'empty-secret.tmp')
    await writeFile(path, 'old'); await writeFile(temporary, '')
    await powershell(`
$path=${quote(path)}
$acl=[IO.File]::GetAccessControl($path)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-19')),'Read','Allow')))
[IO.File]::SetAccessControl($path,$acl)`)
    const readAcl = async (file: string) => JSON.parse(await powershell(`
$acl=[IO.File]::GetAccessControl(${quote(file)})
[ordered]@{protected=$acl.AreAccessRulesProtected;user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value})}|ConvertTo-Json -Compress`))
    await prepareConfigExport(temporary, path, 'secrets')
    const staged = await readAcl(temporary)
    expect(staged.protected).toBe(true)
    expect(staged.rules.sort()).toEqual([...new Set([staged.user, 'S-1-5-18'])].sort())
    await registry.run('export', lease => writeConfigExport(path, 'secret', lease, true, 'secrets'))
    const final = await readAcl(path)
    expect(final.protected).toBe(true)
    expect(final.rules.sort()).toEqual([...new Set([final.user, 'S-1-5-18'])].sort())
    expect(await readFile(path, 'utf8')).toBe('secret')
  })

  it('keeps crash residue private and the destination unchanged after killing the actual staging writer', async () => {
    const path = join(directory, 'crash.json'), childFile = join(directory, 'crash-writer.cjs')
    await writeFile(path, 'old')
    await powershell(`
$path=${quote(path)}
$acl=[IO.File]::GetAccessControl($path)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-19')),'Read','Allow')))
[IO.File]::SetAccessControl($path,$acl)`)
    await build({ entryPoints: [join(process.cwd(), 'src/main/testFixtures/configExportCrash.ts')], outfile: childFile,
      bundle: true, platform: 'node', format: 'cjs', plugins: [{ name: 'isolated-crash-telemetry', setup(builder) {
        builder.onResolve({ filter: /^\.\/appLogger$/ }, () => ({ path: 'logger', namespace: 'crash-fixture' }))
        builder.onLoad({ filter: /.*/, namespace: 'crash-fixture' }, () => ({ contents: 'export function logEvent() {}', loader: 'js' }))
      } }] })
    const child = spawn(process.execPath, [childFile, path], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] })
    const exited = once(child, 'exit')
    try {
      const ready = await Promise.race([once(child, 'message'), exited.then(() => { throw new Error('Crash writer exited before staging') })])
      expect(ready[0]).toBe('staged')
      expect(child.kill()).toBe(true)
      await exited
      const files = (await readdir(directory)).filter(file => /^\.vpnte-export-.*\.tmp$/.test(file))
      expect(files).toHaveLength(1)
      const residue = join(directory, files[0])
      expect(await readFile(residue, 'utf8')).toBe('FAKE-SECRET-CRASH')
      expect(await readFile(path, 'utf8')).toBe('old')
      const acl = JSON.parse(await powershell(`
$acl=[IO.File]::GetAccessControl(${quote(residue)})
[ordered]@{protected=$acl.AreAccessRulesProtected;user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value})}|ConvertTo-Json -Compress`))
      expect(acl.protected).toBe(true)
      expect(acl.rules.sort()).toEqual([...new Set([acl.user, 'S-1-5-18'])].sort())
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill()
      await exited
    }
  }, 20_000)

  it('refuses final replacement when the destination ACL changes after capture', async () => {
    const path = join(directory, 'changed.json'), temporary = join(directory, 'empty.tmp')
    await writeFile(path, 'old'); await writeFile(temporary, '')
    const verify = await prepareConfigExport(temporary, path, 'redacted')
    await powershell(`
$path=${quote(path)}
$acl=[IO.File]::GetAccessControl($path)
$acl.SetAccessRuleProtection($true,$false)
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user,'FullControl','Allow')))
[IO.File]::SetAccessControl($path,$acl)`)
    expect(verify).toThrow(expect.objectContaining({ category: 'conflict' }))
    expect(await readFile(path, 'utf8')).toBe('old')
  })
})
