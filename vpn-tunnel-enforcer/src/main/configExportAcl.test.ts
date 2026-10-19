// AT-00-003 / AT-01-008: actual Windows ACLs and production export persistence.
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { OperationRegistry } from './operationRegistry'
import { writeConfigExport } from './configOperationIo'
import { prepareConfigExport } from './configExportSecurity'

const quote = (value: string) => "'" + value.replaceAll("'", "''") + "'"
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
    expect(await registry.run('export', lease => writeConfigExport(path, 'secret', lease, true))).toBe(true)
    expect(await readFile(path, 'utf8')).toBe('secret')
    expect(await powershell(`[IO.File]::GetAccessControl(${quote(path)}).GetSecurityDescriptorSddlForm('All')`)).toBe(before)
  })

  it('creates a new export with a protected user/SYSTEM DACL before writing plaintext', async () => {
    const path = join(directory, 'new.json')
    await registry.run('export', lease => writeConfigExport(path, 'secret', lease, true))
    const acl = JSON.parse(await powershell(`
$acl=[IO.File]::GetAccessControl(${quote(path)})
[ordered]@{protected=$acl.AreAccessRulesProtected;user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value})}|ConvertTo-Json -Compress`))
    expect(acl.protected).toBe(true)
    expect(acl.rules.sort()).toEqual([...new Set([acl.user, 'S-1-5-18'])].sort())
  })

  it('refuses final replacement when the destination ACL changes after capture', async () => {
    const path = join(directory, 'changed.json'), temporary = join(directory, 'empty.tmp')
    await writeFile(path, 'old'); await writeFile(temporary, '')
    const verify = await prepareConfigExport(temporary, path)
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
