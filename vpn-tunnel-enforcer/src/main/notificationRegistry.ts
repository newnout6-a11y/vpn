import { execFile } from 'child_process'
import { promisify } from 'util'
import { IpcFault } from '../shared/ipc-result'

const execFileAsync = promisify(execFile)

/** .NET distinguishes missing values from access failures without localized reg.exe text. */
export async function notificationRegistry(modelId: string, reset = false): Promise<{ value: number | null; cleared: boolean }> {
  const encodedId = Buffer.from(modelId, 'utf8').toString('base64')
  const script = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$modelId = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedId}'))
$reset = $${reset ? 'true' : 'false'}
$key = $null
try {
  $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\' + $modelId, $reset)
  $value = $null
  $cleared = $false
  if ($null -ne $key) {
    $value = $key.GetValue('Enabled', $null)
    if ($null -ne $value) {
      if ($key.GetValueKind('Enabled') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw [IO.InvalidDataException]::new('Enabled is not a DWORD') }
      if ($reset -and $value -eq 0) { $key.DeleteValue('Enabled', $false); $cleared = $true }
    }
  }
  @{ value = $value; cleared = $cleared } | ConvertTo-Json -Compress
} catch {
  $cause = $_.Exception.GetBaseException()
  $permission = $cause -is [UnauthorizedAccessException] -or $cause -is [Security.SecurityException]
  @{ category = $(if ($permission) { 'permission' } else { 'internal' }); diagnostic = $cause.GetType().FullName; hresult = $cause.HResult } | ConvertTo-Json -Compress
} finally {
  if ($null -ne $key) { $key.Dispose() }
}`
  let stdout: string
  try {
    ;({ stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { timeout: 5000, windowsHide: true, encoding: 'utf8' }))
  } catch (error) {
    const e = error as { killed?: boolean; signal?: unknown }
    if (e?.killed && e.signal === 'SIGTERM') throw new IpcFault('timeout')
    throw error
  }
  const result = JSON.parse(stdout.trim())
  if (result?.category === 'permission' || result?.category === 'internal') {
    const error = new IpcFault(result.category)
    // Only runtime-generated exception type and numeric HRESULT are diagnostic.
    if (typeof result.diagnostic === 'string' && /^[A-Za-z0-9_.]{1,120}$/.test(result.diagnostic) && Number.isInteger(result.hresult)) {
      error.message = `Notification registry ${reset ? 'reset' : 'read'}: ${result.diagnostic}; HRESULT=${result.hresult}`
    }
    throw error
  }
  if (!result || typeof result.cleared !== 'boolean' ||
      (result.value !== null && (!Number.isInteger(result.value) || result.value < -2147483648 || result.value > 4294967295)) ||
      (result.cleared && (!reset || result.value !== 0))) throw new IpcFault('internal')
  return { value: result.value, cleared: result.cleared }
}
