/** AT-03-012: closed data protocol; no scripts or arbitrary artifact paths. */
import { runtimeAclWorkerFunction } from './runtimeAclInspection'
import { PHYSICAL_ADAPTER_DNS_SCRIPT } from './physicalAdapterSnapshot'
export const RECOVERY_MAX_BYTES = 1024 * 1024
export type RecoveryRequest =
  | { op: 'ensure' | 'warmup' | 'inspect-dns-policy' | 'inspect-physical-dns' }
  | { op: 'read' | 'binary' | 'remove'; name: string }
  | { op: 'protect'; name: string }
  | { op: 'quarantine'; name: string; contentHash: string }
  | { op: 'inspect-tun'; alias: string }
  | { op: 'inspect-runtime' | 'inspect-runtime-acl' | 'stop-runtime'; runtimeDir: string }

export function validateRecoveryRequest(value: RecoveryRequest): void {
  const fields = Object.keys(value).sort().join(',')
  if (value.op === 'ensure' || value.op === 'warmup' || value.op === 'inspect-dns-policy' || value.op === 'inspect-physical-dns') {
    if (fields === 'op') return
  } else if (value.op === 'inspect-tun') {
    if (fields === 'alias,op' && typeof value.alias === 'string' && /^(Ethernet (?:[5-9]|1[0-2])|VPNTE-TUN|awg-tun)$/.test(value.alias)) return
  } else if (value.op === 'inspect-runtime' || value.op === 'inspect-runtime-acl' || value.op === 'stop-runtime') {
    if (fields === 'op,runtimeDir' && typeof value.runtimeDir === 'string' && value.runtimeDir.length <= 2048 &&
        /^[a-z]:\\/i.test(value.runtimeDir) && !/[\x00-\x1f"/]/.test(value.runtimeDir) &&
        !value.runtimeDir.slice(2).includes(':') && !value.runtimeDir.split('\\').some(part => part === '..' || part === '.')) return
  } else if (value.op === 'quarantine') {
    if (fields === 'contentHash,name,op' && typeof value.contentHash === 'string' && /^[a-f0-9]{64}$/.test(value.contentHash) && typeof value.name === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}\.json$/.test(value.name)) return
  } else if (['read', 'binary', 'remove', 'protect'].includes(value.op) && 'name' in value) {
    if (fields === 'name,op' && typeof value.name === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}$/.test(value.name) &&
        (value.op !== 'protect' || /^tmp-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value.name))) return
  }
  throw new Error('Invalid recovery worker request')
}

/** Same conservative ownership predicate as the legacy lifecycle status read. */
export const OWNED_RUNTIME_STATUS_QUERY_SCRIPT = String.raw`
$names = @('vpnte-sing-box.exe', 'vpnte-etw-sidecar.exe', 'vpnte-xray.exe')
$found = @(Get-CimInstance Win32_Process -ErrorAction Stop |
  Where-Object {
    ($names -contains $_.Name) -and
    $_.ExecutablePath -and
    $_.ExecutablePath.StartsWith($runtimeDir, [System.StringComparison]::OrdinalIgnoreCase)
  } | Select-Object -First 1)
if ($found.Count -gt 0) { 'true' } else { 'false' }
`

/** Fixed stop command; its result is never used as proof that runtime exited. */
export const OWNED_RUNTIME_STOP_SCRIPT = String.raw`
$names = @('vpnte-sing-box.exe', 'vpnte-etw-sidecar.exe', 'vpnte-xray.exe')
$rows = @(Get-CimInstance Win32_Process -ErrorAction Stop |
  Where-Object {
    ($names -contains $_.Name) -and
    $_.ExecutablePath -and
    $_.ExecutablePath.StartsWith($runtimeDir, [System.StringComparison]::OrdinalIgnoreCase)
  })
$killed = @()
# The upstream must stay alive until the TUN consumer has exited, regardless
# of CIM enumeration order. This also applies to orphan/shutdown cleanup.
foreach ($p in ($rows | Sort-Object { if ($_.Name -ieq 'vpnte-sing-box.exe') { 0 } else { 1 } })) {
  try {
    $stopped = Stop-Process -Id $p.ProcessId -Force -PassThru -ErrorAction Stop
    if ($p.Name -ieq 'vpnte-sing-box.exe' -and -not $stopped.WaitForExit(3000)) {
      throw 'Owned TUN consumer exit was not confirmed'
    }
    $killed += [pscustomobject]@{name=[string]$p.Name;pid=[int]$p.ProcessId}
  } catch { if ($p.Name -ieq 'vpnte-sing-box.exe') { break } }
}

[pscustomobject]@{candidates=[int]$rows.Count;killed=[int]$killed.Count;names=@($killed | ForEach-Object { $_.name })} | ConvertTo-Json -Compress -Depth 3
`

/** Fixed quarantine operation; callers provide only a checked artifact and hash. */
export const RECOVERY_QUARANTINE_SCRIPT = String.raw`
function Get-QuarantineContentHash($stream) {
  if ($stream.Length -gt ${RECOVERY_MAX_BYTES}) { throw 'Recovery manifest exceeds limit' }
  $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true)
  $body=$reader.ReadToEnd().TrimStart([char]0xfeff).Trim()
  $sha=[Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($body)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
Assert-TrustedArtifact $path $false
$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read -bor [IO.FileShare]::Delete)
try {
  $hash=Get-QuarantineContentHash $stream
  if ($hash -ne $expectedHash) { throw 'Recovery manifest changed since rejection; quarantine refused' }
  $quarantine=$path+'.corrupt-'+[Guid]::NewGuid().ToString()
  Move-Item -LiteralPath $path -Destination $quarantine -ErrorAction Stop
} finally { $stream.Dispose() }
Assert-TrustedArtifact $quarantine $false
# Share.Delete allows another writer's atomic replacement during the first read.
# Validate the file actually moved, denying writes/replacements during this read.
$moved=[IO.File]::Open($quarantine,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try { $movedHash=Get-QuarantineContentHash $moved } finally { $moved.Dispose() }
if ($movedHash -ne $expectedHash) {
  # File.Move refuses an existing destination: never overwrite a newer baseline.
  try { [IO.File]::Move($quarantine,$path) }
  catch { throw 'Recovery quarantine raced with replacement; newer baseline and quarantined data preserved' }
  throw 'Recovery manifest changed during quarantine; replacement restored'
}
if (Test-Path -LiteralPath $path) { throw 'Recovery quarantine not confirmed' }
return 'RECOVERY_ARTIFACT_QUARANTINED'
`

/** Fixed, read-only baseline reader shared by the typed worker and pre-dispatch fallback. */
export const DNS_POLICY_SNAPSHOT_SCRIPT = String.raw`
$ErrorActionPreference='Stop'
function Read-RegValue([string]$key, [string]$name, [string]$tag) {
  $registryKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key.Substring(5))
  try {
    $exists=$registryKey -and @($registryKey.GetValueNames()) -contains $name
    if (-not $exists) { return [pscustomobject]@{tag=$tag;exists=$false;type=$null;data=$null} }
    if ($registryKey.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw 'DNS policy has unsupported registry type' }
    $data=[int]$registryKey.GetValue($name)
    $unsigned=[BitConverter]::ToUInt32([BitConverter]::GetBytes($data),0)
    return [pscustomobject]@{tag=$tag;exists=$true;type='REG_DWORD';data=('0x'+$unsigned.ToString('x'))}
  } finally { if($registryKey){$registryKey.Close()} }
}
@(
  Read-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DisableSmartNameResolution' 'smartNameResolution'
  Read-RegValue 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'DisableParallelAandAAAA' 'parallelAandAAAA'
) | ConvertTo-Json -Compress`

/** Kept separate so the real dispatcher can run against fake cmdlets in L2 tests. */
export function recoveryWorkerFunctions(programData: string): string {
  const literal = `'${programData.replace(/'/g, "''")}'`
  return String.raw`
$expectedProgramData=${literal}
${runtimeAclWorkerFunction(programData)}
function Read-DnsPolicySnapshot {
${DNS_POLICY_SNAPSHOT_SCRIPT}
}
function Read-PhysicalAdapterDns {
${PHYSICAL_ADAPTER_DNS_SCRIPT}
}
function Read-OwnedRuntimeStatus([string]$runtimeDir) {
${OWNED_RUNTIME_STATUS_QUERY_SCRIPT}
}
function Stop-OwnedRuntime([string]$runtimeDir) {
${OWNED_RUNTIME_STOP_SCRIPT}
}
function Assert-TrustedArtifact($path, $directory) {
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse recovery artifact rejected' }
  if ([bool]$item.PSIsContainer -ne [bool]$directory) { throw 'Wrong recovery artifact type' }
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
  $allowed = @('S-1-5-18','S-1-5-32-544')
  if ($allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'Untrusted recovery owner' }
  if (-not $acl.AreAccessRulesProtected) { throw 'Recovery ACL must be protected' }
  foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $rule.IdentityReference.Value) { throw 'Untrusted recovery ACE' }
  }
}
function Get-RecoveryRoot {
  $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if (-not [string]::Equals([IO.Path]::GetFullPath($expectedProgramData).TrimEnd([char]92),[IO.Path]::GetFullPath($known).TrimEnd([char]92),[StringComparison]::OrdinalIgnoreCase)) { throw 'ProgramData environment does not match the Windows known folder' }
  $parent = Get-Item -LiteralPath $known -Force -ErrorAction Stop
  if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Untrusted ProgramData path' }
  return [IO.Path]::Combine($known,'VPNTE','manifests')
}
function Assert-RecoveryDirectories($root, [bool]$create) {
  foreach ($dir in @([IO.Path]::GetDirectoryName($root),$root)) {
    if (-not (Test-Path -LiteralPath $dir -ErrorAction Stop)) {
      if (-not $create) { return $false }
      $acl = New-Object Security.AccessControl.DirectorySecurity
      $acl.SetAccessRuleProtection($true,$false)
      foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $id = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
      }
      $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
      $info = New-Object IO.DirectoryInfo($dir)
      $info.Create($acl)
    }
    Assert-TrustedArtifact $dir $true
  }
  return $true
}
function Invoke-RecoveryOperation($request) {
  if ($request.op -isnot [string] -or @('warmup','inspect-tun','inspect-runtime','inspect-runtime-acl','stop-runtime','inspect-dns-policy','inspect-physical-dns','ensure','read','binary','remove','protect','quarantine') -cnotcontains $request.op) { throw 'Unknown recovery worker operation' }
  $fields = @($request.PSObject.Properties.Name | Sort-Object) -join ','
  switch -Exact ($request.op) {
    { $_ -cin @('inspect-runtime','inspect-runtime-acl','stop-runtime') } {
      if ($fields -cne 'op,runtimeDir' -or $request.runtimeDir -isnot [string] -or $request.runtimeDir.Length -gt 2048 -or
          $request.runtimeDir -notmatch '^[a-z]:\\' -or $request.runtimeDir -match '[\x00-\x1f"/]' -or
          $request.runtimeDir.Substring(2).Contains(':') -or @($request.runtimeDir.Split([char]92) | Where-Object { $_ -ceq '..' -or $_ -ceq '.' }).Count) { throw 'Invalid runtime observation directory' }
      if ($request.op -ceq 'stop-runtime') { return (Stop-OwnedRuntime $request.runtimeDir) }
      if ($request.op -ceq 'inspect-runtime-acl') { return (Read-RuntimeAclSnapshot $request.runtimeDir) }
      return (Read-OwnedRuntimeStatus $request.runtimeDir)
    }
    'inspect-dns-policy' {
      if ($fields -ne 'op') { throw 'Invalid recovery worker fields' }
      return (Read-DnsPolicySnapshot)
    }
    'inspect-physical-dns' {
      if ($fields -cne 'op') { throw 'Invalid recovery worker fields' }
      $snapshot = Read-PhysicalAdapterDns
      if ($null -eq $snapshot) { return '[]' }
      return $snapshot
    }
    'warmup' {
      if ($fields -ne 'op') { throw 'Invalid recovery worker fields' }
      Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
      Import-Module NetAdapter,DnsClient,NetTCPIP -ErrorAction Stop
      return 'RECOVERY_MODULES_READY'
    }
    'inspect-tun' {
      if ($fields -ne 'alias,op' -or $request.alias -isnot [string] -or $request.alias -cnotmatch '^(Ethernet (?:[5-9]|1[0-2])|VPNTE-TUN|awg-tun)$') { throw 'Invalid TUN alias' }
      $adapter = @(Get-NetAdapter -Name $request.alias -ErrorAction Stop)
      if ($adapter.Count -ne 1 -or [string]$adapter[0].Name -cne $request.alias) { throw 'VPNTE TUN alias identity mismatch' }
      $adapter = $adapter[0]
      if ([string]$adapter.Status -ne 'Up') { throw 'VPNTE TUN adapter is not Up' }
      if ($adapter.DriverDescription -notmatch '^Wintun\b' -or $adapter.PnPDeviceID -notlike 'SWD\Wintun\*') { throw 'VPNTE TUN driver identity mismatch' }
      $ip = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -eq '192.168.250.253' -and $_.PrefixLength -eq 30 })
      if ($ip.Count -ne 1) { throw 'VPNTE TUN address identity mismatch' }
      if ([string]$adapter.InterfaceGuid -notmatch '^\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?$') { throw 'Invalid TUN GUID' }
      return ([pscustomobject]@{schemaVersion=1;owner='VPNTE';alias=[string]$adapter.Name;interfaceGuid=[string]$adapter.InterfaceGuid} | ConvertTo-Json -Compress)
    }
    'ensure' { if ($fields -ne 'op') { throw 'Invalid recovery worker fields' } }
    'quarantine' {
      if ($fields -cne 'contentHash,name,op' -or $request.contentHash -isnot [string] -or $request.contentHash -cnotmatch '^[a-f0-9]{64}$' -or $request.name -isnot [string] -or $request.name -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}\.json$') { throw 'Invalid recovery quarantine request' }
    }
    { $_ -cin @('read','binary','remove','protect') } {
      if ($fields -ne 'name,op' -or $request.name -isnot [string] -or $request.name -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}$') { throw 'Invalid recovery artifact name' }
      if ($request.op -eq 'protect' -and $request.name -notmatch '^tmp-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$') { throw 'Invalid recovery temporary name' }
    }
    default { throw 'Unknown recovery worker operation' }
  }
  $root = Get-RecoveryRoot
  if (-not (Assert-RecoveryDirectories $root ($request.op -eq 'ensure'))) { return 'RECOVERY_STORAGE_MISSING' }
  if ($request.op -eq 'ensure') { return 'RECOVERY_STORAGE_VERIFIED' }
  $path = [IO.Path]::Combine($root,$request.name)
  if ($request.op -eq 'protect') {
    # Reject reparse/type/owner/parent replacement BEFORE altering the temporary ACL.
    $temporary = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($temporary.PSIsContainer -or ($temporary.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Untrusted recovery temporary type' }
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
      $id = New-Object Security.Principal.SecurityIdentifier($sid)
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
    Assert-TrustedArtifact $path $false
    return 'RECOVERY_TEMP_VERIFIED'
  }
  if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
    if ($request.op -eq 'binary') { throw 'Recovery artifact absent' }
    return 'RECOVERY_ARTIFACT_ABSENT'
  }
  Assert-TrustedArtifact $path $false
  if ($request.op -eq 'quarantine') {
    $expectedHash=$request.contentHash
${RECOVERY_QUARANTINE_SCRIPT}
  }
  if ($request.op -eq 'remove') {
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    return 'RECOVERY_ARTIFACT_REMOVED'
  }
  if ((Get-Item -LiteralPath $path -Force -ErrorAction Stop).Length -gt ${RECOVERY_MAX_BYTES}) { throw 'Recovery artifact exceeds limit' }
  if ($request.op -eq 'binary') { return [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) }
  return Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
}
`
}

export function recoveryWorkerScript(programData: string): string {
  return String.raw`
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
[Console]::InputEncoding=[Text.Encoding]::UTF8
${recoveryWorkerFunctions(programData)}
[Console]::Out.WriteLine('{"id":0,"ok":true,"value":"RECOVERY_WORKER_READY"}')
while ($line = [Console]::In.ReadLine()) {
  if ($line -ceq '__EXIT__') { break }
  $id = 0
  try {
    if ($line.Length -gt 2048) { throw 'Recovery request exceeds limit' }
    $cmd = $line | ConvertFrom-Json -ErrorAction Stop
    if ((@($cmd.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'id,request' -or $cmd.id -isnot [int] -or $cmd.id -le 0) { throw 'Invalid recovery envelope' }
    $id = $cmd.id
    $value = Invoke-RecoveryOperation $cmd.request
    if ($value -isnot [string] -or [Text.Encoding]::UTF8.GetByteCount($value) -gt ${RECOVERY_MAX_BYTES * 2}) { throw 'Invalid recovery operation output' }
    # PS 5.1 Get-Content attaches provider properties to its string. Without
    # this cast ConvertTo-Json emits an object instead of the wire string.
    $value = [string]$value
    $result = @{id=$id;ok=$true;value=$value}
  } catch { $result = @{id=$id;ok=$false;error='Recovery operation rejected: ' + $_.Exception.Message} }
  [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress -Depth 3))
}
`
}
