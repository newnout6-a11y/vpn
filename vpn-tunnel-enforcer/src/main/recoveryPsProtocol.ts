/** AT-03-012: closed data protocol; requests never contain scripts or paths. */
export const RECOVERY_MAX_BYTES = 1024 * 1024
export type RecoveryRequest =
  | { op: 'ensure' | 'warmup' | 'inspect-dns-policy' }
  | { op: 'read' | 'binary' | 'remove'; name: string }
  | { op: 'protect'; name: string }
  | { op: 'inspect-tun'; alias: string }

export function validateRecoveryRequest(value: RecoveryRequest): void {
  const fields = Object.keys(value).sort().join(',')
  if (value.op === 'ensure' || value.op === 'warmup' || value.op === 'inspect-dns-policy') {
    if (fields === 'op') return
  } else if (value.op === 'inspect-tun') {
    if (fields === 'alias,op' && typeof value.alias === 'string' && /^(Ethernet (?:[5-9]|1[0-2])|VPNTE-TUN|awg-tun)$/.test(value.alias)) return
  } else if (['read', 'binary', 'remove', 'protect'].includes(value.op) && 'name' in value) {
    if (fields === 'name,op' && typeof value.name === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}$/.test(value.name) &&
        (value.op !== 'protect' || /^tmp-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value.name))) return
  }
  throw new Error('Invalid recovery worker request')
}

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
function Read-DnsPolicySnapshot {
${DNS_POLICY_SNAPSHOT_SCRIPT}
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
  if ($request.op -isnot [string] -or @('warmup','inspect-tun','inspect-dns-policy','ensure','read','binary','remove','protect') -cnotcontains $request.op) { throw 'Unknown recovery worker operation' }
  $fields = @($request.PSObject.Properties.Name | Sort-Object) -join ','
  switch -Exact ($request.op) {
    'inspect-dns-policy' {
      if ($fields -ne 'op') { throw 'Invalid recovery worker fields' }
      return (Read-DnsPolicySnapshot)
    }
    'warmup' {
      if ($fields -ne 'op') { throw 'Invalid recovery worker fields' }
      Import-Module NetAdapter,NetTCPIP -ErrorAction Stop
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
