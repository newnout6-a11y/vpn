/** Fixed read-only runtime ACL inspector shared by standalone PowerShell and the typed worker. */
export const SID_SYSTEM = 'S-1-5-18'
export const SID_ADMINISTRATORS = 'S-1-5-32-544'
export const SID_TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
export const ALLOWED_SIDS = new Set([SID_SYSTEM, SID_ADMINISTRATORS])
export const ANCESTOR_SIDS = new Set([...ALLOWED_SIDS, SID_TRUSTED_INSTALLER])
// Data/EA/attributes, delete-child/delete, WRITE_DAC and WRITE_OWNER.
export const ARTIFACT_WRITE_MASK = 0x500D0156
// Creating siblings or writing directory attributes is not a grant to rename
// an existing protected child. DELETE_CHILD/DELETE/WRITE_DAC/WRITE_OWNER and
// GENERIC_ALL are. InheritOnly ACEs do not apply to the ancestor itself.
export const NAMESPACE_WRITE_MASK = 0x100D0040

export const POLICY_FAILURE = /^(RuntimeNamespaceUntrusted(?:Owner|Type|Reparse|Access)|RuntimeAclNotProtected|RuntimeAclMissingRules|RuntimeProgramDataMismatch|RuntimeOutsideBoundary)$/
function psSingleQuote(value: string): string { return `'${value.replace(/'/g, "''")}'` }

export const RUNTIME_TREE_HELPERS = `
$artifactSids = @('${SID_SYSTEM}', '${SID_ADMINISTRATORS}')
$ancestorSids = @('${SID_SYSTEM}', '${SID_ADMINISTRATORS}', '${SID_TRUSTED_INSTALLER}')
function Get-RuntimeItem($path) {
  $script:runtimeOperation='read-item'; $script:runtimePath=$path; $script:runtimePrincipal=$null; $script:runtimeRights=$null
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'RuntimeNamespaceUntrustedReparse' }
  return $item
}
function Get-RuntimeAcl($path) {
  $item = Get-RuntimeItem $path
  $script:runtimeOperation='read-acl'
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
  $rules = @()
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $rules += [ordered]@{
      sid = $rule.IdentityReference.Value
      rights = ([long][int]$rule.FileSystemRights -band 4294967295)
      type = $rule.AccessControlType.ToString()
      inheritOnly = (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
    }
  }
  return [ordered]@{
    path = $item.FullName
    directory = [bool]$item.PSIsContainer
    reparse = $false
    owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    protected = $acl.AreAccessRulesProtected
    rules = $rules
  }
}
function Assert-RuntimeAcl($snapshot, $ancestor) {
  $script:runtimeOperation='validate-acl'; $script:runtimePath=$snapshot.path; $script:runtimePrincipal=$snapshot.owner; $script:runtimeRights=$null
  $allowed = $artifactSids; $mask = ${ARTIFACT_WRITE_MASK}
  if ($ancestor) { $allowed = $ancestorSids; $mask = ${NAMESPACE_WRITE_MASK} }
  if ($allowed -notcontains $snapshot.owner) { throw 'RuntimeNamespaceUntrustedOwner' }
  if ($ancestor -and -not $snapshot.directory) { throw 'RuntimeNamespaceUntrustedType' }
  if (-not $ancestor -and -not $snapshot.protected) { throw 'RuntimeAclNotProtected' }
  if ($snapshot.rules.Count -eq 0) { throw 'RuntimeAclMissingRules' }
  foreach ($rule in $snapshot.rules) {
    if ((-not $ancestor -or -not $rule.inheritOnly) -and $rule.type -eq 'Allow' -and $allowed -notcontains $rule.sid -and
        ($rule.rights -band $mask) -ne 0) {
      $script:runtimePrincipal=$rule.sid; $script:runtimeRights=$rule.rights
      throw 'RuntimeNamespaceUntrustedAccess'
    }
  }
}
function Get-RuntimeAncestors($path) {
  $components = New-Object 'System.Collections.Generic.Stack[string]'
  $candidate = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($path))
  while ($candidate) {
    $components.Push($candidate)
    $candidate = [IO.Path]::GetDirectoryName($candidate)
  }
  while ($components.Count -gt 0) {
    $snapshot = Get-RuntimeAcl ($components.Pop())
    Write-Output $snapshot
    # Refuse before walking into the next component, not after reading its ACL.
    Assert-RuntimeAcl $snapshot $true
  }
}
function Get-RuntimeChildren($root) {
  $pending = New-Object 'System.Collections.Generic.Stack[string]'
  $pending.Push($root)
  while ($pending.Count -gt 0) {
    $parent = Get-RuntimeItem ($pending.Pop())
    if (-not $parent.PSIsContainer) { throw 'RuntimeNamespaceUntrustedType' }
    $script:runtimeOperation='list-children'
    foreach ($entry in @(Get-ChildItem -LiteralPath $parent.FullName -Force -ErrorAction Stop)) {
      $item = Get-RuntimeItem $entry.FullName
      Write-Output (Get-RuntimeAcl $item.FullName)
      if ($item.PSIsContainer) { $pending.Push($item.FullName) }
    }
  }
}
`

export function knownFolderCheck(programData: string = process.env.ProgramData || 'C:\\ProgramData'): string {
  return `$script:runtimeOperation='known-folder'; $script:runtimePath=${psSingleQuote(programData)}
$knownProgramData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if (-not [string]::Equals([IO.Path]::GetFullPath(${psSingleQuote(programData)}).TrimEnd([char]92),
    [IO.Path]::GetFullPath($knownProgramData).TrimEnd([char]92), [StringComparison]::OrdinalIgnoreCase)) {
  throw 'RuntimeProgramDataMismatch'
}`
}

export function buildInspectScript(dir: string, programData: string = process.env.ProgramData || 'C:\\ProgramData'): string {
  return `$ErrorActionPreference = 'Stop'
$dir = ${psSingleQuote(dir)}
${inspectionBody(programData)}`
}

function inspectionBody(programData: string): string {
  return `
${RUNTIME_TREE_HELPERS}
${knownFolderCheck(programData)}
# The parent chain is walked root-first and must be authorized before children.
$ancestors = @(Get-RuntimeAncestors $dir)
$root = Get-RuntimeAcl $dir
if (-not $root.directory) { throw 'RuntimeNamespaceUntrustedType' }
$root['ancestors'] = $ancestors
$root['ancestorsInspected'] = $true
$root['children'] = @(Get-RuntimeChildren $dir)
$root['childrenInspected'] = $true
$root | ConvertTo-Json -Depth 7 -Compress`
}

/** A fixed read-only operation: the request supplies a path, never source code. */
export function runtimeAclWorkerFunction(programData: string): string {
  return `
function Read-RuntimeAclSnapshot([string]$dir) {
  $script:runtimeOperation='import-acl-module'; $script:runtimePath=''; $script:runtimePrincipal=$null; $script:runtimeRights=$null
  try {
    Import-Module -Name (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
    ${inspectionBody(programData)}
  } catch {
    $reason='PowerShellError'
    if ($_.Exception.Message -match '${POLICY_FAILURE.source}') { $reason=$_.Exception.Message }
    $cause=$_.Exception
    while ($cause.InnerException) { $cause=$cause.InnerException }
    $diagnostic=[ordered]@{operation=$script:runtimeOperation;path=$script:runtimePath;reason=$reason;
      errorType=$cause.GetType().FullName;hresult=$cause.HResult;principal=$script:runtimePrincipal;rights=$script:runtimeRights}
    return 'VPNTE_RUNTIME_FAILURE:' + ($diagnostic | ConvertTo-Json -Compress)
  }
}`
}
