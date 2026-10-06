param([switch]$RegisterTask, [switch]$UnregisterTask)
# VPN Tunnel Enforcer — Boot-time Network Recovery
# Runs via scheduled task at system startup (before user logon).
# Recovers from a BSOD/crash that left the firewall blocking, DNS pinned,
# IPv6 disabled, or proxy settings wiped.

$hasWarnings = $false

$programData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $knownProgramData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if (-not [string]::Equals([IO.Path]::GetFullPath($programData).TrimEnd([char]92),[IO.Path]::GetFullPath($knownProgramData).TrimEnd([char]92),[StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning 'ProgramData environment does not match the Windows known folder'
        exit 1
    }
}
$script:recoveryMessages = @()
function Log([string]$msg) {
    $script:recoveryMessages += [pscustomobject]@{ time=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); message=$msg }
}

# ACL checks apply to the parent, directory AND each file, with reparse points rejected.
$trustedManifestDir = Join-Path $programData 'VPNTE\manifests'
function Assert-TrustedArtifact($path, $directory) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or [bool]$item.PSIsContainer -ne [bool]$directory) { throw 'Untrusted recovery path type' }
    $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
    $allowed = @('S-1-5-18','S-1-5-32-544')
    if (-not $acl.AreAccessRulesProtected -or $allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'Untrusted recovery owner or inheritance' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $rule.IdentityReference.Value) { throw 'Untrusted recovery ACE' }
    }
}
function Initialize-RecoveryStorage {
    $parent = Get-Item -LiteralPath $programData -Force -ErrorAction Stop
    if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Untrusted ProgramData path' }
    foreach ($dir in @((Join-Path $programData 'VPNTE'), $trustedManifestDir)) {
        if (-not (Test-Path -LiteralPath $dir)) {
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
}
function Write-RecoveryReport([string]$status) {
    Assert-TrustedArtifact (Join-Path $programData 'VPNTE') $true
    Assert-TrustedArtifact $trustedManifestDir $true
    $target = Join-Path $trustedManifestDir 'recovery-result.json'
    if (Test-Path -LiteralPath $target) { Assert-TrustedArtifact $target $false }
    $temporary = Join-Path $trustedManifestDir ('tmp-' + [Guid]::NewGuid().ToString())
    $report = [pscustomobject]@{schemaVersion=1;owner='VPNTE';completedAt=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();status=$status;messages=@($script:recoveryMessages | Select-Object -Last 500)}
    $bytes = [Text.Encoding]::UTF8.GetBytes(($report | ConvertTo-Json -Depth 6 -Compress))
    try {
        $file = New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true,$false)
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $id = New-Object Security.Principal.SecurityIdentifier($sid)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
        }
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        Set-Acl -LiteralPath $temporary -AclObject $acl -ErrorAction Stop
        Assert-TrustedArtifact $temporary $false
        if (Test-Path -LiteralPath $target) { [IO.File]::Replace($temporary,$target,$null) }
        else { [IO.File]::Move($temporary,$target) }
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop } }
}

function Read-TrustedManifest($name) {
    $path = Join-Path $trustedManifestDir $name
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    Assert-TrustedArtifact $path $false
    if ((Get-Item -LiteralPath $path).Length -gt 1048576) { throw 'Recovery manifest size limit' }
    $value = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($value.schemaVersion -ne 1 -or $value.owner -ne 'VPNTE') { throw 'Unsupported recovery manifest schema' }
    return $value
}
function Resolve-RecoveryPrincipalSid([string]$userId) {
    try {
        if ($userId -match '^S-\d-') { return (New-Object Security.Principal.SecurityIdentifier($userId)).Value }
        $account = New-Object Security.Principal.NTAccount($userId)
        return $account.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { throw 'Recovery task read-back mismatch: principal account cannot be resolved' }
}
function Get-BootRecoveryTaskOrNull {
    try { return Get-ScheduledTask -TaskName 'BootRecoveryTask' -TaskPath '\VPNTE\' -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw
    }
}
function Remove-BootRecoveryTask([string]$RecoveryScript) {
    $task = Get-BootRecoveryTaskOrNull
    if (-not $task) { return }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("& '" + $RecoveryScript.Replace("'", "''") + "'"))
    $expectedArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
    $expectedExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    if (@($task.Actions).Count -ne 1 -or $task.Actions.Execute -ne $expectedExe -or $task.Actions.Arguments -ne $expectedArguments -or (Resolve-RecoveryPrincipalSid $task.Principal.UserId) -ne 'S-1-5-18') {
        throw 'Refusing to remove a recovery task not owned by this installation'
    }
    Unregister-ScheduledTask -TaskName 'BootRecoveryTask' -TaskPath '\VPNTE\' -Confirm:$false -ErrorAction Stop
    if (Get-BootRecoveryTaskOrNull) { throw 'Recovery task removal could not be verified' }
}
if ($UnregisterTask) {
    try {
        if ($RegisterTask) { throw 'Task registration and removal are mutually exclusive' }
        Remove-BootRecoveryTask $PSCommandPath
        Write-Output 'RECOVERY_TASK_REMOVED'
        exit 0
    } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
}
# Registration is used by both the installer and application repair path.
if ($RegisterTask) {
    $ErrorActionPreference = 'Stop'
    Initialize-RecoveryStorage
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    try { $null = $service.GetFolder('\VPNTE') } catch { $null = $service.GetFolder('\').CreateFolder('VPNTE') }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("& '" + $PSCommandPath.Replace("'", "''") + "'"))
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
    $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'BootRecoveryTask' -TaskPath '\VPNTE\' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    $task = Get-ScheduledTask -TaskName 'BootRecoveryTask' -TaskPath '\VPNTE\' -ErrorAction Stop
    # Task Scheduler normalizes SYSTEM to a localized name (e.g. on Russian Windows).
    # Compare the resolved identity, never a language-dependent account spelling.
    if ((Resolve-RecoveryPrincipalSid $task.Principal.UserId) -ne 'S-1-5-18' -or $task.Principal.RunLevel -ne 'Highest' -or @($task.Actions).Count -ne 1 -or $task.Actions.Execute -ne $action.Execute -or $task.Actions.Arguments -ne $arguments -or @($task.Triggers).Count -ne 1 -or $task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger') { throw 'Recovery task read-back mismatch' }
    Unregister-ScheduledTask -TaskName 'VPNTE Boot Recovery' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output 'RECOVERY_TASK_VERIFIED'
    exit 0
}

try {
    Assert-TrustedArtifact (Join-Path $programData 'VPNTE') $true
    Assert-TrustedArtifact $trustedManifestDir $true
} catch {
    Write-Warning 'Recovery storage is untrusted; no system changes are permitted'
    exit 1
}
$strictRequired = $false
$firewallManifest = $null
try {
    $policy = Read-TrustedManifest 'recovery-policy.json'
    if ($policy -and $policy.strictMode -isnot [bool]) { throw 'Invalid strict policy' }
    $strictRequired = $policy -and $policy.strictMode
    $firewallManifest = Read-TrustedManifest 'firewall.json'
    if ($firewallManifest) {
        if ($firewallManifest.strictMode -isnot [bool] -or $firewallManifest.phase -notin @('prepared','active') -or @($firewallManifest.savedProfiles).Count -ne 3) { throw 'Invalid firewall snapshot' }
        $names = @()
        foreach ($p in $firewallManifest.savedProfiles) {
            if ($p.name -notin @('Domain','Private','Public') -or $p.name -in $names -or $p.defaultOutbound -notin @('Allow','Block','NotConfigured')) { throw 'Invalid firewall profile or policy' }
            $names += $p.name
        }
        $strictRequired = $strictRequired -or $firewallManifest.strictMode
    }
} catch {
    $strictRequired = $true
    $hasWarnings = $true
    Log "SECURITY: invalid firewall recovery data, retaining Block"
}
if ($strictRequired) {
    # No Allow rules or adapter/DNS cleanup may turn strict protection into fail-open.
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block -ErrorAction Stop
    Log 'Strict protection retained until explicit user action'
    Write-RecoveryReport 'strict-retained'
    exit 0
}
$candidatePaths = @((Join-Path $trustedManifestDir 'latest-physical-adapter-lockdown.json'))
$adapterManifestPath = $null
$adapterManifest = $null
try {
    $adapterManifest = Read-TrustedManifest 'latest-physical-adapter-lockdown.json'
    if ($adapterManifest) {
        if (-not $adapterManifest.adapters -or @($adapterManifest.adapters).Count -gt 256) { throw 'Invalid adapter manifest' }
        foreach ($a in $adapterManifest.adapters) {
            if ($a.ifIndex -le 0 -or $a.alias -isnot [string] -or $a.ipv6Enabled -isnot [bool] -or $a.forcedIpv6Off -isnot [bool] -or $a.interfaceGuid -notmatch '^\{?[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\}?$') { throw 'Invalid adapter snapshot' }
            foreach ($ip in @($a.ipv4DnsServers) + @($a.forcedDnsTo)) {
                if ($ip) { $parsedIP = $null; if (-not [Net.IPAddress]::TryParse([string]$ip, [ref]$parsedIP)) { throw 'Invalid DNS snapshot' } }
            }
        }
        $adapterManifestPath = $candidatePaths[0]
    }
} catch { $adapterManifest = $null; $hasWarnings = $true; Log 'SECURITY: rejected adapter manifest' }

function Get-ManifestAdapter($adapter) {
    if (-not $adapterManifest -or -not $adapterManifest.adapters) { return $null }
    foreach ($entry in @($adapterManifest.adapters)) {
        if ([string]$entry.interfaceGuid -eq [string]$adapter.InterfaceGuid) { return $entry }
    }
    return $null
}

function Get-RecoveryRegistryKey($keyPath) {
    return [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($keyPath)
}
function Restore-RegValue($key, $name, $snapshot, $tag) {
    $registryKey=$null
    try {
        if (-not $snapshot -or $snapshot.exists -isnot [bool]) { throw 'Missing registry ownership snapshot' }
        $expected=0
        if ($snapshot.exists) {
            if ($snapshot.type -ne 'REG_DWORD' -or [string]$snapshot.data -notmatch '^(0x[a-fA-F0-9]{1,8}|[0-9]{1,10})$') { throw 'Invalid DWORD snapshot' }
            $unsigned = if ([string]$snapshot.data -match '^0x') { [Convert]::ToUInt32(([string]$snapshot.data).Substring(2),16) } else { [uint32]$snapshot.data }
            $expected=[BitConverter]::ToInt32([BitConverter]::GetBytes($unsigned),0)
        }
        if ($key -notin @('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient','HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters') -or
            $name -notin @('DisableSmartNameResolution','DisableParallelAandAAAA')) { throw 'Unapproved DNS registry target' }
        $registryKey=Get-RecoveryRegistryKey ($key.Substring(5))
        if ($snapshot.exists) { $registryKey.SetValue($name,$expected,[Microsoft.Win32.RegistryValueKind]::DWord) }
        else { $registryKey.DeleteValue($name,$false) }
        $present=@($registryKey.GetValueNames()) -contains $name
        if ($present -ne $snapshot.exists) { throw 'Registry presence read-back mismatch' }
        if ($present -and ($registryKey.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord -or [int]$registryKey.GetValue($name) -ne $expected)) { throw 'Registry value read-back mismatch' }
        Log "Registry: restored and verified $tag"
    } catch { $script:hasWarnings=$true; Log "Registry: failed to restore $tag" }
    finally { if ($registryKey) { $registryKey.Close() } }
}

# 1. Firewall: restore ONLY proven VPNTE changes, never a foreign Block policy.
$vpnteRules = @(Get-NetFirewallRule -DisplayName 'VPNTE-killswitch*' -ErrorAction SilentlyContinue).Count
if ($firewallManifest -or $vpnteRules -gt 0) {
    $profiles = if ($firewallManifest) { $firewallManifest.savedProfiles } else {
        $hasWarnings = $true
        Log 'CRITICAL_SECURITY_EVENT: missing manifest; Allow fallback, protection unknown'
        @('Domain','Private','Public') | ForEach-Object { [pscustomobject]@{name=$_;defaultOutbound='Allow'} }
    }
    $firewallRecovered = $true
    foreach ($p in $profiles) {
        try {
            Set-NetFirewallProfile -Profile $p.name -DefaultOutboundAction $p.defaultOutbound -ErrorAction Stop
            if ([string](Get-NetFirewallProfile -Profile $p.name -ErrorAction Stop).DefaultOutboundAction -ne $p.defaultOutbound) { throw 'Firewall read-back mismatch' }
        } catch { $firewallRecovered = $false; $hasWarnings = $true; Log "Firewall profile restore failed: $($p.name)" }
    }
    try {
        Get-NetFirewallRule -DisplayName 'VPNTE-killswitch*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        if (@(Get-NetFirewallRule -DisplayName 'VPNTE-killswitch*' -ErrorAction SilentlyContinue).Count -gt 0) { throw 'VPNTE rules remain' }
    } catch { $firewallRecovered = $false; $hasWarnings = $true; Log 'Firewall rule cleanup failed' }
    if ($firewallRecovered -and $firewallManifest) { Remove-Item -LiteralPath (Join-Path $trustedManifestDir 'firewall.json') -Force -ErrorAction Stop }
}

# 2. DNS: reset any adapter still pinned to VPNTE resolver (192.168.250.254/253)
$vpnteDns = @('192.168.250.253', '192.168.250.254')
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
        $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth' -and
        $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00'
    }
foreach ($a in $adapters) {
    $manifestAdapter = Get-ManifestAdapter $a
    $dns = @(Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
    if ($manifestAdapter -and $manifestAdapter.forcedDnsTo -and @($manifestAdapter.forcedDnsTo).Count -gt 0) {
        if ($manifestAdapter.ipv4DnsSource -eq 'static' -and $manifestAdapter.ipv4DnsServers -and @($manifestAdapter.ipv4DnsServers).Count -gt 0) {
            Log "DNS: restoring static DNS on $($a.Name)"
            try {
                Set-DnsClientServerAddress -InterfaceAlias $a.Name -ServerAddresses @($manifestAdapter.ipv4DnsServers) -ErrorAction Stop
                $actualDns=@((Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
                if (($actualDns -join ',') -ne (@($manifestAdapter.ipv4DnsServers) -join ',')) { throw 'DNS read-back mismatch' }
            } catch {
                Log "DNS: failed to restore static DNS on $($a.Name) ($_)"
                $hasWarnings = $true
            }
        } else {
            Log "DNS: resetting DNS to DHCP on $($a.Name)"
            try {
                Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses -ErrorAction Stop
                $dnsKey='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+$a.InterfaceGuid
                $staticDns=[string](Get-ItemProperty -LiteralPath $dnsKey -Name NameServer -ErrorAction SilentlyContinue).NameServer
                if (-not [string]::IsNullOrWhiteSpace($staticDns)) { throw 'DHCP DNS read-back mismatch' }
            } catch {
                Log "DNS: failed to reset DNS to DHCP on $($a.Name) ($_)"
                $hasWarnings = $true
            }
        }
    }
    # 3. IPv6: re-enable only when the manifest says VPNTE disabled it.
    if ($manifestAdapter -and $manifestAdapter.forcedIpv6Off -eq $true -and $manifestAdapter.ipv6Enabled -eq $true) {
        Log "IPv6: re-enabling on $($a.Name)"
        try {
            Enable-NetAdapterBinding -InterfaceAlias $a.Name -ComponentID ms_tcpip6 -ErrorAction Stop
            if (-not (Get-NetAdapterBinding -InterfaceAlias $a.Name -ComponentID ms_tcpip6 -ErrorAction Stop).Enabled) { throw 'IPv6 binding read-back mismatch' }
        } catch {
            Log "IPv6: failed to re-enable ms_tcpip6 on $($a.Name) ($_)"
            $hasWarnings = $true
        }
    }
}

if ($adapterManifest) {
    foreach ($entry in @($adapterManifest.adapters)) {
        if (-not @($adapters | Where-Object { [string]$_.InterfaceGuid -eq [string]$entry.interfaceGuid }).Count) {
            $hasWarnings=$true; Log 'Owned physical adapter not found; snapshot retained'
        }
    }
}

# 4. Transition adapters: restore only known prior state.
if ($adapterManifest -and $adapterManifest.transitionAdapters) {
    $t = $adapterManifest.transitionAdapters
    if ($t.teredoType -in @('disabled','default','client','enterpriseclient','natclient','server')) {
        netsh interface teredo set state type=$($t.teredoType) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Log "Transition adapters: failed to restore teredo state (exit code $LASTEXITCODE)"
            $hasWarnings = $true
        }
    }
    if ($t.sixToFourState -in @('disabled','default','enabled')) {
        netsh interface 6to4 set state state=$($t.sixToFourState) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Log "Transition adapters: failed to restore 6to4 state (exit code $LASTEXITCODE)"
            $hasWarnings = $true
        }
    }
    if ($t.isatapState -in @('disabled','default','enabled')) {
        netsh interface isatap set state state=$($t.isatapState) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Log "Transition adapters: failed to restore isatap state (exit code $LASTEXITCODE)"
            $hasWarnings = $true
        }
    }
    Log "Transition adapters: restored from manifest where known"
}

# 5. Registry: restore pre-existing DNS policy values, or delete app-created ones.
if ($adapterManifest -and $adapterManifest.dnsRegistryPolicy) {
    Restore-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "DisableSmartNameResolution" $adapterManifest.dnsRegistryPolicy.smartNameResolution "DisableSmartNameResolution"
    Restore-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "DisableParallelAandAAAA" $adapterManifest.dnsRegistryPolicy.parallelAandAAAA "DisableParallelAandAAAA"
} else {
    Log "Registry: preserved DNS policy keys (no manifest and no orphaned VPNTE rules detected)"
}

# 6. DNS cache flush
try {
    Clear-DnsClientCache -ErrorAction Stop
    Log "DNS cache: flushed"
} catch {
    Log "DNS cache: flush warning ($_)"
}

# 7. Restore only the exact typed baseline, in its recorded user's hive.
# A SYSTEM HKCU is not the interactive user's HKCU. Use the exact SID if loaded;
# otherwise mount that SID's registered NTUSER.DAT temporarily, never sweep HKU.
$baseline = $null
$mountedHive = $null
$userHive = $null
try {
    $baseline = Read-TrustedManifest 'latest-tun-network-baseline.json'
    if ($baseline) {
        if ($baseline.userSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or @($baseline.values).Count -ne 9) { throw 'Invalid baseline identity or values' }
        $targets = @{
            internet=@{key='Software\Microsoft\Windows\CurrentVersion\Internet Settings';names=@('ProxyEnable','ProxyServer','AutoConfigURL','AutoDetect')}
            environment=@{key='Environment';names=@('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')}
            winhttp=@{key='SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections';names=@('WinHttpSettings')}
        }
        $seen = @{}
        foreach ($v in @($baseline.values)) {
            $id = [string]$v.target + '/' + [string]$v.name
            if (-not $targets.ContainsKey([string]$v.target) -or $v.name -cnotin $targets[[string]$v.target].names -or $seen.ContainsKey($id) -or $v.exists -isnot [bool]) { throw 'Invalid baseline target' }
            $seen[$id]=$true
            if (-not $v.exists) {
                if ($null -ne $v.kind -or $null -ne $v.data) { throw 'Invalid absent registry snapshot' }
                continue
            }
            switch ($v.kind) {
                {$_ -in @('String','ExpandString')} { if ($v.data -isnot [string] -or $v.data.Length -gt 65536) { throw 'Invalid string' } }
                'DWord' { if ($v.data -isnot [long] -and $v.data -isnot [int]) { throw 'Invalid DWORD' }; $null=[int]$v.data }
                'QWord' { if ($v.data -isnot [string] -or $v.data -notmatch '^-?\d{1,19}$') { throw 'Invalid QWORD' }; $null=[long]$v.data }
                'Binary' { if ($v.data -isnot [array] -or $v.data.Count -gt 65536) { throw 'Invalid binary' }; foreach($b in $v.data){ if(($b -isnot [int] -and $b -isnot [long]) -or $b -lt 0 -or $b -gt 255){throw 'Invalid byte'} } }
                'MultiString' { if ($v.data -isnot [array] -or $v.data.Count -gt 1024) { throw 'Invalid multistring' }; foreach($x in $v.data){if($x -isnot [string] -or $x.Length -gt 65536){throw 'Invalid multistring item'}} }
                default { throw 'Unsupported registry type' }
            }
        }
        $sid = [string]$baseline.userSid
        $userHive = [Microsoft.Win32.Registry]::Users.OpenSubKey($sid,$true)
        if (-not $userHive) {
            $profileKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid
            $profilePath = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath)
            if ($profilePath -notmatch '^[a-zA-Z]:\\' -or $profilePath -match '\\\.\.\\') { throw 'Invalid profile path' }
            $hivePath = Join-Path $profilePath 'NTUSER.DAT'
            foreach ($path in @($profilePath,$hivePath)) {
                $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse user hive rejected' }
            }
            $mountName = 'VPNTE-Recovery-' + [Guid]::NewGuid().ToString('N')
            & reg.exe load ('HKU\'+$mountName) $hivePath | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Unable to mount owning user hive' }
            $mountedHive=$mountName
            $userHive=[Microsoft.Win32.Registry]::Users.OpenSubKey($mountName,$true)
            if (-not $userHive) { throw 'Mounted user hive not readable' }
        }
        $baselineRecovered=$true
        foreach ($v in @($baseline.values)) {
            $key=$null
            try {
                $base=if($v.target -eq 'winhttp'){[Microsoft.Win32.Registry]::LocalMachine}else{$userHive}
                $key=$base.CreateSubKey($targets[[string]$v.target].key)
                if($v.exists){
                    $data=$v.data
                    switch($v.kind){
                        'DWord' {$data=[int]$v.data}
                        'QWord' {$data=[long]$v.data}
                        'Binary' {$data=[byte[]]@($v.data)}
                        'MultiString' {$data=[string[]]@($v.data)}
                    }
                    $key.SetValue($v.name,$data,[Enum]::Parse([Microsoft.Win32.RegistryValueKind],[string]$v.kind))
                }else{$key.DeleteValue($v.name,$false)}
                $exists=@($key.GetValueNames()) -contains $v.name
                if($exists -ne $v.exists){throw 'Registry presence read-back mismatch'}
                if($exists){
                    $kind=[string]$key.GetValueKind($v.name)
                    $actual=$key.GetValue($v.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if($kind -eq 'QWord'){$actual=[string]$actual}
                    if($kind -in @('Binary','MultiString')){$actual=@($actual)}
                    if($kind -cne $v.kind -or ($actual|ConvertTo-Json -Compress -Depth 5) -cne ($v.data|ConvertTo-Json -Compress -Depth 5)){throw 'Registry value read-back mismatch'}
                }
                Log ('Baseline restored: '+$v.target+'/'+$v.name)
            }catch{$baselineRecovered=$false;$hasWarnings=$true;Log ('Baseline step failed: '+$v.target+'/'+$v.name)}
            finally{if($key){$key.Close()}}
        }
    }
} catch { $hasWarnings=$true; $baselineRecovered=$false; Log 'Baseline recovery failed; trusted snapshot retained' }
finally {
    if($userHive){$userHive.Close()}
    if($mountedHive){
        [GC]::Collect();[GC]::WaitForPendingFinalizers()
        & reg.exe unload ('HKU\'+$mountedHive) | Out-Null
        if($LASTEXITCODE -ne 0){$hasWarnings=$true;$baselineRecovered=$false;Log 'Owning user hive unload failed'}
    }
}
if($baseline -and $baselineRecovered){Remove-Item -LiteralPath (Join-Path $trustedManifestDir 'latest-tun-network-baseline.json') -Force -ErrorAction Stop}

# 8. Remove only the exact recorded VPNTE adapter (stable GUID + driver + subnet).
try {
    $tunOwner = Read-TrustedManifest 'tun-owner.json'
    if ($tunOwner) {
        if ($tunOwner.interfaceGuid -notmatch '^\{?[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\}?$') { throw 'Invalid TUN ownership GUID' }
        $staleTuns = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
            [string]$_.InterfaceGuid -eq $tunOwner.interfaceGuid
        })
        foreach ($tun in $staleTuns) {
            if ($tun.DriverDescription -notmatch '^Wintun\b' -or $tun.PnPDeviceID -notlike 'SWD\Wintun\*') { throw 'TUN ownership driver mismatch' }
            $ownedIP = @(Get-NetIPAddress -InterfaceIndex $tun.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq '192.168.250.253' -and $_.PrefixLength -eq 30 })
            if ($ownedIP.Count -eq 0) { throw 'TUN ownership address mismatch' }
            try { Remove-NetAdapter -Name $tun.Name -Confirm:$false -ErrorAction Stop }
            catch { Disable-NetAdapter -Name $tun.Name -Confirm:$false -ErrorAction Stop }
        }
        Remove-Item -LiteralPath (Join-Path $trustedManifestDir 'tun-owner.json') -Force -ErrorAction Stop
    }
} catch { $hasWarnings = $true; Log 'TUN recovery failed; ownership record preserved' }

if ($adapterManifest -and -not $hasWarnings -and -not $script:hasWarnings) {
    foreach ($cp in $candidatePaths) {
        if (Test-Path $cp) {
            try {
                $candidate = Get-Content -LiteralPath $cp -Raw | ConvertFrom-Json
                if (($candidate | ConvertTo-Json -Depth 30 -Compress) -ne ($adapterManifest | ConvertTo-Json -Depth 30 -Compress)) { continue }
            } catch { $hasWarnings = $true; continue }
            try {
                Remove-Item $cp -Force -ErrorAction Stop
                Log "Adapter lockdown manifest: removed $cp"
            } catch {
                Log "Adapter lockdown manifest: remove failed for $cp ($_)"
                $hasWarnings = $true
            }
        }
    }
} elseif ($adapterManifest) {
    Log "Adapter lockdown manifest: preserved because recovery finished with warnings"
}

if ($hasWarnings) {
    Log "=== Boot-time recovery complete (with warnings) ==="
} else {
    Log "=== Boot-time recovery complete ==="
}

Write-RecoveryReport $(if ($hasWarnings -or $script:hasWarnings) { 'warnings' } else { 'restored' })
if ($hasWarnings -or $script:hasWarnings) { exit 1 }
