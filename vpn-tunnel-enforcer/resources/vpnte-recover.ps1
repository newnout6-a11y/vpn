param([switch]$RegisterTask)
# Registration is used by both the installer and application repair path.
if ($RegisterTask) {
    $ErrorActionPreference = 'Stop'
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
    if ($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Actions.Arguments -ne $arguments) { throw 'Recovery task read-back mismatch' }
    Unregister-ScheduledTask -TaskName 'VPNTE Boot Recovery' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output 'RECOVERY_TASK_VERIFIED'
    exit 0
}

# VPN Tunnel Enforcer — Boot-time Network Recovery
# Runs via scheduled task at system startup (before user logon).
# Recovers from a BSOD/crash that left the firewall blocking, DNS pinned,
# IPv6 disabled, or proxy settings wiped.

$hasWarnings = $false

$programData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$logDir = Join-Path $programData 'VPNTE\manifests'
if (-not (Test-Path $logDir)) {
    try { New-Item -Path $logDir -ItemType Directory -Force | Out-Null } catch {}
}
$logFile = Join-Path $logDir 'recovery.log'
if (-not (Test-Path (Split-Path $logFile -Parent))) {
    $logFile = Join-Path $env:TEMP 'vpnte-recovery.log'
}

function Log([string]$msg) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    try {
        "$ts $msg" | Out-File $logFile -Append -Encoding UTF8
    } catch {}
}

Log "=== Boot-time recovery started ==="

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
function Read-TrustedManifest($name) {
    $path = Join-Path $trustedManifestDir $name
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    Assert-TrustedArtifact $path $false
    if ((Get-Item -LiteralPath $path).Length -gt 1048576) { throw 'Recovery manifest size limit' }
    $value = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($value.schemaVersion -ne 1 -or $value.owner -ne 'VPNTE') { throw 'Unsupported recovery manifest schema' }
    return $value
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
            if ($a.ifIndex -le 0 -or $a.alias -isnot [string] -or $a.ipv6Enabled -isnot [bool]) { throw 'Invalid adapter snapshot' }
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
        if ($entry.ifIndex -eq $adapter.ifIndex -or $entry.alias -eq $adapter.Name) { return $entry }
    }
    return $null
}

function Restore-RegValue($key, $name, $snapshot, $tag) {
    try {
        if (-not $snapshot -or ($snapshot.exists -ne $true -and $snapshot.exists -ne $false)) {
            $script:hasWarnings = $true
            Log "Registry: missing snapshot for $tag; preserved current value"
            return
        }
        if ($snapshot.exists -eq $true) {
            if (-not $snapshot.type -or $null -eq $snapshot.data) {
                $script:hasWarnings = $true
                return
            }
            reg add $key /v $name /t $snapshot.type /d $snapshot.data /f 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Log "Registry: restored $tag"
            } else {
                Log "Registry: failed to restore $tag (exit code $LASTEXITCODE)"
                $script:hasWarnings = $true
            }
        } else {
            $delOutput = reg delete $key /v $name /f 2>&1
            if ($LASTEXITCODE -eq 0) {
                Log "Registry: removed VPNTE-created $tag"
            } elseif ($delOutput -match 'unable to find|не удается найти') {
                Log "Registry: VPNTE-created $tag was already absent"
            } else {
                Log "Registry: failed to remove VPNTE-created $tag (exit code $LASTEXITCODE, $delOutput)"
                $script:hasWarnings = $true
            }
        }
    } catch {
        Log "Registry: failed to restore $tag ($_)"
        $script:hasWarnings = $true
    }
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
        $_.Status -eq 'Up' -and
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
            } catch {
                Log "DNS: failed to restore static DNS on $($a.Name) ($_)"
                $hasWarnings = $true
            }
        } else {
            Log "DNS: resetting DNS to DHCP on $($a.Name)"
            try {
                Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses -ErrorAction Stop
            } catch {
                Log "DNS: failed to reset DNS to DHCP on $($a.Name) ($_)"
                $hasWarnings = $true
            }
        }
    } elseif (-not $adapterManifest -and ($dns | Where-Object { $vpnteDns -contains $_ })) {
        Log "DNS: resetting orphaned DNS on $($a.Name) without manifest (was: $($dns -join ','))"
        try {
            Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses -ErrorAction Stop
        } catch {
            Log "DNS: failed to reset orphaned DNS on $($a.Name) ($_)"
            $hasWarnings = $true
        }
    }
    # 3. IPv6: re-enable only when the manifest says VPNTE disabled it.
    if ($manifestAdapter -and $manifestAdapter.forcedIpv6Off -eq $true -and $manifestAdapter.ipv6Enabled -eq $true) {
        Log "IPv6: re-enabling on $($a.Name)"
        try {
            Enable-NetAdapterBinding -InterfaceAlias $a.Name -ComponentID ms_tcpip6 -ErrorAction Stop
        } catch {
            Log "IPv6: failed to re-enable ms_tcpip6 on $($a.Name) ($_)"
            $hasWarnings = $true
        }
    }
}

# 4. Transition adapters: restore only known prior state.
if ($adapterManifest -and $adapterManifest.transitionAdapters) {
    $t = $adapterManifest.transitionAdapters
    if ($t.teredoType -match '^[a-z]+$') {
        netsh interface teredo set state type=$($t.teredoType) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Log "Transition adapters: failed to restore teredo state (exit code $LASTEXITCODE)"
            $hasWarnings = $true
        }
    }
    if ($t.sixToFourState -match '^[a-z]+$') {
        netsh interface 6to4 set state state=$($t.sixToFourState) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Log "Transition adapters: failed to restore 6to4 state (exit code $LASTEXITCODE)"
            $hasWarnings = $true
        }
    }
    if ($t.isatapState -match '^[a-z]+$') {
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
} elseif ($vpnteRules -gt 0) {
    $del1 = reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /f 2>&1
    if ($LASTEXITCODE -ne 0 -and $del1 -notmatch 'unable to find|не удается найти') {
        Log "Registry: failed to remove DisableSmartNameResolution ($del1)"
        $hasWarnings = $true
    }
    $del2 = reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /f 2>&1
    if ($LASTEXITCODE -ne 0 -and $del2 -notmatch 'unable to find|не удается найти') {
        Log "Registry: failed to remove DisableParallelAandAAAA ($del2)"
        $hasWarnings = $true
    }
    Log "Registry: VPNTE DNS policy keys removed without manifest (orphaned VPNTE rules detected)"
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

# 7. Env proxy vars: remove only orphaned local/VPNTE proxy settings, preserving custom/corporate proxies
function Clean-VpnteProxyEnv($envPath) {
    $regTarget = $envPath -replace '^Registry::', ''
    if ($regTarget -match '^[A-Za-z0-9_]+:') {
        $regTarget = $regTarget -replace ':', ''
    }
    $proxyKeys = @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')
    foreach ($key in $proxyKeys) {
        $val = (Get-ItemProperty -Path $envPath -Name $key -ErrorAction SilentlyContinue).$key
        if ($val -and ($val -match '^(https?|socks5h?)://(127\.0\.0\.1|localhost)(:\d+)?/?$')) {
            Log "Env: removing orphaned VPNTE $key=$val from $envPath"
            $delRes = reg delete $regTarget /v $key /f 2>&1
            if ($LASTEXITCODE -ne 0 -and $delRes -notmatch 'unable to find|не удается найти') {
                Log "Env: failed to remove $key from $regTarget ($delRes)"
                $script:hasWarnings = $true
            }
        } elseif ($val) {
            Log "Env: preserving non-VPNTE $key=$val in $envPath"
        }
    }
    $noProxyKeys = @('NO_PROXY', 'no_proxy')
    foreach ($key in $noProxyKeys) {
        $val = (Get-ItemProperty -Path $envPath -Name $key -ErrorAction SilentlyContinue).$key
        if ($val -and ($val -eq 'localhost,127.0.0.1,::1')) {
            Log "Env: removing VPNTE default $key=$val from $envPath"
            $delRes = reg delete $regTarget /v $key /f 2>&1
            if ($LASTEXITCODE -ne 0 -and $delRes -notmatch 'unable to find|не удается найти') {
                Log "Env: failed to remove $key from $regTarget ($delRes)"
                $script:hasWarnings = $true
            }
        } elseif ($val) {
            Log "Env: preserving non-VPNTE $key=$val in $envPath"
        }
    }
}

# User environment recovery requires an exact ownership snapshot; broad HKEY_USERS cleanup is intentionally disabled.

# 8. Remove only the exact recorded VPNTE adapter (stable GUID + driver + subnet).
try {
    $tunOwner = Read-TrustedManifest 'tun-owner.json'
    if ($tunOwner) {
        if ($tunOwner.interfaceGuid -notmatch '^\{?[a-fA-F0-9-]{36}\}?$') { throw 'Invalid TUN ownership GUID' }
        $staleTuns = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
            [string]$_.InterfaceGuid -eq $tunOwner.interfaceGuid -and $_.InterfaceDescription -match 'Wintun'
        })
        foreach ($tun in $staleTuns) {
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
