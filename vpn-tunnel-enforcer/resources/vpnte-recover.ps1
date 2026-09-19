# VPN Tunnel Enforcer — Boot-time Network Recovery
# Runs via scheduled task at system startup (before user logon).
# Recovers from a BSOD/crash that left the firewall blocking, DNS pinned,
# IPv6 disabled, or proxy settings wiped.

$ErrorActionPreference = 'SilentlyContinue'

$programData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$logDir = Join-Path $programData 'VPN-Tunnel-Enforcer'
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

# Search candidate locations for adapter lockdown manifest:
# 1. ProgramData (canonical cross-session / SYSTEM-accessible location)
# 2. ProgramData with space in name
# 3. Current user / SYSTEM APPDATA
# 4. User profile directories under C:\Users\*\AppData\Roaming\vpn-tunnel-enforcer
$candidatePaths = @(
    (Join-Path $programData 'VPN-Tunnel-Enforcer\latest-physical-adapter-lockdown.json'),
    (Join-Path $programData 'VPN Tunnel Enforcer\latest-physical-adapter-lockdown.json')
)
if ($env:APPDATA) {
    $candidatePaths += (Join-Path $env:APPDATA 'vpn-tunnel-enforcer\latest-physical-adapter-lockdown.json')
}
$userProfiles = Get-ChildItem 'C:\Users\*\AppData\Roaming\vpn-tunnel-enforcer\latest-physical-adapter-lockdown.json' -ErrorAction SilentlyContinue
if ($userProfiles) {
    foreach ($p in $userProfiles) {
        $candidatePaths += $p.FullName
    }
}

$adapterManifestPath = $null
$adapterManifest = $null
foreach ($cp in $candidatePaths) {
    if (Test-Path $cp) {
        try {
            $parsed = Get-Content $cp -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($parsed) {
                $adapterManifestPath = $cp
                $adapterManifest = $parsed
                Log "Adapter lockdown manifest: loaded from $cp"
                break
            }
        } catch {
            Log "Adapter lockdown manifest: failed to read $cp ($_)"
        }
    }
}

function Get-ManifestAdapter($adapter) {
    if (-not $adapterManifest -or -not $adapterManifest.adapters) { return $null }
    foreach ($entry in @($adapterManifest.adapters)) {
        if ($entry.ifIndex -eq $adapter.ifIndex -or $entry.alias -eq $adapter.Name) { return $entry }
    }
    return $null
}

function Restore-RegValue($key, $name, $snapshot, $tag) {
    try {
        if ($snapshot -and $snapshot.exists -eq $true -and $snapshot.type -and $snapshot.data) {
            reg add $key /v $name /t $snapshot.type /d $snapshot.data /f 2>$null | Out-Null
            Log "Registry: restored $tag"
        } else {
            reg delete $key /v $name /f 2>$null | Out-Null
            Log "Registry: removed VPNTE-created $tag"
        }
    } catch {
        Log "Registry: failed to restore $tag ($_)"
    }
}

# 1. Firewall: restore DefaultOutboundAction to Allow if no VPNTE rules exist
$blockProfiles = Get-NetFirewallProfile -Profile Domain,Private,Public |
    Where-Object { $_.DefaultOutboundAction -eq 'Block' }
$vpnteRules = Get-NetFirewallRule -DisplayName 'VPNTE-killswitch*' |
    Measure-Object | Select-Object -ExpandProperty Count
if ($blockProfiles -and $vpnteRules -eq 0) {
    Log "Firewall: DefaultOutboundAction=Block with no VPNTE rules — restoring Allow"
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
    Log "Firewall: restored"
}
if ($vpnteRules -gt 0) {
    Log "Firewall: removing $vpnteRules orphaned VPNTE-killswitch rules"
    Get-NetFirewallRule -DisplayName 'VPNTE-killswitch*' | Remove-NetFirewallRule
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
    Log "Firewall: rules removed, Allow restored"
}

# 2. DNS: reset any adapter still pinned to VPNTE resolver (192.168.250.254/253)
$vpnteDns = @('192.168.250.253', '192.168.250.254')
$adapters = Get-NetAdapter |
    Where-Object {
        $_.Status -eq 'Up' -and
        $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth' -and
        $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00'
    }
foreach ($a in $adapters) {
    $manifestAdapter = Get-ManifestAdapter $a
    $dns = @(Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4).ServerAddresses
    if ($manifestAdapter -and $manifestAdapter.forcedDnsTo -and @($manifestAdapter.forcedDnsTo).Count -gt 0) {
        if ($manifestAdapter.ipv4DnsSource -eq 'static' -and $manifestAdapter.ipv4DnsServers -and @($manifestAdapter.ipv4DnsServers).Count -gt 0) {
            Log "DNS: restoring static DNS on $($a.Name)"
            Set-DnsClientServerAddress -InterfaceAlias $a.Name -ServerAddresses @($manifestAdapter.ipv4DnsServers)
        } else {
            Log "DNS: resetting DNS to DHCP on $($a.Name)"
            Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses
        }
    } elseif (-not $adapterManifest -and ($dns | Where-Object { $vpnteDns -contains $_ })) {
        Log "DNS: resetting orphaned DNS on $($a.Name) without manifest (was: $($dns -join ','))"
        Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses
    }
    # 3. IPv6: re-enable only when the manifest says VPNTE disabled it.
    if ($manifestAdapter -and $manifestAdapter.forcedIpv6Off -eq $true -and $manifestAdapter.ipv6Enabled -eq $true) {
        Log "IPv6: re-enabling on $($a.Name)"
        Enable-NetAdapterBinding -InterfaceAlias $a.Name -ComponentID ms_tcpip6
    }
}

# 4. Transition adapters: restore only known prior state.
if ($adapterManifest -and $adapterManifest.transitionAdapters) {
    $t = $adapterManifest.transitionAdapters
    if ($t.teredoType -match '^[a-z]+$') { netsh interface teredo set state type=$($t.teredoType) | Out-Null }
    if ($t.sixToFourState -match '^[a-z]+$') { netsh interface 6to4 set state state=$($t.sixToFourState) | Out-Null }
    if ($t.isatapState -match '^[a-z]+$') { netsh interface isatap set state state=$($t.isatapState) | Out-Null }
    Log "Transition adapters: restored from manifest where known"
}

# 5. Registry: restore pre-existing DNS policy values, or delete app-created ones.
if ($adapterManifest -and $adapterManifest.dnsRegistryPolicy) {
    Restore-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "DisableSmartNameResolution" $adapterManifest.dnsRegistryPolicy.smartNameResolution "DisableSmartNameResolution"
    Restore-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "DisableParallelAandAAAA" $adapterManifest.dnsRegistryPolicy.parallelAandAAAA "DisableParallelAandAAAA"
} elseif ($vpnteRules -gt 0) {
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /f 2>$null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /f 2>$null
    Log "Registry: VPNTE DNS policy keys removed without manifest (orphaned VPNTE rules detected)"
} else {
    Log "Registry: preserved DNS policy keys (no manifest and no orphaned VPNTE rules detected)"
}

# 6. DNS cache flush
Clear-DnsClientCache
Log "DNS cache: flushed"

if ($adapterManifest) {
    foreach ($cp in $candidatePaths) {
        if (Test-Path $cp) {
            try {
                Remove-Item $cp -Force
                Log "Adapter lockdown manifest: removed $cp"
            } catch {
                Log "Adapter lockdown manifest: remove failed for $cp ($_)"
            }
        }
    }
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
            reg delete $regTarget /v $key /f 2>$null
        } elseif ($val) {
            Log "Env: preserving non-VPNTE $key=$val in $envPath"
        }
    }
    $noProxyKeys = @('NO_PROXY', 'no_proxy')
    foreach ($key in $noProxyKeys) {
        $val = (Get-ItemProperty -Path $envPath -Name $key -ErrorAction SilentlyContinue).$key
        if ($val -and ($val -eq 'localhost,127.0.0.1,::1')) {
            Log "Env: removing VPNTE default $key=$val from $envPath"
            reg delete $regTarget /v $key /f 2>$null
        } elseif ($val) {
            Log "Env: preserving non-VPNTE $key=$val in $envPath"
        }
    }
}

Clean-VpnteProxyEnv 'HKCU:\Environment'

# When running as SYSTEM, also inspect loaded user profiles under HKEY_USERS
$loadedUsers = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -notmatch '_Classes$' -and $_.PSChildName -notmatch '^(S-1-5-18|S-1-5-19|S-1-5-20|\.DEFAULT)$' }
foreach ($u in $loadedUsers) {
    $userEnvPath = "Registry::HKEY_USERS\$($u.PSChildName)\Environment"
    if (Test-Path $userEnvPath) {
        Clean-VpnteProxyEnv $userEnvPath
    }
}

# 8. Remove stale TUN adapter if present
$tunAliases = @('Ethernet 5', 'VPNTE-TUN')
foreach ($alias in $tunAliases) {
    $tun = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
    if ($tun) {
        Log "TUN: removing stale adapter '$alias'"
        try { Remove-NetAdapter -Name $alias -Confirm:$false } catch {
            try { Disable-NetAdapter -Name $alias -Confirm:$false } catch {}
        }
    }
}

Log "=== Boot-time recovery complete ==="
