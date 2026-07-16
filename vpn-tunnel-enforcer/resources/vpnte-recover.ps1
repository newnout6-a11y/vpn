# VPN Tunnel Enforcer — Boot-time Network Recovery
# Runs via scheduled task at system startup (before user logon).
# Recovers from a BSOD/crash that left the firewall blocking, DNS pinned,
# IPv6 disabled, or proxy settings wiped.

$ErrorActionPreference = 'SilentlyContinue'

$logFile = Join-Path $env:APPDATA 'VPN Tunnel Enforcer\recovery.log'
function Log([string]$msg) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $msg" | Out-File $logFile -Append -Encoding UTF8
}

Log "=== Boot-time recovery started ==="

$userData = Join-Path $env:APPDATA 'vpn-tunnel-enforcer'
$adapterManifestPath = Join-Path $userData 'latest-physical-adapter-lockdown.json'
$adapterManifest = $null
if (Test-Path $adapterManifestPath) {
    try {
        $adapterManifest = Get-Content $adapterManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Log "Adapter lockdown manifest: loaded"
    } catch {
        Log "Adapter lockdown manifest: failed to read ($_)"
        $adapterManifest = $null
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
} else {
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /f 2>$null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /f 2>$null
    Log "Registry: VPNTE DNS policy keys removed without manifest"
}

# 6. DNS cache flush
Clear-DnsClientCache
Log "DNS cache: flushed"

if ($adapterManifest) {
    try {
        Remove-Item $adapterManifestPath -Force
        Log "Adapter lockdown manifest: removed"
    } catch {
        Log "Adapter lockdown manifest: remove failed ($_)"
    }
}

# 7. Env proxy vars: remove orphaned setx HTTP_PROXY
$envKeys = @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
             'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
foreach ($key in $envKeys) {
    $val = (Get-ItemProperty -Path 'HKCU:\Environment' -Name $key -ErrorAction SilentlyContinue).$key
    if ($val) {
        Log "Env: removing orphaned $key=$val"
        reg delete "HKCU\Environment" /v $key /f 2>$null
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
