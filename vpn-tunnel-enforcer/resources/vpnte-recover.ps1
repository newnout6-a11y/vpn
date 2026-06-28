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
    $dns = @(Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4).ServerAddresses
    if ($dns | Where-Object { $vpnteDns -contains $_ }) {
        Log "DNS: resetting orphaned DNS on $($a.Name) (was: $($dns -join ','))"
        Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses
    }
    # 3. IPv6: re-enable if disabled
    $ipv6Binding = Get-NetAdapterBinding -InterfaceAlias $a.Name -ComponentID ms_tcpip6
    if ($ipv6Binding -and $ipv6Binding.Enabled -eq $false) {
        Log "IPv6: re-enabling on $($a.Name)"
        Enable-NetAdapterBinding -InterfaceAlias $a.Name -ComponentID ms_tcpip6
    }
}

# 4. Transition adapters: restore to default
netsh interface teredo set state type=default | Out-Null
netsh interface 6to4 set state state=default | Out-Null
netsh interface isatap set state state=default | Out-Null
Log "Transition adapters: restored to default"

# 5. Registry: remove VPNTE DNS policy keys
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /f 2>$null
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /f 2>$null
Log "Registry: VPNTE DNS policy keys removed"

# 6. DNS cache flush
Clear-DnsClientCache
Log "DNS cache: flushed"

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
