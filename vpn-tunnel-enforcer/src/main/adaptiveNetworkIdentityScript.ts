// AT-10-007: fixed read only; names stay in memory until HMAC, never in logs.
export const ADAPTIVE_NETWORK_IDENTITY_SCRIPT = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$namespace = 'root/StandardCimv2'
# Raw CIM avoids cold NetAdapter/NetTCPIP module imports. Match Get-NetAdapter's
# derived Status/MacAddress and default visible-adapter selection explicitly.
$adapters = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_NetAdapter -ErrorAction Stop | Where-Object {
  -not $_.Hidden -and $_.InterfaceOperationalStatus -eq 1 -and
  $_.NetworkAddresses -and $_.NetworkAddresses[0] -and
  $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth'
})
$allProfiles = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_NetConnectionProfile -ErrorAction Stop)
# Provider enumeration keeps the default compartment, as Get-NetRoute does.
# Never include a saved but inactive gateway in the current network identity.
$allRoutes = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_NetRoute -Filter "Store = 1 AND (DestinationPrefix = '0.0.0.0/0' OR DestinationPrefix = '::/0')" -ErrorAction Stop)
$rows = @()
foreach ($a in $adapters) {
  $profiles = @($allProfiles | Where-Object { $_.InterfaceIndex -eq $a.InterfaceIndex -and $_.Name } | ForEach-Object {
    if ($_.InstanceID) { [string]$_.Name + '|' + [string]$_.InstanceID } else { [string]$_.Name }
  })
  $gateways = @($allRoutes | Where-Object {
    $_.InterfaceIndex -eq $a.InterfaceIndex -and $_.NextHop -and $_.NextHop -notin @('0.0.0.0', '::')
  } | ForEach-Object { [string]$_.NextHop })
  if ($profiles.Count -or $gateways.Count) {
    $rows += [pscustomobject]@{alias=[string]$a.Name;guid=[string]$a.InterfaceGuid;profiles=$profiles;gateways=$gateways}
  }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 4
`
