/** AT-03-005/006/010: fixed read-only adapter snapshot shared by both transports. */
import { ALL_KNOWN_ALIASES } from './tunAdapter'

export const PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT = `
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()
$knownAliases = @(${ALL_KNOWN_ALIASES.map(alias => `'${alias.replace(/'/g, "''")}'`).join(',')})
$adapters = Get-NetAdapter |
  Where-Object {
    $_.Status -eq 'Up' -and
    $_.Name -notin $knownAliases -and
    $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth' -and
    $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00'
  }
foreach ($a in $adapters) {
  $bind6 = Get-NetAdapterBinding -InterfaceAlias $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
  $dns4 = (Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
  if ($null -eq $dns4) { $dns4 = @() }
  $nameServer = ''
  try {
    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($a.InterfaceGuid)"
    $nameServer = [string]((Get-ItemProperty -Path $regPath -Name NameServer -ErrorAction SilentlyContinue).NameServer)
  } catch {}
  $desc = [string]$a.InterfaceDescription
  $name = [string]$a.Name
  $mediaType = [string]$a.MediaType
  $physMedia = [string]$a.PhysicalMediaType
  $gw4 = @((Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).NextHop)
  $profiles = @((Get-NetConnectionProfile -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue).Name)
  $isHotspotSubnet = [bool](
    ($dns4 | Where-Object { $_ -match '^192\\.168\\.(43|137|225|8)\\.' -or $_ -match '^172\\.20\\.10\\.' }) -or
    ($gw4 | Where-Object { $_ -match '^192\\.168\\.(43|137|225|8)\\.' -or $_ -match '^172\\.20\\.10\\.' })
  )
  $hasClatOrIpv6Only = [bool](
    (Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '::/0' -ErrorAction SilentlyContinue) -and
    (-not (Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue))
  )
  $isCellularOrTether = [bool](
    ($desc -match '\\b(rndis|cellular|mobile|wwan|lte|[345]g|modem|tether|tethering)\\b|remote ndis|apple mobile device') -or
    ($name -match '\\b(cellular|mobile|wwan|lte|[345]g|modem|tether|tethering)\\b') -or
    ($mediaType -match 'WWAN|WirelessWan') -or
    ($physMedia -match 'WWAN|WirelessWan') -or
    $isHotspotSubnet -or
    $hasClatOrIpv6Only
  )
  $rows += [pscustomobject]@{
    ifIndex      = [int]$a.ifIndex
    interfaceGuid = [string]$a.InterfaceGuid
    alias        = [string]$a.Name
    description  = [string]$a.InterfaceDescription
    ipv6Enabled  = [bool]($bind6 -and $bind6.Enabled)
    ipv4Dns      = @($dns4)
    gateways     = @($gw4)
    networkProfiles = @($profiles)
    ipv4DnsSource = $(if ([string]::IsNullOrWhiteSpace($nameServer)) { 'dhcp' } else { 'static' })
    isCellularOrTethering = $isCellularOrTether
  }
}
$rows | ConvertTo-Json -Compress -Depth 4
`
