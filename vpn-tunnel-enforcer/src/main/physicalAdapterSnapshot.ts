/** AT-03-005/006/010: fixed adapter selection; DNS discovery is not a lockdown proof. */
import { ALL_KNOWN_ALIASES } from './tunAdapter'

const ADAPTER_EXCLUSION_PATTERN = 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth'

const PHYSICAL_ADAPTER_SELECTION = `
$knownAliases = @(${ALL_KNOWN_ALIASES.map(alias => `'${alias.replace(/'/g, "''")}'`).join(',')})
$adapters = Get-NetAdapter |
  Where-Object {
    $_.Status -eq 'Up' -and
    $_.Name -notin $knownAliases -and
    $_.InterfaceDescription -notmatch '${ADAPTER_EXCLUSION_PATTERN}' -and
    $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00'
  }
`

export const PHYSICAL_ADAPTER_DNS_SCRIPT = `
$ErrorActionPreference = 'Stop'
${PHYSICAL_ADAPTER_SELECTION}
$rows = @(foreach ($a in $adapters) {
  $dns4 = (Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
  [pscustomobject]@{ ifIndex = [int]$a.ifIndex; alias = [string]$a.Name; ipv4Dns = @($dns4 | Where-Object { $_ }) }
})
$rows | ConvertTo-Json -Compress -Depth 3
`

export const PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT = `
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()
$knownAliases = @(${ALL_KNOWN_ALIASES.map(alias => `'${alias.replace(/'/g, "''")}'`).join(',')})
try {
  $namespace = 'root/StandardCimv2'
  $cimAdapters = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_NetAdapter -ErrorAction Stop | Where-Object {
    -not $_.Hidden -and
    $_.InterfaceOperationalStatus -eq 1 -and
    $_.Name -notin $knownAliases -and
    $_.InterfaceDescription -notmatch '${ADAPTER_EXCLUSION_PATTERN}' -and
    $_.PermanentAddress -and $_.PermanentAddress -ne '000000000000'
  })
  $allBindings6 = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_NetAdapterBindingSettingData -Filter "ComponentID = 'ms_tcpip6'" -ErrorAction Stop)
  $allDns = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_DNSClientServerAddress -Filter "AddressFamily = 2" -ErrorAction Stop)
  $allRoutes = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_NetRoute -Filter "Store = 1 AND (DestinationPrefix = '0.0.0.0/0' OR DestinationPrefix = '::/0')" -ErrorAction Stop)
  $allProfiles = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_NetConnectionProfile -ErrorAction Stop)

  foreach ($a in $cimAdapters) {
    $bind6 = $allBindings6 | Where-Object { $_.Name -eq $a.Name -or $_.InterfaceDescription -eq $a.InterfaceDescription } | Select-Object -First 1
    $dns4 = @(($allDns | Where-Object { $_.InterfaceIndex -eq $a.InterfaceIndex -or $_.InterfaceAlias -eq $a.Name }).ServerAddresses)
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

    $routes4 = @($allRoutes | Where-Object { $_.InterfaceIndex -eq $a.InterfaceIndex -and $_.DestinationPrefix -eq '0.0.0.0/0' })
    $gw4 = @($routes4.NextHop | Where-Object { $_ -and $_ -ne '0.0.0.0' })

    $profiles = @(($allProfiles | Where-Object { $_.InterfaceIndex -eq $a.InterfaceIndex }).Name | Where-Object { $_ })

    $isHotspotSubnet = [bool](
      ($dns4 | Where-Object { $_ -match '^192\\.168\\.(43|137|225|8)\\.' -or $_ -match '^172\\.20\\.10\\.' }) -or
      ($gw4 | Where-Object { $_ -match '^192\\.168\\.(43|137|225|8)\\.' -or $_ -match '^172\\.20\\.10\\.' })
    )
    $hasClatOrIpv6Only = [bool](
      ($allRoutes | Where-Object { $_.InterfaceIndex -eq $a.InterfaceIndex -and $_.DestinationPrefix -eq '::/0' }) -and
      (-not $routes4)
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
      ifIndex               = [int]$a.InterfaceIndex
      interfaceGuid         = [string]$a.InterfaceGuid
      alias                 = [string]$a.Name
      description           = [string]$a.InterfaceDescription
      ipv6Enabled           = [bool]($bind6 -and $bind6.Enabled)
      ipv4Dns               = @($dns4)
      gateways              = @($gw4)
      networkProfiles       = @($profiles)
      ipv4DnsSource         = $(if ([string]::IsNullOrWhiteSpace($nameServer)) { 'dhcp' } else { 'static' })
      isCellularOrTethering = $isCellularOrTether
    }
  }
} catch {
  $rows = @()
  ${PHYSICAL_ADAPTER_SELECTION}
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
    $routes4 = @(Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    $gw4 = @($routes4.NextHop)
    $profiles = @((Get-NetConnectionProfile -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue).Name)
    $isHotspotSubnet = [bool](
      ($dns4 | Where-Object { $_ -match '^192\\.168\\.(43|137|225|8)\\.' -or $_ -match '^172\\.20\\.10\\.' }) -or
      ($gw4 | Where-Object { $_ -match '^192\\.168\\.(43|137|225|8)\\.' -or $_ -match '^172\\.20\\.10\\.' })
    )
    $hasClatOrIpv6Only = [bool](
      (Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '::/0' -ErrorAction SilentlyContinue) -and
      (-not $routes4)
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
}
$rows | ConvertTo-Json -Compress -Depth 4
`

export const TRANSITION_ADAPTER_SNAPSHOT_SCRIPT = `
$teredo = $null
$sixToFour = $null
$isatap = $null
try {
  $t = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetTeredoConfiguration -ErrorAction Stop
  $s = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_Net6to4Configuration -ErrorAction Stop
  $i = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetISATAPConfiguration -ErrorAction Stop
  $teredoMap = @('default', 'relay', 'client', 'server', 'disabled', 'automatic', 'enterpriseclient', 'natawareclient')
  $stateMap = @('default', 'automatic', 'enabled', 'disabled')
  if ($null -ne $t.Type -and $t.Type -ge 0 -and $t.Type -lt $teredoMap.Length) { $teredo = 'Type : ' + $teredoMap[$t.Type] }
  if ($null -ne $s.State -and $s.State -ge 0 -and $s.State -lt $stateMap.Length) { $sixToFour = '6to4 Service State : ' + $stateMap[$s.State] }
  if ($null -ne $i.State -and $i.State -ge 0 -and $i.State -lt $stateMap.Length) { $isatap = 'ISATAP State : ' + $stateMap[$i.State] }
} catch {}
if (-not $teredo) { $teredo = (netsh interface teredo show state) -join [Environment]::NewLine }
if (-not $sixToFour) { $sixToFour = (netsh interface 6to4 show state) -join [Environment]::NewLine }
if (-not $isatap) { $isatap = (netsh interface isatap show state) -join [Environment]::NewLine }
[pscustomobject]@{
  teredo = $teredo
  sixToFour = $sixToFour
  isatap = $isatap
} | ConvertTo-Json -Compress
`
