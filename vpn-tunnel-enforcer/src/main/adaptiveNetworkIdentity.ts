import { execFile } from 'child_process'
import { isIP } from 'net'

export interface AdaptiveNetworkIdentity {
  alias: string
  guid: string
  profiles: string[]
  gateways: string[]
}

// Read only: never changes adapters/routes. Names exist only in memory until HMAC.
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

export async function readAdaptiveNetworkIdentity(): Promise<AdaptiveNetworkIdentity[] | null> {
  if (process.platform !== 'win32') return null
  try {
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
        Buffer.from(ADAPTIVE_NETWORK_IDENTITY_SCRIPT, 'utf16le').toString('base64')],
      { windowsHide: true, timeout: 4000, maxBuffer: 256 * 1024, encoding: 'utf8' },
      (error, stdout) => error ? reject(error) : resolve(stdout))
    })
    const parsed = JSON.parse(stdout.trim())
    const rows = Array.isArray(parsed) ? parsed : parsed && typeof parsed === 'object' ? [parsed] : []
    if (!rows.length || rows.some(row => typeof row.alias !== 'string' || typeof row.guid !== 'string'
      || !Array.isArray(row.profiles) || !Array.isArray(row.gateways)
      || ![...row.profiles, ...row.gateways].every(value => typeof value === 'string')
      || !row.profiles.length && !row.gateways.length)) return null
    return rows.map(row => {
      const gateways = row.gateways.filter((value: string) => isIP(value) === 4)
      return { alias: row.alias, guid: row.guid, profiles: [...new Set<string>(row.profiles)].sort(),
        gateways: [...new Set<string>(gateways.length ? gateways : row.gateways)].sort() }
    })
  } catch {
    // Unknown identity must not reuse or learn a decision for another network.
    return null
  }
}
