/** Fixed Windows definitions only; every caller still takes fresh OS snapshots. */
export const NETWORK_MODULE_PREPARATION_PS = `
$networkModulesReady = $false
function Initialize-VpnteNetworkModules {
  if ($script:networkModulesReady) { return }
  $modulesRoot = Join-Path $PSHOME 'Modules'
  try {
    foreach ($pair in @(
      @('NetAdapter','MSFT_NetAdapter.cmdletDefinition.cdxml'),
      @('NetAdapter','MSFT_NetAdapterBinding.cmdletDefinition.cdxml'),
      @('DnsClient','MSFT_DnsClientServerAddress.cdxml'), @('DnsClient','MSFT_DnsClientCache.cdxml'),
      @('NetTCPIP','MSFT_NetIPInterface.cdxml'), @('NetTCPIP','MSFT_NetIPAddress.cdxml'),
      @('NetTCPIP','MSFT_NetRoute.cdxml'), @('NetConnection','MSFT_NetConnectionProfile.cdxml')
    )) { Import-Module (Join-Path (Join-Path $modulesRoot $pair[0]) $pair[1]) -Global -ErrorAction Stop }
    foreach ($pair in @(
      @('NetAdapter','NetAdapter.Types.ps1xml'), @('DnsClient','DnsCmdlets.Types.ps1xml'),
      @('DnsClient','DnsConfig.Types.ps1xml'), @('DnsClient','DnsClientPSProvider.Types.ps1xml'),
      @('NetTCPIP','Tcpip.Types.ps1xml'), @('NetConnection','MSFT_NetConnectionProfile.types.ps1xml')
    )) { Update-TypeData -PrependPath (Join-Path (Join-Path $modulesRoot $pair[0]) $pair[1]) -ErrorAction Stop }
  } catch { Import-Module NetAdapter,DnsClient,NetTCPIP,NetConnection -Global -ErrorAction Stop }
  $script:networkModulesReady = $true
}
`
