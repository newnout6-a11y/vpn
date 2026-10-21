# Read-only second oracle for the real integration runner. Never stops processes or changes adapters.
param([Parameter(Mandatory)][string]$RuntimeDir, [int]$ExpectedPid = 0, [string]$TunAlias = '')
$ErrorActionPreference = 'Stop'
$runtime = [IO.Path]::GetFullPath($RuntimeDir).TrimEnd('\')
$processes = @(Get-CimInstance Win32_Process -Filter "Name='vpnte-sing-box.exe' OR Name='vpnte-xray.exe'" |
    Where-Object { $_.ExecutablePath -and [IO.Path]::GetDirectoryName($_.ExecutablePath) -eq $runtime })
$tun = @($processes | Where-Object { $_.Name -eq 'vpnte-sing-box.exe' })
$configPath = Join-Path $runtime 'sing-box.json'
if (Test-Path -LiteralPath $configPath) {
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $inbound = @($config.inbounds | Where-Object { $_.type -eq 'tun' })
    if ($inbound.Count -ne 1) { throw 'Expected one TUN inbound' }
    $TunAlias = $inbound[0].interface_name
}
$adapter = @(Get-NetAdapter -IncludeHidden | Where-Object { $TunAlias -and $_.Name -eq $TunAlias })
$up = @($adapter | Where-Object { $_.Status -eq 'Up' })
$addresses = @($up | ForEach-Object { Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction Stop })
$matching = $false
if ($tun.Count -eq 1) {
    $matching = $tun[0].ProcessId -eq $ExpectedPid -and $tun[0].CommandLine -like ('*' + $configPath + '*')
}
[ordered]@{
    runtimeProcessCount = $processes.Count
    tunProcessCount = $tun.Count
    matchingPid = $matching
    adapterUp = ($up.Count -eq 1)
    interfaceAddressCount = $addresses.Count
    tunAlias = $TunAlias
} | ConvertTo-Json -Compress
