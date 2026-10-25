# Read-only second oracle for the real integration runner. Never stops processes or changes adapters.
param([Parameter(Mandatory)][string]$RuntimeDir, [int]$ExpectedPid = 0, [string]$TunAlias = '', [switch]$RequireEndpointPair)
$ErrorActionPreference = 'Stop'
$stage = 'RUNTIME_INVENTORY'
try {
$runtime = [IO.Path]::GetFullPath($RuntimeDir).TrimEnd('\')
$processes = @(Get-CimInstance Win32_Process -Filter "Name='vpnte-sing-box.exe' OR Name='vpnte-xray.exe'" |
    Where-Object { $_.ExecutablePath -and [IO.Path]::GetDirectoryName($_.ExecutablePath) -eq $runtime })
$tun = @($processes | Where-Object { $_.Name -eq 'vpnte-sing-box.exe' })
$stage = 'CONFIG_READ'
$config = $null
$configPath = Join-Path $runtime 'sing-box.json'
if (Test-Path -LiteralPath $configPath) {
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $inbound = @($config.inbounds | Where-Object { $_.type -eq 'tun' })
    if ($inbound.Count -ne 1) { throw 'Expected one TUN inbound' }
    $TunAlias = $inbound[0].interface_name
}
$stage = 'ADAPTER_INVENTORY'
$adapter = @(Get-NetAdapter -IncludeHidden | Where-Object { $TunAlias -and $_.Name -eq $TunAlias })
$up = @($adapter | Where-Object { $_.Status -eq 'Up' })
$stage = 'ADDRESS_INVENTORY'
$addresses = @($up | ForEach-Object { Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction Stop })
$stage = 'PID_IDENTITY'
$matching = $false
if ($tun.Count -eq 1) {
    $matching = $tun[0].ProcessId -eq $ExpectedPid -and $tun[0].CommandLine -like ('*' + $configPath + '*')
}
$endpointRoutes = [ordered]@{ applicable = $false }
$stage = 'SELECTOR_READ'
$selector = @($config.outbounds | Where-Object { $_.tag -eq 'proxy-out' -and $_.type -eq 'selector' })
if ($ExpectedPid -gt 0 -and $selector.Count -gt 0) {
    $stage = 'SELECTOR_IDENTITY'
    if (-not $matching -or $up.Count -ne 1 -or $selector.Count -ne 1 -or
        (@($selector[0].outbounds | Sort-Object) -join ',') -cne 'vpnte-upstream-a,vpnte-upstream-b') { throw 'Selector identity not confirmed' }
    $stage = 'TUN_IDENTITY'
    $ownerPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'VPNTE\manifests') 'tun-owner.json'
    $owner = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json
    if ($owner.schemaVersion -ne 1 -or $owner.owner -cne 'VPNTE' -or $owner.alias -ne $TunAlias -or
        [guid]$owner.interfaceGuid -ne [guid]$up[0].InterfaceGuid -or $up[0].DriverDescription -notmatch '^Wintun\b' -or
        $up[0].PnPDeviceID -notlike 'SWD\Wintun\*' -or
        -not @($addresses | Where-Object { $_.IPAddress -eq '192.168.250.253' -and $_.PrefixLength -eq 30 }).Count) { throw 'Owned TUN identity not confirmed' }
    $stage = 'SLOT_IDENTITY'
    $endpoints = @()
    $slots = 0
    foreach ($slot in @('a','b')) {
        $path = Join-Path $runtime "xray-$slot.json"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $xray = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $bridge = @($config.outbounds | Where-Object { $_.tag -ceq "vpnte-upstream-$slot" -and $_.type -ceq 'socks' })
        $listener = @($xray.inbounds | Where-Object { $_.protocol -ceq 'socks' -and $_.listen -ceq '127.0.0.1' })
        if ($bridge.Count -ne 1 -or $listener.Count -ne 1 -or $bridge[0].server -cne '127.0.0.1' -or
            $bridge[0].server_port -ne $listener[0].port -or $listener[0].settings.auth -cne 'password' -or
            @($listener[0].settings.accounts).Count -ne 1 -or -not $bridge[0].username -or -not $bridge[0].password -or
            $bridge[0].username -cne $listener[0].settings.accounts[0].user -or
            $bridge[0].password -cne $listener[0].settings.accounts[0].pass) { throw 'Slot identity not confirmed' }
        $nodes = @($xray.outbounds | Where-Object { $_.protocol -in @('vless','vmess','trojan','shadowsocks','hysteria') } |
            ForEach-Object { @($_.settings.vnext); @($_.settings.servers); if ($_.settings.address) { $_.settings } } | Where-Object { $_ })
        if ($nodes.Count -eq 0) { throw 'Resolved endpoint missing' }
        foreach ($node in $nodes) {
            $ip = $null
            if (-not [Net.IPAddress]::TryParse([string]$node.address, [ref]$ip) -or
                $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or [Net.IPAddress]::IsLoopback($ip)) { throw 'Resolved IPv4 endpoint required' }
            $endpoints += $ip.ToString()
        }
        $slots++
    }
    if ($slots -lt 1 -or ($RequireEndpointPair -and $slots -ne 2)) { throw 'Endpoint pair missing' }
    $endpoints = @($endpoints | Select-Object -Unique)
    $stage = 'ENDPOINT_ROUTE'
    foreach ($endpoint in $endpoints) {
        $indices = @(Find-NetRoute -RemoteIPAddress $endpoint -ErrorAction Stop | Where-Object { $_.InterfaceIndex } |
            Select-Object -ExpandProperty InterfaceIndex -Unique)
        if ($indices.Count -ne 1 -or $indices[0] -ne $up[0].ifIndex) { throw 'Endpoint route does not select owned TUN' }
    }
    $endpointRoutes = [ordered]@{ applicable = $true; configuredSlots = $slots; endpointCount = $endpoints.Count;
        tunRouteCount = $endpoints.Count; allViaOwnedTun = $true }
}
$stage = 'REPORT_SERIALIZE'
[ordered]@{
    runtimeProcessCount = $processes.Count
    tunProcessCount = $tun.Count
    matchingPid = $matching
    adapterUp = ($up.Count -eq 1)
    interfaceAddressCount = $addresses.Count
    tunAlias = $TunAlias
    endpointOsRoutes = $endpointRoutes
} | ConvertTo-Json -Depth 4 -Compress
} catch {
    # Fixed vocabulary only; a native ErrorRecord can contain topology or keys.
    $native = 'READ_FAILED'
    if ($stage -eq 'ADDRESS_INVENTORY' -and
        $_.FullyQualifiedErrorId -match '^CmdletizationQuery_NotFound(?:_[A-Za-z0-9]+)?,Get-NetIPAddress$') {
        $native = 'ADDRESS_NOT_FOUND'
    } elseif ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::PermissionDenied) {
        $native = 'ACCESS_DENIED'
    }
    throw "VPNTE_ORACLE_$stage VPNTE_NATIVE_$native"
}
