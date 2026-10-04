# AT-11-002 / AT-11-009, F-183: request cleanup, never terminate by image name.
param(
    [string]$InstallDir = $env:VPNTE_INSTALL_DIR,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'

function Get-VpnteProcesses {
    @(Get-CimInstance Win32_Process -Filter "Name='VPN Tunnel Enforcer.exe' OR Name='vpnte-sing-box.exe' OR Name='vpnte-xray.exe' OR Name='vpnte-etw-sidecar.exe'" -ErrorAction Stop)
}

function Open-VpnteAppProcess([int]$Id) {
    $process = [Diagnostics.Process]::GetProcessById($Id)
    # Open the handle now: later PID reuse must not replace the process we await.
    $null = $process.Handle
    return $process
}

function Invoke-VpnteShutdown([string]$Directory, [int]$Seconds) {
    if ([string]::IsNullOrWhiteSpace($Directory)) { throw 'Installation path is missing; update refused.' }
    $exe = [IO.Path]::GetFullPath((Join-Path $Directory 'VPN Tunnel Enforcer.exe'))
    $rows = @(Get-VpnteProcesses)
    if ($rows.Count -eq 0) { return }
    $primary = @($rows | Where-Object {
        $_.Name -eq 'VPN Tunnel Enforcer.exe' -and $_.CommandLine -and $_.CommandLine -notmatch '(?:^|\s)--type='
    })
    if ($primary.Count -ne 1 -or $primary[0].ExecutablePath -ne $exe) {
        throw 'Cannot identify the installed primary client. Close VPNTE normally and retry; no processes were killed.'
    }
    $process = Open-VpnteAppProcess $primary[0].ProcessId
    try {
        if ($process.MainModule.FileName -ne $exe) { throw 'Primary process identity changed; update refused.' }
        Start-Process -FilePath $exe -ArgumentList '--shutdown-for-update' -ErrorAction Stop | Out-Null
        if (-not $process.WaitForExit($Seconds * 1000)) { throw 'Client cleanup timed out; update refused.' }
        # 73 is emitted only after main-owned cleanup succeeds for this request.
        # A missing process, normal exit (0), crash or taskkill is not success.
        if ($process.ExitCode -ne 73) { throw 'Client exited without cleanup acknowledgement; update refused.' }
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $remaining = @(Get-VpnteProcesses)
            if ($remaining.Count -eq 0) { return }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)
        throw 'VPNTE background processes remain; update refused.'
    } finally {
        $process.Dispose()
    }
}

# Dot-sourcing exposes the same functions to harmless native fixture tests.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-VpnteShutdown $InstallDir $TimeoutSeconds
        exit 0
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}
