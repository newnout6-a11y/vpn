param(
  [ValidateSet('start', 'rotate', 'connect', 'trigger', 'list', 'stop', 'status')]
  [string]$Action = 'start',
  [string]$Target = '',
  [int]$Port = 17990,
  [switch]$Json
)

$control = "http://127.0.0.1:17873"
$format = if ($Json) { "" } else { "&format=text" }

function Test-VpnteApi {
  try {
    Invoke-RestMethod -Method Get -Uri "$control/status?format=text" -TimeoutSec 2 | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Start-VpnteIfNeeded {
  if (Test-VpnteApi) { return }

  $exe = Join-Path $PSScriptRoot "VPN Tunnel Enforcer.exe"
  if (Test-Path $exe) {
    Start-Process -FilePath $exe -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
      Start-Sleep -Milliseconds 500
      if (Test-VpnteApi) { return }
    }
  }
}

function Invoke-VpnteProxy($path) {
  Start-VpnteIfNeeded
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $path -TimeoutSec 30
    return $response.Content.TrimEnd()
  } catch {
    Write-Error "VPN Tunnel Enforcer is not running or external proxy API is unavailable: $($_.Exception.Message)"
    exit 1
  }
}

switch ($Action) {
  'list' {
    $suffix = if ($Json) { "" } else { "?format=text" }
    if ($Target.Trim()) {
      $joiner = if ($suffix) { "&" } else { "?" }
      $suffix += "$joiner" + "country=$([uri]::EscapeDataString($Target.Trim()))"
    }
    Invoke-VpnteProxy "$control/list$suffix"
    break
  }
  { $_ -eq 'connect' -or $_ -eq 'trigger' } {
    if (!$Target.Trim()) {
      Write-Error "Usage: .\vpnte-proxy.ps1 $Action <profileId>"
      exit 2
    }
    $query = "?port=$Port$format&id=$([uri]::EscapeDataString($Target.Trim()))"
    Invoke-VpnteProxy "$control/$Action$query"
    break
  }
  'status' {
    $suffix = if ($Json) { "" } else { "?format=text" }
    Invoke-VpnteProxy "$control/status$suffix"
    break
  }
  'stop' {
    $suffix = if ($Json) { "" } else { "?format=text" }
    Invoke-VpnteProxy "$control/stop$suffix"
    break
  }
  default {
    $query = "?port=$Port$format"
    if ($Target.Trim()) {
      $query += "&country=$([uri]::EscapeDataString($Target.Trim()))"
    }
    Invoke-VpnteProxy "$control/$Action$query"
  }
}
