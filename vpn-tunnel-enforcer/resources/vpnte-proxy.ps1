param(
  [ValidateSet('start', 'rotate', 'connect', 'trigger', 'list', 'stop', 'status')]
  [string]$Action = 'start',
  [string]$Target = '',
  [int]$Port = 17990,
  [switch]$Json
)

$control = "http://127.0.0.1:17873"
$format = if ($Json) { "" } else { "&format=text" }
$tokenFile = Join-Path $env:APPDATA "VPN Tunnel Enforcer\external-proxy-control-token"

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

function Get-VpnteControlToken {
  if ($env:VPNTE_CONTROL_TOKEN) {
    return $env:VPNTE_CONTROL_TOKEN.Trim()
  }
  if (Test-Path $tokenFile) {
    return (Get-Content -LiteralPath $tokenFile -Raw).Trim()
  }
  return ""
}

function Invoke-VpnteProxy($path, [string]$Method = 'GET') {
  Start-VpnteIfNeeded
  $headers = @{}
  if ($Method -ne 'GET') {
    $token = Get-VpnteControlToken
    if (!$token) {
      Write-Error "External proxy control token was not found. Start VPN Tunnel Enforcer and try again."
      exit 1
    }
    $headers['X-VPNTE-Control-Token'] = $token
  }
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Method $Method -Uri $path -Headers $headers -TimeoutSec 30
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
    Invoke-VpnteProxy "$control/$Action$query" 'POST'
    break
  }
  'status' {
    $suffix = if ($Json) { "" } else { "?format=text" }
    Invoke-VpnteProxy "$control/status$suffix"
    break
  }
  'stop' {
    $suffix = if ($Json) { "" } else { "?format=text" }
    Invoke-VpnteProxy "$control/stop$suffix" 'POST'
    break
  }
  default {
    $query = "?port=$Port$format"
    if ($Target.Trim()) {
      $query += "&country=$([uri]::EscapeDataString($Target.Trim()))"
    }
    Invoke-VpnteProxy "$control/$Action$query" 'POST'
  }
}
