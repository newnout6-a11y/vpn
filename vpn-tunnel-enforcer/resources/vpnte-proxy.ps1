param(
  [ValidateSet('start', 'rotate', 'connect', 'trigger', 'list', 'profiles-health', 'stop', 'status')]
  [string]$Action = 'start',
  [string]$Target = '',
  [ValidateRange(0, 65535)]
  [int]$Port = 0,
  [ValidateRange(1, 47546)]
  [int]$Slot = 1,
  [switch]$Json
)

$Port = if ($Port -gt 0) { $Port } else { 17989 + $Slot }
$format = if ($Json) { "" } else { "&format=text" }
$tokenFile = Join-Path $env:APPDATA "VPN Tunnel Enforcer\external-proxy-control-token"
$endpointFile = Join-Path $env:APPDATA "VPN Tunnel Enforcer\external-proxy-control-endpoint.json"
$control = "http://127.0.0.1:17873"

function Test-IsSafeLocalControlUrl([string]$candidate) {
  if ([string]::IsNullOrWhiteSpace($candidate)) { return $false }
  try {
    $u = [System.Uri]$candidate
    if ($u.Scheme -ne 'http') { return $false }
    $hostLower = $u.Host.ToLowerInvariant()
    $isLoopbackHost = ($hostLower -eq '127.0.0.1' -or $hostLower -eq 'localhost' -or $hostLower -eq '::1' -or $hostLower -eq '[::1]')
    if (-not $isLoopbackHost) { return $false }
    if ($u.Port -le 0 -or $u.Port -gt 65535) { return $false }
    return $true
  } catch {
    return $false
  }
}

function Get-VpnteControlUrl {
  if ($env:VPNTE_CONTROL_URL) {
    $raw = $env:VPNTE_CONTROL_URL.Trim().TrimEnd("/")
    if (Test-IsSafeLocalControlUrl $raw) {
      return $raw
    } else {
      Write-Warning "VPNTE_CONTROL_URL is not a valid local loopback address: '$raw'. Using default."
    }
  }
  if (Test-Path $endpointFile) {
    try {
      $endpoint = Get-Content -LiteralPath $endpointFile -Raw | ConvertFrom-Json
      if ($endpoint.url) {
        $raw = ([string]$endpoint.url).Trim().TrimEnd("/")
        if (Test-IsSafeLocalControlUrl $raw) {
          return $raw
        }
      }
      if ($endpoint.host -and $endpoint.port) {
        $raw = "http://$($endpoint.host):$($endpoint.port)"
        if (Test-IsSafeLocalControlUrl $raw) {
          return $raw
        }
      }
    } catch {
      # Fall back to the default control port below.
    }
  }
  return "http://127.0.0.1:17873"
}

function Test-VpnteApi {
  $script:control = Get-VpnteControlUrl
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
  if (-not (Test-IsSafeLocalControlUrl $path)) {
    Write-Error "Invalid control API request target: '$path'. Must be a local loopback HTTP endpoint."
    exit 1
  }
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
  'profiles-health' {
    if (!$Target.Trim()) {
      Write-Error "Usage: .\vpnte-proxy.ps1 profiles-health <groupId>"
      exit 2
    }
    $suffix = if ($Json) { "?groupId=$([uri]::EscapeDataString($Target.Trim()))" } else { "?format=text&groupId=$([uri]::EscapeDataString($Target.Trim()))" }
    Invoke-VpnteProxy "$control/profiles/healthcheck$suffix" 'POST'
    break
  }
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
    $query = "?slot=$Slot&port=$Port$format&id=$([uri]::EscapeDataString($Target.Trim()))"
    Invoke-VpnteProxy "$control/$Action$query" 'POST'
    break
  }
  'status' {
    $suffix = if ($Json) { "?slot=$Slot" } else { "?slot=$Slot&format=text" }
    Invoke-VpnteProxy "$control/status$suffix"
    break
  }
  'stop' {
    $suffix = if ($Json) { "?slot=$Slot" } else { "?slot=$Slot&format=text" }
    Invoke-VpnteProxy "$control/stop$suffix" 'POST'
    break
  }
  default {
    $query = "?slot=$Slot&port=$Port$format"
    if ($Target.Trim()) {
      $query += "&country=$([uri]::EscapeDataString($Target.Trim()))"
    }
    Invoke-VpnteProxy "$control/$Action$query" 'POST'
  }
}
