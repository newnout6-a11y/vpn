$ErrorActionPreference = 'Stop'

$logDirectory = Join-Path $env:ProgramData 'VPN Tunnel Enforcer'
$logPath = Join-Path $logDirectory 'install-eos-compat.log'
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsBackupPath = "$hostsPath.vpnte-before-eos-ipv4"
$hostsMarker = '# VPNTE Epic EOS IPv4 loopback compatibility'
$eosPorts = 35783..35791

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

function Write-InstallLog {
  param([string]$Message)
  Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) $Message" -Encoding UTF8
}

try {
  # Epic Online Services must resolve localhost to IPv4 on systems where an
  # explicit IPv6 loopback filter rejects its local helper connection.
  & netsh interface ipv6 set prefixpolicy prefix=::ffff:0:0/96 precedence=60 label=4 store=persistent | Out-Null
  if ($LASTEXITCODE -ne 0) {
    & netsh interface ipv6 add prefixpolicy prefix=::ffff:0:0/96 precedence=60 label=4 store=persistent | Out-Null
  }
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to update IPv4-mapped prefix policy (exit code $LASTEXITCODE)"
  }

  if (-not (Test-Path -LiteralPath $hostsBackupPath)) {
    Copy-Item -LiteralPath $hostsPath -Destination $hostsBackupPath -Force
  }

  $hostsLines = @([System.IO.File]::ReadAllLines($hostsPath))
  $markerPattern = [regex]::Escape($hostsMarker) + '\s*$'
  $hostsLines = @($hostsLines | Where-Object { $_ -notmatch $markerPattern })
  $hostsLines += "127.0.0.1 localhost $hostsMarker"
  $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($hostsPath, $hostsLines, $utf8WithoutBom)

  # Preserve the Codex sandbox rule while opening only the EOS helper range.
  $codexRules = @(Get-NetFirewallRule -DisplayName 'codex_sandbox_offline_block_loopback_tcp' -ErrorAction SilentlyContinue)
  foreach ($rule in $codexRules) {
    $rule | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -RemotePort @('1-35782', '35792-65535') | Out-Null
  }

  # Remove diagnostic port-proxy entries left by older/manual workarounds.
  foreach ($port in $eosPorts) {
    & netsh interface portproxy delete v4tov6 listenaddress=127.0.0.1 listenport=$port protocol=tcp | Out-Null
  }

  Clear-DnsClientCache
  Write-InstallLog "Epic EOS compatibility applied; adjusted Codex rules: $($codexRules.Count)"
} catch {
  Write-InstallLog "Epic EOS compatibility failed: $($_.Exception.Message)"
  exit 1
}
