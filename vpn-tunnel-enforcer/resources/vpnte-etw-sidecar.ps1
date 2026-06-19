param(
  [Parameter(Mandatory = $true)]
  [string]$Events,

  [Parameter(Mandatory = $true)]
  [string]$Session,

  [string]$Providers = 'Microsoft-Windows-TCPIP,Microsoft-Windows-DNS-Client,Microsoft-Windows-WFP,Microsoft-Windows-Winsock-AFD,Microsoft-Windows-WebIO',

  [int]$PollMs = 1000,

  [int]$MaxEventsPerPoll = 80
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

$eventDir = Split-Path -Parent $Events
if ($eventDir) {
  New-Item -ItemType Directory -Force -Path $eventDir | Out-Null
}

function Write-NdjsonEvent {
  param([hashtable]$Row)
  $Row.session = $Session
  $Row.sidecar = 'vpnte-etw-sidecar.ps1'
  $Row.ts = (Get-Date).ToUniversalTime().ToString('o')
  ($Row | ConvertTo-Json -Compress -Depth 8) | Add-Content -LiteralPath $Events -Encoding UTF8
}

function Normalize-Provider {
  param([string]$ProviderName)
  if ($ProviderName -match 'DNS') { return 'Microsoft-Windows-DNS-Client' }
  if ($ProviderName -match 'WFP|Firewall') { return 'Microsoft-Windows-WFP' }
  if ($ProviderName -match 'TCPIP|Tcpip') { return 'Microsoft-Windows-TCPIP' }
  if ($ProviderName -match 'AFD') { return 'Microsoft-Windows-Winsock-AFD' }
  if ($ProviderName -match 'WebIO') { return 'Microsoft-Windows-WebIO' }
  return $ProviderName
}

function Convert-Event {
  param($EventRecord)
  $provider = Normalize-Provider $EventRecord.ProviderName
  $message = [string]$EventRecord.Message
  $category = 'event'
  $eventName = 'observed'
  $reason = $null

  if ($provider -match 'DNS') {
    $category = 'dns'
    $eventName = 'query'
  } elseif ($provider -match 'WFP') {
    $category = 'wfp'
    if ($message -match 'block|blocked|drop|discard|5152|5157') {
      $eventName = 'block'
      $reason = 'wfp-block-observed'
    }
  } elseif ($provider -match 'TCPIP') {
    $category = 'tcp'
    if ($message -match 'reset|\brst\b') {
      $eventName = 'reset'
      $reason = 'reset-observed'
    } elseif ($message -match 'timeout|retrans|loss') {
      $eventName = 'loss'
      $reason = 'timeout-or-retransmit-observed'
    } elseif ($message -match 'mtu|fragment|packet too big') {
      $eventName = 'mtu'
      $reason = 'mtu-or-fragmentation-observed'
    }
  }

  $ips = [regex]::Matches($message, '\b(?:\d{1,3}\.){3}\d{1,3}\b') | ForEach-Object { $_.Value } | Select-Object -Unique
  $remoteAddress = if ($ips.Count -gt 0) { [string]$ips[0] } else { $null }
  $query = $null
  if ($category -eq 'dns') {
    $domainMatch = [regex]::Match($message, '\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,}\b', 'IgnoreCase')
    if ($domainMatch.Success) { $query = $domainMatch.Value }
  }

  return @{
    timestamp = [DateTimeOffset]$EventRecord.TimeCreated
    provider = $provider
    category = $category
    event = $eventName
    reason = $reason
    remoteAddress = $remoteAddress
    queryName = $query
    eventId = $EventRecord.Id
    recordId = $EventRecord.RecordId
    level = $EventRecord.LevelDisplayName
    message = if ($message.Length -gt 1000) { $message.Substring(0, 1000) } else { $message }
  }
}

$lastRecordIds = @{}
$pollCount = 0
Write-NdjsonEvent @{
  provider = 'sidecar'
  category = 'lifecycle'
  event = 'started'
  providers = $Providers
  eventsPath = $Events
}

while ($true) {
  $pollCount++
  $pollSeen = 0
  foreach ($provider in ($Providers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    try {
      $events = Get-WinEvent -FilterHashtable @{ ProviderName = $provider } -MaxEvents $MaxEventsPerPoll
      [array]::Reverse($events)
      $seen = 0
      foreach ($eventRecord in $events) {
        $last = $lastRecordIds[$provider]
        if ($last -and $eventRecord.RecordId -le $last) { continue }
        $row = Convert-Event $eventRecord
        Write-NdjsonEvent $row
        $lastRecordIds[$provider] = $eventRecord.RecordId
        $seen++
      }
      $pollSeen += $seen
      if (($pollCount -eq 1) -or ($pollCount % 30 -eq 0)) {
        Write-NdjsonEvent @{
          provider = 'sidecar'
          category = 'health'
          event = 'provider-polled'
          providerName = $provider
          observedEvents = $seen
          lastRecordId = $lastRecordIds[$provider]
        }
      }
      if ($seen -ge $MaxEventsPerPoll) {
        Write-NdjsonEvent @{
          provider = 'sidecar'
          category = 'health'
          event = 'poll-limit-hit'
          droppedEvents = 1
          bufferPressure = 1
          providerName = $provider
        }
      }
    } catch {
      Write-NdjsonEvent @{
        provider = 'sidecar'
        category = 'health'
        event = 'provider-read-failed'
        providerName = $provider
        error = $_.Exception.Message
      }
    }
  }
  if ($pollCount % 30 -eq 0) {
    Write-NdjsonEvent @{
      provider = 'sidecar'
      category = 'health'
      event = 'heartbeat'
      pollCount = $pollCount
      observedEvents = $pollSeen
      note = 'PowerShell sidecar reads Windows Event Log providers; pktmon remains the primary packet capture source.'
    }
  }
  Start-Sleep -Milliseconds $PollMs
}
