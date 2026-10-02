// Read-only Windows comparison of the exact stale-exception lookup scopes.
// Run from vpn-tunnel-enforcer: node scripts/benchmark-firewall-query-batch.mjs
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'

const source = await readFile('src/main/firewallKillSwitch.ts', 'utf8')
if (!source.includes("Get-NetFirewallRule -DisplayName @('${RULE_PREFIX}-user-*','${RULE_PREFIX}-allow-extra-ip')")) {
  throw new Error('Production query scopes changed; update the benchmark before use')
}
const script = String.raw`
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
Import-Module NetSecurity -ErrorAction Stop
# Complete the first native query before measuring repeated fresh reads.
Get-NetFirewallRule -DisplayName 'VPNTE-killswitch*' -ErrorAction SilentlyContinue | Out-Null
$samples=New-Object 'Collections.Generic.List[object]'
foreach($round in 1..6){
 $watch=[Diagnostics.Stopwatch]::StartNew()
 # Alternate order to avoid consistently giving one method the first slot.
 if($round % 2 -eq 1){
   $separate=@(Get-NetFirewallRule -DisplayName 'VPNTE-killswitch-user-*' -ErrorAction SilentlyContinue)+@(Get-NetFirewallRule -DisplayName 'VPNTE-killswitch-allow-extra-ip' -ErrorAction SilentlyContinue)
   $watch.Stop();$separateMs=$watch.Elapsed.TotalMilliseconds;$watch.Restart()
   $batch=@(Get-NetFirewallRule -DisplayName @('VPNTE-killswitch-user-*','VPNTE-killswitch-allow-extra-ip') -ErrorAction SilentlyContinue)
   $watch.Stop();$batchMs=$watch.Elapsed.TotalMilliseconds
 }else{
   $batch=@(Get-NetFirewallRule -DisplayName @('VPNTE-killswitch-user-*','VPNTE-killswitch-allow-extra-ip') -ErrorAction SilentlyContinue)
   $watch.Stop();$batchMs=$watch.Elapsed.TotalMilliseconds;$watch.Restart()
   $separate=@(Get-NetFirewallRule -DisplayName 'VPNTE-killswitch-user-*' -ErrorAction SilentlyContinue)+@(Get-NetFirewallRule -DisplayName 'VPNTE-killswitch-allow-extra-ip' -ErrorAction SilentlyContinue)
   $watch.Stop();$separateMs=$watch.Elapsed.TotalMilliseconds
 }
 $separateIds=@($separate | ForEach-Object { [string]$_.Name } | Sort-Object)
 $batchIds=@($batch | ForEach-Object { [string]$_.Name } | Sort-Object)
 if(($separateIds -join '|') -cne ($batchIds -join '|')){throw 'Fresh exception query results differ'}
 $samples.Add([pscustomobject]@{round=$round;separateMs=$separateMs;batchMs=$batchMs;matchCount=$separate.Count;freshIdentityEqual=$true})
}
# Also check real non-empty results. Values stay inside this process: only
# counts/equality leave it. Escape wildcard characters in localized titles.
$names=@(Get-NetFirewallRule -All -ErrorAction Stop | Where-Object { $_.DisplayName -notlike 'VPNTE-killswitch*' } | Select-Object -ExpandProperty DisplayName -Unique | Select-Object -First 2)
if($names.Count -ne 2){throw 'Two distinct native sample titles required'}
$patterns=@($names | ForEach-Object { [WildcardPattern]::Escape([string]$_) })
$positiveSeparate=@(Get-NetFirewallRule -DisplayName $patterns[0] -ErrorAction Stop)+@(Get-NetFirewallRule -DisplayName $patterns[1] -ErrorAction Stop)
$positiveBatch=@(Get-NetFirewallRule -DisplayName $patterns -ErrorAction Stop)
$left=@($positiveSeparate | ForEach-Object { [string]$_.Name } | Sort-Object)
$right=@($positiveBatch | ForEach-Object { [string]$_.Name } | Sort-Object)
if($left.Count -lt 2 -or ($left -join '|') -cne ($right -join '|')){throw 'Fresh positive query results differ'}
$mixedSeparate=@(Get-NetFirewallRule -DisplayName $patterns[0] -ErrorAction SilentlyContinue)+@(Get-NetFirewallRule -DisplayName 'VPNTE-killswitch-user-*' -ErrorAction SilentlyContinue)
$mixedBatch=@(Get-NetFirewallRule -DisplayName @($patterns[0],'VPNTE-killswitch-user-*') -ErrorAction SilentlyContinue)
$mixedLeft=@($mixedSeparate | ForEach-Object { [string]$_.Name } | Sort-Object)
$mixedRight=@($mixedBatch | ForEach-Object { [string]$_.Name } | Sort-Object)
if($mixedLeft.Count -lt 1 -or ($mixedLeft -join '|') -cne ($mixedRight -join '|')){throw 'Fresh mixed-present query results differ'}
[pscustomobject]@{samples=$samples.ToArray();positiveMatchCount=$left.Count;positiveIdentityEqual=$true;mixedPresentIdentityEqual=$true} | ConvertTo-Json -Compress -Depth 4
`
const env = { ...process.env }
for (const key of Object.keys(env)) if (key.toLowerCase() === 'psmodulepath') delete env[key]
const started = performance.now()
const output = execFileSync('powershell.exe', ['-NoProfile', '-NoLogo', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
  env, windowsHide: true, timeout: 60000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']
})
console.log(JSON.stringify({ ...JSON.parse(output.replace(/^\uFEFF/, '').trim()), totalProcessMs: performance.now() - started,
  limits: ['Fresh read-only default-store queries; no firewall changes.', 'Positive native results verify lookup equality, not removal or complete VPN protection.', 'Separate-process timings exclude helper queue, rule mutation and full lifecycle.'] }, null, 2))
