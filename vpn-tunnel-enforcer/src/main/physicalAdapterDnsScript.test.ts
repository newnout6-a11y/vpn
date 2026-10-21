// AT-03-006 / AT-03-012: the routing-DNS reader keeps working for every other adapter when one adapter has no IPv4 DNS
// entry, still fails on any other error, and its script stays inside the worker's encoded-command budget.
// The production script runs in real PowerShell against fake Get-NetAdapter / Get-DnsClientServerAddress functions.
import { execFileSync } from 'node:child_process'
import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { PHYSICAL_ADAPTER_DNS_SCRIPT, PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT, physicalAdapterSnapshotScript } from './physicalAdapterSnapshot'
import { recoveryWorkerScript } from './recoveryPsProtocol'

/** Fake cmdlets: Wi-Fi has servers, Ethernet 4 raises ObjectNotFound, anything else raises InvalidData. */
const fakeCmdlets = (names: string[]): string => `
$fakeNames = @(${names.map(name => `'${name}'`).join(',')})
function Get-NetAdapter {
  foreach ($n in $fakeNames) {
    [pscustomobject]@{ Name = $n; ifIndex = [int](10 + $fakeNames.IndexOf($n)); Status = 'Up'
      InterfaceDescription = 'Fake adapter ' + $n; MacAddress = 'AA-BB-CC-DD-EE-FF' }
  }
}
function Get-NetIPInterface { foreach ($n in $fakeNames) { [pscustomobject]@{InterfaceIndex=[int](10 + $fakeNames.IndexOf($n))} } }
function Get-DnsClientServerAddress {
  param([string]$InterfaceAlias, [string]$AddressFamily)
  switch ($InterfaceAlias) {
    'Wi-Fi' { return [pscustomobject]@{ ServerAddresses = @('192.168.1.1', '1.1.1.1') } }
    'Ethernet 4' { throw [System.Management.Automation.ErrorRecord]::new([Exception]::new('no entries (any language)'), 'NotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $InterfaceAlias) }
    default { throw [System.Management.Automation.ErrorRecord]::new([Exception]::new('provider broke'), 'Broken', [System.Management.Automation.ErrorCategory]::InvalidData, $InterfaceAlias) }
  }
}
`

function run(script: string): string {
  const loader = '[Console]::InputEncoding=[Text.Encoding]::UTF8; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))'
  return execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(loader, 'utf16le').toString('base64')],
    { input: script, encoding: 'utf8', windowsHide: true, timeout: 60_000, stdio: 'pipe' })
}

describe.runIf(process.platform === 'win32')('routing DNS reader script', () => {
  it('returns an empty list for an adapter without IPv4 DNS (ObjectNotFound) and keeps the others', () => {
    const rows = JSON.parse(run(`${fakeCmdlets(['Wi-Fi', 'Ethernet 4'])}\n${PHYSICAL_ADAPTER_DNS_SCRIPT}`).trim())
    expect(rows).toEqual([
      { ifIndex: 10, alias: 'Wi-Fi', ipv4Dns: ['192.168.1.1', '1.1.1.1'] },
      { ifIndex: 11, alias: 'Ethernet 4', ipv4Dns: [] }
    ])
  })

  it('still fails the whole read on any other error category (no silent empty result)', () => {
    // "Cellular" raises InvalidData: the read must fail, not return a list that looks complete.
    // Matching the injected message proves the read failed because of THIS error, not a broken fixture or a syntax error.
    expect(() => run(`${fakeCmdlets(['Wi-Fi', 'Ethernet 4', 'Cellular'])}\n${PHYSICAL_ADAPTER_DNS_SCRIPT}`)).toThrow(/provider broke/)
  })
})

describe.runIf(process.platform === 'win32')('full physical adapter baseline (AT-03-006/012)', () => {
  it.each([
    ['missing DNS row', '', []],
    ['empty DNS list', "[pscustomobject]@{InterfaceIndex=17;ServerAddresses=@()}", []],
    ['configured resolver', "[pscustomobject]@{InterfaceIndex=17;ServerAddresses=@('1.1.1.1')}", ['1.1.1.1']],
    ['invalid provider value', "[pscustomobject]@{InterfaceIndex=17;ServerAddresses=@('INVALID-DNS')}", ['INVALID-DNS']]
  ])('preserves the adapter and DNS baseline for %s', (_name, dnsRow, expected) => {
    const script = String.raw`
$ProgressPreference='SilentlyContinue'
function Get-CimInstance {
  param($Namespace,$ClassName,$Filter,$ErrorAction)
  switch ($ClassName) {
    'MSFT_NetAdapter' { [pscustomobject]@{HardwareInterface=$true;Hidden=$false;InterfaceOperationalStatus=1;Name='Ethernet';InterfaceDescription='Fixture adapter';PermanentAddress='001122334455';InterfaceGuid='11111111-1111-1111-1111-111111111111';InterfaceIndex=17;MediaType='Ethernet';PhysicalMediaType='Ethernet'} }
    'MSFT_NetIPInterface' { [pscustomobject]@{InterfaceIndex=17} }
    'MSFT_NetAdapterBindingSettingData' { [pscustomobject]@{Name='Ethernet';InterfaceDescription='Fixture adapter';Enabled=$true} }
    'MSFT_DNSClientServerAddress' { ${dnsRow} }
    'MSFT_NetRoute' { }
    'MSFT_NetConnectionProfile' { }
    default { throw 'Unexpected fixture class' }
  }
}
function Get-ItemProperty { param($Path,$Name,$ErrorAction); [pscustomobject]@{NameServer=''} }
function Get-NetAdapter { throw 'Unexpected fallback in fixture' }
${PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT}`
    const snapshot = JSON.parse(run(script).trim())
    expect(snapshot).toMatchObject({ ifIndex: 17, alias: 'Ethernet', ipv6Enabled: true,
      interfaceGuid: '11111111-1111-1111-1111-111111111111', ipv4Dns: expected })
  })
})

describe.runIf(process.platform === 'win32')('physical IP-stack ownership (AT-03-005/006/010)', () => {
  const topology = [
    { Name: 'uplink', HardwareInterface: true, InterfaceDescription: 'Microsoft Hyper-V Network Adapter', Bound: true },
    { Name: 'internal', HardwareInterface: false, InterfaceDescription: 'Hyper-V Virtual Ethernet Adapter', Bound: true },
    { Name: 'vf', HardwareInterface: true, InterfaceDescription: 'SR-IOV VF', Bound: false },
    { Name: 'no-address-yet', HardwareInterface: true, InterfaceDescription: 'Physical Ethernet', Bound: true },
    { Name: 'vpnte-tun', HardwareInterface: true, InterfaceDescription: 'Wintun', Bound: true }
  ].map((a, i) => ({ ...a, ifIndex: i + 10, InterfaceIndex: i + 10, Status: 'Up', InterfaceOperationalStatus: 1,
    InterfaceGuid: `11111111-1111-1111-1111-${String(i + 10).padStart(12, '0')}`, Hidden: false,
    PermanentAddress: '001122334455', MacAddress: '00-11-22-33-44-55', MediaType: 'Ethernet', PhysicalMediaType: 'Ethernet' }))
  const fixture = (mode: string, fail = false) => `
$fixture = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(JSON.stringify(topology)).toString('base64')}')) | ConvertFrom-Json
function Get-NetAdapter { [CmdletBinding()]param([switch]$Physical); $fixture | Where-Object { -not $Physical -or $_.HardwareInterface } }
function Get-NetIPInterface { [CmdletBinding()]param(); ${fail ? "throw 'IP inventory unavailable'" : "$fixture | Where-Object Bound | ForEach-Object { [pscustomobject]@{InterfaceIndex=$_.InterfaceIndex} }"} }
function Get-CimInstance { [CmdletBinding()]param($Namespace,$ClassName,$Filter)
  switch ($ClassName) {
    'MSFT_NetAdapter' { ${mode === 'fallback' ? "throw 'Use cmdlet fallback'" : '$fixture'} }
    'MSFT_NetIPInterface' { Get-NetIPInterface }
    'MSFT_NetAdapterBindingSettingData' { $fixture | Where-Object Bound | ForEach-Object { [pscustomobject]@{Name=$_.Name;InterfaceDescription=$_.InterfaceDescription;Enabled=$true} } }
    'MSFT_DNSClientServerAddress' { }
    'MSFT_NetRoute' { }
    'MSFT_NetConnectionProfile' { }
    default { throw 'Unexpected fixture class' }
  }
}
function Get-NetAdapterBinding { [CmdletBinding()]param($InterfaceAlias,$ComponentID); [pscustomobject]@{Enabled=$true} }
function Get-DnsClientServerAddress { [CmdletBinding()]param($InterfaceAlias,$AddressFamily); [pscustomobject]@{ServerAddresses=@()} }
function Get-NetRoute { [CmdletBinding()]param($InterfaceIndex,$DestinationPrefix) }
function Get-NetConnectionProfile { [CmdletBinding()]param($InterfaceIndex) }
function Get-ItemProperty { [CmdletBinding()]param($Path,$Name); [pscustomobject]@{NameServer=''} }
${mode === 'dns' ? PHYSICAL_ADAPTER_DNS_SCRIPT : PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT}`

  it.each(['cim', 'fallback', 'dns'])('%s selects hardware IP owners, not virtual switches or unbound VFs', mode => {
    const rows = JSON.parse(run(fixture(mode)).trim())
    expect(rows.map((r: { alias: string }) => r.alias)).toEqual(['uplink', 'no-address-yet'])
    expect(rows.every((r: { ipv4Dns: string[] }) => r.ipv4Dns.length === 0)).toBe(true)
  })
  it.each(['cim', 'fallback', 'dns'])('%s fails when IP ownership cannot be read, instead of silently omitting an adapter', mode => {
    expect(() => run(fixture(mode, true))).toThrow(/IP inventory unavailable/)
  })
  it.each(['cim', 'fallback'])('%s retains only a journalled adapter after its last IP binding is disabled (AT-03-006)', mode => {
    const retained = topology.find(a => a.Name === 'no-address-yet')!.InterfaceGuid
    const script = fixture(mode).replace(PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT,
      "$fixture | Where-Object Name -eq 'no-address-yet' | ForEach-Object { $_.Bound=$false }\n" + physicalAdapterSnapshotScript([retained]))
    const rows = JSON.parse(run(script).trim())
    expect(rows.map((r: { alias: string }) => r.alias)).toEqual(['uplink', 'no-address-yet'])
    // A fresh selection must still exclude the unbound VF and the now-unbound old adapter.
    const fresh = script.slice(0, script.indexOf("$fixture | Where-Object Name -eq 'no-address-yet'")) +
      "$fixture | Where-Object Name -eq 'no-address-yet' | ForEach-Object { $_.Bound=$false }\n" + PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT
    expect(JSON.parse(run(fresh).trim()).alias).toBe('uplink')
  })
  it('rejects non-GUID journal input before building any PowerShell command', () => {
    expect(() => physicalAdapterSnapshotScript(["'; throw 'injected'"])).toThrow(/Invalid retained adapter GUID/)
  })
})

describe('worker launch command budget', () => {
  it.each([false, true])('stays well below the 32767-character command limit (adapters scope: %s)', adapters => {
    const compressed = gzipSync(Buffer.from(recoveryWorkerScript('C:\\ProgramData', adapters), 'utf8')).toString('base64')
    // Same launcher text as RecoveryPsWorker; UTF-16 + base64 make every extra source byte cost about 3.5 characters.
    const launcher = `$bytes=[Convert]::FromBase64String('${compressed}');
$stream=New-Object IO.MemoryStream(,$bytes);
$gzip=New-Object IO.Compression.GZipStream($stream,[IO.Compression.CompressionMode]::Decompress);
$reader=New-Object IO.StreamReader($gzip,[Text.Encoding]::UTF8);
try { $source=$reader.ReadToEnd() } finally { $reader.Dispose(); $gzip.Dispose(); $stream.Dispose() };
& ([scriptblock]::Create($source))`
    expect(Buffer.from(launcher, 'utf16le').toString('base64').length).toBeLessThan(31_500)
  })
})
