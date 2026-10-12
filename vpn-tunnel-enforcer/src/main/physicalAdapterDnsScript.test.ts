// AT-03-006 / AT-03-012: the routing-DNS reader keeps working for every other adapter when one adapter has no IPv4 DNS
// entry, still fails on any other error, and its script stays inside the worker's encoded-command budget.
// The production script runs in real PowerShell against fake Get-NetAdapter / Get-DnsClientServerAddress functions.
import { execFileSync } from 'node:child_process'
import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { PHYSICAL_ADAPTER_DNS_SCRIPT } from './physicalAdapterSnapshot'
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
  return execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { encoding: 'utf8', windowsHide: true, timeout: 60_000, stdio: 'pipe' })
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
