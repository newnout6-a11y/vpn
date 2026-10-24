import { execFile } from 'child_process'
import { FIREWALL_STATUS_PS } from './firewallStatus'
import { logEvent } from './appLogger'

// A fixed read in its own process cannot queue behind or delay the mutation
// helper. Imports are pinned to Windows PowerShell's installed modules.
const source = `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Management\\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\\NetSecurity\\NetSecurity.psd1') -ErrorAction Stop
${FIREWALL_STATUS_PS}`

/** AT-03-001/012: no caller-supplied script, UAC, writes, or helper fallback. */
export function readFirewallStatusSnapshot(): Promise<string> {
  const started = performance.now()
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NoLogo', '-NonInteractive', '-Command', source],
      { encoding: 'utf8', windowsHide: true, timeout: 15000, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout) => {
        logEvent('debug', 'firewall-status-reader', 'snapshot timing', {
          durationMs: Math.round(performance.now() - started), outcome: error ? 'failed' : 'complete'
        })
        if (error) reject(error)
        else resolve(stdout)
      })
  })
}
