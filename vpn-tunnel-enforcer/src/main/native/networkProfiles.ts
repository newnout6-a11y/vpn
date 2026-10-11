// AT-03-005/006: connection profile names for the native adapter snapshot.
// Names feed tethering classification, so they must be exact. They come from the already-warm
// elevated PowerShell helper (read-only Get-NetConnectionProfile), never from in-process COM:
// a bad COM vtable call kills the elevated main process instead of throwing.
// Fail closed: helper not running, bad output or any error THROWS and the caller uses the full
// PowerShell worker path.
import { execElevatedPs, isElevatedPsHelperRunning } from '../elevatedPsHelper'

const SCRIPT = `$ErrorActionPreference='Stop'
$rows = @(Get-NetConnectionProfile | ForEach-Object { [pscustomobject]@{ ifIndex = [int]$_.InterfaceIndex; name = [string]$_.Name } })
ConvertTo-Json -Compress -InputObject $rows`

export function parseNetworkProfiles(stdout: string): Map<number, string[]> {
  const parsed: unknown = JSON.parse(String(stdout).replace(/^﻿/, '').trim())
  if (!Array.isArray(parsed)) throw new Error('network profiles: expected a JSON array')
  const result = new Map<number, string[]>()
  for (const row of parsed) {
    const entry = row as { ifIndex?: unknown; name?: unknown }
    if (!Number.isInteger(entry?.ifIndex) || typeof entry?.name !== 'string') throw new Error('network profiles: unexpected row shape')
    if (!entry.name) continue
    const list = result.get(entry.ifIndex as number) ?? []
    list.push(entry.name)
    result.set(entry.ifIndex as number, list)
  }
  return result
}

export async function fetchNetworkProfiles(): Promise<Map<number, string[]>> {
  if (!isElevatedPsHelperRunning()) throw new Error('network profiles: elevated helper is not running')
  const result = await execElevatedPs(SCRIPT, 10000, 'physical-adapter-lockdown')
  if (result.exitCode) throw new Error(`network profiles: helper exit ${result.exitCode}`)
  return parseNetworkProfiles(result.stdout)
}
