import { execFile } from 'child_process'
import { readFile, readdir, rm, writeFile } from 'fs/promises'
import { join } from 'path'

export interface ManagedChildPidFile {
  owner: string
  pid: number
  exePath?: string
  configPath?: string
  createdAt: number
}

function parsePidFile(raw: string): ManagedChildPidFile | null {
  try {
    const parsed = JSON.parse(raw)
    const pid = Number(parsed.pid)
    if (!Number.isInteger(pid) || pid <= 0 || pid === process.pid) return null
    const owner = typeof parsed.owner === 'string' && parsed.owner.trim() ? parsed.owner.trim() : ''
    if (!owner) return null
    return {
      owner,
      pid,
      exePath: typeof parsed.exePath === 'string' && parsed.exePath.trim() ? parsed.exePath : undefined,
      configPath: typeof parsed.configPath === 'string' && parsed.configPath.trim() ? parsed.configPath : undefined,
      createdAt: Number.isFinite(Number(parsed.createdAt)) ? Number(parsed.createdAt) : 0
    }
  } catch {
    return null
  }
}

function execFileAsync(file: string, args: string[], timeout = 5000): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout }, (err, stdout, stderr) => {
      if (err) reject(Object.assign(err, { stdout, stderr }))
      else resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? '') })
    })
  })
}

type ProcessCleanupOutcome = 'missing' | 'stopped' | 'mismatch' | 'unconfirmed'

async function stopWindowsProcessIfMatches(entry: ManagedChildPidFile): Promise<ProcessCleanupOutcome> {
  if (!entry.exePath && !entry.configPath) return 'unconfirmed'
  const script = [
    'param([int]$TargetPid,[string]$ExePath,[string]$ConfigPath)',
    '$ErrorActionPreference="Stop"',
    '$p=Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $TargetPid) -ErrorAction Stop',
    'if (-not $p) { "missing"; exit 0 }',
    // An inaccessible identity is not evidence that the old process is gone.
    'if (($ExePath -and -not $p.ExecutablePath) -or ($ConfigPath -and -not $p.CommandLine)) { "unconfirmed"; exit 0 }',
    // Every config-bearing managed child is spawned as exe run -c config.
    // Match that argument shape, never a substring or a value of another flag.
    `$configArgument='"'+[regex]::Escape($ConfigPath)+'"'`,
    `if ($ConfigPath -notmatch '\\s') { $configArgument='(?:'+$configArgument+'|'+[regex]::Escape($ConfigPath)+')' }`,
    `$configMatches=(!$ConfigPath -or $p.CommandLine -match ('^\\s*(?:"[^"]+"|[^\\s"]+)\\s+run\\s+-c\\s+'+$configArgument+'\\s*$'))`,
    '$match=(!$ExePath -or $p.ExecutablePath -eq $ExePath) -and $configMatches',
    'if (-not $match) { "mismatch"; exit 0 }',
    'Stop-Process -Id $TargetPid -Force -ErrorAction Stop',
    '"stopped"'
  ].join('; ')
  // -Command appends trailing argv to the source; it does not bind param().
  // Invoke the block explicitly and quote recorded paths as PowerShell literals.
  const literal = (value = '') => `'${value.replace(/'/g, "''")}'`
  const command = `& { ${script} } -TargetPid ${entry.pid} -ExePath ${literal(entry.exePath)} -ConfigPath ${literal(entry.configPath)}`

  try {
    const { stdout } = await execFileAsync('powershell.exe', [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      command
    ])
    const outcome = stdout.trim()
    return outcome === 'missing' || outcome === 'stopped' || outcome === 'mismatch' ? outcome : 'unconfirmed'
  } catch {
    return 'unconfirmed'
  }
}

function stopPosixProcess(entry: ManagedChildPidFile): boolean {
  try {
    process.kill(entry.pid, 0)
  } catch {
    return true
  }
  try {
    process.kill(entry.pid)
    return true
  } catch {
    return false
  }
}

export async function writeManagedChildPidFile(pidFile: string, entry: ManagedChildPidFile): Promise<void> {
  await writeFile(pidFile, JSON.stringify(entry, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 })
}

export async function removeManagedChildPidFile(pidFile: string, expectedPid?: number): Promise<void> {
  if (expectedPid) {
    const existing = await readFile(pidFile, 'utf8').then(parsePidFile).catch(() => null)
    if (existing && existing.pid !== expectedPid) return
  }
  await rm(pidFile, { force: true }).catch(() => undefined)
}

export async function cleanupManagedChildPidFile(
  pidFile: string,
  owner: string,
  log?: (message: string, details?: unknown) => void
): Promise<boolean> {
  let raw: string
  try { raw = await readFile(pidFile, 'utf8') }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true
    log?.('managed child pidfile read unconfirmed', { pidFile, owner })
    return false
  }

  const entry = parsePidFile(raw)
  if (!entry) {
    await rm(pidFile, { force: true }).catch(() => undefined)
    return true
  }

  if (entry.owner !== owner) {
    log?.('managed child pidfile belongs to different owner, skipping cleanup', {
      pidFile,
      expectedOwner: owner,
      actualOwner: entry.owner,
      pid: entry.pid
    })
    return false
  }

  const outcome = process.platform === 'win32'
    ? await stopWindowsProcessIfMatches(entry)
    : stopPosixProcess(entry) ? 'stopped' : 'unconfirmed'
  const cleaned = outcome !== 'unconfirmed'

  if (cleaned) {
    try { await rm(pidFile, { force: true }) }
    catch {
      log?.('managed child pidfile cleanup skipped', { pidFile, owner, pid: entry.pid, outcome: 'record-remove-failed' })
      return false
    }
    if (outcome === 'missing' || outcome === 'mismatch') {
      log?.('managed child stale pidfile removed', { pidFile, owner, pid: entry.pid, outcome })
    }
  } else {
    log?.('managed child pidfile cleanup skipped', { pidFile, owner, pid: entry.pid })
  }
  return cleaned
}

export async function cleanupManagedChildPidDirs(
  parentDir: string,
  dirPrefix: string,
  pidFileName: string,
  owner: string,
  log?: (message: string, details?: unknown) => void
): Promise<void> {
  const entries = await readdir(parentDir, { withFileTypes: true }).catch(() => [])
  await Promise.all(entries
    .filter((entry) => entry.isDirectory() && entry.name.startsWith(dirPrefix))
    .map(async (entry) => {
      const dir = join(parentDir, entry.name)
      const cleaned = await cleanupManagedChildPidFile(join(dir, pidFileName), owner, log)
      if (cleaned) await rm(dir, { recursive: true, force: true }).catch(() => undefined)
    }))
}
