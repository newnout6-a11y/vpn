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

async function stopWindowsProcessIfMatches(entry: ManagedChildPidFile): Promise<boolean> {
  if (!entry.exePath && !entry.configPath) return false
  const script = [
    'param([int]$TargetPid,[string]$ExePath,[string]$ConfigPath)',
    '$p=Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $TargetPid) -ErrorAction SilentlyContinue',
    'if (-not $p) { "missing"; exit 0 }',
    '$match=$false',
    'if ($ExePath -and $p.ExecutablePath -eq $ExePath) { $match=$true }',
    'if ($ConfigPath -and $p.CommandLine -like ("*" + $ConfigPath + "*")) { $match=$true }',
    'if (-not $match) { "mismatch"; exit 2 }',
    'Stop-Process -Id $TargetPid -Force -ErrorAction Stop',
    '"stopped"'
  ].join('; ')

  try {
    const { stdout } = await execFileAsync('powershell.exe', [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      script,
      String(entry.pid),
      entry.exePath ?? '',
      entry.configPath ?? ''
    ])
    return /missing|stopped/i.test(stdout)
  } catch {
    return false
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
  const entry = await readFile(pidFile, 'utf8').then(parsePidFile).catch(() => null)
  if (!entry || entry.owner !== owner) {
    await rm(pidFile, { force: true }).catch(() => undefined)
    return true
  }

  const cleaned = process.platform === 'win32'
    ? await stopWindowsProcessIfMatches(entry)
    : stopPosixProcess(entry)

  if (cleaned) {
    await rm(pidFile, { force: true }).catch(() => undefined)
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
