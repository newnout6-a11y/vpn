import { spawn, type ChildProcess } from 'child_process'
import { isProcessElevated } from './admin'
import { logEvent } from './appLogger'

interface PendingCommand {
  resolve: (result: { stdout: string; stderr: string; exitCode: number }) => void
  reject: (err: Error) => void
  timer: ReturnType<typeof setTimeout>
  script: string
}

let helperProcess: ChildProcess | null = null
let helperStarting: Promise<void> | null = null
let commandId = 0
const pendingCommands = new Map<number, PendingCommand>()
let restartCount = 0
const MAX_RESTARTS = 3

const PS_RUNNER_SCRIPT = `
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
while ($line = [Console]::In.ReadLine()) {
  if ($line -eq '__EXIT__') { break }
  try {
    $cmd = $line | ConvertFrom-Json
    $stdout = [string]::Empty
    $stderr = [string]::Empty
    $exitCode = 0
    try {
      $output = Invoke-Expression $cmd.script *>&1 | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] -and $_ -isnot [System.Management.Automation.DebugRecord] }
      $stdout = ($output | Out-String)
    } catch {
      $stderr = $_.Exception.Message
      $exitCode = 1
    }
    $result = @{ id = [int]$cmd.id; success = $exitCode -eq 0; stdout = $stdout; stderr = $stderr; exitCode = $exitCode }
    $result | ConvertTo-Json -Compress -Depth 3
  } catch {
    $result = @{ id = 0; success = $false; stdout = ''; stderr = "JSON parse error: $_"; exitCode = 1 }
    $result | ConvertTo-Json -Compress -Depth 3
  }
  [Console]::Out.Flush()
}
`

export function isElevatedPsHelperRunning(): boolean {
  return helperProcess !== null && !helperProcess.killed && helperProcess.exitCode === null
}

export async function startElevatedPsHelper(): Promise<void> {
  if (isElevatedPsHelperRunning()) return
  if (helperStarting) return helperStarting

  helperStarting = (async () => {
    if (process.platform !== 'win32') {
      logEvent('debug', 'ps-helper', 'skipped on non-Windows platform')
      return
    }

    const elevated = await isProcessElevated()
    if (!elevated) {
      logEvent('warn', 'ps-helper', 'app is not elevated — helper will use sudo-prompt fallback')
      return
    }

    try {
      helperProcess = spawn(
        'powershell.exe',
        ['-NoProfile', '-NoLogo', '-ExecutionPolicy', 'Bypass', '-Command', PS_RUNNER_SCRIPT],
        {
          windowsHide: true,
          stdio: ['pipe', 'pipe', 'pipe']
        }
      )

      let stdoutBuffer = ''

      helperProcess.stdout?.on('data', (chunk: Buffer) => {
        stdoutBuffer += chunk.toString('utf8')
        let newlineIdx: number
        while ((newlineIdx = stdoutBuffer.indexOf('\n')) >= 0) {
          const line = stdoutBuffer.slice(0, newlineIdx).trim()
          stdoutBuffer = stdoutBuffer.slice(newlineIdx + 1)
          if (!line) continue
          try {
            const result = JSON.parse(line)
            const id = result.id
            const pending = pendingCommands.get(id)
            if (pending) {
              clearTimeout(pending.timer)
              pendingCommands.delete(id)
              pending.resolve({
                stdout: result.stdout || '',
                stderr: result.stderr || '',
                exitCode: result.exitCode || 0
              })
            }
          } catch {
            // Not a JSON line — ignore (PS debug output, etc.)
          }
        }
      })

      helperProcess.stderr?.on('data', (chunk: Buffer) => {
        const text = chunk.toString('utf8').trim()
        if (text) {
          logEvent('debug', 'ps-helper', 'stderr', { text: text.slice(0, 500) })
        }
      })

      helperProcess.on('exit', (code, signal) => {
        logEvent('info', 'ps-helper', 'helper process exited', { code, signal, pendingCount: pendingCommands.size })
        helperProcess = null
        for (const [id, pending] of pendingCommands) {
          clearTimeout(pending.timer)
          pendingCommands.delete(id)
          pending.reject(new Error(`PS helper exited (code=${code}, signal=${signal})`))
        }
      })

      helperProcess.on('error', (err) => {
        logEvent('warn', 'ps-helper', 'helper process error', { error: err.message })
        helperProcess = null
      })

      logEvent('info', 'ps-helper', 'persistent elevated PS helper started')
      restartCount = 0
    } catch (err: any) {
      logEvent('warn', 'ps-helper', 'failed to start helper', { error: err?.message || String(err) })
      helperProcess = null
    }
  })()

  try {
    await helperStarting
  } finally {
    helperStarting = null
  }
}

export function stopElevatedPsHelper(): void {
  if (helperProcess) {
    try {
      helperProcess.stdin?.write('__EXIT__\n')
      helperProcess.stdin?.end()
    } catch {}
    setTimeout(() => {
      if (helperProcess) {
        try { helperProcess.kill() } catch {}
      }
    }, 1000)
    helperProcess = null
  }
  for (const [id, pending] of pendingCommands) {
    clearTimeout(pending.timer)
    pendingCommands.delete(id)
    pending.reject(new Error('PS helper stopped'))
  }
}

export async function execElevatedPs(
  script: string,
  timeoutMs = 30000
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  if (process.platform !== 'win32') {
    throw new Error('execElevatedPs is only available on Windows')
  }

  if (!isElevatedPsHelperRunning()) {
    if (restartCount < MAX_RESTARTS) {
      restartCount++
      await startElevatedPsHelper()
    }
    if (!isElevatedPsHelperRunning()) {
      throw new Error('PS helper is not running and could not be started')
    }
  }

  const id = ++commandId

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingCommands.delete(id)
      reject(new Error(`PS command timed out after ${timeoutMs}ms: ${script.slice(0, 100)}`))
    }, timeoutMs)

    pendingCommands.set(id, { resolve, reject, timer, script })

    const cmd = JSON.stringify({ id, script, timeout: timeoutMs }) + '\n'
    try {
      helperProcess!.stdin!.write(cmd)
    } catch (err: any) {
      clearTimeout(timer)
      pendingCommands.delete(id)
      reject(new Error(`Failed to write to PS helper stdin: ${err?.message || String(err)}`))
    }
  })
}
