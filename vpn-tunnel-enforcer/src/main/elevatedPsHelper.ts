import { spawn, type ChildProcess } from 'child_process'
import { isProcessElevated } from './admin'
import { logEvent } from './appLogger'

interface PendingCommand {
  resolve: (result: { stdout: string; stderr: string; exitCode: number }) => void
  reject: (err: Error) => void
  timer: ReturnType<typeof setTimeout>
  script: string
}

export class ElevatedPsHelperError extends Error {
  constructor(
    public readonly code: 'elevated-helper-unavailable' | 'elevated-helper-stopped' | 'elevated-helper-exited' | 'elevated-helper-timeout' | 'elevated-helper-script-rejected',
    message: string
  ) {
    super(message)
    this.name = 'ElevatedPsHelperError'
  }
}

let helperProcess: ChildProcess | null = null
let helperStarting: Promise<void> | null = null
let commandId = 0
const pendingCommands = new Map<number, PendingCommand>()
let restartCount = 0
const MAX_RESTARTS = 3
const MAX_SCRIPT_CHARS = 64 * 1024
const MAX_PENDING_COMMANDS = 8

export type ElevatedPsPolicy = 'firewall-killswitch' | 'physical-adapter-lockdown'

const BLOCKED_SCRIPT_TOKENS = [
  /\bInvoke-Expression\b/i,
  /\biex\b/i,
  /\bStart-Process\b/i,
  /\bInvoke-WebRequest\b/i,
  /\biwr\b/i,
  /\bInvoke-RestMethod\b/i,
  /\birm\b/i,
  /\bNew-Object\s+Net\.WebClient\b/i,
  /\bAdd-Type\b/i,
  /\bSet-ExecutionPolicy\b/i,
  /\bStart-BitsTransfer\b/i,
  /\bcmd(?:\.exe)?\b/i,
  /\bpowershell(?:\.exe)?\b/i,
  /\bpwsh(?:\.exe)?\b/i,
  /\bwscript(?:\.exe)?\b/i,
  /\bcscript(?:\.exe)?\b/i,
  /\bmshta(?:\.exe)?\b/i,
  /(^|[\s;])&(?!&)/,
  /&&|\|\|/,
  /\|\s*(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?)\b/i,
  /\bRemove-Item\b/i,
  /\bdel\b/i,
  /\brm\b/i
]

const POLICY_REQUIRED_TOKENS: Record<ElevatedPsPolicy, RegExp[]> = {
  'firewall-killswitch': [
    /\bGet-NetFirewallProfile\b/i,
    /\bSet-NetFirewallProfile\b/i,
    /\bNew-NetFirewallRule\b/i,
    /\bGet-NetFirewallRule\b/i,
    /\bRemove-NetFirewallRule\b/i
  ],
  'physical-adapter-lockdown': [
    /\bGet-NetAdapter\b/i,
    /\bGet-NetAdapterBinding\b/i,
    /\bDisable-NetAdapterBinding\b/i,
    /\bEnable-NetAdapterBinding\b/i,
    /\bSet-DnsClientServerAddress\b/i,
    /\bClear-DnsClientCache\b/i,
    /\bnetsh\b/i,
    /\breg\s+add\b/i
  ]
}

const POLICY_FORBIDDEN_TOKENS: Record<ElevatedPsPolicy, RegExp[]> = {
  'firewall-killswitch': [
    /\bGet-NetAdapter\b/i,
    /\bGet-NetAdapterBinding\b/i,
    /\bDisable-NetAdapterBinding\b/i,
    /\bEnable-NetAdapterBinding\b/i,
    /\bSet-DnsClientServerAddress\b/i,
    /\bnetsh\b/i,
    /\breg\s+add\b/i,
    /\broute\s+(?:add|change|delete)\b/i
  ],
  'physical-adapter-lockdown': [
    /\bGet-NetFirewallProfile\b/i,
    /\bSet-NetFirewallProfile\b/i,
    /\bNew-NetFirewallRule\b/i,
    /\bRemove-NetFirewallRule\b/i,
    /\bnetsh\s+advfirewall\b/i,
    /\breg\s+add\s+(?:HKLM|HKEY_LOCAL_MACHINE)\\.*\\Run\b/i,
    /\broute\s+(?:add|change|delete)\b/i
  ]
}

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
          pending.reject(new ElevatedPsHelperError('elevated-helper-exited', `PS helper exited (code=${code}, signal=${signal})`))
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
    pending.reject(new ElevatedPsHelperError('elevated-helper-stopped', 'PS helper stopped'))
  }
}

export async function execElevatedPs(
  script: string,
  timeoutMs = 30000,
  policy: ElevatedPsPolicy
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  if (process.platform !== 'win32') {
    throw new Error('execElevatedPs is only available on Windows')
  }
  if (script.length > MAX_SCRIPT_CHARS) {
    throw new Error(`PS helper script is too large (${script.length} chars)`)
  }
  if (pendingCommands.size >= MAX_PENDING_COMMANDS) {
    throw new Error(`PS helper queue is full (${pendingCommands.size} pending)`)
  }
  validateScriptPolicy(script, policy)

  if (!isElevatedPsHelperRunning()) {
    if (restartCount < MAX_RESTARTS) {
      restartCount++
      await startElevatedPsHelper()
    }
    if (!isElevatedPsHelperRunning()) {
      throw new ElevatedPsHelperError('elevated-helper-unavailable', 'PS helper is not running and could not be started')
    }
  }

  const id = ++commandId

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingCommands.delete(id)
      reject(new ElevatedPsHelperError('elevated-helper-timeout', `PS command timed out after ${timeoutMs}ms: ${script.slice(0, 100)}`))
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

function validateScriptPolicy(script: string, policy: ElevatedPsPolicy): void {
  for (const token of BLOCKED_SCRIPT_TOKENS) {
    if (token.test(script)) {
      throw new ElevatedPsHelperError(
        'elevated-helper-script-rejected',
        `PS helper script rejected by ${policy} policy: blocked token ${token.source}`
      )
    }
  }
  for (const token of POLICY_FORBIDDEN_TOKENS[policy]) {
    if (token.test(script)) {
      throw new ElevatedPsHelperError(
        'elevated-helper-script-rejected',
        `PS helper script rejected by ${policy} policy: forbidden command ${token.source}`
      )
    }
  }
  if (!POLICY_REQUIRED_TOKENS[policy].some(token => token.test(script))) {
    throw new ElevatedPsHelperError(
      'elevated-helper-script-rejected',
      `PS helper script rejected by ${policy} policy: no allowed command token found`
    )
  }
}
