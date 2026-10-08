import { spawn, execFile as execFileCb, type ChildProcess } from 'child_process'
import { isProcessElevated } from './admin'
import { logEvent } from './appLogger'

interface PendingCommand {
  resolve: (result: { stdout: string; stderr: string; exitCode: number }) => void
  reject: (err: Error) => void
  timer: ReturnType<typeof setTimeout>
  script: string
  policy: ElevatedPsPolicy
  submittedAt: number
}

export class ElevatedPsHelperError extends Error {
  constructor(
    public readonly code: 'elevated-helper-unavailable' | 'elevated-helper-stopped' | 'elevated-helper-exited' | 'elevated-helper-timeout' | 'elevated-helper-script-rejected' | 'elevated-helper-script-too-large',
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

export type ElevatedPsPolicy = 'firewall-killswitch' | 'physical-adapter-lockdown' | 'wfp-ipv6'

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
  'wfp-ipv6': [/\bVPNTE\.IPv6\.NativeEngine\b/, /\bWFP_APPS:/],
  'firewall-killswitch': [
    /\bGet-VpnteFirewallRuleNames\b/i,
    /\bNew-VpnteFirewallRule\b/i,
    /\bRemove-VpnteFirewallRules\b/i,
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
  'wfp-ipv6': [
    /\b(?:Set|New|Remove)-NetFirewall\w*\b/i,
    /\b(?:Set|Disable|Enable|Remove|New)-Net(?:Adapter|IP|Route|TCP)\w*\b/i,
    /\bSet-DnsClientServerAddress\b/i,
    /\bHNetCfg\b/i,
    /\bnetsh\b/i,
    /\breg\s+add\b/i,
    /\b(?:New|Remove)-VpnteFirewall\w*\b/i
  ],
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
    /\bHNetCfg\.Fw(?:Policy2|Rule)\b/i,
    /\b(?:Get-VpnteFirewallRuleNames|New-VpnteFirewallRule|Remove-VpnteFirewallRules)\b/i,
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
    $executionWatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      $sb = [ScriptBlock]::Create($cmd.script)
      $output = & $sb *>&1 | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] -and $_ -isnot [System.Management.Automation.DebugRecord] }
      $stdout = ($output | Out-String)
    } catch {
      $stderr = $_.Exception.Message
      $exitCode = 1
    }
    $executionWatch.Stop()
    $result = @{ id = [int]$cmd.id; success = $exitCode -eq 0; stdout = $stdout; stderr = $stderr; exitCode = $exitCode; executionMs = $executionWatch.ElapsedMilliseconds }
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

const HELPER_WARMUP_COMMANDS: ReadonlyArray<{ policy: ElevatedPsPolicy; script: string }> = [
  { policy: 'firewall-killswitch', script: 'Import-Module NetSecurity -ErrorAction Stop; Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop | Out-Null' },
  // Yield to admitted work between imports; never queue one long adapter warm-up.
  ...['NetAdapter', 'DnsClient', 'NetTCPIP', 'NetConnection'].map(moduleName => ({
    policy: 'physical-adapter-lockdown' as const,
    script: `Import-Module ${moduleName} -ErrorAction Stop; Get-NetAdapter -ErrorAction Stop | Out-Null`
  }))
]

/** Prepare this helper only; query results are discarded, never reused as evidence. */
export async function warmElevatedPsHelper(shouldDefer: () => boolean = () => false): Promise<void> {
  const owner = helperProcess
  if (!owner || !isElevatedPsHelperRunning()) return
  for (const command of HELPER_WARMUP_COMMANDS) {
    const module = command.script.match(/^Import-Module (\w+)/)![1]
    let deferred = false
    for (;;) {
      // Never restart this helper or dispatch into its replacement.
      if (helperProcess !== owner || !isElevatedPsHelperRunning()) return
      if (pendingCommands.size === 0 && !shouldDefer()) break
      if (!deferred) logEvent('debug', 'ps-helper', 'warm-up deferred', { module })
      deferred = true
      await new Promise<void>(done => { setTimeout(done, 100).unref?.() })
    }
    if (deferred) logEvent('debug', 'ps-helper', 'warm-up resumed', { module })
    const started = performance.now()
    let outcome = 'failed'
    try {
      const result = await execElevatedPs(command.script, 15000, command.policy)
      if (result.exitCode !== 0) throw new Error('Helper warm-up failed')
      outcome = 'complete'
    } catch {
      logEvent('warn', 'ps-helper', 'fixed read-only warm-up unavailable', { policy: command.policy })
    } finally {
      logEvent('debug', 'ps-helper', 'warm-up timing', { policy: command.policy, module, outcome,
        durationMs: Math.round(performance.now() - started) })
    }
  }
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
              const roundtripMs = Math.max(0, performance.now() - pending.submittedAt)
              const executionMs = typeof result.executionMs === 'number' && Number.isFinite(result.executionMs)
                && result.executionMs >= 0 && result.executionMs <= roundtripMs + 5 ? result.executionMs : undefined
              // This residual includes queue wait AND pipe/serialization overhead.
              // Never log source, stdout, stderr, or network identifiers here.
              logEvent('debug', 'ps-helper', 'command timing', {
                policy: pending.policy, roundtripMs: Math.round(roundtripMs),
                ...(executionMs !== undefined ? { executionMs,
                  transportOverheadMs: Math.round(Math.max(0, roundtripMs - executionMs)) } : {})
              })
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
    const proc = helperProcess
    helperProcess = null
    try {
      proc.stdin?.write('__EXIT__\n')
      proc.stdin?.end()
    } catch {}
    setTimeout(() => {
      try {
        if (!proc.killed && proc.exitCode === null) {
          proc.kill('SIGTERM')
        }
      } catch {}
    }, 1000)
  }
  for (const [id, pending] of pendingCommands) {
    clearTimeout(pending.timer)
    pendingCommands.delete(id)
    pending.reject(new ElevatedPsHelperError('elevated-helper-stopped', 'PS helper stopped'))
  }
}

function terminateHungHelper(cause: Error): void {
  const proc = helperProcess
  helperProcess = null
  if (proc) {
    try {
      logEvent('warn', 'ps-helper', 'terminating hung elevated PS helper process', {
        pid: proc.pid,
        error: cause.message
      })
      proc.kill('SIGKILL')
      if (proc.pid && process.platform === 'win32') {
        execFileCb('taskkill.exe', ['/F', '/T', '/PID', String(proc.pid)], { windowsHide: true }, () => {})
      }
    } catch (e: any) {
      logEvent('warn', 'ps-helper', 'error terminating hung helper', { error: e?.message || String(e) })
    }
  }
  for (const [pendingId, pending] of pendingCommands) {
    clearTimeout(pending.timer)
    pendingCommands.delete(pendingId)
    pending.reject(
      new ElevatedPsHelperError('elevated-helper-exited', `PS helper terminated due to hung command: ${cause.message}`)
    )
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
    throw new ElevatedPsHelperError('elevated-helper-script-too-large', `PS helper script is too large (${script.length} chars)`)
  }
  if (pendingCommands.size >= MAX_PENDING_COMMANDS) {
    throw new Error(`PS helper queue is full (${pendingCommands.size} pending)`)
  }
  let policySource = script
  if (policy === 'wfp-ipv6') {
    // Exempt only the exact bundled, SHA-256-verified loader. Add-Type remains
    // prohibited in caller-supplied bodies and every other helper policy.
    const { wfpPrelude } = await import('./wfpIpv6')
    const prelude = await wfpPrelude()
    if (!script.startsWith(prelude)) throw new ElevatedPsHelperError('elevated-helper-script-rejected', 'Untrusted WFP loader')
    policySource = script.slice(prelude.length)
  }
  validateScriptPolicy(policySource, policy)

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
      const timeoutError = new ElevatedPsHelperError(
        'elevated-helper-timeout',
        `PS command timed out after ${timeoutMs}ms: ${script.slice(0, 100)}`
      )
      terminateHungHelper(timeoutError)
      reject(timeoutError)
    }, timeoutMs)

    pendingCommands.set(id, { resolve, reject, timer, script, policy, submittedAt: performance.now() })

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
