// AT-00-005, AT-01-001: stream progress immediately; never echo arguments or raw errors.
import { appendFileSync } from 'node:fs'
import { performance } from 'node:perf_hooks'

export function createProgressLog(path, { write = line => process.stdout.write(line), heartbeatMs = 5000, admit = () => {} } = {}) {
  const started = performance.now(), pending = new Map()
  let sequence = 0
  const record = (event, fields = {}) => {
    const line = `${new Date().toISOString()} +${Math.round(performance.now() - started)}ms ${JSON.stringify({ event, ...fields })}\n`
    // One synchronous append preserves order and evidence even if a later operation hangs.
    appendFileSync(path, line)
    write(line)
  }
  const timer = setInterval(() => {
    for (const [id, action] of pending) record('waiting', { id, action: action.name,
      elapsedMs: Math.round(performance.now() - action.started) })
  }, heartbeatMs)
  timer.unref()
  return { record, close: () => clearInterval(timer), async run(action, operation) {
    const id = ++sequence, start = performance.now()
    pending.set(id, { name: action, started: start })
    record('started', { id, action })
    try {
      admit(action)
      const value = await operation()
      record('finished', { id, action, elapsedMs: Math.round(performance.now() - start), ...safeActionResult(value) })
      return value
    } catch (error) {
      record('failed', { id, action, elapsedMs: Math.round(performance.now() - start), ...safeActionResult(error) })
      throw error
    } finally { pending.delete(id) }
  } }
}

const categories = ['validation', 'permission', 'network', 'conflict', 'internal', 'cancelled', 'timeout']
export function safeActionResult(value) {
  const result = {}
  for (const key of ['success', 'cancelled']) if (typeof value?.[key] === 'boolean') result[key] = value[key]
  const category = value?.category ?? value?.error?.category
  if (categories.includes(category)) result.category = category
  if (typeof value?.oracleCode === 'string' && /^VPNTE_ORACLE_(?:RUNTIME_INVENTORY|CONFIG_READ|ADAPTER_INVENTORY|ADDRESS_INVENTORY|SELECTOR_IDENTITY|TUN_IDENTITY|SLOT_IDENTITY|ENDPOINT_ROUTE)$/.test(value.oracleCode)) result.oracleCode = value.oracleCode
  return result
}

export function safeSnapshot(s) {
  const oneOf = (value, allowed) => allowed.includes(value) ? value : null
  return { at: new Date().toISOString(), revision: Number.isSafeInteger(s.revision) ? s.revision : null,
    state: oneOf(s.state, ['disconnected', 'connected', 'error', 'blocked', 'unknown']),
    transition: oneOf(s.transition, ['connecting', 'disconnecting', 'reconnecting']),
    processState: oneOf(s.processState, ['running', 'stopped']), pid: Number.isSafeInteger(s.pid) ? s.pid : null,
    cleanupRequired: s.cleanupRequired === true,
    correlationId: /^(?:ipc|op)_[0-9a-f]{32}$/i.test(s.operation?.correlationId ?? '') ? s.operation.correlationId : null,
    operationStatus: oneOf(s.operation?.status, ['pending', 'running', 'success', 'error', 'cancelled']) }
}

const phases = new Set(`initial-stale-cleanup initial-create-allows initial-set-block initial-exceptions
  restore-profiles restore-remove-rules live-read-manifest live-prepare-journal live-apply-policy live-commit-journal
  initial-read-manifest verified-adapter-wait snapshot-profiles initial-prepare-journal initial-apply-policy
  initial-commit-journal restore-policy clear-journal registryMs notifyMs stop-previous prepare-runtime cleanup-pid
  rotate-log resolve-server pick-port resolve-connection-graph write-config config-preflight write-pid allow-firewall
  wait-local-socks physical-dns-sources foreign-tun-preflight split-tunnel-rules wfp-priority-reserve adapter-lockdown
  physical-dns-sources-await proxy-listen-and-owner-lookup proxy-full-tunnel-preflight owned-runtime-cleanup
  stale-tun-cleanup singbox-config-check singbox-launch-submit wait-singbox-process adapter-lockdown-await
  wait-tun-interface tun-ownership-record tun-interface-metric-set tun-interface-metric-readback firewall-kill-switch
  firewall-kill-switch-await initial-upstream-probe initial-outbound-selection runtime-pid runtime-stop-preflight stop-runtime wait-runtime-exit stop-xray
  rollback-baseline disable-firewall rollback-adapters repair-dns`.split(/\s+/))

// Raw application logs stay on the disposable runner. Only fixed messages and numeric timings escape.
export function safeAppEvent(event) {
  if (!event || typeof event !== 'object') return null
  const allowed = event.scope === 'ipc'
    ? /^(start-direct-vpn|stop-tun|cancel-tun|servers:(select|cancel-switch|ping-one)|get-firewall-kill-switch-status) (started|finished|failed)$/.test(event.message)
    : ({ app: ['application ready', 'renderer process gone', 'renderer became unresponsive', 'failed to load renderer index.html',
          'relaunching elevated', 'startup failed; saved configuration retained', 'before quit', 'all windows closed',
          'uncaughtException — keeping app alive', 'unhandledRejection — keeping app alive', 'child process gone',
          'failed to start elevated PS helper', 'crash recovery failed', 'startup network recovery unconfirmed',
          'checking for stale TUN adapter during crash recovery', 'V2 feature modules registered and initialized'],
        security: ['Secure store preflight failed; startup refused without changing network protection'],
        tun: ['start timing', 'stop timing', 'stop started', 'stop step started', 'stop step completed',
          'owned runtime status probe failed', 'runtime process stop after stop failed',
          'native runtime PID unavailable, using PowerShell',
          'native runtime status timing', 'native runtime status unavailable, using PowerShell',
          'native route selection timing', 'native route selection unavailable, using PowerShell',
          'start refused because another TUN/VPN is already active', 'WFP priority reservation failed',
          'adapter lockdown result', 'physical adapter lockdown did not apply', 'physical adapter lockdown threw', 'xray startup failed',
          'failed to prepare TUN runtime', 'sing-box exited before startup completed',
          'firewall kill-switch failed to engage — aborting start and rolling back',
          'startup validation failed — rolling back', 'startup runtime termination failed', 'startup rollback step failed',
          'retained TUN upstream switch finished'],
        'ipc-security': ['IPC request rejected', 'IPC request failed'], xray: ['start timing'],
        'phys-lockdown': ['batch lockdown failed', 'transition adapters disabled', 'transition adapter snapshot failed',
          'DNS registry snapshot failed; refusing mutation without baseline', 'snapshot parse failed',
          'lockdown not checked: no physical adapters were discovered', 'adapter coverage rollback failed',
          'physical adapter set changed; lockdown coverage is not verified'],
        'ps-helper': ['command timing', 'warm-up timing'], 'firewall-killswitch': ['command timing', 'phase timing', 'native phase timing'],
        'runtime-acl': ['inspection timing'],
        'socks-upstream-probe': ['candidate egress probe completed'],
        'ip-monitor': ['protected transition IP baseline refreshed', 'protected transition IP baseline not checked', 'public IP provider timing'],
        'system-network': ['baseline native phase timing',
          'native WinINet notification unavailable; falling back to PowerShell'] })[event.scope]?.includes?.(event.message)
  if (!allowed || !Number.isFinite(Date.parse(event.ts))) return null
  const result = { at: event.ts, scope: event.scope, message: event.message }
  for (const key of ['ms', 'totalMs', 'durationMs', 'elapsedMs', 'roundtripMs', 'executionMs', 'transportOverheadMs', 'persistMs', 'adapters']) {
    const value = event.details?.[key]
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) result[key] = value
  }
  for (const key of ['correlationId', 'clockId']) {
    const pattern = key === 'clockId' ? /^clock_[0-9a-f]{24}$/i : /^(?:ipc|op)_[0-9a-f]{32}$/i
    if (pattern.test(event[key] ?? '')) result[key] = event[key]
  }
  if (Number.isFinite(event.monotonicMs) && event.monotonicMs >= 0) result.monotonicMs = event.monotonicMs
  if (event.scope === 'ip-monitor' && Number.isInteger(event.details?.attempt) && event.details.attempt >= 1 && event.details.attempt <= 3) result.attempt = event.details.attempt
  if (event.scope === 'ip-monitor' && event.message === 'public IP provider timing') {
    const index = event.details?.providerIndex
    if (Number.isInteger(index) && index >= 0 && index < 4) result.provider = ['cloudflare', 'ipify', 'icanhazip', 'myip'][index]
    if (['succeeded', 'failed', 'cancelled', 'backoff'].includes(event.details?.outcome)) result.outcome = event.details.outcome
  }
  if (event.scope === 'runtime-acl' && ['worker', 'standalone'].includes(event.details?.transport)) result.transport = event.details.transport
  if (event.scope === 'tun' && event.message === 'retained TUN upstream switch finished') {
    if (['success', 'cancelled', 'failed'].includes(event.details?.outcome)) result.outcome = event.details.outcome
    for (const key of ['committed', 'previousPreserved', 'ownershipLost']) {
      if (typeof event.details?.[key] === 'boolean') result[key] = event.details[key]
    }
    if (Array.isArray(event.details?.phases)) {
      const allowed = ['stage', 'probe', 'select', 'confirm', 'commit', 'restore', 'confirm-previous',
        'stop-candidate', 'stop-previous', 'ownership']
      result.phases = [...new Set(event.details.phases.filter(phase => allowed.includes(phase)))]
    }
    const phaseTimes = {}
    for (const phase of ['stage', 'probe', 'select', 'restore-selector', 'confirm-candidate', 'confirm-previous', 'stop-candidate', 'stop-previous']) {
      const ms = event.details?.phasesMs?.[phase]
      if (typeof ms === 'number' && Number.isFinite(ms) && ms >= 0) phaseTimes[phase] = ms
    }
    if (Object.keys(phaseTimes).length) result.phasesMs = phaseTimes
  }
  if (event.scope === 'socks-upstream-probe') {
    for (const [key, allowed] of Object.entries({
      stage: ['local-connect', 'socks-handshake', 'tls-handshake', 'https-response', 'response-body', 'socket-close'],
      outcome: ['success', 'network', 'cancelled', 'timeout', 'internal'],
      code: ['CONNECT_FAILED', 'SOCKS_FAILED', 'SOCKS_AUTH_REQUIRED', 'SOCKS_AUTH_REJECTED', 'SOCKS_UPSTREAM_REJECTED', 'SOCKS_CLOSED', 'TLS_FAILED', 'HTTPS_FAILED', 'HTTP_STATUS', 'RESPONSE_TOO_LARGE',
        'INVALID_PUBLIC_IP', 'SOCKET_CLOSE_UNCONFIRMED', 'CANCELLED', 'DEADLINE', 'OK'],
      nativeCode: ['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT', 'ERR_SOCKET_CLOSED',
        'ERR_INVALID_ARG_TYPE', 'ERR_INVALID_ARG_VALUE', 'ERR_INVALID_PROTOCOL', 'ERR_STREAM_WRITE_AFTER_END',
        'ERR_TLS_INVALID_PROTOCOL_VERSION', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED',
        'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'ERR_SSL_WRONG_VERSION_NUMBER', 'ERR_SSL_NO_SUITABLE_SIGNATURE_ALGORITHM', 'ERR_OSSL_EVP_UNSUPPORTED',
        'ECONNABORTED', 'EACCES', 'EPERM', 'ENETUNREACH', 'EHOSTUNREACH', 'ERR_TLS_HANDSHAKE_TIMEOUT',
        'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE', 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', 'ERR_SSL_UNEXPECTED_EOF_WHILE_READING']
    })) if (allowed.includes(event.details?.[key])) result[key] = event.details[key]
    if ([0, 1].includes(event.details?.providerIndex)) result.providerIndex = event.details.providerIndex
  }
  if (event.scope === 'ps-helper' && event.message === 'warm-up timing') {
    if (['NetSecurity', 'Network', 'NetAdapter', 'DnsClient', 'NetTCPIP', 'NetConnection'].includes(event.details?.module)) result.module = event.details.module
    if (['complete', 'failed'].includes(event.details?.outcome)) result.outcome = event.details.outcome
  }
  if (['SECURE_STORE_PREFLIGHT_FAILED', 'STARTUP_FAILED'].includes(event.details?.code)) result.code = event.details.code
  for (const key of ['phase', 'step']) if (phases.has(event.details?.[key])) result[key] = event.details[key]
  const timings = {}
  for (const [phase, value] of Object.entries(event.details?.phaseDurations ?? {})) {
    const ms = typeof value === 'number' ? value : value?.durationMs
    if (phases.has(phase) && typeof ms === 'number' && Number.isFinite(ms) && ms >= 0) timings[phase] = ms
  }
  if (Object.keys(timings).length) result.phaseDurations = timings
  if (typeof event.details?.success === 'boolean') result.success = event.details.success
  if (typeof event.details?.applied === 'boolean') result.applied = event.details.applied
  for (const [key, allowed] of Object.entries({ reason: [...categories, 'invalid-payload', 'untrusted-sender'],
    status: ['error', 'cancelled'], channel: ['start-direct-vpn', 'stop-tun', 'cancel-tun', 'servers:select', 'servers:cancel-switch', 'servers:ping-one'] })) {
    if (allowed.includes(event.details?.[key])) result[key] = event.details[key]
  }
  // Diagnose native/config failures using fixed labels; never publish matched text.
  const diagnostic = event.details?.error ?? event.details
  const errorText = typeof event.details === 'string' ? event.details :
    [event.details?.message, typeof diagnostic === 'string' ? diagnostic : diagnostic?.message,
      event.details?.out, ...(Array.isArray(event.details?.warnings) ? event.details.warnings : [])]
      .filter(value => typeof value === 'string').join('\n')
  for (const [kind, pattern] of [
    ['lockdown-manifest', /Invalid lockdown manifest/],
    ['adapter-snapshot', /Missing physical adapter snapshot|Invalid adapter snapshot|Duplicate adapter identity/],
    ['transition-snapshot', /Invalid transition snapshot/], ['dns-policy-missing', /Missing DNS policy snapshot/],
    ['dns-policy-baseline', /DNS registry baseline could not be verified/],
    ['dns-policy-value', /Unsupported DNS registry snapshot value/],
    ['dns-policy-schema', /Incomplete DNS registry snapshot|Invalid DNS registry snapshot/],
    ['runtime-acl', /RuntimeSecurityAclError|untrusted runtime directory/i],
    ['runtime-path-unavailable', /Runtime path unavailable|Cannot prove runtime exit: executable path unavailable|runtime PID: executable path unavailable/],
    ['runtime-process-enumeration', /runtime PID: incomplete process enumeration/],
    ['runtime-status-invalid', /Owned runtime status response is invalid|Native owned runtime state response is invalid/],
    ['unknown-config-field', /unknown field/i], ['invalid-config', /decode config|parse config|check config/i],
    ['file-missing', /ENOENT|cannot find the file/i], ['permission-denied', /EACCES|EPERM|access is denied/i],
    ['socket-conflict', /EADDRINUSE/], ['native-timeout', /ETIMEDOUT|timed out|Owned runtime status deadline exceeded/i]
  ]) if (pattern.test(errorText)) { result.errorKind = kind; break }
  if (event.scope === 'tun' && ['native runtime PID unavailable, using PowerShell', 'native runtime status unavailable, using PowerShell'].includes(event.message)) {
    const pathMessage = typeof diagnostic === 'string' ? diagnostic : diagnostic?.message
    const pathFailure = typeof pathMessage === 'string' && /^runtime PID: executable path unavailable \((OpenProcess|QueryFullProcessImageNameW); win32=(0|[1-9][0-9]{0,9})(?:; exit=(active|unavailable|invalid))?\)$/.exec(pathMessage)
    if (pathFailure && pathFailure[0] === pathMessage) {
      result.runtimePathApi = pathFailure[1]
      result.runtimePathError = ({ 0: 'unspecified', 5: 'access-denied', 6: 'invalid-handle', 31: 'general-failure',
        87: 'invalid-parameter', 122: 'insufficient-buffer', 299: 'partial-copy', 1168: 'not-found' })[pathFailure[2]] ?? 'other'
      if (pathFailure[3]) result.runtimePathState = pathFailure[3]
    }
  }
  if (result.errorKind === 'adapter-snapshot') {
    const fields = ['ifIndex', 'alias', 'ipv6Enabled', 'forcedIpv6Off', 'interfaceGuid', 'ipv4DnsSource', 'ipv4DnsServers', 'forcedDnsTo']
      .filter(field => new RegExp(`\\b${field}\\b`).test(errorText))
    if (fields.length) result.invalidFields = fields
  }
  if (['Error', 'TypeError', 'SyntaxError', 'RecoveryWorkerError'].includes(diagnostic?.name)) result.errorName = diagnostic.name
  if (['unavailable', 'rejected', 'busy', 'closed', 'timeout', 'exited', 'protocol'].includes(diagnostic?.code)) result.workerError = diagnostic.code
  const stack = typeof diagnostic?.stack === 'string' ? diagnostic.stack : ''
  const locations = [...stack.matchAll(/\bindex\.js:([0-9]{1,7}):([0-9]{1,6})/g)].slice(0, 3)
    .map(match => ({ line: Number(match[1]), column: Number(match[2]) }))
  if (locations.length) result.sourceLocations = locations
  const issues = []
  for (const [kind, pattern] of [
    ['adapter-ipv6', /A[0-9]+_ipv6_err:|IPv6 (?:binding not verified|read-back mismatch)/],
    ['adapter-dns', /A[0-9]+_dns_err:|DNS read-back mismatch/],
    ['dns-smart-name-resolution', /DNS_SMNR_err:/], ['dns-parallel-queries', /DNS_PARALLEL_err:/],
    ['teredo', /TRANS_teredo_err:/], ['6to4', /TRANS_6to4_err:/], ['isatap', /TRANS_isatap_err:/],
    ['adapter-coverage', /physical adapter set (?:changed|could not be verified)/]
  ]) if (pattern.test(errorText)) issues.push(kind)
  if (issues.length) result.lockdownIssues = issues
  return result
}

export function safeElectronDiagnostic(line) {
  // Chromium fatal/error headers identify a source location; the rest can contain private data.
  const match = /:(FATAL|ERROR):(?:[A-Za-z0-9_.\\/-]*[\\/])?([A-Za-z0-9_-]+\.(?:cc|cpp|h))(?:\(|:)([0-9]{1,6})\)?\]/.exec(line)
  if (!match) return null
  const result = { severity: match[1], sourceFile: match[2], sourceLine: Number(match[3]), checkFailed: line.includes('Check failed:') }
  const code = /(?:error_code|exit_code)=(-?[0-9]{1,10})/.exec(line)
  if (match[2] === 'gpu_process_host.cc' && code) result.gpuCode = Number(code[1])
  return result
}
