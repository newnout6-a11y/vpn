// Read-only JSONL timing report. Usage: node scripts/analyze-lifecycle-log.mjs app.log
// Without a filename, read stdin. Output deliberately excludes args/results/errors/IPs.
import { readFile } from 'node:fs/promises'

const channels = new Set(['start-tun', 'start-direct-vpn', 'stop-tun', 'cancel-tun', 'cancel-transition'])
const phaseNames = new Set([
  'physical-dns-sources', 'physical-dns-sources-await',
  'foreign-tun-preflight', 'split-tunnel-rules', 'proxy-listen-and-owner-lookup', 'proxy-full-tunnel-check',
  'prepare-runtime', 'owned-runtime-cleanup', 'singbox-config-check', 'stale-tun-cleanup',
  'singbox-launch-submit', 'wait-singbox-process', 'adapter-lockdown', 'adapter-lockdown-await',
  'wait-tun-interface', 'tun-ownership-record', 'tun-interface-metric-set', 'tun-interface-metric-readback',
  'firewall-kill-switch-await', 'firewall-kill-switch', 'stop-xray', 'stop-runtime', 'wait-runtime-exit',
  'rollback-baseline', 'disable-firewall', 'rollback-adapters', 'repair-dns', 'runtime-stop-preflight',
  'stop-previous', 'cleanup-pid', 'rotate-log', 'resolve-server', 'pick-port', 'write-config',
  'config-preflight', 'write-pid', 'allow-firewall', 'wait-local-socks'
])
const finiteMs = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
const timestamp = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT/.test(value) && Number.isFinite(Date.parse(value)) ? value : null
const pending = new Map()
const report = {
  schemaVersion: 1, invalidLines: 0, outOfOrderRecords: 0, ipc: [], timings: [], unfinished: [], summary: [],
  limits: ['IPC finished is not proof of protection or successful rollback.', 'Summary combines terminal outcomes, including cancelled/failed connections.', 'Parallel/background phase durations must not be summed.', 'Overlapping same-channel operations have no reliable pairing without operation IDs.']
}

function consume(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) { report.invalidLines++; return }
  const at = timestamp(event.ts)
  if (!at || typeof event.message !== 'string') { report.invalidLines++; return }
  const details = event.details && typeof event.details === 'object' ? event.details : {}
  if (event.scope === 'ipc') {
    const match = /^(\S+) (started|finished|failed)$/.exec(event.message)
    if (!match || !channels.has(match[1])) return
    const [, channel, kind] = match
    const queue = pending.get(channel) ?? []
    if (kind === 'started') {
      if (queue.length) queue.forEach(item => { item.ambiguous = true })
      queue.push({ at, ambiguous: queue.length > 0 })
      pending.set(channel, queue)
      return
    }
    const start = queue.shift()
    const elapsed = start && !start.ambiguous ? Date.parse(at) - Date.parse(start.at) : null
    const ordered = elapsed !== null && elapsed >= 0
    if (elapsed !== null && !ordered) report.outOfOrderRecords++
    report.ipc.push({ channel, terminal: kind, endedAt: at,
      startedAt: ordered ? start.at : null, elapsedMs: ordered ? elapsed : null,
      loggedMs: finiteMs(details.ms), pairing: !start ? 'missing-start' : start.ambiguous ? 'ambiguous' : ordered ? 'unique-window' : 'out-of-order'
    })
    return
  }
  if (!['tun', 'xray'].includes(event.scope) || !['start timing', 'stop timing'].includes(event.message)) return
  const phases = {}
  for (const [name, value] of Object.entries(details.phaseDurations ?? {})) {
    if (!phaseNames.has(name)) continue
    const durationMs = finiteMs(typeof value === 'number' ? value : value?.durationMs)
    if (durationMs === null) continue
    const phase = { durationMs }
    if (value && typeof value === 'object') {
      for (const field of ['startMs', 'endMs']) {
        const ms = finiteMs(value[field])
        if (ms !== null) phase[field] = ms
      }
      for (const field of ['parallel', 'background', 'failed']) if (typeof value[field] === 'boolean') phase[field] = value[field]
    }
    phases[name] = phase
  }
  report.timings.push({ scope: event.scope, action: event.message === 'start timing' ? 'start' : 'stop', at, totalMs: finiteMs(details.totalMs), phases })
}

try {
  if (process.argv.length > 3) throw new Error('Usage: node scripts/analyze-lifecycle-log.mjs [app.log]')
  let source
  if (process.argv[2]) source = await readFile(process.argv[2], 'utf8')
  else {
    const chunks = []
    for await (const chunk of process.stdin) chunks.push(chunk)
    source = Buffer.concat(chunks).toString('utf8')
  }
  for (const line of source.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    if (!line.trim()) continue
    try { consume(JSON.parse(line)) } catch { report.invalidLines++ }
  }
  for (const [channel, queue] of pending) for (const start of queue) report.unfinished.push({ channel, startedAt: start.ambiguous ? null : start.at, pairing: start.ambiguous ? 'ambiguous' : 'missing-terminal' })
  for (const channel of channels) {
    // Prefer the logger's monotonic duration; derive from timestamps only when unambiguous.
    const values = report.ipc.filter(item => item.channel === channel).map(item => item.loggedMs ?? item.elapsedMs).filter(value => value !== null).sort((a, b) => a - b)
    if (!values.length) continue
    const n = values.length
    report.summary.push({ channel, samples: n, minMs: values[0], medianMs: (values[Math.floor((n - 1) / 2)] + values[Math.floor(n / 2)]) / 2, p95Ms: values[Math.ceil(n * 0.95) - 1], maxMs: values[n - 1] })
  }
  process.stdout.write(JSON.stringify(report, null, 2) + '\n')
} catch (error) {
  // Paths may contain private account names; expose only the OS code or fixed usage text.
  process.stderr.write((error?.code ?? 'Invalid arguments or input') + '\n')
  process.exitCode = 1
}
