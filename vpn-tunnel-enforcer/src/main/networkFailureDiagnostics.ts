import { open } from 'node:fs/promises'
import { join } from 'node:path'
import { isIP, type Socket } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { SocksClient } from 'socks'

// No error messages, domains, addresses, credentials or response bodies cross
// this boundary. Even arbitrary error.code values are untrusted input.
export function networkFailureCode(error: unknown): string {
  const codes = new Set(['ECONNREFUSED', 'ECONNRESET', 'ECONNABORTED', 'ETIMEDOUT', 'EACCES', 'EPERM', 'ENETUNREACH', 'EHOSTUNREACH', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEOUT', 'ENODATA', 'ESERVFAIL', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_CANCELED', 'PROBE_RESPONSE_REJECTED'])
  let value = error as any
  for (let depth = 0; value && depth < 4; depth++, value = value.cause) {
    if (codes.has(value.code)) return value.code
    const message = String(value.message ?? '')
    if (/timed? ?out|timeout|deadline exceeded/i.test(message)) return 'ETIMEDOUT'
    if (/connection refused|actively refused/i.test(message)) return 'ECONNREFUSED'
    if (/connection reset|ECONNRESET/i.test(message)) return 'ECONNRESET'
    if (/permission denied|access.*forbidden|WSAEACCES/i.test(message)) return 'EACCES'
  }
  return 'UNKNOWN'
}

export const CORE_TAIL_BYTES = 256 * 1024
export async function readCoreLogTail(path: string): Promise<{ text: string; truncated: boolean }> {
  const file = await open(path, 'r')
  try {
    const size = (await file.stat()).size
    const start = Math.max(0, size - CORE_TAIL_BYTES)
    const bytes = Buffer.alloc(Math.min(size, CORE_TAIL_BYTES))
    const { bytesRead } = await file.read(bytes, 0, bytes.length, start)
    let text = bytes.subarray(0, bytesRead).toString('utf8')
    // The first record may have been cut in the middle of a line/UTF-8 codepoint.
    if (start > 0) text = text.includes('\n') ? text.slice(text.indexOf('\n') + 1) : ''
    return { text, truncated: start > 0 }
  } finally { await file.close() }
}

function coreInstant(line: string): number | null {
  const x = /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?/.exec(line)
  if (x) return new Date(+x[1], +x[2] - 1, +x[3], +x[4], +x[5], +x[6], +(x[7] ?? '').slice(0, 3).padEnd(3, '0')).getTime()
  const s = /^([+-]\d{4}) (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})/.exec(line)
  if (s) return Date.parse(`${s[2]}T${s[3]}${s[1].slice(0, 3)}:${s[1].slice(3)}`)
  return null
}

export function summarizeCoreNetwork(text: string, since: number) {
  const counts = { records: 0, dialing: 0, protocolRequests: 0, timeouts: 0, refused: 0, resets: 0, denied: 0, realityFailures: 0, tlsFailures: 0, localSocksFailures: 0 }
  for (const line of text.split(/\r?\n/)) {
    const at = coreInstant(line)
    if (at === null || at < since) continue
    counts.records++
    if (/dialing TCP/i.test(line)) counts.dialing++
    // This is protocol progress; it is not proof that an HTTPS response arrived.
    if (/tunneling request/i.test(line)) counts.protocolRequests++
    if (/i\/o timeout|deadline exceeded|timed? ?out/i.test(line)) counts.timeouts++
    if (/connection refused|actively refused/i.test(line)) counts.refused++
    if (/connection reset|forcibly closed/i.test(line)) counts.resets++
    if (/permission denied|WSAEACCES|access.*forbidden/i.test(line)) counts.denied++
    if (/reality verification failed|reality:.*invalid connection|bad reality/i.test(line)) counts.realityFailures++
    if (/x509|bad certificate|tls: handshake failure|remote error: tls/i.test(line)) counts.tlsFailures++
    if (/outbound\/socks\[proxy-out\]/i.test(line) && /dial tcp 127\.0\.0\.1:.*(?:refused|timeout|forbidden)/i.test(line)) counts.localSocksFailures++
  }
  return counts
}

async function coreSummary(dir: string, name: 'xray.log' | 'sing-box.log', since: number) {
  try {
    const tail = await readCoreLogTail(join(dir, name))
    return { readable: true, truncated: tail.truncated, ...summarizeCoreNetwork(tail.text, since) }
  } catch (error) { return { readable: false, code: networkFailureCode(error) } }
}

const PATH_PROBE_TIMEOUT_MS = 3000
export function failureAssessment(physicalTcp: { ok?: boolean; checked?: boolean }, engineHttps: { ok?: boolean; checked?: boolean }): string {
  if (engineHttps.ok === true) return 'TUN_PATH_FAILED_ENGINE_HTTPS_OK'
  if (physicalTcp.ok === false) return 'UPSTREAM_TCP_UNCONFIRMED'
  if (physicalTcp.ok === true && engineHttps.ok === false) return 'UPSTREAM_TCP_OK_ENGINE_EGRESS_UNCONFIRMED'
  return 'INSUFFICIENT_EVIDENCE'
}
// Only the configured VPN endpoint is probed over the physical path. The
// foreign HTTPS reflector always uses Xray's local SOCKS, bypassing TUN/DNS.
export function probeSocksPath(localPort: number, destination: { host: string; port: number }, verifyHttps = false): Promise<{ ok: boolean; stage: string; code?: string; elapsedMs: number }> {
  return new Promise(resolve => {
    const began = Date.now()
    let socket: Socket | undefined
    let secure: ReturnType<typeof tlsConnect> | undefined
    let done = false
    let stage = 'local-socks-and-remote-connect'
    let response = ''
    const finish = (ok: boolean, code?: string) => {
      if (done) return
      done = true
      clearTimeout(timer)
      secure?.destroy()
      socket?.destroy()
      resolve({ ok, stage, code, elapsedMs: Date.now() - began })
    }
    const timer = setTimeout(() => finish(false, 'ETIMEDOUT'), PATH_PROBE_TIMEOUT_MS)
    SocksClient.createConnection({ proxy: { host: '127.0.0.1', port: localPort, type: 5 }, command: 'connect', destination, timeout: PATH_PROBE_TIMEOUT_MS })
      .then(result => {
        socket = result.socket
        if (done) { socket.destroy(); return }
        if (!verifyHttps) { finish(true); return }
        stage = 'tls'
        // Validate the certificate against the IP SAN; no DNS or SNI lookup.
        secure = tlsConnect({ socket, rejectUnauthorized: true, servername: '', host: destination.host })
        secure.once('secureConnect', () => {
          stage = 'https-response'
          secure!.write('GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n')
        })
        secure.on('data', chunk => {
          response += chunk.toString('utf8')
          if (response.length > 16384) { finish(false, 'PROBE_RESPONSE_REJECTED'); return }
          const bodyAt = response.indexOf('\r\n\r\n')
          if (/^HTTP\/1\.[01] 200\b/.test(response) && bodyAt >= 0 && /(?:^|\n)ip=([^\r\n]+)\r?\n/.exec(response.slice(bodyAt + 4))?.[1]) {
            const value = /(?:^|\n)ip=([^\r\n]+)\r?\n/.exec(response.slice(bodyAt + 4))![1].trim()
            if (isIP(value)) finish(true)
          }
        })
        secure.once('error', error => finish(false, networkFailureCode(error)))
        secure.once('end', () => finish(false, 'PROBE_RESPONSE_REJECTED'))
        secure.once('close', () => finish(false, 'ECONNRESET'))
      })
      .catch(error => finish(false, networkFailureCode(error)))
  })
}

export async function collectTunnelFailureDiagnostics(options: {
  runtimeDir: string; startedAt: number; xrayStartedAt?: number | null
  xrayPort?: number | null; directPort?: number | null
  dialTarget?: { host: string; port: number } | null
}) {
  const [xray, tun, physicalTcp, engineHttps] = await Promise.all([
    coreSummary(options.runtimeDir, 'xray.log', options.xrayStartedAt ?? options.startedAt),
    coreSummary(options.runtimeDir, 'sing-box.log', options.startedAt),
    options.directPort && options.dialTarget && isIP(options.dialTarget.host)
      ? probeSocksPath(options.directPort, options.dialTarget) : Promise.resolve({ checked: false }),
    options.xrayPort ? probeSocksPath(options.xrayPort, { host: '1.1.1.1', port: 443 }, true) : Promise.resolve({ checked: false })
  ])
  return { schemaVersion: 1, sessionStartedAt: options.startedAt, assessment: failureAssessment(physicalTcp, engineHttps), xray, tun, physicalTcp, engineHttps }
}
