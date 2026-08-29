/**
 * Consistent pseudonymization for exported traffic-forensics artifacts.
 *
 * THE PROBLEM. `stageTrafficForensicsArtifacts` used to copy the whole session
 * directory into the support ZIP verbatim, while the bundle's own manifest
 * claimed "sensitive values are redacted". Raw ETL/pcapng were excluded, but
 * everything else was not: `dns.ndjson` lists every domain the user resolved,
 * `flows.ndjson` every remote IP and port, `netstat-*.txt` and `dns-cache-*.txt`
 * the complete connection table and resolver cache. A user reading that manifest
 * would reasonably conclude the bundle was scrubbed, and hand it to support.
 *
 * WHY NOT JUST MASK EVERYTHING. Replacing every address with `<redacted-ip>`
 * would make the artifacts worthless — the entire point of packet forensics is
 * correlating a DNS answer with a flow with a reset with a firewall drop, and
 * that correlation lives in the addresses. Stripping them turns a diagnosable
 * bundle into noise, which would push users back to sending raw captures.
 *
 * WHAT WE DO INSTEAD. Consistent pseudonymization: every distinct address maps
 * to a stable token for the lifetime of one export, so
 *
 *     DNS a.example.com -> 203.0.113.7 ; flow to 203.0.113.7:443 was reset
 *
 * becomes
 *
 *     DNS <domain-1>.com -> <ip-public-1> ; flow to <ip-public-1>:443 was reset
 *
 * The causal chain survives intact; the addresses do not leave the machine. Two
 * properties are deliberately preserved because leak analysis depends on them:
 *
 *   1. Address class. `<ip-public-N>` vs `<ip-private-N>` — "did this egress to
 *      a public address outside the tunnel" is the leak question, and it is
 *      answerable from the class alone.
 *   2. Public suffix. `<domain-4>.ru` keeps smart-RU split-routing analysis
 *      possible (was an RU host sent direct, was a foreign host sent direct)
 *      without disclosing which host it was.
 *
 * Loopback and our own TUN constants pass through unchanged: they are fixed,
 * public knowledge from this very source tree, and `tunPathConfirmed` reasoning
 * is unreadable without them.
 *
 * The token→value mapping is never written to the bundle. It only exists in
 * memory for the duration of the export; that is the whole point.
 */

import { isIP } from 'node:net'
import { getDomain, getPublicSuffix } from 'tldts'
import { TUN_IPV4_PREFIX } from './tunAdapter'

/**
 * MAC addresses are matched FIRST and with a strict shape. `aa:bb:cc:dd:ee:ff`
 * is also a syntactically plausible IPv6 fragment, so if the IPv6 pass ran
 * first every MAC in the bundle would come out as a bogus `<ipv6-*>` token.
 */
const MAC_RE = /\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/gi

/**
 * IPv6 is matched as a loose *candidate* and then validated with `net.isIP`,
 * rather than pinned down by regex. A regex tight enough to accept every legal
 * form (`::`-compression, zone IDs, IPv4-mapped) and reject everything else is
 * unreadable and gets it wrong at the edges: an earlier version silently
 * matched only `2001:db8:` out of `2001:db8::dead:beef` and left the rest of the
 * address in the file. Validating the candidate makes over-matching harmless —
 * a timestamp like `12:34:56` fails `isIP` and passes through untouched.
 */
const IPV6_CANDIDATE_RE = /[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[0-9a-z_.-]+)?/gi
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
/**
 * Hostnames with at least two labels and a plausible alphabetic TLD. The
 * alphabetic-TLD requirement keeps dotted-quad literals out; the IPv4 pass
 * above owns those.
 */
const HOST_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi

/**
 * Hostnames that appear in our own artifacts and carry no user information:
 * masking them just makes the bundle harder to read.
 */
const HOST_ALLOWLIST = new Set([
  'localhost',
  'localhost.localdomain'
])

/**
 * Substrings that mark a "hostname-looking" match as in fact a filename or a
 * schema/namespace token from our own artifacts. Masking `summary.json` or
 * `wfp-state.xml` would be pure noise.
 */
const NOT_A_HOST = /\.(json|ndjson|txt|xml|etl|pcapng|log|exe|dll|ps1|tmp|manifest|csv|xsd|md)$/i

function isLoopback(ip: string): boolean {
  return ip === '127.0.0.1' || ip.startsWith('127.') || ip === '::1' || ip === '0.0.0.0' || ip === '::'
}

function isOwnTunIpv4(ip: string): boolean {
  return ip.startsWith(TUN_IPV4_PREFIX)
}

/**
 * Private / link-local / CGNAT / multicast per RFC1918, RFC3927, RFC6598.
 * Classifying rather than disclosing is enough for leak analysis.
 */
function isPrivateIpv4(ip: string): boolean {
  const octets = ip.split('.').map(Number)
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return false
  const [a, b] = octets
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 255) return true
  if (a >= 224 && a <= 239) return true
  return false
}

function isPrivateIpv6(ip: string): boolean {
  const lower = ip.toLowerCase()
  // fc00::/7 unique-local, fe80::/10 link-local, ff00::/8 multicast.
  return /^f[cd]/.test(lower) || /^fe[89ab]/.test(lower) || lower.startsWith('ff')
}

export interface ForensicsRedactionStats {
  ipv4: number
  ipv6: number
  mac: number
  hosts: number
}

export interface ForensicsRedactor {
  /** Pseudonymize a text blob (txt, xml, ndjson line, log). */
  redactText(value: string): string
  /** Pseudonymize a parsed JSON value, walking strings and numeric-free keys. */
  redactJson(value: unknown): unknown
  /** How many distinct values were replaced, for the export manifest. */
  stats(): ForensicsRedactionStats
}

/**
 * Build a redactor whose token assignment is stable for its own lifetime. Use
 * ONE redactor per export so tokens line up across every file in the bundle —
 * a fresh redactor per file would break exactly the correlation this exists to
 * preserve.
 */
export function createForensicsRedactor(): ForensicsRedactor {
  const ipv4 = new Map<string, string>()
  const ipv6 = new Map<string, string>()
  const mac = new Map<string, string>()
  const hosts = new Map<string, string>()

  const tokenFor = (
    table: Map<string, string>,
    key: string,
    build: (index: number) => string
  ): string => {
    const existing = table.get(key)
    if (existing) return existing
    const token = build(table.size + 1)
    table.set(key, token)
    return token
  }

  const redactIpv4 = (raw: string): string => {
    if (isLoopback(raw) || isOwnTunIpv4(raw)) return raw
    const kind = isPrivateIpv4(raw) ? 'private' : 'public'
    return tokenFor(ipv4, raw, index => `<ip-${kind}-${index}>`)
  }

  const redactIpv6 = (raw: string): string => {
    if (isLoopback(raw)) return raw
    const kind = isPrivateIpv6(raw) ? 'private' : 'public'
    return tokenFor(ipv6, raw, index => `<ipv6-${kind}-${index}>`)
  }

  const redactMac = (raw: string): string =>
    tokenFor(mac, raw.toLowerCase(), index => `<mac-${index}>`)

  const redactHost = (raw: string): string => {
    const lower = raw.toLowerCase()
    if (HOST_ALLOWLIST.has(lower)) return raw
    if (NOT_A_HOST.test(lower)) return raw
    // Keep the public suffix so RU-vs-foreign routing stays analyzable. When
    // tldts cannot classify the name (an internal TLD, say) mask the whole thing
    // rather than guessing — a wrong split would leak the interesting label.
    const suffix = getPublicSuffix(lower, { allowPrivateDomains: false })
    const registrable = getDomain(lower, { allowPrivateDomains: false })
    if (!suffix || !registrable) {
      return tokenFor(hosts, lower, index => `<host-${index}>`)
    }
    const token = tokenFor(hosts, registrable, index => `<domain-${index}>`)
    // Subdomains of one registrable domain share its token and keep their depth
    // visible, which matters for CDN/wildcard analysis.
    const labelsBelow = lower.slice(0, Math.max(0, lower.length - registrable.length))
      .replace(/\.$/, '')
    const depth = labelsBelow ? labelsBelow.split('.').filter(Boolean).length : 0
    const prefix = depth > 0 ? `<sub${depth}>.` : ''
    return `${prefix}${token}.${suffix}`
  }

  const redactText = (value: string): string => {
    if (!value) return value
    return value
      // MACs first — see MAC_RE. The placeholder they leave behind contains no
      // colons, so it cannot be re-matched by the IPv6 pass.
      .replace(MAC_RE, match => redactMac(match))
      .replace(IPV6_CANDIDATE_RE, match => {
        // Strip the zone ID before validating; isIP rejects `fe80::1%eth0`.
        const zoneAt = match.indexOf('%')
        const address = zoneAt === -1 ? match : match.slice(0, zoneAt)
        if (isIP(address) !== 6) return match
        const token = redactIpv6(address)
        // Pass-through (loopback) keeps its zone; a tokenized address drops it,
        // because the interface name is itself topology.
        return token === address ? match : token
      })
      .replace(IPV4_RE, match => redactIpv4(match))
      .replace(HOST_RE, match => redactHost(match))
  }

  const redactJson = (value: unknown): unknown => {
    if (typeof value === 'string') return redactText(value)
    if (Array.isArray(value)) return value.map(redactJson)
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {}
      for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
        // Keys are our own schema names, never user data — leave them readable.
        out[key] = redactJson(raw)
      }
      return out
    }
    return value
  }

  return {
    redactText,
    redactJson,
    stats: () => ({
      ipv4: ipv4.size,
      ipv6: ipv6.size,
      mac: mac.size,
      hosts: hosts.size
    })
  }
}

/**
 * Redact an NDJSON body line by line. Falls back to text redaction for lines
 * that are not valid JSON, so a truncated last line (the capture was still
 * being written) is scrubbed rather than passed through raw.
 */
export function redactNdjson(body: string, redactor: ForensicsRedactor): string {
  const lines = body.split(/\r?\n/)
  const out: string[] = []
  for (const line of lines) {
    if (!line.trim()) {
      out.push('')
      continue
    }
    try {
      out.push(JSON.stringify(redactor.redactJson(JSON.parse(line))))
    } catch {
      out.push(redactor.redactText(line))
    }
  }
  return out.join('\n')
}

/** Redact a JSON document, falling back to text redaction if it will not parse. */
export function redactJsonDocument(body: string, redactor: ForensicsRedactor): string {
  try {
    return JSON.stringify(redactor.redactJson(JSON.parse(body)), null, 2)
  } catch {
    return redactor.redactText(body)
  }
}
