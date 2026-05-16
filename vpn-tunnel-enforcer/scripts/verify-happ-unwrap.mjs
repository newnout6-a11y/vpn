// Quick standalone verification of the happ:// unwrap logic.
// Mirrors the implementation in src/main/vpnProfiles.ts so we can sanity-check
// the parser without booting Electron. Keep this file in sync with the real
// implementation; it is meant for local manual runs and not part of CI.

function safeDecode(value) {
  try { return decodeURIComponent(value) } catch { return value }
}

function decodeBase64Text(value) {
  const compact = value.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (!compact || compact.length < 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null
  try {
    const padded = compact + '='.repeat((4 - compact.length % 4) % 4)
    const decoded = Buffer.from(padded, 'base64').toString('utf8')
    if (!decoded.trim() || decoded.includes('\u0000')) return null
    return decoded
  } catch { return null }
}

function unwrapHappAddLink(input) {
  const match = input.match(/^happ:\/\/([^/]+)(?:\/(.*))?$/i)
  if (!match) return null
  const host = match[1].toLowerCase()
  const rest = match[2] ?? ''
  if (host === 'crypt3' || host === 'crypt4' || host === 'crypt5' || host === 'crypto') {
    throw new Error('encrypted-' + host)
  }
  if (host === 'routing') throw new Error('routing-not-subscription')
  if (host === 'add') {
    const candidates = []
    const trySafeDecode = v => { const d = safeDecode(v).trim(); if (d) candidates.push(d) }
    trySafeDecode(rest)
    if (/^https?:\/\//i.test(rest)) candidates.push(rest)
    const b64 = decodeBase64Text(rest); if (b64) candidates.push(b64.trim())
    for (const c of candidates) {
      if (/^https?:\/\//i.test(c)) return c
      if (/^(?:vless|trojan|ss|vmess|hysteria2|hy2):\/\//i.test(c)) return c
      if (/(?:vless|trojan|ss|vmess|hysteria2|hy2):\/\//i.test(c)) return c
    }
    throw new Error('add-payload-unknown')
  }
  throw new Error('unknown-host-' + host)
}

const cases = [
  // URL-encoded https URL after happ://add/
  { input: 'happ://add/https%3A%2F%2Fsosa.la%2Fsub%2Fabc123', expect: 'https://sosa.la/sub/abc123' },
  // Bare https URL after happ://add/
  { input: 'happ://add/https://example.com/sub/xyz', expect: 'https://example.com/sub/xyz' },
  // Base64 of an https URL
  { input: 'happ://add/aHR0cHM6Ly9leGFtcGxlLmNvbS9zdWIvYWJjMTIz', expect: 'https://example.com/sub/abc123' },
  // Bare vless link
  { input: 'happ://add/vless%3A%2F%2Fuuid%40host%3A443', expect: 'vless://uuid@host:443' },
  // Non-happ input — pass-through (returns null)
  { input: 'https://example.com/sub', expect: null },
  // Encrypted subscription — should throw
  { input: 'happ://crypt3/AAAA', expectThrow: 'encrypted-crypt3' },
  { input: 'happ://crypt5/AAAA', expectThrow: 'encrypted-crypt5' },
  // Routing rule — should throw
  { input: 'happ://routing/onadd/AAAA', expectThrow: 'routing-not-subscription' },
  // Unknown happ host — should throw
  { input: 'happ://weird/something', expectThrow: 'unknown-host-weird' }
]

let pass = 0, fail = 0
for (const c of cases) {
  try {
    const got = unwrapHappAddLink(c.input)
    if (c.expectThrow) {
      console.error(`FAIL: ${c.input} → expected throw "${c.expectThrow}", got value "${got}"`); fail++
    } else if (got === c.expect) {
      console.log(`OK  : ${c.input} → ${got}`); pass++
    } else {
      console.error(`FAIL: ${c.input} → got "${got}", expected "${c.expect}"`); fail++
    }
  } catch (err) {
    if (c.expectThrow && err.message === c.expectThrow) {
      console.log(`OK  : ${c.input} → throws ${err.message}`); pass++
    } else {
      console.error(`FAIL: ${c.input} → unexpected throw "${err.message}"`); fail++
    }
  }
}
console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
