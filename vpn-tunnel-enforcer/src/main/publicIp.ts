// Shared, pure public-address validation; no Electron or runtime startup dependencies.
import { isIP } from 'node:net'
import { Address6 } from 'ip-address'

export function isPublicIpv4(ip: string): boolean {
  if (!ip || isIP(ip) !== 4) return false
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return false

  // 0.0.0.0/8 (Current network)
  if (parts[0] === 0) return false
  // 10.0.0.0/8 (Private)
  if (parts[0] === 10) return false
  // 100.64.0.0/10 (Shared address space / CGNAT - RFC 6598: 100.64.0.0 - 100.127.255.255)
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return false
  // 127.0.0.0/8 (Loopback)
  if (parts[0] === 127) return false
  // 169.254.0.0/16 (Link-local)
  if (parts[0] === 169 && parts[1] === 254) return false
  // 172.16.0.0/12 (Private: 172.16.0.0 - 172.31.255.255)
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false
  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return false
  // 192.0.2.0/24 (TEST-NET-1 documentation)
  if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return false
  // 192.88.99.0/24 (6to4 Relay Anycast)
  if (parts[0] === 192 && parts[1] === 88 && parts[2] === 99) return false
  // 192.168.0.0/16 (Private)
  if (parts[0] === 192 && parts[1] === 168) return false
  // 198.18.0.0/15 (Benchmarking: 198.18.0.0 - 198.19.255.255)
  if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return false
  // 198.51.100.0/24 (TEST-NET-2 documentation)
  if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return false
  // 203.0.113.0/24 (TEST-NET-3 documentation)
  if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return false
  // 224.0.0.0/4 (Multicast) and 240.0.0.0/4 (Reserved / Broadcast)
  if (parts[0] >= 224) return false

  return true
}

export function isPublicIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false
  const cleanIp = ip.trim().replace(/^\[|\]$/g, '')
  const family = isIP(cleanIp)
  if (family === 4) {
    return isPublicIpv4(cleanIp)
  }
  if (family === 6) {
    try {
      if (!Address6.isValid(cleanIp)) return false
      const a6 = new Address6(cleanIp)

      // Unpack IPv4-mapped IPv6 (::ffff:x.x.x.x)
      if (a6.is4()) {
        const v4 = a6.to4().address
        return isPublicIpv4(v4)
      }

      // Check standard IPv6 reserved ranges
      if (a6.isLoopback() || cleanIp === '::' || cleanIp === '::1') return false
      if (a6.isLinkLocal()) return false
      if (a6.isMulticast()) return false

      // Canonical form for prefix checks (0-padded hex per group)
      const canon = a6.canonicalForm() // e.g. 2001:0db8:0000:...
      // Unique-Local (fc00::/7 -> fc00::/8 and fd00::/8)
      if (canon.startsWith('fc') || canon.startsWith('fd')) return false
      // Link-local (fe80::/10)
      if (canon.startsWith('fe8') || canon.startsWith('fe9') || canon.startsWith('fea') || canon.startsWith('feb')) return false
      // Multicast (ff00::/8)
      if (canon.startsWith('ff')) return false

      // Documentation range: 2001:db8::/32 (RFC 3849)
      if (canon.startsWith('2001:0db8:') || canon.startsWith('2001:db8:')) return false

      // Discard prefix: 100::/64 (RFC 6666)
      if (canon.startsWith('0100:0000:0000:0000:') || canon.startsWith('0100::')) return false

      // ORCHID / ORCHIDv2: 2001:10::/28 and 2001:20::/28 (RFC 7343)
      if (canon.startsWith('2001:001') || canon.startsWith('2001:002')) return false

      // Benchmarking: 2001:2::/48 (RFC 5180)
      if (canon.startsWith('2001:0002:')) return false

      return true
    } catch {
      return false
    }
  }
  return false
}
