/**
 * Proxy Engine Resolver — determines whether sing-box or xray-core should
 * handle the upstream proxy connection.
 *
 * Upstream xray-core >= 26.7.11 enforces a default minClientVer on REALITY inbounds
 * that rejects all sing-box clients ("reality verification failed").
 * In 'auto' mode (default), profiles using REALITY are routed through the bundled
 * xray-core engine, while other protocols (and non-REALITY outbounds) remain on sing-box.
 */

export type ProxyEngineMode = 'auto' | 'sing-box' | 'xray'

export const XRAY_CAPABLE_PROTOCOLS = new Set([
 'vless',
 'vmess',
 'trojan',
 'shadowsocks'
])

/**
 * Resolves which proxy core should execute the outbound connection.
 *
 * - Non-xray capable protocols (hysteria2, tuic, wireguard, naive, anytls, shadowtls)
 * always resolve to 'sing-box'.
 * - Explicit setting 'sing-box' forces sing-box.
 * - Explicit setting 'xray' uses xray for any xray-capable protocol.
 * - 'auto' mode uses xray ONLY when the outbound has REALITY TLS enabled.
 */
export function resolveProxyEngine(
 outbound: Record<string, any> | undefined | null,
 setting: ProxyEngineMode | string = 'auto'
): 'sing-box' | 'xray' {
 if (!outbound || typeof outbound !== 'object') return 'sing-box'
 const type = String(outbound.type || '').toLowerCase()
 if (!XRAY_CAPABLE_PROTOCOLS.has(type)) {
 return 'sing-box'
 }
 if (setting === 'sing-box') return 'sing-box'
 if (setting === 'xray') return 'xray'

 // 'auto' mode (default): switch to xray only if REALITY TLS is enabled
 const tls = outbound.tls
 const isReality =
 tls &&
 typeof tls === 'object' &&
 tls.reality &&
 typeof tls.reality === 'object' &&
 tls.reality.enabled !== false

 return isReality ? 'xray' : 'sing-box'
}
