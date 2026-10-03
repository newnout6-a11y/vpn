/**
 * Proxy Engine Resolver — determines whether sing-box or xray-core should
 * handle the upstream proxy connection.
 *
 * Upstream xray-core >= 26.7.11 enforces a default minClientVer on REALITY inbounds
 * that rejects all sing-box clients ("reality verification failed").
 * In 'auto' mode, native Xray JSON, XHTTP, explicit gRPC modes and REALITY use Xray;
 * other translated profiles remain on sing-box.
 */

import { getNativeXrayProfile } from './nativeXrayProfile'

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
 * - Native JSON and Xray-specific transports reject forced sing-box.
 * - Explicit setting 'sing-box' forces sing-box for other translated profiles.
 * - Explicit setting 'xray' uses xray for any xray-capable protocol.
 * - 'auto' uses Xray for native JSON, Xray-specific transports or REALITY TLS.
 */
export function resolveProxyEngine(
 outbound: Record<string, any> | undefined | null,
 setting: ProxyEngineMode | string = 'auto'
): 'sing-box' | 'xray' {
 if (!outbound || typeof outbound !== 'object') return 'sing-box'
 const native = getNativeXrayProfile(outbound)
 if (native) {
   if (setting === 'sing-box') throw new Error('Этот JSON-профиль содержит настройки Xray; выберите Auto или Xray для сохранения маршрута.')
   return 'xray'
 }
 const type = String(outbound.type || '').toLowerCase()
 const transport = outbound.transport
 const requiresXrayTransport = ['xhttp', 'splithttp'].includes(String(transport?.type || '').toLowerCase())
   || transport?.type === 'grpc' && typeof transport.multi_mode === 'boolean'
 if (requiresXrayTransport && XRAY_CAPABLE_PROTOCOLS.has(type)) {
   if (setting === 'sing-box') throw new Error('Параметры транспорта требуют Xray; выберите Auto или Xray.')
   return 'xray'
 }
 if (!XRAY_CAPABLE_PROTOCOLS.has(type)) {
 return 'sing-box'
 }
 if (setting === 'sing-box') return 'sing-box'
 if (setting === 'xray') return 'xray'

 // Remaining 'auto' profiles use Xray when REALITY TLS is enabled.
 const tls = outbound.tls
 const isReality =
 tls &&
 typeof tls === 'object' &&
 tls.reality &&
 typeof tls.reality === 'object' &&
 tls.reality.enabled !== false

 return isReality ? 'xray' : 'sing-box'
}
