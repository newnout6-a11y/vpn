/**
 * Proxy Engine Resolver — determines whether sing-box or xray-core should
 * handle the upstream proxy connection.
 *
 * Upstream xray-core >= 26.7.11 enforces a default minClientVer on REALITY inbounds
 * that rejects all sing-box clients ("reality verification failed").
 * In 'auto' mode, preserved native Xray JSON and REALITY profiles use Xray;
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
 * - Preserved native Xray profiles require Xray; forcing sing-box is rejected.
 * - Explicit setting 'sing-box' forces sing-box for translated profiles.
 * - Explicit setting 'xray' uses xray for any xray-capable protocol.
 * - 'auto' uses Xray for native JSON or REALITY TLS.
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
