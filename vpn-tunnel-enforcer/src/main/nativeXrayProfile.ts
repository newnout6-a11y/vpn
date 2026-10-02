/** Lossless Xray connection data. Stored inside the encrypted outbound, never in diagnostics. */
export const NATIVE_XRAY_FIELD = 'vpnte_xray'
type Json = Record<string, any>
export interface NativeXrayProfile {
  version: 1
  selectedTag: string
  entry: { outboundTag?: string; balancerTag?: string }
  outbounds: Json[]
  routing?: Json
  observatory?: Json
  burstObservatory?: Json
  policy?: Json
}

export function getNativeXrayProfile(outbound: Json): NativeXrayProfile | null {
  const profile = outbound[NATIVE_XRAY_FIELD]
  if (profile === undefined) return null
  if (!profile || profile.version !== 1 || !Array.isArray(profile.outbounds)
    || !profile.selectedTag || !profile.entry) throw new Error('Invalid preserved Xray profile')
  return profile
}

export function preserveNativeXrayProfile(selected: Json, context?: Json,
  entry: NativeXrayProfile['entry'] = { outboundTag: selected.tag || 'proxy' }): NativeXrayProfile {
  const raw = JSON.parse(JSON.stringify(selected))
  raw.tag = raw.tag || 'proxy'
  const needsGraph = Boolean(entry.balancerTag || (entry.outboundTag && entry.outboundTag !== raw.tag)
    || raw.streamSettings?.sockopt?.dialerProxy || raw.proxySettings?.tag)
  const outbounds = (needsGraph ? context?.outbounds || [raw] : [raw]).map((o: Json) => o === selected || o.tag === raw.tag
    || (!selected.tag && context?.outbounds?.length === 1) ? raw : o)
  const profile: NativeXrayProfile = { version: 1, selectedTag: raw.tag, entry, outbounds }
  for (const key of ['routing', 'observatory', 'burstObservatory', 'policy'] as const) {
    if (context?.[key]) profile[key] = context[key]
  }
  // Keep only reachable dependencies. Independent raw outbounds must not each
  // copy the entire subscription (quadratic memory / duplicated credentials).
  const graph = compileNativeXrayProfile(profile, raw)
  const sourceTag = (tag: string) => tag === 'proxy' ? raw.tag : tag.slice('vpnte-source:'.length)
  const usedTags = new Set(graph.outbounds.map(o => sourceTag(o.tag)))
  profile.outbounds = outbounds.filter((o: Json) => usedTags.has(o.tag))
  const virtualTags = new Set(graph.rules.flatMap(r => r.inboundTag || []).map((tag: string) => tag.slice('vpnte-loop:'.length)))
  const balancerTags = new Set(graph.balancers.map(b => b.tag.slice('vpnte-balancer:'.length)))
  if (context?.routing) profile.routing = {
    rules: (context.routing.rules || []).filter((r: Json) => r.inboundTag?.some((tag: string) => virtualTags.has(tag))),
    balancers: (context.routing.balancers || []).filter((b: Json) => balancerTags.has(b.tag))
  }
  return JSON.parse(JSON.stringify(profile))
}

export function nativeXraySelectedOutbound(profile: NativeXrayProfile): Json {
  const outbound = profile.outbounds.find(o => o.tag === profile.selectedTag)
  if (!outbound) throw new Error('Preserved Xray entry outbound is missing')
  return JSON.parse(JSON.stringify(outbound))
}

/** Only an unconditional terminal route can describe the complete provider connection. */
export function nativeXrayDocumentEntry(document: Json): NativeXrayProfile['entry'] | null {
  if (!Array.isArray(document.routing?.balancers) || !document.routing.balancers.length) return null
  const rule = document.routing?.rules?.at(-1)
  if (!rule || Object.keys(rule).some(k => !['type', 'network', 'outboundTag', 'balancerTag'].includes(k))) return null
  if (rule.network && rule.network !== 'tcp,udp' && rule.network !== 'udp,tcp') return null
  if (rule.outboundTag) return { outboundTag: rule.outboundTag }
  if (rule.balancerTag) return { balancerTag: rule.balancerTag }
  return null
}

/**
 * Compile only the connection graph reachable from the chosen entry. Provider
 * listeners, global application bypass rules, DNS and file/log paths are excluded.
 * Virtual loopback routes and balancers retain the provider's connection policy.
 */
export function compileNativeXrayProfile(profile: NativeXrayProfile, primary: Json,
  leafDialerProxy?: string): { outbounds: Json[]; rules: Json[]; balancers: Json[]; entry: Json; observatory?: Json; burstObservatory?: Json; policy?: Json } {
  const byTag = new Map<string, Json>()
  for (const outbound of profile.outbounds) {
    if (!outbound.tag || byTag.has(outbound.tag)) throw new Error('Missing or duplicate preserved Xray outbound tag')
    byTag.set(outbound.tag, outbound)
  }
  const balancerByTag = new Map<string, Json>()
  for (const balancer of profile.routing?.balancers || []) {
    if (!balancer.tag || balancerByTag.has(balancer.tag)) throw new Error('Invalid preserved Xray balancer tag')
    balancerByTag.set(balancer.tag, balancer)
  }
  const visited = new Set<string>(), active = new Set<string>(), usedBalancers = new Set<string>(), protectedEntries = new Set<string>()
  const loopRules: Json[] = []
  const candidates = (balancer: Json): string[] => [...byTag.keys()].filter(tag =>
    (balancer.selector || []).some((prefix: string) => tag.startsWith(prefix)))
  const visitBalancer = (tag: string, application: boolean): void => {
    const balancer = balancerByTag.get(tag)
    if (!balancer) throw new Error('Missing preserved Xray balancer dependency')
    const targets = candidates(balancer)
    if (balancer.fallbackTag) targets.push(balancer.fallbackTag)
    if (!targets.length) throw new Error('Empty preserved Xray balancer')
    usedBalancers.add(tag)
    for (const target of new Set(targets)) visitOutbound(target, application)
  }
  const visitOutbound = (tag: string, application: boolean): void => {
    const outbound = byTag.get(tag)
    if (!outbound) throw new Error('Missing preserved Xray outbound dependency')
    // A plain application egress must never be enabled by a provider fallback.
    // Freedom is allowed as a dialer for an encrypted VPN connection.
    if (application && ['freedom', 'socks', 'http', 'dns'].includes(outbound.protocol)) {
      throw new Error('Preserved Xray application route can bypass VPN protection')
    }
    if (active.has(tag)) throw new Error('Cyclic preserved Xray connection dependencies')
    if (visited.has(tag) && (!application || protectedEntries.has(tag))) return
    active.add(tag)
    if (outbound.protocol === 'loopback') {
      const inbound = outbound.settings?.inboundTag
      const rules = (profile.routing?.rules || []).filter((r: Json) => Array.isArray(r.inboundTag) && r.inboundTag.includes(inbound))
      if (!inbound || !rules.length) throw new Error('Missing preserved Xray loopback route')
      for (const rule of rules) {
        if (rule.outboundTag) visitOutbound(rule.outboundTag, application)
        else if (rule.balancerTag) visitBalancer(rule.balancerTag, application)
        else throw new Error('Preserved Xray loopback route has no destination')
        if (!loopRules.includes(rule)) loopRules.push(rule)
      }
    } else {
      if (!['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria', 'freedom', 'blackhole'].includes(outbound.protocol)) {
        throw new Error('Unsupported preserved Xray outbound dependency')
      }
      const dialer = outbound.streamSettings?.sockopt?.dialerProxy
      if (dialer) visitOutbound(dialer, false)
      if (outbound.proxySettings?.tag) visitOutbound(outbound.proxySettings.tag, false)
    }
    active.delete(tag)
    visited.add(tag)
    if (application) protectedEntries.add(tag)
  }
  if (profile.entry.outboundTag) visitOutbound(profile.entry.outboundTag, true)
  else if (profile.entry.balancerTag) visitBalancer(profile.entry.balancerTag, true)
  else throw new Error('Preserved Xray profile has no application entry')
  // The selected outbound is also used for endpoint/bootstrap metadata.
  if (!visited.has(profile.selectedTag)) throw new Error('Preserved Xray selected outbound is outside its entry graph')
  const mappedTag = (tag: string) => tag === profile.selectedTag ? 'proxy' : `vpnte-source:${tag}`
  const mappedBalancer = (tag: string) => `vpnte-balancer:${tag}`
  const mappedInbound = (tag: string) => `vpnte-loop:${tag}`
  const outbounds = [...visited].map(tag => {
    const raw = tag === profile.selectedTag ? primary : byTag.get(tag)!
    const outbound = JSON.parse(JSON.stringify(raw))
    const rejectFileReferences = (value: any): void => {
      if (!value || typeof value !== 'object') return
      for (const [key, child] of Object.entries(value)) {
        if (/^(?:certificateFile|keyFile|echConfigListFile|sessionTicketKeyFile)$/i.test(key) && child) {
          throw new Error('Preserved Xray subscription references an external local file')
        }
        rejectFileReferences(child)
      }
    }
    rejectFileReferences(outbound)
    outbound.tag = mappedTag(tag)
    if (outbound.protocol === 'loopback') outbound.settings.inboundTag = mappedInbound(outbound.settings.inboundTag)
    const dialer = outbound.streamSettings?.sockopt?.dialerProxy
    if (dialer) outbound.streamSettings.sockopt.dialerProxy = mappedTag(dialer)
    if (outbound.proxySettings?.tag) outbound.proxySettings.tag = mappedTag(outbound.proxySettings.tag)
    if (leafDialerProxy && outbound.protocol !== 'loopback' && outbound.protocol !== 'blackhole'
      && !dialer && !outbound.proxySettings?.tag) {
      outbound.streamSettings ||= {}
      outbound.streamSettings.sockopt = { ...outbound.streamSettings.sockopt, dialerProxy: leafDialerProxy }
    }
    return outbound
  })
  outbounds.sort((a, b) => Number(b.tag === 'proxy') - Number(a.tag === 'proxy'))
  const rules = loopRules.map(rule => {
    const copy = JSON.parse(JSON.stringify(rule))
    copy.inboundTag = copy.inboundTag.filter((tag: string) => [...visited].some(t => byTag.get(t)?.settings?.inboundTag === tag)).map(mappedInbound)
    if (copy.outboundTag) copy.outboundTag = mappedTag(copy.outboundTag)
    if (copy.balancerTag) copy.balancerTag = mappedBalancer(copy.balancerTag)
    return copy
  })
  // Conditional virtual rules must fail closed instead of falling into the primary.
  const virtualInbounds = [...visited].filter(t => byTag.get(t)?.protocol === 'loopback').map(t => mappedInbound(byTag.get(t)!.settings.inboundTag))
  if (virtualInbounds.length) rules.push({ type: 'field', inboundTag: virtualInbounds, outboundTag: 'block' })
  const balancers = [...usedBalancers].map(tag => {
    const copy = JSON.parse(JSON.stringify(balancerByTag.get(tag)))
    copy.tag = mappedBalancer(tag)
    // Exact expanded tags preserve selector semantics despite namespacing.
    copy.selector = candidates(balancerByTag.get(tag)!).filter(t => visited.has(t)).map(mappedTag)
    if (copy.fallbackTag) copy.fallbackTag = mappedTag(copy.fallbackTag)
    return copy
  })
  const entry = profile.entry.outboundTag ? { outboundTag: mappedTag(profile.entry.outboundTag) }
    : { balancerTag: mappedBalancer(profile.entry.balancerTag!) }
  const result: ReturnType<typeof compileNativeXrayProfile> = { outbounds, rules, balancers, entry }
  if (profile.policy) result.policy = JSON.parse(JSON.stringify(profile.policy))
  for (const key of ['observatory', 'burstObservatory'] as const) {
    if (!profile[key]) continue
    const copy = JSON.parse(JSON.stringify(profile[key]))
    copy.subjectSelector = [...visited].filter(tag => (copy.subjectSelector || []).some((prefix: string) => tag.startsWith(prefix))).map(mappedTag)
    if (copy.subjectSelector.length) result[key] = copy
  }
  return result
}
