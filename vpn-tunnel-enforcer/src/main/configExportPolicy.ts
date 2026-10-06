import { redactSensitiveText } from './vpnProfiles'
import { NATIVE_XRAY_FIELD } from './nativeXrayProfile'
import type { ConfigExportData } from './configManager'

type Policy = (value: unknown) => unknown
const masked: Policy = () => 'REDACTED'
const scalar: Policy = value => {
  if (typeof value === 'string') return redactSensitiveText(value)
  if (value == null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value
  return masked(value)
}
// UUID-shaped application IDs are not VPN credentials. Only explicitly reviewed
// ID/FK positions get this policy; an outbound's id remains masked.
const reference: Policy = value => typeof value === 'string' ? value : value == null ? value : masked(value)
const list = (policy: Policy): Policy => value => Array.isArray(value) ? value.map(policy) : masked(value)
const fields = (...names: string[]): Record<string, Policy> => Object.fromEntries(names.map(name => [name, scalar]))
const object = (policies: Record<string, Policy>): Policy => value => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return masked(value)
  return Object.fromEntries(Object.entries(value).map(([field, item]) => [
    field, (Object.hasOwn(policies, field) ? policies[field] : masked)(item)
  ]))
}

// AT-01-008/011, F-144, AC-SET-CFG-001: review containers BEFORE descending.
// A known leaf name inside an unknown graph is not authorization to disclose it.
const outbound = object({
  ...fields('type', 'tag', 'server', 'server_port', 'method', 'flow', 'network',
    'enabled', 'server_name', 'insecure', 'fingerprint', 'path', 'host',
    'service_name', 'congestion_control', 'up_mbps', 'down_mbps', 'mtu',
    'version', 'packet_encoding', 'domain_strategy', 'detour', 'connect_timeout'),
  alpn: list(scalar),
  tls: object({
    ...fields('enabled', 'server_name', 'insecure', 'fingerprint'),
    alpn: list(scalar),
    utls: object(fields('enabled', 'fingerprint')),
    reality: object(fields('enabled'))
  }),
  transport: object(fields('type', 'path', 'host', 'service_name', 'method', 'network', 'enabled')),
  multiplex: object(fields('enabled', 'padding', 'max_connections', 'min_streams', 'max_streams')),
  [NATIVE_XRAY_FIELD]: masked
})

const profile = object({
  ...fields('name', 'protocol', 'server', 'port', 'resolvedIp', 'resolvedIpAt',
    'country', 'countryVerifiedAt', 'countryVerifiedIp', 'egressIp',
    'countryGeoVersion', 'clientDevice', 'clientFingerprint', 'ping', 'status',
    'lastChecked', 'healthStatus', 'healthCheckedAt', 'healthLatencyMs',
    'healthReason', 'lastSeenInSubscriptionAt', 'removedFromSubscriptionAt',
    'enabledBeforeSubscriptionRemoval', 'enabled'),
  id: reference, groupId: reference, outbound
})
const group = object({
  ...fields('name', 'source', 'importedAt', 'lastFetchedAt', 'lastFetchAttemptAt',
    'lastFetchError', 'status', 'trafficUsedBytes', 'trafficUploadBytes',
    'trafficDownloadBytes', 'trafficTotalBytes', 'expiresAt',
    'refreshIntervalSeconds', 'webPageUrl', 'profileTitle', 'supportUrl',
    'lastRefreshProfilesCount', 'refreshIntervalOverrideMinutes'),
  id: reference, profileIds: list(reference)
})
const configPolicy = object({
  ...fields('version', 'exportedAt'),
  profiles: list(profile), serverGroups: list(group),
  schedules: list(object({
    ...fields('name', 'enabled', 'startTime', 'endTime', 'mode'),
    id: reference, profileId: reference, days: list(scalar)
  })),
  splitTunnel: list(object({ ...fields('name', 'path', 'icon', 'rule', 'kind'), id: reference })),
  dns: list(object({
    ...fields('name', 'primary', 'secondary', 'type', 'primaryType', 'secondaryType', 'isBuiltin', 'isSelected'),
    id: reference
  })),
  activeDnsProfileId: reference,
  domainRouting: list(object({ ...fields('pattern', 'action', 'priority', 'hitCount'), id: reference })),
  themes: list(object({
    ...fields('name', 'mode', 'isCustom'), id: reference,
    colors: object(fields('background', 'sidebar', 'cardBackground', 'cardElevated',
      'accent', 'text', 'textSecondary', 'textMuted', 'border', 'borderStrong', 'success', 'warning', 'danger'))
  })),
  rotation: object({
    ...fields('enabled', 'intervalMinutes', 'order', 'currentIndex', 'nextRotationAt'),
    profileIds: list(reference)
  }),
  killSwitch: object({
    ...fields('level'),
    exceptions: list(object({ ...fields('type', 'value', 'label'), id: reference }))
  }),
  notifications: object(fields('vpnConnect', 'vpnDisconnect', 'leakDetected',
    'profileRotation', 'scheduleTriggered', 'connectionError', 'method', 'sound'))
})

/** A new object: exporting cannot mutate the live config or its credentials.
 * Unknown fields and malformed public containers default to masking, not recursion. */
export function redactConfigExport(config: ConfigExportData): ConfigExportData {
  return configPolicy(config) as ConfigExportData
}
