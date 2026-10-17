import { randomUUID } from 'crypto'
import { matchesFirewallPolicy, type FirewallStatusSnapshot } from '../firewallStatus'
import type { FirewallManifest } from '../firewallKillSwitch'
const prefix = 'VPNTE-killswitch-allow-'
const lan = ['127.0.0.0/8', '10.0.0.0/8']
export function firewallStatusFixture() {
  const rules: FirewallStatusSnapshot['rules'] = ['singbox', 'app', 'tun-interface', 'loopback-out', 'loopback-in', 'lan', 'tun', 'dhcp', 'ntp'].map(name => ({
    name: prefix + name, enabled: 'True', direction: name === 'loopback-in' ? 'Inbound' : 'Outbound', action: 'Allow', profile: 'Any',
    program: name === 'singbox' ? 'C:\\VPNTE\\sing-box.exe' : name === 'app' ? 'C:\\VPNTE\\app.exe' : 'Any',
    interfaces: name === 'tun-interface' ? ['Ethernet 5'] : ['Any'],
    remote: name === 'lan' ? lan : name === 'tun' ? ['192.168.250.252/30'] : name === 'loopback-out' ? ['127.0.0.0/8'] : ['Any'],
    local: name === 'loopback-in' ? ['127.0.0.0/8'] : ['Any'],
    protocol: ['dhcp', 'ntp'].includes(name) ? 'UDP' : 'Any', remotePorts: name === 'dhcp' ? ['67', '68'] : name === 'ntp' ? ['123'] : ['Any']
  }))
  const snapshot: FirewallStatusSnapshot = { services: ['BFE', 'MpsSvc'].map(name => ({ name, status: 'Running' })),
    profiles: ['Domain', 'Private', 'Public'].map(name => ({ name, enabled: 'True', outbound: 'Block', disabledInterfaces: [] })),
    rules, storedNames: rules.map(r => r.name), foreignAllows: 0 }
  const manifest: FirewallManifest = { schemaVersion: 1, owner: 'VPNTE', operationId: randomUUID(), phase: 'active', strictMode: false,
    createdAt: 1, ruleNames: [...snapshot.storedNames], singboxExePath: 'C:\\VPNTE\\sing-box.exe', savedProfiles: [] }
  const matches = () => matchesFirewallPolicy(snapshot, manifest, { app: 'C:\\VPNTE\\app.exe', proxy: 'C:\\VPNTE\\proxy.exe' }, 'Ethernet 5', lan, '192.168.250.252/30')
  return { snapshot, manifest, matches }
}
