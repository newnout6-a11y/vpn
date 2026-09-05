import { describe, expect, it } from 'vitest'
import {
  parseSubscriptionUserInfo,
  parseVpnProfiles,
  type VpnProfile
} from './vpnProfiles'
import { isSameServerProfile } from './serverPicker'
import { profileTupleKey, vpnProfileTupleKey } from './serverGroups'
import type { ServerProfile } from '../shared/ipc-types'

describe('Subscription bridge relays, remarks parsing and deduplication', () => {
  describe('parseSubscriptionUserInfo profile-title base64 decoding', () => {
    it('decodes base64:QUxMIFZQTg== to "ALL VPN"', () => {
      const headers = {
        'profile-title': 'base64:QUxMIFZQTg=='
      }
      const info = parseSubscriptionUserInfo(headers)
      expect(info?.profileTitle).toBe('ALL VPN')
    })

    it('decodes quoted "base64:QUxMIFZQTg==" correctly', () => {
      const headers = {
        'profile-title': '"base64:QUxMIFZQTg=="'
      }
      const info = parseSubscriptionUserInfo(headers)
      expect(info?.profileTitle).toBe('ALL VPN')
    })

    it('preserves plain profile-title without base64 prefix', () => {
      const headers = {
        'profile-title': 'My Provider VPN'
      }
      const info = parseSubscriptionUserInfo(headers)
      expect(info?.profileTitle).toBe('My Provider VPN')
    })

    it('handles case-insensitive BASE64: prefix', () => {
      const headers = {
        'profile-title': 'BASE64:QUxMIFZQTg=='
      }
      const info = parseSubscriptionUserInfo(headers)
      expect(info?.profileTitle).toBe('ALL VPN')
    })
  })

  describe('parseVpnProfiles with shared gateway/bridge and remarks', () => {
    it('extracts top-level remarks as profile name instead of outbound.tag "proxy"', () => {
      const jsonSubscription = JSON.stringify([
        {
          remarks: '🇩🇪 Дарвин ВПН | Германия',
          log: { loglevel: 'warning' },
          outbounds: [
            {
              tag: 'proxy',
              protocol: 'vless',
              settings: {
                vnext: [
                  {
                    address: 'bridge1.alvsub.cc',
                    port: 443,
                    users: [{ id: '11111111-2222-3333-4444-555555555555', flow: 'xtls-rprx-vision' }]
                  }
                ]
              },
              streamSettings: {
                network: 'tcp',
                security: 'reality',
                realitySettings: {
                  serverName: 'speedtest.net',
                  publicKey: 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
                  shortId: '12345678'
                }
              }
            },
            {
              tag: 'direct',
              protocol: 'freedom'
            }
          ]
        },
        {
          remarks: 'Soda VPN | Нидерланды',
          log: { loglevel: 'warning' },
          outbounds: [
            {
              tag: 'proxy',
              protocol: 'vless',
              settings: {
                vnext: [
                  {
                    address: 'bridge1.alvsub.cc',
                    port: 443,
                    users: [{ id: '99999999-8888-7777-6666-555555555555', flow: 'xtls-rprx-vision' }]
                  }
                ]
              },
              streamSettings: {
                network: 'tcp',
                security: 'reality',
                realitySettings: {
                  serverName: 'speedtest.net',
                  publicKey: 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
                  shortId: '12345678'
                }
              }
            }
          ]
        },
        {
          remarks: '🇫🇮 Хельсинки Релей 2',
          outbounds: [
            {
              tag: 'proxy',
              protocol: 'vless',
              settings: {
                vnext: [
                  {
                    address: 'bridge2.alvsub.cc',
                    port: 8443,
                    users: [{ id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }]
                  }
                ]
              },
              streamSettings: {
                network: 'ws',
                security: 'tls',
                tlsSettings: { serverName: 'fi.example.com' }
              }
            }
          ]
        }
      ])

      const profiles = parseVpnProfiles(jsonSubscription)
      expect(profiles).toHaveLength(3)
      expect(profiles[0].name).toBe('🇩🇪 Дарвин ВПН | Германия')
      expect(profiles[0].outbound.server).toBe('bridge1.alvsub.cc')
      expect(profiles[0].protocol).toBe('vless')

      expect(profiles[1].name).toBe('Soda VPN | Нидерланды')
      expect(profiles[1].outbound.server).toBe('bridge1.alvsub.cc')
      expect(profiles[1].protocol).toBe('vless')

      expect(profiles[2].name).toBe('🇫🇮 Хельсинки Релей 2')
      expect(profiles[2].outbound.server).toBe('bridge2.alvsub.cc')
      expect(profiles[2].outbound.server_port).toBe(8443)
    })

    it('extracts remarks when direct outbound array is provided', () => {
      const jsonDirect = JSON.stringify([
        {
          remarks: 'Direct Node 1',
          tag: 'proxy',
          protocol: 'vless',
          settings: {
            vnext: [{ address: 'bridge1.example.com', port: 443, users: [{ id: 'uuid-1' }] }]
          }
        },
        {
          remarks: 'Direct Node 2',
          tag: 'proxy',
          protocol: 'vless',
          settings: {
            vnext: [{ address: 'bridge1.example.com', port: 443, users: [{ id: 'uuid-2' }] }]
          }
        }
      ])

      const profiles = parseVpnProfiles(jsonDirect)
      expect(profiles).toHaveLength(2)
      expect(profiles[0].name).toBe('Direct Node 1')
      expect(profiles[1].name).toBe('Direct Node 2')
    })
  })

  describe('isSameServerProfile deduplication', () => {
    function makeServerProfile(overrides: Partial<ServerProfile>): ServerProfile {
      return {
        id: 'id-' + Math.random(),
        name: 'Default Node',
        protocol: 'vless',
        server: 'bridge1.alvsub.cc',
        port: 443,
        status: 'unknown',
        enabled: true,
        groupId: 'g-1',
        outbound: { type: 'vless', server: 'bridge1.alvsub.cc', server_port: 443 },
        ...overrides
      }
    }

    it('does NOT treat profiles on the same bridge but with different names as duplicates', () => {
      const a = makeServerProfile({
        name: '🇩🇪 Дарвин ВПН | Германия',
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless'
      })
      const b = makeServerProfile({
        name: 'Soda VPN | Нидерланды',
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless'
      })

      expect(isSameServerProfile(a, b)).toBe(false)
    })

    it('does NOT treat profiles on the same bridge with different sourceUri as duplicates', () => {
      const a = makeServerProfile({
        name: 'Node',
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless',
        sourceUri: 'vless://uuid1@bridge1.alvsub.cc:443'
      })
      const b = makeServerProfile({
        name: 'Node',
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless',
        sourceUri: 'vless://uuid2@bridge1.alvsub.cc:443'
      })

      expect(isSameServerProfile(a, b)).toBe(false)
    })

    it('treats profiles with identical server, port, protocol, and name as duplicates', () => {
      const a = makeServerProfile({
        name: '🇩🇪 Дарвин ВПН',
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless'
      })
      const b = makeServerProfile({
        name: '🇩🇪 Дарвин ВПН',
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless'
      })

      expect(isSameServerProfile(a, b)).toBe(true)
    })

    it('treats profiles with identical server, port, protocol, name, and sourceUri as duplicates', () => {
      const a = makeServerProfile({
        name: '🇩🇪 Дарвин ВПН',
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless',
        sourceUri: 'https://sub.alvsub.cc/sub'
      })
      const b = makeServerProfile({
        name: '🇩🇪 Дарвин ВПН',
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless',
        sourceUri: 'https://sub.alvsub.cc/sub'
      })

      expect(isSameServerProfile(a, b)).toBe(true)
    })

    it('does NOT treat profiles with different server or port as duplicates', () => {
      const a = makeServerProfile({ server: 'bridge1.alvsub.cc', port: 443, name: 'Node' })
      const b = makeServerProfile({ server: 'bridge2.alvsub.cc', port: 443, name: 'Node' })
      const c = makeServerProfile({ server: 'bridge1.alvsub.cc', port: 8443, name: 'Node' })

      expect(isSameServerProfile(a, b)).toBe(false)
      expect(isSameServerProfile(a, c)).toBe(false)
    })
  })

  describe('vpnProfileTupleKey and profileTupleKey', () => {
    it('produces different tuple keys for nodes on the same bridge with different names', () => {
      const vpnProfile1: VpnProfile = {
        name: '🇩🇪 Дарвин ВПН | Германия',
        protocol: 'vless',
        outbound: { server: 'bridge1.alvsub.cc', server_port: 443 }
      }
      const vpnProfile2: VpnProfile = {
        name: 'Soda VPN | Нидерланды',
        protocol: 'vless',
        outbound: { server: 'bridge1.alvsub.cc', server_port: 443 }
      }

      const key1 = vpnProfileTupleKey(vpnProfile1)
      const key2 = vpnProfileTupleKey(vpnProfile2)
      expect(key1).not.toBe(key2)
    })

    it('matches profileTupleKey with vpnProfileTupleKey for identical endpoint and name', () => {
      const vpnProfile: VpnProfile = {
        name: '🇩🇪 Darwin',
        protocol: 'vless',
        outbound: { server: 'bridge1.alvsub.cc', server_port: 443 }
      }
      const serverProfile = {
        server: 'bridge1.alvsub.cc',
        port: 443,
        protocol: 'vless',
        name: '🇩🇪 Darwin'
      }

      expect(vpnProfileTupleKey(vpnProfile)).toBe(profileTupleKey(serverProfile))
    })

    it('includes sourceUri in keys when available to distinguish nodes with same name', () => {
      const vpnProfile1: VpnProfile = {
        name: 'Proxy',
        protocol: 'vless',
        sourceUri: 'vless://uuid1@bridge1.alvsub.cc:443',
        outbound: { server: 'bridge1.alvsub.cc', server_port: 443 }
      }
      const vpnProfile2: VpnProfile = {
        name: 'Proxy',
        protocol: 'vless',
        sourceUri: 'vless://uuid2@bridge1.alvsub.cc:443',
        outbound: { server: 'bridge1.alvsub.cc', server_port: 443 }
      }

      expect(vpnProfileTupleKey(vpnProfile1)).not.toBe(vpnProfileTupleKey(vpnProfile2))
    })
  })

  describe('deriveSubscriptionGroupName', () => {
    it('prefers profileTitle over hostname or webPageUrl', async () => {
      const { deriveSubscriptionGroupName } = await import('./serverPicker')
      const name = deriveSubscriptionGroupName(
        'https://sub.alvsub.cc/eaGGz8F15gH-LXs5',
        'https://dash.alvsub.cc',
        'ALL VPN'
      )
      expect(name).toBe('ALL VPN')
    })

    it('falls back to webPageUrl or host when profileTitle is not provided', async () => {
      const { deriveSubscriptionGroupName } = await import('./serverPicker')
      const nameFromWeb = deriveSubscriptionGroupName(
        'https://sub.alvsub.cc/eaGGz8F15gH-LXs5',
        'https://dash.alvsub.cc'
      )
      expect(nameFromWeb).toBe('dash.alvsub.cc')

      const nameFromHost = deriveSubscriptionGroupName(
        'https://sub.alvsub.cc/eaGGz8F15gH-LXs5'
      )
      expect(nameFromHost).toBe('sub.alvsub.cc')
    })
  })
})
