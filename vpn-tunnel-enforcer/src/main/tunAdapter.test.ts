import { describe, expect, it } from 'vitest'
import {
  resolveTunAdapterAlias,
  isOwnTunAddress,
  ALL_KNOWN_ALIASES,
  TUN_ADAPTER_ALIAS,
  DEFAULT_TUN_ADAPTER_ALIAS,
  CANDIDATE_TUN_ADAPTER_ALIASES,
  parseNetshInterfaceNames,
  updateTunAdapterAlias,
  getTunAdapterAlias
} from './tunAdapter'

describe('tunAdapter collision avoidance', () => {
  it('returns default Ethernet 5 when no collision exists', () => {
    const alias = resolveTunAdapterAlias(['Wi-Fi', 'Ethernet', 'Loopback Pseudo-Interface 1'])
    expect(alias).toBe(DEFAULT_TUN_ADAPTER_ALIAS)
  })

  it('picks Ethernet 6 when Ethernet 5 is already used by a physical/RNDIS adapter', () => {
    const alias = resolveTunAdapterAlias(['Ethernet', 'Ethernet 5', 'Wi-Fi'])
    expect(alias).toBe('Ethernet 6')
  })

  it('skips multiple existing Ethernet adapters to find a free alias', () => {
    const alias = resolveTunAdapterAlias(['Ethernet 5', 'Ethernet 6', 'Ethernet 7'])
    expect(alias).toBe('Ethernet 8')
  })

  it('is case-insensitive when checking existing adapter names', () => {
    const alias = resolveTunAdapterAlias(['ethernet 5'])
    expect(alias).toBe('Ethernet 6')
  })

  it('falls back to VPNTE-TUN if all candidate Ethernet aliases are taken', () => {
    const taken = [...CANDIDATE_TUN_ADAPTER_ALIASES]
    const alias = resolveTunAdapterAlias(taken)
    expect(alias).toBe('VPNTE-TUN')
  })

  it('identifies own TUN addresses accurately', () => {
    expect(isOwnTunAddress('192.168.250.253')).toBe(true)
    expect(isOwnTunAddress('192.168.250.1')).toBe(true)
    expect(isOwnTunAddress('172.19.0.1')).toBe(true)

    // Mobile hotspot / cellular gateway addresses must not match as own TUN
    expect(isOwnTunAddress('192.168.43.1')).toBe(false)
    expect(isOwnTunAddress('192.168.43.50')).toBe(false)
    expect(isOwnTunAddress('172.20.10.1')).toBe(false)
    expect(isOwnTunAddress('10.0.0.1')).toBe(false)
    expect(isOwnTunAddress('8.8.8.8')).toBe(false)
    expect(isOwnTunAddress('')).toBe(false)
  })

  it('includes candidate aliases and legacy names in ALL_KNOWN_ALIASES for cleanup', () => {
    expect(ALL_KNOWN_ALIASES).toContain('VPNTE-TUN')
    expect(ALL_KNOWN_ALIASES).toContain('Ethernet 5')
    expect(ALL_KNOWN_ALIASES).toContain('Ethernet 6')
    expect(ALL_KNOWN_ALIASES).toContain(TUN_ADAPTER_ALIAS)
  })

  it('parses interface names from netsh output correctly regardless of language', () => {
    const sampleRussian = `
Состояние адм.  Состояние     Тип              Имя интерфейса
---------------------------------------------------------------------
Разрешен       Отключен       Выделенный       Подключение по локальной сети
Запрещен       Отключен       Выделенный       Ethernet
Разрешен       Подключен      Выделенный       Ethernet 5
Разрешен       Подключен      Выделенный       Беспроводная сеть
`
    const namesRu = parseNetshInterfaceNames(sampleRussian)
    expect(namesRu).toContain('Подключение по локальной сети')
    expect(namesRu).toContain('Ethernet')
    expect(namesRu).toContain('Ethernet 5')
    expect(namesRu).toContain('Беспроводная сеть')

    const sampleEnglish = `
Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Connected      Dedicated        Ethernet 5
Enabled        Disconnected   Dedicated        Wi-Fi
`
    const namesEn = parseNetshInterfaceNames(sampleEnglish)
    expect(namesEn).toContain('Ethernet 5')
    expect(namesEn).toContain('Wi-Fi')
  })

  it('updates and retrieves dynamically resolved alias via getTunAdapterAlias', () => {
    updateTunAdapterAlias(['Ethernet 5'])
    expect(getTunAdapterAlias()).toBe('Ethernet 6')
    updateTunAdapterAlias()
  })
})
