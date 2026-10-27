// koffi refuses to declare the same named struct twice in one process ("Duplicate type name"),
// so a binding that is rebuilt after a partial failure would throw forever. Declare idempotently.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function defineStruct(koffi: any, name: string, definition: Record<string, unknown>): unknown {
  try {
    return koffi.struct(name, definition)
  } catch (error) {
    if (!/Duplicate type name/i.test(String((error as Error)?.message))) throw error
    return koffi.type(name)
  }
}

// Win32 constants shared by every native reader, so the two cannot drift apart.
export const AF_UNSPEC = 0
export const AF_INET = 2
export const AF_INET6 = 23
export const ERROR_BUFFER_OVERFLOW = 111
/** GAA_FLAG_SKIP_ANYCAST | SKIP_MULTICAST | INCLUDE_GATEWAYS */
export const GAA_FLAGS = 0x2 | 0x4 | 0x80
export const FORWARD_ROW2_SIZE = 104
export const IF_ROW2_SIZE = 1352

/** Byte offsets inside MIB_IF_ROW2 that the raw-buffer readers rely on (x64/arm64 layout, ifmib.h). */
export const IF_ROW2_OFFSETS = {
  permanentPhysicalAddress: 1092,
  mediaType: 1136,
  physicalMediumType: 1140,
  interfaceAndOperStatusFlags: 1152,
  operStatus: 1156,
  mediaConnectState: 1164,
  transmitLinkSpeed: 1192,
  inOctets: 1208,
  outOctets: 1280
} as const

/**
 * Declares MIB_IF_ROW2 once and refuses to continue unless its size and every offset the readers use
 * match the compiler layout of the loaded koffi struct. A wrong offset would misreport adapter state,
 * so a mismatch throws and callers fall back to PowerShell.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function assertIfRow2Layout(koffi: any): void {
  const row = defineStruct(koffi, 'VPNTE_MIB_IF_ROW2', {
    InterfaceLuid: 'uint64_t', InterfaceIndex: 'uint32_t', InterfaceGuid: koffi.array('uint8_t', 16),
    Alias: koffi.array('uint16_t', 257), Description: koffi.array('uint16_t', 257),
    PhysicalAddressLength: 'uint32_t', PhysicalAddress: koffi.array('uint8_t', 32), PermanentPhysicalAddress: koffi.array('uint8_t', 32),
    Mtu: 'uint32_t', Type: 'uint32_t', TunnelType: 'uint32_t', MediaType: 'uint32_t', PhysicalMediumType: 'uint32_t',
    AccessType: 'uint32_t', DirectionType: 'uint32_t', InterfaceAndOperStatusFlags: 'uint8_t', OperStatus: 'uint32_t',
    AdminStatus: 'uint32_t', MediaConnectState: 'uint32_t', NetworkGuid: koffi.array('uint8_t', 16), ConnectionType: 'uint32_t',
    TransmitLinkSpeed: 'uint64_t', ReceiveLinkSpeed: 'uint64_t', InOctets: 'uint64_t', InUcastPkts: 'uint64_t',
    InNUcastPkts: 'uint64_t', InDiscards: 'uint64_t', InErrors: 'uint64_t', InUnknownProtos: 'uint64_t',
    InUcastOctets: 'uint64_t', InMulticastOctets: 'uint64_t', InBroadcastOctets: 'uint64_t', OutOctets: 'uint64_t',
    OutUcastPkts: 'uint64_t', OutNUcastPkts: 'uint64_t', OutDiscards: 'uint64_t', OutErrors: 'uint64_t',
    OutUcastOctets: 'uint64_t', OutMulticastOctets: 'uint64_t', OutBroadcastOctets: 'uint64_t', OutQLen: 'uint64_t'
  })
  if (koffi.sizeof(row) !== IF_ROW2_SIZE) throw new Error(`MIB_IF_ROW2 size ${koffi.sizeof(row)} != ${IF_ROW2_SIZE}`)
  const expected: Array<[string, number]> = [
    ['PermanentPhysicalAddress', IF_ROW2_OFFSETS.permanentPhysicalAddress],
    ['MediaType', IF_ROW2_OFFSETS.mediaType],
    ['PhysicalMediumType', IF_ROW2_OFFSETS.physicalMediumType],
    ['InterfaceAndOperStatusFlags', IF_ROW2_OFFSETS.interfaceAndOperStatusFlags],
    ['OperStatus', IF_ROW2_OFFSETS.operStatus],
    ['MediaConnectState', IF_ROW2_OFFSETS.mediaConnectState],
    ['TransmitLinkSpeed', IF_ROW2_OFFSETS.transmitLinkSpeed],
    ['InOctets', IF_ROW2_OFFSETS.inOctets],
    ['OutOctets', IF_ROW2_OFFSETS.outOctets]
  ]
  for (const [member, offset] of expected) {
    const actual = koffi.offsetof(row, member)
    if (actual !== offset) throw new Error(`MIB_IF_ROW2.${member} offset ${actual} != ${offset}`)
  }
}

/**
 * koffi may only run inside the native-read host (a utility process) or under plain Node (tests, tooling).
 * In the Electron main process (process.type === 'browser') a fatal koffi/N-API error aborts the whole elevated
 * application, which is exactly what #26 did. Loaders call this first: the throw is catchable, so the caller
 * falls back to PowerShell instead of risking an uncatchable abort.
 */
export function assertKoffiAllowedHere(what: string): void {
  if ((process as { type?: string }).type === 'browser') {
    throw new Error(`${what}: koffi must not run in the Electron main process; use the native-read host`)
  }
}
