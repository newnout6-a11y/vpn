// AT-06-003 / AT-09-011: a local TUN start is not a verified exit or a full-tunnel promise.
export function tunnelStartedMessageKey(smartRuSplit: boolean): string {
  return smartRuSplit ? 'tunnel.startedSmartRu' : 'tunnel.started'
}
