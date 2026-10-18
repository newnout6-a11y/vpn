export interface IpcInventory {
  registered: string[]
  exposed: Array<{ channel: string; method: string }>
  declared: Array<{ channel: string; method: string }>
  problems: string[]
}
export function inspectIpcContract(sources: { main: Record<string, string>; preload: string; shared: string }): IpcInventory
export function checkIpcContract(root?: string): IpcInventory
