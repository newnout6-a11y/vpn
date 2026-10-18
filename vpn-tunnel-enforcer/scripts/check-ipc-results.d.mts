import type ts from 'typescript'
import type { IpcInventory } from './check-ipc-contract.mjs'

export interface IpcResultInspection {
  problems: string[]
  checked: string[]
  /** Public results containing any, including nested objects and aliases. */
  legacy: string[]
}
export function inspectIpcResults(program: ts.Program, input: {
  declared: IpcInventory['declared']; mainFiles: string[]; apiFile: string
}): IpcResultInspection
export function checkIpcResults(root: string, inventory: IpcInventory & { mainFiles: string[] }): IpcResultInspection
