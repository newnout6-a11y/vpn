/** JSON-shaped IPC values; optional members may be undefined before persistence. */
export type IpcJsonValue = null | undefined | boolean | number | string | IpcJsonValue[] | { [key: string]: IpcJsonValue }

/** Narrow a JSON container for field access; this does not validate its fields. */
export function asJsonObject(value: IpcJsonValue): Record<string, IpcJsonValue> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : undefined
}
