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
