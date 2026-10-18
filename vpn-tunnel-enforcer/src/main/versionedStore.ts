import ElectronStore from 'electron-store'
import { assertStoreSchema, storeSchemaVersion } from './storeSchema'
import { refuseIncompatibleStoreStartup } from './storeSchemaStartup'

/** Guard before Conf merges defaults or invokes a repairing deserializer.
 * Also guard serialization: whole-store replacement/clear bypass Conf's read
 * path and must not overwrite a file replaced by a newer app after open. */
export default class Store<T extends Record<string, any> = Record<string, unknown>> extends ElectronStore<T> {
  constructor(options: ElectronStore.Options<T>) {
    const name = options.name ?? ''
    try {
      storeSchemaVersion(name)
      super({
        ...options,
        deserialize(raw) {
          let parsed: unknown
          try { parsed = JSON.parse(raw) }
          catch (error) {
            if (options.deserialize) return options.deserialize(raw)
            throw error
          }
          assertStoreSchema(name, parsed)
          return options.deserialize ? options.deserialize(raw) : parsed as T
        },
        serialize(this: ElectronStore<T>, value: T) {
          assertStoreSchema(name, this.store)
          assertStoreSchema(name, value)
          return options.serialize ? options.serialize(value) : JSON.stringify(value, undefined, '\t')
        }
      })
    } catch (error) {
      refuseIncompatibleStoreStartup(error)
      throw error
    }
  }
}
