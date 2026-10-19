// AT-00-003 / AT-01-008: parent kills this process after actual staged write/fsync/close.
import { writeConfigExport } from '../configOperationIo'
import { OperationRegistry } from '../operationRegistry'
const registry = new OperationRegistry()
process.on('message', () => {}) // Keep the child alive at the controlled pre-commit boundary.
void registry.run('export', lease => writeConfigExport(process.argv[2], 'FAKE-SECRET-CRASH', {
  ...lease,
  async wait<T>(staging: Promise<T>): Promise<T> {
    const result = await lease.wait(staging)
    process.send?.('staged')
    await new Promise<never>(() => {})
    return result
  }
}, true, 'secrets')).catch(() => { process.send?.('failed'); process.exitCode = 1 })
