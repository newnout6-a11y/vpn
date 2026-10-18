import { app, dialog } from 'electron'
import { StoreSchemaError } from './storeSchema'

/** Static Store imports run before main's startup/crash handlers. ErrorBox is
 * supported before app.ready; exit here avoids Electron's second generic box
 * and never enters main's network teardown for a refused startup. */
export function refuseIncompatibleStoreStartup(error: unknown): void {
  if (!(error instanceof StoreSchemaError) || app?.isReady?.() !== false) return
  console.error('VPNTE storage startup refused', { code: error.code })
  const reason = error.code === 'STORE_SCHEMA_FUTURE'
    ? 'Хранилище создано более новой версией VPNTE. Откройте его совместимой версией приложения.'
    : error.code === 'STORE_SCHEMA_INVALID'
      ? 'Версия схемы хранилища повреждена. Восстановите совместимую резервную копию.'
      : 'Схема хранилища не зарегистрирована. Обновите приложение или сообщите разработчику.'
  try {
    dialog.showErrorBox('VPNTE: запуск отменён', `${reason}\n\nНесовместимый файл не изменён. Существующая сетевая защита сохранена.`)
  } finally {
    app.exit(1)
  }
}
