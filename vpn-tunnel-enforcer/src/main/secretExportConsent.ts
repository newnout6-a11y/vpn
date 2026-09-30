import { BrowserWindow, dialog, type WebContents } from 'electron'

export interface CancelledSecretExport { ok: false; cancelled: true }

/** AT-01-008: a renderer cannot authorize disclosure with a boolean or by
 * skipping its own warning. The native dialog gates the operation in main. */
export async function withSecretExportConsent<T>(
  sender: WebContents,
  destination: 'clipboard' | 'file' | 'renderer',
  operation: () => T | Promise<T>
): Promise<T | CancelledSecretExport> {
  const cancelled: CancelledSecretExport = { ok: false, cancelled: true }
  if (sender.isDestroyed()) return cancelled
  const options = {
    type: 'warning' as const,
    title: 'Экспорт секретов VPN',
    message: 'Экспортируемые ключи содержат конфиденциальные данные доступа.',
    detail: destination === 'clipboard'
      ? 'Ключ будет скопирован в буфер обмена. Не передавайте его по незащищённым каналам. Приложение очистит неизменённый буфер через 60 секунд; история и синхронизация буфера Windows могут сохранить копию.'
      : 'Экспорт содержит открытые пароли и ключи VPN. Не передавайте их по незащищённым каналам и храните в защищённом месте.',
    buttons: ['Отмена', 'Продолжить'],
    defaultId: 0,
    cancelId: 0,
    noLink: true
  }
  const window = BrowserWindow.fromWebContents(sender)
  const result = window
    ? await dialog.showMessageBox(window, options)
    : await dialog.showMessageBox(options)
  if (result.response !== 1 || sender.isDestroyed()) return cancelled
  return operation()
}
