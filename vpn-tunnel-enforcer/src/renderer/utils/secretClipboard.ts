const DEFAULT_CLEAR_DELAY_MS = 60_000

export function confirmSecretExport(action: 'clipboard' | 'file'): boolean {
  const destination = action === 'clipboard' ? 'буфер обмена' : 'обычный текстовый файл'
  return window.confirm(
    `VPN-ключ содержит пароль или приватный идентификатор. Он будет помещён в ${destination}. ` +
    'Любой, кто получит эти данные, сможет использовать ваш VPN-доступ. Продолжить?'
  )
}

export function scheduleSecretClipboardCleanup(
  secret: string,
  delayMs = DEFAULT_CLEAR_DELAY_MS
): number {
  return window.setTimeout(async () => {
    try {
      const current = await navigator.clipboard.readText()
      if (current === secret) await navigator.clipboard.writeText('')
    } catch {
      // Clipboard-read permission can be revoked after the user gesture. Do
      // not overwrite unknown clipboard contents in that case.
    }
  }, delayMs)
}
