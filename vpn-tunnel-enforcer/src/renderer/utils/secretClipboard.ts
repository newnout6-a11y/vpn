export function confirmSecretExport(action: 'clipboard' | 'file'): boolean {
  const destination = action === 'clipboard' ? 'буфер обмена' : 'обычный текстовый файл'
  const cleanupNotice = action === 'clipboard'
    ? ' Текущий буфер будет очищен через 60 секунд, если вы его не замените. История буфера и облачные копии не удаляются.'
    : ''
  return window.confirm(
    `VPN-ключ содержит пароль или приватный идентификатор. Он будет помещён в ${destination}. ` +
    'Любой, кто получит эти данные, сможет использовать ваш VPN-доступ.' + cleanupNotice + ' Продолжить?'
  )
}
