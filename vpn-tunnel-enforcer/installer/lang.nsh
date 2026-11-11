; Texts shown by the installer and the uninstaller (English first: it is the fallback language).
; GateFailed is the Electron installer's text verbatim (installer.nsh), so both generations say the same thing.

LangString GateFailed ${LANG_ENGLISH} "VPNTE shutdown was not confirmed. Exit the client normally and retry. Installation/removal has stopped; no processes were force-killed."
LangString GateFailed ${LANG_RUSSIAN} "Завершение VPNTE не подтверждено. Штатно выйдите из клиента и повторите попытку. Установка/удаление остановлены без принудительного завершения процессов."

LangString CleanupFailed ${LANG_ENGLISH} "VPNTE could not remove its network protection rules. Uninstall has stopped so that you can restore network access from the app (Maintenance → Reset network protection)."
LangString CleanupFailed ${LANG_RUSSIAN} "VPNTE не удалось снять правила сетевой защиты. Удаление остановлено, чтобы вы могли восстановить доступ к сети из приложения (Обслуживание → Сбросить сетевую защиту)."

LangString AppMissing ${LANG_ENGLISH} "VPN Tunnel Enforcer.exe is missing, so its network protection rules cannot be removed. Reinstall VPN Tunnel Enforcer, then uninstall it again."
LangString AppMissing ${LANG_RUSSIAN} "Файл VPN Tunnel Enforcer.exe отсутствует, поэтому правила сетевой защиты не могут быть сняты. Переустановите VPN Tunnel Enforcer, затем удалите его снова."

LangString PreviousBusy ${LANG_ENGLISH} "The previous version of VPN Tunnel Enforcer is still in use and cannot be removed. Close it and click Retry, or click Cancel to stop the installation."
LangString PreviousBusy ${LANG_RUSSIAN} "Предыдущая версия VPN Tunnel Enforcer ещё используется и не может быть удалена. Закройте её и нажмите «Повтор» или нажмите «Отмена», чтобы прервать установку."

LangString PreviousFailed ${LANG_ENGLISH} "The previous version could not be removed. Close VPN Tunnel Enforcer and retry."
LangString PreviousFailed ${LANG_RUSSIAN} "Не удалось удалить предыдущую версию. Закройте VPN Tunnel Enforcer и повторите попытку."

LangString FilesBusy ${LANG_ENGLISH} "A file of VPN Tunnel Enforcer is in use and cannot be replaced:"
LangString FilesBusy ${LANG_RUSSIAN} "Файл VPN Tunnel Enforcer используется и не может быть заменён:"

LangString WebView2Missing ${LANG_ENGLISH} "Microsoft Edge WebView2 Runtime is not installed; VPN Tunnel Enforcer needs it to show its window. Download it from https://developer.microsoft.com/microsoft-edge/webview2/"
LangString WebView2Missing ${LANG_RUSSIAN} "Не установлен Microsoft Edge WebView2 Runtime — без него окно VPN Tunnel Enforcer не откроется. Скачайте его: https://developer.microsoft.com/microsoft-edge/webview2/"

LangString NeedsX64 ${LANG_ENGLISH} "VPN Tunnel Enforcer requires 64-bit Windows."
LangString NeedsX64 ${LANG_RUSSIAN} "Для VPN Tunnel Enforcer нужна 64-разрядная Windows."

LangString NeedsWin10 ${LANG_ENGLISH} "VPN Tunnel Enforcer requires Windows 10 version 2004 (build 19041) or later."
LangString NeedsWin10 ${LANG_RUSSIAN} "Для VPN Tunnel Enforcer нужна Windows 10 версии 2004 (сборка 19041) или новее."

LangString AlreadyRunning ${LANG_ENGLISH} "Another VPN Tunnel Enforcer setup is already running."
LangString AlreadyRunning ${LANG_RUSSIAN} "Уже запущена другая установка VPN Tunnel Enforcer."
