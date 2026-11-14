; Texts shown by the installer and the uninstaller (English first: it is the fallback language).
; GateFailed is the Electron installer's text verbatim (installer.nsh), so both generations say the same thing.

LangString GateFailed ${LANG_ENGLISH} "VPNTE shutdown was not confirmed. Exit the client normally and retry. Installation/removal has stopped; no processes were force-killed."
LangString GateFailed ${LANG_RUSSIAN} "Завершение VPNTE не подтверждено. Штатно выйдите из клиента и повторите попытку. Установка/удаление остановлены без принудительного завершения процессов."

LangString CleanupFailed ${LANG_ENGLISH} "VPN Tunnel Enforcer could not restore your network settings (system proxy or network protection rules). Uninstall has stopped and the app stays installed: start it once to restore them (or use Maintenance → Reset network protection), quit it, then uninstall again."
LangString CleanupFailed ${LANG_RUSSIAN} "VPN Tunnel Enforcer не удалось восстановить сетевые настройки (системный прокси или правила сетевой защиты). Удаление остановлено, приложение осталось установленным: запустите его, чтобы восстановить настройки (или выберите «Обслуживание → Сбросить сетевую защиту»), закройте его и повторите удаление."

LangString AppMissing ${LANG_ENGLISH} "VPN Tunnel Enforcer.exe is missing, so the network settings it changed (system proxy, network protection rules) cannot be restored. Reinstall VPN Tunnel Enforcer, then uninstall it again."
LangString AppMissing ${LANG_RUSSIAN} "Файл VPN Tunnel Enforcer.exe отсутствует, поэтому изменённые им сетевые настройки (системный прокси, правила сетевой защиты) не могут быть восстановлены. Переустановите VPN Tunnel Enforcer, затем удалите его снова."

LangString MachineWideKept ${LANG_ENGLISH} "An older version of VPN Tunnel Enforcer is installed on this computer for all users. Removing it needs administrator rights, so it was left in place. You can remove it in Windows Settings > Apps (quit VPN Tunnel Enforcer first). Its data is imported into this version automatically."
LangString MachineWideKept ${LANG_RUSSIAN} "На этом компьютере для всех пользователей установлена старая версия VPN Tunnel Enforcer. Для её удаления нужны права администратора, поэтому она оставлена. Удалить её можно в «Параметры Windows → Приложения» (сначала закройте VPN Tunnel Enforcer). Её данные переносятся в эту версию автоматически."

LangString PreviousBusy ${LANG_ENGLISH} "The previous version of VPN Tunnel Enforcer is still in use and cannot be removed. Close it and click Retry, or click Cancel to stop the installation."
LangString PreviousBusy ${LANG_RUSSIAN} "Предыдущая версия VPN Tunnel Enforcer ещё используется и не может быть удалена. Закройте её и нажмите «Повтор» или нажмите «Отмена», чтобы прервать установку."

LangString PreviousFailed ${LANG_ENGLISH} "The previous version could not be removed. Close VPN Tunnel Enforcer and retry."
LangString PreviousFailed ${LANG_RUSSIAN} "Не удалось удалить предыдущую версию. Закройте VPN Tunnel Enforcer и повторите попытку."

LangString FilesBusy ${LANG_ENGLISH} "A file of VPN Tunnel Enforcer is in use and cannot be replaced:"
LangString FilesBusy ${LANG_RUSSIAN} "Файл VPN Tunnel Enforcer используется и не может быть заменён:"

; WebView2 (webview2.nsh): one status line while it installs; one finish-page line when it could not be.
LangString WebView2Installing ${LANG_ENGLISH} "Installing Microsoft Edge WebView2 for the app window…"
LangString WebView2Installing ${LANG_RUSSIAN} "Устанавливается Microsoft Edge WebView2 для окна приложения…"
LangString WebView2Later ${LANG_ENGLISH} "Microsoft Edge WebView2 could not be installed now, and the app window needs it. Connect to the internet and start VPN Tunnel Enforcer: it offers to install it."
LangString WebView2Later ${LANG_RUSSIAN} "Microsoft Edge WebView2 сейчас установить не удалось, а без него окно приложения не откроется. Подключитесь к интернету и запустите VPN Tunnel Enforcer: оно предложит установить его."

LangString NeedsX64 ${LANG_ENGLISH} "VPN Tunnel Enforcer requires 64-bit Windows."
LangString NeedsX64 ${LANG_RUSSIAN} "Для VPN Tunnel Enforcer нужна 64-разрядная Windows."

LangString NeedsWin10 ${LANG_ENGLISH} "VPN Tunnel Enforcer requires Windows 10 version 2004 (build 19041) or later."
LangString NeedsWin10 ${LANG_RUSSIAN} "Для VPN Tunnel Enforcer нужна Windows 10 версии 2004 (сборка 19041) или новее."

LangString AlreadyRunning ${LANG_ENGLISH} "Another VPN Tunnel Enforcer setup is already running."
LangString AlreadyRunning ${LANG_RUSSIAN} "Уже запущена другая установка VPN Tunnel Enforcer."

; The helper service (svc-wire): one calm line where something stays for later; nothing is shown
; when the service was installed, updated or removed, or when the Windows prompt was declined.
LangString ServiceStopped ${LANG_ENGLISH} "The helper service could not be updated and is stopped for now: Windows starts it again the next time the PC starts. Tunnel mode works again then."
LangString ServiceStopped ${LANG_RUSSIAN} "Службу-помощник не удалось обновить, пока она остановлена: Windows запустит её снова при следующем включении компьютера. Тогда режим «Туннель» снова заработает."
LangString ServiceKept ${LANG_ENGLISH} "The helper service stays for now: it removes its network filters later. Everything else is removed."
LangString ServiceKept ${LANG_RUSSIAN} "Служба-помощник пока остаётся: она уберёт свои сетевые фильтры позже. Остальное удалено."
