# Восстановление сети после сбоя

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/c7f263d1-2de1-4316-9941-819877c1817d

## Feature Summary

Функция восстанавливает сетевые изменения VPN Tunnel Enforcer после аварийного завершения, сбоя туннеля или загрузки Windows. Она использует startup recovery в Electron, задачу Windows Boot Recovery и ручные операции обслуживания, чтобы обработать baseline, kill-switch, блокировку физических адаптеров, DNS, переменные прокси окружения и stale TUN-адаптеры. Требования функции описаны в @Восстановление сети после сбоя.

## Component Blueprint Composition

Функция использует @Защита от утечек как родительскую область и связывает восстановление с компонентами сетевой защиты. Startup orchestration в `src/main/index.ts` последовательно вызывает восстановление stale baseline, kill-switch, блокировки физических адаптеров, orphaned DNS и env autoconfig. Для ручного обслуживания тот же контейнер предоставляет целевые операции ремонта через IPC Dashboard.

`settings.ts` регистрирует задачу Windows «VPNTE Boot Recovery» при синхронизации автозапуска. Задача запускает `resources/vpnte-recover.ps1` от имени SYSTEM при старте Windows. Скрипт независимо ищет манифесты, восстанавливает доступные ресурсы, пишет `recovery.log` и удаляет манифест только после завершения без предупреждений.

## Feature-Specific Components

### Восстановление при запуске приложения

```component
name: StartupRecoveryCoordinator
container: Electron Main Process
responsibilities:
	- Проверяет stale baseline и отсутствие работающего vpnte-sing-box.exe перед откатом.
	- Обрабатывает stale kill-switch, блокировку физических адаптеров, orphaned DNS и env autoconfig.
	- Продолжает восстановление остальных областей после ошибки одной области и записывает предупреждение.
```

```component
name: BootRecoveryTaskRegistrar
container: Electron Main Process, Windows Task Scheduler
responsibilities:
	- Формирует задачу «VPNTE Boot Recovery» с расписанием ONSTART и учётной записью SYSTEM.
	- Запускает resources/vpnte-recover.ps1 через PowerShell без профиля.
	- Подавляет ошибку регистрации задачи после передачи команды на выполнение.
```

```component
name: BootRecoveryScript
container: Windows PowerShell at system startup
responsibilities:
	- Загружает манифест блокировки физических адаптеров из ProgramData и пользовательских профилей.
	- Обрабатывает правила VPNTE-killswitch, DefaultOutboundAction, DNS, IPv6, переходные адаптеры, DNS-политики, DNS-кэш, proxy environment и известные stale TUN-алиасы.
	- Сохраняет предупреждения в recovery.log и удаляет обработанный манифест только при успешном завершении без предупреждений.
```

`StartupRecoveryCoordinator` использует состояние и операции сетевых компонентов родительской функции. `BootRecoveryScript` повторяет минимальный набор восстановления независимо от запущенного приложения, потому что задача выполняется до входа пользователя.

### Ручное восстановление

```component
name: ManualRecoveryHandlers
container: Electron Main Process, Dashboard
responsibilities:
	- Предоставляет Dashboard целевые операции ремонта VPNTE firewall-состояния, orphaned DNS и блокировки физических адаптеров.
	- Предоставляет отдельный полный сброс Windows Firewall с подтверждением.
	- Возвращает результат операции для отображения пользователю.
```

## System Contracts

### Key Contracts

* `StartupRecoveryCoordinator` выполняет области восстановления последовательно в начале жизненного цикла приложения, до завершения обычной инициализации защиты.
* Восстановление не должно откатывать baseline или блокировку физических адаптеров, пока защищённый runtime считается работающим.
* `BootRecoveryScript` восстанавливает только значения, описанные найденным манифестом, а без манифеста удаляет только распознанные VPNTE-остатки.
* При предупреждениях `BootRecoveryScript` сохраняет манифест для последующего разбора.
* Политика для отсутствующего манифеста kill-switch не определена. Выбор между сохранением Block и возвратом Allow ожидает решения F-017/F-030.
* Регистрация Boot Recovery не считается гарантированной: команда создания выполняется с подавлением ошибки, а путь регистрации зависит от синхронизации автозапуска. Это открытый вопрос F-150.

### Integration Contracts

* `BootRecoveryTaskRegistrar` передаёт Windows Task Scheduler команду `schtasks /Create` с задачей «VPNTE Boot Recovery», расписанием `ONSTART`, учётной записью `SYSTEM` и вызовом `vpnte-recover.ps1`.
* `BootRecoveryScript` пишет журнал в `%ProgramData%\VPN-Tunnel-Enforcer\recovery.log`, с fallback в `%TEMP%\vpnte-recovery.log`.
* Манифест блокировки адаптеров содержит сведения, по которым скрипт сопоставляет адаптеры по `ifIndex` или alias и восстанавливает DNS, IPv6, переходные адаптеры и DNS-политики.
* Скрипт удаляет только переменные окружения с локальным VPNTE-прокси и сохраняет другие proxy values.
* `vpnte-eos-compat.ps1` изменяет IPv6 prefix policy, hosts, правило Codex и port-proxy cleanup. Его включение в восстановление не подтверждено.

## Architecture Decision Records

### ADR-001: Два контура восстановления

**Context:** Сбой может оставить сетевые изменения до следующего запуска приложения или до входа пользователя в Windows.

**Decision:** Использовать startup recovery в Electron для координации состояния приложения и отдельную задачу SYSTEM с PowerShell-скриптом для восстановления при загрузке Windows.

**Consequences:** Восстановление может начаться раньше приложения, но два контура должны сохранять совместимость манифестов и одинаковое безопасное поведение при неполных данных.

### ADR-002: Осторожное удаление манифеста

**Context:** Ошибка отдельной операции восстановления может оставить сеть в частично изменённом состоянии.

**Decision:** Удалять манифест только после завершения без предупреждений. При предупреждении сохранять его и записывать результат в журнал.

**Consequences:** Повторный запуск может повторить часть операций, но сохраняет возможность диагностики и последующего отката.
