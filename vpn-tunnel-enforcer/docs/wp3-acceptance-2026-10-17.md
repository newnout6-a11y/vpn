# WP-3: сверка приёмки, 17.10.2026

Основание: `AGENTS.md`, том 2 ТЗ §1.1–3.1, решения владельца §10.1,
§10.2 и §10.11 ТЗ-06, набор `AT-03-001…012` и методология L0–L4.
Это отчёт о доказательствах, а не изменение нормативных требований.

**Статус пакета: частично; переход к WP-0 ещё не обоснован.**
Наличие реализации, CI PASS и полная трассировка не заменяют обязательный L3.
Подтверждённые локальные поднаборы ниже не означают PASS всего AT.

## Среда и границы

- Локально: Windows 11 Pro, build 26300; Node 24.21.0; процесс агента
  не имеет административного токена. Это не OS-матрица из методологии.
- Hyper-V доступен для чтения. Единственная зарегистрированная VM
  `Windows 10 MSIX packaging environment` выключена, заявленный VHDX отсутствует.
  Готовая изолированная Windows-лаборатория не обнаружена.
- Рабочее установленное приложение запущено. Его firewall, адаптеры и DNS
  при этой сверке не изменялись; перезагрузка рабочей ОС не выполнялась.
- Нет записанного второго внешнего packet oracle, операторского IPv6-only/
  464XLAT аплинка и трёх поддерживаемых гостевых Windows.

## Матрица всех 12 AT

| AT | Доступное подтверждение в коде и тестах | Что ещё требуется для полного PASS |
| --- | --- | --- |
| 03-001 | `firewallTransactions.test.ts`, `granularKillSwitch.test.ts`, `wfpIpv6.test.ts`: установка защиты до разрыва, отказ вместо ложного успеха, форма политик | **NOT-CHECKED L3:** фактические WFP counters, pktmon и внешний capture; три способа разрыва, окно 60 с, UI ≤2 с |
| 03-002 | `bootRecoveryRegistration.test.ts`, `bootRecoveryTaskReadBack.test.ts`, `bootRecoveryExecution.test.ts`, `bootRecoveryBehavior.test.ts`: команда задачи, read-back, исполнение production-скрипта на подставных системных API, проверка GUID/driver/subnet | **NOT-CHECKED L3:** установленная сборка, жёсткое убийство, настоящий reboot, SYSTEM, итоговый отчёт в UI |
| 03-003 | `recoveryManifestStorage.test.ts`, `firewallTransactions.test.ts`, `bootRecoveryExecution.test.ts`, `systemNetwork.test.ts`: corrupt/missing/future schema, карантин, сохранение strict, отсутствие эффектов для недоверенных данных; `lifecycleCleanup.test.ts`: startup warning до создания окна при неполном baseline recovery | **Частично:** полная матрица частичных манифестов и реальный boot/обычный rollback; mocks не доказывают системные ACL |
| 03-004 | `firewallTransactions.test.ts`, `bootRecoveryExecution.test.ts`: сохранение исходных Block, удаление только собственных правил, независимый read-back | **NOT-CHECKED L3:** три реальных цикла apply/stop и сравнение экспортов чужих Block/Allow |
| 03-005 | `physicalAdapterSnapshot.test.ts`, `physicalAdapterLifecycle.test.ts`, `lifecycleCleanup.test.ts`: отсутствие фиктивных адаптеров и проверки запуска/отката | **NOT-CHECKED L3:** VM без NIC, отсутствие созданных правил и правдивый статус в UI |
| 03-006 | `physicalAdapterLifecycle.test.ts`, `physicalAdapterSnapshot.test.ts`, `physicalAdapterHotspot.test.ts`: свежий snapshot, добавление/удаление/замена GUID, смена alias, компенсация | **NOT-CHECKED L3:** настоящий hot-plug/переименование во время apply, итоговый набор фильтров и UI |
| 03-007 | `systemNetwork.test.ts`: отказ каждого из 9 registry-шагов и реальный PowerShell с подставным Restore-Snapshot; `firewallTransactions.test.ts`, `physicalAdapterLifecycle.test.ts`, `lifecycleCleanup.test.ts`: общий Stop operationId, независимость Firewall/WFP/baseline/adapters, явные результаты шагов, failure через IPC, общий ID concurrent Stop и новый ID retry; `Dashboard.cancel.test.tsx`: видимые перечень отказов и рекомендация вместо success | Доступные L2-сценарии проверены на production bodies и renderer с подставными системными/IPC границами. Сквозной ID этой задачи относится к controller Stop и вызываемым rollback, не ко всем startup/crash/shutdown-backstop путям; системные эффекты этим прогоном не доказаны |
| 03-008 | `granularKillSwitch.test.ts`, `firewallTransactions.test.ts`: 50 конкурентных обновлений, seeded mixed add/remove, сверка каждого native set, конечного store и всех audit-событий; journal-before-effects, store/system compensation, сохранение core/upstream | Доступные L2-сценарии прошли; системные API подставлены. Полное реальное применение Windows/WFP остаётся отдельной системной проверкой |
| 03-009 | `firewallKillSwitchValidation.test.ts`, `killSwitchExceptionValidation.test.ts`: generated IPv4/IPv6 и маски, невалидные числовые формы, readable `.exe`/realpath; `granularKillSwitch.test.ts`: настоящий GetShortPathName и отклонение 8.3-дубликата; `firewallTransactions.test.ts`: отказ до записи/native effects | **Частично L1:** расширенный генератор типов/путей/длин; локальный 8.3 PASS не объявляет проверенными файловые системы без этой возможности |
| 03-010 | `wfpIpv6.test.ts`, `physicalAdapterHotspot.test.ts`, `firewallTransactions.test.ts`: production C# с fake engine, AND scope, NAT64 endpoint, отсутствие широких permit, независимая компенсация | **NOT-CHECKED L3:** полная OS-матрица, настоящий BFE/boot-time, pktmon + внешний capture, physical mobile 464XLAT positive/negative и byte-equivalent restore |
| 03-011 | `physicalAdapterLifecycle.test.ts`, `physicalAdapterDnsScript.test.ts`, `systemNetwork.test.ts`: read-back DNS, частичные отказы и сохранение recovery-обязанности | **NOT-CHECKED L3:** отказ DNS посередине apply, полный baseline restore, причина в UI и успешная повторная попытка |
| 03-012 | `recoveryManifestStorage.test.ts`, `firewallManifestSecurity.test.ts`, `bootRecoveryExecution.test.ts`: trust-before-effects, ACL/owner/reparse отказ, строгая схема | **NOT-CHECKED L3:** настоящие ослабленные ACL/подложный манифест на отдельной VM, reboot, SYSTEM и положительный легитимный контроль |

## Исправления этой итерации

### AT-03-009: строгая десятичная CIDR-маска

`Number(prefix)` пропускал `/0x10`, `/1e1`, `/+24`, дробную запись целого
и пробел перед маской. Через granular API такие строки ещё и молча
переписывались в обычную маску. Теперь синтаксис маски проверяется до числового
преобразования; обычные IPv4/IPv6, границы диапазонов и запрет wildcard сохранены.

Новые проверки сначала воспроизвели дефект: **17 failed, 106 passed, 1 skipped**.
После исправления:

```text
npm.cmd test -- src/main/firewallKillSwitchValidation.test.ts src/main/killSwitchExceptionValidation.test.ts src/main/firewallTransactions.test.ts
123 passed, 1 skipped; 3 files passed; exit 0
```

Property-based seed: 30009 (IPv4), 30010 (IPv6), 30011 (numeric coercions).
Полный прогон: `npm.cmd run typecheck` — exit 0; `npm.cmd test` —
3113 passed, 5 skipped, 0 failed; 232 files passed, 2 skipped; 166.42 с, exit 0.
`python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py`
(из корня) — AC 927/927, F 210/210, exit 0. `git diff --check` — exit 0.

Нативный smoke `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
-File vpn-tunnel-enforcer/scripts/test-wfp-ipv6-native.ps1` — **exit 1**:
cleanup возвращает `WFP error 0x8032000D` (нет активной транзакции), скрывая
исходный отказ. `ok=false`, `aborted=false`; это не подтверждение работы BFE.
Нужны исправление harness и отдельный запуск на привилегированном CI runner.

### AT-03-007/010: нативный smoke и CI

Harness теперь запоминает успешный Begin: при отказе начала не пытается
откатывать отсутствующую транзакцию, повторный Abort не отправляется в BFE.
Commit остаётся no-op независимо от вызовов production Policy.Apply; cleanup
ошибка не может оставить `ok=true`. Регрессия компилирует настоящий C# wrapper
из smoke-скрипта с fake IEngine и проверяет отказ Begin, запрет commit и ровно
один Abort. Физические адаптеры не нужны для отдельного ABI/LUID smoke:
на CI допускается активный виртуальный интерфейс; это не проверка NIC ownership.

- `npm.cmd test -- src/main/wfpIpv6.test.ts`: 28 passed, exit 0.
- Повторный `npm.cmd run typecheck`: exit 0.
- Повторный `npm.cmd test`: 3113 passed, 5 skipped, 0 failed;
  232 files passed, 2 skipped; 171.67 с, exit 0.
- Нативный smoke после исправления: exit 1, исходный **WFP 0x00000005
  (Access denied) на Begin** теперь сохранён. Транзакция не начата.
- В Windows CI добавлен обязательный шаг реального BFE smoke с выводом
  JSON в RUNNER_TEMP и job log. До фактического результата CI PASS не заявлен.

PR: https://github.com/newnout6-a11y/vpn/pull/46. Финальные CI/review проверяются
по SHA последнего коммита; версия первого коммита не доказывает новую версию.

CI на `9f8e26ffb93fb550d6d312f0b09eae70ba614d62`: Windows success, Rust success,
Revix success. В [нативном шаге](https://github.com/newnout6-a11y/vpn/actions/runs/39055637354/job/117463031596)
реальный BFE вернул `ok=true`, `aborted=true`, `rules=23`, `priority=verified`.
Это доказательство ABI/read-back в откатываемой транзакции на runner;
фильтрация настоящего трафика и boot-time поведение не проверены.

### AT-03-007/008/009: trace и дополнительные локальные сценарии

Baseline rollback теперь возвращает `operationId` и добавляет тот же UUID
к старту, native timings, каждому из 9 шагов, WinINet notification и итогу.
Ошибки чтения также имеют ID; повторная попытка имеет отдельный UUID.
Это корреляция внутри baseline, а не заявленная сквозная корреляция всего Stop.
Новые fault-injection assertions до исправления: 11 failed, 40 passed, 1 skipped.

Для исключений добавлены 50 смешанных add/remove с seed 30008: после каждой
операции проверяется следующий native set, итоговые in-memory/store данные
и порядок audit-событий. Отдельно настоящий Win32 GetShortPathName выдаёт
8.3 alias созданного `.exe`; granular API отклоняет его как дубликат длинного
пути. Если том не создаёт alias, тест явно SKIP; локально он прошёл без SKIP.

Последние проверки: `npm.cmd run typecheck` — exit 0; `npm.cmd test` —
3117 passed, 5 skipped, 0 failed; 232 files passed, 2 skipped; 164.69 с,
exit 0. Трассировка AC 927/927, F 210/210 и `git diff --check` — exit 0.

## AT-03-001/003/004/010: достоверность статуса kill-switch

Устранён прежний путь `manifest → active:boolean → «Интернет заблокирован»`.
IPC/preload/store теперь передают `verified / inactive / unknown` с причиной
и отдельным признаком необходимости cleanup. `isKillSwitchActive()` сохраняет
семантику наличия артефактов для lifecycle; это не доказательство блокировки.

Пассивный verifier читает свежий доверенный манифест и выполняется в очереди
firewall. Проверяются BFE/MpsSvc, Enabled и DefaultOutboundAction=Block всех
трёх профилей **ActiveStore**, полнота ожидаемых имён, области разрешений,
отсутствие неизвестных исходящих Allow, точный WFP read-back и соответствие
TUN доверенному GUID, драйверу Wintun, адресу и LUID. Prepared/pending journal,
осиротевшие артефакты, ошибка/неполнота чтения и неизвестные scopes дают unknown.
Отсутствие защиты требует доказанного отсутствия manifest/Firewall/WFP.

Проверка не запускает helper/UAC и не использует fallback. Если helper исчезает
между подготовкой WFP script и отправкой, `startIfUnavailable:false` запрещает
его автоматический запуск. Нет helper — unknown. Чужие правила не меняются.
Неизвестные helper/proxy paths старых журналов также остаются unknown:
произвольные approved program paths в них не сохранены.

Renderer немедленно снимает старую верификацию при новом запросе/ручной мутации,
игнорирует старые ответы и сохраняет unknown при ошибках. После cleanup/reset
выполняется повторная проверка вместо присваивания false по одному success.
Dashboard различает проверенную конфигурацию и неизвестность, предоставляет
повторную проверку; tray и crash/proxy-down сообщения не утверждают, что
файрвол гарантированно блокирует трафик. Проверка конфигурации прямо отделена
в UI от проверки утечек пакетов.

Нативный read-only запуск production snapshot на рабочем хосте: exit 0,
BFE/MpsSvc Running, три профиля Enabled=True/Block, **131 чужое outbound Allow**.
Это не доказывает фактическую утечку, но не позволяет подтвердить полноту
блокировки. Изменений правил/DNS/адаптеров этим чтением не выполнялось.
Тот же запуск обнаружил реальную форму IPv4 `address/dotted-mask`; добавлена
канонизация сетевых областей. Новая регрессия до исправления: 1 failed,
31 passed; после — PASS, включая отрицательные non-contiguous/broader masks.

Проверки статуса, очереди, WFP ownership, helper no-start и UI races:
`npm.cmd test -- src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts src/main/elevatedPsHelper.test.ts src/main/wfpIpv6.test.ts src/renderer/store.firewallStatus.test.ts src/renderer/pages/Dashboard.cancel.test.tsx src/renderer/store.connectionBusy.test.ts`
— **201 passed, 1 skipped**, 7 files passed, exit 0.
`npm.cmd test -- src/main/firewallStatus.test.ts src/main/granularKillSwitch.test.ts`
до последнего расширения масок — 42 passed, exit 0; реальная 8.3 ветка без skip.

Playwright CLI проверил настоящий Dashboard в изолированном Vite harness с
подставным IPC: unknown в dark/light, verified, исчезновение баннера при
inactive, повторную проверку, неуспешное снятие и отказ от reset confirmation.
PNG просмотрены; 414 px визуально проверен. Измерения overflow при 280/320 px
записаны в журнале. Это UI fixture, не installed E2E. Скрипты gates,
на которые ссылается локальный design-doctrine, в установленном skill
отсутствуют; их PASS не заявляется.

Финальные проверки текущего изменения: `npm.cmd run typecheck` — exit 0;
`npm.cmd run build` — exit 0; `npm.cmd test` — **3168 passed, 5 skipped,
0 failed**, 234 files passed, 2 skipped, 132.11 с, exit 0. Трассировка —
AC 927/927, F 210/210; `git diff --check` — exit 0.

### Уточнения после review f1b22f7

Windows/Rust CI на f1b22f7 — success; Revix — neutral. Исправлено issue
с локализацией двух App log messages (en/ru). Начальный checking больше
не показывает cleanup alert; failed unknown после чтения сохраняет
предупреждение, поскольку отказ проверки не доказывает отсутствие правил.
Добавлен UI regression и assertion очистки baseline manifest после retry.

`npm.cmd run typecheck` — exit 0; `npm.cmd test` — **3169 passed, 5 skipped,
0 failed**, 234 files passed, 2 skipped, 124.12 с, exit 0. Трассировка —
AC 927/927, F 210/210; `git diff --check` — exit 0. Повторная production
сборка после этих небольших уточнений не запускалась.

### AT-03-007: общая корреляция Stop и независимых rollback

Controller создаёт UUID один раз при допуске Stop. Одновременные вызовы,
ожидающие ту же остановку, получают один ID; самостоятельная повторная
попытка получает новый. ID возвращается в TunStopResult, записывается
в start/step/timing/completion и forensic-события и передаётся в baseline,
firewall, adapter rollback и DNS safety repair. Baseline сохраняет отдельный
UUID для самостоятельного вызова вне Stop. Результат false не записывается
как успешный шаг, даже если Promise исполнился без исключения.

Коррелируются результаты Firewall/WFP rollback, adapter/DNS/transition
результаты и 9 baseline registry-шагов. Это не введение глобального контекста
логирования: низкоуровневые transport timings, сторонние фоновые события и
другие lifecycle-пути не объявляются сквозно коррелированными этой задачей.

Регрессии исполняют production controller с инъекцией отказов runtime,
Xray, baseline, firewall, adapter и DNS; проверяют продолжение допустимых
шагов, отказ после неподтверждённого runtime exit, общий ID и отдельный retry.
Firewall tests проверяют независимые read-back результаты Firewall/WFP,
adapter tests — продолжение следующего адаптера и DNS policy после отказа.
Настоящий Dashboard на IPC fixture показывает полный текст неудачных шагов
и рекомендацию повторной остановки; success notification отсутствует.

Проверки correlation-изменения: `npm.cmd run typecheck` — exit 0;
`npm.cmd test` — **3187 passed, 5 skipped, 0 failed**, 234 files passed,
2 skipped, 122.16 с, exit 0. Трассировка — AC 927/927, F 210/210;
`git diff --check` — exit 0.

### AT-03-003/007: вызывающий код не теряет неполный baseline rollback

Result API baseline сохраняется для Stop/shutdown, которые проверяют success.
Добавлен явный OrThrow API для recovery-кода, использующего catch: resolved
success:false превращается в отказ с message, подробностями failed steps
и рекомендацией повторить восстановление; trusted absence остаётся no-op.

Ручной proxy/direct start возвращает обе ошибки — исходную ошибку запуска
и ошибку восстановления. AutoPilot включает failed recovery step в steps
и дополняет итоговый message. Обычный/emergency crash callback теперь пишет
отказ при resolved success:false; прежний emergency catch не теряет его.
Startup recovery показывает нативный warning dialog до createWindow:
renderer IPC на этой стадии не имел бы получателя. Ошибка доверенного чтения
baseline также попадает в эту boundary. Вместо tasklist/fall-through используется
isOwnedTunRuntimeRunning(true): unknown runtime запрещает rollback; живой
owned runtime сохраняет baseline. Только доказанное отсутствие допускает откат.

`systemNetwork.test.ts` исполняет настоящий rollback через подставные OS API:
отказ registry step, WinINet notification, untrusted storage, сохранение
снимка и успешный retry. `lifecycleCleanup.test.ts` проверяет обе start ветки,
startup dialog/no-op/live-runtime и обычный/emergency onExit на production
bodies; `autoPilot.test.ts` — failed step и обе ошибки в result.message.
Адресный прогон этих трёх файлов: 209 passed, 1 skipped, exit 0.

Финальные проверки: `npm.cmd run typecheck` и `npm.cmd run build` — exit 0;
`npm.cmd test` — 3202 passed, 5 skipped, 234 files passed, 2 skipped,
123.10 с, exit 0. Проверка трассировки — AC 927/927, F 210/210;
`git diff --check` — exit 0. Это L1/L2; системная приёмка не добавлена.

## Условие перехода дальше

Закрыть доступные пробелы L1/L2, получить и сохранить реальные L3-доказательства
для всех требуемых сред/оракулов; CI и review на текущем SHA должны быть без
существенных замечаний. Пока это не выполнено, WP-3 не объявлять завершённым
и WP-0/WP-2 не объявлять начатыми по факту этой сверки.
