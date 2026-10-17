# WP-3: сверка приёмки, 17.10.2026

Основание: `AGENTS.md`, том 2 ТЗ §1.1–3.1, решения владельца §10.1,
§10.2 и §10.11 ТЗ-06, набор `AT-03-001…012` и методология L0–L4.
Это отчёт о доказательствах, а не изменение нормативных требований.

**Статус пакета: частично; L3-приёмка — ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026).**
Владелец сообщил, что лаборатории нет и она не нужна, и назначил отдельный
статус **«Пропущено владельцем»** (`SKIPPED_BY_OWNER`). Решение записано
в ТЗ-06 §10.12. Оно охватывает оставшиеся L3-сценарии WP-3 и OS-матрицу.
Смысл AT-03-003(c) уточнён владельцем в §10.13; исправные записи доверенного
файла восстанавливаются, испорченные пропускаются с ошибкой. Проверки L1/L2
и review новых исправлений учитываются отдельно.

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

| AT | Доступное подтверждение в коде и тестах | Статус и оставшийся объём |
| --- | --- | --- |
| 03-001 | `firewallTransactions.test.ts`, `granularKillSwitch.test.ts`, `wfpIpv6.test.ts`: установка защиты до разрыва, отказ вместо ложного успеха, форма политик | **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026):** фактические WFP counters, pktmon и внешний capture; три способа разрыва, окно 60 с, UI ≤2 с |
| 03-002 | `bootRecoveryRegistration.test.ts`, `bootRecoveryTaskReadBack.test.ts`, `bootRecoveryExecution.test.ts`, `bootRecoveryBehavior.test.ts`: команда задачи, read-back, исполнение production-скрипта на подставных системных API, проверка GUID/driver/subnet | **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026):** установленная сборка, жёсткое убийство, настоящий reboot, SYSTEM, итоговый отчёт в UI |
| 03-003 | `recoveryManifestStorage.test.ts`, `firewallTransactions.test.ts`, `bootRecoveryExecution.test.ts`, `systemNetwork.test.ts`: corrupt/missing/future schema, карантин, сохранение strict, отсутствие эффектов для недоверенных данных; `systemNetwork.test.ts`, `firewallTransactions.test.ts`, `physicalAdapterLifecycle.test.ts`: обычный rollback валидных соседей невалидной/отсутствующей/конфликтующей записи, отказ и сохранение журнала; `bootRecoveryExecution.test.ts`, `bootRecoveryBehavior.test.ts`: те же границы в production PowerShell на подставных API; `lifecycleCleanup.test.ts`: детали пропуска в Stop error и startup warning до создания окна | Смысл (c) принят владельцем (§10.13); реализация и L2-матрица дополнены, проверки нового кода и PR review перечислены ниже. L3 boot/системные ACL — **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026)** |
| 03-004 | `firewallTransactions.test.ts`, `bootRecoveryExecution.test.ts`: сохранение исходных Block, удаление только собственных правил, независимый read-back | **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026):** три реальных цикла apply/stop и сравнение экспортов чужих Block/Allow |
| 03-005 | `physicalAdapterSnapshot.test.ts`, `physicalAdapterLifecycle.test.ts`, `lifecycleCleanup.test.ts`: отсутствие фиктивных адаптеров и проверки запуска/отката | **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026):** VM без NIC, отсутствие созданных правил и правдивый статус в UI |
| 03-006 | `physicalAdapterLifecycle.test.ts`, `physicalAdapterSnapshot.test.ts`, `physicalAdapterHotspot.test.ts`: свежий snapshot, добавление/удаление/замена GUID, смена alias, компенсация | **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026):** настоящий hot-plug/переименование во время apply, итоговый набор фильтров и UI |
| 03-007 | `systemNetwork.test.ts`: отказ каждого из 9 registry-шагов и реальный PowerShell с подставным Restore-Snapshot; `firewallTransactions.test.ts`, `physicalAdapterLifecycle.test.ts`, `lifecycleCleanup.test.ts`: общий Stop operationId, независимость Firewall/WFP/baseline/adapters, явные результаты шагов, failure через IPC, общий ID concurrent Stop и новый ID retry; `Dashboard.cancel.test.tsx`: видимые перечень отказов и рекомендация вместо success | Доступные L2-сценарии проверены на production bodies и renderer с подставными системными/IPC границами. Сквозной ID этой задачи относится к controller Stop и вызываемым rollback, не ко всем startup/crash/shutdown-backstop путям; оставшиеся системные L3-запуски — **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026)** |
| 03-008 | `granularKillSwitch.test.ts`, `firewallTransactions.test.ts`: 50 конкурентных обновлений, seeded mixed add/remove, сверка каждого native set, конечного store и всех audit-событий; journal-before-effects, store/system compensation, сохранение core/upstream | Доступные L2-сценарии прошли; системные API подставлены. Оставшаяся L3-приёмка Windows/WFP — **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026)** |
| 03-009 | `firewallKillSwitchValidation.test.ts`, `killSwitchExceptionValidation.test.ts`: generated IPv4/IPv6, маски, типы путей, canonical dot paths, readable `.exe`/realpath и directory rejection; `granularKillSwitch.test.ts`: IPC field types/lengths, normalized CIDR duplicates без store/native effects, настоящий GetShortPathName и отклонение 8.3-дубликата; `firewallTransactions.test.ts`: отказ до записи/native effects | Подтверждены перечисленные L1-поднаборы на текущей Windows. Локальный 8.3 PASS относится к использованной файловой системе; оставшаяся L3-приёмка WP-3 — **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026)** |
| 03-010 | `wfpIpv6.test.ts`, `physicalAdapterHotspot.test.ts`, `firewallTransactions.test.ts`: production C# с fake engine, AND scope, NAT64 endpoint, отсутствие широких permit, независимая компенсация | **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026):** полная OS-матрица, настоящий BFE/boot-time, pktmon + внешний capture, physical mobile 464XLAT positive/negative и byte-equivalent restore |
| 03-011 | `physicalAdapterLifecycle.test.ts`, `physicalAdapterDnsScript.test.ts`, `systemNetwork.test.ts`: read-back DNS, частичные отказы и сохранение recovery-обязанности | **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026):** отказ DNS посередине apply, полный baseline restore, причина в UI и успешная повторная попытка |
| 03-012 | `recoveryManifestStorage.test.ts`, `firewallManifestSecurity.test.ts`, `bootRecoveryExecution.test.ts`: trust-before-effects, ACL/owner/reparse отказ, строгая схема | **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ (18.10.2026):** настоящие ослабленные ACL/подложный манифест на отдельной VM, reboot, SYSTEM и положительный легитимный контроль |

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

### AT-03-007: отсутствие runtime требует доступного пути

Наблюдатель CIM теперь отклоняет недоступный ExecutablePath кандидата:
невозможность установить владельца не означает, что процесс завершился.
Worker и standalone fallback используют один readonly запрос. Status и stop
проверяют границу runtime-каталога с завершающим слэшем; соседний каталог
`runtime-extra` больше не попадает в принудительную остановку.

Нативные regression fixtures воспроизвели три прежние ошибки (3 failed,
17 passed), затем профильные 3 suites дали 265 passed. Stop-Process/CIM
подставлены; это проверка production dispatcher, не завершение реального ядра.
Тесты fallback и строгого результата сохранены в `ownedRuntimeStatus.test.ts`
и `tunRuntimeExitProof.test.ts` (29 passed после обновления AST dependencies).

Финальная проверка observer-изменения: `npm.cmd test` — 3202 passed,
5 skipped, 234 files passed, 2 skipped, 123.97 с, exit 0; typecheck/build,
traceability (AC 927/927, F 210/210) и `git diff --check` — exit 0.

### Status read-back: четыре filter query на снимок

Проверено замечание CodeRabbit 4304029954: вместо четырёх CIM association
queries на каждое правило выполняются четыре bulk ActiveStore reads.
Фильтры индексируются по InstanceID и связываются с rule.Name, сохраняя
проверку ровно одной записи каждого типа и прежние поля результата.
Ошибки чтения, пропуски, повторные записи и пустые ID не дают успешного статуса.
Индексы создаются заново на каждом запросе.

17 native fixtures проверяют малый/110-rule/пустой набор, два одинаковых
DisplayName с разными native ID/scopes, обратный порядок фильтров и отрицательные
ветки каждого типа. Успешный снимок требует ровно четырёх queries независимо
от размера. Адресно: `npm.cmd test -- src/main/firewallStatus.test.ts
src/main/firewallTransactions.test.ts` — 135 passed, 1 skipped, exit 0.
Системные cmdlet подставлены; ускорение реального привилегированного чтения
и отсутствие status timeout на произвольных установках этим не доказаны.

Финальный `npm.cmd test` — 3218 passed, 5 skipped, 234 files passed,
2 skipped, 129.39 с, exit 0. `npm.cmd run typecheck`, `npm.cmd run build`,
traceability (AC 927/927, F 210/210) и `git diff --check` — exit 0.

### AT-03-009: расширенные seeded properties

IPC handler проверяет non-string и неизвестные type, неверные value/label,
пустые строки и границы 200/2048 с указанием поля до store/native effects.
Generated normalized CIDR duplicates не создают второй entry/native update.
Readable `.exe` с повторными `./` возвращает canonical path; readable directory
с расширением `.exe`, control chars, relative/UNC/ADS/`..` и неверное расширение
отвергаются. Seeds 30012…30015: 200/50/50/50 runs с явными length examples.
Новые свойства исполняют production API/IPC handler; сетевые cmdlet подставлены.
Предыдущая реальная 8.3 проверка остаётся отдельным доказательством.

В existing runtime suite добавлена проверка controller имени в status/stop
scripts (Revix 4304071624), предотвращающая будущий drift. Production код
этим расширением тестов не менялся.

Review 36611ed: сценарий broadened remote Any у allow-singbox не подтвердился
как дефект verifier: production создаёт эту rule с Program и remote Any;
остальные поля без ограничений также уже Any. Для остальных core rules
проверены соответствующие ограничения creation script. Слабый combined test
заменён 11 независимыми изменениями program/interface/address/protocol/ports;
каждое расширение ограничивающего поля отвергается. Это проверка текущей
объявленной политики, не доказательство отсутствия packet leaks.
Fixtures теперь создают проектную `.tmp` перед mkdtemp (clean-checkout case).
Финальные четыре адресных suites — 102 passed, без пропусков, exit 0.

Финальный полный `npm.cmd test` — 3224 passed, 5 skipped, 234 files passed,
2 skipped, 127.01 с, exit 0; typecheck, traceability (AC 927/927, F 210/210)
и `git diff --check` — exit 0. Production build проверен на 36611ed;
после него менялись только тесты и этот отчёт/журнал.

### AT-03-003: частичные документы и независимые DNS registry steps

Production boot recovery исполняется на fake Windows API с четырьмя новыми
вариантами: неполные firewall profiles, вторая запись адаптера без identity,
четыре из девяти baseline values, TUN record без GUID. Каждая ошибка даёт
warnings/exit 1; другие валидные манифесты продолжают восстановление.
Повреждённый firewall snapshot карантинируется, fallback Allow явно сообщает
protection unknown. Неподтверждённые adapter/baseline/TUN записи не удаляются.

Шесть native fixtures исполняют production Restore-RegValue: missing,
неверный registry type и DWORD overflow в каждом из двух DNS policy steps.
Валидный соседний step выполняется и проходит read-back, невалидный не меняет
fixture registry; результат обоих шагов присутствует в журнале, warning=true.
Настоящие сетевые ключи и настройки Windows этим harness не затрагиваются.

**На момент fdfac87 оставалось открыто (уточнено 18.10.2026, §10.13):** формулировка AT-03-003(c) «половина шагов без подписи» не
определяет вид подписи. Текущий формат проверяет ACL/owner/schema, отдельных
криптографических подписей шагов нет. Обычные baseline/adapter validators
также требуют полный документ. Владельцу задано уточнение смысла подписи;
до ответа нельзя считать эти fixtures доказательством всего пункта (c).
Нормативные документы не менялись.

Revix fdfac87: исправлены 4304125808 (ExecutionPolicy только дочернего
fixture-процесса, как у boot harness) и 4304125811 (явная assert наличия rule).
4304125817 о .itest suffix — оставлено как minor: перенос исключил бы эту
L2-матрицу из обычного npm test/Windows CI, текущая сборка тестов сознательно
включает другие native PowerShell fixtures. Результат ревью не объявляется
APPROVED на основании этих исправлений.

Адресный прогон вместе с startup regression suite: `npm.cmd test --
src/main/lifecycleCleanup.test.ts src/main/bootRecoveryBehavior.test.ts
src/main/bootRecoveryExecution.test.ts src/main/firewallStatus.test.ts` —
223 passed, 4 files passed, 16.44 s, exit 0. Финальный `npm.cmd test` —
3236 passed, 5 skipped, 234 files passed / 2 skipped, 128.34 s, exit 0.
Typecheck, build, traceability (AC 927/927, F 210/210), diff check — exit 0.

### Startup recovery: неблокирующее предупреждение

CodeRabbit 4304147637 подтверждён: ожидание закрытия диалога задерживало
остальные recovery steps до появления main window; отказ показа мог прервать
startup recovery. Теперь диалог не ожидается, его rejection логируется
отдельно. Заголовок и текст отличают отказ preflight от неудачного rollback.
Условие подтверждённого runtime exit перед восстановлением не изменилось.

В lifecycleCleanup.test.ts pending/rejected dialog не мешают завершению
recoverStaleBaseline и переходу к следующему recovery. Runtime/storage
preflight failures не запускают rollback и получают сообщение «не проверено».
До исправления startup subset: 4 failed / 4 passed / 132 skipped; после —
все 223 теста четырёх адресных suites прошли. Финальные полные проверки выше
выполнены после исправления production кода; build также exit 0.

### Уточнение native fixtures после review 0d175b5

Revix 4304178126 и CodeRabbit 5559714772 подтвердили коллизию GUID:
physical fixture наследовал TUN GUID/driver/PnP. Теперь у физического адаптера
отдельные GUID/ifIndex/driver/PnP. Обязательны отсутствие его удаления,
удаление только TUN и очистка TUN ownership record при успешном шаге.
Новые отрицательные assertions до ремонта фикстуры: 3 failed / 1 passed /
16 skipped. После ремонта boot execution/behavior — 33 passed, exit 0.
Write-RecoveryReport fixture также читает конечные профили через
Get-NetFirewallProfile; проверяются финальные Allow/Block и сохранённый
Domain Block после injected failure, а не только вызовы setter.

### P1: исключённые интерфейсы профиля не доказывают firewall protection

Review 4304183201 подтверждён: DisabledInterfaceAliases раньше терялся при
чтении ActiveStore. Теперь snapshot содержит обязательный disabledInterfaces.
Отсутствующее native property отклоняется; явный native CIM null (проверен
read-only на текущем хосте) означает пустой список. Штатный NotConfigured
разрешён только как единственное значение. Реальные excluded aliases,
пустая строка или неподтверждённая форма дают unknown, без native writes.

Нативные fixtures проверяют excluded alias, NotConfigured, null, missing
property и неверный тип; TypeScript — все три профиля и неполные данные;
настоящий status API с fake OS boundaries возвращает incomplete-policy или
read-back-failed вместо verified. До ремонта 13 failed / 52 passed.
Реальные firewall settings при расследовании и проверке не менялись.

### P1: startup требует подтверждённого runtime exit

Review 4304193950 подтверждён на production query + production wrapper +
production startup/firewall-recovery bodies. Старый нестрогий wrapper при
ошибке CIM возвращал false и разрешал cleanup. До исправления: owned,
mixed (known owned + unknown path), unknown дали 3 failed; absent — passed.

performCrashRecovery теперь сначала требует свежую строгую runtime proof,
при live/unknown не запускает cleanup, при unknown показывает native warning
без ожидания закрытия. Callback firewall recovery и проверка перед adapter
rollback также используют requireProof=true; поздняя ошибка останавливает
оставшиеся шаги. Тестируются шесть сценариев: owned/mixed/unknown/absent,
потеря наблюдения перед firewall cleanup и перед adapter rollback.
Внешние Windows API подставлены; это не SYSTEM reboot/packet acceptance.

Пять адресных suites: `npm.cmd test -- src/main/lifecycleCleanup.test.ts
src/main/ownedRuntimeStatus.test.ts src/main/firewallStatus.test.ts
src/main/firewallTransactions.test.ts src/main/bootRecoveryExecution.test.ts`
— 339 passed / 1 skipped, 5 files passed, 20.72 s, exit 0.
`npm.cmd run build` — exit 0; полный набор выполняется.

### P2: correlation ID сохраняется в настоящем app.log

Review 4304208372 подтверждён: production redactor маскировал randomUUID()
внутренней операции тем же маркером, что VPN credential UUID. Новый тест
настоящего appLogger, redactor и очереди записи файла до исправления падал:
два разных receipt ID в файле превращались в один <redacted-uuid>.

Baseline и Stop теперь генерируют baseline_/stop_ + 32 hex-символа.
Наследуемый ID не меняется; общий redactor и UUID-схема durable firewall
manifest сохранены. File-log regression проверяет две операции baseline
(failed rollback и successful retry): ID совпадает с receipt, различается
между операциями, присутствует на девяти шагах и в завершении с правильным
success. Синтетический credential UUID по-прежнему маскируется. Для Stop
проверены формат, наследование ID и concurrent/retry lifecycle; отдельный
настоящий Stop file-log этим тестом не проверяется. OS boundaries подменены.

Полный прогон после P1 сначала обнаружил одно устаревшее строковое ожидание
mainIpcRegression (3257 passed / 1 failed / 5 skipped); оно исправлено на
строгий callback. Whole-chain startup поведение проверяется отдельно.
После всех исправлений `npm.cmd test -- src/main/systemNetwork.test.ts
src/main/lifecycleCleanup.test.ts src/main/mainIpcRegression.test.ts
src/main/firewallStatus.test.ts src/main/firewallTransactions.test.ts
src/main/bootRecoveryExecution.test.ts` — 397 passed / 2 skipped,
6 files passed, 23.09 s, exit 0; `npm.cmd run build` — exit 0.

Финальный полный `npm.cmd test` — 3259 passed / 5 skipped,
234 files passed / 2 skipped, 130.84 s, exit 0. `npm.cmd run typecheck` —
exit 0. Из корня `python -X utf8
docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC 927/927,
F 210/210, exit 0; `git diff --check` — exit 0. Полный лог сохранён в
`.tmp/wp3-review-final-full.log`; это локальные проверки, CI/review нового
SHA проверяются отдельно.

### Remote gates после исправлений: b31807f

Windows job 117488889602: success, 3260 passed / 4 skipped,
235 files passed / 1 skipped, 129.54 s; AC 927/927, F 210/210.
Native BFE smoke: ok=true, aborted=true, priority=verified; Electron native
reads: 1 passed / 1 skipped. Rust job 117488889576: success. Эти результаты
относятся к b31807f, а не к будущим коммитам. BFE ABI/read-back с Abort
не подтверждает packet filtering, boot-time или физический 464XLAT.

Revix check 117488897178 завершён neutral: check-run ещё содержит старую
Needs changes summary и 2 issue(s) found, а актуальная PR Timeline отмечает
исправления и Low risk для b31807f в 19:57 UTC. Новых inline findings,
созданных для b31807f, нет. Формальный APPROVED не получен.

CodeRabbit автоматически skipped; ручная команда 6239986186 получила
ответ 6239987347 «Review rate limited / Action not completed». Последнее
завершённое review 5559714772 относится к 0d175b5. Новый head пока не
проверен этим reviewer; skipped success не считается review. До доступной
квоты повторные команды не отправляются (последний review — 19:39 UTC,
план сообщает одно included review в час).

Требуемая L3-среда не появилась: процесс non-admin, build 26300,
зарегистрированная VM выключена, её известный VHDX отсутствует. Запрошено
местоположение доступной изолированной лаборатории. Вопрос о смысле подписи
в AT-03-003(c) остаётся без ответа; требование не переопределено.

## Решение владельца от 18.10.2026

Ответ на вопрос об изолированной L3-среде: «нет. нету . да и не надо.
отметь как пропущено владельцем». Владелец отдельно уточнил статус:
«не не проверено  а пропущено владельцем,это разное».

Итоговый статус оставшейся L3-приёмки WP-3 — **ПРОПУЩЕНО ВЛАДЕЛЬЦЕМ**
(`SKIPPED_BY_OWNER`). Объём: packet oracle, SYSTEM reboot, чужие firewall
rules, отсутствие NIC/hot-plug, DNS failure, IPv6/NAT64/mobile 464XLAT,
системные ACL-манифесты и поддерживаемая OS-матрица; L3-часть AT-03-003
также входит в решение. В матрице выше этот статус указан по сценариям.
Формулировки тестовых оракулов и записанные локальные результаты сохранены.

## CI и review 251a634 (18.10.2026)

Windows job 117506906954 завершён success на 251a634: 3260 passed /
4 skipped, 235 files passed / 1 skipped, 212.40 s; AC 927/927, F 210/210.
Electron native read smoke: 1 passed / 1 skipped. Rust job 117506906749 —
success. Лог: `.tmp/wp3-ci-117506906954.log`. Это автоматические результаты;
статус L3 остаётся «Пропущено владельцем» по §10.12.

CodeRabbit review 5560162474 завершён 17.10.2026 в 21:24 UTC и охватывает
изменения 0d175b5 → 251a634, включая P1/P2 исправления. Единственное
замечание — Minor к README: прогон 13 октября ошибочно назван последним.
Запись исправлена на историческую со ссылкой на этот отчёт и журнал.
Существенных новых замечаний в этом review нет; формального APPROVED нет.
Revix check 117506917043 завершён neutral, без новых inline findings для
251a634; заголовок сохраняет 2 issue(s) found и старую Needs changes summary.
Neutral не трактуется как APPROVED. Условие minor-only review соблюдено
для проверенного 251a634; проверка последующих коммитов учитывается отдельно.

## AT-03-003(c): решение владельца и частичные записи, 18.10.2026

Владелец подтвердил: «Да, восстановить исправные записи» доверенного файла
отката, пропуская испорченные с явной ошибкой. Это не подпись EXE и не новое
требование сертификата; решение записано в ТЗ-06 §10.13.

Recovery-режим валидаторов baseline, firewall profiles и adapter snapshots
сохраняет проверки общего документа, доверенного хранилища и версии схемы.
Отдельные невалидные записи не мешают валидным соседям. Конфликтующие дубли
одного target/profile/GUID не исполняются; первая запись не получает приоритета.
DNS registry policy и transition snapshots проверяются независимо. Apply,
запись манифестов и passive status по-прежнему требуют полной строгой схемы.
Startup и обычный Stop допускают частичный документ только на пути recovery.

Пропуски отражаются в логах и результате/UI. Итог неполного отката — ошибка;
исходный манифест не переписывается и не удаляется. Boot recovery выполняет
валидацию до эффектов каждого шага, сохраняет strict и поддерживает независимость
валидных записей того же файла. Native fixtures используют подставные сетевые
API и registry handles; рабочие firewall, DNS и сетевые ключи не менялись.

Self-review дополнительно различает отсутствующее transition-поле и явный
`null`: missing/невалидное значение даёт warning с сохранением журнала,
валидный соседний переходный механизм восстанавливается. В fixture команда
netsh подставлена. Адресный прогон
`npm.cmd test -- src/main/bootRecoveryExecution.test.ts src/main/bootRecoveryScriptSource.test.ts`
— 35 passed, 20.10 s, exit 0. Полные промежуточные прогоны — 3281 passed /
5 skipped (189.32 s) и 3283 passed / 5 skipped (193.23 s), exit 0.

`npm.cmd run typecheck` и `npm.cmd run dist:win` — exit 0. SHA-256 исходного
и упакованного `resources/vpnte-recover.ps1` совпадает:
`155c175332855980933b7c7081db58784af8c9bd2e09b2dda76f2b4fa414e490`.
`dist/VPN-Tunnel-Enforcer-Setup-1.1.24.exe`: 139728889 bytes, SHA-256
`dc085e8fd4867f1eaadefae48a6f6a415cb844f3f0b5404bd866cab5ccc4d23e`;
реальный Authenticode status — `NotSigned`. Установка/системный reboot
не выполнялись. Логи сборки и хэшей находятся в `.tmp/wp3-partial-frozen-*`.

Финальный полный `npm.cmd test` после последних изменений — **3285 passed /
5 skipped / 0 failed**, 234 files passed / 2 skipped, 181.74 s, exit 0
(`.tmp/wp3-partial-commit-full.log`). `npm.cmd run typecheck` — exit 0;
`python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` —
AC 927/927, F 210/210, exit 0; `git diff --check` — exit 0. Это завершённые
локальные проверки; CI/review нового коммита фиксируются после отправки.

## Условие перехода дальше

Закрыть доступные пробелы L1/L2; смысл AT-03-003(c) принят в §10.13. CI и review на
текущем SHA должны быть без существенных замечаний. L3-сценарии со статусом
«Пропущено владельцем» исключены из ожидаемых запусков по решению §10.12;
отсутствие этой лаборатории больше не является условием ожидания.
