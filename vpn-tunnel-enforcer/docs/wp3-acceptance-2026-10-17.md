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
| 03-003 | `recoveryManifestStorage.test.ts`, `firewallTransactions.test.ts`, `bootRecoveryExecution.test.ts`, `systemNetwork.test.ts`: corrupt/missing/future schema, карантин, сохранение strict, отсутствие эффектов для недоверенных данных | **Частично:** полная матрица частичных манифестов и реальный boot/обычный rollback; mocks не доказывают системные ACL |
| 03-004 | `firewallTransactions.test.ts`, `bootRecoveryExecution.test.ts`: сохранение исходных Block, удаление только собственных правил, независимый read-back | **NOT-CHECKED L3:** три реальных цикла apply/stop и сравнение экспортов чужих Block/Allow |
| 03-005 | `physicalAdapterSnapshot.test.ts`, `physicalAdapterLifecycle.test.ts`, `lifecycleCleanup.test.ts`: отсутствие фиктивных адаптеров и проверки запуска/отката | **NOT-CHECKED L3:** VM без NIC, отсутствие созданных правил и правдивый статус в UI |
| 03-006 | `physicalAdapterLifecycle.test.ts`, `physicalAdapterSnapshot.test.ts`, `physicalAdapterHotspot.test.ts`: свежий snapshot, добавление/удаление/замена GUID, смена alias, компенсация | **NOT-CHECKED L3:** настоящий hot-plug/переименование во время apply, итоговый набор фильтров и UI |
| 03-007 | `systemNetwork.test.ts`: отказ каждого из 9 registry-шагов, реальный PowerShell с подставным Restore-Snapshot; `firewallTransactions.test.ts` и `lifecycleCleanup.test.ts`: независимость Firewall/WFP/baseline/adapters, failure через IPC и retry | **Частично L2:** свести независимые отказы разных подсистем в один протокол; подтвердить correlation id событий каждого шага и отображение сводки в UI |
| 03-008 | `granularKillSwitch.test.ts`, `firewallTransactions.test.ts`: 50 конкурентных обновлений, journal-before-effects, store/system compensation, сохранение core/upstream | **Частично L2:** seeded смешанный сценарий UI + scheduler с сопоставлением итогового store/native policy и журнала всех операций |
| 03-009 | `firewallKillSwitchValidation.test.ts`, `killSwitchExceptionValidation.test.ts`: generated IPv4/IPv6 и маски, невалидные числовые формы, локальный readable `.exe`/realpath; `firewallTransactions.test.ts`: отказ до записи и native effects | **Частично L1:** явная проверка эквивалентности реальных 8.3/длинных путей и дубликатов; расширенный генератор типов/путей/длин. Новые prefix-регрессии не закрывают AT целиком |
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

## Условие перехода дальше

Закрыть доступные пробелы L1/L2, получить и сохранить реальные L3-доказательства
для всех требуемых сред/оракулов; CI и review на текущем SHA должны быть без
существенных замечаний. Пока это не выполнено, WP-3 не объявлять завершённым
и WP-0/WP-2 не объявлять начатыми по факту этой сверки.
