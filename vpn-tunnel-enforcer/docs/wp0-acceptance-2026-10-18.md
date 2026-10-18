# WP-0: контракты и наблюдаемость — 18.10.2026

Статус: **в работе**. Основание: том 3 §1.1–1.2, ТЗ-06 WP-0
и решения владельца §10, AT-00-001…010. WP-3 завершён в PR #46;
его L3 `SKIPPED_BY_OWNER` не распространяется на WP-0.
CodeRabbit исключён из ожидания владельцем; CI и действующий review обязательны.

## Полная область и первоначальная инвентаризация

| AT | Найденная реализация / доказательства | Остаток до приёмки |
| --- | --- | --- |
| 00-001 | `ipcChannelContract.test.ts` проверяет упоминание preload-каналов в main | Точное сравнение трёх множеств, реальные регистрации, схемы входа и единый типизированный envelope всех каналов; упоминание строки недостаточно |
| 00-002 | `tunController.ts`, lifecycle fault-injection tests | Единая модель и интегрированный координатор; все туры ≤6, недопустимые события, ресурсные инварианты |
| 00-003 | Локальная отмена в отдельных подсистемах | Реестр connect/refresh/speed/import/export/rotation; отмена на 10/50/90%, deadline, запрет поздних эффектов |
| 00-004 | IPC trust boundary реализована в WP-1 | Полная typed taxonomy на каждом privileged канале, негативная матрица и отсутствие stack/absolute path |
| 00-005 | `appLogger.ts`, `connectionHistory.ts`; новый regression passive rejection dedup | Сквозной correlation id, монотонный порядок, source/owner/route/confidence истории и redaction всех полей |
| 00-006 | Локальные миграции, в том числе `readSettingsWithMigration` | Централизованный упорядоченный реестр, fixtures всех исторических версий, future-version hash invariance |
| 00-007 | Lifecycle tests отдельных гонок | Seeded 200 команд из 10 потоков, typed losers, итог последней принятой команды и 0 child PID при disconnected |
| 00-008 | Существующие UI-статусы | Матрица кадров всех операций, progress, запрет преждевременной защиты, соответствие общей модели |
| 00-009 | Плановые функции WP-12 не приняты в production | Проверить реестр production flags, отсутствие DOM и отказ включения без laboratory evidence с audit event |
| 00-010 | `connectionHistory.ts`: electron-store, проверка только Array.isArray | Тесты 100 событий/повреждений/перезапуска, явный `history.corrupted` и последующая запись |

Это перечень обнаруженного, а не PASS десяти AT. Ни один новый
неиспользуемый модуль сам по себе не закрывает критерий интеграции.

## Первый адресный regression

Revix `4304732489` из PR #46: повторный passive status polling повреждённого
манифеста заполнял журнал одинаковыми critical events. Теперь одинаковый
отказ подавляется до изменения evidence или успешного trusted read.
Hash повреждённого содержимого входит в fingerprint. Явные операции
сохраняют отдельные события, состояние остаётся unknown, native effects отсутствуют.

- До исправления: `npm.cmd test -- src/main/firewallTransactions.test.ts -t 'deduplicates passive'`
  — 2 failed / 96 skipped, exit 1 (`.tmp/wp0-rejection-dedup-before.log`).
- После: `npm.cmd test -- src/main/firewallTransactions.test.ts`
  — 97 passed / 1 skipped, 9.16 s, exit 0.
- Общие проверки перед коммитом записываются в `progress.md`.
