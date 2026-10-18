# WP-0: контракты и наблюдаемость — 18.10.2026

Статус: **в работе**. Основание: том 3 §1.1–1.2, ТЗ-06 WP-0
и решения владельца §10, AT-00-001…010. WP-3 завершён в PR #46;
его L3 `SKIPPED_BY_OWNER` не распространяется на WP-0.
Главный ревьюер — Qodo по решению владельца от 18.10. CodeRabbit исключён
из ожидания; окончание trial Greptile не блокирует работу. CI и review обязательны.
18.10 владелец разрешил продолжать WP-0 при открытом PR #54, сохраняя запрет
его слияния до отдельного решения. Полного Revix для #54 не было из-за квоты.

## Полная область и первоначальная инвентаризация

| AT | Найденная реализация / доказательства | Остаток до приёмки |
| --- | --- | --- |
| 00-001 | AST-проверка 157 main/preload/shared request channels, общий реестр входов и versioned transport envelope; object contracts проверяют поля/массивы, save-settings покрывает все 39 общих полей AppSettings; TypeScript checker проверяет results всех 157 listeners, public results с `any` больше нет; native contextBridge сохраняет JSON профиля и nullable active result | Завершить проверку текущего PR; отдельная semantic matrix ошибок остаётся в 00-004 |
| 00-002 | `tunController.ts`, lifecycle fault-injection tests | Единая модель и интегрированный координатор; все туры ≤6, недопустимые события, ресурсные инварианты |
| 00-003 | Локальная отмена в отдельных подсистемах | Реестр connect/refresh/speed/import/export/rotation; отмена на 10/50/90%, deadline, запрет поздних эффектов |
| 00-004 | Общая классификация transport; 157 каналов × 7 категорий через guard; native contextBridge сохраняет code/category/correlation в en/ru; typed local validation; 4 настоящих config handlers × 7 категорий, canonical domain failures | Миграция legacy domain-result `{success:false,error}` и semantic matrix настоящих feature handlers; transport fixtures не доказывают её |
| 00-005 | `appLogger.ts`, `connectionHistory.ts`; новый regression passive rejection dedup | Сквозной correlation id, монотонный порядок, source/owner/route/confidence истории и redaction всех полей |
| 00-006 | Локальные миграции, в том числе `readSettingsWithMigration` | Централизованный упорядоченный реестр, fixtures всех исторических версий, future-version hash invariance |
| 00-007 | Lifecycle tests отдельных гонок | Seeded 200 команд из 10 потоков, typed losers, итог последней принятой команды и 0 child PID при disconnected |
| 00-008 | Существующие UI-статусы | Матрица кадров всех операций, progress, запрет преждевременной защиты, соответствие общей модели |
| 00-009 | Плановые функции WP-12 не приняты в production | Проверить реестр production flags, отсутствие DOM и отказ включения без laboratory evidence с audit event |
| 00-010 | История подключений: настоящий Conf backend, 100 записей, повторная загрузка, повреждённый JSON/схема, `history.corrupted`, сохранение валидных записей и последующая запись | Адресная L2-матрица истории подключений добавлена; перенос той же гарантии на общий audit/event history всех операций после его введения |

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

## AT-00-010 — история подключений

`connectionHistoryStorage.test.ts` использует настоящий файловый backend Conf
(тот же backend electron-store), заменяя только обнаружение Electron userData
и версии приложения. Это L2: повторное создание сервиса читает файл заново;
полный перезапуск Electron/Windows этим стендом не заявляется.

- 100 событий сохраняются после повторной загрузки, старые записи без outcome
  и errorMessage поддерживаются; CSV/JSON читаются.
- Обрезанный JSON, мусор в хвосте, неверная корневая схема и повреждённые
  отдельные записи вызывают `history.corrupted`. Валидные записи массива
  сохраняются; отбракованные элементы удерживаются в rejectedConnectionHistory
  при последующих записях, включая outcome из более нового приложения. Raw payload, имена профилей и ошибки парсера в событие не попадают.
- Новый write атомарно сохраняет исправленную историю через Conf. До записи
  повреждённый файл не стирается: возвращается безопасное представление,
  а событие явно сообщает о повреждении. Повторное чтение одного повреждения
  подавляется до изменения содержимого, успешного чтения/записи либо очистки.
- Ошибки файловой системы не превращаются в пустую историю. Невалидные новые
  записи отклоняются до записи файла.

До production-исправления: 8 failed / 2 passed,
`npm.cmd test -- src/main/connectionHistoryStorage.test.ts`, exit 1;
`.tmp/wp0-history-before.log`. Проверки итогового кода — в progress.md.
Это не завершает AT-00-005 или весь WP-0.

Revix PR #48 suggestion 4306503597 закрыт сохранением отбракованных
элементов в том же store и общим runtime SESSION_OUTCOME_KINDS для union-типа
и reader. Повторная запись не дублирует отбракованные элементы; явная очистка
удаляет их вместе с остальной историей. Question 4306503603: оба production
call site addEntry в index.ts catches, исключение записи не выходит в teardown.

## Следующий участок — AT-00-001

Первичный AST-инвентарь текущих исходников: 157 уникальных invoke-каналов
preload, 78 строковых деклараций в *Channels интерфейсах shared,
44 прямых ipcMain.handle регистрации и 9 мест регистрации через wrapper.
78 включает event-only progress каналы: их следует разделить с invoke API,
а не объявлять отсутствующими request handlers. Wrapper calls требуют
разрешения до реальных channel arguments.

Это подтверждает недостаточность нынешнего string-presence теста, но
не доказывает отсутствия 113 main handlers: большая часть зарегистрирована
через wrapper. Полный паритет, схемы входа и envelope остаются открытыми.
Артефакт первичного сканирования: .tmp/wp0-ipc-inventory.json (не норматив).

## Реализованная граница IPC — 18.10.2026

`shared/ipc-contract.ts` (реэкспорт из ipc-types) содержит 157 request channels,
имена публичных методов и runtime-схемы wire arguments. `electron-api.ts`
содержит прежний публичный API; preload сохраняет прежние типовые экспорты.
События не смешиваются с request registry. Неиспользуемый дубликат
`diagnostics:run-leak-check` и осиротевшие старые *Channels удалены.

`scripts/check-ipc-contract.mjs` разбирает TypeScript AST реальных исходников,
разрешает девять обёрток регистрации, сравнивает множества и имена методов.
Комментарии не считаются регистрациями; неизвестные динамические регистрации,
дубликаты, лишние декларации, прямой обход preload decoder вызывают ошибку
с указанием имени. Проверка входит в typecheck и build.

Все зарегистрированные handlers проходят sender-frame/origin guard,
ограничение структуры/размера и схему аргументов перед вызовом listener.
`ipMonitor` больше не регистрирует handlers при импорте: main явно вызывает
registrar после установки guard. Регрессия проверяет импорт с process.type=browser,
отказ чужому кадру без эффектов и успешные suspend/resume через guard.

Wire response: `{version:1, correlationId:UUIDv4, ok:true, result}` либо
`{version:1, correlationId:UUIDv4, ok:false, error:{category,code,message}}`.
Preload снимает transport envelope; существующие domain result, в том числе
`undefined` и `{ok:false}`, сохраняются. Исключения и отказы transport становятся
`IpcRemoteError` внутри preload; повреждённый ответ и reject Electron имеют
безопасную внутреннюю ошибку. Перед contextBridge request-обёртка преобразует
исключение в `IpcRemoteErrorData`: plain-object Promise rejection с name,
category, code, каноническим message и optional correlationId. Никакие stack,
cause или произвольный текст exception не копируются. main world проверяет
форму через isIpcRemoteErrorData; instanceof Error для этих данных неверен.
Все 157 request methods выбираются из того же registry; subscriptions и их
синхронные unsubscribe handles не оборачиваются. Даже локальная валидация
параметров теперь отклоняет Promise, как объявлено публичным API; main IPC
не вызывается и correlationId не выдумывается. Сквозная domain correlation
AT-00-005 ещё не реализована.

Revix PR #50 suggestion 4306715099 учтён: локальные валидаторы явно бросают
`IpcValidationError`; неожиданные `TypeError`/`RangeError` внутри preload
остаются `internal`. Ошибка сериализации входного объекта классифицируется
валидатором до IPC. Регрессии различают ошибку параметров и внутренний сбой.
Nitpick 4306715102 о loose assert не применим: native fixture уже импортирует
`node:assert/strict`, поэтому `assert.equal` выполняет строгое сравнение.

| category | Стабильный code | Условие transport |
| --- | --- | --- |
| validation | IPC_VALIDATION_ERROR | Отказ схемы/лимитов либо typed validation fault |
| permission | IPC_PERMISSION_DENIED | Чужой sender/frame/origin, EACCES, EPERM |
| network | IPC_NETWORK_ERROR | ECONNRESET/ECONNREFUSED/ENOTFOUND/EAI_AGAIN/ENETUNREACH/EHOSTUNREACH |
| conflict | IPC_STATE_CONFLICT | Явный IpcFault(conflict) |
| internal | IPC_INTERNAL_ERROR | Неизвестное исключение/некорректный transport |
| cancelled | IPC_CANCELLED | AbortError либо typed fault |
| timeout | IPC_TIMEOUT | ETIMEDOUT либо typed fault |

Сообщения заданы константами в `ipc-result.ts`; произвольный текст исключения
не сериализуется. Даже бросающий getter code/name остаётся внутри safe envelope.
Bounded guard audit metadata использует обратимое `ipc_` + UUID без дефисов:
все 128 бит сохранены и однозначно соответствуют envelope correlationId.
Голый UUID redactor справедливо скрывает как потенциальный credential;
политика редактирования секретов не ослаблена. `ipcAuditLog.test.ts` проверяет
настоящую guard, настоящий logger/redactor и файл app.log, включая positive
control скрытия голого UUID. Это закрывает Revix issue 4306608229.

Canonical сообщения имеют en/ru варианты. Preload выбирает исходный язык
из navigator так же, как renderer i18n, затем учитывает persisted get-locale,
успешный set-locale и межоконное событие locale-changed. Текст main exception
при этом по-прежнему не используется. Unit и native smoke подтверждают
English/Russian без зависимости от языка Windows. Это ответ на 4306608232.
Suggestion 4306608234 учтён сужением документации и комментария реестра:
bounded legacy object не объявлен полной field schema; остаток явный.

`ipcContractAcceptance.test.ts` проводит все 157 channels через production guard:
допустимые wire args, неверный тип каждого аргумента, лишний аргумент, чужой
кадр и все семь исключений. Feature listeners в этой матрице заменены на
контролируемые эффекты; это не исполнение 157 настоящих подсистем.
Plain-object inputs legacy API ограничены по размеру/форме, но не все имеют
глубокую field schema. Старые domain-result ошибки пока не переведены
в новую taxonomy. Поэтому AT-00-001/004 и WP-0 целиком не объявлены PASS.

Native Electron 44.4.3: `node scripts/test-electron-runtime.mjs` — exit 0,
production preload/contextBridge, reload, loopback dev parity, unknown sender,
navigation rejection, native safeStorage. `node scripts/test-wp1-native.mjs --ipc-only`
— exit 0, настоящий hostile subframe с нулём effects и production CSP.
Режим явно ограничен IPC/CSP, не выполняет ACL/ZIP/clipboard или OS matrix.
Исправлена сборка native fixture: koffi остаётся external native dependency.
Полные команды DoD и результаты записаны в progress.md.

## Main-world typed errors — 18.10.2026, после PR #49

До исправления усиленный `node scripts/test-electron-runtime.mjs` завершился
exit 1: native renderer получил undefined вместо IPC_VALIDATION_ERROR
(`.tmp/wp0-renderer-error-before.log`). Unit mock сохранял поля Error и
этого не обнаруживал. Promise rejection plain object решает реальную
границу; синхронный throw через contextBridge тоже теряет поля, поэтому
валидация request methods возвращает rejected Promise.

Теперь native Electron 44.4.3 проверяет все семь категорий в en/ru (14 вызовов)
через production guard/preload/contextBridge, уникальный UUID каждого ответа,
code/category/message и отсутствие exception text/stack/path. Отдельно
проверяет typed local validation без main correlation. Listener get-settings
в этом native стенде управляемый; полноценная semantic matrix feature handlers
этим не подменяется. Windows CI выполняет production build, этот native smoke
и IPC/CSP subset в каждом PR; OS/installed/L3 matrix не заявлена.

Quick server picker распознаёт plain-object ошибку и показывает message,
вместо `[object Object]`; остальные существующие `.message` catches совместимы.
Root unhandledrejection handler тоже распознаёт типизированную ошибку.
Оба глобальных error handlers наблюдают rejected logRenderer Promise:
сбой самого reporting IPC не порождает рекурсивную unhandled rejection.
Это покрыто функциональными renderer tests, вместе с прежним Error fallback.
Legacy any/deep object schemas/domain-result failures и остальные AT остаются
в работе; WP-0 не завершён.

## AT-00-001 — вложенные object contracts

На ветке codex/wp0-ipc-object-schemas 12 прежних bounded object inputs
уточнены: scheduler create/update, rotation config, kill-switch exception,
DNS create/update, domain rule add/update, history filter, notification patch,
theme create и live-check history filter. Проверяются типы вложенных полей,
элементы и длина массивов, числовые диапазоны и перечень разрешённых ключей.
Массивы с пустыми слотами не обходят проверку через Array.every.

Одинаковая схема применяется в production preload и main guard. До исправления
21 некорректный объект достигал listener: `npm.cmd test -- src/main/ipcContractAcceptance.test.ts -t 'rejects invalid nested'`
— 21 failed / 321 skipped, exit 1 (.tmp/wp0-object-schema-before.log).
После исправления негативные запросы имеют validation и ноль эффектов.
Таблица положительных примеров отдельно сохраняет пустые patches, дни 0/6,
nullable/отсутствующий secondary DNS, исходные семь цветов темы, 1000 profileIds
и конечные интервалы вне 5…1440: clamp выполняет существующий rotation service,
wire contract не подменяет его политикой отказа.

У этих функций убраны any из публичных входов/результатов. NextEvent, filters
и aggregated stats переехали в shared с совместимыми type-only reexports из
main. Logs использует тип фильтра. Семантические feature validators по-прежнему
проверяют адрес DNS, доменный шаблон, время и hex-палитру. Уточнённый контракт
не объявлен доказательством всех негативных сценариев реальных handlers.

Native production contextBridge smoke проверяет отказ scheduler.days=[7]
до effects и успешный partial update. Команды, итоговые counts и удалённая
приёмка записываются в progress.md. save-settings остаётся единственным
object() без fields; его глубокая схема и оставшиеся any ответов — следующий
остаток AT-00-001, наряду с общей работой WP-0 по матрице выше.

## AT-00-001 — общий settings contract

AppSettings больше не дублируется в main и renderer: общий тип находится
в shared/settings.ts, старые импорты сохранены через type-only reexport.
getSettings/saveSettings/setLoginItem используют его в public ElectronAPI.
Схема save-settings описывает все 39 полей и имеет compile-time ключи
Record<keyof AppSettings,...>: добавленное или удалённое поле требует
синхронного обновления runtime-схемы. Последний object() без fields устранён.

Новые IPC-патчи проверяют boolean/enum/number/string, profile arrays и
рекурсивные JSON-shaped outbound values до любых effects. Произвольные
функции/необычные prototype/нечисловые числа не проходят; JSON ограничен
по глубине и числу значений. Тип outbound не содержит any; optional значения
undefined до JSON persistence поддержаны. Это схема значений transport,
а не замена semantic protocol validators sing-box/Xray.

До исправления `npm.cmd test -- src/main/ipcContractAcceptance.test.ts -t 'rejects invalid nested'`
— 13 failed / 27 passed / 343 skipped, exit 1
(.tmp/wp0-settings-schema-before.log): строковые флаги и другие неверные
типы достигали listener. Production contextBridge smoke отдельно проверяет
строковый autoStart без эффектов и успешный boolean partial update.
Неверный checkInterval:NaN теперь отклоняется самим preload, поэтому у
этой локальной ошибки нет выдуманного main correlation; main correlation
по-прежнему проверяется нативной матрицей 7 категорий × 2 языка.

Нормализация исторических store и DPAPI migration не изменены. Numeric
clamp по-прежнему выполняет settingsStore, а пустые/частичные patches,
nullable cachedAt и вложенные cache JSON сохраняют поддержку. Целевые
feature/renderer/migration tests и полный DoD — в progress.md. Оставшиеся
any ответов других функций и legacy domain failures сохраняются в остатке
WP-0; отсутствие bounded legacy object() не объявляет весь пакет завершённым.

## AT-00-001 — типы результатов диагностики и проверка listeners

Встроенный в typecheck/build checker теперь использует TypeScript program:
для каждого из 157 реальных listeners (включая локальные registration wrappers)
сравнивает awaited return с методом ElectronAPI. Несовместимые вложенные поля,
nullable branches и any внутри результата при конкретном public type приводят
к ошибке с именем канала. Неразрешённая сигнатура или непроверенный канал также
не считаются успехом. Отдельно учитываются legacy public types с any, включая
вложенные поля, массивы, словари и aliases: их остаётся 37, поэтому полный
AT-00-001 и WP-0 пока не объявлены PASS.

14 public methods диагностики и логов получили конкретные результаты:
proxy detection, adaptive status/retry/reset, leak/system checks, routing plan,
full logs, renderer logging/clear, URL availability/history и speed test/history.
Чистые типы собраны в shared/diagnostics.ts; main сохраняет type-only reexports,
renderer использует те же определения вместо независимых копий. SpeedTestResult
уже находился в shared и переиспользован.

Проверка обнаружила четыре случая расширения true в boolean; as const сохраняет
реальное значение без изменения runtime. Ещё шесть обработчиков могли вернуть
объект в error вместо обещанной строки: notifications reset/open, group health
и три file exports. Преобразование в строку и функциональные негативные тесты
с нестроковым message фиксируют контракт; обычные строковые сообщения сохранены.
Это не закрывает оставшуюся задачу canonical domain failures: legacy business
results и их тексты ещё требуют отдельного аудита. Результаты команд и CI/review
фиксируются в progress.md; нормативные docs/ не менялись.

## AT-00-001 — результаты остальных сервисов

Ещё 28 public result contracts используют конкретные pure types:
network maintenance (baseline/firewall/adapters/DNS), browser hardening/location,
AutoPilot, rule-sets, autoconfig, traffic history/forensics, server probe,
пять split-tunnel methods и пять group methods. Существующие модели
SplitTunnelApp/Config и ServerGroup переиспользованы; RefreshGroupResult
переехал в shared. У nullable splitTunnelAddApp и serverProbe сохранён null.
Blocked/skipped branches ремонта включены в публичный тип.

Типы network.ts и traffic.ts не имеют runtime dependencies. Старые main imports
совместимы через type-only reexports. Server probe использует существующий AsnInfo
из shared, остальные probe types добавлены в diagnostics.ts. UI-копии заменены
shared types; локальный AutoconfigTarget дополняет transport type только UI-флагом
enabled, который main не обещает возвращать.

Read-only проверка transpilation сравнивает исполняемые токены 22 изменённых
production-модулей с HEAD при одинаковых переводах строк: идентичны. Новые shared
modules испускают только пустой export. Это подтверждает границу type-only change,
а не заменяет unit/native tests. Source regression для protectedTunnelActive
проверяет новую shared declaration и её импорт, сохраняя прежние проверки label.

В inventory остаются 9 profile results с any; AT-00-001 не объявлен PASS.
Canonical domain failures, интегрированный FSM, cancellation/deadline,
correlation/history, migrations, flags и race/UI матрицы остаются в WP-0.
Команды, фактические результаты полного прогона и CI/review — в progress.md.

## AT-00-001 — оставшиеся profile results

На ветке codex/wp0-profile-results поверх открытого #54 все 9 оставшихся
methods используют ServerProfile: list/get-active/ping-all/resolve-ips,
verify-active-country/verify-country, add/add-to-group и set-client-device.
Nullable active profile и discriminated country results сохранены.
ServerProfile.outbound использует общий рекурсивный IpcJsonValue вместо any;
тип допускает JSON-расширения протоколов и не является заменой protocol validator.
Определение JSON переехало из settings.ts в shared/json.ts с совместимым reexport.

Доступ к вложенным TLS/Reality/ECH/uTLS/ALPN полям уточняет контейнер и тип
значения. asJsonObject проверяет только внешний контейнер; функция не обещает
полную валидацию его полей. Массив reality:[] не считается camouflage:
describeProbeTarget сохраняет tlsLeaksSni:true вместо ошибочного false.
Production call sites describeProbeTarget/tlsLeaksSni не найдены: текущий
checkProfileHealth использует checkOutboundHealth и полный outbound, поэтому
исправление классификатора не заявляется устранением активной SNI-утечки.
Реальные прежние pickServerName/describeProbeTarget извлечены
из parent и текущего файла без I/O: baseline false, исправленный true; три
корректных случая Reality/disabled/absent совпадают. Это локальная регрессия,
а не packet oracle или лабораторная приёмка сетевой изоляции.

Functional tests сохраняют корректные badges и handshake evidence, не считают
array TLS/Reality/OBFS валидными объектами и не возвращают numeric/object-valued
transport или ALPN. Настоящие picker handlers сохраняют вложенные JSON extensions
в list/get-active. Native production preload/contextBridge отдельно проверяет
неизменённый JSON ответа и null у active profile; service I/O в этом smoke
заменён fixture handlers. Эти доказательства не смешиваются.

Typecheck проверяет 157 listeners и 0 legacy any. Contract regression требует
пустой legacy inventory, поэтому возврат публичного any обнаруживается. Полный
набор тестов, CI и review записываются в progress.md; оставшиеся 9 AT WP-0,
canonical domain failures и весь WP-2 не объявлены завершёнными.


## AT-00-004 — доменные ошибки конфигурации

Config export/import/apply больше не возвращают raw business error внутри
успешного transport envelope. Handler бросает исходную ошибку для общей
классификации либо IpcFault с явной категорией; boundary возвращает стабильные
IPC_* code, category, canonical message и correlationId. Shared ElectronAPI
описывает только успешные results. ImportExportSettings обрабатывает canonical
rejection; raw/поддельный message заменяется generic internal, отмена save
остаётся без уведомления об успехе/ошибке. Browse cancellation сохраняет null.

configIpcErrors.test.ts использует настоящие feature handlers и production
installTrustedIpcBoundary. Ошибки всех семи категорий внедряются на store.get
и native-dialog boundary, проверяя отсутствие FAKE-SECRET, stack и абсолютных
Windows paths в ошибках renderer. Electron/dialog/store mocked; выбранный JSON
и файловая логика настоящие. Дополнительно проверяются malformed JSON/version,
array object sections, отсутствующая selection capability, cancelled save,
partial import и rollback после ошибки поздней записи. Capability после apply
расходуется даже при ошибке. Откат сохраняет system DNS (null), вместо выбора
первого builtin профиля. Пустой/неизвестный/отсутствующий выбранный раздел не
вызывает запись. Полная валидация содержимого каждого раздела этим изменением
не заявляется; проверки контейнеров не заменяют nested schema validation.

Компонентные тесты проверяют canonical ошибки на export/browse/import/apply,
локализованный fallback, отсутствие успеха после ошибок/отмены, выбор режима
экспорта, pending state и успешный apply. Имеющиеся security tests сохраняют
проверки native consent, sender authority, snapshot bytes, expiry и single-use.

Это адресная матрица четырёх каналов. AT-00-004 требует semantic error matrix
остальных privileged features; общий guard и native contextBridge fixtures
не заменяют её. FSM/coordinator, cancellation/deadline, correlation/history,
migrations, flags и race/UI остаются в работе. Команды и CI — в progress.md.


### Qodo #55 — импорт должен сохранять profile result contract

Qodo 6251403696 подтвердил сквозную дыру: typed ServerProfile[] не мешает
config import записать profiles:[null]. Новый regression вызывает настоящий
selected-file import/apply и проверяет отказ до записи и неизменность прежних
профилей. validateImportData проверяет поля ServerProfile, включая required
strings, numeric port, status и типы известных optional metadata. Профиль без
outbound поддерживается для backward compatibility; вложенные JSON extensions
сохраняются. Это validation входного config, а не полная protocol semantics
или отдельная приёмка уже повреждённых исторических stores. Результаты в progress.md.
