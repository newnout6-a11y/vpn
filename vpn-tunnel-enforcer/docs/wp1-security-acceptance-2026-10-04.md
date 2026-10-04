# WP-1: локальные проверки доверенной границы — 04.10.2026

## Объём и вердикт

Продолжены незакоммиченные изменения после `7da36fb` (PR #20). Пакет включает защиту секретов, default-redacted экспорт, доверенную IPC-границу, CSP, проверку runtime и приёмочные стенды.

**Вердикт: доступные локальные проверки PASS; полный WP-1 остаётся частично проверенным.** VM отсутствует по сообщению владельца; VM-сценарии не запускались. Этот отчёт фиксирует измерения и ограничения, не изменяет нормативные документы `docs/` и не закрывает все AT по наличию unit-тестов.

Среда: Windows x64, Node.js 24.12.0, npm 11.8.0, Python 3.14.3, Electron 44.4.3 (встроенный Node.js 24.21.0), Vitest 4.1.11. Все native-фикстуры работают с отдельными временными `userData`/`sessionData` и синтетическими секретами. Действующий VPN, установленные приложения, Firewall/DNS/IPv6, login items и системный clipboard не менялись. Собственные временные каталоги удаляются после каждого прогона.

## Реализация

- Новые SecretRef используют `enc:dpapi:v1:`, legacy raw-base64 продолжает читаться. Settings/server-picker используют `schemaVersion: 2`; auth в `proxyOverride` и adaptive installation secret не записываются plaintext. Миграция готовит и проверяет расшифровку до commit; backup-шаги имеют безопасный аудит.
- Settings, profiles и groups открываются до startup recovery/автоматизации. При отказе безопасного хранилища приложение показывает ошибку и завершает запуск **без обычного сетевого shutdown**. Завершение graceful: Chromium должен сохранить Local State ключа шифрования после уже выполненной миграции.
- Экспорт конфигурации по умолчанию маскирует секреты и неизвестные поля. Полный экспорт — отдельный режим через main-owned native consent. ID/FK приложения сохраняются; ID внутри outbound не считается безопасным полем. Renderer получает результат/путь, не файл с секретами.
- IPC: типизированный `IpcValidationError`, ограниченные audit-события с correlation ID, без отвергнутых payload/URL. Production CSP — явный список источников; OSM iframe sandboxed, packaged DevTools выключены. Обоснованные исключения CSP: inline styles для темы/motion, browser-egress ipify/myip и sandboxed OSM frame.
- Runtime: fresh owner/ACL/reparse inspection всего существующего дерева; успешный прошлый результат не кешируется между операциями. Hardening не использует recursive traversal через junction; children требуют проверки owner и прав. ACL cmdlets загружаются из manifest под `$PSHOME`, а не из унаследованного PS7 `PSModulePath`.
- Staging проверяет SHA-256 относительно bundled-источника, дескрипторы/идентичность файлов и компоненты пути; неподтверждённые файлы не допускаются к запуску. Публикация через проверенный временный файл и rename. Это не независимая подпись bundled-источника и не handle-level доказательство отсутствия всех Windows TOCTOU.

Основная трассировка: AT-01-001…011; F-001/004/005/006/038/055/130/132/139…145/158/206; AC-SET-CFG-001…003 и AC-SRV-EXP-001…003. Статусы отдельных F не объявляются закрытыми этим списком.

## Выполненные команды

Команды ниже выполняются из `vpn-tunnel-enforcer/`, если не указано иначе.

| Команда | Фактический результат |
| --- | --- |
| `npm run typecheck` | exit 0, повторён после финальных runtime/startup правок |
| `npm test -- --maxWorkers=4` | exit 0; **200 файлов passed / 2 skipped; 2397 тестов passed / 10 skipped / 0 failed**; 108.44 s |
| `npm run build` | exit 0; main/preload/renderer production bundles; предупреждения о смешанных static/dynamic imports, без ошибок |
| `node scripts/test-electron-runtime.mjs` | exit 0; 8 native smoke checks: DPAPI persistence, preload/contextBridge, reload, sandbox, IPC и dev-loopback |
| `node scripts/test-wp1-native.mjs` после build | exit 0; 6 локальных подмножеств; native clipboard/VM/full installed scan явно NOT-CHECKED |
| `npm run test:wp1:migration:local` | exit 0; seed44 → injected failure → migration → unavailable storage → restart; финальный исправленный сценарий повторён **2/2** |
| `npm run test:wp1:fuzz` | exit 0; 2 файла / 5 тестов; 342.01 s; подробности ниже |
| `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` | exit 0; AC 927/927, F 210/210; проверяет связи требований с AT, не их PASS |
| `node scripts/test-wp1-migration.mjs` без Electron 42 | **exit 77, NOT-CHECKED**, а не PASS |
| `git diff --check` из корня | exit 0 |

### Бюджет IPC/redactor

Seed: 1004. Каждый из **155 preload-invokable каналов** проверен на **100 000** невалидных envelope-мутациях: **15 500 000 rejected**, **0 handler effects**, **15 500 000 timing observations**. Для каждой операции измеряется длительность; bounded histogram округляет вверх до миллисекунды. Общая и максимальная поканальная верхняя оценка p99 — **1 ms**, бюджет 50 ms соблюдён.

Семейства envelope: NaN/±Infinity, запрещённые ключи, слишком длинная строка, глубокая вложенность, нестандартный прототип; изменяются имя поля и sequence. Это **не** полноценный grammar/schema fuzz реальных обработчиков: handlers в стенде заменены счётчиком effects. Store snapshot и semantic payload oracle для каждого privileged handler этим прогоном не доказаны.

Каждый из трёх property-тестов redactor выполнен на **100 000** случаях: реалистичные base64-ключи/UUID/user paths, secret-bearing keys и VPN URI; сохранение проверенных clean values. Это не доказательство полного default-deny контракта всех полей глобальной телеметрии.

## Границы по AT

| AT | Что доказано локально | Что не засчитывается как PASS |
| --- | --- | --- |
| AT-01-001 | Реальные electron-store/DPAPI, failure injection, повторная миграция, restart и scan plaintext файлов/backup на Electron 44 | Настоящий 42→44: executable Electron 42 не задан; исходные данные seed44, не released-store matrix |
| AT-01-002 | Реальный Windows ZIP pipeline/файлы/логи, synthetic canary и positive scanner control | System diagnostics/manifest readers — объявленные L2 fixtures; нет полного VPN-цикла, VM и CIM argv scan |
| AT-01-003 | Native foreign WebContents, реальный hostile subframe, навигация entry point, zero effects stub handler и unit audit | Не вся матрица реальных production handlers/побочных эффектов; не installed OS matrix |
| AT-01-004 | 100k envelope-мутаций на каждый из 155 каналов, typed rejection, поканальный p99 | Semantic schema fuzz всех реальных handlers и неизменность их stores отдельно не доказаны |
| AT-01-005 | Реальный loopback HTTP transport + production Host guard: trusted IPv4/localhost доходят до token gate; external/decimal/IPv6/missing Host отклоняются | Не заявляется допуск всех локальных слушателей или успешная авторизованная мутация VPN |
| AT-01-006 | Настоящий Electron, CSP из собранного production meta: inline/eval/remote script/style/image блокируются | Не installed-сборка/OS matrix; inline styles — явное исключение политики. Local frame разрешён только в отдельной hostile-IPC fixture, не в CSP oracle |
| AT-01-007 | Production preload в изолированных native windows, безопасные preferences, dev-loopback smoke и source regressions | Это subsets, не вся матрица BrowserWindow/BrowserView установленной сборки |
| AT-01-008 | Default masking и opt-in consent покрыты main/renderer регрессиями; clipboard ownership/TTL — unit-тестами | Реальный clipboard **не трогался**, native 60s oracle NOT-CHECKED; интерактивный installed export отдельно не выполнен |
| AT-01-009 | Fresh tree ACL contract, staging/hash/path regressions; реальный user-owned каталог отказан с независимым owner read-back | Elevation/Everyone:Write/tampered binary и concurrent OS abuse matrix не запускались; нет VM |
| AT-01-010 | Native unavailable safeStorage: store bytes неизменны; unit отказ записи; startup-refusal guard не вызывает network cleanup | Не все системные account/DPAPI failure сценарии установленного клиента |
| AT-01-011 | 3 × 100k property cases, clean-value metamorphic checks, отдельный default-deny export | Полная schema/default-deny проверка каждого глобального logging/telemetry поля не заявляется |

## Промежуточные отказы и исправления

- Первый запуск нового fuzz launcher не нашёл неэкспортируемый `vitest/vitest.mjs`; CLI теперь определяется через экспортируемый package manifest и его `bin`.
- Усиленный независимый ACL oracle поймал ошибку загрузки Microsoft.PowerShell.Security: внешний `PSModulePath` содержал PS7 modules перед Windows PowerShell 5.1. Старое `hardened === false` могло принять ошибку reader за доказанный owner refusal. Исправлен pinned builtin import; итоговый native oracle требует owner/offenders и независимое чтение, после исправления PASS.
- Попытка `app.exit()` в межпроцессной миграционной fixture привела к ошибке расшифровки следующего процесса. Возвращён graceful `app.quit()` для сохранения Chromium Local State. Production startup refusal тоже graceful и отдельно ограждён от network cleanup; итоговый native сценарий 2/2 PASS.

## Запуск и совместимость

- `npm run test:wp1:native`: собирает текущий код и запускает локальные subsets **без clipboard**.
- `npm run test:wp1:migration:local`: изолированная same-version проверка, явно не 42→44.
- `npm run test:wp1:migration`: требует `VPNTE_ELECTRON42_EXE`; проверяет реальную major-version seed42, не допускает синтетический cross-version PASS.
- Native clipboard fixture доступна только явным `node scripts/test-wp1-native.mjs --clipboard` после build. В этой сессии не запускалась; изменяет общий clipboard на 61 секунду, поэтому не предназначена для фонового запуска на рабочем компьютере.

Новые секреты/backup имеют версионированный формат; текущий reader понимает legacy raw-base64. **Откат на прежний executable после записи нового prefix нельзя считать безопасным:** старый reader префикс не понимает. Нужна отдельно проверенная совместимость rollback-reader/миграции; не вручную менять ciphertext и не удалять защищённые backup.

Installer не пересобирался и не устанавливался; действующий клиент не менялся. Подпись кода не выбиралась, WP-12 не затрагивался. Нормативные `docs/` не редактировались.
