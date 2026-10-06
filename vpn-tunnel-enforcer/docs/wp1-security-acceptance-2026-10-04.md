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
- Runtime (уточнён после ревью PR #21): privileged execution перенесён в `%ProgramData%\VPNTE\runtime\<instance-hash>\`; свежая owner/ACL/reparse-проверка охватывает всё дерево и всех предков до volume root. Проверяются эффективные права удаления/подмены namespace, InheritOnly ACE и owner implicit WRITE_DAC. Даже существующий runtime требует сверки ProgramData с Windows known folder. Bootstrap атомарно создаёт только отсутствующие application-компоненты с защищённым DACL; существующие небезопасные каталоги не исправляются/не получают доверие автоматически. Успешный прошлый результат не кешируется. ACL cmdlets загружаются из manifest под `$PSHOME`, а не из унаследованного PS7 `PSModulePath`.
- Staging проверяет SHA-256 относительно bundled-источника, дескрипторы/идентичность файлов и компоненты пути; неподтверждённые файлы не допускаются к запуску. Публикация через проверенный временный файл и rename. Это не независимая подпись bundled-источника и не handle-level доказательство отсутствия всех Windows TOCTOU.

Основная трассировка: AT-01-001…011; F-001/004/005/006/038/055/130/132/139…145/158/206; AC-SET-CFG-001…003 и AC-SRV-EXP-001…003. Статусы отдельных F не объявляются закрытыми этим списком.

## Выполненные команды исходного коммита `333adad`

Результаты повторной проверки после ревью приведены в конце отчёта.

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
| AT-01-009 | Fresh tree + parent namespace ACL contract, staging/hash/path regressions; native read-only known-folder и policy predicates; реальный user-owned namespace отказан с типизированным маркером security refusal и независимым owner read-back | Elevation/Everyone:Write/tampered binary и concurrent OS abuse matrix не запускались; нет VM |
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

## Исправления ревью PR #21 и повторная проверка

### Runtime namespace

Замечание `discussion_r4177564146` подтверждено: защищённый DACL дочернего runtime не исключал его rename/replace через родителя. Исправление использует разрешённый томом 1 §1.3 ProgramData runtime и защищает namespace, а не выдаёт повторный pathname-check за устранение TOCTOU.

- Единый getter разделяет пользователей/instances по SHA-256 нормализованного userData path. TUN/Xray, external proxy, forensics scripts, firewall allow-list, PID/getter consumers и log/diagnostic readers используют согласованные пути.
- Parent-before-child проверка охватывает owner, reparse/type и эффективные DELETE_CHILD/DELETE/WRITE_DAC/WRITE_OWNER/GENERIC_ALL. Системные предки допускают SYSTEM/Admins/TrustedInstaller. Право создать соседний объект не равно праву заменить существующий защищённый child; InheritOnly проверяется отдельно. Runtime-права проверяются численно, включая generic write/all; наследуемые write-гранты для будущих artifacts тоже запрещены.
- Bootstrap сначала подтверждает known folder и системную цепочку, затем создаёт только отсутствующие VPNTE/runtime/instance/leaf компоненты через `DirectoryInfo.Create(DirectorySecurity)` с owner Administrators и protected DACL. Существующие недоверенные компоненты/contents не «лечатся» через Set-Acl/icacls. Это исключает перенос доверия на заранее открытые user-writable artifacts.
- Diagnostic runtime `version` не запускается до ACL proof. Форензика теперь действительно fail-closed (раньше ACL failure только логировался); sessionDir/etlPath не могут указывать на старый root или произвольную директорию.
- AppData и системные ancestor ACL не изменяются. Старые runtime/forensics каталоги не читаются как execution source, не копируются и не удаляются автоматически. Перед обновлением следует штатно остановить старый клиент; миграция его процессов/сессий и installed-upgrade oracle не реализованы.

### Остальные замечания

Preload экспорт проверяет `redacted | secrets` до IPC. Startup logs используют только фиксированный code/type без exception message/stack, обычные Error получают post-redaction size limit. Quit guard вынесен в тестируемый helper без `new Function`, graceful Chromium key flush сохранён. Runner cleanup сохраняет primary error и cleanup error (AggregateError), cleanup failure завершает run nonzero, общий PASS печатается после очистки. Broad secret-key redaction намеренно не ослаблена: `id` может быть credential; application ID/FK уже имеют отдельную context-aware export policy.

### Фактические результаты повторного прогона

| Проверка | Результат |
| --- | --- |
| `npm run typecheck`, `npm run build` | exit 0; существующие bundler warnings о mixed imports |
| `npm test -- --maxWorkers=4 --reporter=dot` | exit 0; **203 files passed / 2 skipped; 2439 passed / 10 skipped / 0 failed**; 99.45 s |
| Runtime ACL/path + systemDiagnostics + trafficForensics focused suites | **123/123 PASS**; отдельные hostile session paths **4/4 PASS** |
| `node --test scripts/wp1-test-cleanup.test.mjs` | **10/10 PASS** |
| Native PowerShell tests внутри runtimeDirSecurity suite | Actual inspection/bootstrap AST parse, real read-only system namespace, real numeric policy predicates, forged ProgramData refusal — PASS; никаких elevated writes |
| `node scripts/test-electron-runtime.mjs` | 8 checks PASS, Electron 44.4.3 |
| `node scripts/test-wp1-native.mjs` | 6 local subsets PASS; production runtime getter заменён явно объявленным isolated userData shim **только для L2 ZIP fixture**, не для native ACL helper |
| `node scripts/test-wp1-migration.mjs --same-version` | seed44/fail44/migrate44/unavailable44/restart44 PASS; 42→44 NOT-CHECKED |
| Traceability checker | exit 0; AC927/927, F210/210 |

Промежуточный default-worker full run: два существующих bundled-core preflight теста превысили 5 s. Изолированный повтор — 85/85 PASS; полный повтор с четырьмя workers — PASS без изменения таймаутов. Cleanup проверен после native/migration run, не только по дочернему PASS marker.

Полный 15.5M envelope fuzz повторно не запускался: main envelope/schema/redactor contract не менялся; новый preload enum покрыт focused/full regression. **Это не полный AT-01-009/L3 PASS:** elevated ProgramData bootstrap/launch, concurrent OS ACL abuse, VM/installed/OS matrix по-прежнему NOT-CHECKED. Clipboard и действующая сеть не трогались; ограничения настоящего 42→44 и старого rollback reader сохраняются.

## Второй проход ревью: очистка логов и provider stop

Подтверждены `discussion_r4177892597` (unsafe runtime mkdir при очистке логов), `discussion_r4177892600` (developer path в fixtures) и архитектурная находка CodeRabbit о ложном `running=false` после отказа ACL/ошибки stop.

- `clearAppLog` не создаёт runtime namespace. Существующие TUN logs изменяются только после проверки ACL; отказ не отравляет следующую операцию в очереди. Регрессии AT-01-009/F-005/F-006: missing namespace, existing logs, hostile namespace и повтор очистки.
- Форензические fixtures, staging и sidecar находятся в уникальном `mkdtemp(os.tmpdir())`, удаляемом после suite; production ProgramData и чужие профили не используются.
- Mandatory provider stop отделён от best-effort diagnostics: фиксированный системный `pktmon.exe` / `netsh.exe`, обязательный native exit=0 и stdout acknowledgement. Ошибка, timeout или отсутствие acknowledgement сохраняют `running=true`, `stoppedAt=null`, `CaptureStopUnconfirmed` и возможность повторить stop; restart/удаление artifacts не могут игнорировать этот отказ. Concurrent stops объединяются.
- При отказе runtime ACL только capture, успешно запущенный текущим процессом, получает path-free EncodedCommand cleanup без чтения/записи/исполнения runtime scripts. Disk manifest не даёт такого полномочия. При подтверждённой остановке и отказе persistence сохраняется отдельный `CaptureStoppedArtifactsUnavailable`, а не ложная ошибка провайдера.
- Manifest persistence больше не меняет память до ACL/layout/write proof и не подавляет ошибки JSON I/O. Успешный старт регистрирует in-memory ownership до artifact finalization; последующая ошибка persistence не запускает второй provider поверх первого.
- Stop artifacts и выход сайдкара больше не переводят packet provider в stopped (F-198). UI показывает `cleanupPending` и ошибку запроса статуса как «ОСТАНОВКА НЕ ПОДТВЕРЖДЕНА», в том числе при выключенной настройке capture.
- Старый AppData manifest читается только как ограниченный 64 KiB недоверенный hint. Running/повреждённый/нечитаемый marker означает warning и отказ нового capture; чужие пути/PID не импортируются, legacy scripts не выполняются, старые данные не переписываются. **Это не OS ownership proof и не полноценный installer handoff:** legacy file может быть подделан или удалён; автоматический reclaim глобального pktmon по нему небезопасен. Контролируемый shutdown/прерванный installed upgrade остаётся отдельной задачей WP-11, не объявляется исправленным/принятым.
- Предложение `discussion_r4177863955` о `SuppressedError` не принято: helper намеренно агрегирует две самостоятельные ошибки, сохраняет primary как cause и проверен 10 Node-тестами. Это не потеря исходной ошибки.

### Проверки актуального исходника

- `npm run typecheck`, production build, `npm run dist:win`: exit 0.
- Финальный `npm test -- --maxWorkers=4 --reporter=dot`: **206 files passed / 2 skipped; 2459 passed / 10 skipped / 0 failed**, 98.86 s. Предыдущий промежуточный полный прогон тоже зелёный: 2458 passed до добавления UI status-failure regression.
- Focused capture/log/security/UI suite: 67/67 PASS до последнего UI regression; все новые тесты входят в финальный full run. `node --test scripts/wp1-test-cleanup.test.mjs`: 10/10 PASS.
- Native PowerShell проверяет настоящий exit/acknowledgement control flow для обоих провайдеров, но сами provider calls заранее заменены безвредными scriptblocks. Реальный pktmon/netsh stop, elevated writes и действующий VPN не запускались.
- Traceability: AC927/927, F210/210, exit 0; полнота ссылок, не исполнение всех AT.
- NSIS EXE 1.1.22 пересобран, **NotSigned**, не устанавливался. SHA-256: `AEEA3D7D04098422D50C72F72100C6C7D9CAC6F08DD08CE6831BE374ED177EC6`. Упакованные main/preload/renderer index совпадают с `out/` по SHA-256; main содержит новые stop/legacy markers. `dist/checksums.txt` обновлён для installer и blockmap.

AT-08-004/005 и AT-01-009 имеют новые L1/L2 регрессии, **не полный L3 PASS**. Native live-capture/OS matrix, installed-upgrade, VM, cross-version 42→44 и rollback-reader остаются NOT-CHECKED. Нормативные `docs/` не изменены.

## Третий проход ревью: гонка переходов и предупреждения

- Гонка stop/start воспроизведена до исправления: оба новых regression cases запускали новый provider до окончания старой finalization (ожидался 1 native call, получено 2). Общая небольшая promise-очередь теперь охватывает start/stop/restart и staging вместе с записью manifest; внутренние restart/zombie recovery не ждут собственную очередь. Последующий stop не теряется за предыдущим stop.
- Sidecar callbacks проверяют принадлежность текущему child/session; поздние error/exit старого child не заменяют новую сессию. Отложенная запись наблюдения sidecar объединяется с текущим provider state. Status reconciliation не изменяет runtimeState из устаревшего снимка.
- `discussion_r4178028247`: legacy `running:false` с ошибкой, без положительного stoppedAt, с активным sidecar или ложным reconciliation reason остаётся pending. Legacy marker по-прежнему только недоверенный hint; scripts/PID/paths не импортируются, данные не меняются, полноценный installer handoff не заявляется.
- `discussion_r4178041325`: running manifest без in-memory ownership текущего процесса означает cleanupPending независимо от startedAt (прошлое/отсутствует/будущее). Работающий capture текущего процесса без sidecar не получает ложное предупреждение.
- `discussion_r4178028250`: новые warnings и затронутый status block используют совпадающие RU/EN ключи и `useTranslation`; legacy backend marker отображается локализованно. UI regressions используют настоящий i18next, включая смену языка без перемонтирования.
- Production delta: +57 строк net, включая 24 строки locale JSON; без новых зависимостей/классов/менеджеров. Добавлено 17 regression cases.
- `npm run typecheck`, `npm run build`, `npm run dist:win`: exit 0. Focused capture/security/UI: **59/59 PASS**. Full `npm test -- --maxWorkers=4 --reporter=dot`: **206 files passed / 2 skipped; 2476 passed / 10 skipped / 0 failed**, 109.40 s. Traceability: AC927/927, F210/210, exit 0 (покрытие ссылками, не исполнение всех AT).
- Пересобран NSIS installer 1.1.22: **139180033 bytes, NotSigned**, без установки. SHA-256: `7C42C3F6F08F12B827C4C64BD429FF25A2CCFA4DEAA0FF8DE4FFC3DD15BA8DD4`. 40 packaged main/preload/renderer files совпали с out по SHA-256; новые queue/legacy и RU/EN markers присутствуют. `dist/checksums.txt` обновлён для EXE/blockmap.

Проверки выполнялись на изолированных fixtures с mocked capture providers. Реальный elevated capture, установленный клиент, VPN/Firewall/DNS/clipboard не изменялись; VM отсутствует и не запускалась. Ранее перечисленные L3/upgrade/42→44/rollback ограничения сохраняются, полный WP-1 PASS не заявляется.

## Согласованный follow-up WP-8 / WP-11: дождаться очистки перед выходом и обновлением

Владелец отдельно поручил реализовать второй retained concern — controlled shutdown; совместимость старого reader/откат (первый concern) не расширялись. Соответствие: Том 2 §7.1, AT-11-002/009, F-183; capture boundary — AT-08-005/F-198.

- Main shutdown теперь дожидается `stopTrafficForensicsSession`, включая queued start/stop и manifest finalization, до отключения helper и `app.exit`. Running/cleanupPending/ошибка блокируют выход. Проверяются receipts сетевых backstops и env rollback; остальные cleanup steps продолжаются после отказа. При неполной очистке helpers сохраняются для повторной попытки, возвращается локализованное RU/EN предупреждение и допускается повторный «Выход». Manual capture restart во время выхода запрещён.
- Добавлен фиксированный `--shutdown-for-update` через существующий Electron single-instance IPC: живой primary вызывает штатный quit; вторичный процесс не выполняет recovery, а probe без primary завершается без запуска VPN. Только подтверждённый shutdown по этому запросу возвращает код **73**, обычный выход остаётся 0.
- NSIS customInit/customUnInit и override customCheckAppRunning заменяют прежние image-name `taskkill` и default builder force-kill. Helper связывает ожидание с открытым handle исходного primary, проверяет точный executable path, ждёт специальный exit code и освобождение VPNTE processes. Exit 0, crash, timeout, недоступная identity/query и остаточные процессы не считаются подтверждением. Операция прекращается до замены/удаления файлов, а не добивает приложение.
- PowerShell helper встраивается при сборке как immutable EncodedCommand, не исполняется из подменяемого temp-file. InstallDir передаётся как literal process environment, не вставляется в PowerShell source. Generated Base64 ограничен command budget и исключён из Git; новых зависимостей/менеджеров нет.
- **Первый переход:** старые EXE не умеют новый shutdown request — их следует заранее штатно закрыть. Helper не заставляет их завершиться и не объявляет отсутствие процесса доказательством очистки осиротевшего kernel capture. Уже убитые legacy sessions/installed interrupted-upgrade и старая версия chained uninstaller остаются отдельными границами, не заявлены автоматически восстановленными. Посторонние/остаточные VPNTE image names консервативно блокируют setup, но никогда не используются как полномочие kill.
- Добавлено **24 regression cases**: ожидание finalization, pending/reject, неполные network/env receipts, request routing, обычный/installer exit, failure/retry, native refusal matrix и настоящий handle к безвредному PowerShell child с exit 0/73. Focused shutdown/lifecycle **99/99 PASS** до финального source-contract уточнения; все входят в финальный full run.
- Финальные `npm run typecheck`/production build/`npm run dist:win`: exit 0; **207 files passed / 2 skipped; 2500 passed / 10 skipped / 0 failed**, 115.64 s. Traceability AC927/927, F210/210, exit 0. Первый NSIS прогон отказал из-за неполного LangString в таблице языков; исправлен RU/EN fallback без подавления compiler warnings. Отдельно проверены точное соответствие embedded command исходнику и его PowerShell AST syntax.
- EXE 1.1.22 пересобран: **139180341 bytes, NotSigned**, не установлен. SHA-256 `F08247EA9B97B6651EE6A19AC62E0391F1607D83D8DDD41010380025B07C1F4B`; 40 packaged main/preload/renderer files совпадают с out, новые shutdown markers присутствуют. `dist/checksums.txt` обновлён для EXE/blockmap.

**Предел доказательства:** native tests не завершают установленный VPNTE и не трогают реальные capture/Firewall/DNS/clipboard. NSIS сборка и L1/L2 control-flow не заменяют AT-11-002/AT-08-005 L3. VM отсутствует и не запускалась; полный installed active-upgrade/uninstall/OS matrix, прошлые legacy orphan sessions и credential rollback остаются NOT-CHECKED. Нормативные docs не изменялись.

## Follow-up ревью be104c1: не подтверждать неизвестный результат shutdown

Трассировка: AT-11-002/F-183, Том 2 §7.1. Исправлены оба actionable замечания CodeRabbit без расширения credential rollback или legacy capture recovery:

- `performShutdownCleanup` отклоняет `{success:false}` и неполный `killed/candidates` от owned-runtime stop, а не только исключения. Независимые cleanup steps продолжаются; при отказе helpers остаются для retry и before-quit не выдаёт installer acknowledgement 73.
- Shutdown вызывает строгий `autoconfig.isApplied('env')`, не UI `getStatus()` с fallback. Ошибка доступа, timeout и непарсируемый registry stdout остаются неизвестным состоянием и блокируют shutdown; backup не удаляется, blind rollback не запускается. Только распознанный missing-value error с exit 1 без termination indicators подтверждает отсутствие. Общий parser также прерывает backup preparation до apply при неполном чтении. UI контракт не менялся.
- Nitpick Revix закрыт переносом 10 harmless native cases в `.itest.ts` и opt-in `npm run test:installer-shutdown`; обычный unit glob исключает их. Добавлены 35 regression cases с mocked registry/targets/runtime; ни реальный клиент, ни registry не менялись.
- Typecheck/build/dist:win exit 0; focused **134/134**, integration **10/10**; full **208 files passed / 2 skipped; 2525 passed / 10 skipped / 0 failed**, 90.36 s. AC927/927, F210/210 exit 0. Промежуточная syntax error при правке Vitest config исправлена до финального полного прогона.
- EXE 1.1.22: **139180693 bytes, NotSigned**, SHA-256 `D157455011C95E1580DFA4E6FCF260330746E09AD78EB74228C7E0423909B70F`. Все **185 файлов out/** сверены с packaged ASAR по SHA-256, strict shutdown markers присутствуют; `dist/checksums.txt` обновлён для EXE/blockmap. Не устанавливался и не публиковался как release.

VM отсутствует, live VPN/Firewall/DNS/capture/registry не трогались. Этот L1/L2 follow-up не заменяет installed upgrade/uninstall AT-11-002 L3; ранее перечисленные legacy/rollback/OS ограничения сохраняются. Нормативные docs не менялись.

## Финальный согласованный follow-up c2c5342: env ownership и настоящий residual deadline

Трассировка: AT-11-002/F-183, Том 2 §7.1. Владелец поручил закрыть текущие два замечания и закончить без нового цикла запросов ревью.

- `env.isApplied()` теперь проверяет валидный VPNTE backup как recovery obligation, а не наличие чужого HTTP_PROXY. Без backup и без ранее наблюдавшегося текущим процессом обязательства возвращает false, не выполняя registry commands; чужие настройки не мешают shutdown и не изменяются. Повреждённый/недоступный receipt остаётся неизвестным; исчезнувший known receipt отклоняется и не заменяется snapshot текущих изменённых значений.
- Pending obligation сохраняется до подтверждённого rollback всех четырёх переменных и успешного удаления receipt. Восстановление HTTP_PROXY не скрывает остаток HTTPS_PROXY/ALL_PROXY/NO_PROXY. Rollback не записывает уже восстановленные значения или значения с неизвестным текущим состоянием; после set/delete проверяет readback, продолжает независимые entries при отказе и сохраняет backup/flag для retry. Production delta +21 строк net, без новых зависимостей/схем/менеджеров.
- `installerShutdown.itest.ts` оставляет настоящий Start-Sleep: remaining scenario достигает production 5s deadline и проверяет `VPNTE background processes remain; update refused.`, а не ошибку мока. Добавлен released-after-polls success, проверяются число polls, причины отказа и handle disposal.
- `npm run typecheck`/production build/`npm run dist:win` exit 0; focused **181/181**, `npm run test:installer-shutdown` **11/11**; full **208 files passed / 2 skipped; 2572 passed / 10 skipped / 0 failed**, 105.66 s. AC927/927, F210/210 exit 0. Registry/FS — in-memory fixtures; native tests используют только harmless children и подставные процессы.
- EXE 1.1.22 пересобран: **139180562 bytes, NotSigned**, SHA-256 `721C1083EE77336116F35A6DB2D679738FA51B1C604F65DEBD278546C711947C`. Все 185 файлов out/ совпали с packaged ASAR по SHA-256; readback/shutdown markers присутствуют; `dist/checksums.txt` обновлён для EXE/blockmap. Установка и Release upload не выполнялись.

**Границы:** backup используется как существующая recovery metadata, не как новый защищённый ownership store. Потерянный между процессами receipt не восстанавливается in-memory флагом; автоматическое восстановление таких/legacy состояний не добавлялось. VM отсутствует и не запускалась; live VPN/Firewall/DNS/capture/registry не изменялись. Installed active-upgrade/uninstall L3, OS matrix, настоящий 42→44, credential downgrade и legacy capture recovery сохраняют предыдущие NOT-CHECKED/retained ограничения. Полный WP-1/L3 PASS не заявляется, нормативные docs не менялись.

## Follow-up 2026-10-06, b776fdc: сохранять env cleanup после перезапуска

Исправлено `discussion_r4186342978`, трассировка AT-11-002/F-183 и AT-03-007. Отдельный пустой `env-proxy-backup.json.pending` создаётся эксклюзивно до изменения переменных; существующий backup также получает маркер. Он удаляется последним, после readback всех четырёх переменных и удаления backup. Потеря backup при наличии маркера после перезапуска остаётся неизвестным состоянием: shutdown не подтверждается, повторный apply не подменяет исходные настройки новым snapshot. Ошибки доступа/записи/удаления не скрываются. Без обоих файлов и process-local obligation чужие proxy values по-прежнему не считаются своими.

Production delta: **+10 строк net**, без зависимостей и изменения схемы backup. Добавлено 11 regression cases; существующие сценарии потери backup теперь также перезагружают модуль, проверяя границу процесса. До патча env suite: 17 failed / 71 passed; после исправления focused suite: 186/186 PASS.

Проверки из `vpn-tunnel-enforcer/`:

- `npx.cmd vitest run src/main/autoconfig/env.test.ts src/main/autoconfig/index.test.ts src/main/lifecycleCleanup.test.ts --maxWorkers=2 --reporter=dot`: 186/186 PASS, 3 файла, exit 0.
- `npm.cmd test -- --maxWorkers=2 --reporter=dot --reporter=json --outputFile=.tmp/pr21-env-recovery-tests-20261006-verified.json`: **208 files passed / 2 skipped; 2597 passed / 10 skipped / 0 failed**, 236.78 s, exit 0.
- `npm.cmd run typecheck` и `npm.cmd run build`: exit 0; build сохранил предупреждения Vite о mixed static/dynamic imports и размере renderer chunk.
- `node --test scripts/wp1-test-cleanup.test.mjs`: 10/10 PASS, exit 0.
- `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py`: AC927/927, F210/210, exit 0; это полнота ссылок, не исполнение всех AT.

Первый full run из чистого worktree: 2589 passed / 14 skipped / 4 failed, 219.58 s. Все четыре отказа — отсутствие ignored bundled Xray/sing-box ресурсов в worktree (ENOENT); production код для них не менялся. Локальные ресурсы подключены hard links без дублирования бинарников на диске.

**Границы текущего исправления:** маркер сохраняет обязанность очистки, но не восстанавливает потерянные исходные значения. Одновременная потеря backup и маркера, а также уже потерянный legacy backup до обновления автоматически не определяются. Реальный registry/VPN и установленный клиент не изменялись, NSIS installer в этом проходе не пересобирался и не устанавливался; прежние L3/OS/upgrade ограничения сохраняются. Suggestions о новом runtime-ACL policy и замене `AggregateError` не включены в этот env fix; обе ошибки cleanup helper по-прежнему сохраняются и проверены 10 Node-тестами. Нормативные `docs/` не менялись, новых Markdown-файлов нет.

### Следующий follow-up: сохранить retry при отказе удаления metadata

Замечание `discussion_r4197671244` подтверждено: b776fdc удалял backup до маркера и при отказе второго удаления терял возможность retry. Порядок двух удалений исправлен: после verified readback сначала удаляется маркер, затем backup. Отказ первого удаления сохраняет оба файла; отказ второго оставляет backup, из которого после перезапуска заново создаётся маркер. Регрессии проверяют обе ошибки и успешный retry без повторных изменений registry. Production delta этого follow-up — 0 строк net.

- Повторный focused запуск той же команды: **186/186 PASS**, 3 файла, 10.68 s, exit 0.
- Повторный `npm.cmd run build` (включая typecheck) и traceability той же командой: exit 0, AC927/927, F210/210.
- Финальный `npm.cmd test -- --maxWorkers=2 --reporter=dot --reporter=json --outputFile=.tmp/pr21-env-retirement-tests-20261006.json`: **208 files passed / 2 skipped; 2597 passed / 10 skipped / 0 failed**, 201.01 s, exit 0. Прежние ограничения native/L3 и installer сохраняются.
