# VPN Tunnel Enforcer — рабочее пространство Rust

Исходники клиента 2.0.0 для Windows 10/11 x64 (состояние на 12.11.2026): Rust 2024 (rustc 1.99), интерфейс на
Dioxus 0.7.10 desktop в WebView2 в одном процессе с бэкендом, движки sing-box 1.14.4 и Xray 26.11.9 —
дочерние процессы. Без прав администратора работает режим «Прокси» (loopback-вход `mixed` + системный
прокси пользователя); «Туннель» (TUN Wintun) и WFP kill switch — только когда приложение запущено от имени
администратора. Поставка — установщик на пользователя и переносной zip. Обзор продукта — `../README.md`.

Прежний клиент на Electron/TypeScript (`src/`, `scripts/`, `native/`, `package.json` и др.) удалён; его
данные приложение один раз импортирует, а следы в системе убирает крейт `cleanup`.

## Что где

```
Cargo.toml          рабочее пространство: версии зависимостей, общие lints, профили сборки
.cargo/config.toml  статический CRT, алиас `cargo xtask`
crates/<имя>/       крейты `vpnte-<имя>`; у каждого API.md (публичный API) и progress/ (журналы пакетов)
crates/CONTRACT.md  общие решения и правила для всех крейтов
xtask/              сборка: закрепление движков, NSIS, dist, smoke-install
installer/          сценарий NSIS (на пользователя), шимы vpnte-proxy.cmd/.ps1, лицензии
resources/          engines.toml (закрепы SHA-256), наборы правил .srs; движки кладёт `cargo xtask engines`
docs/architecture/  устройство рабочего пространства и порядок ревью
```

## Сборка, запуск, тесты

```bash
cargo xtask engines            # скачать закреплённые sing-box, Xray, Wintun, сверить SHA-256, заполнить resources/
cargo xtask verify             # resources/ совпадает с resources/engines.toml
cargo build -p vpnte-app       # target/debug/vpn-tunnel-enforcer.exe
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask dist               # target/dist/: VPN-Tunnel-Enforcer-Setup-<версия>.exe, ...-portable.zip, checksums.txt
cargo xtask                    # список всех команд
```

Переменные окружения:

| Переменная | Значение |
| --- | --- |
| `VPNTE_RESOURCES_DIR` | папка движков; по умолчанию `<папка exe>\resources`. Для `cargo run -p vpnte-app` — абсолютный путь к `resources/` этого каталога |
| `VPNTE_DATA_DIR` | папка данных вместо `%APPDATA%\VPN Tunnel Enforcer\` (удобно, чтобы не трогать свои данные) |
| `VPNTE_LEGACY_DIR` | папка данных старой версии вместо `%APPDATA%\vpn-tunnel-enforcer\` (только чтение) |
| `VPNTE_LAN_TESTS` | включает тесты, которые слушают адрес в локальной сети (в CI; локально брандмауэр спрашивает разрешение) |

Тесты, которые нельзя запускать на рабочей машине, помечены `#[ignore]`: `elevated_*` требуют прав
администратора (настоящие объекты WFP, TUN, захват пакетов), `system_*` меняют реальные настройки
пользователя (системный прокси, значение `Run`). Обе группы запускает только CI на одноразовом раннере с
правами администратора: `cargo test --workspace -- --ignored --test-threads=1`.

## Крейты

Зависимости идут только сверху вниз по таблице (точно — `[dependencies]` в `crates/<имя>/Cargo.toml`).

| Крейт | Зависит от | Что внутри |
| --- | --- | --- |
| `base` | — | общий контракт: `AppError`, `Msg`, общие перечисления, поиск строк i18n, настройки HTTP/TLS |
| `core` | base | папки данных, JSON-документы с атомарной записью, секреты DPAPI, настройки, редактирование логов, журналы, разбор адресов, SOCKS5, разрешение имён, реестр операций, чтение данных старой версии |
| `winnet` | base | Win32: адаптеры и маршруты, процессы и Job Object, счётчики, ICMP, WFP, реестр, окружение, системный прокси, права, автозапуск, единственный экземпляр, буфер обмена, события питания, уведомления |
| `profiles` | base | модель профиля, импорт, генератор конфигурации sing-box, граф Xray, экспорт; без ввода-вывода |
| `view` | base | чистая логика стартовой страницы и маскота |
| `ui` | base, view | интерфейс Dioxus: окно, оболочка, «Пломба», маскот, трей, все страницы; трейты `XxxApi` и демо-бинарники `demo_*` |
| `servers` | base, core, profiles | список серверов, группы, подписки, выбор, архив, фоновое обновление |
| `engine` | base, core, winnet, profiles | конфигурации sing-box и Xray, процессы, Clash API, маршрутизация и DNS, Smart RU |
| `forensics` | base, core, winnet | статистика трафика, история доменов, pktmon + ETW, архив диагностики |
| `automation` | base, core, winnet | расписание, ротация, AutoPilot, адаптивный обход, обратимые настройки «Прокси», защита браузеров |
| `probes` | base, core, winnet, profiles, engine | IP и утечки, диагностика, доступность, скорость, пинги, здоровье ключей, живая проверка |
| `tunnel` | base, core, winnet, profiles, engine | актор подключения, захват (TUN или прокси), жизненный цикл, конечный автомат, история |
| `proxies` | base, core, profiles, engine | слоты внешних прокси, API управления на `127.0.0.1:17873`, `vpnte-proxy.exe` |
| `cleanup` | base, core, winnet | одноразовое удаление следов старой версии (только от администратора) |
| `app` | все | бинарник `vpn-tunnel-enforcer` (`VPN Tunnel Enforcer.exe`): запуск, реализации `XxxApi` над бэкендом, `--setup` |

Схема работы и что где ревьюить — `docs/architecture/`.

## Что проверено и что нет

- Локально без прав (12.11.2026): `cargo check --workspace --all-targets`, `cargo clippy --workspace
  --all-targets -- -D warnings` — чисто; `cargo test --workspace` — 2751 пройден, 0 упало, 31 пропущен.
- Только CI с правами администратора: TUN, WFP, `system_*`, установщик. Последний завершённый прогон
  (12.11.2026, PR #137): WFP пройден; сквозной тест TUN и проверка удаления установщиком — нет (`../progress.md`).
- Никогда: реальные российские сети; «Туннель» на машине владельца; обновление поверх версии 1.1.24.

Вопросы владельцу и решения по умолчанию — `../ВОПРОСЫ-ВЛАДЕЛЬЦУ.md`.
