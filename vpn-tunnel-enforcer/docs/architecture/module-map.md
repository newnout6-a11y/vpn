# Карта крейтов

Рабочее пространство `vpn-tunnel-enforcer/Cargo.toml`, крейты `crates/<имя>` (пакет `vpnte-<имя>`, путь Rust
`vpnte_<имя>`). Подробный публичный API — `crates/<имя>/API.md`.

## Слои и зависимости

Зависимости только сверху вниз и никогда обратно (`crates/CONTRACT.md` §2). Ниже — фактические
`[dependencies]` из `Cargo.toml` (12.11.2026); контракт разрешает ещё `tunnel` → `servers` и `proxies` →
`winnet`, но они не используются.

```
base        общий контракт: AppError, Msg, общие перечисления, i18n, HTTP/TLS        -
core        папки, Store<T>, Secret (DPAPI), настройки, редактирование, логи, сеть    -> base
winnet      Win32: адаптеры, процессы, WFP, реестр, системный прокси, автозапуск ...  -> base
profiles    модель профиля, импорт, генератор sing-box, граф Xray, экспорт           -> base
view        чистая логика стартовой страницы и маскота                              -> base
ui          интерфейс Dioxus: окно, оболочка, страницы, трей                         -> base, view
servers     список серверов, группы, подписки                                       -> base, core, profiles
engine      конфигурации и процессы sing-box / Xray, Clash API, маршрутизация, DNS  -> base, core, winnet, profiles
forensics   статистика, история доменов, pktmon + ETW, архив диагностики            -> base, core, winnet
automation  расписание, ротация, AutoPilot, обход, настройки «Прокси», защита       -> base, core, winnet
probes      IP / утечки, диагностика, доступность, скорость, пинги, живая проверка  -> base, core, winnet, profiles, engine
tunnel      актор подключения, захват, жизненный цикл, история                     -> base, core, winnet, profiles, engine
proxies     слоты внешних прокси, API управления, vpnte-proxy.exe                   -> base, core, profiles, engine
cleanup     одноразовое удаление следов старой версии                               -> base, core, winnet
app         бинарник: запуск, Backend, реализации XxxApi                            -> все
```

Чего нет в зависимостях, крейт получает трейтом или простыми данными: например, `automation` просит
подключения через свой `Coordinator`, `tunnel` берёт профили через `ProfileSource`, а реализует их `app`.

## Модули

| Крейт | Модули `src/` |
| --- | --- |
| `base` | `error`, `msg`, `types`, `i18n`, `http` |
| `core` | `paths`, `store`, `secret` + `dpapi`, `settings`, `redact`, `logging`, `net`, `resolve`, `socks5`, `ops`, `legacy` |
| `winnet` | `adapters`, `process`, `counters`, `icmp`, `wfp`, `registry`, `env`, `sysproxy`, `elevation`, `autostart`, `single_instance`, `clipboard`, `power`, `shell`, `toast` |
| `profiles` | `model`, `uri`, `json`, `clash`, `wg_ini`, `deeplink`, `text`, `legacy`, `emit_singbox`, `xray_native`, `export`, `identity`, `caps`, `countries`, `device` |
| `view` | `phase`, `labels`, `identity`, `traffic`, `fmt`, `mascot`, `swiss` |
| `ui` | `shell`, `dashboard`, `servers`, `settings`, `split_tunnel`, `traffic_history`, `logs`, `maintenance`, `availability`, `speedtest`, `schedule`, `wizard`, `panels`, `tray`, `mascot`, `widgets`, `theme`; `assets/` (CSS, шрифты, локали); `src/bin/demo_*` |
| `servers` | `model`, `store`, `parse`, `subscription`, `refresh`, `legacy` |
| `engine` | `singbox_config`, `singbox_process`, `xray_config`, `xray_process`, `clash_api`, `routing`, `ports`, `slot`, `apps`, `tags` |
| `forensics` | `traffic`, `connections`, `domains`, `enrichment`, `capture`, `etw`, `summary`, `export` |
| `automation` | `scheduler`, `schedule`, `rotation`, `autopilot`, `adaptive`, `coordinator`, `tweaks`, `hardening` |
| `probes` | `public_ip`, `ip_monitor`, `leak`, `diagnostics`, `local_proxy`, `availability`, `speedtest`, `ping`, `geo`, `egress`, `key_health`, `live`, `live_stages`, `curl`, `tls_client` |
| `tunnel` | `api`, `fsm`, `lifecycle`, `runtime` (`actor`, `capture/{tun,proxy}`, `engines`, `watchdog`, `recovery`), `switch`, `outcome`, `history` |
| `proxies` | `slot`, `manager`, `config`, `probe`, `health`, `control`, `token`, `model`; `src/bin/vpnte_proxy` |
| `cleanup` | `legacy` |
| `app` | `main`, `args`, `boot`, `root`, `setup`, `import`, `services`, `svc_core`, `svc_tunnel`, `svc_live`, `svc_proxies`, `api_*` (реализации `XxxApi`), `support` |

## Вне `crates/`

| Путь | Что |
| --- | --- |
| `xtask/` | отдельный крейт `cargo xtask`: `engines`, `verify`, `nsis`, `dist`, `smoke-install`, `version` |
| `installer/` | `vpnte.nsi` (установка на пользователя), `lang.nsh`, шимы `vpnte-proxy.cmd` / `.ps1`, лицензия GPL |
| `resources/` | `engines.toml` (закрепы), наборы правил `.srs`; движки после `cargo xtask engines` |
| `.cargo/config.toml` | статический CRT, алиас `xtask` |

## Куда класть новое

- Новый модуль — в крейт своего слоя; зависимость вверх по слоям не добавлять, а взять трейт или данные.
- Win32 — только в `winnet` (маленькие `unsafe` с `// SAFETY:`); UI — только в `ui`, бэкенд — через `XxxApi`.
- Документы хранятся через `core::store::Store<T>`; каждый крейт владеет своими типами документов.
- Строки для пользователя — `crates/<крейт>/locales/<пакет>.{ru,en}.json` под ключом верхнего уровня = имя
  крейта.
