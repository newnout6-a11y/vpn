# Маршрут ревью

Сначала `API.md` затронутого крейта и его `progress/` (что сделано, что не запускалось), затем код. Общие
правила — `crates/CONTRACT.md` §3–4.

## Туннель, захват, WFP

Где: `tunnel/src/runtime/` (актор, `capture/{tun,proxy}.rs`, `watchdog.rs`, `recovery.rs`),
`tunnel/src/lifecycle/`, `tunnel/src/switch/`, `engine/src/singbox_config/`, `engine/src/*_process/`,
`winnet/src/wfp/`, `winnet/src/adapters/`.

- Старт, остановка, сбой, переключение и выход симметричны: всё, что `Capture::begin` подняло, `release`
  снимает; незавершённая остановка видна как «не проверено», а не как успех.
- Без прав «Туннель» отвечает `Permission` сразу (`RuntimeDeps::tun = None`); молчаливого перехода в
  «Прокси» нет.
- WFP: `standard` — динамическая сессия, `strict` — постоянные фильтры в своём провайдере и подслое.
- Код с правами администратора проверяется тестами `elevated_*` (`#[ignore = "needs elevation"]`), которые
  убирают за собой; их запускает только CI.

## Режим «Прокси» и системные настройки

Где: `tunnel/src/runtime/capture/proxy.rs`, `automation/src/tweaks/`, `winnet/src/sysproxy/`,
`winnet/src/env.rs`, `app/src/svc_tunnel/`.

- «Подключено» — только когда движок принимает на порту `mixed` и системный прокси применён и считан обратно.
- Каждая настройка попадает в `tweaks::Journal` с исходным значением и откатывается: при выходе — сразу,
  после сбоя — при следующем запуске; значение, которое пользователь сменил сам, не затирается.
- Тесты не трогают реальный системный прокси и `Run`: фейки или ключи `HKCU\Software\VPNTE-Test-*`;
  реальное — только `system_*` под `#[ignore = "changes system state"]`.

## Профили, серверы, движки

Где: `profiles/src/` (`uri`, `json`, `clash`, `wg_ini`, `emit_singbox`, `xray_native`),
`servers/src/` (`subscription`, `refresh`), `engine/src/xray_config/`, `engine/src/routing/`.

- Конфигурацию sing-box строит только `emit_singbox`, Xray — только `xray_config`; нормализация исходящих —
  один раз, в `emit_singbox`.
- Сгенерированная конфигурация проверяется настоящим движком из `resources/`, если он есть.
- Секреты: DPAPI на диске, `core::redact` в логах и выгрузках; в тестах только очевидные фейки.

## Проверки, диагностика, внешние прокси

Где: `probes/src/`, `forensics/src/`, `proxies/src/` (`control`, `slot`, `manager`).

- Результат, который не наблюдался, — `Verdict::NotChecked`, а не успех.
- Архив диагностики проходит редактирование; ключей и ссылок подписок в нём нет.
- Слоты и API управления слушают только `127.0.0.1`; API защищён токеном.

## Интерфейс

Где: `ui/src/<страница>/` (view-модели, трейт `XxxApi`, демо-реализация), `ui/assets/`, `view/src/`,
реализации — `app/src/api_*`.

- `ui` не вызывает бэкенд-крейты; состояние приходит через `watch::Receiver`, действия — async-методы `XxxApi`.
- Весь текст — ключи `Msg` с переводами ru и en; стартовая страница совпадает с эталоном «Пломба».
- Демо-бинарник `cargo run -p vpnte-ui --bin demo_<страница>` показывает страницу без бэкенда.

## Сборка и поставка

Где: `xtask/src/`, `installer/vpnte.nsi`, `resources/engines.toml`, `.github/workflows/`.

- Каждый сторонний файл закреплён SHA-256 в `engines.toml`; `cargo xtask verify` сверяет `resources/`.
- Установщик пишет только в HKCU и профиль пользователя, UAC не вызывает; `cargo xtask smoke-install` — только CI.

## Definition of Done

```bash
cd vpn-tunnel-enforcer
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 ../docs/04-приёмочные-тесты/traceability/check-coverage.py
```

Плюс: новые сущности имеют тесты, в doc-комментарии — тег `AT-<WP>-<NNN>`, если тест переносит приёмочный;
в `progress/` пакета записано, что не запускалось.
