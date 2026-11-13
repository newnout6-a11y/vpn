# resources/

Папка разработки с теми же движками и наборами правил, что попадают в `resources\` установки рядом с
`VPN Tunnel Enforcer.exe`: тесты и `cargo run` берут движки отсюда (`VPNTE_RESOURCES_DIR` или
`<папка exe>\resources`). `engines.toml` и этот файл не поставляются.

| Файл | В git | Что |
| --- | --- | --- |
| `engines.toml` | да | единый манифест закреплений: архивы движков, их файлы и лицензии с SHA-256, локальные файлы поставки, NSIS для сборки |
| `geoip-ru.srs`, `geosite-category-gov-ru.srs` | да | наборы правил Smart RU; поставляются файлами, потому что неудачная первая загрузка удалённого набора — фатальная ошибка sing-box |
| `geosite-ru-blocked.srs`, `geoip-ru-blocked.srs` | да | заблокированные в РФ сайты и адреса: Smart RU ведёт их через туннель, даже если сайт в РФ. [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat), ветка `release`, на 13.11.2026; лицензия GPL-3.0 (полный текст ставится в `licenses\GPL-3.0.txt`). Управляемое обновление (раз в 24 ч) заменяет их свежими |
| `sing-box.exe`, `libcronet.dll` | нет | sing-box 1.14.4 (windows-amd64) |
| `xray.exe` | нет | Xray 26.11.9 (windows-64) |
| `wintun.dll` | нет | Wintun 0.14.1 (amd64), нужен sing-box для TUN |
| `mihomo.exe` | нет | mihomo 1.19.34 (windows-amd64-compatible = GOAMD64 v1): лабораторный движок WP-12 для AmneziaWG (`lab = true` в `engines.toml`), только для тестов и сборки `cargo xtask dist --lab` |
| `README.md` | да | этот файл |

Движки не хранятся в git (`*.exe`, `*.dll` в `.gitignore`). Их кладёт сюда команда из `vpn-tunnel-enforcer/`:

```bash
cargo xtask engines            # скачать архивы (кэш target/download-cache), сверить SHA-256 архива и каждого файла
cargo xtask engines --offline  # то же только из кэша
cargo xtask verify             # каждый закреплённый файл на месте и совпадает с закрепом
```

Новая версия движка — только правкой `engines.toml` (URL, версия, SHA-256 архива и файлов) и повторным
`cargo xtask engines`. `cargo xtask dist` раскладывает каждую запись `engines.toml` по её пути `install` в
`target/stage`; лицензии движков попадают в `licenses\` установки.

Архив с `lab = true` (сейчас mihomo) `cargo xtask engines` кладёт сюда вместе с остальными (его проверяют
тесты с `--features lab`), а `cargo xtask dist` пропускает: в поставку он попадает только из
`cargo xtask dist --lab`, которая собирает приложение с функцией `lab` и называет все артефакты `…-lab`.
