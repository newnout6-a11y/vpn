# resources/

Папка разработки с теми же движками и наборами правил, что попадают в `resources\` установки рядом с
`VPN Tunnel Enforcer.exe`: тесты и `cargo run` берут движки отсюда (`VPNTE_RESOURCES_DIR` или
`<папка exe>\resources`). `engines.toml` и этот файл не поставляются.

| Файл | В git | Что |
| --- | --- | --- |
| `engines.toml` | да | единый манифест закреплений: архивы движков, их файлы и лицензии с SHA-256, локальные файлы поставки, NSIS для сборки |
| `geoip-ru.srs`, `geosite-category-gov-ru.srs` | да | наборы правил Smart RU; поставляются файлами, потому что неудачная первая загрузка удалённого набора — фатальная ошибка sing-box |
| `sing-box.exe`, `libcronet.dll` | нет | sing-box 1.14.4 (windows-amd64) |
| `xray.exe` | нет | Xray 26.11.9 (windows-64) |
| `wintun.dll` | нет | Wintun 0.14.1 (amd64), нужен sing-box для TUN |
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
