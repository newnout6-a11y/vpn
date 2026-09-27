# VPN Tunnel Enforcer

[![Electron](https://img.shields.io/badge/Electron-42_LTS-47848F?logo=electron&logoColor=white)](https://www.electronjs.org/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Vitest](https://img.shields.io/badge/Vitest-1260+_tests-729B1B?logo=vitest&logoColor=white)](https://vitest.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Комплексное клиентское приложение для Windows (10/11 x64), предназначенное для гарантированной изоляции сетевого трафика, туннелирования через современные протоколы обхода блокировок и предотвращения любых видов утечек данных (IP, IPv6, DNS, WebRTC).

---

## 🚀 Ключевые возможности

- **Многоядерный сетевой стек (Hard Mode / TUN):**
  - Создание виртуального адаптера Wintun (`VPNTE-TUN`, `awg-tun`) и перехват всего системного IPv4/IPv6 трафика.
  - Поддержка ядер `sing-box` (схемы 1.13.x и 1.14.x с автоматической адаптацией конфигурации), сателлита `xray-core` (VLESS-REALITY) и альтернативного ядра `mihomo` (`CoreAdapter`).
  - Поддержка обфусцированного протокола **AmneziaWG** (AWG 1.0/2.0 с параметрами `Jc, Jmin, Jmax, S1..S4, H1..H4`) через выделенный процесс `amneziawg-go.exe`.
- **Поддерживаемые протоколы:**
  - `VLESS` (XTLS-Reality, Vision, gRPC, WebSocket), `WireGuard` (через схему `endpoints[]`), `Hysteria 2` (RFC-параметры), `Shadowsocks 2022 AEAD` (SIP002 IPv6), `VMess` (AEAD, `alter_id: 0`), `Trojan`, `NaiveProxy`, `ECH`.
- **Защита от утечек и WFP Kill-Switch (Zero-Leak Security):**
  - Блокировка утечек через Windows Filtering Platform (WFP) и Windows Firewall.
  - Полная изоляция IPv6 (`outbound block ::/0`), защита от утечек DNS (FakeIP, DoH/DoT/DoQ, отключение Windows Smart Multi-Homed Name Resolution).
  - Транзакционный откат конфигурации сети: хранение манифестов в `%ProgramData%\VPNTE\manifests\` с жестким DACL (SYSTEM/Admins), атомарная запись и фоновая задача аварийного восстановления при загрузке ОС (Boot Recovery).
- **Изоляция профилей (Chromium Browser Boxes):**
  - Запуск независимых инстансов Chromium с выделенными SOCKS5-инбаундами (`127.0.0.1:10801..10850`) для безопасной работы с мультиаккаунтами без пересечения цифровых отпечатков (fingerprints), cookies и WebRTC.
- **Интеллектуальная маршрутизация:**
  - Режим **Smart RU**: комплектные бинарные наборы правил (`geoip-ru.srs`, `geosite-category-gov-ru.srs`) для локального fallback и бесперебойного доступа к сервисам РФ в обход туннеля.
  - Split Tunneling по абсолютным путям процессов (`.exe`) и диапазонам IP/CIDR.
- **Режим разработчика (Soft Mode / Autoconfig):**
  - Безадминистраторское прямое локальное SOCKS5/HTTP проксирование.
  - Автоматическая настройка окружения разработчика: Android Studio (`proxy.settings.xml`), Git, Gradle, переменные среды (`HTTP_PROXY`, `HTTPS_PROXY` через прямую запись в `HKCU\Environment`).
- **Форензика трафика и ETW-сайдкар:**
  - Высокопроизводительный сайдкар на Rust для непрерывного отслеживания сетевых сокетов через Event Tracing for Windows (`Microsoft-Windows-TCPIP` + WinsockAFD) с нагрузкой < 0.5% CPU.
  - Атрибуция соединений по процессам, ротация базы 50 МБ / 24 ч, захват сетевых дампов через `pktmon`.
- **Автоматизация и жизненный цикл:**
  - Планировщик подключений (таймзоны, DST, объединение окон активности).
  - Ротация серверов по принципу **Health-Before-Commit** (переключение только на предварительно проверенный здоровый узел).
  - Управление внешним локальным прокси (Happ Proxy Utility) с защитой токена NTFS DACL и предотвращением DNS Rebinding.

---

## 📁 Структура репозитория

```
vpn/
├── docs/                                 # 🌟 Официальное консолидированное ТЗ (3 тома)
│   ├── README.md                         # Оглавление и навигация по ТЗ
│   ├── 01-ТЗ-СЕТЕВОЕ-ЯДРО...md           # Сетевое ядро, протоколы, Wintun, маршрутизация, DNS
│   ├── 02-ТЗ-СИСТЕМНАЯ-БЕЗОПАСНОСТЬ...md # WFP Kill-Switch, защита от утечек, DPAPI, ОС
│   └── 03-ТЗ-ЖИЗНЕННЫЙ-ЦИКЛ...md         # Lifecycle, автоматизация, UI/UX, диагностика, CI/CD
│
├── docs-factory8090/                     # База знаний и артефакты Software Factory 8090
│   ├── 00-журнал-аудита.md               # Полный реестр 185 аудиторских находок (F-001..F-185)
│   ├── 01-обзор/                         # Обзорные документы продукта и требования
│   ├── 02-фичи/                          # 44 фичи по 10 направлениям (requirements + blueprint)
│   ├── 03-контейнеры/                    # Архитектурные схемы контейнеров
│   ├── 04-компоненты/                    # Спецификации компонентов
│   ├── 05-открытые-вопросы.md            # Реестр 128 вопросов с утверждёнными решениями PO
│   └── 06-ТЗ-исправление-и-развитие.md   # Комплексное ТЗ устранения дефектов и развития (WP-0..12)
│
├── vpn-tunnel-enforcer/                  # 💻 Исходный код приложения (Electron + React)
│   ├── src/
│   │   ├── main/                         # Главный процесс Electron (сеть, IPC, безопасность)
│   │   ├── preload/                      # Безопасный контекстный мост (contextBridge)
│   │   ├── renderer/                     # UI интерфейс (React 18, Tailwind, Fluent UI)
│   │   └── shared/                       # Общие типы, схемы валидации и утилиты
│   ├── resources/                        # Встраиваемые бинарники, скрипты и правила SRS
│   ├── scripts/                          # Скрипты сборки сайдкаров и снапшотов V8
│   └── package.json                      # Зависимости приложения (версия 1.1.22)
│
├── sing-box-1.13.8-windows-amd64/        # Вендорный дистрибутив sing-box
├── wintun/                               # Драйвер Wintun (заголовки, библиотеки)
├── package.json                          # Корневой манифест рабочих сценариев монорепозитория
└── README.md                             # Этот документ
```

---

## 🛠️ Требования к окружению

- **ОС:** Windows 10 (сборка 19041+) или Windows 11 x64 (рекомендуется).
- **Среда выполнения:** Node.js 18+ (рекомендуется Node.js 20 LTS / 22 LTS).
- **Менеджер пакетов:** npm 9+
- **Права доступа:** Для операций с Wintun, сетевыми адаптерами и WFP требуются права Администратора Windows (UAC-элевация реализована внутри приложения).

---

## 🚀 Быстрый старт

### Установка зависимостей

Вы можете запускать команды как из корня репозитория, так и из папки `vpn-tunnel-enforcer`:

```bash
# Установка зависимостей приложения
cd vpn-tunnel-enforcer
npm install
```

### Запуск в режиме разработки

```bash
# Из корня репозитория:
npm run dev

# Либо напрямую из каталога приложения:
cd vpn-tunnel-enforcer
npm run dev
```

> **Важно:** `npm run dev` запускает приложение через `electron-vite`. Открывайте окно Electron, а не браузерный URL Vite, так как интерфейс использует типизированный IPC-мост `contextBridge`.

---

## 🧪 Тестирование

Проект содержит всеобъемлющий набор unit- и integration-тестов на базе **Vitest** (1260+ тестов), покрывающих жизненный цикл, маршрутизацию, парсинг профилей, защиту от утечек и UI-компоненты:

```bash
# Запуск полного набора тестов из корня:
npm test

# Запуск тестов в режиме отслеживания изменений (watch):
npm --prefix vpn-tunnel-enforcer run test:watch

# Запуск с отчетом о покрытии кода (coverage):
npm --prefix vpn-tunnel-enforcer run test:coverage
```

Проверка типов TypeScript:
```bash
npm run typecheck
```

---

## 📦 Сборка и упаковка (Production Build)

Сборка оптимизированного Windows-инсталлятора (NSIS) и портативной версии:

```bash
# Полная сборка Windows-инсталлятора (.exe):
npm run dist:win

# Сборка портативной версии (Portable):
npm run dist:portable
```

Артефакты сборки сохраняются в каталог `vpn-tunnel-enforcer/dist/`:
- `VPN-Tunnel-Enforcer-Setup-1.1.22.exe` (инсталлятор NSIS с автоматической регистрацией Boot Recovery)
- `VPN-Tunnel-Enforcer-1.1.22-portable.exe` (портативная сборка)

---

## 🔌 Внешний API управления прокси (External Proxy Control API)

Приложение поднимает локальный управляющий REST API на порту `127.0.0.1:17873`:

- `GET /api/external-proxy/status` — текущий статус службы.
- `GET /api/external-proxy/instances` — список активных инстансов.
- `GET /api/external-proxy/list` — перечень доступных слотов прокси.
- `POST /api/external-proxy/start` — запуск выделенного локального прокси.
- `POST /api/external-proxy/rotate` — ротация серверов в слоте.
- `POST /api/external-proxy/stop` — остановка инстанса.

API поддерживает 10 независимых слотов: слот 1 по умолчанию слушает порт `17990`, слоты 2–10 используют порты `17991`..`17999`. Мутирующие запросы защищены сессионным токеном `X-VPNTE-Control-Token` (`%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-token`).

---

## 📚 Архитектурная документация и ТЗ

Подробная документация сведена в три мастер-тома в папке [`docs/`](docs/):

1. [**Том 1: Сетевое ядро, протоколы, Wintun, маршрутизация и DNS**](docs/01-ТЗ-СЕТЕВОЕ-ЯДРО-ПРОТОКОЛЫ-И-МАРШРУТИЗАЦИЯ.md)
2. [**Том 2: Системная безопасность, защита от утечек, транзакционный откат и ОС**](docs/02-ТЗ-СИСТЕМНАЯ-БЕЗОПАСНОСТЬ-ЗАЩИТА-ОТ-УТЕЧЕК-И-ОС.md)
3. [**Том 3: Жизненный цикл, автоматизация, мониторинг, UI/UX и диагностика**](docs/03-ТЗ-ЖИЗНЕННЫЙ-ЦИКЛ-АВТОМАТИЗАЦИЯ-UI-И-ДИАГНОСТИКА.md)

---

## 📄 Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
