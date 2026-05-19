# Multi-account / profile isolation — plan

Статус: **черновик, ждёт одобрения**.
Не реализовано. Этот документ — спецификация перед стартом.

## Зачем

Темщику нужно одновременно держать несколько изолированных «личностей»:

- 3 разных Instagram (под разные ниши / страны)
- 5 ChatGPT (бесплатные триалы)
- 2 Steam (под разные регионы)
- N браузерных сессий для арбитража / партнёрок

«Изолированный» здесь — это **3 разные вещи**, и они часто путаются:

1. **IP-изоляция** — каждый профиль выходит наружу через свой VPN-узел.
2. **Cookie/storage-изоляция** — у каждого профиля свои куки, localStorage,
   кэш, расширения.
3. **Fingerprint-изоляция** — canvas, WebGL, fonts, timezone, language,
   user-agent выглядят по-разному. Без этого даже разные IP+куки
   палятся на одном устройстве.

Коммерческие аналоги: Multilogin (99$/мес), GoLogin (24$/мес),
Dolphin Anty (89$/мес), AdsPower (от 9$/мес). Все хороши, все
платные, ни один не делает свой VPN — пользователю надо отдельно
покупать прокси (часто резидентные).

Наша UPS: интегрировать всё в одно приложение. Пользователь покупает
VPN-ключи под разные страны → создаёт «бокс» с привязанным профилем
→ кликает «запустить браузер» → получает изолированную среду.

## MVP scope (что войдёт в первый коммит)

**В MVP**:

- IP-изоляция: бокс = (UserDataDir, server profile).
- Cookie/storage-изоляция: через `--user-data-dir` Chromium-флага.
- Запуск Chrome / Edge / Yandex Browser / Brave из приложения с
  `--proxy-server` + `--user-data-dir`.
- Список боксов в новой странице «Боксы» (sidebar entry).
- Per-box server picker (можно поменять выход не пересоздавая бокс).

**НЕ в MVP** (отдельные итерации потом):

- Fingerprint-подмена (canvas/WebGL/timezone). Требует injection через
  CDP — это +500 строк + риски. Сделаем отдельно после того как
  базовая часть стабилизируется.
- Firefox containers интеграция (Firefox использует другую модель
  изоляции, отложим).
- Резидентные прокси на вход (chain). Требует UI для хранения
  внешних прокси-credentials.
- Запуск произвольных приложений (Telegram, Steam) через прокси.
  Технически можно через proxychains-style wrap, но это сложнее
  для не-Chromium программ. Браузер покрывает 80% use-case.

## Архитектура

### Модель данных

Новый стор `boxes.json` (electron-store), отдельно от server-picker:

```ts
interface BrowserBox {
  id: string                       // uuid
  name: string                     // "IG США #2" / "GPT Ниша Auto"
  browser: 'chrome' | 'edge' | 'yandex' | 'brave'
  serverProfileId: string | null   // ссылка на server-picker profile;
                                   // null = direct (без VPN)
  userDataDir: string              // absolute path; по умолчанию
                                   // <userData>/boxes/<id>/profile
  proxyPort: number                // случайный 49152-65535, выделяется
                                   // при создании. Локальный SOCKS5
                                   // прокси sing-box, изолирующий
                                   // именно этот бокс.
  color: string                    // hex для тэга в UI ("красный IG")
  createdAt: number
  lastLaunchedAt: number | null
  notes: string                    // свободный текст для пользователя
}
```

### Как добиться per-box IP — ключевое архитектурное решение

Есть два подхода:

#### Вариант A: один sing-box, выделенные SOCKS5-inbounds per-box

Главный TUN-режим продолжает работать. Дополнительно в singbox config
добавляются inbounds типа `socks` на 127.0.0.1:<random>, по одному на
бокс. Каждый такой inbound маршрутизируется по правилу `inbound:
'box-<id>'` → `outbound: 'box-<id>-out'` (своя vless конфигурация).

Браузер запускается с `--proxy-server=socks5://127.0.0.1:<port>`. Его
трафик попадает в свой inbound → свой outbound → свой VPN-узел.

**Плюсы**: всё в одном sing-box, реюз нашей логики, kill-switch
работает на бокс автоматически.

**Минусы**: каждое добавление/удаление бокса требует пересборки
config.json и перезапуска sing-box. Перезапуск занимает 2-3 сек и
гасит активные сессии других боксов.

#### Вариант B: отдельный sing-box per-box

Каждый бокс = отдельный процесс sing-box с минимальным конфигом
(только socks-inbound + один outbound). TUN-режим главного приложения
остаётся как есть.

**Плюсы**: добавление/удаление бокса не трогает другие. Изоляция
сильнее (если один sing-box упадёт, другие живут).

**Минусы**: больше памяти (каждый процесс ~30 MB), сложнее cleanup при
краше Electron, отдельный watchdog per-process.

**Рекомендация**: **Вариант B**. Память дешёвая, изоляция важнее.
Будем держать `Map<boxId, ChildProcess>` в main-процессе и завершать
их по `app.on('before-quit')`.

### Лайфцикл бокса

```
   создать → выбрать сервер → запустить браузер
                ↓
            (box stopped)
                ↓
       launchBox() запускает sing-box-box-<id>.exe (копия binary)
            на 127.0.0.1:<proxyPort> с outbound из serverProfile
                ↓
       ждём 1s до здоровья socks-inbound
                ↓
       spawn(browser_exe, ['--proxy-server=socks5://127.0.0.1:<port>',
                           '--user-data-dir=<userDataDir>'])
                ↓
            (box running)
                ↓
       пользователь закрывает браузер
                ↓
       мы детектим death of browser PID
                ↓
       gracefully stop sing-box-box-<id> через SIGTERM
                ↓
            (box stopped)
```

### Какой бинарь Chromium запускать

Под Windows ищем в этом порядке (первый найденный):

- **Google Chrome**: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe
- **Microsoft Edge**: %ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe
- **Yandex Browser**: %LocalAppData%\\Yandex\\YandexBrowser\\Application\\browser.exe
- **Brave**: %ProgramFiles%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe

В UI юзер выбирает явно. Default = первый найденный из списка.

### Файлы которые надо тронуть

Новые:

- `src/main/browserBox.ts` — модель + IPC + лайфцикл (~400 строк):
  - `createBox(name, serverProfileId, browser)` → BrowserBox
  - `deleteBox(id)` — останавливает если запущен, удаляет UserDataDir
  - `launchBox(id)` — старт sing-box + spawn браузера
  - `stopBox(id)` — terminate browser + sing-box
  - `listBoxes()`, `getBox(id)`, `updateBox(id, patch)`
- `src/main/boxRuntime.ts` — спавн sing-box-per-box, мониторинг
  процессов, генерация per-box singbox config (~200 строк).
- `src/renderer/pages/Boxes.tsx` — список боксов, кнопки
  «Запустить»/«Остановить»/«Удалить», создание модалкой (~300 строк).
- `src/renderer/components/BoxRow.tsx` — карточка бокса (~150 строк).
- `src/main/browserDetect.ts` — поиск установленных Chromium-браузеров
  на машине (~80 строк).

Изменения:

- `src/main/index.ts` — register handlers, cleanup при quit.
- `src/preload/index.ts` — bridge для box-* IPC.
- `src/renderer/App.tsx` — добавить роут `boxes`.
- `src/renderer/nav.ts` — добавить `boxes` в AppPage.
- `src/renderer/components/Sidebar.tsx` — добавить пункт «Боксы».
- `src/shared/ipc-types.ts` — типы для бокса.

Всего: **~1100 новых строк, ~30 изменений в существующих файлах**.

## Безопасность / риски

1. **UserDataDir разрастается**. Каждый бокс держит свой Chrome
   профиль = 100-500 MB. При 20 боксах = до 10 GB. Покажем размер в
   UI + кнопку «очистить кэш».

2. **Утечка через DNS**. Браузер с `--proxy-server=socks5://...` по
   умолчанию НЕ резолвит DNS через прокси — он резолвит локально
   через ОС, и DNS-запрос идёт мимо бокса (палит цель в систему).
   Решение: добавить `--host-resolver-rules="MAP * ~NOTFOUND ,
   EXCLUDE 127.0.0.1"` НЕТ, это не то. Правильный флаг:
   `--proxy-server=socks5://...` + `--dns-prefetch-disable` +
   убедиться что socks5h (с h, DNS через прокси). Chromium умеет
   socks5h начиная с какого-то билда. Надо проверить — это
   критический риск, без этого нет настоящей изоляции.
   **Дополнительно**: запускать с `--enable-features=AsyncDns` и
   указывать DNS-over-HTTPS сервер.

3. **WebRTC leak**. Браузер по умолчанию палит локальные IP через
   WebRTC API. Решение: применить нашу существующую
   `applyBrowserLeakProtection` per-UserDataDir, в режиме `Local
   State` policy на конкретный профиль, а не глобально.

4. **Утечка через `--proxy-bypass-list`**. По умолчанию localhost
   игнорирует прокси — это ОК. Но если пользователь зайдёт на
   `chrome://flags` и тыкнет что-то — может вылезти. Запретить
   через `--disable-features=PolicyBlocklist` и через managed
   policy, форсированную через --policy-resource-uri.

5. **Конфликт портов**. Если SOCKS-порт уже занят чем-то другим —
   sing-box падает на старте. Использовать `net.createServer().listen(0)`
   для аренды порта перед записью в config.

6. **Закрытие приложения**. Если юзер закрывает VPN-приложение
   при работающих боксах — что делать? Опции:
   - Завершить все боксы (закрывает Chrome-окна пользователя — плохо)
   - Оставить боксы работать (но без TUN main app остановится, и
     прокси-цепочка может оборваться если sing-box-box-X использует
     TUN-маршрут для своего outbound)
   - Решение: спрашивать в diologue confirm. Default — «оставить».

7. **Crash recovery**. Если main app падает, sing-box-box-X
   процессы остаются. На старте надо найти их (по имени
   `vpnte-box-*.exe`) и решить — присвоить их обратно к боксу или
   убить.

## UI mockup (текстом)

```
┌─────────────────────────────────────────────────────────────┐
│ Sidebar                  │ Боксы (5)        + Создать бокс   │
│ ┌────────────────────┐  │ ─────────────────────────────────  │
│ │ Главная            │  │                                    │
│ │ Приложения         │  │ 🇺🇸 IG Бренд #1     [Chrome]        │
│ │ Серверы            │  │ ⬤ Запущен · 23 мин                 │
│ │ Тесты скорости     │  │ Сервер: США (4 ms)                 │
│ │ Доступность        │  │  [Открыть в браузере] [Остановить] │
│ │ ► Боксы          ◀ │  │                                    │
│ │ История траф.      │  │ 🇩🇪 GPT Auto         [Edge]         │
│ │ Расписание         │  │ ⚪ Остановлен                       │
│ │ Логи               │  │ Сервер: Германия                   │
│ │ Настройки          │  │  [Запустить]   [Удалить]           │
│ └────────────────────┘  │                                    │
│                          │ 🇰🇿 SteamShop        [Brave]        │
│                          │ ⚪ Остановлен                       │
│                          │ Сервер: Казахстан                  │
│                          │  [Запустить]   [Удалить]           │
└─────────────────────────────────────────────────────────────┘
```

## Что нужно подтвердить у пользователя перед стартом

1. **Вариант A или B** для архитектуры sing-box. По умолчанию —
   B (отдельный sing-box на бокс).
2. **MVP без fingerprint-подмены** ОК? Или сразу включаем?
3. **Закрытие приложения при работающих боксах** — confirm dialog
   или silent terminate?
4. Куда мы складываем UserDataDir? Default:
   `<userData>/boxes/<id>/profile`. Альтернатива: пользователь
   указывает свою папку (например, на отдельном диске).
5. **Шифрование UserDataDir**? Каждый Chrome-профиль содержит куки,
   токены, пароли. На физически украденной машине без шифрования
   диска — всё видно. Можем форсить BitLocker-check + warning, или
   полностью шифровать UserDataDir-папку (но это сильно бьёт по
   скорости старта браузера).
6. **Брендинг боксов**. Цвет + эмодзи в названии хватит? Или нужны
   иконки сервисов (IG, FB, TG)?

## Оценка времени

С твоей готовностью отвечать на вопросы по architecture decisions и
без отвлечения на другие фичи:

- MVP без fingerprint: **3-4 итерации по 1-2 часа** (то есть
  «сессионный день» — но я не оцениваю в часах).
- + DNS-leak protection в браузере: +1 итерация
- + Crash recovery / process supervisor: +1 итерация
- + Fingerprint subset (timezone/UA/language только): +2 итерации
- + Полный fingerprint (canvas/WebGL inject через CDP): отдельный
  большой эпик, +5-7 итераций

Итого MVP минимально жизнеспособный (всё перечисленное в «В MVP»
выше + DNS leak fix + базовый crash recovery): **5-6 итераций**.
