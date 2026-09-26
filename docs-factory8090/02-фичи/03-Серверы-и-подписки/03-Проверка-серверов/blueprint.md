# Проверка серверов

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/18aa853a-a78f-4cac-8cdf-9cc14009b07d

## Feature Summary

Фича реализует проверки профилей VPN-серверов в приложении Windows на Electron 42. Она объединяет прямое измерение endpoint, пакетный ping, временную проверку outbound через sing-box или Xray, проверку группы ключей и представление деталей сервера. Результаты прямой задержки, состояния ключа, внешнего IP и геоданных хранятся и показываются как разные типы сведений.

## Component Blueprint Composition

Фича использует инфраструктуру @Серверы и подписки для чтения профилей, групп и активного профиля, а также для передачи выбора сервера в общий механизм выбора. Проверки запускаются из страницы `Servers` через IPC-контракты main process и обновляют состояние списка без изменения кода профилей.

## Feature-Specific Components

### Прямые проверки endpoint

```component
name: ServerPickerPing
container: Electron Main
responsibilities:
	- Измеряет прямую задержку endpoint через `smartEndpointPing` и разделяет режим физического подключения от режима активного VPN-туннеля.
	- Выполняет пакетный `pingAll` с ограничением PING_CONCURRENCY равным 5.
	- Не записывает результаты в профиль, когда активный туннель делает маршрут несопоставимым с прямым измерением.
```

```component
name: ServerProbe
container: Electron Main
responsibilities:
	- Разрешает hostname в IPv4 и IPv6 адреса и отклоняет private или loopback адреса.
	- Измеряет TCP-задержку серией подключений к известному порту профиля.
	- Возвращает DNS, reverse DNS, ASN, доступные порты и результат задержки через `ServerProbeResult`.
```

`ServerPickerPing` предоставляет странице `Servers` быстрый результат для одного профиля и пакетной операции. `ServerProbe` используется модалкой деталей для расширенного диагностического результата, поэтому его latency является отдельным результатом от сохранённого ping профиля.

### Проверка ключей

```component
name: KeyHealthChecker
container: Electron Main
responsibilities:
	- Создаёт временный каталог и конфигурацию проверки для outbound профиля.
	- Запускает bundled sing-box или Xray, выбранный через настройку proxyEngine и тип outbound.
	- Проверяет рабочий SOCKS-маршрут через несколько HTTPS-направлений и завершает проверку по первому успешному результату.
	- Проверяет профили группы с ограничением HEALTH_CHECK_CONCURRENCY и сохраняет online/offline, healthCheckedAt, healthLatencyMs, reason, egressIp и country.
```

`KeyHealthChecker` не использует health latency как географическую прямую задержку. Результат временной проверки показывает, работает ли ключ и какой выходной IP или страна были подтверждены через него.

### Представление списка и деталей

```component
name: ServersPage
container: Electron Renderer
responsibilities:
	- Показывает сохранённые профили и запускает одиночную или пакетную проверку ping.
	- Запускает проверку здоровья группы и показывает отдельное состояние загрузки, доступность и latency результата для каждого профиля.
	- Передаёт выбранный профиль в `ServerDetailModal`.
```

```component
name: ServerDetailModal
container: Electron Renderer
responsibilities:
	- Показывает протокол, endpoint, порт и сохранённую прямую задержку профиля.
	- Запускает `serverProbe` для DNS, latency и доступных диагностических данных.
	- Запрашивает геоданные IP через HTTPS `ipapi.co` с fallback на `ipwho.is`, если геолокация не отключена.
	- Отделяет геоданные внешнего провайдера от результата проверки ключа и прямой задержки.
```

```component
name: LiveServerHistoryManager
container: Electron Main
responsibilities:
	- Хранит результаты live-проверок по ключам `profile:<id>`, `host:<host>` и `global`.
	- Загружает и сохраняет историю в локальный JSON-файл через `app.getPath('userData')`.
	- Возвращает историю отдельной цели или 20 последних результатов по всем целям соответственно.
	- Выбирает предыдущую неотменённую успешную проверку с учетом цели и порта.
	- Санитизирует данные перед сохранением и игнорирует поврежденный файл.
```

```component
name: computeHistoryDiff
container: Electron Main
responsibilities:
	- Сравнивает текущий результат с предыдущей успешной live-проверкой.
	- Вычисляет изменения IP A/AAAA, TLS fingerprint, ASN, страны, задержки, портов, handshake, egress IPv4/IPv6, PMTU и медианной скорости.
	- Возвращает признаки изменений и значения до и после сравнения для результата live-проверки.
```

`ServersPage` передаёт действия пользователя в main process через IPC, а `ServerDetailModal` параллельно обрабатывает best-effort геолокацию и основной `serverProbe`. Ошибка внешнего геосервиса не блокирует отображение профиля и результата main-process проверки.

`LiveServerHistoryManager` получает завершенный `LiveServerCheck` из `liveServerProbe`, а `computeHistoryDiff` сравнивает его с предыдущей успешной записью до сохранения. Renderer получает список истории через `serverLiveCheckHistory` и показывает подтвержденные признаки изменения IP и TLS-отпечатка внутри блока инфраструктуры и диффов.

```model
name: LiveServerCheckHistory
store: Local JSON file
description: Локальная история результатов live-проверок, сгруппированная по целевой проверке.
fields:
	- target_key: string (`profile:<id>`, `host:<host>` или `global`)
	- checks: LiveServerCheck[] (не более 20, новые записи первыми)
constraints:
	- Перед сохранением результат проходит через `sanitizeLiveCheckForStorage`.
	- Повреждённое содержимое файла не блокирует live-проверку.
```

## System Contracts

### Key Contracts

* Прямая задержка профиля измеряется отдельно от результата проверки ключа и не заменяется health latency.
* Пакетная проверка ограничивает параллелизм и сохраняет результаты отдельных профилей независимо друг от друга.
* При работающем TUN пакетный `pingAll` не перезаписывает сохранённые значения прямой задержки результатами другого маршрута.
* Проверки не выполняются для разрешённых private или loopback адресов.
* Успешная проверка ключа сохраняет состояние доступности, время, длительность, а при наличии результат выхода и страну.
* Геолокация является best-effort. Ошибка или ограничение провайдера не делает всю карточку деталей недоступной.
* `LiveServerHistoryManager` ограничивает историю каждой цели 20 результатами и помещает новый результат в начало списка.
* Ключ цели имеет вид `profile:<id>`, `host:<host>` или `global`; hostname нормализуется в нижний регистр и очищается от пробелов.
* `sanitizeLiveCheckForStorage` удаляет из evidence поля, содержащие `uuid`, `secret`, `password`, `key`, `shortid`, `token` или `uri`, и заменяет UUID в строковых данных на `[REDACTED_UUID]`.
* Ошибка чтения поврежденного файла истории игнорируется, а ошибка записи не блокирует текущую live-проверку.
* `getPreviousSuccessfulCheck` выбирает последнюю неотменённую запись с `reachability.status === 'ok'` или `dns.status === 'ok'`, учитывая порт.
* `computeHistoryDiff` считает скачком задержки рост `avg` более чем в 1,5 раза и более чем на 50 мс, а падением скорости снижение `medianMbps` менее чем до 65 процентов предыдущего значения.
* Изменение PMTU сравнивается только при одинаковых `family`, `method` и совместимых `destination`.

### Integration Contracts

* `ServerPickerPing` предоставляет операции одиночного и пакетного ping для renderer и обновляет поля `ping`, `status` и `lastChecked` только в допустимом режиме.
* `ServerProbe` возвращает `ServerProbeResult`, включающий `resolvedIps`, `reverseDns`, `asn`, `latency`, `openPorts`, `tlsCert` и `httpBanner`. Для VPN endpoint TLS и HTTP banner могут быть отключены и возвращать `null`.
* `KeyHealthChecker` возвращает список результатов с `profileId`, `online`, `latencyMs`, `reason`, `egressIp` и `country` и обновляет профильные поля проверки здоровья.
* `ServerDetailModal` обращается к `https://ipapi.co/{ip}/json/` и при ошибке к `https://ipwho.is/{ip}` непосредственно из renderer. Политика допустимости таких запросов остаётся открытым вопросом из F-158.
* `liveServerProbe` вызывает `liveServerHistory.getPreviousSuccessfulCheck`, `computeHistoryDiff` и `liveServerHistory.addCheck` для завершенного результата.
* IPC-канал `server:live-check-history` принимает необязательный фильтр `profileId` или `host` и возвращает `LiveServerCheck[]`.
* Preload предоставляет renderer метод `serverLiveCheckHistory`, который вызывает `server:live-check-history`.
* `LiveServerCheck.infrastructure.changesFromPrevious` передает в renderer признаки диффа, включая `ipChanged`, `tlsCertChanged`, `asnChanged`, `countryChanged`, `portsChanged`, `latencySpike`, `handshakeChanged`, `egressChanged`, `pmtuChanged` и `throughputChanged`.

## Architecture Decision Records

### ADR-001: Разделение прямого ping и проверки ключа

**Context:** Прямое TCP/ICMP-подобное измерение endpoint и временный запуск VPN-движка отвечают на разные вопросы. Активный TUN также может изменить маршрут и сделать число задержки вводящим в заблуждение.

**Decision:** Хранить и отображать прямую задержку, результат проверки ключа и health latency как отдельные значения. При активном туннеле не сохранять пакетные значения, которые нельзя сопоставить с физическим маршрутом.

**Consequences:** Пользователь получает более точную интерпретацию результатов. В интерфейсе нужно явно различать метрики и их источник.

### ADR-002: Best-effort геолокация из renderer

**Context:** `ServerDetailModal` показывает страну и дополнительные сведения IP через внешние HTTPS-сервисы. F-158 фиксирует передачу адреса VPN-сервера из renderer, а F-072 указывает на отсутствие общего ограничения частоты запросов.

**Decision:** Сохранить наблюдаемое поведение с `ipapi.co` и fallback на `ipwho.is`, отключая запросы при пользовательской настройке privacy. Политику провайдеров, rate limiting и предупреждения оставить открытыми до отдельного решения.

**Consequences:** Детали сервера могут показать геоданные без зависимости от main process, но запрос раскрывает внешний IP провайдеру и может упереться в бесплатные лимиты.
