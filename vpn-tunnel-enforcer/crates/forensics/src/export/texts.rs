//! Fixed documents of the archive (Russian, as the old archive; B-34 fixed: loopback and own TUN
//! addresses are kept, not removed).
use serde_json::{Value, json};

/// `README.txt` (DX:338-371, Electron/Node lines removed, the pseudonym scheme as implemented).
pub(super) fn readme(created: &str) -> String {
    format!(
        "Диагностика VPN Tunnel Enforcer
Создано: {created}

Содержимое:
  diagnostics-manifest.json         - версия приложения, состав архива и политика редактирования секретов
  settings.json                     - текущие настройки приложения, секреты скрыты
  app-log.json                      - последние записи журналов приложения и движков
  system-info.json                  - версия Windows, память, CPU, версии движков
  system-diagnostics.json           - маршруты, proxy, DNS, firewall и итог проверок
  runtime-*.json, runtime-*.log     - конфигурация и журналы sing-box / Xray, секреты скрыты
  recovery-artifacts-status.json    - какие файлы состояния восстановления включены
  snapshots/                        - снимки состояния сети и системы
  traffic-forensics/                - packet/WFP/DNS/TCP артефакты для глубокого разбора
  traffic-forensics/REDACTION.txt   - как именно псевдонимизированы эти артефакты

Про traffic-forensics:
  Домены заменены на устойчивые токены (<domain-2>.ru и т.п.), публичные IP-адреса -
  на псевдонимы ip_xxxxxxxx, такие же, как в журналах. Связки DNS → соединение →
  reset → drop разбираются как раньше, сами адреса в архив не попадают.
  Подробности - в traffic-forensics/REDACTION.txt.

  Raw-захваты пакетов (*.etl, *.pcapng, pktmon-trace.txt) в архив НЕ включены:
  они содержат payload целиком. Путь к ним локально есть в логе приложения -
  если поддержка попросит именно их, их нужно приложить осознанно.

Что в архиве всё равно остаётся:
  Имя компьютера, версия ОС, состав адаптеров, названия интерфейсов и структура
  маршрутов, адреса в снимках состояния и системной диагностике - этого требует
  разбор сетевых проблем.

Архив подготовлен для поддержки или повторного локального разбора.
"
    )
}

/// `traffic-forensics/REDACTION.txt` (TF:1347-1371 for the scheme actually applied).
pub(super) fn redaction(domains: usize) -> String {
    format!(
        "Артефакты traffic-forensics псевдонимизированы.

Каждое уникальное значение заменено на устойчивый токен, одинаковый во всех файлах архива:
  ip_xxxxxxxx      - публичный IPv4 / IPv6 (тот же псевдоним, что и в журналах; важно
                     для анализа утечек: адрес вне туннеля)
  <redacted-mac>   - MAC-адрес
  <domain-N>.tld   - домен; публичный суффикс сохранён, чтобы был виден
                     разбор smart-RU (.ru против остальных)
  <subN>.          - глубина поддомена
  <host-N>         - имя, которое само является публичным суффиксом
  <user>           - имя пользователя Windows

Один и тот же токен = один и тот же адрес. Связки DNS → flow → reset → drop
сохраняются, сами адреса в архив не попадают. Таблица соответствия доменов нигде не
сохраняется и существует только в памяти во время экспорта.

Сохранены как есть: loopback (127.0.0.0/8, ::1), частные, CGNAT и link-local адреса
и адреса собственного TUN-интерфейса - без них не читается вывод про tunPathConfirmed.

НЕ включены в архив вообще: raw-захваты пакетов (*.etl, *.pcapng,
pktmon-trace.txt). Они содержат payload целиком и не поддаются редактированию.
Локальный путь к ним есть в логе приложения.

Заменено уникальных доменов: {domains}
"
    )
}

/// `redaction` block of `diagnostics-manifest.json` (DX:373-403, for this scheme).
pub(super) fn policy(forensics_included: bool) -> Value {
    let forensics = if forensics_included {
        "public IPs are ip_ pseudonyms (as in the logs), host names are stable per-export \
         <domain-N> tokens with the public suffix kept, MACs and user names are masked. \
         See traffic-forensics/REDACTION.txt"
    } else {
        "not included in this bundle"
    };
    json!({
        "settings": "secret keys, proxy credentials and non-local proxy hosts are redacted; \
                     the log pseudonym key is not exported",
        "runtimeJson": "engine configs are parsed; server addresses, ids, keys and other secret \
                        keys are redacted",
        "logs": "logs are redacted when written (secrets masked, public IPs as ip_ pseudonyms) \
                 and scrubbed again",
        "snapshots": "snapshot, diagnostics and recovery JSON: secret-named keys and \
                      secret-shaped values are redacted; addresses are kept",
        "trafficForensics": forensics,
        "rawPacketCaptures": "excluded entirely (*.etl, *.pcapng, pktmon-trace.txt): payloads \
                              cannot be redacted",
        "notRedacted": "hostname, OS build, adapter names and aliases, private addresses and \
                        route structure are kept: network diagnosis is not possible without them",
    })
}
