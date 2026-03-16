# GuAI — System Guardian AI

Autonomiczny straznik bezpieczenstwa systemu Windows oparty na architekturze hybrydowej: lokalny engine monitoringu + MCP integration z Claude Code.

## Architektura

```text
SecurityEvent → EventBus → RuleEngine → AlertManager → AlertStore + Channels
                              ↓
                          EventStore (SQLite)
```

**Warstwy:**

- **Monitory** — zbieranie danych (psutil, netsh, Event Log, BLE)
- **Event Bus** — async pub/sub z filtrowaniem i drop strategy
- **Rules Engine** — YAML-based detection rules z MITRE ATT&CK mapping
- **Alert System** — deduplikacja, kanaly (CLI/Rich), lifecycle management
- **Storage** — SQLite (WAL mode) z retention i batch insert
- **MCP Server** — integracja z Claude Code (tools + resources)
- **CLI** — asyncclick + Rich dashboard

## Instalacja

```bash
# Z pip (editable)
pip install -e ".[windows,mcp]"

# Lub z uv
uv sync --all-extras
```

Wymaga Python >= 3.11.

## Uruchomienie

```bash
# Start monitoringu (domyslny config)
guai start

# Z jawna sciezka do configu
guai start --config config/guai.toml

# Lub jako modul
python -m guai start
```

### Komendy CLI

| Komenda        | Opis                                          |
| -------------- | --------------------------------------------- |
| `guai start` | Uruchom monitoring systemu |
| `guai status` | Pokaz health + statystyki |
| `guai alerts` | Lista alertow (--severity, --since, --limit) |

## Konfiguracja

Plik: `config/guai.toml` (przyklad: `config/guai.example.toml`)

```toml
[general]
log_level = "INFO"          # DEBUG|INFO|WARNING|ERROR|CRITICAL
data_dir = "data"

[monitoring]
network_interval = 5.0      # sekundy
process_interval = 5.0
event_log_interval = 3.0
wifi_interval = 10.0
bluetooth_interval = 15.0
dns_interval = 10.0
min_interval = 0.5          # adaptacyjne probkowanie (min)
max_interval = 30.0         # adaptacyjne probkowanie (max)
enabled_monitors = ["network", "process", "event_log", "wifi", "bluetooth", "dns"]

[monitoring.event_log]
critical_event_ids = [4625, 4688, 1102, 7045, 4697]

[storage]
db_path = "data/guai.db"
retention_days = 30
batch_size = 50

[event_bus]
max_queue_size = 10000
drop_strategy = "oldest"    # oldest | newest | none

[alerts]
suppress_window_minutes = 15
max_alerts_per_minute = 100
enabled_channels = ["cli"]

[rules]
rules_dir = "config/rules"
```

## Monitory

| Monitor | Zrodlo danych | Wykrywa |
|---------|---------------|---------|
| **NetworkMonitor** | `psutil.net_connections()` | Nowe polaczenia TCP/UDP, stany (ESTABLISHED, CLOSE_WAIT, SYN_SENT) |
| **ProcessMonitor** | `psutil.process_iter()` | Nowe procesy, suspicious parent-child (np. WINWORD→cmd.exe) |
| **EventLogMonitor** | `win32evtlog` | Failed logon (4625), log cleared (1102), new service (7045), process creation (4688) |
| **WiFiMonitor** | `netsh wlan` | Nowe sieci WiFi, otwarte sieci (brak auth) |
| **BluetoothMonitor** | `bleak` (BLE) | Nowe/znikajace urzadzenia Bluetooth |
| **DNSMonitor** | `ipconfig /displaydns` | Nowe DNS records, DGA-like domains (entropia Shannon) |

Kazdy monitor dziedziczy z `BaseMonitor` i implementuje `async stream() → AsyncIterator[SecurityEvent]`.

Monitory maja graceful degradation — jesli brak wymaganych uprawien lub bibliotek, przechodza w tryb DEGRADED zamiast crash.

## Reguly detekcyjne

Reguly sa definiowane w YAML w katalogu `config/rules/`:

| Regula | Severity | MITRE | Opis |
|--------|----------|-------|------|
| `brute_force.yaml` | HIGH | T1110.001 | 5+ failed logon w 60s |
| `suspicious_process.yaml` | HIGH | T1059.001 | Shell spawned z Office app |
| `log_clearing.yaml` | CRITICAL | T1070.001 | Security log cleared |
| `new_service.yaml` | MEDIUM | T1543.003 | Nowy Windows service |

### Format reguly

```yaml
name: brute_force_detection
description: Multiple failed logon attempts in short time window
severity: 3                    # 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
source: event_log
conditions:
  category: auth
  data.event_id: 4625          # dot-notation do pol w event.data
window_seconds: 60             # 0 = instant trigger
threshold: 5                   # ile matchow w oknie
mitre_technique: "T1110.001"
enabled: true
```

**Operatory w conditions:**
- Bare value — equality (`data.event_id: 4625`)
- `{eq: value}` — explicit equality
- `{contains: str}` — substring
- `{regex: pattern}` — regex
- `{gt: n}`, `{gte: n}`, `{lt: n}`, `{lte: n}` — porownania
- `{in: [a, b, c]}` — lista dozwolonych

## MCP Integration (Claude Code)

GuAI wystawia MCP server z toolami i zasobami do integracji z Claude Code.

### Konfiguracja MCP

Plik `.mcp.json` w katalogu projektu:

```json
{
  "mcpServers": {
    "guai": {
      "command": ".venv/Scripts/python",
      "args": ["-m", "guai.mcp.server"],
      "env": {
        "GUAI_CONFIG": "config/guai.toml"
      }
    }
  }
}
```

### MCP Tools

| Tool | Opis |
|------|------|
| `guai_status()` | Status systemu: health, event/alert counts, rules loaded |
| `guai_events(since, severity, category, limit)` | Query eventow z filtrami |
| `guai_alerts(severity, status, limit)` | Lista alertow z filtrami |
| `guai_alert_ack(alert_id)` | Potwierdz alert |
| `guai_rules()` | Lista loaded rules |
| `guai_event_stats()` | Statystyki by category/severity/time range |

### MCP Resources

| URI | Opis |
|-----|------|
| `guai://config` | Aktualna konfiguracja (JSON) |
| `guai://rules/{rule_name}` | Konkretna regula |

## Modele danych

### SecurityEvent

```python
SecurityEvent(
    event_id: str,          # UUID
    timestamp: datetime,    # UTC
    source: str,            # "network_monitor", "process_monitor", ...
    severity: Severity,     # LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4
    category: str,          # "network", "process", "auth", "security", ...
    data: dict[str, Any],   # payload specyficzny dla monitora
    trust_level: TrustLevel,# UNTRUSTED | SEMI_TRUSTED | TRUSTED
    mitre_technique: str | None
)
```

### Alert

```python
Alert(
    alert_id: str,
    timestamp: datetime,
    severity: Severity,
    title: str,
    description: str,
    source_events: list[str],   # event IDs
    status: AlertStatus,        # NEW → ACKNOWLEDGED → RESOLVED | SUPPRESSED
    mitre_technique: str | None,
    rule_name: str | None
)
```

## Struktura projektu

```
sGuAI/
├── config/
│   ├── guai.toml              # Konfiguracja produkcyjna
│   ├── guai.example.toml      # Przyklad konfiguracji
│   └── rules/                 # Reguly detekcyjne (YAML)
│       ├── brute_force.yaml
│       ├── log_clearing.yaml
│       ├── new_service.yaml
│       └── suspicious_process.yaml
├── src/guai/
│   ├── core/                  # Jadro systemu
│   │   ├── app.py             # GuAIApp — orkiestrator
│   │   ├── config.py          # GuAIConfig (Pydantic + TOML)
│   │   ├── event_bus.py       # Async pub/sub event bus
│   │   ├── scheduler.py       # Periodyczne taski
│   │   ├── models.py          # SecurityEvent, Alert
│   │   ├── types.py           # Severity, TrustLevel, AlertStatus, ...
│   │   ├── exceptions.py      # Hierarchia wyjatkow
│   │   └── logging_setup.py   # structlog + redakcja sensitive fields
│   ├── monitors/              # Monitory systemowe
│   │   ├── base.py            # BaseMonitor (abstract)
│   │   ├── sampling.py        # AdaptiveSampler
│   │   ├── network.py         # NetworkMonitor (psutil)
│   │   ├── process.py         # ProcessMonitor (psutil)
│   │   ├── event_log.py       # EventLogMonitor (win32evtlog)
│   │   ├── wifi.py            # WiFiMonitor (netsh)
│   │   ├── bluetooth.py       # BluetoothMonitor (bleak)
│   │   └── dns.py             # DNSMonitor (ipconfig + entropy)
│   ├── rules/                 # Silnik regul
│   │   ├── models.py          # DetectionRule, RuleMatch
│   │   ├── matcher.py         # RuleMatcher (operatory, dot-notation)
│   │   └── engine.py          # RuleEngine (load, evaluate, threshold)
│   ├── alerts/                # System alertow
│   │   ├── dedup.py           # AlertDeduplicator (SHA256 fingerprint)
│   │   ├── channels.py        # AlertChannel, CLIChannel (Rich)
│   │   └── manager.py         # AlertManager (orchestration)
│   ├── storage/               # Warstwa persystencji
│   │   ├── database.py        # Database (async SQLite, WAL)
│   │   ├── event_store.py     # EventStore (CRUD, batch, retention)
│   │   └── alert_store.py     # AlertStore (CRUD, acknowledge, resolve)
│   ├── mcp/                   # MCP server
│   │   ├── server.py          # FastMCP server (tools + resources)
│   │   └── tools.py           # Helpery (parse_since, format_*)
│   ├── cli/                   # CLI interface
│   │   ├── main.py            # Click group entry point
│   │   ├── dashboard.py       # Rich dashboard
│   │   └── commands/
│   │       ├── start.py       # guai start
│   │       ├── status.py      # guai status
│   │       └── alerts.py      # guai alerts
│   ├── __init__.py
│   └── __main__.py            # python -m guai
├── tests/
│   ├── conftest.py            # Fixtures (tmp_config, tmp_db_path)
│   ├── unit/                  # 16 unit test modules
│   └── integration/           # test_app.py, test_cli.py
├── data/                      # Runtime data (guai.db)
├── docs/
│   └── PLAN.md                # Oryginalny plan implementacji
├── pyproject.toml
└── .mcp.json                  # MCP server config dla Claude Code
```

## Testy

```bash
# Wszystkie testy
pytest tests/ -v

# Tylko unit
pytest tests/unit/ -v

# Tylko integracyjne
pytest tests/integration/ -v

# Z coverage
pytest tests/ --cov=guai --cov-report=term-missing

# Linting
ruff check src/

# Type checking
mypy src/guai/
```

## Wymagania systemowe

- **OS:** Windows 10/11
- **Python:** >= 3.11
- **Uprawnienia:** Administrator (zalecane, wymagane dla Event Log Security)
- **Opcjonalne:** Bluetooth adapter (dla BluetoothMonitor), WiFi adapter (dla WiFiMonitor)

## Stack technologiczny

| Komponent | Technologia |
|-----------|-------------|
| Async runtime | asyncio + anyio |
| Konfiguracja | Pydantic Settings + TOML |
| Logging | structlog (JSON/console) |
| CLI | asyncclick + Rich |
| Baza danych | aiosqlite (SQLite WAL) |
| System monitoring | psutil |
| Windows Event Log | pywin32 (win32evtlog) |
| Bluetooth | bleak (BLE) |
| MCP server | mcp (FastMCP) |
| Testy | pytest + pytest-asyncio |
| Linting | ruff |
| Types | mypy (strict) |

## Licencja

MIT
