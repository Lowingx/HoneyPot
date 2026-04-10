# Explicação Técnica Completa — Honeypot v2

> Documento de aprendizado separado do README.
> Foco nas novas funcionalidades da v2 e nos conceitos de segurança aprofundados.

---

## 1. O que mudou da v1 para a v2 — e por quê

| Funcionalidade | v1 | v2 |
|---|---|---|
| Formato de log | `.json` (array) | `.jsonl` (NDJSON, uma linha por evento) |
| Classificação de ataque | ❌ | ✅ `attack_type` em cada evento |
| Fingerprinting de ferramenta | Básico | 20+ assinaturas (Nuclei, sqlmap, libssh…) |
| Severidade | ❌ | ✅ CRITICAL/HIGH/MEDIUM/LOW/INFO |
| Correlação multi-serviço | ❌ | ✅ mesmo IP em SSH + HTTP |
| Timeline por IP | ❌ | ✅ first_seen, last_seen, duration |
| GeoIP / ASN | ❌ | ✅ (opcional, graceful fallback) |
| Live tail mode | ❌ | ✅ `--live` |
| Auto-report bundle | ❌ | ✅ txt + md + json de uma vez |
| Módulo separado de detecção | ❌ | ✅ `detection.py` testável |

---

## 2. JSONL — por que um formato por linha

```python
self._file.write(json.dumps(event, ensure_ascii=False) + "\n")
```

**NDJSON (Newline-Delimited JSON)**, também chamado de JSONL, é o formato padrão de logging em segurança moderna. Cada linha é um objeto JSON válido e independente.

**Por que não JSON em array (`[{...}, {...}]`)?**

| Situação | JSON Array | JSONL |
|---|---|---|
| Adicionar evento sem reescrever arquivo | ❌ precisa abrir e fechar | ✅ `append` |
| `tail -f` em tempo real | ❌ arquivo parcial é inválido | ✅ cada linha válida |
| Ingestão no Elastic/Splunk | ❌ precisa parser especial | ✅ nativo |
| Filtrar com `jq` | Possível mas lento | ✅ direto |
| Arquivo de 10 GB de eventos | ❌ precisa carregar tudo | ✅ stream linha a linha |

**Integração com ferramentas reais:**
```bash
# Elastic Filebeat entende JSONL nativamente
filebeat -e -c filebeat.yml  # aponte para logs/honeypot_events.jsonl

# jq filtra linha a linha — sem carregar o arquivo inteiro
jq 'select(.severity == "CRITICAL")' logs/honeypot_events.jsonl
```

---

## 3. `detection.py` — separação de responsabilidades

Na v1, toda a lógica estava em um arquivo só. Na v2, criamos `detection.py` como módulo independente.

**Por que isso importa?**

```python
# Você pode testar a lógica de detecção sem precisar do servidor rodando
from detection import classify_attack, fingerprint_tool, score_severity

ev = {"service": "ssh", "event_type": "auth_attempt", "username": "root", "password": "toor"}
history = {"1.2.3.4": [ev, ev, ev, ev]}

assert classify_attack(ev, history) == "brute_force"
assert fingerprint_tool({"client_banner": "SSH-2.0-libssh_0.9.6"}).name == "libssh"
```

Isso segue o princípio **Single Responsibility** — cada módulo tem uma razão para existir. Em projetos maiores, `detection.py` poderia evoluir para um serviço separado consumindo eventos via fila (Kafka, Redis Streams).

---

## 4. Classificação de `attack_type`

```python
def classify_attack(event: dict, ip_history: dict) -> str:
```

A função recebe o evento atual e o histórico de eventos do mesmo IP. A classificação é **stateful** — o mesmo tipo de evento pode ter classificações diferentes dependendo do contexto.

### Lógica de decisão

```
Evento SSH auth_attempt:
  └── past_auth_attempts >= 3?
        ├── SIM  → brute_force
        └── NÃO  → credential_attempt

Evento HTTP request com username:
  └── past_auth_attempts >= 3?
        ├── SIM  → brute_force
        └── NÃO  → credential_attempt

Evento HTTP GET sem credenciais:
  └── path em VULN_SCAN_PATHS?
        ├── SIM  → vuln_scan
        └── NÃO  → path em RECON_PATHS?
              ├── SIM  → recon
              └── NÃO  → past_http_requests >= 5?
                    ├── SIM  → recon (directory scan)
                    └── NÃO  → automation_tool
```

**Por que o threshold de 3 para brute_force?** Um usuário legítimo que esquece a senha tenta no máximo 2-3 vezes. A partir de 4 tentativas do mesmo IP, o padrão automatizado é quase certo.

### Paths de vuln scan vs recon

```python
VULN_SCAN_PATHS = {
    "/.env",         # credenciais de ambiente (muito comum em ataques reais)
    "/.git/config",  # expõe repositório Git completo
    "/wp-config.php",# credenciais do banco WordPress
    "/shell.php",    # webshell
    ...
}

RECON_PATHS = {
    "/robots.txt",   # lista o que o dono não quer indexado (útil para attackers)
    "/sitemap.xml",  # mapa de todos os paths do site
    ...
}
```

A distinção é importante: `/.env` é ativamente malicioso (o atacante quer credenciais específicas), enquanto `/robots.txt` é passivo (coleta informações sobre a estrutura do site).

---

## 5. Tool fingerprinting com regex

```python
TOOL_SIGNATURES: list[tuple[re.Pattern, ToolSignature]] = [
    (re.compile(r"Nuclei", re.I),
        ToolSignature("Nuclei", "scanner", "high")),
    (re.compile(r"libssh[_/](\S+)", re.I),
        ToolSignature("libssh", "bruteforce", "high")),
    ...
]
```

**Por que regex e não `str.contains()`?**

Regex permite capturar variantes:
- `libssh_0.9.6`, `libssh/0.8.1`, `libssh-1.0` — todas combinam com `libssh[_/](\S+)`
- Sem regex, precisaríamos de múltiplas condições

**Ordem importa:** padrões mais específicos primeiro. Se `Nuclei - Open-source project` viesse depois de `python-requests`, e o User-Agent contivesse ambos, o resultado errado seria retornado.

**O que cada campo `ToolSignature` significa:**

```python
@dataclass
class ToolSignature:
    name:     str   # nome legível da ferramenta
    category: str   # scanner | exploit_framework | bruteforce | crawler
    risk:     str   # low | medium | high
```

- `scanner` — ferramentas de reconhecimento (Nuclei, Nikto, nmap)
- `exploit_framework` — frameworks ofensivos (Metasploit, sqlmap, ZmEu)
- `bruteforce` — ferramentas de força bruta (libssh, Paramiko, JSch)
- `crawler` — automação genérica (python-requests, curl, wget)

**Como isso aparece no relatório:**
```
TOOL FINGERPRINTS
  libssh           3x    ← ferramentas de brute force SSH
  Nuclei           3x    ← scanner de vulnerabilidades
  Paramiko         2x    ← biblioteca Python usada em scripts de ataque
```

---

## 6. Severity scoring: a matriz de decisão

```python
_SEVERITY_MATRIX = {
    ("brute_force", "high",   True):  "CRITICAL",  # brute force + ferramenta agressiva + multi-serviço
    ("brute_force", "high",   False): "CRITICAL",  # brute force + ferramenta agressiva
    ("brute_force", "medium", True):  "CRITICAL",  # brute force + multi-serviço já eleva
    ("brute_force", "medium", False): "HIGH",
    ...
}
```

**Três eixos de risco:**

1. **attack_type** — o que o atacante está fazendo (brute_force é pior que recon)
2. **tool_risk** — quão agressiva é a ferramenta usada (Metasploit = high, curl = low)
3. **multi_service** — o mesmo IP atacando SSH e HTTP simultaneamente indica automação coordenada

**Por que a matriz e não uma fórmula numérica?**

Uma fórmula como `score = attack_weight + tool_weight + multi_weight` pareceria mais elegante, mas:
- É difícil de auditar ("por que esse evento é CRITICAL e não HIGH?")
- Pequenas mudanças nos pesos têm efeitos imprevisíveis
- Uma matriz explícita é legível, versionável e auditável — qualidades essenciais em segurança

---

## 7. `EventStore` — correlação em memória

```python
class EventStore:
    MAX_PER_IP = 200

    def __init__(self):
        self._history:  dict[str, list] = defaultdict(list)
        self._services: dict[str, set]  = defaultdict(set)

    def is_multi_service(self, ip: str) -> bool:
        return len(self._services.get(ip, set())) > 1
```

**Por que limitar a 200 eventos por IP?**

Em um ataque de brute force intenso, um único IP pode gerar milhares de eventos por minuto. Sem limite, um único atacante poderia consumir toda a memória disponível — um tipo de DoS involuntário contra o próprio honeypot.

200 eventos é suficiente para detectar todos os padrões relevantes (brute force é identificado com 3-5 tentativas, multi-service com 1 evento por serviço).

**O que `is_multi_service` detecta na prática?**

Um atacante sofisticado que usa um framework de ataque unificado (ex: um script personalizado ou Metasploit com múltiplos módulos) vai atacar SSH e HTTP do mesmo IP quase simultaneamente. Isso é um indicador forte de:
- Ataque automatizado e coordenado
- Possível reconhecimento abrangente (o atacante quer mapear toda a superfície de ataque)

---

## 8. GeoIP: integração opcional com graceful fallback

```python
class GeoIPEnricher:
    def __init__(self, city_db=None, asn_db=None):
        self._city_reader = None
        self._asn_reader  = None
        if not _GEOIP2_AVAILABLE:
            return   # biblioteca não instalada — funciona sem ela
        try:
            if city_db:
                self._city_reader = geoip2.database.Reader(city_db)
        except Exception:
            pass     # arquivo não encontrado — funciona sem ele
```

**O padrão "graceful fallback"** é essencial em ferramentas de segurança: a ferramenta nunca deve falhar completamente por causa de uma dependência opcional. O honeypot captura eventos e classifica ataques mesmo sem GeoIP — o enriquecimento é um bônus.

**Por que ASN é tão valioso quanto o país?**

- País pode ser enganado com VPN
- ASN (Autonomous System Number) identifica o provedor de rede
- Atacantes em `AS14061` (DigitalOcean), `AS16509` (Amazon AWS), `AS15169` (Google Cloud) são comuns — indicam VPS alugados para ataques
- Atacantes em `AS7162` (Claro Brasil) sugerem IP residencial comprometido ou atacante local

```json
"geo": {
  "country": "Netherlands",
  "asn": "AS60781",
  "org": "LeaseWeb Netherlands B.V."   // hosting provider popular para ataques
}
```

---

## 9. `analyzer.py` — timeline por IP

```python
for ip in ip_events:
    first  = ip_first_seen.get(ip, "")
    last   = ip_last_seen.get(ip, "")
    dt_first   = datetime.fromisoformat(first)
    dt_last    = datetime.fromisoformat(last)
    duration_s = int((dt_last - dt_first).total_seconds())
```

**Por que `duration_s` é um indicador relevante?**

- `duration_s = 0` → uma conexão única, scanner rápido que não encontrou nada interessante
- `duration_s = 60s com 50 tentativas` → brute force automatizado (0.8 tentativas/segundo)
- `duration_s = 3600s com 5 tentativas` → reconhecimento manual ou tentativa de evasão

Scanners automatizados tendem a ser rápidos e uniformes. Atacantes humanos tendem a ter intervalos irregulares e longos. Essa diferença é usada em sistemas de detecção avançados.

---

## 10. Live tail mode

```python
def live_tail(log_path: Path, interval: float = 1.0) -> None:
    seen_lines = 0
    while True:
        lines     = log_path.read_text().splitlines()
        new_lines = lines[seen_lines:]
        for line in new_lines:
            ev = json.loads(line)
            # ... formata e imprime
        seen_lines = len(lines)
        time.sleep(interval)
```

**Por que não usar `inotify` ou `watchdog`?**

- `inotify` (Linux) e `watchdog` (cross-platform) são mais eficientes, mas são dependências externas
- A solução de polling com `time.sleep(1.0)` é portátil (Linux, macOS, Windows) e suficiente para monitoramento humano
- 1 segundo de latência é imperceptível para um analista olhando a tela

Em produção real, você usaria Filebeat + Kibana para live monitoring — mas a lógica aqui demonstra o conceito de forma clara e independente.

---

## 11. Auto-report bundle

```python
def auto_report(data: dict, output_dir: Path) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    for fmt, renderer, ext in [
        ("text",     render_text,     "txt"),
        ("markdown", render_markdown, "md"),
        ("json",     render_json,     "json"),
    ]:
        path = output_dir / f"report_{ts}.{ext}"
        path.write_text(renderer(data))
```

**Por que três formatos?**

- `.txt` → para ler no terminal imediatamente
- `.md` → para incluir em relatórios de incidente no GitHub/Confluence
- `.json` → para integrar com outras ferramentas, scripts, dashboards

O timestamp no nome (`report_20240110_080000.txt`) permite manter histórico de relatórios sem sobrescrever.

---

## 12. Conceitos de segurança aprendidos aqui

| Conceito | Onde aparece |
|---|---|
| Low-interaction honeypot | Arquitetura geral |
| SSH banner e protocol fingerprinting | `SSH_BANNER`, `client_banner` |
| Tarpitting | `--delay`, `asyncio.sleep` |
| Brute force vs credential stuffing | `classify_attack` com histórico |
| Directory scanning e vuln scanning | `VULN_SCAN_PATHS`, `RECON_PATHS` |
| Tool fingerprinting (OSINT/TI) | `TOOL_SIGNATURES`, regex patterns |
| Severity scoring | `_SEVERITY_MATRIX` |
| Multi-service correlation | `EventStore.is_multi_service` |
| GeoIP / ASN intelligence | `GeoIPEnricher` |
| NDJSON / structured logging | `HoneypotLogger` |
| Graceful degradation | GeoIP fallback sem crash |
| Attacker timeline analysis | `analyze()` em `analyzer.py` |
| Log tailing em tempo real | `live_tail()` |

---

## 13. Como conecta com os próximos projetos

**Projeto 3 — Threat Intelligence Feed Parser:**
Os IPs capturados pelo honeypot serão verificados contra feeds públicos de Threat Intelligence (AbuseIPDB, AlienVault OTX). O parser consome esses feeds e enriquece ainda mais os eventos.

**Projeto 4 — SIEM com Elastic Stack:**
O JSONL produzido é o formato nativo do Filebeat. Apontar o Filebeat para `logs/honeypot_events.jsonl` já popula o Elasticsearch — os campos `attack_type`, `severity` e `geo` aparecem automaticamente como filtros no Kibana.

**Projeto 5 — Network Traffic Analyzer:**
O honeypot captura o conteúdo da sessão. O analisador de tráfego captura os pacotes. Juntos, você tem visibilidade em duas camadas: o que chegou na rede (PCAP) e o que aconteceu dentro da sessão (eventos do honeypot).

---

*Este documento faz parte da trilha de portfólio Blue Team / SOC.*
*Cada projeto da trilha constrói sobre os conceitos do anterior.*
