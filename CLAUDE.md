# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SPECTRE (Security Platform for Enrichment, Collection, Threat Research & Evaluation) is an open-source, self-hosted, agentic intelligence platform that combines OSINT research automation with continuous cyber threat intelligence monitoring.

**Current Status:** Active development - Phases 1-5.2 complete, Phase 6 in progress (heartbeat engine done, campaign tracking pending).

### Core Thesis

Existing OSINT tools (SpiderFoot, Recon-ng, Maltego) are powerful but fragmented, manual, and reactive. SPECTRE adds an agentic orchestration layer:
1. Natural language interface via CLI, Slack, Discord, or Telegram
2. Autonomous investigation planning - AI decides which tools/APIs to query
3. Cross-source correlation and synthesized intelligence reports
4. Continuous monitoring with proactive alerting

## Architecture

### 5-Layer Architecture
```
[1] INTERFACE LAYER      CLI (Typer) | Slack | Discord | Telegram | Web UI
[2] AGENT CORE           Task Planner | Tool Router | Memory/State | Report Generator
[3] PLUGIN ENGINE        OSINT Plugins | Threat Intel Plugins | Adversary Plugins
[4] DATA LAYER           Entity Graph (SQLite/Neo4j) | Investigation Store | Cache
[5] INFRASTRUCTURE       Docker | Scheduler/Heartbeat | Secrets Vault | Sandboxing
```

### Core Components

#### Agent Core (`spectre/agent/`)
The orchestration engine. When a user sends a query:
- Parses intent and extracts target entities (domains, IPs, emails, orgs, hashes)
- Builds investigation plan as execution DAG of plugin calls
- Executes plan with failure handling and adaptation
- Correlates results across plugins, resolving entities and detecting relationships
- Generates structured intelligence reports with confidence scores and source citations
- Stores findings in entity graph for future reference

#### Plugin Engine (`spectre/plugins/`)
Every data source, tool, and integration is a plugin:
```python
class SpectrePlugin(ABC):
    name: str                           # Unique identifier
    description: str                    # What this plugin does (for AI routing)
    input_types: list[EntityType]       # What entities it accepts
    output_types: list[EntityType]      # What entities it produces
    required_config: list[str]          # API keys, credentials needed
    rate_limit: RateLimit | None        # Optional rate limiting

    @abstractmethod
    async def execute(self, input: Entity, config: Config) -> PluginResult: ...

    @abstractmethod
    async def health_check(self) -> bool: ...
```

#### Entity Graph (`spectre/models/graph.py`)
SQLite-backed graph with FTS5 for full-text search. All entity types follow STIX 2.1 semantics:

| Entity Type | Key Attributes | Relationships |
|-------------|----------------|---------------|
| Domain | registrar, creation_date, nameservers, dns_records | resolves_to (IP), registered_by (Person/Org) |
| IP Address | asn, geolocation, open_ports, services | hosts (Domain), belongs_to (ASN), flagged_by (ThreatFeed) |
| Email | provider, breach_count, associated_domains | registered (Domain), belongs_to (Person) |
| Person/Org | name, aliases, social_profiles | owns (Domain), operates (IP range) |
| Hash/IOC | type, first_seen, last_seen, malware_family | communicates_with (IP/Domain), distributed_via (URL) |
| Certificate | issuer, validity, SANs | secures (Domain), issued_to (Org) |
| Vulnerability | CVE, CVSS, affected_software | affects (Service), exploited_by (ThreatActor) |
| ThreatActor | name, aliases, type, motivation, sophistication, country_of_origin | attributed-to (IntrusionSet), uses (Malware/Tool/AttackPattern), targets (Sector/Org) |
| IntrusionSet | name, aliases, goals, resource_level, primary_motivation | attributed-to (ThreatActor), uses (AttackPattern/Malware) |
| Campaign | name, objective, first_seen, last_seen, status | attributed-to (ThreatActor), uses (Malware/Infrastructure), targets (Sector/Org) |
| AttackPattern | name, mitre_id, tactic, platform | used-by (ThreatActor/IntrusionSet/Campaign) |
| Malware | name, type, is_family, kill_chain_phases | used-by (ThreatActor), communicates-with (Infrastructure) |
| Tool | name, type, version | used-by (ThreatActor) |
| Infrastructure | name, type (C2, botnet, hosting) | hosts (Domain/IP), used-by (Campaign) |

#### Heartbeat Engine (`spectre/heartbeat/`)
Proactive monitoring with APScheduler. Users define watch conditions:
- "Alert me if any new subdomains appear for target.com"
- "Watch for any of our company IPs appearing on threat feeds"
- "Notify me if the SSL certificate for api.ourservice.com changes"
- "Monitor CVE feeds for vulnerabilities in our tech stack"
- "Track campaign:SolarWinds for new IOCs and infrastructure rotation"
- "Alert on any new ATT&CK techniques attributed to APT29"

## Adversary Intelligence Module

### Attribution Pipeline (`spectre/adversary/attributor.py`)
4-stage scoring pipeline when SPECTRE discovers infrastructure:

**STAGE 1: IOC Matching (weight: 0.40)**
- Check discovered IPs, domains, hashes against threat feed IOCs
- Match against known C2 infrastructure databases
- Cross-reference with MITRE ATT&CK indicators

**STAGE 2: Infrastructure Pattern Matching (weight: 0.25)**
- Group related infrastructure by shared registration, hosting, or DNS patterns
- Compare clusters to known intrusion set infrastructure signatures
- Detect passive DNS overlaps with historical threat actor domains

**STAGE 3: TTP Fingerprinting (weight: 0.20)**
- Analyze detected services, configurations, and behaviors
- Match patterns against known TTP profiles
- Compare SSL certificate patterns, WHOIS registrant behaviors

**STAGE 4: AI Synthesis (weight: 0.15)**
- LLM synthesizes all signals with context from MITRE ATT&CK
- Produces attribution assessment with confidence level:
  - HIGH (80-100): Multiple strong indicators match a single actor
  - MEDIUM (50-79): Several indicators suggest an actor but with ambiguity
  - LOW (20-49): Weak or circumstantial indicators only
  - UNATTRIBUTED (<20): Insufficient data for any assessment
- Always presents alternative hypotheses when confidence < HIGH

### Threat Actor Dossier Generation (`spectre/adversary/profiler.py`)

| Section | Content | Data Sources |
|---------|---------|--------------|
| Identity | Name, aliases, type, suspected origin, motivation | MITRE ATT&CK, OpenCTI, Malpedia |
| Activity Timeline | First seen, last seen, activity periods, dormancy patterns | Threat feeds, MITRE campaigns |
| Victimology | Targeted sectors, regions, specific organizations | MITRE ATT&CK, OTX pulses |
| Arsenal | Malware families, custom tools, shared/commodity tools | Malpedia, MITRE software, VT |
| TTPs (ATT&CK Map) | Full MITRE ATT&CK technique matrix | MITRE ATT&CK Groups data |
| Infrastructure | Known C2 servers, domains, hosting preferences | OSINT findings + threat feeds |
| Campaigns | Named campaigns with timelines, objectives, targets, IOCs | MITRE campaigns, CTI reports |
| Indicators | Active IOCs with last-seen dates | All threat intel plugins |
| Evolution | How TTPs have changed over time | Temporal analysis |
| Related Actors | Known collaborations, shared infrastructure | Graph relationship analysis |

### Campaign Tracking (`spectre/adversary/campaign_tracker.py`)

**Known Campaign Ingestion:**
- Ingest named campaigns from MITRE ATT&CK (e.g., SolarWinds, C0015, Operation Dream Job)
- Pull campaign data from OpenCTI including IOCs, TTPs, and victimology
- Import campaign reports from OTX pulses with structured indicator extraction
- Link all campaign IOCs to entity graph for automatic cross-investigation matching

**Campaign Detection (`spectre/adversary/campaign_detector.py`):**
AI-powered clustering to detect unreported campaigns:
- Temporal Clustering: Multiple targets seeing similar IOCs within a time window
- Infrastructure Overlap: Shared C2 servers, registrants, SSL certs, or hosting
- TTP Consistency: Same attack patterns used across different targets
- Tooling Fingerprint: Same malware families or custom tools deployed
- Victimology Pattern: Targets sharing sector, geography, or organizational characteristics

### MITRE ATT&CK Integration

**Data Ingestion:**
- Full STIX 2.1 dataset via TAXII 2.1 API from attack-taxii.mitre.org
- Enterprise, Mobile, and ICS matrices
- All 143+ groups with technique usage, software, and campaign data
- All 700+ techniques and sub-techniques with detection guidance
- Automatic refresh on configurable schedule (default: weekly)

**Automatic TTP Tagging (`spectre/adversary/ttp_analyzer.py`):**

| Finding | Auto-Tagged Technique | Reasoning |
|---------|----------------------|-----------|
| Open RDP port (3389) | T1021.001 Remote Desktop Protocol | Exposed remote access service |
| Phishing domain mimicking target | T1566.003 Spearphishing via Service | Credential harvesting infrastructure |
| Cobalt Strike beacon on IP | T1071.001 Web Protocols (C2) | Known C2 framework |
| Mimikatz hash detected | T1003.001 LSASS Memory | Credential dumping tool |
| New subdomain with LE cert | T1583.001 Domains + T1588.004 Certs | Adversary infrastructure acquisition |
| CVE in detected service | T1190 Exploit Public-Facing Application | Known vulnerability |

**Additional ATT&CK Features:**
- ATT&CK Navigator layer export (JSON) for any actor, campaign, or investigation
- Side-by-side actor TTP comparison
- Detection gap analysis: compare actor TTPs against user's detection coverage matrix
- Temporal TTP evolution tracking

## MVP Plugin Roster

### OSINT Reconnaissance Plugins (`spectre/plugins/osint/`)

| Plugin | Data Source | Purpose |
|--------|-------------|---------|
| dns_recon | DNS resolvers + zone transfers | Enumerate DNS records, subdomains, mail servers |
| whois_lookup | WHOIS databases | Domain registration data, registrant info, dates |
| subdomain_enum | Certificate Transparency, brute, passive | Comprehensive subdomain discovery |
| port_scanner | Nmap (via wrapper) | Open ports and service identification |
| cert_transparency | crt.sh, Censys CT | Certificate history and SAN enumeration |
| web_tech_detect | Wappalyzer / httpx signatures | Identify web technologies, frameworks, CDNs |
| email_harvester | theHarvester, Hunter.io API | Email addresses associated with a domain |
| metadata_extract | ExifTool, FOCA-style | Document metadata from public files |
| wayback_machine | Wayback Machine CDX API | Historical snapshots and content changes |
| social_recon | Username enumeration across platforms | Social media presence mapping |

### Threat Intelligence Plugins (`spectre/plugins/threat_intel/`)

| Plugin | Data Source | Purpose |
|--------|-------------|---------|
| abuse_ch | URLhaus, MalwareBazaar, ThreatFox | Malware URLs, samples, IOCs |
| alienvault_otx | AlienVault OTX API | Community threat pulses, IOC enrichment |
| virustotal | VirusTotal API | Multi-engine file/URL/domain reputation |
| shodan_lookup | Shodan API | Internet-wide device and service exposure |
| greynoise | GreyNoise API | Distinguish targeted attacks from background noise |
| cve_monitor | NVD / CVE APIs | Vulnerability tracking for detected software |
| misp_feed | MISP community feeds | Structured threat intelligence in STIX format |
| spamhaus | Spamhaus DROP/EDROP | Known bad IP ranges and botnet C2s |

### Adversary Intelligence Plugins (`spectre/plugins/adversary/`)

| Plugin | Data Source | Purpose |
|--------|-------------|---------|
| mitre_attack | MITRE ATT&CK STIX/TAXII API | Full knowledge base: 143+ groups, 700+ techniques |
| mitre_groups | MITRE ATT&CK Groups endpoint | Detailed threat actor profiles with aliases, techniques |
| opencti_feed | OpenCTI API | Rich threat actor data: intrusion sets, campaigns, TTPs |
| malpedia | Malpedia API | Malware family profiles with actors, YARA rules |
| ransomlook | ransomlook.io API | Ransomware group tracking: leak sites, victim lists |

## Project Structure

```
spectre/
├── spectre/
│   ├── __init__.py
│   ├── cli/                        # Typer CLI commands
│   │   ├── __init__.py
│   │   ├── main.py                 # Entry point
│   │   ├── investigate.py          # Investigation commands
│   │   ├── monitor.py              # Watch/heartbeat commands
│   │   ├── actor.py                # Threat actor profile/search/compare commands
│   │   ├── campaign.py             # Campaign track/list/watch commands
│   │   └── threats.py              # Sector/region threat landscape commands
│   ├── agent/                      # Agent core
│   │   ├── planner.py              # Investigation planner
│   │   ├── executor.py             # Plugin execution engine
│   │   ├── correlator.py           # Cross-source entity correlation
│   │   ├── reporter.py             # Report generation
│   │   └── llm.py                  # Model-agnostic LLM interface
│   ├── adversary/                  # Adversary intelligence module
│   │   ├── __init__.py
│   │   ├── profiler.py             # Threat actor dossier generation
│   │   ├── attributor.py           # AI-driven attribution engine
│   │   ├── campaign_tracker.py     # Campaign lifecycle tracking
│   │   ├── campaign_detector.py    # Novel campaign detection
│   │   ├── ttp_analyzer.py         # ATT&CK technique mapping & auto-tagging
│   │   ├── ttp_timeline.py         # Temporal TTP analysis
│   │   └── gap_analyzer.py         # Detection gap analysis
│   ├── plugins/                    # Built-in plugins
│   │   ├── base.py                 # Plugin ABC interface
│   │   ├── registry.py             # Plugin discovery & loading
│   │   ├── osint/                  # OSINT plugins
│   │   ├── threat_intel/           # Threat intel plugins
│   │   └── adversary/              # Adversary intel plugins
│   ├── models/                     # Data models (Pydantic v2)
│   │   ├── entities.py             # Domain, IP, Email, Hash, etc.
│   │   ├── threat_actor.py         # ThreatActor, IntrusionSet
│   │   ├── campaign.py             # Campaign model
│   │   ├── attack_pattern.py       # ATT&CK technique model
│   │   ├── malware.py              # Malware and Tool models
│   │   ├── graph.py                # Entity graph operations
│   │   ├── investigation.py        # Investigation state
│   │   └── stix_export.py          # STIX 2.1 serialization
│   ├── adapters/                   # Chat platform adapters
│   │   ├── base.py
│   │   ├── slack.py
│   │   ├── discord.py
│   │   └── telegram.py
│   ├── heartbeat/                  # Proactive monitoring
│   │   ├── scheduler.py
│   │   └── watchers.py
│   ├── reports/                    # Report templates
│   │   ├── templates/
│   │   │   ├── investigation.j2
│   │   │   ├── actor_dossier.j2
│   │   │   ├── campaign_report.j2
│   │   │   ├── threat_landscape.j2
│   │   │   └── navigator_layer.j2
│   │   └── generator.py
│   └── config/                     # Configuration management
│       ├── settings.py
│       └── secrets.py
├── tests/
├── docs/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

## Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Language | Python 3.12+ | Richest OSINT/security ecosystem, async support, AI library maturity |
| Agent Framework | LangGraph or custom agent loop | Stateful, multi-step orchestration with tool routing |
| LLM Backend | Claude API (primary), OpenAI, Ollama (local) | Model-agnostic; user brings their own API key |
| Plugin System | Python ABC + entry_points | Pip-installable plugins, zero coupling |
| Entity Graph | SQLite (MVP) / Neo4j (future) | SQLite for zero-dep local; Neo4j for scale graph queries |
| Task Queue | APScheduler (MVP) / Celery+Redis (future) | Heartbeat scheduling, background investigation jobs |
| Messaging | Slack SDK, Discord.py, python-telegram-bot | Chat interface adapters |
| CLI | Typer + Rich | Beautiful terminal UI with progress, tables, panels |
| Containerization | Docker + docker-compose | One-command deployment, network isolation |
| Report Generation | Jinja2 templates to Markdown/HTML/PDF | Professional intelligence reports |
| STIX Handling | stix2 + taxii2-client + mitreattack-python | STIX 2.1 native data model, TAXII ingestion |
| Graph Analysis | networkx | Infrastructure clustering and campaign detection |
| Testing | pytest + pytest-asyncio | Async-first test suite |
| Linting | ruff | Fast Python linter |
| CI/CD | GitHub Actions | Lint, test, build Docker image, publish |

### Key Dependencies

| Package | Purpose |
|---------|---------|
| httpx | Async HTTP client for all network calls |
| pydantic | Data validation and models (v2) |
| typer | CLI framework |
| rich | Terminal formatting |
| stix2 | Parse and create STIX 2.1 objects |
| taxii2-client | TAXII 2.1 API client for ATT&CK ingestion |
| mitreattack-python | Official MITRE ATT&CK utility library |
| networkx | Graph algorithms for clustering and campaign detection |
| jinja2 | Report template rendering |
| structlog | Structured logging |
| apscheduler | Task scheduling for heartbeat engine |
| dnspython | DNS resolution and enumeration |
| python-whois | WHOIS lookups |
| python-nmap | Port scanning wrapper |

## Build Commands

```bash
# Install dependencies (dev mode)
pip install -e ".[dev]"

# Run tests
pytest

# Run single test
pytest tests/path/to/test.py::test_function -v

# Run async tests
pytest tests/ -v --asyncio-mode=auto

# Lint
ruff check .

# Format
ruff format .

# Run with Docker
docker-compose up

# Build Docker image
docker build -t spectre .
```

## CLI Command Reference

### Investigation Commands
| Command | Description |
|---------|-------------|
| `spectre investigate <target>` | Full OSINT investigation with auto-enrichment |
| `spectre investigate <target> --attribute` | Investigation + threat actor attribution |
| `spectre investigate <target> --depth [quick\|standard\|full]` | Control investigation depth |
| `spectre investigate <target> --report [markdown\|html\|pdf]` | Generate formatted report |
| `spectre enrich --ioc <indicator>` | Enrich specific IOCs across all feeds |
| `spectre plugins list` | List all available and enabled plugins |

### Threat Actor Commands
| Command | Description |
|---------|-------------|
| `spectre actor profile <name>` | Generate full threat actor dossier |
| `spectre actor profile <name> --report pdf` | Export dossier as PDF |
| `spectre actor search <query>` | Search actors by name, alias, sector, region |
| `spectre actor list --sector <sector>` | List actors targeting a sector |
| `spectre actor compare <actor1> <actor2>` | Side-by-side TTP/tool/targeting comparison |
| `spectre actor navigator <name>` | Export ATT&CK Navigator layer JSON |
| `spectre actor timeline <name>` | Show activity timeline with campaigns |

### Campaign Commands
| Command | Description |
|---------|-------------|
| `spectre campaign list --active` | List actively tracked campaigns |
| `spectre campaign track <name>` | Start tracking with continuous monitoring |
| `spectre campaign detail <name>` | Full breakdown: actors, IOCs, TTPs, timeline |
| `spectre campaign detect --investigation <id>` | Run campaign detection against findings |
| `spectre campaign iocs <name> --format csv` | Export campaign IOCs |

### Threat Landscape Commands
| Command | Description |
|---------|-------------|
| `spectre threats --sector <sector>` | Sector threat landscape |
| `spectre threats --region <region>` | Regional threat landscape |
| `spectre threats gap-analysis --coverage <file>` | Detection gap analysis |
| `spectre threats trending` | Trending TTPs, actors, campaigns (last 30 days) |

### Monitoring Commands
| Command | Description |
|---------|-------------|
| `spectre watch <target> --interval <duration>` | Start continuous monitoring |
| `spectre watch campaign:<name> --alert <channel>` | Monitor campaign for changes |
| `spectre watch list` | Show all active watchers |
| `spectre watch stop <id>` | Stop a watcher |

## Configuration

```yaml
# spectre.yaml
llm:
  provider: claude            # claude | openai | ollama
  model: claude-sonnet-4-5-20250929
  api_key: ${ANTHROPIC_API_KEY}

plugins:
  dns_recon:
    enabled: true
  whois_lookup:
    enabled: true
  virustotal:
    enabled: true
    api_key: ${VT_API_KEY}
  shodan:
    enabled: false            # disabled until API key provided
    api_key: ${SHODAN_API_KEY}
  mitre_attack:
    enabled: true
    refresh_interval: 7d      # weekly ATT&CK sync
  opencti_feed:
    enabled: false
    instance_url: ${OPENCTI_URL}
    api_key: ${OPENCTI_API_KEY}

heartbeat:
  enabled: true
  default_interval: 6h

reporting:
  default_format: markdown    # markdown | html | pdf
  output_dir: ./reports

security:
  sandbox_plugins: true
  max_concurrent_investigations: 3
  rate_limit_global: 100/minute
```

## Build Phases

### Phase 1: Foundation ✅ COMPLETE
- Project scaffolding: pyproject.toml, Docker, CI, linting (ruff), pre-commit
- Plugin ABC + registry with entry_points discovery
- Entity models (Pydantic v2) for ALL entity types
- CLI skeleton with Typer
- DNS Recon and WHOIS plugins

### Phase 2: Agent Brain ✅ COMPLETE
- LLM interface abstraction (Claude, OpenAI, Ollama)
- Investigation planner: LLM builds execution DAG
- Async execution engine with retry logic
- Cross-source correlator with entity resolution
- subdomain_enum and cert_transparency plugins
- Integration test suite

### Phase 3: Threat Intelligence & Adversary Layer ✅ COMPLETE
- Threat feed plugins (Abuse.ch, OTX, VirusTotal, Shodan)
- Auto-enrichment pipeline with concurrent execution
- Confidence scoring and threat level assessment
- MITRE ATT&CK integration with TTP keyword matching
- Attribution pipeline (4-stage scoring: TTP, Infrastructure, Tooling, Victimology)
- 6 built-in threat actor profiles (APT28, APT29, Lazarus, APT41, FIN7, Conti)
- TTP auto-tagger for findings
- Report generator v1 (Markdown, JSON, HTML, text formats)

### Phase 4: Chat Interfaces ✅ COMPLETE
- Adapter abstraction for chat platforms
- Slack, Discord, Telegram integrations
- Conversation state for multi-turn investigations
- Adversary commands via chat

### Phase 5: Web UI (React/TypeScript) ✅ COMPLETE (5.1 + 5.2)
- FastAPI backend with REST + WebSocket APIs
- React/TypeScript frontend with Vite (Cold War dossier aesthetic)
- Unified InvestigationService used by CLI, Chat, and Web API
- Real-time event bus for investigation lifecycle
- Investigation list, detail, and new investigation UI
- Dashboard with mock data, Sidebar, Header components
- Docker multi-stage builds for API and web
- **Known Issue**: WebSocket real-time updates need debugging (UI doesn't auto-update)
- **Not Yet Implemented**: Phase 5.3-5.6 (Entity graph visualization, Threat actor dossiers, Reports UI, Docker polish)

### Phase 6: Heartbeat, Monitoring & Campaign Detection ← IN PROGRESS
**Done:**
- APScheduler-based scheduler (`spectre/heartbeat/scheduler.py`)
- Watch models, store, executor (`spectre/heartbeat/models.py`, `store.py`, `watchers.py`)
- Diff detection (`spectre/heartbeat/diff.py`)
- Alert routing to CLI/Slack/Discord/Telegram (`spectre/heartbeat/alerts.py`)
- CLI commands: `spectre watch create|list|show|run|pause|resume|delete|start-daemon`

**Pending:**
- Campaign tracker (`spectre/adversary/campaign_tracker.py`)
- Campaign detector (`spectre/adversary/campaign_detector.py`)
- TTP timeline analysis (`spectre/adversary/ttp_timeline.py`)
- CLI commands: `spectre campaign`

### Phase 7: Hardening & Release
- Security hardening: sandboxing, input sanitization, secrets
- Rate limiting with backoff
- Detection gap analysis
- STIX 2.1 export
- ATT&CK Navigator export
- Documentation
- Docker polish
- Community plugin template
- v1.0.0 release

## Security Architecture

| Threat | Mitigation |
|--------|------------|
| Prompt injection via ingested data | Sanitize all plugin outputs before passing to LLM; use structured data extraction |
| Malicious community plugins | Plugin sandboxing via subprocess isolation; mandatory capability declarations |
| API key exposure | Secrets stored in encrypted vault (not env vars); never logged or in reports |
| Excessive permissions | Plugins declare required permissions; user approves on install |
| Data exfiltration | Network policies in Docker; plugins cannot make undeclared outbound connections |
| Supply chain attacks | Pinned dependencies; reproducible builds; SBOM generation; signed releases |

### Ethical Guardrails
- Only collects publicly available information (true OSINT)
- No credential stuffing, password spraying, or active exploitation
- Rate limiting on all external queries
- Clear logging of all actions for audit trails
- Optional scope-locking: restrict to user-owned domains/IPs

## Key Implementation Notes

- Use Python 3.12+ for best async and typing support
- Use Pydantic v2 for all data models with strict validation
- Plugin discovery via Python entry_points for pip-installable community plugins
- SQLite entity graph with FTS5 for full-text search
- All network calls via async httpx with configurable timeouts
- Every plugin must implement health_check() to verify API access
- Use structured logging (structlog) with investigation ID correlation
- Docker: non-root user, read-only filesystem where possible
- All adversary intel models follow STIX 2.1 semantics
- MITRE ATT&CK: full sync on first run, incremental sync on schedule
- Attribution engine: scoring pipeline with configurable weights per stage

## Free Threat Intelligence Sources

| Source | Type | Endpoint |
|--------|------|----------|
| Abuse.ch URLhaus | Malware URLs | urlhaus-api.abuse.ch |
| Abuse.ch ThreatFox | IOCs | threatfox-api.abuse.ch |
| Abuse.ch MalwareBazaar | Malware samples | bazaar.abuse.ch/api |
| AlienVault OTX | Community threat pulses | otx.alienvault.com/api |
| VirusTotal | Multi-engine scanning (free tier) | www.virustotal.com/api/v3 |
| Shodan | Internet-wide scanning (free tier) | api.shodan.io |
| GreyNoise | Internet noise vs targeted | api.greynoise.io |
| CIRCL Passive DNS | Historical DNS | www.circl.lu/services/passive-dns |
| MISP Default Feeds | Aggregated IOCs in STIX | www.misp-project.org |
| NVD / CVE | Vulnerability database | services.nvd.nist.gov/rest/json |
| Spamhaus DROP | Known bad IP ranges | www.spamhaus.org/drop |
| crt.sh | Certificate Transparency | crt.sh |
| MITRE ATT&CK | Adversary TTPs, groups, campaigns | attack-taxii.mitre.org |
| Malpedia | Malware families + actor mapping | malpedia.caad.fkie.fraunhofer.de |

## MITRE ATT&CK TAXII Endpoints

```
Base URL:   https://attack-taxii.mitre.org/api/v21/
Enterprise: 95ecc380-afe9-11e4-9b6c-751b66dd541e
Mobile:     2f669986-b40b-4423-b720-4396ca6a462b
ICS:        02c3ef24-9cd4-48f3-a99f-b74ce24f1d34

Libraries:  stix2, taxii2-client, mitreattack-python
```
