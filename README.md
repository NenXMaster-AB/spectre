# SPECTRE

**Security Platform for Enrichment, Collection, Threat Research & Evaluation**

An open-source, self-hosted, agentic OSINT and cyber threat intelligence platform.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

## Overview

SPECTRE combines OSINT research automation with continuous cyber threat intelligence monitoring. Unlike traditional OSINT tools that are fragmented and manual, SPECTRE adds an agentic orchestration layer:

1. **Natural language interface** - Talk to it via CLI, Slack, Discord, or Telegram
2. **Autonomous planning** - AI decides which tools/APIs to query for your investigation
3. **Cross-source correlation** - Synthesizes findings across multiple data sources
4. **Continuous monitoring** - Heartbeat engine for proactive alerting

## Features

### Current (Phase 1)
- DNS reconnaissance (A, AAAA, MX, NS, TXT, SOA, CNAME, CAA records)
- WHOIS domain registration lookup
- Plugin architecture with entry_point discovery
- Rich CLI with progress indicators and formatted output
- Docker deployment ready

### Planned
- Threat intelligence integration (VirusTotal, Shodan, AlienVault OTX)
- MITRE ATT&CK mapping and threat actor profiling
- Campaign tracking and detection
- Chat platform adapters (Slack, Discord, Telegram)
- Heartbeat monitoring with scheduled investigations

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/spectre-osint/spectre.git
cd spectre

# Install with pip (recommended)
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Show help
spectre --help

# List available plugins
spectre plugins list

# Investigate a domain
spectre investigate domain example.com

# Run a specific plugin
spectre plugins run dns_recon example.com

# Check plugin health
spectre plugins health
```

### Docker

```bash
# Build the image
docker build -t spectre .

# Run interactively
docker run -it spectre investigate domain example.com

# Or use docker-compose
docker-compose run spectre investigate domain example.com
```

## CLI Commands

### Investigation Commands

```bash
# Full domain investigation
spectre investigate domain example.com

# Investigation with specific plugins
spectre investigate domain example.com --plugins dns_recon,whois_lookup

# Output as JSON
spectre investigate domain example.com --json

# Save results to file
spectre investigate domain example.com --output results.json

# Auto-detect target type
spectre investigate auto example.com
spectre investigate auto 8.8.8.8
```

### Plugin Commands

```bash
# List all plugins
spectre plugins list

# List plugins by category
spectre plugins list --category osint

# Show plugin details
spectre plugins info dns_recon

# Check plugin health
spectre plugins health
spectre plugins health dns_recon

# Run a single plugin
spectre plugins run dns_recon example.com
```

## Configuration

Copy the example configuration file:

```bash
cp spectre.yaml.example spectre.yaml
```

Edit `spectre.yaml` to configure:
- LLM provider and API keys
- Plugin settings and API keys
- Monitoring/heartbeat schedules
- Security settings

### Environment Variables

API keys can be provided via environment variables:

```bash
export ANTHROPIC_API_KEY=your-key
export VIRUSTOTAL_API_KEY=your-key
export SHODAN_API_KEY=your-key
```

## Plugin Architecture

SPECTRE uses a plugin system where all data sources implement the `SpectrePlugin` interface:

```python
from spectre.plugins.base import SpectrePlugin, EntityType, PluginCategory

class MyPlugin(SpectrePlugin):
    name = "my_plugin"
    description = "What this plugin does"
    category = PluginCategory.OSINT
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.IP_ADDRESS]

    async def execute(self, entity, config):
        # Implementation
        pass

    async def health_check(self):
        return True
```

Plugins are discovered via Python entry_points, allowing community plugins to be pip-installed.

## Development

### Setup

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=spectre

# Run only unit tests
pytest tests/unit/

# Run integration tests (requires network)
pytest -m integration
```

### Code Quality

```bash
# Lint
ruff check .

# Format
ruff format .

# Type check
mypy spectre/
```

## Project Structure

```
spectre/
├── spectre/
│   ├── cli/                 # Typer CLI commands
│   ├── agent/               # Agent core (future)
│   ├── adversary/           # Threat actor profiling (future)
│   ├── plugins/
│   │   ├── base.py          # Plugin ABC interface
│   │   ├── registry.py      # Plugin discovery
│   │   └── osint/           # OSINT plugins
│   ├── models/
│   │   └── entities.py      # Pydantic data models
│   ├── adapters/            # Chat adapters (future)
│   ├── heartbeat/           # Monitoring (future)
│   └── config/              # Configuration
├── tests/
├── docs/
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

## Roadmap

### Phase 1: Foundation (Current)
- [x] Project scaffolding
- [x] Plugin architecture
- [x] Entity models
- [x] CLI skeleton
- [x] DNS recon plugin
- [x] WHOIS lookup plugin

### Phase 2: Agent Brain
- [ ] LLM interface abstraction
- [ ] Investigation planner
- [ ] Plugin execution engine
- [ ] Cross-source correlator

### Phase 3: Threat Intelligence
- [ ] Threat feed plugins
- [ ] MITRE ATT&CK integration
- [ ] Threat actor profiling
- [ ] Attribution engine

### Phase 4: Chat Interfaces
- [ ] Slack adapter
- [ ] Discord adapter
- [ ] Telegram adapter

### Phase 5: Monitoring
- [ ] Heartbeat scheduler
- [ ] Watch definitions
- [ ] Campaign detection

### Phase 6: Hardening
- [ ] Security review
- [ ] Documentation
- [ ] v1.0 release

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by the autonomous agent paradigm
- Built with [Typer](https://typer.tiangolo.com/), [Rich](https://rich.readthedocs.io/), and [Pydantic](https://pydantic.dev/)
- DNS resolution powered by [dnspython](https://www.dnspython.org/)
