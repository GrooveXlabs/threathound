# ThreatHound

> Blue Team SOC Automation. Hunt threats on Windows, analyze logs, detect anomalies, extract IOCs, generate Sigma rules.

[![Tests](https://github.com/GrooveXlabs/threathound/actions/workflows/test.yml/badge.svg)](https://github.com/GrooveXlabs/threathound/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What It Does

- **IOC Extraction** — Pull IPs, URLs, hashes, emails, crypto addresses from files and logs
- **Sigma Generation** — Build detection rules from hunt findings
- **Hunt Playbook** — Pre-built Windows Event Log hunting commands

## Install

```bash
pip install threathound
```

Or from source:

```bash
git clone https://github.com/GrooveXlabs/threathound.git
cd threathound
pip install -e ".[dev]"
```

## Quick Start

```bash
# Extract IOCs from a file or directory
threathound ioc suspicious_dump.bin -o iocs.json

# Extract IOCs recursively
threathound ioc /var/log -r -o logs_iocs.json

# Generate a Sigma rule
threathound sigma --title "Suspicious PowerShell" --logsource '{"product":"windows"}' --detection '{"selection":{"EventID":4104}}' --tags attack.execution,attack.t1059.001

# Show built-in hunt commands
threathound hunts
```

## Ecosystem

ThreatHound is part of the **GrooveXlabs** security toolchain:

- **[GrooveGuard](https://github.com/GrooveXlabs/grooveguard)** — Static security scanner
- **[GrooveStrike](https://github.com/GrooveXlabs/groovestrike)** — Autonomous pentest framework
- **[PurpleForge](https://github.com/GrooveXlabs/purpleforge)** — Purple team defense rules
- **[RedTrack](https://github.com/GrooveXlabs/redtrack)** — Red Team recon & attack paths

## License

MIT — see [LICENSE](LICENSE)
