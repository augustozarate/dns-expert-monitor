# DNS Expert Monitor

![Version](https://img.shields.io/badge/version-0.2.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Security](https://img.shields.io/badge/security-detection-red)

[![English](https://img.shields.io/badge/lang-en-red.svg)](README.md)
[![Español](https://img.shields.io/badge/lang-es-yellow.svg)](README.es.md)

**DNS Expert Monitor** is an advanced DNS traffic monitoring and security analysis tool with proactive threat detection. Designed for security professionals, system administrators, and forensic analysts.

---

## 📋 Table of Contents
- [Key Features](#-key-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Detailed Commands](#-detailed-commands)
- [Professional Reporting](#-professional-reporting-system)
- [Multi-format Export](#-multi-format-export)
- [Security Detectors](#security-detectors)
- [Utilities & Maintenance](#-utilities--maintenance)
- [Recommended Workflows](#-recommended-workflows)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Contributing](#-contributing)

---

## 🎯 Key Features

### 🔍 Real-time Monitoring
| Feature | Description |
|---------|-------------|
| 📡 DNS Capture | Real-time DNS traffic capture on network interfaces |
| 📊 Statistics | QPS, top domains, unique clients in real-time |
| 🌍 Cross-platform | Linux, Windows, macOS (with Npcap/libpcap) |
| 🎨 Modern CLI | Interactive interface with Rich |

---

### 🛡️ DNS Threat Detection

<details>
<summary><b>📌 DNS Tunneling</b> - Data exfiltration via DNS</summary>

- 🔴 High entropy domain names (>4.5)
- 🔴 Base64/Hexadecimal patterns
- 🔴 Abnormally long subdomains (>50 chars)
- 🔴 Suspicious record types (TXT, NULL, KEY, OPT)
</details>

<details>
<summary><b>⚠️ DNS Poisoning</b> - Cache poisoning</summary>

- 🟡 Abnormally low TTL (<30s)
- 🟡 Multiple different responses to same query
- 🟡 Unauthorized DNS servers
</details>

<details>
<summary><b>🚨 Amplification DDoS</b> - Amplification attacks</summary>

- 🟠 High response/query ratios (>10x)
- 🟠 Anomalous query rates (>100 QPS)
- 🟠 Excessive ANY type queries
</details>

<details>
<summary><b>📌 NXDOMAIN Attacks</b> - Non-existent domain flooding</summary>

- 🔵 High NXDOMAIN response percentage (>30%)
- 🔵 Elevated NXDOMAIN rates per minute (>100)
- 🔵 Randomly generated subdomains
</details>

---

### 📊 Analysis & Reporting
- 📈 **Executive reports** with critical findings
- 📋 **Multi-format export**: HTML, JSON, CSV, YAML, PCAP
- 🏷️ **Severity classification**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- 🔍 **Detailed evidence** for each detection
- 💡 **Actionable recommendations** for mitigation

---

## 🚀 Installation

### 📦 From source (recommended)
```
git clone https://github.com/augustozarate/dns-expert-monitor.git
cd dns-expert-monitor
pip install -e .
```

## 🐧 Linux (Debian/Ubuntu)
## System dependencies
```
sudo apt-get install libpcap-dev
```

## Python dependencies (minimal)
```
pip install -r requirements.txt
```
### or
```
pip install scapy>=2.5.0 rich>=13.0.0 click>=8.1.0 netifaces>=0.11.0 pyyaml>=6.0
```

## For analysis and visualization (optional)
```
pip install pandas matplotlib numpy
```

## 🍎 macOS
```
brew install libpcap
pip install -e .
```

## 🪟 Windows
```
Install Npcap in "WinPcap API-compatible Mode"
Install Python 3.8+
pip install -e .
```
---

# 🔧 Permission Configuration (Linux)
## Use sudo (recommended for testing)
```
sudo python run.py monitor
```

---

# ⚡ Quick Start
## Verify installation

## Show available interfaces
```
dns-expert interfaces
```
### or
```
python run.py interfaces
```

## Test mode (no real traffic)
```
sudo python run.py test --duration 10
```

## First capture

## Quick analysis (30 seconds)
```
sudo python run.py quick --duration 30
```

## Monitoring with security detection
```
sudo python run.py monitor --security
```

## Generate report

## Markdown report (readable)
```
python run.py report capture.json --output report.md
```

## JSON report (processable)
```
dns-expert report capture.json --format json --output report.json
```
### or
```
python run.py report capture.json --format json --output report.json
```
---

# 📚 Detailed Commands
## 🎯 Monitoring & Capture

| Command	| Description	| Example |
|---------|-------------|---------|
| monitor |	Continuous capture until Ctrl+C | `sudo python run.py monitor --security` |
| quick	| Time-based capture | `sudo python run.py quick --duration 60` |
| test | Simulated traffic (no network) | `sudo python run.py test --duration 20` |

## Available options:

| Option | Description | Default |
|--------|-------------|-------------|
| `--duration` | Capture duration in seconds | 10 |
| `-i, --interface` | Network interface | auto-detected |
| `-o, --output` | Save capture to JSON | None |
| `-s, --security` | Enable detectors | False |
| `-c, --config` | Configuration file |	None |
| `-v, --verbose` | Real-time activity display | False |

## Complete examples:
```
sudo python run.py monitor --security --verbose --output capture.json -i eth0
sudo python run.py quick --duration 120 --security --output analysis.json
sudo python run.py monitor --config config/detectors.yaml
```

### ⚡ Quick Command Examples

## Basic usage
```
sudo python run.py quick --duration 30
```

## With security detection
```
sudo python run.py quick --duration 120 --security
```

## Save capture
```
sudo python run.py quick --duration 60 --security --output analysis.json
```

## Verbose mode
```
sudo python run.py quick --duration 30 --security --verbose
```

## Specify interface
```
sudo python run.py quick -i eth0 --duration 30 --security
```

# 📊 Reporting & Export

| Command |	Description | Example |
|---------|-------------|---------|
| report |	Generate security report	| `dns-expert report captura.json` |
| export |	Export to multiple formats |	`dns-expert export captura.json --format all` |

## Report options:

`-o, --output - Output file`

`-f, --format - md (default) or json`

## Markdown report
```
dns-expert report capture.json --output report.md
```
### or
```
python run.py report capture.json --output report.md
```

## JSON report
```
dns-expert report capture.json --format json
```
### or
```
python run.py report capture.json --format json
```

# 🔧 Utilities

| Command |	Description | Example |
|---------|-------------|---------|
| `interfaces` | List available interfaces | `dns-expert interfaces` |
| `fix-json` | Repair corrupted JSON files | `dns-expert fix-json captura.json` |
| `version` | Show version | `python run.py version` |

## fix-json options:

- `--diagnostic - Diagnose only`

- `--force - Aggressive repair methods`

- `--no-backup - No automatic backup`
---

# 📋 Professional Reporting System
## 🏗️ Report Structure
```
📊 DNS Security Analysis Report
├── 📋 Executive Summary
│   └── Summary of critical findings
├── 📈 Analysis Statistics
│   ├── Analysis period
│   ├── Traffic volume
│   └── Performance metrics
├── 🚨 Security Findings
│   ├── 🔴 CRITICAL (0)
│   ├── 🟠 HIGH (32)
│   ├── 🟡 MEDIUM (51)
│   ├── 🔵 LOW (0)
│   └── ⚪ INFO (0)
└── 📋 Recommendations
    ├── Immediate actions
    ├── Short-term improvements
    └── Long-term strategy
```

## 📄 Example Report (Markdown)
```
# DNS Security Analysis Report
Generated: 2026-02-11 16:19:05

## Executive Summary
🚨 **CRITICAL FINDINGS DETECTED**: 32 high/critical security issues found.

## Key Statistics
- **Analysis Period**: 2m 4s
- **Total Packets**: 266
- **DNS Queries**: 142
- **DNS Responses**: 124
- **Unique Clients**: 3
- **Unique Domains**: 31
- **Average QPS**: 1.14

## Security Findings
### 🟠 HIGH Severity Findings (32)
#### Possible DNS Tunneling Detected
- **Domain**: y1apecughjwuye2qgbhxw9d0arnb2t.example.com
- **Entropy**: 4.52
- **Client**: 192.168.xxx.xxx
- **Recommendation**: Investigate source IP, block suspicious domains
```
---

# 📤 Multi-format Export
## 🎯 Supported Formats

| Format |	Extension |	Primary Use | Command Status |
|---------|-----------|---------------|----------------|
| HTML | .html | Interactive dashboard, visual reports | `--format html` |	✅ |
| JSON | .json | Programmatic processing, APIs | `--format json` |	✅ |
| CSV	| .csv | Excel, Google Sheets, statistical analysis	| `--format csv` |	✅ |
| YAML | .yaml | Configuration, documentation	| `--format yaml`	| ✅ |
| PCAP | .pcap | Wireshark, forensic analysis | `--format pcap`	| ✅ |
| ALL | - |	All formats simultaneously | `--format all`	| ✅ |

# 📊 HTML Dashboard
## The HTML report includes:

<div align="center"> <table> <tr> <td>📊 Real-time statistics</td> <td>🏆 Top queried domains</td> </tr> <tr> <td>🛡️ Highlighted security alerts</td> <td>📋 Recent activity</td> </tr> <tr> <td colspan="2">📈 Traffic and distribution charts</td> </tr> </table> </div>

# 💻 Export Examples
## Interactive dashboard
```
dns-expert export capture.json --format html
```
## Generates: capture.html

## Forensic analysis with Wireshark
```
dns-expert export capture.json --format pcap
```
## Generates: capture.pcap

## Statistical analysis in Excel
```
dns-expert export capture.json --format csv
```
## Generates: capture.csv

## Complete export (all formats)
```
dns-expert export capture.json --format all
```
## Generates: capture.json, .csv, .html, .yaml, .pcap
---
# Security Detectors
1. 🚨 DNS Tunneling Detector
- **Detection 🛡️**: Data exfiltration via DNS
- Indicators: High entropy, Base64/Hex patterns, long subdomains, suspicious record types

| Parameter | Threshold | Description |
|-----------|--------|-------------|
| Entropy | > 4.5 | Domains with high randomness |
| Length | > 50 chars | Excessively long subdomains |
| Patterns | Base64/Hex | Data encoding |
| Types | TXT, NULL, KEY | Unusual records |

Example detection:
```
🚨 ALERT: High entropy (4.62) in domain: 23pzgde427i3ln7qmkdr986h4snnkt.example.com
```

2. ⚠️ DNS Poisoning Detector

- **Detection 🛡️**: Cache poisoning protection
- Indicators: Low TTL, multiple different responses, unauthorized servers

| Parameter | Threshold | Description |
|-----------|--------|-------------|
| TTL |	< 30s |	Abnormally low TTL responses |
| Responses | > 2 | Multiple different responses |
| Servers |	Unauthorized | Responses from untrusted sources |

Example detection:
```
⚠️ WARNING: Abnormally low TTL (5s) for main.vscode-cdn.net
```

3. 🟠 Amplification Detector

- **Detection 🛡️**: DDoS amplification attacks
- Indicators: High response/query ratio, anomalous query rates, excessive ANY queries

| Parameter | Threshold | Description |
|-----------|--------|-------------|
| Ratio | > 10x | Response much larger than query |
| QPS |	> 100 |	High queries per second |
| ANY Queries |	> 50/min | Excessive ANY type queries |

Example detection:
```
⚠️ WARNING: High query rate (1183.4 QPS) from 192.168.xxx.xxx
```

4. 🔵 NXDOMAIN Attack Detector

- **Detection 🛡️**: Non-existent domain flooding

- Indicators: High NXDOMAIN percentage, elevated rates, random subdomains

Parameter	Threshold	Description
% NXDOMAIN	> 30%	High percentage of non-existent domains
Rate	> 100/min	Many NXDOMAIN responses per minute
Subdomains	Random	Automatic generation patterns

| Parameter | Threshold | Description |
|-----------|--------|-------------|
| % NXDOMAIN | > 30% | High percentage of non-existent domains |
| Tasa | > 100/min | Many NXDOMAIN responses per minute |
| Subdominios |	Random | Automatic generation patterns |

Example detection:
```
📊 Análisis del cliente 192.168.xxx.xxx:
   • Nivel sospechoso: high
   • NXDOMAIN responses: 69/min
```

# 📊 Detection Results

🔒 SECURITY SUMMARY 
   Security Alerts 
Type            Quantity 
base64_pattern         8 
high_query_rate        1 
low_ttl                2 
high_entropy           4

Active detectors: 
    • tunneling: 12 alerts, 1 suspicious client 
    • poisoning: 2 alerts, 1 suspicious domain 
    • amplification: 1 alert, abnormal rate detected 
    • nxdomain: 69 NXDOMAIN/min, HIGH level

---

# 🔧 Utilities & Maintenance
## 🛠️ JSON File Repair

Capture files can become corrupted if writing is interrupted. DNS Expert Monitor includes advanced repair tools:
## 1. Diagnose problems
```
dns-expert fix-json --diagnostic capture.json
```
## 2. Repair automatically (recommended)
```
dns-fix --diagnostic capture.json
```
## 3. Force repair with aggressive methods
```
dns-fix --force capture.json
```
## 4. Repair without backup
```
dns-fix --no-backup capture.json
```
## 5. Save to different file
```
dns-fix capture.json --output repaired.json
```

## Repair strategies:
- ✅ Trailing comma removal - Removes commas before `]` or `}`
- ✅ Object extraction - Recovers individual JSON objects
- ✅ Robust parser - Multiple recovery methods
- ✅ Automatic backup - Always creates .bak before modifying

---

# 🧹 Maintenance
## Verify JSON integrity
```
python3 -c "import json; json.load(open('capture.json'))" && echo "✅ Valid"
```
## Clean old backups
```
rm capture.json.bak.* 2>/dev/null
```
## Compress old captures
```
gzip capture_*.json
```
---

# 🔄 Recommended Workflows

1. 🚨 Incident Investigation
## Focused capture (60 seconds)
```
sudo python run.py quick --duration 60 --output incident.json
```
## Immediate analysis
```
dns-expert report incident.json --output incident_report.md
```
### or
```
python run.py report incident.json --output incident_report.md
```

## Export evidence for forensics
```
dns-expert export incident.json --format pcap
dns-expert export incident.json --format html
```
### or
```
python run.py export incident.json --format pcap
python run.py export incident.json --format html
```

2. 📊 Scheduled Security Audit
```
#!/bin/bash
# audit_dns.sh - Run daily via cron

DATE=$(date +%Y%m%d)
OUTPUT_DIR="/var/log/dns-audit"
mkdir -p $OUTPUT_DIR

echo "📡 Starting DNS audit $DATE..."

# 5-minute capture
sudo dns-expert monitor --security \
  --output "$OUTPUT_DIR/capture_$DATE.json" \
  --duration 300

# Generate report
dns-expert report "$OUTPUT_DIR/capture_$DATE.json" \
  --output "$OUTPUT_DIR/report_$DATE.md"

# Export statistics
dns-expert export "$OUTPUT_DIR/capture_$DATE.json" \
  --format csv

echo "✅ Audit completed"
```

3. 🔄 Continuous Monitoring
```
# monitor_continuous.sh
while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    sudo dns-expert monitor --security \
      --output "capture_$TIMESTAMP.json" \
      --duration 300
    sleep 60  # Pause between captures
done
```

4. 📈 Trend Analysis
```
# Collect data for one hour
for i in {1..6}; do
    sudo dns-expert quick --duration 600 \
      --output "trend_$(date +%H%M).json"
    sleep 60
done

# Combine and analyze
dns-expert export trend_*.json --format all
```
---

5. ⚡ Combined Commands

## Capture + Report (one-liner)
```
sudo python run.py monitor --security --output temp.json \
  && python run.py report temp.json --output report.md
```

## Quick capture + Complete export
```
sudo python run.py quick --duration 60 --output quick.json \
  && python run.py export quick.json --format all
```

## Complete analysis with all formats
```
sudo python run.py monitor --security --output analysis.json \
  && python run.py export analysis.json --format all \
  && python run.py report analysis.json --output security_report.md
```

# Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `JSON decode error` | Corrupted JSON file | `dns-expert fix-json captura.json` |
| `Interface not found` | Wrong/non-existent interface | `dns-expert interfaces` to list available |
| `No traffic captured` | No DNS traffic on network | Check: `ping 8.8.8.8`, `nslookup google.com` |
| `Module not found` | issing dependencies | `pip install -e .` o `pip install -r requirements.txt` |
| `[Errno 1]` | Capture permissions | Configure Npcap (Windows) or capabilities (Linux) |
| `No module named 'core'` | Wrong path | Run from project root directory |

---

# Architecture
🏗️
```
dns_expert_monitor/
├── src/
│   └── dns_expert_monitor/          # Main package
│       ├── __init__.py
│       ├── cli.py                   # Command-line interface
│       │
│       ├── core/                    # Core components
│       │   ├── packet_engine.py     # Scapy capture engine
│       │   ├── interface_manager.py # Cross-platform interface management
│       │   └── packet_queue.py      # Thread-safe queues
│       │
│       ├── detectors/               # Security detectors
│       │   ├── dns_tunneling.py     # Tunneling detection
│       │   ├── poisoning_detector.py # Poisoning detection
│       │   ├── amplification_detector.py # DDoS detection
│       │   ├── nxdomain_attack.py   # NXDOMAIN detection
│       │   └── security_manager.py  # Orchestrator
│       │
│       ├── analyzers/                # Data analysis
│       │   ├── statistics_engine.py  # Real-time metrics
│       │   ├── security_analyzer.py  # Malicious packet scanning
│       │   ├── dns_parser.py         # Advanced parsing
│       │   └── cache_analyzer.py     # Cache analysis
│       │
│       └── visualizers/              # Visualization & reporting
│           ├── data_export.py        # Multi-format export
│           ├── report_generator.py   # Professional reports
│           └── realtime_dashboard.py # Interactive dashboard
│
├── tests/                             # Unit tests
│   ├── generate_test_traffic.py       # DNS traffic generator for testing
│   └── test_security.py               # Security detectors test script
├── config/                            # Configuration
│   ├── detectors.yaml                 # Attack signatures
│   ├── detectors_simple.yaml
│   └── signatures.yaml
├── docs/                               # Documentation
├── examples/                           # Usage examples
├── run.py                              # Execution script
├── fix_json.py                         # JSON repair tool
├── dns-fix.py                          # DNS repair utility
├── requirements.txt                    # Dependencies
├── requirements-dev.txt                # Dependencies-dev
├── README.es.md                        # Spanish
└── README.md                           # English (Default)
```

---

# 🤝 Contributing

Contributions are welcome and appreciated!

## 🎯 Contribution Areas
- 🐛 Report bugs - Open an issue with problem details
- 💡 Suggest features - New functionality or improvements
- 📚 Documentation - Improve guides and examples
- 🌍 Translations - Internationalization
- 🔧 Plugins - New security detectors

## 🙏 Acknowledgments

### 📚 Libraries
- **[Scapy](https://scapy.net/)** - Packet manipulation library
- **[Rich](https://rich.readthedocs.io/)** - Beautiful terminal formatting
- **[Click](https://click.palletsprojects.com/)** - Professional CLI framework
- **[Netifaces](https://github.com/al45tair/netifaces)** - Cross-platform network interface detection
- **[PyYAML](https://pyyaml.org/)** - YAML configuration parsing
- **[Pandas](https://pandas.pydata.org/)** - Data analysis (optional)
- **[Matplotlib](https://matplotlib.org/)** - Data visualization (optional)

### 👥 Community
- To all contributors who have helped improve this tool
- To the security community sharing knowledge about DNS threats
- To users reporting bugs and suggesting improvements

# ⚠️ LEGAL WARNING

DNS Expert Monitor is a tool designed for:

✅ AUTHORIZED USE:

- Own network administration

- Security audits with consent

- Research and education

- Incident response

❌ UNAUTHORIZED USE:

- Network monitoring without consent

- Malicious or illegal activities

- Privacy violation

- Attacks on third-party infrastructure

**Unauthorized use of this tool to monitor networks without explicit permission may violate local and international laws. The author is not responsible for misuse of this tool.**

# 👨‍💻 Project Information

| Developer | Augusto Zarate |
|---------------|----------------|
| Versión	0.2.0 | (Stable) |
| Last Updated | February 2026 |
| License | MIT |
| Repository |	github.com/augustozarate/dns-expert-monitor |
| Report Issues |	GitHub Issues |
| Documentation | docs/ |

<div align="center"> <h3>⭐ Like the project? Give it a star on GitHub! ⭐</h3> <p> <a href="https://github.com/augustozarate/dns-expert-monitor/stargazers"> <img src="https://img.shields.io/github/stars/augustozarate/dns-expert-monitor?style=social" alt="GitHub stars"> </a> <a href="https://github.com/augustozarate/dns-expert-monitor/network/members"> <img src="https://img.shields.io/github/forks/augustozarate/dns-expert-monitor?style=social" alt="GitHub forks"> </a> <a href="https://github.com/augustozarate/dns-expert-monitor/watchers"> <img src="https://img.shields.io/github/watchers/augustozarate/dns-expert-monitor?style=social" alt="GitHub watchers"> </a> </p> <p> <sub>Made with ❤️ for the security community</sub> </p> </div> ```
