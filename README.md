# Security Scanner

A professional security scanning tool that detects cross-origin web attack vulnerabilities, dangling DNS records, shared certificates, and potential domain takeover risks. Built on research presented at Black Hat 2025.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Table of Contents

- [What It Does](#what-it-does)
- [Why This Matters](#why-this-matters)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Commands](#cli-commands)
- [Understanding Security Findings](#understanding-security-findings)
- [Usage Examples](#usage-examples)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## What It Does

This scanner helps security teams identify vulnerabilities that could allow attackers to take over subdomains and launch cross-origin attacks. It automatically:

- Discovers all subdomains for your domains using multiple sources
- Checks DNS records for dangling CNAMEs pointing to deleted cloud services
- Identifies misconfigured services across 8 major platforms (Heroku, GitHub Pages, AWS, Azure, GCP, Netlify, Vercel, and more)
- Analyzes certificate transparency logs for shared certificates
- Provides CVSS-scored findings with actionable remediation steps
- Maintains a historical database of all scans for tracking over time

## Why This Matters

Subdomain takeover and dangling DNS records represent a critical security risk that many organizations overlook. When a subdomain points to a cloud service that no longer exists, attackers can claim that service and completely control your subdomain. This enables:

- **Universal XSS attacks** against your users through trusted domains
- **Cookie theft and session hijacking** via same-site cookies
- **Phishing campaigns** using your legitimate domain names
- **Malware distribution** from domains users trust
- **HSTS bypass** and man-in-the-middle attacks

These vulnerabilities can persist for up to 796 days due to certificate authority validation caching, giving attackers an extended window for exploitation.

## Features

- **Multi-Source Subdomain Discovery**
  - Certificate Transparency (crt.sh)
  - subfinder integration (optional)
  - assetfinder integration (optional)

- **Comprehensive DNS Analysis**
  - Async DNS resolution with multiple nameservers
  - Dangling CNAME detection
  - TTL-aware caching
  - Support for A, AAAA, CNAME, and MX records

- **Certificate Transparency Monitoring**
  - CT log analysis
  - Shared certificate detection
  - Expiration tracking

- **Platform-Specific Takeover Detection**
  - 8 platforms: Heroku, GitHub Pages, AWS S3, AWS Elastic Beanstalk, Azure, GCP, Netlify, Vercel
  - HTTP fingerprinting verification
  - Confidence scoring (0.0-1.0)

- **Professional Reporting & Alerting**
  - Multiple report formats: JSON, HTML, Markdown, CSV
  - Beautiful HTML reports with Jinja2 templates
  - Executive summaries in Markdown
  - Email alerts via SMTP with HTML formatting
  - Slack webhook notifications with rich formatting
  - Severity-based alert filtering
  - SQLite database for historical tracking
  - CVSS v3.1 scoring
  - Detailed remediation guidance

## Installation

### Prerequisites

- Python 3.11 or higher
- pip

### Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Or install with development tools
pip install -r requirements-dev.txt
```

### Initialize Database

```bash
# Create database schema
security-scanner init-db

# Or use make
make init-db
```

## Quick Start

### Scan a Single Domain

```bash
security-scanner scan -d example.com
```

### Scan Multiple Domains

```bash
security-scanner scan -d example.com -d test.com -d app.example.com
```

### Scan from File

Create a file `domains.txt`:

```text
example.com
test.com
app.example.com
```

Then run:

```bash
security-scanner scan -f domains.txt
```

### Verbose Output

```bash
security-scanner scan -d example.com --verbose
```

## Configuration

The scanner uses environment variables and configuration files. Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

### Key Configuration Options

```bash
# Database
DATABASE_PATH=data/security_scanner.db

# DNS
DNS_NAMESERVERS=8.8.8.8,1.1.1.1
DNS_TIMEOUT=5

# HTTP
HTTP_TIMEOUT=10
HTTP_MAX_RETRIES=3

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_SECOND=2

# Scanner
MAX_CONCURRENT_SCANS=50
SUBDOMAIN_SOURCES=crtsh,subfinder,assetfinder

# Alerting (optional)
ENABLE_EMAIL_ALERTS=false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=security-team@example.com
ALERT_SEVERITY_THRESHOLD=HIGH

ENABLE_SLACK_ALERTS=false
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

## CLI Commands

### Scan Commands

```bash
# Basic scan
security-scanner scan -d example.com

# Multiple domains
security-scanner scan -d example.com -d test.com

# From file
security-scanner scan -f domains.txt

# Verbose mode
security-scanner scan -d example.com --verbose

# Quiet mode
security-scanner scan -d example.com --quiet
```

### Database Commands

```bash
# Initialize database
security-scanner init-db

# List recent scans
security-scanner list-scans

# Limit number of results
security-scanner list-scans --limit 20
```

### Report Generation

```bash
# Generate report from previous scan
security-scanner report --scan-id <SCAN_ID> --format html

# Generate multiple formats
security-scanner report --scan-id <SCAN_ID> --format json,html,markdown,csv

# Specify output directory
security-scanner report --scan-id <SCAN_ID> --output reports/
```

### Utility Commands

```bash
# Validate configuration
security-scanner validate-config

# Show version
security-scanner --version

# Show help
security-scanner --help
security-scanner scan --help
```

## Development

### Setup Development Environment

```bash
# Install development dependencies
make install-dev

# Initialize database
make init-db

# Run tests
make test

# Check code quality
make lint
make type-check

# Format code
make format

# Run all validations
make validate
```

### Project Structure

```text
security_monitoring/
├── src/security_scanner/      # Main source code
│   ├── scanner/               # Scanner modules
│   ├── detectors/             # Vulnerability detectors
│   ├── storage/               # Database and caching
│   ├── utils/                 # Utility functions
│   ├── config.py              # Configuration management
│   ├── orchestrator.py        # Scan orchestration
│   └── main.py                # CLI interface
├── config/                    # Configuration files
├── tests/                     # Test suite
├── data/                      # Database storage
├── logs/                      # Application logs
└── reports/                   # Generated reports
```

## Understanding Security Findings

### Severity Levels

The scanner classifies findings into four severity levels:

- **CRITICAL** (9.0-10.0): Immediate action required. Dangling CNAME records pointing to non-existent targets that allow complete domain takeover.
- **HIGH** (7.0-8.9): Potential subdomain takeover with confirmed platform pattern match. Registration of the target service may be available to attackers.
- **MEDIUM** (4.0-6.9): Unusual DNS configurations or unresponsive services that require investigation.
- **LOW** (0.1-3.9): Informational findings such as expiring certificates or configuration notices.

### CVSS v3.1 Scoring

All findings include Common Vulnerability Scoring System (CVSS) v3.1 scores to help prioritize remediation efforts based on actual risk impact.

## Alerting

The scanner supports automated alerts when security findings are detected.

### Email Alerts

Configure email alerts via SMTP in your `.env` file:

```bash
ENABLE_EMAIL_ALERTS=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=security-team@example.com
ALERT_SEVERITY_THRESHOLD=HIGH
```

Email alerts include:

- HTML-formatted findings with color-coded severity
- CVSS scores and confidence ratings
- Direct links to remediation documentation
- Summary statistics

### Slack Alerts

Configure Slack webhook notifications:

```bash
ENABLE_SLACK_ALERTS=true
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
ALERT_SEVERITY_THRESHOLD=CRITICAL
```

Slack alerts feature:

- Rich message formatting with Blocks API
- Color-coded attachments by severity
- Grouped findings by severity level
- Scan metadata and timing information

### Alert Thresholds

Control which findings trigger alerts using `ALERT_SEVERITY_THRESHOLD`:

- `CRITICAL` - Only critical findings
- `HIGH` - High and critical findings
- `MEDIUM` - Medium, high, and critical findings
- `LOW` - All findings

## Usage Examples

### Basic Domain Scan

```bash
$ security-scanner scan -d example.com

Security Scanner v0.1.0

Scanning 1 domain(s)...

Scan Complete!

Scan ID: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
Domains: example.com

┏━━━━━━━━━━━┳━━━━━━━┓
┃ Severity  ┃ Count ┃
┡━━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL  │     2 │
│ HIGH      │     1 │
│ MEDIUM    │     3 │
│ LOW       │     0 │
└───────────┴───────┘

Total findings: 6
```

### Viewing Scan History

```bash
$ security-scanner list-scans --limit 5

┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┓
┃ Scan ID     ┃ Start Time      ┃ Status    ┃ Domains┃ Findings ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━┩
│ a1b2c3d4... │ 2026-01-27 10:30│ completed │      1 │        6 │
│ e5f6a7b8... │ 2026-01-26 15:45│ completed │      3 │       12 │
└─────────────┴─────────────────┴───────────┴────────┴──────────┘
```

### Generating Reports

```bash
$ security-scanner report --scan-id a1b2c3d4 --format html,json,markdown

Generating reports...
✓ JSON report: reports/scan_a1b2c3d4_report.json
✓ HTML report: reports/scan_a1b2c3d4_report.html
✓ Markdown report: reports/scan_a1b2c3d4_report.md

Reports generated successfully!
```

The HTML report provides a beautiful, professional presentation of findings with:

- Executive summary with risk scoring
- Findings grouped by severity with color coding
- CVSS scores and confidence ratings
- Detailed remediation steps
- Print-friendly formatting

## Troubleshooting

### Common Issues

#### Database not initialized

```bash
security-scanner init-db
```

#### Permission errors

```bash
chmod +x security-scanner
```

#### Missing dependencies

```bash
pip install -r requirements.txt
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes with proper tests
4. Run code quality checks (`make validate`)
5. Commit your changes (`git commit -m 'Add some feature'`)
6. Push to your branch (`git push origin feature/your-feature`)
7. Open a pull request

### Development Standards

- Follow PEP 8 style guidelines (enforced with Black and Ruff)
- Add type hints to all functions (validated with mypy in strict mode)
- Write tests for new features (pytest with async support)
- Update documentation as needed
- Maintain 100% test pass rate (currently 118/118 tests passing)
- All code is type-safe with zero mypy errors

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

## Credits

Based on research from Black Hat 2025 on cross-origin web attacks and subdomain takeover vulnerabilities. This tool was developed to help security teams identify and remediate these critical vulnerabilities in their infrastructure.

## Author

Adam Rhys Heaton (Ap6pack)

## Status

**Current Version: 0.1.0** - Production Ready ✅

All core features are complete and fully tested with 118/118 tests passing (100% pass rate).

### ✅ Implemented Features

- ✅ Multi-source subdomain discovery (crt.sh, subfinder, assetfinder)
- ✅ Comprehensive DNS analysis with dangling CNAME detection
- ✅ Platform-specific takeover detection (8 platforms)
- ✅ Email alerting integration via SMTP
- ✅ Slack webhook notifications
- ✅ HTML/JSON/Markdown/CSV report generation
- ✅ SQLite database for historical tracking
- ✅ CVSS v3.1 scoring and risk assessment
- ✅ Professional CLI with rich output
- ✅ Comprehensive test suite (118 tests)

### 🚀 Future Enhancements

Potential future additions (community contributions welcome):

- [ ] Continuous monitoring mode with scheduled scans
- [ ] REST API interface
- [ ] Web dashboard for visualization
- [ ] Integration with SIEM and SOAR tools
- [ ] Custom pattern definition UI
- [ ] Automated remediation workflows via cloud provider APIs
- [ ] Webhook support for custom integrations
- [ ] Container/Docker deployment options

## Acknowledgments

Special thanks to the security research community and the developers of the underlying tools:

- Certificate Transparency project (crt.sh)
- ProjectDiscovery (subfinder)
- Tom Hudson (assetfinder)
- The Python async ecosystem contributors
