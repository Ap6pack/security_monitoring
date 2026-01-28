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
  - Heroku, GitHub Pages, AWS S3, Azure, GCP
  - HTTP fingerprinting
  - Confidence scoring

- **Professional Reporting**
  - SQLite database for historical tracking
  - CVSS scoring
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

- Follow PEP 8 style guidelines
- Add type hints to all functions
- Write tests for new features
- Update documentation as needed
- Maintain >80% test coverage

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

## Credits

Based on research from Black Hat 2025 on cross-origin web attacks and subdomain takeover vulnerabilities. This tool was developed to help security teams identify and remediate these critical vulnerabilities in their infrastructure.

## Author

Adam Rhys Heaton (Ap6pack)

## Roadmap

Future enhancements planned:

- [ ] Email alerting integration
- [ ] Slack webhook notifications
- [ ] HTML report generation
- [ ] Continuous monitoring mode
- [ ] REST API interface
- [ ] Web dashboard
- [ ] Additional cloud platform patterns
- [ ] Integration with SIEM and SOAR tools
- [ ] Custom pattern definition UI
- [ ] Automated remediation workflows

## Acknowledgments

Special thanks to the security research community and the developers of the underlying tools:

- Certificate Transparency project (crt.sh)
- ProjectDiscovery (subfinder)
- Tom Hudson (assetfinder)
- The Python async ecosystem contributors
