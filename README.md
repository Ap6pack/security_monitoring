# Security Scanner

A professional security scanning tool that detects cross-origin web attack vulnerabilities, dangling DNS records, shared certificates, and potential domain takeover risks. Built on research presented at Black Hat 2025.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/Ap6pack/security-monitoring/actions/workflows/ci.yml/badge.svg)](https://github.com/Ap6pack/security-monitoring/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Table of Contents

- [What It Does](#what-it-does)
- [Why This Matters](#why-this-matters)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [REST API](#rest-api)
- [Continuous Monitoring](#continuous-monitoring)
- [Docker Deployment](#docker-deployment)
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
  - CT log analysis via crt.sh API
  - Local JSON file fallback (bypass rate limiting)
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
  - AlertManager with multi-channel dispatch and fault isolation
  - Email alerts via SMTP with HTML formatting
  - Slack webhook notifications with rich formatting
  - Generic webhook alerts (PagerDuty, Teams, custom endpoints)
  - Severity-based alert filtering and deduplication
  - Alert history tracking per channel per finding
  - SQLite database for historical tracking
  - CVSS v3.1 scoring
  - Detailed remediation guidance

- **REST API (FastAPI)**
  - Full CRUD API for scans and findings
  - Async background scan execution
  - Report generation via API
  - Health check and config validation endpoints
  - Optional API key authentication
  - Pydantic request/response models

- **Continuous Monitoring Mode**
  - Scheduled scan daemon with configurable intervals
  - Delta detection — alerts only on new findings
  - Automatic alert dispatch on new findings via AlertManager
  - Graceful signal handling (SIGINT/SIGTERM)
  - Scan history tracking and comparison

- **Docker Deployment**
  - Multi-stage Dockerfile with non-root user
  - docker-compose with API and monitor services
  - Persistent volumes for data and reports
  - WAL journal mode for concurrent SQLite access

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

## REST API

The scanner includes a full REST API built with FastAPI for programmatic access.

### Start the API Server

```bash
security-scanner serve --host 0.0.0.0 --port 8000
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans` | Start a new scan (async, returns scan_id) |
| `GET` | `/api/v1/scans` | List scans with pagination |
| `GET` | `/api/v1/scans/{scan_id}` | Get scan details and findings |
| `POST` | `/api/v1/scans/{scan_id}/reports` | Generate reports |
| `GET` | `/api/v1/health` | Health check with DB status |
| `GET` | `/api/v1/config/validate` | Validate configuration |

### Example: Start a Scan via API

```bash
# Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"]}'

# Check scan status
curl http://localhost:8000/api/v1/scans/<scan_id>
```

### API Authentication

API key authentication is optional. Set `SECURITY_SCANNER_API_KEY` in your environment to enable it:

```bash
export SECURITY_SCANNER_API_KEY=your-secret-key

# Then pass the key via header
curl -H "X-API-Key: your-secret-key" http://localhost:8000/api/v1/scans
```

Interactive API docs are available at `http://localhost:8000/docs` when the server is running.

## Continuous Monitoring

Run the scanner as a daemon that performs scheduled scans and alerts on new findings.

### Start Monitoring

```bash
# Scan every hour
security-scanner monitor -d example.com --interval 3600

# Monitor multiple domains
security-scanner monitor -d example.com -d api.example.com --interval 1800
```

The monitor daemon:

- Runs scans at the configured interval
- Detects new findings by comparing against the last 7 days
- Dispatches alerts via AlertManager when new findings are detected
- Logs all activity with structured logging
- Handles SIGINT/SIGTERM for graceful shutdown

## Docker Deployment

### Using Docker Compose

```bash
# Start API server
docker-compose up -d scanner-api

# Start monitoring daemon
docker-compose --profile monitoring up -d

# View logs
docker-compose logs -f scanner-api
```

### Using Docker Directly

```bash
# Build image
docker build -t security-scanner .

# Run API server
docker run -p 8000:8000 -v scanner-data:/app/data security-scanner

# Run a one-off scan
docker run -v scanner-data:/app/data security-scanner scan -d example.com
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

# Certificate Data (optional - fallback for rate limiting)
# If crt.sh API returns 429 errors, download JSON manually:
# 1. Visit: https://crt.sh/json?q=yourdomain.com in your browser
# 2. Save response to: data/crtsh_yourdomain.json
# 3. Set: CERTIFICATE_JSON_FILE=data/crtsh_yourdomain.json
CERTIFICATE_JSON_FILE=

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

# Webhook (generic HTTP POST — PagerDuty, Teams, custom)
ENABLE_WEBHOOK_ALERTS=false
WEBHOOK_URL=https://your-webhook-endpoint.example.com/alerts
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

### API Server

```bash
# Start REST API server
security-scanner serve --host 0.0.0.0 --port 8000

# With auto-reload for development
security-scanner serve --reload
```

### Monitoring Mode

```bash
# Start continuous monitoring (scan every hour)
security-scanner monitor -d example.com --interval 3600

# Monitor multiple domains
security-scanner monitor -d example.com -d test.com --interval 1800
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
│   ├── api/                   # REST API (FastAPI)
│   │   ├── routes/            # API endpoint handlers
│   │   ├── app.py             # Application factory
│   │   ├── auth.py            # API key authentication
│   │   ├── dependencies.py    # Dependency injection
│   │   └── models.py          # Request/response schemas
│   ├── scanner/               # Scanner modules
│   ├── detectors/             # Vulnerability detectors
│   ├── reporters/             # Report generators
│   ├── alerters/              # Alert channels
│   ├── storage/               # Database and caching
│   ├── utils/                 # Utility functions
│   ├── config.py              # Configuration management
│   ├── orchestrator.py        # Scan orchestration
│   ├── scheduler.py           # Scan scheduling engine
│   ├── monitor.py             # Monitoring daemon
│   └── main.py                # CLI interface
├── .github/workflows/         # CI/CD pipeline
├── config/                    # Configuration files
├── tests/                     # Test suite (488 tests)
├── data/                      # Database storage
├── logs/                      # Application logs
├── reports/                   # Generated reports
├── Dockerfile                 # Container image
└── docker-compose.yml         # Multi-service deployment
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

### Webhook Alerts

Configure generic HTTP POST webhook notifications for any endpoint (PagerDuty, Teams, custom):

```bash
ENABLE_WEBHOOK_ALERTS=true
WEBHOOK_URL=https://your-webhook-endpoint.example.com/alerts
```

Webhook alerts send a JSON payload containing:

- Scan ID and timestamp
- Findings count and severity summary
- Full finding details (domain, description, CVSS, remediation)

### Alert Thresholds

Control which findings trigger alerts:

- `ALERT_ON_CRITICAL=true` - Alert on critical findings
- `ALERT_ON_HIGH=true` - Alert on high severity findings
- `ALERT_MIN_FINDINGS=1` - Minimum findings to trigger alert

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

#### crt.sh rate limiting (429 errors)

If you encounter "429 Too Many Requests" errors from crt.sh:

1. **Wait a few minutes** - Rate limits reset after a short period
2. **Use a local JSON file** as fallback:

   ```bash
   # Download certificate data in your browser
   # Visit: https://crt.sh/json?q=yourdomain.com
   # Save the JSON response to: data/crtsh_yourdomain.json

   # Configure the scanner to use the file
   export CERTIFICATE_JSON_FILE=data/crtsh_yourdomain.json

   # Run scan - it will use the file instead of API
   security-scanner scan -d yourdomain.com
   ```

3. **Reduce scan frequency** - Space out scans to avoid hitting rate limits

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
- Maintain 100% test pass rate (currently 488 tests passing)
- Coverage gate: 80%+ (currently 85%+)
- All code is type-safe with zero mypy errors
- CI pipeline validates all PRs (lint, types, tests across Python 3.11-3.13)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

## Credits

Based on research from Black Hat 2025 on cross-origin web attacks and subdomain takeover vulnerabilities. This tool was developed to help security teams identify and remediate these critical vulnerabilities in their infrastructure.

## Author

Adam Rhys Heaton (Ap6pack)

## Status

**Current Version: 0.1.0** - Production Ready

488 tests passing, 85%+ coverage, zero lint/type errors, CI/CD pipeline active.

### Implemented Features

- Multi-source subdomain discovery (crt.sh, subfinder, assetfinder)
- Comprehensive DNS analysis with dangling CNAME detection
- Platform-specific takeover detection (8 platforms: Heroku, GitHub Pages, AWS S3/EB, Azure, GCP, Netlify, Vercel)
- AlertManager with multi-channel dispatch, deduplication, and fault isolation
- Email alerting integration via SMTP with HTML formatting
- Slack webhook notifications with rich formatting
- Generic webhook alerts (PagerDuty, Teams, custom endpoints)
- HTML/JSON/Markdown/CSV report generation
- SQLite database for historical tracking and deduplication
- CVSS v3.1 scoring and risk assessment
- Professional CLI with rich output and progress tracking
- REST API with FastAPI (async background scans, report generation, health checks)
- Continuous monitoring mode with scheduled scans and delta detection
- Docker deployment with docker-compose (API + monitor services)
- CI/CD pipeline (GitHub Actions: lint, types, tests across Python 3.11-3.13)
- Type-safe codebase (mypy strict mode, zero errors)
- 488-test suite with 85%+ coverage

### Future Enhancements

Potential future additions (community contributions welcome):

- [ ] Automated remediation workflows via cloud provider APIs (AWS Route53, Cloudflare, etc.)
- [ ] Alerting digest mode (daily/weekly summaries instead of immediate alerts)
- [ ] GraphQL API for flexible querying
- [ ] Integration with SIEM platforms (Splunk, Elastic, QRadar)
- [ ] Integration with SOAR tools (TheHive, Cortex, Demisto)
- [ ] Web dashboard for visualization and management
- [ ] DNS hijacking detection
- [ ] TLS/SSL misconfiguration scanning
- [ ] CORS policy analysis / CSP header validation
- [ ] Kubernetes Helm charts
- [ ] High-availability clustering support

## Acknowledgments

Special thanks to the security research community and the developers of the underlying tools:

- Certificate Transparency project (crt.sh)
- ProjectDiscovery (subfinder)
- Tom Hudson (assetfinder)
- The Python async ecosystem contributors
