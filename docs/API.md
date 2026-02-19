# API Documentation

Complete API reference for the Security Monitoring Tool.

## Table of Contents

- [REST API (HTTP Endpoints)](#rest-api-http-endpoints)
- [Scanner APIs](#scanner-apis)
- [Detector APIs](#detector-apis)
- [Reporter APIs](#reporter-apis)
- [Alerter APIs](#alerter-apis)
- [Storage APIs](#storage-apis)
- [Utility APIs](#utility-apis)

---

## REST API (HTTP Endpoints)

The scanner provides a REST API via FastAPI. Start it with `security-scanner serve`.

Interactive docs: `http://localhost:8000/docs` (Swagger UI) or `http://localhost:8000/redoc` (ReDoc).

### Authentication

Set `SECURITY_SCANNER_API_KEY` environment variable to enable API key authentication. Pass the key via `X-API-Key` header. Authentication is disabled when the env var is not set.

### Endpoints

#### POST /api/v1/scans

Start a new scan. Returns immediately with a scan_id; the scan runs in the background.

**Request:**

```json
{"domains": ["example.com", "test.com"]}
```

**Response (202):**

```json
{"scan_id": "a1b2c3d4-...", "status": "running", "domains": ["example.com", "test.com"]}
```

#### GET /api/v1/scans

List scans with pagination.

**Query Parameters:** `limit` (default 20), `offset` (default 0)

**Response (200):**

```json
{"scans": [...], "total": 42, "limit": 20, "offset": 0}
```

#### GET /api/v1/scans/{scan_id}

Get scan details including findings.

**Response (200):** Scan metadata, findings list, and severity summary.

#### POST /api/v1/scans/{scan_id}/reports

Generate reports for a completed scan.

**Request:**

```json
{"formats": ["json", "html", "markdown"]}
```

**Response (200):** List of generated report file paths.

#### GET /api/v1/health

Health check. Returns API status and database connectivity. No authentication required.

**Response (200):**

```json
{"status": "healthy", "version": "0.1.0", "database": "connected"}
```

#### GET /api/v1/config/validate

Validate the current scanner configuration.

---

## Scanner APIs

### SubdomainScanner

Discovers subdomains using multiple sources (Certificate Transparency, subfinder, assetfinder).

#### Constructor

```python
SubdomainScanner(
    http_client: HTTPClient,
    subfinder_path: Optional[Path] = None,
    assetfinder_path: Optional[Path] = None,
    sources: Optional[list[str]] = None
)
```

**Parameters:**

- `http_client` (HTTPClient): HTTP client for API requests
- `subfinder_path` (Optional[Path]): Path to subfinder binary
- `assetfinder_path` (Optional[Path]): Path to assetfinder binary
- `sources` (Optional[list[str]]): List of sources to use (default: all)

#### Methods

##### `async scan(domain: str) -> list[SubdomainResult]`

Scan for subdomains of a target domain.

**Parameters:**

- `domain` (str): Target domain to scan

**Returns:**

- `list[SubdomainResult]`: List of discovered subdomains

**Example:**

```python
scanner = SubdomainScanner(http_client=client)
subdomains = await scanner.scan("example.com")

for subdomain in subdomains:
    print(f"{subdomain.domain} (from {subdomain.source})")
```

---

### DNSScanner

Performs DNS resolution with support for multiple record types and nameservers.

####

```python
DNSScanner(
    nameservers: list[str] = ["8.8.8.8", "1.1.1.1"],
    timeout: int = 5,
    max_retries: int = 3
)
```

**Parameters:**

- `nameservers` (list[str]): List of DNS nameservers to use
- `timeout` (int): Query timeout in seconds
- `max_retries` (int): Maximum retry attempts

#### Methods

##### `async scan(domain: str) -> list[DNSResult]`

Perform comprehensive DNS scan for all record types.

**Parameters:**

- `domain` (str): Domain to scan

**Returns:**

- `list[DNSResult]`: DNS records for A, AAAA, CNAME, MX

**Example:**

```python
scanner = DNSScanner(nameservers=["8.8.8.8"])
records = await scanner.scan("example.com")

for record in records:
    print(f"{record.record_type}: {record.values}")
```

##### `async resolve(domain: str, record_type: str, use_cache: bool = True) -> DNSResult`

Resolve specific DNS record type.

**Parameters:**

- `domain` (str): Domain to resolve
- `record_type` (str): Record type (A, AAAA, CNAME, MX)
- `use_cache` (bool): Whether to use cached results

**Returns:**

- `DNSResult`: DNS resolution result

##### `async check_dangling_cname(domain: str) -> tuple[bool, Optional[str]]`

Check if a domain has a dangling CNAME record.

**Parameters:**

- `domain` (str): Domain to check

**Returns:**

- `tuple[bool, Optional[str]]`: (is_dangling, cname_target)

**Example:**

```python
is_dangling, target = await scanner.check_dangling_cname("api.example.com")
if is_dangling:
    print(f"Dangling CNAME: {target}")
```

---

### CertificateScanner

Scans Certificate Transparency logs for certificates.

#### Constructor

```python
CertificateScanner(http_client: HTTPClient)
```

**Parameters:**

- `http_client` (HTTPClient): HTTP client for CT log queries

#### Methods

##### `async scan(domain: str) -> list[CertificateResult]`

Scan CT logs for certificates.

**Parameters:**

- `domain` (str): Domain to search

**Returns:**

- `list[CertificateResult]`: List of certificates

---

## Detector APIs

### DanglingDNSDetector

Detects dangling DNS records that could lead to subdomain takeover.

#### Constructor

```python
DanglingDNSDetector(dns_scanner: DNSScanner)
```

**Parameters:**

- `dns_scanner` (DNSScanner): DNS scanner instance

#### Methods

##### `async detect(data: dict[str, Any]) -> list[Finding]`

Detect dangling DNS records.

**Parameters:**

- `data` (dict): Dictionary with keys:
  - `domain` (str): Target domain
  - `dns_records` (list[DNSResult]): DNS records to analyze
  - `scan_id` (str): Current scan ID

**Returns:**

- `list[Finding]`: List of security findings

**Example:**

```python
detector = DanglingDNSDetector(dns_scanner)
findings = await detector.detect({
    "domain": "example.com",
    "dns_records": dns_results,
    "scan_id": "scan-123"
})

for finding in findings:
    print(f"{finding.severity}: {finding.description}")
```

---

### TakeoverDetector

Detects potential subdomain takeover vulnerabilities.

#### Constructor

```python
TakeoverDetector(
    dns_scanner: DNSScanner,
    http_client: HTTPClient,
    pattern_matcher: Optional[PatternMatcher] = None
)
```

**Parameters:**

- `dns_scanner` (DNSScanner): DNS scanner instance
- `http_client` (HTTPClient): HTTP client for verification
- `pattern_matcher` (Optional[PatternMatcher]): Pattern matcher (auto-created if None)

#### Methods

##### `async detect(data: dict[str, Any]) -> list[Finding]`

Detect subdomain takeover vulnerabilities.

**Parameters:**

- `data` (dict): Dictionary with keys:
  - `domain` (str): Target domain
  - `dns_records` (list[DNSResult]): DNS records to analyze
  - `scan_id` (str): Current scan ID

**Returns:**

- `list[Finding]`: List of findings

---

## Reporter APIs

All reporters implement the `BaseReporter` protocol.

### JSONReporter

Generates detailed JSON reports.

#### Methods

##### `generate(scan_results: dict[str, Any], output_path: Path) -> None`

Generate JSON report.

**Parameters:**

- `scan_results` (dict): Scan results dictionary
- `output_path` (Path): Output file path

**Example:**

```python
reporter = JSONReporter()
reporter.generate(results, Path("report.json"))
```

##### `get_file_extension() -> str`

Returns: `".json"`

---

### HTMLReporter

Generates professional HTML reports with Jinja2 templates.

#### Methods

##### `generate(scan_results: dict[str, Any], output_path: Path) -> None`

Generate HTML report.

**Parameters:**

- `scan_results` (dict): Scan results dictionary
- `output_path` (Path): Output file path

**Example:**

```python
reporter = HTMLReporter()
reporter.generate(results, Path("report.html"))
```

##### `get_file_extension() -> str`

Returns: `".html"`

---

### MarkdownReporter

Generates executive summary in Markdown format.

#### Methods

##### `generate(scan_results: dict[str, Any], output_path: Path) -> None`

Generate Markdown report.

##### `get_file_extension() -> str`

Returns: `".md"`

---

### CSVReporter

Exports findings to CSV format.

#### Methods

##### `generate(scan_results: dict[str, Any], output_path: Path) -> None`

Generate CSV report.

##### `get_file_extension() -> str`

Returns: `".csv"`

---

## Alerter APIs

All alerters implement the `BaseAlerter` protocol.

### EmailAlerter

Sends email alerts via SMTP.

#### Constructor

```python
EmailAlerter(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_email: str,
    to_emails: list[str],
    use_tls: bool = True
)
```

**Parameters:**

- `smtp_host` (str): SMTP server hostname
- `smtp_port` (int): SMTP server port (587 for TLS, 465 for SSL)
- `smtp_user` (str): SMTP username
- `smtp_password` (str): SMTP password
- `from_email` (str): Sender email address
- `to_emails` (list[str]): List of recipient emails
- `use_tls` (bool): Use TLS encryption (default: True)

#### Methods

##### `async send(findings: list[Any], scan_id: str, severity_threshold: str = "HIGH") -> bool`

Send email alert.

**Parameters:**

- `findings` (list): List of findings
- `scan_id` (str): Scan identifier
- `severity_threshold` (str): Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)

**Returns:**

- `bool`: True if sent successfully

**Example:**

```python
alerter = EmailAlerter(
    smtp_host="smtp.gmail.com",
    smtp_port=587,
    smtp_user="alerts@example.com",
    smtp_password="password",
    from_email="alerts@example.com",
    to_emails=["security@example.com"]
)

success = await alerter.send(
    findings=critical_findings,
    scan_id="scan-123",
    severity_threshold="CRITICAL"
)
```

##### `should_alert(finding: Any, severity_threshold: str) -> bool`

Check if finding meets alert criteria.

---

### SlackAlerter

Sends alerts to Slack via webhooks.

#### Constructor

```python
SlackAlerter(
    webhook_url: str,
    http_client: HTTPClient | None = None
)
```

**Parameters:**

- `webhook_url` (str): Slack incoming webhook URL
- `http_client` (Optional[HTTPClient]): HTTP client (auto-created if None)

#### Methods

##### `async send(findings: list[Any], scan_id: str, severity_threshold: str = "HIGH") -> bool`

Send Slack alert.

**Parameters:**

- `findings` (list): List of findings
- `scan_id` (str): Scan identifier
- `severity_threshold` (str): Minimum severity

**Returns:**

- `bool`: True if sent successfully

**Example:**

```python
alerter = SlackAlerter(
    webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
)

await alerter.send(
    findings=findings,
    scan_id="scan-123",
    severity_threshold="HIGH"
)
```

---

## Storage APIs

### DatabaseManager

Manages SQLite database operations.

#### Constructor

```python
DatabaseManager(db_path: Path | str)
```

**Parameters:**

- `db_path` (Path | str): Path to SQLite database file

#### Methods

##### `async initialize() -> None`

Initialize database and create tables.

**Example:**

```python
db = DatabaseManager(Path("security_scanner.db"))
await db.initialize()
```

##### `async create_scan(scan: Scan) -> str`

Create scan record.

**Parameters:**

- `scan` (Scan): Scan object

**Returns:**

- `str`: Scan ID

##### `async create_finding(finding: Finding) -> str`

Create finding record.

**Parameters:**

- `finding` (Finding): Finding object

**Returns:**

- `str`: Finding ID

##### `async get_scan(scan_id: str) -> Optional[Scan]`

Retrieve scan by ID.

**Parameters:**

- `scan_id` (str): Scan ID

**Returns:**

- `Optional[Scan]`: Scan object or None

##### `async get_scan_findings(scan_id: str) -> list[Finding]`

Get all findings for a scan.

**Parameters:**

- `scan_id` (str): Scan ID

**Returns:**

- `list[Finding]`: List of findings

##### `async list_scans(limit: int = 10) -> list[Scan]`

List recent scans.

**Parameters:**

- `limit` (int): Maximum number of scans to return

**Returns:**

- `list[Scan]`: List of scans (most recent first)

##### `async get_similar_findings(domain: str, finding_type: str, days: int = 7) -> list[Finding]`

Find similar findings from recent scans.

**Parameters:**

- `domain` (str): Domain to search
- `finding_type` (str): Type of finding
- `days` (int): Number of days to search back

**Returns:**

- `list[Finding]`: Similar findings

##### `async mark_finding_alerted(finding_id: str) -> None`

Mark finding as alerted.

**Parameters:**

- `finding_id` (str): Finding ID

---

## Utility APIs

### Validators

Domain and input validation utilities.

#### Functions

##### `is_valid_domain(domain: str) -> bool`

Validate domain name format.

**Example:**

```python
from security_scanner.utils.validators import is_valid_domain

if is_valid_domain("example.com"):
    print("Valid domain")
```

##### `normalize_domain(domain: str) -> str`

Normalize domain (lowercase, strip whitespace, remove trailing dot).

**Example:**

```python
domain = normalize_domain("  EXAMPLE.COM.  ")  # Returns "example.com"
```

##### `extract_root_domain(domain: str) -> str`

Extract root domain from subdomain.

**Example:**

```python
root = extract_root_domain("api.sub.example.com")  # Returns "example.com"
```

##### `is_valid_email(email: str) -> bool`

Validate email address format.

##### `is_valid_ipv4(ip: str) -> bool`

Validate IPv4 address format.

---

### HTTPClient

Async HTTP client with retry and rate limiting.

#### Constructor

```python
HTTPClient(
    timeout: int = 30,
    user_agent: str = "SecurityScanner/0.1.0",
    rate_limit: float = 2.0,
    rate_burst: int = 5
)
```

**Parameters:**

- `timeout` (int): Request timeout in seconds
- `user_agent` (str): User-Agent header
- `rate_limit` (float): Requests per second
- `rate_burst` (int): Burst allowance

#### Methods

##### `async get(url: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> dict[str, Any]`

Make GET request.

**Example:**

```python
async with HTTPClient() as client:
    data = await client.get("https://api.example.com/data")
```

##### `async post(url: str, data: Optional[dict] = None, json: Optional[dict] = None) -> dict[str, Any]`

Make POST request.

---

### Logger

Structured logging with structlog.

#### Functions

##### `get_logger(name: str | None = None, **initial_values: Any) -> BoundLogger`

Get a structured logger instance.

**Example:**

```python
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)
logger.info("Scan started", domain="example.com", scan_id="scan-123")
logger.error("Scan failed", error=str(e))
```

---

## Data Models

### Scan

Scan session record.

**Fields:**

- `id` (str): Unique scan ID
- `start_time` (datetime): Scan start time
- `end_time` (Optional[datetime]): Scan end time
- `duration_seconds` (Optional[int]): Scan duration
- `domains_scanned` (list[str]): List of domains scanned
- `status` (str): Scan status (running, completed, failed)
- `total_findings` (int): Total findings count
- `critical_findings` (int): Critical findings count

---

### Finding

Security finding record.

**Fields:**

- `id` (str): Unique finding ID
- `scan_id` (str): Associated scan ID
- `severity` (str): Severity level (CRITICAL, HIGH, MEDIUM, LOW)
- `type` (str): Finding type (dangling_cname, takeover, etc.)
- `domain` (str): Affected domain
- `record_type` (Optional[str]): DNS record type
- `target` (Optional[str]): Target resource
- `description` (str): Finding description
- `cvss_score` (Optional[float]): CVSS score
- `remediation` (str): Remediation steps
- `detected_at` (datetime): Detection timestamp
- `alerted` (bool): Whether alert was sent

---

### DNSResult

DNS resolution result.

**Fields:**

- `domain` (str): Domain queried
- `record_type` (str): Record type (A, AAAA, CNAME, MX)
- `values` (list[str]): Record values
- `ttl` (int): Time to live
- `nameserver` (str): Nameserver used
- `error` (Optional[str]): Error message if resolution failed
- `is_dangling` (bool): Whether record is dangling

---

## Error Handling

### Exception Hierarchy

```bash
SecurityScannerError (base)
├── ConfigurationError
├── NetworkError
│   ├── DNSError
│   └── APIError
├── ValidationError
└── AlerterError
```

### Usage

```python
from security_scanner.utils.exceptions import DNSError

try:
    result = await scanner.resolve("example.com", "A")
except DNSError as e:
    logger.error("DNS resolution failed", error=str(e), domain=e.domain)
```

---

## CLI Usage

### Main Commands

```bash
# Run scan
security-scanner scan -d example.com

# Multiple domains
security-scanner scan -d example.com -d test.com

# From file
security-scanner scan --domains-file domains.txt

# With alerts
security-scanner scan -d example.com --alert-email --alert-slack

# Initialize database
security-scanner init-db

# List scans
security-scanner list-scans --limit 10

# Validate configuration
security-scanner validate-config
```

### Options

- `--verbose / -v`: Enable verbose output
- `--quiet / -q`: Quiet mode (errors only)
- `--output / -o`: Output directory
- `--format`: Report formats (json,html,md,csv)
- `--config / -c`: Configuration file
- `--severity-threshold`: Minimum severity for alerts

---

## Configuration

### Environment Variables

```bash
# Database
DATABASE_PATH=data/security_scanner.db

# SMTP Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@example.com
SMTP_PASSWORD=your_password
FROM_EMAIL=alerts@example.com
TO_EMAILS=security@example.com,team@example.com

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Scanner
DNS_NAMESERVERS=8.8.8.8,1.1.1.1
MAX_CONCURRENT_DNS=50
RATE_LIMIT=2.0
```

### Configuration File

```yaml
# config/settings.yaml
database:
  path: data/security_scanner.db

scanner:
  dns_nameservers:
    - 8.8.8.8
    - 1.1.1.1
  max_concurrent: 50
  rate_limit: 2.0
  timeout: 30

alerts:
  email:
    enabled: true
    severity_threshold: HIGH
  slack:
    enabled: true
    severity_threshold: CRITICAL
```

---

## Complete Example

```python
import asyncio
from pathlib import Path
from security_scanner.scanner.subdomain import SubdomainScanner
from security_scanner.scanner.dns import DNSScanner
from security_scanner.detectors.dangling_dns import DanglingDNSDetector
from security_scanner.reporters import JSONReporter, HTMLReporter
from security_scanner.alerters import EmailAlerter
from security_scanner.utils.http_client import HTTPClient
from security_scanner.storage.database import DatabaseManager
from security_scanner.storage.models import Scan

async def main():
    # Initialize components
    http_client = HTTPClient()
    subdomain_scanner = SubdomainScanner(http_client)
    dns_scanner = DNSScanner()
    detector = DanglingDNSDetector(dns_scanner)
    db = DatabaseManager(Path("scan.db"))
    await db.initialize()

    # Create scan
    scan = Scan(domains_scanned=["example.com"])
    scan_id = await db.create_scan(scan)

    # Discover subdomains
    subdomains = await subdomain_scanner.scan("example.com")
    print(f"Found {len(subdomains)} subdomains")

    # Check DNS
    dns_records = []
    for sub in subdomains[:10]:  # Limit for demo
        records = await dns_scanner.scan(sub.domain)
        dns_records.extend(records)

    # Detect issues
    findings = await detector.detect({
        "domain": "example.com",
        "dns_records": dns_records,
        "scan_id": scan_id
    })

    # Store findings
    for finding in findings:
        await db.create_finding(finding)

    # Generate reports
    results = {
        "scan_id": scan_id,
        "domain": "example.com",
        "findings": findings,
        "subdomains": subdomains
    }

    JSONReporter().generate(results, Path("report.json"))
    HTMLReporter().generate(results, Path("report.html"))

    # Send alerts
    if findings:
        alerter = EmailAlerter(
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_user="alerts@example.com",
            smtp_password="password",
            from_email="alerts@example.com",
            to_emails=["security@example.com"]
        )
        await alerter.send(findings, scan_id, "HIGH")

    await http_client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## API Version

**Version:** 0.1.0
**Last Updated:** 2026-02-19

For the latest API documentation, see: <https://github.com/Ap6pack/security-monitoring>
