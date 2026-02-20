# Architecture Documentation

This document provides a comprehensive overview of the Security Monitoring Tool's architecture, including system design, component interactions, and data flow.

## Table of Contents

- [System Overview](#system-overview)
- [High-Level Architecture](#high-level-architecture)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Database Schema](#database-schema)
- [Deployment Architecture](#deployment-architecture)

---

## System Overview

The Security Monitoring Tool is a professional-grade security scanner designed to detect cross-origin web attack vulnerabilities, including dangling DNS records and subdomain takeover risks.

### Key Features

- **Multi-source subdomain discovery** (Certificate Transparency, subfinder, assetfinder)
- **Comprehensive DNS analysis** (A, AAAA, CNAME, MX records)
- **Intelligent detection** (dangling DNS, subdomain takeover across 8 platforms)
- **Flexible reporting** (JSON, HTML, Markdown, CSV)
- **Real-time alerting** (Email via SMTP, Slack via webhooks, generic webhooks)
- **Persistent storage** (SQLite with async operations)

### Technology Stack

- **Language:** Python 3.11+
- **Async Framework:** asyncio
- **HTTP Client:** aiohttp
- **REST API:** FastAPI + Uvicorn
- **Database:** SQLite (aiosqlite) with WAL journal mode
- **DNS Resolution:** dnspython
- **CLI Framework:** Typer
- **Templating:** Jinja2
- **Logging:** structlog
- **Type Checking:** mypy (strict mode)
- **CI/CD:** GitHub Actions

---

## High-Level Architecture

```mermaid
graph TB
    User[User] --> CLI[CLI Interface<br/>Typer]
    CLI --> Orchestrator[Scan Orchestrator]

    Orchestrator --> SubScan[Subdomain Scanner]
    Orchestrator --> DNSScan[DNS Scanner]
    Orchestrator --> CertScan[Certificate Scanner]
    Orchestrator --> Detectors[Detectors]

    SubScan --> CrtSh[crt.sh API]
    SubScan --> Subfinder[subfinder]
    SubScan --> AssetFinder[assetfinder]

    DNSScan --> DNS[DNS Resolvers<br/>8.8.8.8, 1.1.1.1]

    CertScan --> CrtSh

    Detectors --> DanglingDNS[Dangling DNS Detector]
    Detectors --> Takeover[Takeover Detector]

    Orchestrator --> DB[(SQLite Database)]
    Orchestrator --> Reporters[Report Generators]
    Orchestrator --> Alerters[Alert System]

    Reporters --> JSON[JSON Report]
    Reporters --> HTML[HTML Report]
    Reporters --> MD[Markdown Report]
    Reporters --> CSV[CSV Export]

    Alerters --> AlertMgr[AlertManager<br/>Coordinator]
    AlertMgr --> Email[Email<br/>SMTP + TLS]
    AlertMgr --> Slack[Slack<br/>Webhooks]
    AlertMgr --> Webhook[Webhook<br/>HTTP POST]

    style Orchestrator fill:#4CAF50,color:#fff
    style DB fill:#2196F3,color:#fff
    style Reporters fill:#FF9800,color:#fff
    style Alerters fill:#F44336,color:#fff
```

### Architecture Layers

1. **Presentation Layer** - CLI interface with Rich output, REST API with FastAPI
2. **Orchestration Layer** - Scan coordination, scheduling, and monitoring daemon
3. **Scanner Layer** - Data collection from multiple sources
4. **Detection Layer** - Vulnerability analysis and pattern matching
5. **Storage Layer** - Data persistence and retrieval
6. **Output Layer** - Reporting and alerting

---

## Component Architecture

```mermaid
graph LR
    subgraph Scanner Layer
        Base[BaseScannerProtocol] -.implements.-> Sub[SubdomainScanner]
        Base -.implements.-> DNS[DNSScanner]
        Base -.implements.-> Cert[CertificateScanner]
    end

    subgraph Detection Layer
        Det[BaseDetector] -.implements.-> Dang[DanglingDNSDetector]
        Det -.implements.-> Take[TakeoverDetector]
        Take --> Patterns[PatternMatcher]
    end

    subgraph Data Layer
        Config[ConfigManager]
        Storage[DatabaseManager]
        Cache[CacheManager]
    end

    subgraph Output Layer
        Rep[BaseReporter] -.implements.-> JR[JSONReporter]
        Rep -.implements.-> HR[HTMLReporter]
        Rep -.implements.-> MR[MarkdownReporter]
        Rep -.implements.-> CR[CSVReporter]

        Alert[BaseAlerter] -.implements.-> EA[EmailAlerter]
        Alert -.implements.-> SA[SlackAlerter]
        Alert -.implements.-> WA[WebhookAlerter]
        AM[AlertManager] --> EA
        AM --> SA
        AM --> WA
    end

    subgraph Utils
        HTTP[HTTPClient]
        Log[Logger]
        Valid[Validators]
        Rate[RateLimiter]
    end

    Sub --> HTTP
    Cert --> HTTP
    Take --> HTTP
    DNS --> Cache

    style Base fill:#E3F2FD
    style Det fill:#E8F5E9
    style Rep fill:#FFF3E0
    style Alert fill:#FFEBEE
```

### Design Patterns

- **Protocol Pattern** - Interface definitions for extensibility
- **Factory Pattern** - Component creation and initialization
- **Strategy Pattern** - Multiple detection algorithms
- **Observer Pattern** - Event-driven alerting
- **Repository Pattern** - Data access abstraction
- **Singleton Pattern** - Logger and configuration

---

## Data Flow

### Complete Scan Workflow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Orchestrator
    participant SubdomainScanner
    participant DNSScanner
    participant Detector
    participant DB
    participant Reporter
    participant Alerter

    User->>CLI: security-scanner scan -d example.com
    CLI->>Orchestrator: initialize_scan()
    Orchestrator->>DB: create_scan_record()
    DB-->>Orchestrator: scan_id

    Note over Orchestrator: Phase 1: Discovery
    Orchestrator->>SubdomainScanner: scan(domain)
    SubdomainScanner->>SubdomainScanner: query_crtsh()
    SubdomainScanner->>SubdomainScanner: run_subfinder()
    SubdomainScanner->>SubdomainScanner: run_assetfinder()
    SubdomainScanner-->>Orchestrator: List[subdomains]

    Note over Orchestrator: Phase 2: DNS Analysis
    loop For each subdomain
        Orchestrator->>DNSScanner: scan(subdomain)
        DNSScanner->>DNSScanner: resolve A, AAAA, CNAME, MX
        DNSScanner-->>Orchestrator: DNSResults
    end

    Note over Orchestrator: Phase 3: Detection
    Orchestrator->>Detector: detect(dns_records)
    Detector->>Detector: check_dangling_cname()
    Detector->>Detector: check_takeover_patterns()
    Detector-->>Orchestrator: List[findings]

    Note over Orchestrator: Phase 4: Storage
    loop For each finding
        Orchestrator->>DB: create_finding()
    end

    Orchestrator->>DB: update_scan_status()

    Note over Orchestrator: Phase 5: Reporting
    Orchestrator->>Reporter: generate_reports()
    Reporter-->>User: JSON, HTML, MD, CSV files

    Note over Orchestrator: Phase 6: Alerting
    alt Critical findings exist
        Orchestrator->>Alerter: AlertManager.process_findings()
        Alerter->>Alerter: filter_unalerted()
        Alerter->>Alerter: check_severity_threshold()
        Alerter->>Alerter: dispatch to Email/Slack/Webhook
        Alerter->>DB: create_alert_history()
        Alerter->>DB: mark_findings_alerted()
        Alerter-->>User: Email/Slack/Webhook notification
    end

    Orchestrator-->>CLI: scan_complete
    CLI-->>User: Display summary
```

### DNS Resolution Flow

```mermaid
flowchart TD
    Start([Resolve Domain]) --> CheckCache{Cache Hit?}
    CheckCache -->|Yes| ReturnCached[Return Cached Result]
    CheckCache -->|No| Query[Query Nameserver]

    Query --> QueryType{Record Type?}
    QueryType -->|A/AAAA| ResolveIP[Resolve IP Address]
    QueryType -->|CNAME| ResolveCNAME[Resolve CNAME]
    QueryType -->|MX| ResolveMX[Resolve Mail Server]

    ResolveIP --> Success1{Success?}
    ResolveCNAME --> Success2{Success?}
    ResolveMX --> Success3{Success?}

    Success1 -->|Yes| CacheResult1[Cache with TTL]
    Success1 -->|No| HandleError1[Handle NXDOMAIN/Timeout]

    Success2 -->|Yes| CheckTarget{Target Resolves?}
    Success2 -->|No| HandleError2[Mark as Dangling]

    Success3 -->|Yes| CacheResult3[Cache with TTL]
    Success3 -->|No| HandleError3[Handle Error]

    CheckTarget -->|Yes| CacheResult2[Cache CNAME]
    CheckTarget -->|No| MarkDangling[Mark as Dangling CNAME]

    CacheResult1 --> Return[Return DNSResult]
    CacheResult2 --> Return
    CacheResult3 --> Return
    HandleError1 --> Return
    HandleError2 --> Return
    HandleError3 --> Return
    MarkDangling --> Return
    ReturnCached --> Return

    Return --> End([End])

    style Start fill:#4CAF50,color:#fff
    style Return fill:#2196F3,color:#fff
    style MarkDangling fill:#F44336,color:#fff
    style End fill:#4CAF50,color:#fff
```

### Detection Logic Flow

```mermaid
flowchart TD
    Start([Analyze DNS Records]) --> FilterCNAME[Filter CNAME Records]

    FilterCNAME --> LoopCNAME{For Each CNAME}
    LoopCNAME --> CheckDangling[Check if Target Resolves]

    CheckDangling --> IsDangling{Target NXDOMAIN?}
    IsDangling -->|Yes| CreateCritical[Create CRITICAL Finding<br/>Dangling CNAME]
    IsDangling -->|No| CheckPlatform[Check Platform Patterns]

    CheckPlatform --> MatchPattern{Pattern Match?}
    MatchPattern -->|Yes| CheckHTTP[HTTP Verification]
    MatchPattern -->|No| NextCNAME[Next CNAME]

    CheckHTTP --> HTTPMatch{Error Pattern?}
    HTTPMatch -->|Yes| CreateHigh[Create HIGH Finding<br/>Takeover Risk]
    HTTPMatch -->|No| NextCNAME

    CreateCritical --> CalcCVSS1[Calculate CVSS Score<br/>9.1]
    CreateHigh --> CalcCVSS2[Calculate CVSS Score<br/>7.5-8.5]

    CalcCVSS1 --> StoreDB1[(Store in Database)]
    CalcCVSS2 --> StoreDB2[(Store in Database)]

    StoreDB1 --> NextCNAME
    StoreDB2 --> NextCNAME

    NextCNAME --> LoopCNAME
    LoopCNAME -->|Done| FilterIP[Filter A/AAAA Records]

    FilterIP --> CheckUnresponsive[Check for Unresponsive IPs]
    CheckUnresponsive --> CreateMedium{Found Issues?}
    CreateMedium -->|Yes| CreateMediumFinding[Create MEDIUM Finding]
    CreateMedium -->|No| Complete[Complete]

    CreateMediumFinding --> Complete
    Complete --> End([Return Findings])

    style Start fill:#4CAF50,color:#fff
    style CreateCritical fill:#D32F2F,color:#fff
    style CreateHigh fill:#F57C00,color:#fff
    style CreateMedium fill:#FBC02D,color:#333
    style End fill:#4CAF50,color:#fff
```

---

## Database Schema

### Entity Relationship Diagram

```mermaid
erDiagram
    SCANS ||--o{ FINDINGS : contains
    SCANS ||--o{ CERTIFICATES : discovers
    FINDINGS ||--o{ ALERT_HISTORY : triggers

    SCANS {
        string id PK "UUID"
        datetime start_time
        datetime end_time
        int duration_seconds
        json domains_scanned
        string status "running|completed|failed"
        string scanner_version
        int total_findings
        int critical_findings
        int high_findings
        int medium_findings
        int low_findings
    }

    FINDINGS {
        string id PK "UUID"
        string scan_id FK
        string severity "CRITICAL|HIGH|MEDIUM|LOW"
        string type "dangling_cname|takeover|nxdomain"
        string domain
        string record_type "A|AAAA|CNAME|MX"
        string target "Optional"
        text description
        float cvss_score
        text remediation
        json raw_data
        datetime detected_at
        datetime first_seen
        boolean alerted
        string platform "Optional"
        float confidence "0.0-1.0"
    }

    CERTIFICATES {
        string id PK "UUID"
        string scan_id FK
        string cert_id
        string issuer
        datetime expires
        boolean shared
        int san_count
        json san_domains
        json external_domains
        string risk_level
        datetime logged_at
    }

    ALERT_HISTORY {
        string id PK "UUID"
        string finding_id FK
        string channel "email|slack|webhook"
        datetime sent_at
        boolean success
        text error_message
        int retry_count
    }
```

### Indexes

```sql
-- Performance-critical indexes
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_domain ON findings(domain);
CREATE INDEX idx_findings_detected_at ON findings(detected_at);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_start_time ON scans(start_time);
CREATE INDEX idx_certificates_scan_id ON certificates(scan_id);
CREATE INDEX idx_alert_history_finding_id ON alert_history(finding_id);
```

---

## Deployment Architecture

### Single-Server Deployment

```mermaid
graph TB
    subgraph "Production Server"
        CLI[CLI Application]
        Python[Python 3.11+ Runtime]

        CLI --> Scanner[Scanner Components]
        Scanner --> SubScan[Subdomain Scanner]
        Scanner --> DNSScan[DNS Scanner]
        Scanner --> CertScan[Certificate Scanner]

        CLI --> Detectors[Detector Components]
        CLI --> Reports[Report Generators]
        CLI --> Alerts[Alert System]

        CLI --> DB[(SQLite Database<br/>security_scanner.db)]

        DB --> Backup[Automated Backups<br/>Daily]
    end

    subgraph "External Services"
        CrtSh[crt.sh API]
        DNS1[8.8.8.8]
        DNS2[1.1.1.1]
        SMTP[SMTP Server<br/>TLS Port 587]
        Slack[Slack Webhooks]
    end

    SubScan --> CrtSh
    DNSScan --> DNS1
    DNSScan --> DNS2
    Alerts --> SMTP
    Alerts --> Slack

    subgraph "Monitoring"
        Logs[Structured Logs<br/>logs/security_scanner.log]
        Metrics[Performance Metrics]
    end

    CLI --> Logs
    CLI --> Metrics

    style CLI fill:#4CAF50,color:#fff
    style DB fill:#2196F3,color:#fff
    style Logs fill:#FF9800,color:#333
```

### Docker Deployment

```mermaid
graph TB
    subgraph "Docker Host"
        subgraph "Scanner Container"
            App[Security Scanner]
            Venv[Python venv]
            Code[Application Code]
        end

        subgraph "Volumes"
            Data[/data<br/>Database]
            Logs[/logs<br/>Log Files]
            Reports[/reports<br/>Generated Reports]
            Config[/config<br/>Configuration]
        end

        App --> Data
        App --> Logs
        App --> Reports
        App --> Config
    end

    subgraph "External"
        DNS[DNS Servers]
        APIs[External APIs]
        Email[Email Server]
        SlackAPI[Slack API]
    end

    App --> DNS
    App --> APIs
    App --> Email
    App --> SlackAPI

    style App fill:#4CAF50,color:#fff
    style Data fill:#2196F3,color:#fff
```

### Cron-Based Scheduling

```mermaid
sequenceDiagram
    participant Cron
    participant Script
    participant Scanner
    participant DB
    participant Alerter
    participant Admin

    Note over Cron: Daily at 2 AM
    Cron->>Script: /usr/local/bin/run-scan.sh
    Script->>Scanner: security-scanner scan --domains-file domains.txt

    Scanner->>Scanner: Perform full scan
    Scanner->>DB: Store findings
    Scanner->>Scanner: Generate reports
    Scanner-->>Script: Exit with status

    alt Critical findings found
        Script->>Alerter: Send alerts
        Alerter->>Admin: Email/Slack notification
    end

    Script->>Script: Log execution
    Script-->>Cron: Complete
```

### Scaling Architecture (Future)

```mermaid
graph TB
    subgraph "Load Balancer"
        LB[Nginx/HAProxy]
    end

    subgraph "API Layer"
        API1[API Server 1]
        API2[API Server 2]
        API3[API Server 3]
    end

    subgraph "Worker Pool"
        Worker1[Scanner Worker 1]
        Worker2[Scanner Worker 2]
        Worker3[Scanner Worker 3]
    end

    subgraph "Queue"
        Redis[Redis Queue<br/>Scan Jobs]
    end

    subgraph "Storage"
        Postgres[(PostgreSQL<br/>Primary Database)]
        S3[S3-Compatible<br/>Report Storage]
    end

    LB --> API1
    LB --> API2
    LB --> API3

    API1 --> Redis
    API2 --> Redis
    API3 --> Redis

    Redis --> Worker1
    Redis --> Worker2
    Redis --> Worker3

    Worker1 --> Postgres
    Worker2 --> Postgres
    Worker3 --> Postgres

    Worker1 --> S3
    Worker2 --> S3
    Worker3 --> S3

    style LB fill:#4CAF50,color:#fff
    style Redis fill:#F44336,color:#fff
    style Postgres fill:#2196F3,color:#fff
```

---

## System Components

### Core Components

| Component | Responsibility | Technology |
|-----------|---------------|------------|
| CLI | User interface, command parsing | Typer, Rich |
| REST API | HTTP API for programmatic access | FastAPI, Uvicorn |
| Orchestrator | Workflow coordination | asyncio |
| Scheduler | Scan scheduling and delta detection | asyncio |
| Monitor Daemon | Signal handling, graceful lifecycle | asyncio, signal |
| Subdomain Scanner | Subdomain discovery | aiohttp, subprocess |
| DNS Scanner | DNS resolution | dnspython |
| Certificate Scanner | CT log analysis | aiohttp |
| Dangling DNS Detector | Vulnerability detection | Custom logic |
| Takeover Detector | Pattern matching | Custom patterns |
| Database Manager | Data persistence | aiosqlite |
| Report Generators | Output formatting | Jinja2, csv |
| AlertManager | Alert coordination and dispatch | Custom |
| Alert System | Notifications | smtplib, aiohttp |

### External Dependencies

| Service | Purpose | Rate Limits |
|---------|---------|-------------|
| crt.sh | Certificate Transparency logs | 1-2 req/sec |
| DNS Resolvers | DNS resolution | No limit (public) |
| SMTP Server | Email delivery | Provider-dependent |
| Slack Webhooks | Slack notifications | 1 req/sec |
| Custom Webhooks | Generic HTTP POST alerts | Endpoint-dependent |
| subfinder | Subdomain enumeration | N/A (local) |
| assetfinder | Subdomain enumeration | N/A (local) |

---

## Performance Characteristics

### Throughput

- **Subdomain Discovery:** 100-500 subdomains/minute (varies by source)
- **DNS Resolution:** 50 concurrent queries (configurable)
- **Detection:** 1000+ records/second
- **Report Generation:** <1 second for 1000 findings

### Latency

- **Single DNS Query:** 50-200ms (network dependent)
- **Database Write:** <1ms (SQLite)
- **Report Generation:** 100-500ms
- **Email Alert:** 500-2000ms (network dependent)

### Resource Usage

- **Memory:** ~50-100MB baseline, +100KB per 1000 subdomains
- **CPU:** Minimal (I/O bound)
- **Disk:** ~10MB per 1000 findings (database)
- **Network:** ~100KB per subdomain scan

---

## Security Architecture

### Security Controls

```mermaid
flowchart LR
    subgraph "Input Validation"
        Domains[Domain Input] --> Validate[Validate Format]
        Validate --> Sanitize[Sanitize Input]
    end

    subgraph "Network Security"
        TLS[TLS/SSL<br/>Encryption]
        RateLimit[Rate Limiting]
        Timeout[Timeouts]
    end

    subgraph "Data Security"
        Encrypt[Credential<br/>Encryption]
        NoLog[No PII Logging]
        SecureDB[Secure Database]
    end

    subgraph "Error Handling"
        Try[Try/Except]
        Log[Structured Logging]
        Graceful[Graceful Degradation]
    end

    Sanitize --> TLS
    TLS --> RateLimit
    RateLimit --> Timeout
    Timeout --> Try
    Try --> Log
    Log --> Graceful

    Encrypt --> SecureDB
    NoLog --> Log

    style Validate fill:#4CAF50,color:#fff
    style TLS fill:#2196F3,color:#fff
    style Encrypt fill:#F44336,color:#fff
```

### Security Features

- ✅ Input validation (all user inputs)
- ✅ TLS/SSL encryption (email, HTTPS)
- ✅ No command injection (subprocess with list args)
- ✅ Rate limiting (respect API limits)
- ✅ Secure credential storage (environment variables)
- ✅ No PII in logs
- ✅ SQL injection prevention (parameterized queries)
- ✅ Timeout protection (all network operations)

---

## Monitoring & Observability

### Logging Architecture

```mermaid
flowchart LR
    App[Application] --> StructLog[Structlog]
    StructLog --> Console[Console Output<br/>Development]
    StructLog --> File[Log File<br/>Production]

    File --> Rotation[Log Rotation<br/>Daily]

    Console --> Format1[Human-Readable<br/>Colored]
    File --> Format2[JSON<br/>Structured]

    Format2 --> Monitoring[Monitoring System<br/>ELK/Splunk]

    style App fill:#4CAF50,color:#fff
    style File fill:#2196F3,color:#fff
    style Monitoring fill:#FF9800,color:#333
```

### Metrics Collected

- Scan duration
- Subdomains discovered
- DNS queries performed
- Findings by severity
- Alert success rate
- Error rates by component
- API response times

---

## Recent Architecture Additions

### REST API Layer (FastAPI)

The scanner exposes a full REST API for programmatic access:

- **Application factory** (`api/app.py`) with lifespan context manager
- **Dependency injection** via `AppState` singleton and FastAPI `Depends()`
- **Background task execution** for async scan processing
- **Pydantic v2 models** for request/response validation
- **Optional API key authentication** with timing-safe comparison
- **UUID validation** on path parameters to prevent traversal attacks

### Monitoring & Scheduling

- **ScanScheduler** (`scheduler.py`) — interval-based scan loop with delta detection
- **MonitorDaemon** (`monitor.py`) — signal handling, graceful shutdown, timeout management
- **AlertManager** (`alerters/manager.py`) — multi-channel dispatch with deduplication, severity filtering, fault isolation, and history recording
- Compares findings against 7-day history to identify new vulnerabilities
- Automatically dispatches alerts when new findings are detected

### Docker Deployment

- Multi-stage `Dockerfile` with non-root `scanner` user
- `docker-compose.yml` with API + monitor services and persistent volumes
- SQLite WAL journal mode for concurrent container access

## Future Architecture

### Planned Enhancements

1. ~~**Alerting Integration** - AlertManager with multi-channel dispatch~~ (Done)
2. **Web Dashboard** - Real-time monitoring UI
2. **Distributed Scanning** - Worker pool architecture
3. **PostgreSQL Support** - Enterprise database option
4. **Kubernetes Deployment** - Container orchestration via Helm charts
5. **Prometheus Metrics** - Advanced monitoring
6. **GraphQL API** - Flexible data queries

---

## Conclusion

The Security Monitoring Tool follows a modular, layered architecture that prioritizes:

- **Extensibility** - Protocol-based design for easy extension
- **Performance** - Async operations, caching, connection pooling
- **Reliability** - Comprehensive error handling, retries, logging
- **Security** - Input validation, secure communications, no sensitive data logging
- **Maintainability** - Type safety, clear separation of concerns, comprehensive documentation

The architecture supports both single-server deployments for small-scale use and can be extended to distributed architectures for enterprise-scale operations.

---

**Version:** 0.1.0
**Last Updated:** 2026-02-19
