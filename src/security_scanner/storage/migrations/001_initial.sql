-- Initial database schema for security scanner

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    duration_seconds INTEGER,
    domains_scanned TEXT NOT NULL,
    status TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    domain TEXT NOT NULL,
    record_type TEXT,
    target TEXT,
    description TEXT NOT NULL,
    cvss_score REAL,
    remediation TEXT NOT NULL,
    raw_data TEXT NOT NULL,
    detected_at TIMESTAMP NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    alerted BOOLEAN DEFAULT 0,
    platform TEXT,
    confidence REAL DEFAULT 1.0,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
CREATE INDEX IF NOT EXISTS idx_findings_detected_at ON findings(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);

-- Certificates table
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    cert_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    expires TIMESTAMP NOT NULL,
    shared BOOLEAN DEFAULT 0,
    san_count INTEGER DEFAULT 0,
    san_domains TEXT NOT NULL,
    external_domains TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    logged_at TIMESTAMP NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_certificates_scan_id ON certificates(scan_id);
CREATE INDEX IF NOT EXISTS idx_certificates_expires ON certificates(expires);
CREATE INDEX IF NOT EXISTS idx_certificates_shared ON certificates(shared);
CREATE INDEX IF NOT EXISTS idx_certificates_cert_id ON certificates(cert_id);

-- Alert history table
CREATE TABLE IF NOT EXISTS alert_history (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    sent_at TIMESTAMP NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alert_history_finding_id ON alert_history(finding_id);
CREATE INDEX IF NOT EXISTS idx_alert_history_sent_at ON alert_history(sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_history_channel ON alert_history(channel);
