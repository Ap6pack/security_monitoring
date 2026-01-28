# Quick Start Guide

Get scanning for subdomain takeover vulnerabilities in 5 minutes.

## Prerequisites

You need Python 3.11 or newer. Check your version:

```bash
python3 --version
```

## Installation

1. **Clone or navigate to the project directory:**

   ```bash
   cd /path/to/security_monitoring
   ```

2. **Install the tool:**

   ```bash
   pip install -e .
   ```

3. **Initialize the database:**

   ```bash
   security-scanner init-db
   ```

That's it. You're ready to scan.

## Your First Scan

Scan a domain to find vulnerabilities:

```bash
security-scanner scan -d example.com
```

You'll see output like this:

```text
Security Scanner v0.1.0

Scanning 1 domain(s)...

Scan Complete!

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

## Common Usage

**Scan multiple domains:**

```bash
security-scanner scan -d example.com -d api.example.com -d blog.example.com
```

**Scan domains from a file:**

```bash
# Create a file with one domain per line
echo -e "example.com\napi.example.com\nblog.example.com" > domains.txt

# Run the scan
security-scanner scan -f domains.txt
```

**See detailed output:**

```bash
security-scanner scan -d example.com --verbose
```

**View previous scans:**

```bash
security-scanner list-scans
```

**Check your configuration:**

```bash
security-scanner validate-config
```

## Understanding Results

The scanner finds four types of issues:

**CRITICAL** - Dangling CNAME records pointing to services that don't exist. An attacker can register the service and take over your subdomain. Fix these immediately.

**HIGH** - Subdomains pointing to cloud services (Heroku, AWS, Azure, etc.) that appear unclaimed. The scanner verified the platform-specific error message indicating the service is available for registration.

**MEDIUM** - DNS configurations that look unusual or services that aren't responding. These need investigation but aren't immediately exploitable.

**LOW** - Informational findings like certificates expiring soon or configuration notices.

## What Gets Checked

The scanner automatically:

- Finds all your subdomains using certificate transparency logs
- Checks DNS records for misconfigurations
- Tests if CNAMEs point to services that don't exist
- Verifies against 8 major cloud platforms (Heroku, GitHub Pages, AWS S3, AWS Elastic Beanstalk, Azure, GCP, Netlify, Vercel)
- Scores findings using industry-standard CVSS metrics
- Stores everything in a local database for tracking

## Configuration (Optional)

The scanner works out of the box with sensible defaults. If you want to customize it:

```bash
# Copy the example config
cp .env.example .env

# Edit with your preferred settings
nano .env
```

Common settings:

```bash
# Use different DNS servers
DNS_NAMESERVERS=8.8.8.8,1.1.1.1

# Adjust scan speed
MAX_CONCURRENT_SCANS=50
RATE_LIMIT_REQUESTS_PER_SECOND=2

# Change database location
DATABASE_PATH=data/security_scanner.db
```

## Boost Subdomain Discovery (Optional)

The scanner works fine on its own, but you can find more subdomains by installing these optional tools:

**subfinder:**

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**assetfinder:**

```bash
go install github.com/tomnomnom/assetfinder@latest
```

The scanner will automatically detect and use them if they're installed.

## Running Regular Scans

Set up a daily scan with cron:

```bash
# Edit your crontab
crontab -e

# Add this line to run every day at 2 AM
0 2 * * * cd /path/to/security_monitoring && security-scanner scan -f domains.txt
```

## Troubleshooting

**Command not found:**
Make sure you installed the tool with `pip install -e .`

**Database errors:**
Run `security-scanner init-db` to create the database

**Import errors:**
Install dependencies with `pip install -r requirements.txt`

**Slow scans:**
Adjust `MAX_CONCURRENT_SCANS` in your `.env` file. Higher numbers scan faster but use more resources.

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check out [config/patterns.yaml](config/patterns.yaml) to see how platform detection works
- Look at the database in `data/security_scanner.db` to see stored results
- Run tests with `pytest tests/` to verify everything works

## Getting Help

Found a bug or have a question? Check the [README](README.md) or review the code - it's well documented with inline comments.

## Quick Reference

```bash
# Initialize
security-scanner init-db

# Scan single domain
security-scanner scan -d example.com

# Scan multiple domains
security-scanner scan -d example.com -d test.com

# Scan from file
security-scanner scan -f domains.txt

# Verbose output
security-scanner scan -d example.com --verbose

# Quiet output
security-scanner scan -d example.com --quiet

# View history
security-scanner list-scans

# Validate config
security-scanner validate-config

# Show version
security-scanner --version

# Get help
security-scanner --help
```

That's all you need to get started. Now go find some vulnerabilities!
