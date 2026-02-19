# Contributing to Security Monitoring Tool

Thank you for your interest in contributing to the Security Monitoring Tool! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security Research Guidelines](#security-research-guidelines)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to TBD.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- Basic understanding of DNS, security scanning, and async Python

### Useful Resources

- [README.md](README.md) - Project overview
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [docs/API.md](docs/API.md) - API documentation
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Architecture documentation
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) - Implementation status

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/security-monitoring.git
cd security-monitoring
```

### 2. Set Up Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Install package in editable mode
pip install -e .
```

### 4. Initialize Database

```bash
security-scanner init-db
```

### 5. Verify Setup

```bash
# Run tests
pytest tests/ -v

# Run type checking
mypy --strict src/

# Run linting
ruff check src/ tests/

# Run formatting check
black --check src/ tests/
```

## How to Contribute

### Types of Contributions

We welcome many types of contributions:

- **Bug Reports** - Found a bug? Open an issue
- **Feature Requests** - Have an idea? We'd love to hear it
- **Code Contributions** - Fix bugs, add features, improve performance
- **Documentation** - Improve docs, add examples, write tutorials
- **Tests** - Increase coverage, add edge cases
- **Security Research** - Find vulnerabilities, improve detection patterns

### Finding Something to Work On

- Check [Issues](https://github.com/Ap6pack/security-monitoring/issues) labeled `good first issue`
- Look for issues labeled `help wanted`
- Review [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for incomplete features
- Check TODO comments in the code

### Before You Start

1. **Check existing issues** to avoid duplicate work
2. **Comment on the issue** to let others know you're working on it
3. **Ask questions** if anything is unclear
4. **Keep the scope small** for your first contribution

## Coding Standards

### Python Style

We follow strict Python coding standards:

```python
# Type hints on all functions
def process_domain(domain: str, options: dict[str, Any]) -> DNSResult:
    """Process a domain and return DNS results.

    Args:
        domain: Domain name to process
        options: Processing options

    Returns:
        DNS resolution result

    Raises:
        ValidationError: If domain format is invalid
    """
    pass
```

### Key Standards

1. **Type Hints** - All functions must have complete type annotations
2. **Docstrings** - Google-style docstrings for all public functions/classes
3. **Formatting** - Black with line length 100
4. **Linting** - Ruff for fast linting
5. **Type Checking** - mypy in strict mode (no type errors allowed)
6. **Async** - Use async/await for all I/O operations
7. **Error Handling** - Never use bare `except:`, use specific exceptions
8. **Logging** - Use structured logging with context
9. **Security** - Input validation, no command injection, no secrets in code
10. **Testing** - Write tests for all new code

### File Organization

```python
"""Module docstring explaining the purpose."""

# Standard library imports
import asyncio
from pathlib import Path
from typing import Any, Optional

# Third-party imports
import aiohttp
from pydantic import BaseModel

# Local imports
from security_scanner.utils.exceptions import ValidationError
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)

# Constants
MAX_RETRIES = 3

# Classes and functions
class MyClass:
    """Class docstring."""
    pass
```

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `DNSScanner`)
- **Functions/Methods**: `snake_case` (e.g., `resolve_domain`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_RETRIES`)
- **Private members**: `_leading_underscore` (e.g., `_internal_method`)
- **Modules**: `snake_case.py` (e.g., `dns_scanner.py`)

## Testing Guidelines

### Writing Tests

```python
"""Unit tests for DNS scanner."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from security_scanner.scanner.dns import DNSScanner
from security_scanner.scanner.models import DNSResult


class TestDNSScanner:
    """Test DNS scanner functionality."""

    @pytest.fixture
    def scanner(self) -> DNSScanner:
        """Create scanner instance for testing."""
        return DNSScanner(nameservers=["8.8.8.8"])

    @pytest.mark.asyncio
    async def test_resolve_domain(self, scanner: DNSScanner) -> None:
        """Test that domain resolution works correctly."""
        with patch.object(scanner, "_query") as mock_query:
            mock_query.return_value = DNSResult(
                domain="example.com",
                record_type="A",
                values=["93.184.216.34"],
                nameserver="8.8.8.8"
            )

            result = await scanner.resolve("example.com", "A")

            assert result.domain == "example.com"
            assert "93.184.216.34" in result.values
            mock_query.assert_called_once()
```

### Test Organization

- **Unit Tests**: `tests/unit/test_<module>.py`
- **Integration Tests**: `tests/integration/test_<feature>.py`
- **Fixtures**: `tests/conftest.py`
- **Test Data**: `tests/fixtures/`

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific file
pytest tests/unit/test_dns_scanner.py -v

# With coverage
pytest tests/ --cov=src/security_scanner --cov-report=html

# Fast fail
pytest tests/ -x

# Specific test
pytest tests/unit/test_dns_scanner.py::TestDNSScanner::test_resolve_domain -v
```

### Test Coverage

- **Minimum coverage**: 80% overall (enforced by CI)
- **New code**: Should have >80% coverage
- **Critical paths**: 100% coverage (validators, detectors)
- **Happy path + error cases**: Test both success and failure

## Commit Message Guidelines

We follow conventional commit format:

```text
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```bash
# Good commit messages
feat(scanner): add support for DNSSEC validation
fix(alerter): handle SMTP connection timeout gracefully
docs(api): add examples for custom detectors
test(dns): add tests for dangling CNAME detection

# Bad commit messages
update code
fix bug
changes
wip
```

### Detailed Example

```bash
feat(detector): add support for Azure subdomain takeover detection

Implement pattern matching for Azure App Service takeover scenarios.
Includes HTTP fingerprinting and error message detection.

Closes #123
```

## Pull Request Process

### Before Submitting

1. **Create a branch** from `main`:

   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make your changes** following coding standards

3. **Run the quality checks**:

   ```bash
   # Format code
   black src/ tests/

   # Check types
   mypy --strict src/

   # Run linter
   ruff check src/ tests/

   # Run tests
   pytest tests/ -v
   ```

4. **Commit your changes** with good commit messages

5. **Push to your fork**:

   ```bash
   git push origin feature/my-feature
   ```

### Submitting Pull Request

1. **Open PR** on GitHub from your branch to `main`

2. **Fill out the PR template** completely:
   - Description of changes
   - Related issues
   - Testing performed
   - Screenshots (if UI changes)

3. **Ensure CI passes**:
   - All tests pass
   - Type checking passes
   - Linting passes
   - Coverage doesn't decrease

4. **Request review** from maintainers

5. **Address feedback** promptly and professionally

### PR Review Process

- Maintainers will review within 2-3 business days
- Address review comments by pushing new commits
- Use `git commit --fixup` for small fixes
- Once approved, maintainer will merge

### PR Requirements

✅ Tests pass (CI green)
✅ Type checking passes
✅ Code coverage maintained or improved
✅ Documentation updated (if needed)
✅ Commit messages follow convention
✅ No merge conflicts
✅ Approved by at least one maintainer

## Security Research Guidelines

### Ethical Scanning

When contributing detection patterns or scanner improvements:

- **Only test on domains you own** or have explicit permission to test
- **Never perform DoS attacks** or send excessive traffic
- **Respect rate limits** for all APIs and services
- **Don't store sensitive data** found during scans in the codebase
- **Report real vulnerabilities** to the domain owner first

### Adding Detection Patterns

When adding new subdomain takeover patterns:

1. **Research the platform** thoroughly
2. **Verify the pattern** on a test domain you control
3. **Document the detection method** clearly
4. **Include references** to security advisories
5. **Add tests** with mocked responses

Example pattern contribution:

```yaml
# config/patterns.yaml
platforms:
  new_platform:
    name: "New Platform"
    cname_patterns:
      - "*.newplatform.com"
    http_patterns:
      - "Error: Service not found"
      - "404 - No such application"
    dns_error: "NXDOMAIN"
    severity: "HIGH"
    cvss_score: 7.5
    reference: "https://security-advisory-url"
```

### Responsible Disclosure

If you discover a vulnerability:

1. Email TBD privately
2. Include reproduction steps
3. Allow 90 days for fix before public disclosure
4. We'll credit you in security advisories

## Development Workflow

### Typical Workflow

```bash
# 1. Update your main branch
git checkout main
git pull upstream main

# 2. Create feature branch
git checkout -b fix/issue-123

# 3. Make changes and test
# ... edit files ...
pytest tests/ -v
mypy --strict src/

# 4. Commit changes
git add src/security_scanner/scanner/dns.py
git commit -m "fix(scanner): handle DNS timeout correctly"

# 5. Push and create PR
git push origin fix/issue-123
# Open PR on GitHub
```

### Keeping Your Fork Updated

```bash
# Add upstream remote (once)
git remote add upstream https://github.com/original/security-monitoring.git

# Sync your fork
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

## Project Structure

```bash
security_monitoring/
├── src/security_scanner/    # Main package
│   ├── scanner/             # Scanner modules
│   ├── detectors/           # Detector modules
│   ├── reporters/           # Reporter modules
│   ├── alerters/            # Alerter modules
│   ├── storage/             # Database and storage
│   └── utils/               # Utility modules
├── tests/                   # Test suite
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── fixtures/           # Test fixtures
├── docs/                    # Documentation
├── config/                  # Configuration files
└── reports/                # Generated reports
```

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/Ap6pack/security-monitoring/discussions)
- **Bugs**: Open an [Issue](https://github.com/Ap6pack/security-monitoring/issues)
- **Chat**: Join our Discord/Slack (link)
- **Email**: TBD

## Recognition

Contributors will be:

- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in security advisories
- Featured on the project website

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to making the internet safer!**

**Last Updated:** 2026-02-19
