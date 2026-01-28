"""
Security Scanner - Professional-grade security scanning tool.

A comprehensive tool for detecting cross-origin web attack vulnerabilities
including dangling DNS records, shared certificates, and domain takeover risks.
"""

__version__ = "0.1.0"
__author__ = "Security Team"
__license__ = "MIT"

from security_scanner.config import Settings

__all__ = ["Settings", "__version__"]
