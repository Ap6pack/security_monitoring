"""Detection modules for security vulnerabilities."""

from security_scanner.detectors.dangling_dns import DanglingDNSDetector
from security_scanner.detectors.takeover import TakeoverDetector

__all__ = [
    "DanglingDNSDetector",
    "TakeoverDetector",
]
