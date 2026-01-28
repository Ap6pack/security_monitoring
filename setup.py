"""Setup script for security scanner."""

from setuptools import find_packages, setup

setup(
    name="security-scanner",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "security-scanner=security_scanner.main:app",
        ],
    },
)
