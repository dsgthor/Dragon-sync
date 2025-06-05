#!/usr/bin/env python3
"""
dragon-sync - Distributed Threat Intelligence Sync Tool
Setup script for package installation and distribution
"""

from setuptools import setup
import os

# Read the README file for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements from requirements.txt
def read_requirements():
    requirements = []
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            # Skip comments and empty lines
            if line and not line.startswith("#"):
                requirements.append(line)
    return requirements

setup(
    # Basic package information
    name="dragon-sync",
    version="1.0.0",
    author="dragon-sync Development Team",
    author_email="dev@dragon-sync.org",
    description="A federated cybersecurity platform for secure threat intelligence sharing and analysis",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/dragon-sync",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/dragon-sync/issues",
        "Documentation": "https://github.com/yourusername/dragon-sync/wiki",
        "Source Code": "https://github.com/yourusername/dragon-sync",
    },
    
    # Single-file application - no packages
    py_modules=["dragon_sync"],
    
    # Requirements
    install_requires=read_requirements(),
    python_requires=">=3.8",
    
    # Optional dependencies for API integrations
    extras_require={
        "apis": [
            "virustotal-python>=1.0.0",
            "shodan>=1.30.0",
            "python-whois>=0.8.0",
            "requests-toolbelt>=1.0.0",
        ],
        "validation": [
            "validators>=0.22.0",
            "email-validator>=2.0.0",
        ],
        "logging": [
            "structlog>=23.1.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
    },
    
    # Entry points for direct execution
    entry_points={
        "console_scripts": [
            "dragon-sync=dragon_sync:main",
        ],
    },
    
    # Package metadata
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: X11 Applications",
        "Natural Language :: English",
    ],
    
    # Keywords for PyPI search
    keywords=[
        "cybersecurity",
        "threat-intelligence", 
        "ioc",
        "security",
        "malware",
        "threat-hunting",
        "distributed",
        "sync",
        "encryption",
        "rsa",
    ],
    
    # Include additional files
    include_package_data=True,
    package_data={
        "": ["requirements.txt", "requirements-dev.txt", "README.md", "LICENSE"],
    },
    
    # Zip safety
    zip_safe=False,
)