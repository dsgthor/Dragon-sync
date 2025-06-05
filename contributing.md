# Contributing to dragon-sync

Thank you for your interest in contributing to dragon-sync! This document provides guidelines and information for contributors.

## 🚀 Quick Start for Contributors

### Prerequisites

- Python 3.8+ (Python 3.11+ recommended)
- Git
- Basic understanding of cybersecurity concepts
- Familiarity with threat intelligence (IOCs, MITRE ATT&CK, etc.)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/dragon-sync.git
   cd dragon-sync
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/macOS
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Verify Installation**
   ```bash
   python dragon_sync.py --mode cli --help
   ```

## 🎯 How to Contribute

### Types of Contributions

We welcome several types of contributions:

- **🐛 Bug Reports**: Help us identify and fix issues
- **💡 Feature Requests**: Suggest new functionality
- **📝 Documentation**: Improve or add documentation
- **🔧 Code Contributions**: Bug fixes, new features, optimizations
- **🧪 Testing**: Add test cases, improve test coverage
- **🎨 UI/UX Improvements**: Enhance user interface and experience
- **🔐 Security**: Identify and fix security vulnerabilities

### Before You Start

1. **Check Existing Issues**: Look through existing issues to avoid duplicates
2. **Discuss Major Changes**: For significant features, open an issue first to discuss
3. **Follow Code Style**: Maintain consistency with existing code
4. **Test Your Changes**: Ensure all tests pass and add new tests as needed

## 📋 Contribution Process

### 1. Create an Issue (Optional but Recommended)

For bugs:
- Use the bug report template
- Include steps to reproduce
- Provide system information
- Include relevant logs or screenshots

For features:
- Use the feature request template
- Explain the use case and expected behavior
- Consider security implications

### 2. Development Workflow

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b bugfix/issue-number
   ```

2. **Make Changes**
   - Write clean, documented code
   - Follow existing code patterns
   - Add comments for complex logic
   - Update documentation if needed

3. **Test Your Changes**
   ```bash
   # Run basic functionality tests
   python dragon_sync.py --mode cli
   python dragon_sync.py --mode gui
   
   # Run unit tests (when available)
   python -m pytest tests/
   
   # Test on multiple platforms if possible
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new threat enrichment source"
   # or
   git commit -m "fix: resolve sync timeout issue #42"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### 3. Pull Request Guidelines

#### PR Title Format
- `feat: description` - New features
- `fix: description` - Bug fixes
- `docs: description` - Documentation changes
- `refactor: description` - Code refactoring
- `test: description` - Adding tests
- `security: description` - Security improvements

#### PR Description Should Include
- **What**: Brief description of changes
- **Why**: Reason for the change
- **How**: How the change was implemented
- **Testing**: How you tested the changes
- **Screenshots**: For UI changes

#### Example PR Description
```markdown
## What
Adds support for AbuseIPDB API integration for IP reputation lookups.

## Why
Users requested ability to enrich IP indicators with reputation data from AbuseIPDB.

## How
- Added AbuseIPDB class in threat enrichment module
- Integrated API calls with existing enrichment pipeline
- Added configuration options for API key

## Testing
- Tested with valid and invalid IP addresses
- Verified API rate limiting handling
- Tested with missing API key scenarios

## Screenshots
N/A - CLI feature only
```

## 🏗️ Code Guidelines

### Code Style

- **Follow PEP 8**: Use Python standard style guide
- **Use Type Hints**: Add type annotations where helpful
- **Docstrings**: Document classes and functions
- **Error Handling**: Include proper exception handling
- **Logging**: Use appropriate log levels

### Example Code Style

```python
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class ThreatEnricher:
    """Enriches threat indicators with additional intelligence."""
    
    def __init__(self, api_key: Optional[str] = None) -> None:
        """Initialize the threat enricher.
        
        Args:
            api_key: Optional API key for external services
        """
        self.api_key = api_key
        self._cache: Dict[str, Dict] = {}
    
    def enrich_ip(self, ip_address: str) -> Optional[Dict]:
        """Enrich IP address with threat intelligence.
        
        Args:
            ip_address: IPv4 or IPv6 address to enrich
            
        Returns:
            Dictionary containing enrichment data or None if failed
            
        Raises:
            ValueError: If IP address format is invalid
        """
        try:
            # Implementation here
            logger.info(f"Enriching IP: {ip_address}")
            return self._fetch_ip_data(ip_address)
        except Exception as e:
            logger.error(f"Failed to enrich IP {ip_address}: {e}")
            return None
```

### Security Considerations

- **No Hardcoded Secrets**: Use environment variables or config files
- **Input Validation**: Validate all user inputs
- **Safe Defaults**: Use secure defaults for configuration
- **Logging**: Don't log sensitive information
- **Dependencies**: Keep dependencies updated

### Testing Guidelines

- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test component interactions
- **Edge Cases**: Test error conditions and edge cases
- **Platform Testing**: Test on Windows, Linux, and macOS when possible

## 📝 Documentation Guidelines

### Code Documentation

- **Docstrings**: Document all public classes and methods
- **Comments**: Explain complex logic and design decisions
- **Type Hints**: Use for better code clarity

### README Updates

- Update README.md if adding new features
- Include usage examples for new functionality
- Update installation instructions if needed

### Wiki Contributions

- Add troubleshooting guides
- Create tutorials for advanced features
- Document integration examples

## 🔐 Security Contributions

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email: security@dragon-sync.org
2. Include detailed description and reproduction steps
3. Allow reasonable time for response before disclosure

### Security Code Review

- Check for input validation issues
- Review cryptographic implementations
- Verify secure defaults
- Test authentication and authorization

## 🧪 Testing

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=dragon_sync

# Run specific test file
python -m pytest tests/test_crypto.py
```

### Writing Tests

```python
import pytest
from dragon_sync import CryptoManager

class TestCryptoManager:
    def test_key_generation(self):
        """Test RSA key pair generation."""
        crypto = CryptoManager()
        private_key, public_key = crypto.generate_key_pair()
        
        assert private_key is not None
        assert public_key is not None
        assert len(public_key) > 0
    
    def test_encryption_decryption(self):
        """Test encryption and decryption cycle."""
        crypto = CryptoManager()
        message = "test message"
        
        encrypted = crypto.encrypt(message)
        decrypted = crypto.decrypt(encrypted)
        
        assert decrypted == message
```

## 📊 Performance Guidelines

- **Profiling**: Profile code for performance bottlenecks
- **Memory Usage**: Monitor memory consumption
- **Database Queries**: Optimize database operations
- **Network Calls**: Minimize API calls and add caching

## 🎨 UI/UX Contributions

### GUI Improvements

- **Consistency**: Follow existing UI patterns
- **Accessibility**: Consider screen readers and keyboard navigation
- **Responsiveness**: Test with different window sizes
- **Error Messages**: Provide helpful error messages

### CLI Improvements

- **Help Text**: Clear and comprehensive help messages
- **Progress Indicators**: Show progress for long operations
- **Error Handling**: Graceful error handling with helpful messages

## 🚀 Release Process

### Version Numbering

We use Semantic Versioning (SemVer):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version number bumped
- [ ] Security review completed

## 💬 Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn and contribute
- Maintain professional communication

### Getting Help

- **GitHub Discussions**: General questions and ideas
- **GitHub Issues**: Bug reports and feature requests
- **Email**: security@dragon-sync.org for security issues

### Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

## 📚 Resources

### Learning Resources

- [Python Security Best Practices](https://security.openstack.org/guidelines/dg_using-python-native-crypto.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [STIX/TAXII Standards](https://oasis-open.github.io/cti-documentation/)
- [Threat Intelligence Concepts](https://www.cyber-threat-intelligence.com/)

### Development Tools

- **Code Formatters**: black, autopep8
- **Linters**: flake8, pylint
- **Type Checking**: mypy
- **Testing**: pytest
- **Documentation**: Sphinx

## 🎉 Thank You!

Your contributions help make dragon-sync better for the entire cybersecurity community. Whether you're fixing a typo, adding a feature, or improving documentation, every contribution matters!

---

**Questions?** Feel free to reach out through GitHub Discussions or email the development team.