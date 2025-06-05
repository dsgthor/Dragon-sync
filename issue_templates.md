# GitHub Issue Templates

## Bug Report Template
**File: `.github/ISSUE_TEMPLATE/bug_report.yml`**

```yaml
name: 🐛 Bug Report
description: Report a bug or unexpected behavior
title: "[Bug]: "
labels: ["bug", "needs-triage"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to report this bug! Please fill out the information below to help us resolve it quickly.

  - type: checkboxes
    id: checklist
    attributes:
      label: Pre-submission checklist
      options:
        - label: I have searched existing issues to avoid duplicates
          required: true
        - label: I have read the troubleshooting section in README.md
          required: true
        - label: This is not a security vulnerability (use security@dragon-sync.org instead)
          required: true

  - type: textarea
    id: description
    attributes:
      label: Bug Description
      description: A clear description of what the bug is
      placeholder: Describe the bug...
    validations:
      required: true

  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: Detailed steps to reproduce the issue
      placeholder: |
        1. Launch dragon-sync with '...'
        2. Click on '...'
        3. Enter '...'
        4. See error
    validations:
      required: true

  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: What should have happened?
      placeholder: Describe expected behavior...
    validations:
      required: true

  - type: textarea
    id: actual
    attributes:
      label: Actual Behavior
      description: What actually happened?
      placeholder: Describe actual behavior...
    validations:
      required: true

  - type: dropdown
    id: mode
    attributes:
      label: Application Mode
      description: Which mode were you using?
      options:
        - GUI Mode
        - CLI Mode
        - Server Mode
    validations:
      required: true

  - type: input
    id: version
    attributes:
      label: dragon-sync Version
      description: What version of dragon-sync? (check with --version)
      placeholder: "1.0.0"
    validations:
      required: true

  - type: dropdown
    id: os
    attributes:
      label: Operating System
      description: What OS are you running?
      options:
        - Windows 10
        - Windows 11
        - Ubuntu 20.04
        - Ubuntu 22.04
        - macOS 12 (Monterey)
        - macOS 13 (Ventura)
        - macOS 14 (Sonoma)
        - CentOS/RHEL 8
        - CentOS/RHEL 9
        - Arch Linux
        - Other (specify in additional info)
    validations:
      required: true

  - type: input
    id: python-version
    attributes:
      label: Python Version
      description: Python version output from `python --version`
      placeholder: "Python 3.11.5"
    validations:
      required: true

  - type: textarea
    id: logs
    attributes:
      label: Relevant Logs
      description: |
        Please include relevant log output from dragon-sync.log
        **WARNING: Remove any sensitive information like private keys, IP addresses, or threat data**
      placeholder: Paste relevant logs here (remove sensitive info)...
      render: text

  - type: textarea
    id: config
    attributes:
      label: Configuration Details
      description: |
        Relevant configuration settings (remove sensitive data like API keys)
      placeholder: |
        - Custom port: 9090
        - Custom database path: /custom/path.db
        - API integrations enabled: VirusTotal
        - etc.

  - type: textarea
    id: additional
    attributes:
      label: Additional Context
      description: Any other relevant information
      placeholder: Screenshots, network topology, error frequency, etc.

  - type: checkboxes
    id: willing-to-help
    attributes:
      label: Contribution
      options:
        - label: I am willing to help test a fix for this issue
        - label: I am willing to submit a pull request to fix this issue
```

---

## Feature Request Template
**File: `.github/ISSUE_TEMPLATE/feature_request.yml`**

```yaml
name: 💡 Feature Request
description: Suggest a new feature or enhancement
title: "[Feature]: "
labels: ["enhancement", "needs-discussion"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for suggesting a new feature! Please provide details below to help us understand your needs.

  - type: checkboxes
    id: checklist
    attributes:
      label: Pre-submission checklist
      options:
        - label: I have searched existing issues and discussions
          required: true
        - label: This feature aligns with dragon-sync's cybersecurity focus
          required: true
        - label: I have considered the security implications
          required: true

  - type: textarea
    id: problem
    attributes:
      label: Problem Statement
      description: What problem does this feature solve?
      placeholder: |
        Describe the problem or limitation you're experiencing.
        Example: "As a SOC analyst, I need to..."
    validations:
      required: true

  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution
      description: How would you like this feature to work?
      placeholder: Describe your proposed solution in detail...
    validations:
      required: true

  - type: textarea
    id: alternatives
    attributes:
      label: Alternative Solutions
      description: Have you considered any alternative approaches?
      placeholder: What other solutions have you considered?

  - type: dropdown
    id: category
    attributes:
      label: Feature Category
      description: What type of feature is this?
      options:
        - Threat Intelligence (IOC types, enrichment)
        - Network Sync (P2P, protocols)
        - User Interface (GUI, CLI)
        - Security (encryption, authentication)
        - Analytics (reporting, visualization)
        - API Integration (VirusTotal, Shodan, etc.)
        - Database (storage, search)
        - Performance (optimization, caching)
        - Other
    validations:
      required: true

  - type: dropdown
    id: priority
    attributes:
      label: Priority Level
      description: How important is this feature to you?
      options:
        - Critical (blocking current work)
        - High (significantly improves workflow)
        - Medium (nice to have)
        - Low (minor improvement)
    validations:
      required: true

  - type: textarea
    id: use-case
    attributes:
      label: Use Case Examples
      description: Provide specific examples of how this would be used
      placeholder: |
        Example scenarios:
        1. SOC analyst investigating incident...
        2. Threat researcher analyzing malware...
        3. Security engineer setting up monitoring...

  - type: textarea
    id: security-considerations
    attributes:
      label: Security Considerations
      description: What security implications should be considered?
      placeholder: |
        Consider:
        - Data privacy and sensitivity
        - Network security implications
        - Authentication/authorization needs
        - Encryption requirements

  - type: textarea
    id: mockup
    attributes:
      label: UI Mockup/Wireframe
      description: For UI features, provide mockups or detailed descriptions
      placeholder: |
        Describe the user interface or attach images/mockups.
        For CLI features, show example commands and output.

  - type: checkboxes
    id: implementation
    attributes:
      label: Implementation Willingness
      options:
        - label: I am willing to implement this feature
        - label: I can help with testing this feature
        - label: I can help with documentation for this feature
        - label: I can provide additional requirements/feedback

  - type: input
    id: timeline
    attributes:
      label: Desired Timeline
      description: When would you like to see this feature? (if urgent, explain why)
      placeholder: "Next release, within 3 months, no rush, etc."

  - type: textarea
    id: additional
    attributes:
      label: Additional Context
      description: Any other relevant information
      placeholder: Links to similar features, standards compliance, industry trends, etc.
```

---

## Security Issue Template
**File: `.github/ISSUE_TEMPLATE/security_issue.yml`**

```yaml
name: 🔒 Security Issue
description: Report a security vulnerability (use security@dragon-sync.org for sensitive issues)
title: "[Security]: "
labels: ["security", "needs-immediate-attention"]
body:
  - type: markdown
    attributes:
      value: |
        ⚠️ **IMPORTANT**: For sensitive security vulnerabilities, please email security@dragon-sync.org instead of creating a public issue.
        
        Use this template only for security improvements or low-risk security issues.

  - type: checkboxes
    id: checklist
    attributes:
      label: Security Issue Checklist
      options:
        - label: This is NOT a critical vulnerability (use email for critical issues)
          required: true
        - label: I have not included sensitive information in this public report
          required: true
        - label: I understand this issue will be publicly visible
          required: true

  - type: dropdown
    id: severity
    attributes:
      label: Severity Level
      description: How severe is this security issue?
      options:
        - Low (security improvement suggestion)
        - Medium (potential security weakness)
        - High (should use email instead)
        - Critical (MUST use email instead)
    validations:
      required: true

  - type: textarea
    id: description
    attributes:
      label: Security Issue Description
      description: Describe the security concern (without sensitive details)
      placeholder: |
        General description of the security issue or improvement.
        Do NOT include exploit details or sensitive information.
    validations:
      required: true

  - type: dropdown
    id: category
    attributes:
      label: Security Category
      description: What type of security issue is this?
      options:
        - Cryptography (encryption, keys, signatures)
        - Network Security (communication, protocols)
        - Authentication/Authorization
        - Input Validation
        - Data Protection (storage, transmission)
        - Dependency Security (outdated packages)
        - Configuration Security
        - Code Security (best practices)
        - Documentation Security
    validations:
      required: true

  - type: textarea
    id: impact
    attributes:
      label: Potential Impact
      description: What could happen if this issue isn't addressed?
      placeholder: Describe potential security implications...

  - type: textarea
    id: recommendation
    attributes:
      label: Recommended Solution
      description: How do you suggest fixing this issue?
      placeholder: Suggested fixes or improvements...

  - type: checkboxes
    id: help
    attributes:
      label: Assistance Offered
      options:
        - label: I can help implement a fix
        - label: I can help test the fix
        - label: I can provide additional security review
```

---

## Documentation Issue Template
**File: `.github/ISSUE_TEMPLATE/documentation.yml`**

```yaml
name: 📝 Documentation Issue
description: Report documentation problems or suggest improvements
title: "[Docs]: "
labels: ["documentation"]
body:
  - type: dropdown
    id: doc-type
    attributes:
      label: Documentation Type
      description: What type of documentation needs attention?
      options:
        - README.md
        - Installation Guide
        - Usage Guide
        - API Documentation
        - Troubleshooting
        - Contributing Guide
        - Code Comments
        - Wiki Pages
        - Examples/Tutorials
    validations:
      required: true

  - type: dropdown
    id: issue-type
    attributes:
      label: Issue Type
      description: What kind of documentation issue is this?
      options:
        - Missing Information
        - Incorrect Information
        - Outdated Information
        - Unclear Instructions
        - Typo/Grammar
        - New Documentation Needed
        - Formatting Issues
    validations:
      required: true

  - type: textarea
    id: description
    attributes:
      label: Issue Description
      description: What's wrong with the current documentation?
      placeholder: Describe the documentation issue...
    validations:
      required: true

  - type: textarea
    id: location
    attributes:
      label: Documentation Location
      description: Where is this documentation issue located?
      placeholder: |
        Examples:
        - README.md, line 45
        - Wiki page "Network Setup"
        - Function docstring in dragon_sync.py, line 123
    validations:
      required: true

  - type: textarea
    id: suggested-fix
    attributes:
      label: Suggested Fix
      description: How should this be corrected?
      placeholder: |
        Provide your suggested correction or improvement.
        For typos, include the corrected text.

  - type: checkboxes
    id: help-offered
    attributes:
      label: Assistance
      options:
        - label: I can help fix this documentation issue
        - label: I can help review the fix
```

---

## Support/Question Template
**File: `.github/ISSUE_TEMPLATE/support.yml`**

```yaml
name: ❓ Support/Question
description: Ask for help or clarification
title: "[Support]: "
labels: ["question", "support"]
body:
  - type: markdown
    attributes:
      value: |
        Please check the following resources before creating a support issue:
        - [README.md Troubleshooting Section](../README.md#troubleshooting)
        - [GitHub Discussions](../discussions) for general questions
        - [Project Wiki](../wiki) for detailed guides

  - type: textarea
    id: question
    attributes:
      label: Question/Issue
      description: What do you need help with?
      placeholder: Describe your question or issue in detail...
    validations:
      required: true

  - type: dropdown
    id: category
    attributes:
      label: Category
      description: What area does your question relate to?
      options:
        - Installation/Setup
        - Configuration
        - Usage/How-to
        - Network Sync Setup
        - Threat Intelligence
        - API Integration
        - Performance/Optimization
        - Security Configuration
        - Troubleshooting
        - Other
    validations:
      required: true

  - type: textarea
    id: environment
    attributes:
      label: Environment Details
      description: Provide relevant system information
      placeholder: |
        - OS: Windows 11 / Ubuntu 22.04 / macOS 14
        - Python version: 3.11.5
        - dragon-sync version: 1.0.0
        - Installation method: pip / git clone

  - type: textarea
    id: attempted
    attributes:
      label: What Have You Tried?
      description: What solutions have you already attempted?
      placeholder: List the troubleshooting steps you've already tried...

  - type: textarea
    id: additional
    attributes:
      label: Additional Context
      description: Any other relevant information
      placeholder: Screenshots, logs (with sensitive info removed), configuration details, etc.
```