# 🛡️ dragon-sync - Distributed Threat Intelligence Sync Tool

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

> **A federated cybersecurity platform for secure threat intelligence sharing and analysis across distributed nodes**

dragon-sync enables multiple systems to securely share, analyze, and enrich cyber threat indicators (IOCs) in real-time. Built with enterprise-grade security features including RSA encryption, digital signatures, and peer trust scoring.

---

## 🎯 **Key Features**

- **🔄 Real-time Threat Sync**: Automatically share IOCs across trusted nodes
- **🔐 End-to-End Security**: RSA 2048-bit encryption with digital signatures  
- **🧠 Smart Analysis**: Automated threat scoring and correlation
- **🌐 Multi-Platform**: GUI and CLI interfaces for Windows, Linux, and macOS
- **📊 Rich Analytics**: Visual dashboards and threat timeline analysis
- **🔍 Threat Enrichment**: Integration-ready for VirusTotal, Shodan, and WHOIS
- **💾 Persistent Storage**: SQLite backend with indexed search capabilities
- **🤝 Peer Trust System**: Dynamic trust scoring for network nodes

---

## 🏗️ **Architecture Overview**

```
┌─────────────────────┐
│   User Interface   │ ← GUI (Tkinter) or CLI
├─────────────────────┤
│  ThreatIntelEngine  │ ← Core logic (enrichment, scoring, validation)
├─────────────────────┤
│  DatabaseManager    │ ← SQLite backend for threats and peers
├─────────────────────┤
│   CryptoManager     │ ← Encryption, signatures, key rotation
├─────────────────────┤
│ NetworkSyncManager  │ ← P2P sync across nodes
└─────────────────────┘
```

---

## 🚀 **Quick Start**

### Prerequisites

- **Python 3.8+** (Python 3.11+ recommended)
- pip package manager

### Installation

1. **Clone or download** the project:
   ```bash
   git clone <repository-url>
   cd dragon-sync
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run dragon-sync**:
   ```bash
   # GUI Mode (Recommended)
   python dragon_sync.py --mode gui
   
   # CLI Mode
   python dragon_sync.py --mode cli
   ```

---

## 📋 **System Requirements**

| Component | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| **Python** | 3.8+ | 3.8+ | 3.8+ |
| **Memory** | 512MB+ | 512MB+ | 512MB+ |
| **Storage** | 100MB+ | 100MB+ | 100MB+ |
| **Network** | TCP/IP | TCP/IP | TCP/IP |

---

## 🖥️ **Platform-Specific Setup**

<details>
<summary><strong>🪟 Windows Setup</strong></summary>

1. **Install Python**:
   - Download from [python.org](https://www.python.org/downloads/)
   - ✅ Check "Add Python to PATH" during installation

2. **Install dragon-sync**:
   ```cmd
   pip install -r requirements.txt
   python dragon_sync.py --mode gui
   ```

3. **Verify Installation**:
   ```cmd
   python --version
   ```
</details>

<details>
<summary><strong>🐧 Linux Setup</strong></summary>

1. **Install Python & pip**:
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install python3 python3-pip python3-tk
   
   # Fedora
   sudo dnf install python3 python3-pip python3-tkinter
   
   # Arch
   sudo pacman -S python python-pip tk
   ```

2. **Install dragon-sync**:
   ```bash
   pip3 install -r requirements.txt
   python3 dragon_sync.py --mode gui
   ```

3. **For headless servers**:
   ```bash
   python3 dragon_sync.py --mode cli
   ```
</details>

<details>
<summary><strong>🍎 macOS Setup</strong></summary>

1. **Install Python**:
   ```bash
   # Using Homebrew (recommended)
   brew install python python-tk
   
   # Or download from python.org
   ```

2. **Install dragon-sync**:
   ```bash
   pip3 install -r requirements.txt
   python3 dragon_sync.py --mode gui
   ```
</details>

---

## 🎮 **Usage Guide**

### GUI Mode (Recommended)

Launch the graphical interface:
```bash
python dragon_sync.py --mode gui
```

**Three Main Tabs:**
- **🎯 Threat Indicators**: View, add, and filter IOCs
- **🌐 Network Sync**: Manage peers and synchronization  
- **📊 Analytics**: Statistics, timeline, and system logs

### CLI Mode

Launch command-line interface:
```bash
python dragon_sync.py --mode cli
```

**Common Commands:**
```bash
# Add threat indicator
add ip 192.168.1.100 high 0.9 honeypot malware

# List all indicators
list

# Search indicators  
search malware

# View peers
peers

# Sync with network
sync

# Export data
export backup.json

# View statistics
stats

# Get help
help
```

---

## 🔗 **Network Setup & Peer Connection**

### Setting Up Node Communication

1. **Start Server** (Node A):
   ```bash
   python dragon_sync.py --mode gui
   # Click "Start Server" in Network Sync tab
   ```

2. **Add Peer** (Node B):
   - Copy Node A's public key from `keys/public_key.pem`
   - In Node B, go to Network Sync → "Add Peer"
   - Enter Node A's IP address and port (default: 8080)
   - Paste the public key

3. **Verify Connection**:
   - Both nodes should show each other in the peers list
   - Sync status should show "Connected"

### Example Multi-Node Setup

```bash
# Network topology
Windows PC (192.168.1.5:8080) ←→ Linux Server (192.168.1.6:8080)
                ↕
      Mobile Dashboard (view-only)
```

---

## 📊 **Data Models & IOC Types**

### Supported Indicator Types

| Type | Description | Example |
|------|-------------|---------|
| **IP** | IPv4/IPv6 addresses | `192.168.1.100`, `2001:db8::1` |
| **Domain** | Malicious domains | `evil.example.com` |
| **Hash** | File hashes | `d41d8cd98f00b204e9800998ecf8427e` |
| **URL** | Malicious URLs | `http://bad.example.com/malware` |
| **Email** | Email addresses | `attacker@evil.com` |

### Threat Indicator Structure

```json
{
  "id": "uuid-string",
  "ioc_type": "ip|domain|hash|url|email",
  "value": "indicator-value",
  "confidence": 0.0-1.0,
  "severity": "low|medium|high|critical",
  "source": "source-name",
  "tags": ["malware", "phishing"],
  "first_seen": "timestamp",
  "last_seen": "timestamp",
  "ttl_hours": 168,
  "metadata": {},
  "kill_chain_phase": "reconnaissance",
  "mitre_tactics": ["T1566"],
  "geo_location": "country-code"
}
```

---

## 🔐 **Security Features**

### Cryptographic Security
- **RSA 2048-bit** key pairs for each node
- **OAEP + SHA-256** padding for encryption
- **Digital signatures** for message integrity
- **Key rotation** capabilities

### Trust & Access Control  
- **Peer trust scoring** based on behavior
- **Public key verification** for all communications
- **Secure key exchange** requirements
- **Message replay protection**

### Data Protection
- **Local SQLite encryption** (optional)
- **Secure key storage** in `keys/` directory
- **Audit logging** of all operations
- **Automatic key backup** recommendations

---

## 📁 **File Structure**

```
dragon-sync/
├── dragon_sync.py             # Main application
├── requirements.txt           # Core dependencies
├── requirements-dev.txt       # Development dependencies
├── keys/                      # Cryptographic keys
│   ├── private_key.pem       # Node private key (keep secret!)
│   └── public_key.pem        # Node public key (share with peers)
├── threat_intel.db           # SQLite database
├── dragon-sync.log           # Application logs
└── exports/                  # Exported reports (optional)
    └── *.json
```

---

## ⚙️ **Configuration Options**

### Command Line Arguments

```bash
python dragon_sync.py [OPTIONS]

Options:
  --mode {gui,cli,server}    Interface mode (default: gui)
  --port PORT               Server port (default: 8080)  
  --db DATABASE             Database file path
  --log-level {DEBUG,INFO,WARN,ERROR}
  --config CONFIG_FILE      Configuration file path
  --help                    Show help message
```

### Advanced Configuration

```bash
# Custom port and database
python dragon_sync.py --mode gui --port 9090 --db custom.db

# Debug mode with verbose logging
python dragon_sync.py --mode cli --log-level DEBUG
```

---

## 🔧 **API Integration**

### Threat Enrichment Sources

dragon-sync supports integration with popular threat intelligence APIs:

| Service | Type | Status |
|---------|------|--------|
| **VirusTotal** | File/URL analysis | Install with: `pip install virustotal-python` |
| **Shodan** | IP intelligence | Install with: `pip install shodan` |
| **AbuseIPDB** | IP reputation | Install with: `pip install requests-toolbelt` |
| **WHOIS** | Domain/IP info | Install with: `pip install python-whois` |

### Adding API Keys

1. Edit configuration or environment variables
2. Restart dragon-sync to load new settings
3. Test enrichment in GUI or CLI

---

## 📊 **Analytics & Reporting**

### Built-in Analytics
- **Threat timeline** visualization (24-hour view)
- **IOC statistics** by type and severity
- **Peer network** health monitoring
- **Sync performance** metrics

### Export Formats
- **JSON**: Structured data export
- **CSV**: Spreadsheet-compatible format
- **STIX**: Industry-standard format (planned)
- **MISP**: Integration format (planned)

---

## 🚨 **Troubleshooting**

### Common Issues

<details>
<summary><strong>🔴 "cryptography" module not found</strong></summary>

**Solution:**
```bash
pip install -r requirements.txt
```
</details>

<details>
<summary><strong>🔴 GUI window not appearing</strong></summary>

**Possible causes:**
- Running in headless environment
- Missing GUI libraries

**Solutions:**
```bash
# Try CLI mode instead
python dragon_sync.py --mode cli

# On Linux, install GUI libraries
sudo apt install python3-tk
```
</details>

<details>
<summary><strong>🔴 Sync not working between nodes</strong></summary>

**Checklist:**
- [ ] Both nodes have exchanged public keys
- [ ] Firewall allows traffic on sync port (default: 8080)
- [ ] IP addresses are correct and reachable
- [ ] Both nodes are running and server is started

**Debug:**
```bash
# Check network connectivity
ping 192.168.1.5

# Test with verbose logging
python dragon_sync.py --mode cli --log-level DEBUG
```
</details>

<details>
<summary><strong>🔴 Database corruption</strong></summary>

**Recovery:**
```bash
# Backup existing database
cp threat_intel.db threat_intel.db.backup

# Start with fresh database
rm threat_intel.db
python dragon_sync.py --mode gui

# Restore from export if available
import backup.json
```
</details>

---

## 🏢 **Use Cases**

### Enterprise Security Operations
- **SOC environments** for centralized threat tracking
- **Incident response** teams sharing IOCs
- **Threat hunting** across multiple networks
- **Compliance reporting** and audit trails

### Research & Education  
- **Malware analysis** labs sharing samples
- **Cybersecurity training** environments
- **Academic research** on threat patterns
- **Honeypot networks** for threat collection

### Personal & Home Labs
- **Multi-device** home security monitoring
- **Learning platform** for cybersecurity skills
- **Network monitoring** across home devices
- **Privacy-focused** threat intelligence

---

## 🛣️ **Roadmap**

### Short Term (Next Release)
- [ ] **Web dashboard** for mobile access
- [ ] **Real API integrations** (VirusTotal, Shodan)
- [ ] **STIX/TAXII** format support
- [ ] **Docker containerization**

### Medium Term
- [ ] **Real-time packet analysis** integration
- [ ] **Machine learning** threat scoring
- [ ] **Automated blocking** via firewall APIs
- [ ] **Multi-user authentication** system

### Long Term
- [ ] **Cloud deployment** options
- [ ] **Blockchain-based** trust system
- [ ] **Mobile applications** for iOS/Android
- [ ] **Enterprise SSO** integration

---

## 🤝 **Contributing**

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/dragon-sync.git
cd dragon-sync

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 **Support**

### Documentation
- **Wiki**: [Project Wiki](https://github.com/yourusername/dragon-sync/wiki)
- **API Docs**: [API Documentation](https://dragon-sync.readthedocs.io/)
- **Tutorials**: [Getting Started Guide](https://dragon-sync.readthedocs.io/en/latest/tutorials/)

### Community
- **Issues**: [GitHub Issues](https://github.com/yourusername/dragon-sync/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/dragon-sync/discussions)

### Professional Support
For enterprise support, training, or custom development:
- 📧 **Email**: support@dragon-sync.org
- 🌐 **Website**: [www.dragon-sync.org](https://dragon-sync.org)

---

## 🙏 **Acknowledgments**

- **MITRE ATT&CK** framework for threat categorization
- **STIX/TAXII** standards for threat intelligence sharing
- **OpenCTI** project for inspiration and standards
- **Python cryptography** library for security features

---

## ⚠️ **Disclaimer**

dragon-sync is provided for legitimate cybersecurity purposes only. Users are responsible for:
- Complying with applicable laws and regulations
- Ensuring proper authorization before deployment
- Protecting sensitive threat intelligence data
- Following responsible disclosure practices

**Use at your own risk. The authors assume no liability for misuse.**

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

[⭐ Star this project](../../stargazers) | [🐛 Report Bug](../../issues) | [💡 Request Feature](../../issues)

</div>