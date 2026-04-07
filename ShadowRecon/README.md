# 🔍 ShadowRecon - Advanced Security & Forensics Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Ethical-Use%20Only-red.svg" alt="Ethical">
</p>

> ⚠️ **LEGAL NOTICE**: This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal.

## 📂 Contents

```
ShadowRecon/
├── shadowint.py          # Advanced OSINT Framework
├── shadowforensics.py    # Digital Forensics Toolkit
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ShadowRecon.git
cd ShadowRecon

# Install dependencies
pip install -r requirements.txt

# Run
python shadowint.py --help
python shadowforensics.py --help
```

## 🕵️ SHADOWINT - OSINT Framework

### Features
- **Domain Recon** - WHOIS, DNS enumeration, port scanning, subdomain discovery
- **Email OSINT** - Breach checking, validation, disposable email detection
- **Username Search** - 30+ platform cross-reference search
- **Phone OSINT** - Carrier detection, location, timezone analysis
- **Image Forensics** - EXIF extraction, metadata, hashing
- **Network Scan** - Service enumeration, banner grabbing, SSL analysis

### Usage Examples

```bash
# Domain reconnaissance
python shadowint.py --domain example.com

# Email OSINT
python shadowint.py --email target@email.com

# Username search across platforms
python shadowint.py --username johndoe

# Phone intelligence
python shadowint.py --phone +1234567890

# Image forensics
python shadowint.py --image photo.jpg

# Network scanning
python shadowint.py --network 192.168.1.1

# Full comprehensive scan
python shadowint.py --all --target example.com
```

## 🔬 SHADOWFORENSICS - Digital Forensics

### Features
- **File Forensics** - Magic signatures, entropy analysis, string extraction
- **Document Analysis** - PDF/Office metadata extraction, hidden data detection
- **Network Forensics** - PCAP packet analysis, protocol breakdown
- **Malware Analysis** - PE analysis, suspicious pattern detection, risk scoring

### Usage Examples

```bash
# File forensic analysis
python shadowforensics.py --file suspicious.exe

# Document metadata extraction
python shadowforensics.py --document report.pdf

# Network capture analysis
python shadowforensics.py --pcap capture.pcap

# Malware analysis
python shadowforensics.py --malware sample.bin

# Complete forensic analysis
python shadowforensics.py --all malware_sample.exe
```

## 🛠️ Tool Overview

| Module | Capabilities |
|--------|-------------|
| **Domain Recon** | WHOIS lookup, DNS records (A, MX, NS, TXT, DKIM, DMARC), port scanning, tech fingerprinting, subdomain enumeration |
| **Email OSINT** | Breach database checking, MX validation, disposable email detection, domain verification |
| **Username Search** | GitHub, Twitter, Instagram, LinkedIn, Reddit, TikTok, Steam, and 20+ more platforms |
| **Phone OSINT** | International formatting, carrier identification, timezone detection, number validation |
| **Image Forensics** | EXIF extraction, MD5/SHA1/SHA256 hashing, metadata analysis |
| **File Forensics** | Magic signatures, entropy analysis, string extraction, embedded content detection |
| **Document Forensics** | PDF metadata, Office document properties, macro detection, author tracking |
| **Network Forensics** | PCAP parsing, protocol analysis, DNS query extraction, IP tracking |
| **Malware Analysis** | PE analysis, suspicious API detection, obfuscation patterns, risk scoring |

## 📋 Requirements

```
colorama>=0.4.6
python-whois>=0.7.10
dnspython>=2.4.0
requests>=2.31.0
Pillow>=10.0.0
phonenumbers>=8.13.0
ssdeep>=3.4
scapy>=2.5.0  # Optional, for PCAP analysis
```

## ⚖️ Disclaimer

This tool is designed for:
- Authorized penetration testing
- Security research and education
- Corporate security assessments (with written consent)
- Bug bounty hunting (on authorized targets)

**Any use without explicit authorization is strictly prohibited.**

## 🤝 Contributing

Contributions welcome! Please read the contribution guidelines and ensure all PRs include proper documentation.

## 📜 License

MIT License - See LICENSE file for details.

---

<p align="center">
Made for Security Researchers 🔐
</p>
