# Module 02: Linux Fundamentals, Security Tools & Controlled Reconnaissance

[![Cybersecurity Track](https://img.shields.io/badge/Track-Cybersecurity%20%26%20Ethical%20Hacking-0052CC.svg?style=for-the-badge&logo=shield)](https://github.com/)
[![Codomax Digital Solutions](https://img.shields.io/badge/Internship-Codomax%20Digital%20Solutions-FF5722.svg?style=for-the-badge&logo=codementor)](https://codomax.com)
[![Status](https://img.shields.io/badge/Status-Completed-success.svg?style=for-the-badge&logo=checkmarx)](https://github.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

---

## 📌 Intern & Project Information

| Field | Detail |
| :--- | :--- |
| **Intern Name** | Shivam Tiwari |
| **Intern ID** |  CDS/INTERN/261153|
| **Organization** | **Codomax Digital Solutions** |
| **Program** | Virtual Internship Program — 2026 |
| **Domain Track** | Cybersecurity & Ethical Hacking |
| **Module Code** | `MODULE-02` |
| **Module Title** | Linux, Security Tools & Controlled Reconnaissance |
| **Submission Date** | November 2026 |

---

## 📖 Module Overview

This repository houses the complete practical work, technical documentation, and automated tooling developed during **Module 02** of the **Cybersecurity & Ethical Hacking Internship** at **Codomax Digital Solutions**.

Module 02 focuses on establishing robust operational capabilities across Linux administration, defensive and offensive security utility configuration, reconnaissance methodologies (passive and active), and controlled laboratory testing.

### Core Objectives
1. **Linux Security & Administration**: Master Linux directory hierarchy, absolute vs. relative paths, discretionary access controls (`chmod`, `chown`, octal/symbolic permissions), special permission bits (SUID, SGID, Sticky Bit), privilege management (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`), and operational process monitoring (`ps`, `top`, `kill`, `systemctl`).
2. **Reconnaissance & Footprinting Methodologies**: Delve into the core differences between passive (non-intrusive, OSINT, public records) and active (intrusive, packet transmission, service querying) information gathering across DNS architecture, domain registrars, and network perimeter mapping.
3. **Core Security Tools Mastery**: Conduct rigorous hands-on assessments using industry-standard tools:
   - **Nmap**: Host discovery, TCP SYN / Connect port scanning, service version detection (`-sV`), OS fingerprinting (`-O`), and script engine (`--script nse`) workflows.
   - **Wireshark**: Deep packet inspection, pcap analysis, protocol dissection, and targeted display filter construction (DNS, ARP, TCP flags, HTTP headers).
   - **Burp Suite**: HTTP/S proxying, request/response tampering, Repeater state testing, and Decoder analysis.
   - **OWASP ZAP**: Automated web security vulnerability scanning, active and passive baseline analysis, and spidering within controlled virtual environments.
4. **Controlled Reconnaissance Lab**: Execute safe, non-destructive discovery and enumeration against pre-authorized targets (`localhost` / `scanme.nmap.org`), generating structured evidence logs and actionable risk mitigation roadmaps.

---

## 📂 Repository Directory Structure

```plaintext
codomax-cybersecurity-module-02/
│
├── README.md                               # Project documentation & execution handbook
├── LINKEDIN_POST.md                        # Professional completion announcement & takeaways
│
├── docs/                                   # Theoretical & practical deep-dive documentation
│   ├── 01-linux-security-fundamentals.md   # Filesystem hierarchy, permissions, users, processes
│   └── 02-security-tools-guide.md          # Nmap, Wireshark, Burp Suite, & OWASP ZAP handbook
│
├── labs/                                   # Empirical laboratory exercises & formal reports
│   └── 03-controlled-recon-lab-report.md   # Controlled lab execution, findings, & hardening plans
│
├── scripts/                                # Custom automation & reconnaissance tooling
│   └── recon_lab.sh                        # Automated safe reconnaissance & enumeration script
│
└── reports/                                # Output artifacts from laboratory scans (.gitkeep)
    └── .gitkeep                            # Git directory preservation anchor
```

---

## 🛠️ Security Tools & Technologies

| Tool / Technology | Category | Purpose in Module 02 |
| :--- | :--- | :--- |
| **Linux CLI / Bash** | Operating System & Scripting | System hardening, permission auditing, log inspection, process management, and recon scripting |
| **Nmap (7.9x+)** | Network Enumeration | Layer 3 & Layer 4 port scanning, service version profiling, banner grabbing, and NSE vulnerability scanning |
| **Wireshark (4.x+)** | Network Traffic Analysis | Capturing packet flows, analyzing handshake sequences (SYN-SYN/ACK-ACK), isolating cleartext credentials, and DNS triage |
| **Burp Suite (Community/Pro)** | Web Application Security | Intercepting HTTP/S proxies, inspect/modify request payloads, session analysis via Repeater, decoding strings |
| **OWASP ZAP** | Dynamic Application Security (DAST) | Performing automated baseline web security checks, passive rule evaluation, and endpoint spidering |
| **WHOIS & BIND Utils (`dig`, `nslookup`)** | DNS & Domain Reconnaissance | Querying registrar metadata, nameservers, MX records, zone file indicators, and reverse DNS mapping |

---

## 🚀 Script Execution & Usage Guide

The included Bash script (`scripts/recon_lab.sh`) provides a safe, non-intrusive automation wrapper to conduct preliminary host and domain enumeration against authorized systems.

### Prerequisites
- Bash shell (Linux, macOS, or WSL on Windows)
- Installed utilities: `nmap`, `dnsutils` (`dig`, `nslookup`), `whois`, `curl`

To verify or install dependencies on Debian/Ubuntu/Kali:
```bash
sudo apt update && sudo apt install -y nmap dnsutils whois curl iproute2
```

### Running the Reconnaissance Script
1. Clone or navigate to the repository:
   ```bash
   cd codomax-cybersecurity-module-02
   ```

2. Make the script executable:
   ```bash
   chmod +x scripts/recon_lab.sh
   ```

3. Launch the script:
   ```bash
   ./scripts/recon_lab.sh
   ```

4. Follow interactive prompts:
   - Read and accept the **Authorized Target Confirmation Prompt**.
   - Input your authorized domain or IP address (e.g., `scanme.nmap.org` or `127.0.0.1`).
   - The script performs:
     - Local network interface status & gateway mapping.
     - Public IP / egress check.
     - DNS records resolution (`A`, `NS`, `MX`, `TXT`, `SOA`).
     - WHOIS registrar data extraction.
     - Non-intrusive fast service detection (`nmap -sV -F --reason`).
   - Results are automatically timestamped and exported into `reports/recon_<target>_<timestamp>.txt`.

---

## ⚠️ Legal & Ethical Disclaimer

> [!CAUTION]
> **STRICT AUTHORIZATION REQUIRED BEFORE TESTING**
> 
> The tools, scripts, commands, and laboratory workflows detailed within this repository are compiled exclusively for **educational, academic, and authorized defensive security research purposes** in connection with the **Codomax Digital Solutions Internship Program**.
> 
> Unauthorized port scanning, network enumeration, packet interception, or vulnerability testing against systems without explicit, written prior permission from the system owner is strictly prohibited by law, including:
> - **The Information Technology Act, 2000 (India)** (Sections 43 & 66)
> - **Computer Fraud and Abuse Act (CFAA) (18 U.S.C. § 1030) (United States)**
> - **Computer Misuse Act 1990 (United Kingdom)**
> 
> Neither the author (**Ayan Mondal**) nor **Codomax Digital Solutions** accepts any liability for misuse or damage caused by the application of the material in this repository. Ensure all active scans are directed solely toward sandboxed internal virtual labs (e.g., OWASP Juice Shop, DVWA, Metasploitable) or authorized public test endpoints (`scanme.nmap.org`).
