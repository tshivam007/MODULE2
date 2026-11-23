# Module 02: Essential Security Tools Practical Guide

**Author:** Ayan Mondal (Intern ID: `CDS/INT/2026/26637504`)  
**Track:** Cybersecurity & Ethical Hacking  
**Organization:** Codomax Digital Solutions  

---

## 1. Executive Summary

A successful cybersecurity practitioner must possess both defensive analytical rigor and offensive operational competence. This guide provides an authoritative reference manual for the four core security tools mastered in Module 02:
1. **Nmap (Network Mapper)** — Host discovery, port state analysis, service interrogation, and script automation.
2. **Wireshark** — Deep packet inspection, network protocol analysis, and traffic forensic triage.
3. **Burp Suite** — Web application interception proxy, session replay, and manual security evaluation.
4. **OWASP ZAP (Zed Attack Proxy)** — Dynamic Application Security Testing (DAST), automated spidering, and vulnerability scanning.

---

## 2. Nmap (Network Mapper)

Nmap is the open-source industry standard for network exploration and vulnerability scanning. It operates by sending raw, crafted IP packets and parsing the responses to deduce host states, active network services, OS versions, and configuration flaws.

### 2.1 Core Scanning Types & Mechanics

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       NMAP TCP SYN SCAN (-sS) WORKFLOW                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Scanner (Client)                                          Target Server    │
│       │                                                          │          │
│       │ ──── [1] SYN Packet (Port 80) ─────────────────────────> │          │
│       │ <─── [2] SYN/ACK Packet (Port Open) ──────────────────── │          │
│       │ ──── [3] RST Packet (Connection Aborted) ──────────────> │          │
│                                                                             │
│  *Port is flagged OPEN; full 3-way handshake is never completed (Stealth).  │
└─────────────────────────────────────────────────────────────────────────────┘
```

| Scan Flag | Name | Technical Mechanism | Root/Sudo Needed? | Use Case & Stealth Profile |
| :---: | :--- | :--- | :---: | :--- |
| `-sS` | **TCP SYN (Half-Open)** | Sends SYN; if SYN/ACK received, responds with RST. Never completes handshake. | **Yes** | Fast, stealthy, standard default scan. Frequently avoids older application logs. |
| `-sT` | **TCP Connect** | Issues full POSIX `connect()` syscall; completes standard 3-way handshake (SYN $\rightarrow$ SYN/ACK $\rightarrow$ ACK). | No | Default scan when running as unprivileged user; noisier in server application logs. |
| `-sU` | **UDP Scan** | Transmits empty UDP probes to ports; expects ICMP Port Unreachable (Port Closed) or no response (Open\|Filtered). | **Yes** | Essential for DNS (53), SNMP (161), DHCP (67/68), NTP (123). Extremely slow due to ICMP rate-limiting. |
| `-sN` / `-sF` / `-sX` | **Null / FIN / Xmas** | Sets abnormal TCP flags (Null = None; FIN = FIN; Xmas = FIN+PSH+URG). | **Yes** | Bypasses stateless firewalls; targets RFC 793 compliance. Fails against Windows hosts (which send RST to all). |

### 2.2 Host Discovery Techniques
- `-sn` *(Ping Scan)*: Disables port scanning. On local Ethernet, uses ARP requests (`ARP who-has`); over routable subnets, sends ICMP Echo, TCP SYN to port 443, TCP ACK to port 80, and ICMP Timestamp requests.
- `-Pn` *(No Ping)*: Treats all target hosts as alive. Bypasses ICMP-blocking firewalls; mandatory when scanning hardened external targets.
- `-PR`: Performs ARP discovery on local subnets (fastest and most reliable).

### 2.3 Service Version Detection & Operating System Fingerprinting
- `-sV`: Interrogates open ports using probes defined in `nmap-service-probes` to parse banners and handshake protocols, matching against thousands of service signatures.
- `--version-intensity <0-9>`: Adjusts probe aggressiveness (default is 7; 9 tests all probes).
- `-O`: Sends crafted TCP/UDP packets and evaluates responses against `nmap-os-db` (analyzes TCP window size, sequence predictability, IP ID generation).
- `-A`: Aggressive scan template; combines `-sV`, `-O`, traceroute (`--traceroute`), and default NSE scripts (`-sC`).

### 2.4 Nmap Scripting Engine (NSE)
NSE empowers users to automate network discovery, vulnerability detection, and brute-forcing using embedded Lua scripts (`/usr/share/nmap/scripts/`).

```bash
# Execute safe default scripts against an authorized host
nmap -sC scanme.nmap.org

# Target specific vulnerability categories
nmap -p 80,443 --script "vuln and safe" 192.168.1.50

# Inspect HTTP security headers and SSL/TLS cipher suites
nmap -p 443 --script ssl-cert,ssl-enum-ciphers,http-security-headers scanme.nmap.org
```

### 2.5 Timing & Output Optimization
- **Timing Templates (`-T0` to `-T5`):**
  - `-T0` (Paranoid) & `-T1` (Sneaky): Evades IDS detection; highly latent.
  - `-T3` (Normal): Default balanced mode.
  - `-T4` (Aggressive): Recommended for reliable, modern networks; minimizes round-trip timeouts.
- **Output Storage (`-oA <basename>`):** Generates all three primary output formats simultaneously:
  - `-oN`: Normal human-readable text.
  - `-oX`: Structured XML for automated ingestion into SIEMs or vulnerability management suites.
  - `-oG`: Grepable format for shell pipelines (`awk`, `grep`, `cut`).

---

## 3. Wireshark (Network Traffic Analysis)

Wireshark is the world's foremost graphical packet analysis and deep packet inspection (DPI) tool. It decodes raw byte streams captured across network interfaces into dissected, protocol-layered conversations.

### 3.1 Packet Capture Architecture
- **Promiscuous Mode**: Forces the Network Interface Card (NIC) to pass all frames seen on the wire to the operating system, rather than solely frames addressed to the host's physical MAC address.
- **Capture Filters vs. Display Filters**:
  - *Capture Filters (Berkeley Packet Filter - BPF)*: Applied before recording packets to disk; minimizes buffer drop in high-throughput links (e.g., `host 192.168.1.1 and port 80`).
  - *Display Filters*: Applied post-capture against memory to sift, highlight, and isolate specific conversational fields without discarding captured data.

### 3.2 Protocol Dissection: The TCP Handshake
In Wireshark, validating connection integrity requires tracing TCP flags:

```
Packet 1: Client -> Server  [SYN]      Seq=0, Ack=0         (Initiate)
Packet 2: Server -> Client  [SYN, ACK] Seq=0, Ack=1         (Acknowledge & Sync)
Packet 3: Client -> Server  [ACK]      Seq=1, Ack=1         (Established)
```

Connection teardown involves:
- `FIN` (Graceful close): Requesting sender has no further data to transmit.
- `RST` (Reset): Abrupt termination caused by closed ports, firewall drops, or protocol violations.

### 3.3 High-Value Wireshark Display Filters

```wireshark
# ==============================================================================
# HTTP & WEB SECURITY FILTERS
# ==============================================================================
# Filter all POST requests (often contains authentication or form data)
http.request.method == "POST"

# Isolate web server errors or unauthorized responses
http.response.code >= 400

# String match inside HTTP payload for sensitive parameters
http contains "password" or http contains "token"

# ==============================================================================
# DNS & RESOLUTION FILTERS
# ==============================================================================
# Filter queries for specific domains
dns.qry.name contains "codomax"

# Locate failed DNS resolutions (NXDOMAIN = rcode 3)
dns.flags.rcode != 0

# ==============================================================================
# ARP & LAYER 2 SPOOFING DETECTION
# ==============================================================================
# Detect duplicate IP claims (classic indicator of ARP Poisoning / MITM)
arp.duplicate-address-frame

# Filter ARP requests vs responses (Opcode 1 = Request, 2 = Reply)
arp.opcode == 1

# ==============================================================================
# TCP ANOMALIES & RECONNAISSANCE DETECTION
# ==============================================================================
# Detect incoming SYN scans (SYN set, ACK clear)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Detect retransmissions, indicative of packet loss or rate-limiting
tcp.analysis.retransmission

# Filter traffic destined for HTTPS
tcp.port == 443
```

### 3.4 Forensic Workflows
- **Follow TCP Stream:** Right-click a packet $\rightarrow$ `Follow` $\rightarrow$ `TCP Stream` reconstructing the full bidirectionally reassembled payload in human-readable ASCII or hex.
- **Export Objects:** Extract transferred payloads (executables, HTML, images) directly from the capture via `File` $\rightarrow$ `Export Objects` $\rightarrow$ `HTTP`.

---

## 4. Burp Suite

Burp Suite (developed by PortSwigger) is the industry-standard platform for web application penetration testing. It operates as an explicit, man-in-the-middle HTTP/HTTPS forward proxy positioned between the security tester's browser and the target web server.

```
┌──────────┐             ┌─────────────────────┐             ┌────────────┐
│          │             │     BURP SUITE      │             │   TARGET   │
│ Browser  │ ──HTTP/S──> │ 127.0.0.1:8080      │ ──HTTP/S──> │ Web Server │
│ (Client) │ <───TLS───  │ Intercept / Inspect │ <───TLS───  │            │
└──────────┘             └─────────────────────┘             └────────────┘
```

### 4.1 Proxy & CA Certificate Installation
To intercept encrypted HTTPS traffic without triggering browser certificate warnings:
1. Configure browser proxy to point to `127.0.0.1:8080`.
2. Navigate to `http://burp` in the browser and download the **PortSwigger CA Certificate** (`cacert.der`).
3. Import the certificate into the browser's Authorities trust store with permission to identify websites.

### 4.2 Core Tool Modules & Practical Workflows

| Module | Core Functionality | Practical Penetration Testing Application |
| :--- | :--- | :--- |
| **Proxy (Intercept)** | Real-time traffic interception and tampering | Pause requests in-flight; alter parameters (e.g., changing `role=user` to `role=admin` or altering prices) before forwarding to server. |
| **Target (Site Map)** | Hierarchical asset mapping and scope definition | Defines testing boundaries ("Target Scope") to restrict active actions strictly to authorized hostnames. |
| **Repeater** | Manual request modification and reissue engine | Send single requests repeatedly with mutated payloads (SQLi apostrophes `'`, XSS script tags, path traversal `../../`) while analyzing raw response diffs. |
| **Decoder** | Cryptographic and encoding translation utility | Rapidly decode/encode Base64, URL encoding, Hex, HTML entities, and compute MD5/SHA256 hashes on the fly. |
| **Intruder** | Automated customized payload attack engine | Conduct parameter fuzzing, dictionary attacks, and credential stuffing across multiple attack types (Sniper, Cluster Bomb). |

---

## 5. OWASP ZAP (Zed Attack Proxy)

OWASP ZAP is an open-source Dynamic Application Security Testing (DAST) tool maintained by the international application security community. Designed to identify security vulnerabilities in web applications during runtime, ZAP serves as an automated counterpart to Burp Suite.

### 5.1 Passive vs. Active Scanning

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      OWASP ZAP SCANNING CLASSIFICATION                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [PASSIVE SCANNING]                                                         │
│  • Purely observational; analyzes responses already flowing through proxy.   │
│  • Does NOT generate new requests or modify payloads.                       │
│  • Flags missing headers (HSTS, CSP), insecure cookie flags, info leaks.    │
│  • Safe to run against production environments.                             │
│                                                                             │
│  [ACTIVE SCANNING]                                                          │
│  • Intrusive; constructs and transmits malicious payloads to endpoints.     │
│  • Actively tests for SQL Injection, Cross-Site Scripting (XSS), LFI, etc.  │
│  • CAN corrupt database entries, trigger account lockouts, or crash nodes.  │
│  • STRICT REQUIREMENT: Only execute in sandboxed, authorized test labs!     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Spidering & Application Discovery
Before vulnerabilities can be evaluated, ZAP must discover all reachable attack surfaces:
- **Traditional Spider**: Recursively crawls static HTML markup parsing `<a href>`, `<form action>`, and metadata tags.
- **AJAX Spider**: Launches a headless browser instance (Chrome or Firefox) to execute client-side JavaScript, trigger DOM event handlers, and uncover modern Single Page Application (SPA) routes.

### 5.3 ZAP Alert Severity Categorization
ZAP tags identified security defects according to risk severity:
- 🔴 **High**: Immediate exploitability leading to compromise (e.g., Remote Code Execution, SQLi).
- 🟠 **Medium**: Significant flaw requiring specific conditions (e.g., Reflected XSS, CSRF, broken access control).
- 🟡 **Low**: Security posture hygiene defect (e.g., Missing `X-Content-Type-Options`, Cookie without `SameSite` attribute).
- 🔵 **Informational**: Informative architectural discovery (e.g., Modern web framework disclosure, timestamp leaks).

---

## 6. Integrated Security Toolkit Comparison Matrix

| Attribute / Tool | Nmap | Wireshark | Burp Suite | OWASP ZAP |
| :--- | :--- | :--- | :--- | :--- |
| **Primary OSI Layer** | Layer 3 (Network) & Layer 4 (Transport) | Layer 2 through Layer 7 | Layer 7 (Application - HTTP/S, WebSockets) | Layer 7 (Application - Web & API) |
| **Operational Role** | Port scanning, host discovery, service fingerprinting | Packet capture, protocol dissection, traffic triage | Web interception, manual payload manipulation | Automated DAST scanning, spidering, CI/CD security |
| **Interactivity** | CLI-driven batch execution | GUI/CLI (`tshark`) passive analysis | Interactive manual proxy & manipulation | Hybrid automated scanner & proxy |
| **Impact on Target** | Minimal to Moderate (SYN/Version probes) | Zero (completely passive on physical link) | High if tampering; Zero if passive | High during Active Scans (can alter database state) |

---
*Document compiled for Codomax Digital Solutions Cybersecurity Virtual Internship — Module 02.*
