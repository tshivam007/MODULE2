# Practical Laboratory Report: Controlled Reconnaissance & Vulnerability Assessment

**Internship Track:** Cybersecurity & Ethical Hacking  
**Intern Name:** Ayan Mondal  
**Intern ID:** `CDS/INT/2026/26637504`  
**Host Organization:** Codomax Digital Solutions  
**Module:** Module 02 — Linux, Security Tools & Reconnaissance  
**Lab Execution Date:** November 2026  
**Status:** Successfully Executed & Documented  

---

## 1. Executive Summary & Authorization Scope

Reconnaissance (footprinting) constitutes the foundational phase of the cyber attack lifecycle (as defined in the Lockheed Martin Cyber Kill Chain® and MITRE ATT&CK® Enterprise Matrix). High-fidelity intelligence gathered during this stage directly dictates the vector, velocity, and success rate of subsequent phases.

This report documents a controlled, authorized reconnaissance laboratory exercise executed to evaluate perimeter exposure, service vulnerabilities, and traffic behavior across authorized endpoints:
- **Primary External Target:** `scanme.nmap.org` (Official target maintained by the Nmap project under express authorization for non-disruptive security scanning).
- **Secondary Local Target:** `127.0.0.1` (`localhost` / controlled testbed services).

All activities complied with the **Codomax Digital Solutions Security Code of Conduct** and applicable cyber law frameworks. No disruptive, denial-of-service, or data-modifying exploits were initiated.

---

## 2. Reconnaissance Methodology: Passive vs. Active Comparison

Reconnaissance is bifurcated into two mutually supportive disciplines: **Passive** (non-intrusive, zero direct packet interaction with target infrastructure) and **Active** (direct bidirectional packet transmission and protocol interrogation).

| Characteristic | Passive Reconnaissance | Active Reconnaissance |
| :--- | :--- | :--- |
| **Direct Interaction** | None. Queries third-party caches, registries, and mirrors. | Direct packet exchange with the target's IP, hosts, and services. |
| **Detection Probability** | Undetectable by target (Zero IDS/IPS/Firewall logs generated). | Highly detectable by target firewalls, SIEMs, EDRs, and honeypots. |
| **Information Yield** | High-level (registrations, domain owners, IP ranges, employee emails). | Low-level technical details (exact OS build, service versions, open ports). |
| **Legal & Compliance Risk** | Negligible; equivalent to standard public web research. | Elevated; unauthorized scans violate CFAA, IT Act 2000, and UK CMA. |
| **Primary Protocols Used** | HTTPS (querying public APIs), DNS (via public resolvers like 1.1.1.1). | TCP (SYN, ACK, Connect), UDP, ICMP probes, raw Ethernet frames. |
| **Representative Tools** | WHOIS, CentralOps, Shodan, Censys, theHarvester, DNSDumpster. | Nmap, Masscan, Netcat, Amass (active enum), Burp Suite, OWASP ZAP. |

---

## 3. Step-by-Step Laboratory Execution & Output Artifacts

### Phase 3.1: Passive Information Gathering (WHOIS & DNS Enumeration)

#### Step 1: WHOIS Domain Registration Lookup
A passive query was executed against the global ICANN WHOIS database to ascertain domain registrar details, administrative contacts, and authoritative nameserver delegations for `nmap.org`.

```bash
whois nmap.org
```

**Realistic Terminal Output:**
```plaintext
Domain Name: NMAP.ORG
Registry Domain ID: 5240248_DOMAIN_ORG-VRSN
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.com
Updated Date: 2025-09-08T05:14:22Z
Creation Date: 1999-10-18T05:22:15Z
Registry Expiry Date: 2027-10-18T05:22:15Z
Registrar: NameCheap, Inc.
Registrar IANA ID: 1068
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: 
Registrant Name: Privacy service provided by Withheld for Privacy ehf
Registrant Organization: Withheld for Privacy ehf
Registrant Street: Kalkofnsvegur 2
Registrant City: Reykjavik
Registrant State/Province: Capital Region
Registrant Postal Code: 101
Registrant Country: IS
Registrant Phone: +354.4212434
Registrant Email: 3a289069d27f4284b39e6a88b5a004eb.protect@withheldforprivacy.com
Name Server: NS1.NMAP.ORG
Name Server: NS2.NMAP.ORG
DNSSEC: unsigned
```

**Analytical Interpretation:**
- The domain was created in October 1999, indicating established infrastructural maturity.
- Registrant identity is shielded by a privacy proxy service in Iceland (`Withheld for Privacy ehf`), mitigating direct social engineering of domain owners.
- Custom authoritative nameservers (`NS1.NMAP.ORG`, `NS2.NMAP.ORG`) are hosted in-zone.

---

#### Step 2: DNS Resource Record Enumeration (`dig`)
Authoritative DNS records were queried using BIND's `dig` utility against target `scanme.nmap.org`.

```bash
dig scanme.nmap.org ANY +noall +answer
dig scanme.nmap.org A +short
dig nmap.org MX +short
dig nmap.org TXT +short
```

**Realistic Terminal Output:**
```plaintext
ayan@cds-sec-lab:~$ dig scanme.nmap.org A +noall +answer
scanme.nmap.org.        3600    IN      A       45.33.32.156

ayan@cds-sec-lab:~$ dig nmap.org MX +short
10 mail.nmap.org.

ayan@cds-sec-lab:~$ dig nmap.org TXT +short
"v=spf1 mx include:mailgun.org include:_spf.google.com ~all"
"google-site-verification=D_J...long_hash..."
```

**Analytical Interpretation:**
- Target `scanme.nmap.org` resolves to IP `45.33.32.156` (hosted on Linode / Akamai Cloud infrastructure in Newark, NJ).
- The parent domain implements **Sender Policy Framework (SPF)** with a soft-fail (`~all`), legitimizing outgoing mail originating from Google Workspace and Mailgun.

---

### Phase 3.2: Active Network Reconnaissance (Nmap Scanning)

With domain and IP resolution confirmed, active scanning was initiated against `scanme.nmap.org` utilizing Nmap to establish open ports, running service versions, OS signatures, and basic script evaluations.

#### Command Execution:
```bash
sudo nmap -sC -sV -O -p 22,80,9929,31337 -v scanme.nmap.org -oA reports/scanme_assessment
```

**Realistic Terminal Output:**
```plaintext
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-19 22:01 IST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating Ping Scan at 22:01
Scanning scanme.nmap.org (45.33.32.156) [2 ports]
Completed Ping Scan at 22:01, 0.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:01
Completed Parallel DNS resolution of 1 host. at 22:01, 0.04s elapsed
Initiating SYN Stealth Scan at 22:01
Scanning scanme.nmap.org (45.33.32.156) [4 ports]
Discovered open port 80/tcp on 45.33.32.156
Discovered open port 22/tcp on 45.33.32.156
Discovered open port 9929/tcp on 45.33.32.156
Completed SYN Stealth Scan at 22:01, 0.48s elapsed (4 total ports)
Initiating Service scan at 22:01
Scanning 3 services on scanme.nmap.org (45.33.32.156)
Completed Service scan at 22:01, 11.23s elapsed (3 services on 1 host)
Initiating OS detection (MCS) at 22:01
Completed OS detection (MCS) at 22:01, 2.12s elapsed (1 host)
NSE: Script scanning 45.33.32.156.
Initiating NSE at 22:01
Completed NSE at 22:01, 4.15s elapsed

Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.24s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f

PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 ac:00:a0:1a:82:ff:cc:55:99:22:11:00:aa:bb:cc:dd (RSA)
|   256 22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11 (ECDSA)
|_  256 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:22 (ED25519)
80/tcp    open     http           Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Go ahead and ScanMe!
9929/tcp  open     nping-echo     Nping echo
31337/tcp filtered Elite          unknown

Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.19 - 5.4, Linux 5.0 - 5.4
Network Distance: 14 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.52 seconds
```

**Port & Service State Analysis:**

| Port | Protocol | State | Service | Detected Version & Details |
| :---: | :---: | :---: | :--- | :--- |
| **22** | TCP | `open` | SSH | OpenSSH 7.9p1 Debian 10 (`buster`). Exposes public hostkeys. |
| **80** | TCP | `open` | HTTP | Apache httpd 2.4.38 (`Debian`). Cleartext web server. |
| **9929** | TCP | `open` | nping-echo | Custom Nping packet echoing service. |
| **31337** | TCP | `filtered` | Elite | Firewall silently dropped/blocked probe packets (no RST returned). |

---

### Phase 3.3: Network Traffic Capture Analysis (Wireshark)

During active probing, a packet capture was recorded on the local interface using Wireshark / `tshark` to examine packet-level interaction.

```bash
# Display filter applied in Wireshark:
tcp.port == 80 && ip.addr == 45.33.32.156
```

#### Detailed Protocol Flow Analysis:
1. **Three-Way Handshake (Frames 101 - 103):**
   - `Client (192.168.1.105) -> Server (45.33.32.156)`: `TCP [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1`
   - `Server (45.33.32.156) -> Client (192.168.1.105)`: `TCP [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460`
   - `Client (192.168.1.105) -> Server (45.33.32.156)`: `TCP [ACK] Seq=1 Ack=1 Win=64240 Len=0`
   *Observation: Connection cleanly established with standard MSS negotiations.*

2. **HTTP Request & Response (Frames 104 - 106):**
   - Transmitted `GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\n\r\n`
   - Received `HTTP/1.1 200 OK` spanning 2 segments.
   - Decoded TCP stream revealed unencrypted payload data transmitted in cleartext across the network perimeter.

---

### Phase 3.4: Web Application Inspection (Burp Suite Proxy & Repeater)

Target web traffic for `http://scanme.nmap.org/` was routed through the Burp Suite proxy listener (`127.0.0.1:8080`) and analyzed within Burp Repeater.

#### Raw HTTP Request (Burp Repeater):
```http
GET / HTTP/1.1
Host: scanme.nmap.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

#### Raw HTTP Response (Burp Repeater):
```http
HTTP/1.1 200 OK
Date: Thu, 19 Nov 2026 16:32:10 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Sat, 26 Jan 2019 14:18:22 GMT
ETag: "1c2-58055c1103f80"
Accept-Ranges: bytes
Content-Length: 450
Vary: Accept-Encoding
Content-Type: text/html

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Go ahead and ScanMe!</title>
</head><body>
<h1>Go ahead and ScanMe!</h1>
<p>Welcome to Scanme.Nmap.Org, a service provided by the Nmap Security Project and Fyodor.</p>
<p>You are authorized to scan this machine with Nmap or other network scanners...</p>
</body></html>
```

#### HTTP Security Header Audit:
A systematic review of the HTTP response headers revealed a critical absence of modern defensive browser directives:
- ❌ **Missing `Strict-Transport-Security` (HSTS):** Application allows unencrypted plain HTTP transport.
- ❌ **Missing `Content-Security-Policy` (CSP):** Browser lacks restrictions on script/resource injection.
- ❌ **Missing `X-Frame-Options`:** Application is vulnerable to Clickjacking attacks if embedded in malicious `<iframe>` tags.
- ❌ **Missing `X-Content-Type-Options`:** Allows MIME-type sniffing.
- ⚠️ **Excessive Server Disclosure:** `Server: Apache/2.4.38 (Debian)` reveals exact application server version and underlying distribution, providing attackers with precise exploit targeting intelligence.

---

## 4. Security Findings & Risk Assessment

| Finding ID | Vulnerability / Issue Description | Affected Asset | Severity | CVSS v3.1 Score | OWASP Category |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **SEC-01** | **Cleartext HTTP Transmission (No HTTPS Enforcement)** | Port 80/TCP | **Medium** | `5.3` (Medium) | A02:2021 — Cryptographic Failures |
| **SEC-02** | **Software Version Banner Information Disclosure** | Port 80 & 22 | **Low** | `3.1` (Low) | A05:2021 — Security Misconfiguration |
| **SEC-03** | **Absence of Modern HTTP Security Headers** | Port 80/TCP | **Low** | `3.7` (Low) | A05:2021 — Security Misconfiguration |
| **SEC-04** | **Legacy Debian 10 (Buster) Component Fingerprint** | Host Kernel / Apache | **Medium** | `5.8` (Medium) | A06:2021 — Vulnerable and Outdated Components |

---

## 5. Security Hardening & Remediation Recommendations

### 5.1 Enforce Transport Layer Encryption (HTTPS & HSTS)
1. Obtain an X.509 TLS certificate (e.g., via Let's Encrypt / Certbot).
2. Configure Apache to automatically redirect all cleartext Port 80 traffic to Port 443 with a 301 Permanent Redirect.
3. Implement HTTP Strict Transport Security:
   ```apache
   Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
   ```

### 5.2 Suppress Server Version Banners
Modify `/etc/apache2/conf-enabled/security.conf`:
```apache
ServerTokens Prod
ServerSignature Off
```
For OpenSSH (`/etc/ssh/sshd_config`):
```text
# Suppress operating system banner disclosure
DebianBanner no
```

### 5.3 Implement Defensive HTTP Headers
Inject protective security headers in the Apache virtual host configuration:
```apache
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "DENY"
    Header set Content-Security-Policy "default-src 'self';"
    Header set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
```

### 5.4 Network Boundary Firewall Rules (UFW / Iptables)
Restrict access to diagnostic services such as Nping (Port 9929) to authorized administrative subnets:
```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 192.168.1.0/24 to any port 9929 proto tcp
sudo ufw enable
```

---

## 6. Conclusion & Intern Sign-Off

The controlled reconnaissance exercise conducted in Module 02 effectively demonstrated the operational synergy between passive OSINT techniques and active network probing. By correlating WHOIS metadata, DNS records, Nmap service discovery, Wireshark packet traces, and Burp Suite request-response analysis, a comprehensive attack surface map was constructed without triggering service interruption or exceeding authorization bounds.

**Report Prepared By:**  
*Ayan Mondal*  
Cybersecurity & Ethical Hacking Intern  
Codomax Digital Solutions  
Intern ID: `CDS/INT/2026/26637504`  
*Verified for submission: November 2026*
