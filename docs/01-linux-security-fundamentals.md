# Module 02: Linux Security Fundamentals Study Guide

**Author:** Ayan Mondal (Intern ID: `CDS/INT/2026/26637504`)  
**Track:** Cybersecurity & Ethical Hacking  
**Organization:** Codomax Digital Solutions  

---

## 1. Introduction to Linux Security Architecture

Linux is the foundational operating system of modern internet infrastructure, cloud workloads, embedded devices, and cybersecurity platforms (such as Kali Linux and Parrot OS). Securing a Linux environment or conducting ethical evaluations against Linux hosts requires deep familiarity with its Filesystem Hierarchy Standard (FHS), Discretionary Access Control (DAC) permission model, user authentication databases, process scheduling, and daemon service managers.

---

## 2. Linux Filesystem Hierarchy Standard (FHS)

Unlike operating systems that utilize drive letters (e.g., `C:\`, `D:\`), Linux presents an inverted unified tree structure originating at the root directory `/`. Every physical volume, virtual filesystem, and peripheral device is mounted into this single tree.

```
/ (Root Directory)
├── bin -> usr/bin          # Essential binary executables for all users
├── sbin -> usr/sbin        # Essential administrative and system binaries (root)
├── etc/                    # System-wide configuration files and startup scripts
├── home/                   # User personal storage directories (/home/username)
├── root/                   # Home directory of the root superuser
├── var/                    # Variable dynamic data (logs, spools, mail, web roots)
│   ├── log/                # Security and system audit event logs
│   └── www/                # Web application document roots
├── proc/                   # Virtual pseudo-filesystem exposing kernel & process data
├── sys/                    # Kernel virtual device and subsystem interface
├── dev/                    # Special device nodes representing physical/virtual hardware
├── tmp/                    # Temporary files (world-writable, sticky bit enabled)
├── usr/                    # Secondary hierarchy containing user utilities and libraries
│   ├── bin/                # Standard user binaries
│   ├── lib/                # Shared object libraries (.so)
│   └── local/              # Locally compiled software
└── opt/                    # Add-on third-party software packages
```

### Critical Security Directories

| Directory | Security Significance | Primary Audit Objectives |
| :--- | :--- | :--- |
| `/etc` | System configuration storage | Check file permissions of `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, and cron definitions (`/etc/cron*`). |
| `/var/log` | System audit and event history | Analyze security logs: `auth.log` (Debian/Ubuntu) or `secure` (RHEL/CentOS) for brute-force attacks and privilege escalation. |
| `/proc` | Runtime memory mapped filesystem | Inspect running process details directly (`/proc/<PID>/cmdline`, `/proc/<PID>/environ`, `/proc/version`). |
| `/tmp` & `/dev/shm` | Temporary storage & shared RAM | High-risk areas for adversary payload staging; often configured with `noexec`, `nosuid`, and `nodev` mount flags. |

### Absolute vs. Relative Paths
- **Absolute Path**: Explicit path specified from the root directory `/`, regardless of current working directory.
  - *Example:* `/var/log/auth.log` or `/home/ayan/scripts/recon.sh`
- **Relative Path**: Path resolved relative to the current working directory (`.` or `..`).
  - *Example:* `./recon.sh` (within `/home/ayan/scripts`) or `../../etc/passwd` (classic directory traversal payload pattern).

---

## 3. The Linux Permission & Ownership Model

Linux implements **Discretionary Access Control (DAC)** based on POSIX user and group identities. Every file, directory, socket, and pipe possesses an **Owner**, an **Assigned Group**, and access permission bits.

### 3.1 Permission Bits & Triads
Permissions are grouped into three distinct triads:
1. **User (u)**: The specific user account that owns the file.
2. **Group (g)**: Members of the system group assigned to the file.
3. **Others (o)**: Any other authenticated user account on the host.

Each triad represents three fundamental operational rights:

| Symbol | Permission | Numeric Octal | File Capability | Directory Capability |
| :---: | :--- | :---: | :--- | :--- |
| `r` | Read | `4` | View contents of the file | List directory contents (`ls`) |
| `w` | Write | `2` | Modify or truncate file contents | Create, rename, or delete files inside directory |
| `x` | Execute | `1` | Run file as executable or script | Traverse / access directory (`cd`) |
| `-` | Denied | `0` | No access granted | No access granted |

### 3.2 Octal vs. Symbolic Calculation
The sum of each triad's numeric values forms a 3-digit (or 4-digit with special bits) octal permission mode:
- `rwx` = $4 + 2 + 1 = 7$ (Full read, write, and execute)
- `rw-` = $4 + 2 + 0 = 6$ (Read and write)
- `r-x` = $4 + 0 + 1 = 5$ (Read and execute)
- `r--` = $4 + 0 + 0 = 4$ (Read only)
- `---` = $0 + 0 + 0 = 0$ (No permissions)

**Example Octal Modes:**
- `chmod 755 script.sh` $\rightarrow$ User: `rwx` (7), Group: `r-x` (5), Others: `r-x` (5).
- `chmod 644 config.conf` $\rightarrow$ User: `rw-` (6), Group: `r--` (4), Others: `r--` (4).
- `chmod 600 id_rsa` $\rightarrow$ User: `rw-` (6), Group: `---` (0), Others: `---` (0) *(Mandatory for private SSH keys)*.

**Symbolic Notation Usage:**
```bash
# Add execute permission to the file owner
chmod u+x script.sh

# Remove write permissions from group and others
chmod go-w sensitive.txt

# Grant read/write to owner, read to group, revoke everything else
chmod u=rw,g=r,o= config.yml
```

---

## 4. Special Permission Bits & Security Implications

Standard DAC permissions alone cannot handle specific multi-user paradigms (such as allowing an unprivileged user to change their password via `/usr/bin/passwd` which modifies `/etc/shadow`). Linux addresses this using special bits.

### 4.1 SUID (Set User ID) — Octal `4000`
- **Representation:** An `s` in the owner execute position (`-rwsr-xr-x`). If owner lacks execute permission, it displays as capital `S`.
- **Behavior:** When an executable with SUID is executed, the process runs with the privileges of the **file owner** rather than the user executing it.
- **Security Implication:** If a binary owned by `root` has the SUID bit set and contains vulnerabilities or allows arbitrary shell execution (e.g., misconfigured `find`, `vim`, `bash`, `nmap`), a local attacker can exploit it to achieve instantaneous local root privilege escalation.

### 4.2 SGID (Set Group ID) — Octal `2000`
- **Representation:** An `s` in the group execute position (`-rwxr-sr-x`).
- **Behavior on Files:** Executes with the effective group ID of the file's assigned group.
- **Behavior on Directories:** Any file or subdirectory created within this directory automatically inherits the group ownership of the parent directory, regardless of the creator's primary group.
- **Security Implication:** Often used in shared developer environments. Misconfigurations can lead to unauthorized horizontal group escalation.

### 4.3 Sticky Bit — Octal `1000`
- **Representation:** A `t` in the others execute position (`drwxrwxrwt`).
- **Behavior:** Applied primarily to world-writable directories (e.g., `/tmp`, `/var/tmp`). Only the file owner, the directory owner, or `root` can delete or rename files within the directory, preventing malicious unprivileged users from deleting or replacing other users' temporary files.

### 4.4 Auditing Special Permissions via CLI
Cybersecurity professionals regularly audit hosts for anomalous SUID/SGID binaries:

```bash
# Find all SUID executables owned by root across the filesystem
find / -perm -4000 -user root -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find all world-writable directories lacking sticky bits (high risk)
find / -type d -perm -0002 ! -perm -1000 2>/dev/null
```

---

## 5. User, Group & Authentication Security

### 5.1 `/etc/passwd` Breakdown
The `/etc/passwd` file is world-readable (`644`) and maps system user accounts to identifiers and default environments. Each line comprises seven colon-delimited fields:

```
ayan:x:1001:1001:Ayan Mondal,Room 401,CDS:/home/ayan:/bin/bash
  1  2   3    4                   5              6          7
```

1. **Username (`ayan`):** System login identifier.
2. **Password Placeholder (`x`):** Historical password hash field. The `x` indicates the actual password hash is shadowed in `/etc/shadow`.
3. **User ID (UID) (`1001`):** Numerical identifier. UID `0` represents root. UIDs 1–999 typically designate system service accounts (`daemon`, `www-data`, `nobody`).
4. **Group ID (GID) (`1001`):** Primary group numerical identifier.
5. **GECOS Field:** Descriptive user metadata (full name, phone, building, etc.).
6. **Home Directory (`/home/ayan`):** User working directory upon authentication.
7. **Default Shell (`/bin/bash`):** Executable shell launched upon login. Service accounts often use `/usr/sbin/nologin` or `/bin/false` to prohibit interactive logins.

### 5.2 `/etc/shadow` Security
The `/etc/shadow` file stores salted and cryptographically hashed passwords alongside aging parameters. It is readable only by `root` or members of the `shadow` group (`640` or `000` depending on distribution).

```
ayan:$6$rounds=5000$saltsalt$v7hZkL9...:19680:0:90:7:::
  1                   2                   3   4  5  6 789
```

- **Hash Identifier ($6$):**
  - `$1$` = MD5 (Deprecated, vulnerable to collision attacks)
  - `$2a$` / `$2y$` = Blowfish / bcrypt
  - `$5$` = SHA-256
  - `$6$` = SHA-512 (Standard modern Linux default)
  - `$y$` = yescrypt (Modern Debian/Ubuntu standard default)
- **Aging Fields:** Last password change (days since Jan 1, 1970), minimum days before change, maximum validity days before required rotation, and warning period.

### 5.3 Sudo Privileges & `/etc/sudoers`
The `sudo` (SuperUser DO) utility allows delegated execution of commands with elevated credentials. Sudo privileges must be edited exclusively using `visudo`, which enforces syntax checking prior to saving, preventing administrative lockouts.

```
# Format: WHO   WHERE=(AS_WHOM)   COMMANDS
root    ALL=(ALL:ALL)     ALL
ayan    ALL=(ALL:ALL)     /usr/bin/apt, /bin/systemctl restart nginx
%sudo   ALL=(ALL:ALL)     ALL
```

**Common Misconfigurations (Privilege Escalation vectors):**
- Granting `NOPASSWD: ALL` allows execution without password verification.
- Allowing binaries that permit shell escapes (e.g., `ayan ALL=(ALL) NOPASSWD: /usr/bin/vim` allows invoking `:!/bin/sh` to obtain a root shell).

---

## 6. Process Monitoring & Service Management

### 6.1 Process Investigation
A process is an active instance of a running program characterized by a unique **Process ID (PID)**.

| Command | Usage & Security Objective |
| :--- | :--- |
| `ps aux` | Lists all active processes across all users with CPU/Memory metrics and full command-line arguments. |
| `ps -ef --forest` | Displays processes in an ASCII hierarchical tree, demonstrating parent-child execution linkages (PPID to PID). |
| `top` / `htop` | Interactive real-time process monitoring; useful for detecting cryptocurrency miners or anomalous CPU spikes. |
| `pgrep -l <name>` | Searches for running PIDs matching a specific executable name. |
| `lsof -i :<port>` | Identifies which process and user owns an open listening network port or established socket. |
| `ss -tulpn` | Modern replacement for `netstat`; enumerates listening TCP/UDP sockets with associated PIDs. |

### 6.2 Process Signal Control
Processes communicate and terminate through POSIX signals sent via `kill`:
- `SIGTERM (15)`: Graceful termination signal allowing the process to clean up resources and close connections.
- `SIGKILL (9)`: Immediate kernel-level termination; the process cannot catch or ignore this signal.
- `SIGHUP (1)`: Hang-up signal; frequently instructs daemons to reload configuration files without restarting.

```bash
# Graceful termination request
kill -15 1337

# Forceful immediate kill
kill -9 1337

# Terminate all processes belonging to a specific binary name
killall -9 malicious_agent
```

### 6.3 Systemd Service Management
Modern Linux systems employ `systemd` as the init system (PID 1). Daemons and services are governed via `systemctl`:

```bash
# Check service execution status and recent journal logs
systemctl status sshd

# Start, stop, or restart an operational service
systemctl start apache2
systemctl stop apache2
systemctl restart apache2

# Enable or disable service launch during system boot
systemctl enable ufw
systemctl disable telnet

# Prevent any user or service from activating a service (masking)
systemctl mask rsh.service
```

---

## 7. Essential Linux Security Commands Reference

| Command | Syntax | Primary Security Function | Risk / Administrative Notes |
| :--- | :--- | :--- | :--- |
| `chmod` | `chmod 600 <file>` | Modifies file permission mode bits | Setting `777` creates world-writable vulnerability |
| `chown` | `chown user:group <file>` | Modifies user and group ownership | Requires root or sudo to reassign ownership |
| `chattr` | `chattr +i <file>` | Sets immutable bit; prevents editing/deletion even by root | Highly effective against rootkit persistence |
| `ls` | `ls -la /var/log` | Lists detailed permissions, ownership, and hidden files | Flag `-a` reveals dot-prefixed hidden files (`.bash_history`) |
| `find` | `find / -perm -4000 2>/dev/null` | Scans filesystem for specific permissions, sizes, dates | Unfiltered find searches can create substantial disk I/O |
| `grep` | `grep -rn "sudo" /var/log/` | Recursively searches text files for keyword patterns | Use `-E` for extended regular expressions |
| `ss` | `ss -tulpn` | Displays all listening network ports and binding PIDs | Identifies rogue backdoors and unauthorized services |
| `iptables` / `ufw` | `ufw status verbose` | Inspects and configures local firewall packet filter rules | Improper rules can instantly sever SSH management |
| `journalctl` | `journalctl -u ssh -n 50 -f` | Queries systemd unified binary system journal | Crucial for live forensic triage and login audits |
| `last` | `last -F -n 20` | Displays history of recent successful system logins | Sourced from `/var/log/wtmp` binary records |
| `lastb` | `lastb -n 20` | Displays history of failed authentication attempts | Sourced from `/var/log/btmp`; detects brute-force |
| `who` / `w` | `w` | Identifies currently logged-in users and active commands | Shows source IP and active terminal tty/pts |
| `sha256sum` | `sha256sum <binary>` | Generates cryptographic hash for integrity validation | Used in baseline integrity monitoring (Tripwire/AIDE) |
| `visudo` | `sudo visudo -f /etc/sudoers` | Edits sudo configuration safely with syntax linting | Never edit `/etc/sudoers` directly with standard text editors |

---
*Document compiled for Codomax Digital Solutions Cybersecurity Virtual Internship — Module 02.*
