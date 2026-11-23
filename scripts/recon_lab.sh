#!/usr/bin/env bash
# ==============================================================================
# Script Name   : recon_lab.sh
# Description   : Controlled, safe, non-intrusive reconnaissance automation
# Author        : Ayan Mondal
# Intern ID     : CDS/INT/2026/26637504
# Organization  : Codomax Digital Solutions
# Track         : Cybersecurity & Ethical Hacking
# Module        : Module 02 — Linux, Security Tools & Reconnaissance
# ==============================================================================

set -euo pipefail

# ANSI Color Codes for Professional Terminal Formatting
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ------------------------------------------------------------------------------
# Banner Display
# ------------------------------------------------------------------------------
display_banner() {
    clear || true
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
==============================================================================
   ____ ___  ____   ___  __  __    _    __  __   ____  _____ ____ ___  _   _ 
  / ___/ _ \|  _ \ / _ \|  \/  |  / \   \ \/ /  |  _ \| ____/ ___/ _ \| \ | |
 | |  | | | | | | | | | | |\/| | / _ \   \  /   | |_) |  _|| |  | | | |  \| |
 | |__| |_| | |_| | |_| | |  | |/ ___ \  /  \   |  _ <| |__| |__| |_| | |\  |
  \____\___/|____/ \___/|_|  |_/_/   \_\/_/\_\  |_| \_\_____\____\___/|_| \_|
==============================================================================
EOF
    echo -e "${NC}"
    echo -e "${BOLD}Codomax Digital Solutions — Cybersecurity & Ethical Hacking Track${NC}"
    echo -e "${BOLD}Module 02: Controlled Reconnaissance Automation Utility${NC}"
    echo -e "Intern: ${GREEN}Ayan Mondal${NC} | ID: ${GREEN}CDS/INT/2026/26637504${NC}"
    echo -e "==============================================================================\n"
}

# ------------------------------------------------------------------------------
# Ethical Disclaimer & Authorization Verification
# ------------------------------------------------------------------------------
check_authorization() {
    echo -e "${YELLOW}${BOLD}[!] MANDATORY ETHICAL & LEGAL NOTICE:${NC}"
    echo -e "This utility conducts host discovery, DNS enumeration, and active port scanning."
    echo -e "You must possess EXPLICIT, WRITTEN AUTHORIZATION from the asset owner."
    echo -e "Authorized testing candidates include: ${CYAN}localhost, 127.0.0.1, scanme.nmap.org${NC}\n"

    read -rp "Are you fully authorized to scan the intended target? (yes/no): " auth_response
    if [[ "${auth_response,,}" != "yes" && "${auth_response,,}" != "y" ]]; then
        echo -e "\n${RED}[-] Execution halted. Unauthorized scanning is prohibited by law.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Authorization confirmed. Initializing toolchain...${NC}\n"
}

# ------------------------------------------------------------------------------
# Dependency Checking
# ------------------------------------------------------------------------------
check_dependencies() {
    local deps=("nmap" "whois" "curl")
    local missing=()

    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    # Check for either dig or nslookup
    if ! command -v dig &>/dev/null && ! command -v nslookup &>/dev/null; then
        missing+=("dnsutils (dig or nslookup)")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[-] Missing required dependencies:${NC} ${missing[*]}"
        echo -e "${YELLOW}[!] Install them via: sudo apt update && sudo apt install -y nmap whois dnsutils curl${NC}"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Main Reconnaissance Pipeline
# ------------------------------------------------------------------------------
main() {
    display_banner
    check_authorization
    check_dependencies

    # Target Input & Sanitization
    read -rp "Enter target hostname or IP [default: scanme.nmap.org]: " raw_target
    raw_target="${raw_target:-scanme.nmap.org}"

    # Sanitize input: strip protocol prefixes and trailing slashes
    TARGET=$(echo "$raw_target" | sed -e 's|^[^/]*//||' -e 's|/.*$||' | tr -d '[:space:]')

    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[-] Invalid target input.${NC}"
        exit 1
    fi

    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    REPORT_DIR="$(dirname "$0")/../reports"
    mkdir -p "$REPORT_DIR"
    REPORT_FILE="$REPORT_DIR/recon_${TARGET}_${TIMESTAMP}.txt"

    echo -e "\n${BLUE}[*] Output Report Artifact:${NC} ${REPORT_FILE}"
    echo -e "${BLUE}[*] Target Selected:${NC} ${BOLD}${TARGET}${NC}\n"

    # Header for report file
    {
        echo "=============================================================================="
        echo "CODOMAX DIGITAL SOLUTIONS — CONTROLLED RECONNAISSANCE REPORT"
        echo "Intern: Ayan Mondal | ID: CDS/INT/2026/26637504"
        echo "Target: $TARGET"
        echo "Scan Timestamp: $(date)"
        echo "=============================================================================="
        echo ""
    } > "$REPORT_FILE"

    # Phase 1: Local System & Egress Interface Discovery
    echo -e "${CYAN}${BOLD}=== [PHASE 1] Local Host & Interface Discovery ===${NC}" | tee -a "$REPORT_FILE"
    {
        echo "[+] Local Interface Details:"
        if command -v ip &>/dev/null; then
            ip -brief address show || true
        else
            ifconfig || true
        fi
        echo ""
        echo "[+] Default Routing Gateway:"
        if command -v ip &>/dev/null; then
            ip route show default || true
        else
            netstat -rn || true
        fi
        echo ""
        echo "[+] Public Egress IP Check:"
        curl -s --max-time 4 https://ifconfig.me || echo "Egress check offline or timeout"
        echo -e "\n"
    } 2>&1 | tee -a "$REPORT_FILE"

    # Phase 2: DNS & Domain Information Gathering
    echo -e "${CYAN}${BOLD}=== [PHASE 2] DNS Enumeration & Domain Mapping ===${NC}" | tee -a "$REPORT_FILE"
    {
        if command -v dig &>/dev/null; then
            echo "[+] Querying A Records:"
            dig +noall +answer "$TARGET" A || true
            echo ""
            echo "[+] Querying Name Servers (NS):"
            dig +noall +answer "$TARGET" NS || true
            echo ""
            echo "[+] Querying Mail Exchangers (MX):"
            dig +noall +answer "$TARGET" MX || true
            echo ""
            echo "[+] Querying Text Records (TXT/SPF):"
            dig +noall +answer "$TARGET" TXT || true
        elif command -v nslookup &>/dev/null; then
            echo "[+] Running nslookup queries:"
            nslookup "$TARGET" || true
        fi
        echo ""
    } 2>&1 | tee -a "$REPORT_FILE"

    # Phase 3: Passive WHOIS Query
    echo -e "${CYAN}${BOLD}=== [PHASE 3] WHOIS Registration Query ===${NC}" | tee -a "$REPORT_FILE"
    {
        echo "[+] Gathering Registrar Information for $TARGET:"
        whois "$TARGET" | grep -Ei 'Registrar:|Creation Date:|Registry Expiry Date:|Name Server:|Domain Status:|Organization:' | head -n 25 || echo "WHOIS query returned no parsed records or rate-limited."
        echo ""
    } 2>&1 | tee -a "$REPORT_FILE"

    # Phase 4: Active Non-Intrusive Network Scanning (Nmap)
    echo -e "${CYAN}${BOLD}=== [PHASE 4] Non-Intrusive Nmap Service Scan ===${NC}" | tee -a "$REPORT_FILE"
    echo -e "${YELLOW}[*] Executing fast service probe: nmap -sV -F --reason ${TARGET}${NC}"
    {
        echo "[+] Nmap Command: nmap -sV -F --reason $TARGET"
        nmap -sV -F --reason "$TARGET"
        echo ""
    } 2>&1 | tee -a "$REPORT_FILE"

    # Phase 5: Web Security Header Triage (HTTP/HTTPS)
    echo -e "${CYAN}${BOLD}=== [PHASE 5] HTTP Security Header Inspection ===${NC}" | tee -a "$REPORT_FILE"
    {
        echo "[+] Probing HTTP (Port 80) Headers:"
        curl -I -s -L --max-time 5 "http://$TARGET" || echo "HTTP service unresponsive or refused."
        echo ""
        echo "[+] Probing HTTPS (Port 443) Headers:"
        curl -I -s -L --max-time 5 "https://$TARGET" || echo "HTTPS service unresponsive or refused."
        echo ""
    } 2>&1 | tee -a "$REPORT_FILE"

    # Completion Wrap-up
    {
        echo "=============================================================================="
        echo "RECONNAISSANCE PIPELINE COMPLETED SUCCESSFULLY"
        echo "Finished at: $(date)"
        echo "=============================================================================="
    } >> "$REPORT_FILE"

    echo -e "${GREEN}${BOLD}[✔] Controlled Reconnaissance Completed!${NC}"
    echo -e "${GREEN}[✔] Consolidated report generated at:${NC} ${BOLD}${REPORT_FILE}${NC}\n"
}

main "$@"
