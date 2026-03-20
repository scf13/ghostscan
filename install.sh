#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  GhostScan v2.0 — Installer for Kali Linux / Debian / Ubuntu
#  Usage: sudo bash install.sh [--full] [--no-wordlists] [--no-gpu]
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[1;91m'; GRN='\033[1;92m'; YLW='\033[1;93m'
CYN='\033[1;96m'; DIM='\033[2m'; RST='\033[0m'
BOLD='\033[1m'

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FULL_INSTALL=false
SKIP_WORDLISTS=false
SKIP_GPU=false
SKIP_PYTHON=false

# ── ARGUMENT PARSING ─────────────────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --full)          FULL_INSTALL=true ;;
    --no-wordlists)  SKIP_WORDLISTS=true ;;
    --no-gpu)        SKIP_GPU=true ;;
    --no-python-deps) SKIP_PYTHON=true ;;
    --help|-h)
      echo "Usage: sudo bash install.sh [OPTIONS]"
      echo "  --full           Install ALL optional tools (slow)"
      echo "  --no-wordlists   Skip SecLists/wordlists install"
      echo "  --no-gpu         Skip hashcat GPU dependencies"
      echo "  --no-python-deps Skip pip installs"
      exit 0 ;;
  esac
done

# ── HELPERS ──────────────────────────────────────────────────────────────────
info()    { echo -e "${CYN}[*]${RST} $*"; }
success() { echo -e "${GRN}[✓]${RST} $*"; }
warn()    { echo -e "${YLW}[!]${RST} $*"; }
error()   { echo -e "${RED}[✗]${RST} $*" >&2; }
section() { echo -e "\n${BOLD}${CYN}══════════════════════════════════════════${RST}";
            echo -e "${BOLD}${CYN}  $*${RST}";
            echo -e "${BOLD}${CYN}══════════════════════════════════════════${RST}"; }

apt_install() {
  local pkg="$1"
  if dpkg -s "$pkg" &>/dev/null 2>&1; then
    echo -e "  ${DIM}already installed: $pkg${RST}"
    return 0
  fi
  info "Installing $pkg..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>/dev/null && \
    success "Installed: $pkg" || warn "Failed: $pkg (continuing)"
}

pip_install() {
  python3 -m pip install --quiet --break-system-packages "$@" 2>/dev/null || \
  python3 -m pip install --quiet "$@" 2>/dev/null || \
  warn "pip install failed: $*"
}

# ── ROOT CHECK ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  error "Please run as root: sudo bash install.sh"
  exit 1
fi

# ── DETECT DISTRO ────────────────────────────────────────────────────────────
DISTRO="unknown"
if [[ -f /etc/os-release ]]; then
  source /etc/os-release
  DISTRO="${ID,,}"
fi

section "GhostScan v2.0 Installer"
info "Distro detected: $DISTRO"
info "Install directory: $INSTALL_DIR"

# ── UPDATE APT ───────────────────────────────────────────────────────────────
section "System Update"
info "Updating package lists..."
apt-get update -qq 2>/dev/null || warn "apt-get update failed (continuing)"

# ── CORE SYSTEM PACKAGES ─────────────────────────────────────────────────────
section "Core System Packages"
CORE_PKGS=(
  python3 python3-pip python3-venv python3-dev
  curl wget git unzip gunzip tar
  build-essential libssl-dev libffi-dev
  net-tools iputils-ping dnsutils whois
)
for pkg in "${CORE_PKGS[@]}"; do apt_install "$pkg"; done

# ── NETWORK RECON TOOLS ───────────────────────────────────────────────────────
section "Network Reconnaissance Tools"
RECON_PKGS=(
  nmap              # Port scanning, NSE scripts
  masscan           # Ultra-fast port scanner
  dnsrecon          # DNS enumeration
  dnsenum           # DNS zone transfer + brute
  fierce            # DNS brute-force
  sublist3r         # Subdomain enumeration (OSINT)
  amass             # Advanced subdomain enumeration
  theharvester      # OSINT email/host harvesting
  netcat-traditional # nc — banner grabbing, relay
  p0f               # Passive OS fingerprinting
  whois             # WHOIS lookups
)
for pkg in "${RECON_PKGS[@]}"; do apt_install "$pkg"; done

# ── WEB ANALYSIS TOOLS ────────────────────────────────────────────────────────
section "Web Analysis & Fuzzing Tools"
WEB_PKGS=(
  nikto             # Web vulnerability scanner
  whatweb           # Technology fingerprinting
  wafw00f           # WAF detection
  gobuster          # Dir/DNS/vhost brute-force
  dirb              # Directory brute-force
  wfuzz             # Web fuzzer
  wpscan            # WordPress scanner
  joomscan          # Joomla scanner
  sslscan           # SSL/TLS analysis
  sslyze            # SSL/TLS scanner
  testssl.sh        # SSL/TLS comprehensive check
  curl              # HTTP Swiss-army knife
  wget              # HTTP downloader
)
for pkg in "${WEB_PKGS[@]}"; do apt_install "$pkg"; done

# FFUF (not always in apt — try multiple methods)
if ! command -v ffuf &>/dev/null; then
  info "Installing ffuf..."
  apt_install ffuf 2>/dev/null || {
    if command -v go &>/dev/null; then
      go install github.com/ffuf/ffuf/v2@latest && \
        cp ~/go/bin/ffuf /usr/local/bin/ && success "ffuf installed via go" || warn "ffuf install failed"
    else
      warn "ffuf not found in apt — install manually: apt install golang && go install github.com/ffuf/ffuf/v2@latest"
    fi
  }
fi

# Feroxbuster
if ! command -v feroxbuster &>/dev/null; then
  info "Installing feroxbuster..."
  apt_install feroxbuster 2>/dev/null || {
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
      -o /tmp/install_feroxbuster.sh 2>/dev/null && \
    bash /tmp/install_feroxbuster.sh /usr/local/bin 2>/dev/null && \
    success "feroxbuster installed" || warn "feroxbuster install failed"
  }
fi

# Nuclei
if ! command -v nuclei &>/dev/null; then
  info "Installing nuclei..."
  apt_install nuclei 2>/dev/null || {
    NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest 2>/dev/null | \
      grep -o '"browser_download_url": "[^"]*linux_amd64[^"]*\.zip"' | head -1 | cut -d'"' -f4)
    if [[ -n "$NUCLEI_URL" ]]; then
      curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip && \
        unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin && \
        mv /tmp/nuclei_bin/nuclei /usr/local/bin/ && \
        chmod +x /usr/local/bin/nuclei && \
        success "nuclei installed" || warn "nuclei install failed"
      rm -rf /tmp/nuclei.zip /tmp/nuclei_bin
    else
      warn "nuclei not found — install manually from projectdiscovery.io"
    fi
  }
fi

# ── SQL INJECTION & EXPLOIT TOOLS ────────────────────────────────────────────
section "Vulnerability & Exploit Tools"
VULN_PKGS=(
  sqlmap            # SQL injection automation
  commix            # Command injection
  beef-xss          # XSS browser exploitation (optional)
)
for pkg in "${VULN_PKGS[@]}"; do apt_install "$pkg" || true; done

# XSStrike
if ! command -v xsstrike &>/dev/null && ! python3 -c "import xsstrike" &>/dev/null 2>&1; then
  info "Installing XSStrike..."
  pip_install xsstrike 2>/dev/null || {
    git clone --depth=1 https://github.com/s0md3v/XSStrike /opt/XSStrike 2>/dev/null && \
    ln -sf /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike && \
    chmod +x /usr/local/bin/xsstrike && success "XSStrike installed" || warn "XSStrike install failed"
  }
fi

# ── BRUTE-FORCE TOOLS (ONLINE) ────────────────────────────────────────────────
section "Online Brute-force Tools"
BRUTE_PKGS=(
  hydra             # Multi-protocol online brute-force
  medusa            # Parallel login brute-forcer
  ncrack            # High-speed authentication cracker
  patator           # Flexible brute-forcer
  crowbar           # SSH key / OpenVPN brute-force
)
for pkg in "${BRUTE_PKGS[@]}"; do apt_install "$pkg" || true; done

# ── OFFLINE CRACKING TOOLS ────────────────────────────────────────────────────
section "Offline Password Cracking Tools"
CRACK_PKGS=(
  john              # John the Ripper CPU cracker
  johnny            # GUI for John (optional)
)
for pkg in "${CRACK_PKGS[@]}"; do apt_install "$pkg" || true; done

if [[ "$SKIP_GPU" == "false" ]]; then
  apt_install hashcat || true
  apt_install hashcat-utils || true
fi

# Haiti (hash identifier)
if ! command -v haiti &>/dev/null; then
  info "Installing haiti (hash identifier)..."
  gem install haiti-hash 2>/dev/null && success "haiti installed" || \
    warn "haiti install failed (requires ruby-full: apt install ruby-full)"
fi

# ── SMB / WINDOWS ENUMERATION ─────────────────────────────────────────────────
section "SMB / Windows Enumeration Tools"
SMB_PKGS=(
  enum4linux        # Windows/Samba enumeration
  enum4linux-ng     # Modern enum4linux rewrite
  smbclient         # SMB client
  smbmap            # SMB share mapper
  nbtscan           # NetBIOS scanner
  rpcclient         # RPC enumeration (in samba-common)
)
for pkg in "${SMB_PKGS[@]}"; do apt_install "$pkg" || true; done

# CrackMapExec
if ! command -v crackmapexec &>/dev/null && ! command -v cme &>/dev/null; then
  info "Installing CrackMapExec..."
  apt_install crackmapexec 2>/dev/null || \
    pip_install crackmapexec 2>/dev/null || \
    warn "CrackMapExec install failed — try: pip install crackmapexec"
fi

# ── SNMP ──────────────────────────────────────────────────────────────────────
section "SNMP Enumeration Tools"
SNMP_PKGS=(snmp snmp-mibs-downloader onesixtyone snmpcheck)
for pkg in "${SNMP_PKGS[@]}"; do apt_install "$pkg" || true; done

# ── NETWORK TOOLS ─────────────────────────────────────────────────────────────
section "Additional Network Tools"
NET_PKGS=(
  netcat-openbsd    # nc fallback
  tcpdump           # Packet capture
  ncat              # Nmap's netcat
  socat             # Socket relay
  arp-scan          # ARP network discovery
  fping             # Parallel ping
  traceroute        # Route tracing
  hping3            # TCP/IP packet crafter
)
for pkg in "${NET_PKGS[@]}"; do apt_install "$pkg" || true; done

# ── WORDLISTS ─────────────────────────────────────────────────────────────────
if [[ "$SKIP_WORDLISTS" == "false" ]]; then
  section "Wordlists & Dictionaries"

  apt_install wordlists  || true
  apt_install seclists   || true
  apt_install dirbuster  || true

  # rockyou.txt
  if [[ -f /usr/share/wordlists/rockyou.txt.gz ]] && \
     [[ ! -f /usr/share/wordlists/rockyou.txt ]]; then
    info "Decompressing rockyou.txt..."
    gunzip -k /usr/share/wordlists/rockyou.txt.gz && success "rockyou.txt ready"
  fi
  [[ -f /usr/share/wordlists/rockyou.txt ]] && \
    success "rockyou.txt: $(wc -l < /usr/share/wordlists/rockyou.txt) lines" || \
    warn "rockyou.txt not found"

  # WordPress wordlists (fix 0/3 shown in --wordlists)
  WP_DIR="/usr/share/seclists/Discovery/Web-Content/CMS/WordPress"
  mkdir -p "$WP_DIR"
  if [[ ! -f "$WP_DIR/wp-plugins.fuzz.txt" ]]; then
    info "Generating WordPress plugins wordlist..."
    printf '%s\n' \
      "wp-content/plugins/akismet" "wp-content/plugins/jetpack" \
      "wp-content/plugins/contact-form-7" "wp-content/plugins/woocommerce" \
      "wp-content/plugins/yoast-seo" "wp-content/plugins/wordfence" \
      "wp-content/plugins/elementor" "wp-content/plugins/wpforms-lite" \
      "wp-content/plugins/classic-editor" "wp-content/plugins/really-simple-ssl" \
      "wp-content/plugins/wp-super-cache" "wp-content/plugins/all-in-one-seo-pack" \
      "wp-content/plugins/updraftplus" "wp-content/plugins/mailchimp-for-wp" \
      "wp-content/plugins/advanced-custom-fields" "wp-content/plugins/w3-total-cache" \
      "wp-content/plugins/wp-file-manager" "wp-content/plugins/loginizer" \
      "wp-content/plugins/revslider" "wp-content/plugins/gravityforms" \
      "wp-content/plugins/better-wp-security" "wp-content/plugins/sucuri-scanner" \
      "wp-content/plugins/limit-login-attempts-reloaded" "wp-content/plugins/wp-mail-smtp" \
      > "$WP_DIR/wp-plugins.fuzz.txt"
    success "wp-plugins.fuzz.txt created"
  fi
  if [[ ! -f "$WP_DIR/wp-themes.fuzz.txt" ]]; then
    info "Generating WordPress themes wordlist..."
    printf '%s\n' \
      "wp-content/themes/twentytwentyfour" "wp-content/themes/twentytwentythree" \
      "wp-content/themes/twentytwentytwo" "wp-content/themes/astra" \
      "wp-content/themes/divi" "wp-content/themes/avada" \
      "wp-content/themes/generatepress" "wp-content/themes/oceanwp" \
      "wp-content/themes/hello-elementor" "wp-content/themes/flatsome" \
      "wp-content/themes/storefront" "wp-content/themes/newspaper" \
      > "$WP_DIR/wp-themes.fuzz.txt"
    success "wp-themes.fuzz.txt created"
  fi
  if [[ ! -f "$WP_DIR/wordpress-plugins.txt" ]]; then
    printf '%s\n' akismet jetpack contact-form-7 woocommerce wordpress-seo \
      wordfence elementor updraftplus revslider gravityforms sucuri-scanner \
      > "$WP_DIR/wordpress-plugins.txt"
    success "wordpress-plugins.txt created"
  fi

  # XSS payloads
  XSS_FILE="/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt"
  mkdir -p "$(dirname $XSS_FILE)"
  if [[ ! -f "$XSS_FILE" ]]; then
    info "Generating XSS payload list..."
    printf '%s\n' \
      '<script>alert(1)</script>' '"><script>alert(1)</script>' \
      '<img src=x onerror=alert(1)>' '<svg onload=alert(1)>' \
      "';alert(1)//" '{{7*7}}' '${7*7}' \
      '<details open ontoggle=alert(1)>' '" onmouseover="alert(1)' \
      '<iframe src="javascript:alert(1)">' '<body onload=alert(1)>' \
      '<script>alert(document.cookie)</script>' \
      > "$XSS_FILE"
    success "XSS-Jhaddix.txt created"
  fi

  # SQLi payloads
  SQLI_FILE="/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt"
  mkdir -p "$(dirname $SQLI_FILE)"
  if [[ ! -f "$SQLI_FILE" ]]; then
    info "Generating SQLi payload list..."
    printf '%s\n' \
      "'" "''" "' OR '1'='1" "' OR '1'='1'--" "1 OR 1=1" \
      "1' ORDER BY 1--" "' UNION SELECT NULL--" "1' AND SLEEP(5)--" \
      "admin'--" "' OR 1=1--" "' OR 1=1#" "1; DROP TABLE users--" \
      > "$SQLI_FILE"
    success "Generic-SQLi.txt created"
  fi

  # LFI payloads
  LFI_FILE="/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
  mkdir -p "$(dirname $LFI_FILE)"
  if [[ ! -f "$LFI_FILE" ]]; then
    info "Generating LFI payload list..."
    printf '%s\n' \
      "../../etc/passwd" "../../../etc/passwd" "../../../../etc/passwd" \
      "../../../../../etc/passwd" "../../etc/shadow" "../../etc/hosts" \
      "../../proc/self/environ" "/etc/passwd" "/etc/shadow" \
      "....//....//etc/passwd" "..%2F..%2Fetc%2Fpasswd" \
      > "$LFI_FILE"
    success "LFI-gracefulsecurity-linux.txt created"
  fi

  # Parameters wordlist
  PARAMS_FILE="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
  mkdir -p "$(dirname $PARAMS_FILE)"
  if [[ ! -f "$PARAMS_FILE" ]]; then
    info "Generating parameter names list..."
    printf '%s\n' id page search query q s url path file dir name user username \
      email pass password token key api_key apikey auth redirect return next goto \
      target dest action cmd exec command code lang locale callback jsonp format \
      type cat category view template theme style debug test mode sort order limit \
      offset start ref source > "$PARAMS_FILE"
    success "burp-parameter-names.txt created"
  fi

  # vhosts wordlist
  VHOSTS_FILE="/usr/share/seclists/Discovery/Web-Content/vhosts.txt"
  if [[ ! -f "$VHOSTS_FILE" ]]; then
    info "Generating vhosts wordlist..."
    printf '%s\n' dev staging test admin api internal intranet portal dashboard \
      app beta demo preview sandbox qa uat preprod old new v2 mobile m secure \
      mail smtp ftp vpn remote git gitlab jenkins monitor logs db database backup \
      cdn assets static media docs help wiki support crm erp > "$VHOSTS_FILE"
    success "vhosts.txt created"
  fi

  # SNMP communities
  SNMP_FILE="/usr/share/seclists/Discovery/SNMP/snmp.txt"
  mkdir -p "$(dirname $SNMP_FILE)"
  if [[ ! -f "$SNMP_FILE" ]]; then
    printf '%s\n' public private community manager admin snmp cisco default \
      internal monitor write read secret password test guest backup network \
      switch router > "$SNMP_FILE"
    success "snmp.txt created"
  fi

  # Run GhostScan built-in wordlist fixer for any remaining gaps
  info "Running wordlist gap fixer..."
  cd "$INSTALL_DIR"
  python3 -c "
import sys; sys.path.insert(0,'.')
from modules.wordlists import WordlistManager
wl = WordlistManager(verbose=True)
fixed = wl.fix_missing(verbose=True)
print(f'Fixed {len(fixed)} missing categories with built-in fallbacks')
" 2>/dev/null && success "Wordlist gaps patched" || true

  # Final count
  if [[ -d /usr/share/seclists ]]; then
    SECLISTS_COUNT=$(find /usr/share/seclists -name "*.txt" | wc -l)
    success "SecLists: $SECLISTS_COUNT wordlist files"
  fi
fi

# ── PYTHON DEPENDENCIES ───────────────────────────────────────────────────────
if [[ "$SKIP_PYTHON" == "false" ]]; then
  section "Python Dependencies"

  if [[ -f "$INSTALL_DIR/requirements.txt" ]]; then
    info "Installing from requirements.txt..."
    pip_install -r "$INSTALL_DIR/requirements.txt"
  else
    PYTHON_PKGS=(
      requests urllib3 dnspython beautifulsoup4
      lxml colorama tqdm tabulate
      reportlab
    )
    for pkg in "${PYTHON_PKGS[@]}"; do
      info "  pip: $pkg"
      pip_install "$pkg"
    done
  fi
  success "Python dependencies installed"
fi

# ── NUCLEI TEMPLATES ──────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
  section "Nuclei Templates"
  info "Updating Nuclei templates..."
  nuclei -update-templates -silent 2>/dev/null && \
    success "Nuclei templates updated" || warn "Nuclei template update failed (check internet)"
fi

# ── SYMLINK ───────────────────────────────────────────────────────────────────
section "Creating Symlink"
GHOSTSCAN_BIN="$INSTALL_DIR/ghostscan.py"
SYMLINK="/usr/local/bin/ghostscan"

if [[ -f "$GHOSTSCAN_BIN" ]]; then
  chmod +x "$GHOSTSCAN_BIN"
  ln -sf "$GHOSTSCAN_BIN" "$SYMLINK"
  success "Symlink created: $SYMLINK → $GHOSTSCAN_BIN"
else
  error "ghostscan.py not found at $GHOSTSCAN_BIN"
  exit 1
fi

# ── VERIFY PYTHON SYNTAX ─────────────────────────────────────────────────────
section "Syntax Verification"
cd "$INSTALL_DIR"
SYNTAX_OK=true
for pyfile in ghostscan.py modules/utils.py modules/recon.py modules/web_analysis.py \
              modules/vuln_detection.py modules/reporting.py modules/wordlists.py \
              modules/workflow.py modules/tool_integration.py; do
  if [[ -f "$pyfile" ]]; then
    if python3 -m py_compile "$pyfile" 2>/dev/null; then
      echo -e "  ${GRN}✓${RST} $pyfile"
    else
      echo -e "  ${RED}✗${RST} $pyfile"
      SYNTAX_OK=false
    fi
  fi
done

if [[ "$SYNTAX_OK" == "true" ]]; then
  success "All syntax checks passed"
else
  warn "Some files have syntax errors — check above"
fi

# ── TOOL INVENTORY ────────────────────────────────────────────────────────────
section "Installed Tool Summary"
TOOLS=(nmap masscan gobuster ffuf dirb wfuzz feroxbuster nikto whatweb wafw00f
       sqlmap hydra medusa john hashcat nuclei dnsrecon amass sublist3r
       theHarvester wpscan enum4linux smbclient crackmapexec snmpwalk onesixtyone
       sslscan testssl.sh xsstrike commix)

INSTALLED=(); MISSING=()
for t in "${TOOLS[@]}"; do
  if command -v "$t" &>/dev/null; then
    INSTALLED+=("$t")
  else
    MISSING+=("$t")
  fi
done

echo -e "\n  ${GRN}Installed (${#INSTALLED[@]}):${RST}"
printf '    %s\n' "${INSTALLED[@]}" | pr -3 -t -w 80

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo -e "\n  ${YLW}Not found (${#MISSING[@]}):${RST}"
  printf '    %s\n' "${MISSING[@]}" | pr -3 -t -w 80
  echo ""
  warn "Install missing tools:"
  echo "    sudo apt install -y ${MISSING[*]::5}"
fi

# ── FINAL INSTRUCTIONS ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GRN}╔══════════════════════════════════════════════════╗${RST}"
echo -e "${BOLD}${GRN}║         GhostScan v2.0 — Install Complete!       ║${RST}"
echo -e "${BOLD}${GRN}╚══════════════════════════════════════════════════╝${RST}"
echo ""
echo -e "${CYN}Quick Start:${RST}"
echo -e "  ${BOLD}ghostscan -t example.com --all --report pdf${RST}"
echo ""
echo -e "${CYN}Show tool status:${RST}"
echo -e "  ghostscan -t example.com --tools"
echo ""
echo -e "${CYN}Show wordlists:${RST}"
echo -e "  ghostscan -t example.com --wordlists"
echo ""
echo -e "${CYN}Full pentest workflow guide:${RST}"
echo -e "  ghostscan -t example.com --workflow"
echo ""
echo -e "${YLW}⚠  For authorized security testing only.${RST}"
echo ""
