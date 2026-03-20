#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  GhostScan v3.0 — Usage Examples Script
#  Run any example by passing its number: bash usage.sh 1
#  Or just read this file as a reference guide.
#
#  AUTHORIZED USE ONLY — only run against systems you own or have
#  explicit written permission to test.
# ═══════════════════════════════════════════════════════════════════════════

TARGET="${2:-example.com}"   # Pass target as second arg, default example.com

show_help() {
cat << 'HELP'
GhostScan v3.0 — Usage Examples

  bash usage.sh <example_number> [target]

EXAMPLES:
  1  — Full scan (all modules, PDF report)
  2  — Recon only (DNS, subdomains, ports)
  3  — Web scan only
  4  — Vuln scan (headers, SQLi, XSS, CVEs)
  5  — Parallel recon (all tools simultaneously)
  6  — Aggressive mode + all injections
  7  — WAF bypass mode
  8  — Headless browser (DOM XSS)
  9  — Tor routing
  10 — Internal network scan
  11 — WordPress deep scan
  12 — Brute-force login / services
  13 — Offline hash cracking
  14 — Show tool inventory
  15 — Show wordlist inventory
  16 — Full pentest workflow guide
  17 — Resume interrupted scan
  18 — Scope-restricted scan
  19 — Through Burp Suite proxy
  20 — Minimum severity filter (HIGH+ only)

HELP
}

run_example() {
  case $1 in

  # ── 1. FULL SCAN ────────────────────────────────────────────────────────
  1)
    echo "[+] Full scan — all modules, PDF + Markdown report"
    ghostscan -t "$TARGET" \
      --all \
      --report both \
      --output ./results \
      -v
    ;;

  # ── 2. RECON ONLY ───────────────────────────────────────────────────────
  2)
    echo "[+] Recon only — DNS, WHOIS, subdomains, ports"
    ghostscan -t "$TARGET" \
      --recon \
      --ports "21,22,25,53,80,110,143,443,445,3306,3389,8080,8443" \
      --report json \
      --output ./results
    ;;

  # ── 3. WEB SCAN ONLY ────────────────────────────────────────────────────
  3)
    echo "[+] Web scan — crawl, dir brute, nikto, nuclei, JS secrets"
    ghostscan -t "$TARGET" \
      --web \
      --depth 4 \
      --threads 30 \
      --wordlist-size large \
      --report both \
      --output ./results
    ;;

  # ── 4. VULNERABILITY SCAN ───────────────────────────────────────────────
  4)
    echo "[+] Vuln scan — headers, SQLi, XSS, CVE correlation"
    ghostscan -t "$TARGET" \
      --vuln \
      --sqli \
      --xss \
      --report both \
      --output ./results
    ;;

  # ── 5. PARALLEL RECON (FAST) ────────────────────────────────────────────
  5)
    echo "[+] Parallel recon — nmap + amass + sublist3r + theHarvester simultaneously"
    ghostscan -t "$TARGET" \
      --recon \
      --parallel \
      --threads 30 \
      --report json \
      --output ./results
    ;;

  # ── 6. AGGRESSIVE FULL SCAN ─────────────────────────────────────────────
  6)
    echo "[+] Aggressive mode — all modules + injections + brute-force"
    ghostscan -t "$TARGET" \
      --all \
      --intensity aggressive \
      --sqli \
      --xss \
      --brute \
      --fast \
      --wordlist-size large \
      --threads 50 \
      --report all \
      --output ./results
    ;;

  # ── 7. WAF BYPASS ───────────────────────────────────────────────────────
  7)
    echo "[+] WAF bypass — auto-detect + apply evasion profile"
    ghostscan -t "$TARGET" \
      --web \
      --vuln \
      --sqli \
      --xss \
      --waf-bypass \
      --intensity normal \
      --report both \
      --output ./results

    echo ""
    echo "[+] Force specific WAF profile (CloudFlare example):"
    echo "    ghostscan -t $TARGET --web --waf-bypass --waf-profile cloudflare"
    echo ""
    echo "[+] Available WAF profiles:"
    echo "    cloudflare | akamai | aws-waf | f5 | imperva | modsecurity | wordfence | sucuri | generic"
    ;;

  # ── 8. HEADLESS BROWSER (DOM XSS) ───────────────────────────────────────
  8)
    echo "[+] Headless browser — DOM XSS, hidden endpoints, JS storage"
    echo "    Requires: pip install playwright && playwright install chromium"
    ghostscan -t "$TARGET" \
      --web \
      --browser \
      --depth 3 \
      --report both \
      --output ./results
    ;;

  # ── 9. TOR ROUTING ──────────────────────────────────────────────────────
  9)
    echo "[+] Scan through Tor — requires tor service running"
    echo "    Setup: sudo apt install tor && sudo service tor start"
    ghostscan -t "$TARGET" \
      --all \
      --tor \
      --intensity passive \
      --report both \
      --output ./results
    ;;

  # ── 10. INTERNAL NETWORK SCAN ───────────────────────────────────────────
  10)
    echo "[+] Internal network scan — CIDR range"
    ghostscan -t "192.168.1.0/24" \
      --recon \
      --no-subdomains \
      --no-ssrf-protect \
      --ports "22,80,135,139,443,445,3306,3389,5432,5900,8080,8443" \
      --fast \
      --parallel \
      --report both \
      --output ./results
    ;;

  # ── 11. WORDPRESS DEEP SCAN ─────────────────────────────────────────────
  11)
    echo "[+] WordPress deep scan — plugins, themes, users, brute-force"
    ghostscan -t "$TARGET" \
      --web \
      --vuln \
      --xss \
      --sqli \
      --brute \
      --wordlist-size large \
      --intensity aggressive \
      --report both \
      --output ./results

    echo ""
    echo "[+] Manual WPScan commands:"
    echo "    wpscan --url https://$TARGET --enumerate vp,vt,u,cb,dbe --plugins-detection aggressive"
    echo "    wpscan --url https://$TARGET --passwords /usr/share/wordlists/rockyou.txt"
    ;;

  # ── 12. BRUTE-FORCE ─────────────────────────────────────────────────────
  12)
    echo "[+] Online brute-force — HTTP login, SSH, FTP, SMB"
    ghostscan -t "$TARGET" \
      --vuln \
      --brute \
      --username-wordlist /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      --password-wordlist /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
      --report both \
      --output ./results

    echo ""
    echo "[+] Manual Hydra examples:"
    echo "    # HTTP POST form:"
    echo "    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form '/login:user=^USER^&pass=^PASS^:Invalid' -t 16 -f"
    echo "    # SSH:"
    echo "    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 4 -f"
    echo "    # SMB:"
    echo "    crackmapexec smb $TARGET -u users.txt -p /usr/share/wordlists/rockyou.txt"
    ;;

  # ── 13. OFFLINE HASH CRACKING ───────────────────────────────────────────
  13)
    echo "[+] Offline hash cracking — John + Hashcat"
    echo ""
    echo "    John the Ripper (CPU):"
    echo "    john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt"
    echo "    john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64"
    echo "    john hashes.txt --format=ntlm --wordlist=/usr/share/wordlists/rockyou.txt"
    echo "    john --show hashes.txt"
    echo ""
    echo "    Hashcat (GPU — common modes):"
    echo "    hashcat -m 0    hashes.txt /usr/share/wordlists/rockyou.txt --force  # MD5"
    echo "    hashcat -m 100  hashes.txt /usr/share/wordlists/rockyou.txt --force  # SHA1"
    echo "    hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --force  # NTLM"
    echo "    hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt --force  # Net-NTLMv2"
    echo "    hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt --force  # bcrypt"
    echo "    hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt --force  # sha512crypt"
    echo ""
    echo "    With rules:"
    echo "    hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force"
    echo ""
    echo "    SSH key cracking:"
    echo "    ssh2john id_rsa > id_rsa.hash"
    echo "    john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt"
    ;;

  # ── 14. TOOL INVENTORY ──────────────────────────────────────────────────
  14)
    echo "[+] Show all installed tools"
    ghostscan -t "$TARGET" --tools
    ;;

  # ── 15. WORDLIST INVENTORY ──────────────────────────────────────────────
  15)
    echo "[+] Show all available wordlists"
    ghostscan -t "$TARGET" --wordlists
    ;;

  # ── 16. WORKFLOW GUIDE ──────────────────────────────────────────────────
  16)
    echo "[+] Full pentest workflow reference"
    ghostscan -t "$TARGET" --workflow
    ;;

  # ── 17. RESUME SCAN ─────────────────────────────────────────────────────
  17)
    echo "[+] Resume from saved session"
    LATEST=$(ls -t ./results/session_*.json 2>/dev/null | head -1)
    if [[ -z "$LATEST" ]]; then
      echo "[-] No session file found in ./results/"
      echo "    Run a scan first, then use --resume"
    else
      echo "[+] Resuming from: $LATEST"
      ghostscan -t "$TARGET" \
        --web \
        --vuln \
        --resume "$LATEST" \
        --report both \
        --output ./results
    fi
    ;;

  # ── 18. SCOPE-RESTRICTED SCAN ───────────────────────────────────────────
  18)
    echo "[+] Scope-restricted scan — blocks out-of-scope requests"
    ghostscan -t "$TARGET" \
      --all \
      --scope "*.${TARGET}" \
      --scope "${TARGET}" \
      --strict-scope \
      --report both \
      --output ./results

    echo ""
    echo "[+] With scope file:"
    echo "    echo '*.example.com'  > scope.txt"
    echo "    echo 'example.com'   >> scope.txt"
    echo "    echo '!staging.example.com' >> scope.txt  # exclude staging"
    echo "    ghostscan -t example.com --all --scope-file scope.txt --strict-scope"
    ;;

  # ── 19. THROUGH BURP SUITE ──────────────────────────────────────────────
  19)
    echo "[+] Route all traffic through Burp Suite proxy"
    echo "    Make sure Burp is running on 127.0.0.1:8080"
    ghostscan -t "$TARGET" \
      --web \
      --vuln \
      --proxy "http://127.0.0.1:8080" \
      --report both \
      --output ./results

    echo ""
    echo "[+] With session cookie (post-auth scan):"
    echo "    ghostscan -t $TARGET --web --proxy http://127.0.0.1:8080 --cookies '{\"PHPSESSID\":\"abc123\"}'"
    ;;

  # ── 20. SEVERITY FILTER ─────────────────────────────────────────────────
  20)
    echo "[+] Only show HIGH and CRITICAL findings — suppress noise"
    ghostscan -t "$TARGET" \
      --all \
      --min-severity high \
      --report both \
      --output ./results
    ;;

  *)
    show_help
    ;;
  esac
}

# ── ENTRY POINT ──────────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
  show_help
else
  run_example "$1"
fi
