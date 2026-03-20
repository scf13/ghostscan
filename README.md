<div align="center">

```
  ██████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
▒██    ▒ ▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
░ ▓██▄   ▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
  ▒   ██▒░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░
▒██████▒▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
```

**Elite Modular Penetration Testing Framework for Kali Linux**

[![CI](https://github.com/YOURUSERNAME/ghostscan/actions/workflows/ci.yml/badge.svg)](https://github.com/YOURUSERNAME/ghostscan/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?logo=linux)](https://kali.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tools](https://img.shields.io/badge/tools-53%20integrated-orange)](docs/sample_report.md)
[![Plugins](https://img.shields.io/badge/plugins-extensible-purple)](#plugin-system)

> ⚠️ **For authorized security testing only.** Unauthorized use is illegal.

</div>

---

## Philosophy

GhostScan is designed to **reduce noise, prioritise real risks, and guide pentesters through complex environments** — not to replace human expertise.

Most scanners give you 300 findings and leave you to figure out what matters.  
GhostScan gives you **10 findings you can act on today**, ranked by a scoring formula that accounts for impact, confidence, and business context.

> *"Login panel + SQL injection = CRITICAL" — not two separate MEDIUM findings.*

**Core principles:**
- **Signal over noise** — every finding has a score, confidence %, and business context
- **Context-aware** — correlated findings reveal compound attack paths automatically  
- **Guidance built-in** — adaptive workflow generates exact commands based on what was found
- **Fail gracefully** — one broken tool never stops the scan chain
- **Extensible** — drop a `.py` file into `plugins/` to add custom checks

---

## What Makes GhostScan Different

| Feature | Typical Scanner | GhostScan v3 |
|---------|----------------|--------------|
| Output | Raw dump, 300+ items | Correlated, scored, ranked |
| Severity | Static HIGH/MEDIUM/LOW | `score = (impact × 0.6) + (confidence × 0.4)` |
| Context | None | Login + SQLi → CRITICAL automatically |
| WAF | Gets blocked | Auto-detects + applies evasion profile |
| Workflow | Static commands | Adaptive — decisions from actual findings |
| Scope | No enforcement | Hard gate — blocks out-of-scope + SSRF protection |
| Plugins | None | Drop `.py` into `plugins/` — auto-loaded + sandboxed |
| Performance | Sequential | Parallel with per-tool timeout + retry |

---

## Quick Install

```bash
git clone https://github.com/YOURUSERNAME/ghostscan.git
cd ghostscan
sudo bash install.sh
```

Verify:
```bash
ghostscan -t example.com --tools
ghostscan -t example.com --wordlists
```

**Optional — DOM XSS scanning:**
```bash
pip install playwright --break-system-packages
playwright install chromium
```

---

## Scan Profiles

```bash
ghostscan -t TARGET --mode stealth      # passive recon only, 2s rate, no probing
ghostscan -t TARGET --mode standard --all --report pdf   # balanced (default)
ghostscan -t TARGET --mode aggressive   # all tools, all injections, max threads
```

| Profile | Rate | Threads | SQLi | XSS | Brute | WAF Bypass | Wordlists |
|---------|------|---------|------|-----|-------|------------|-----------|
| `stealth` | 2.0s | 5 | ✗ | ✗ | ✗ | ✗ | small |
| `standard` | 0.1s | 20 | ✓ | ✓ | ✗ | auto | medium |
| `aggressive` | 0.05s | 50 | ✓ | ✓ | ✓ | ✓ | large |

---

## Usage Examples

```bash
# Full scan, PDF report
ghostscan -t example.com --all --report pdf

# WAF bypass (auto-detect or force profile)
ghostscan -t example.com --web --waf-bypass
ghostscan -t example.com --web --waf-bypass --waf-profile cloudflare

# DOM XSS with screenshots
ghostscan -t example.com --web --browser --screenshots

# Parallel recon (all tools simultaneously)
ghostscan -t example.com --recon --parallel

# Show HIGH+ findings only — suppress noise
ghostscan -t example.com --all --min-severity high --report pdf

# Scope-restricted scan
ghostscan -t example.com --all --scope "*.example.com" --strict-scope

# Internal network
ghostscan -t 192.168.1.0/24 --recon --no-ssrf-protect --parallel

# Through Burp Suite
ghostscan -t example.com --web --proxy http://127.0.0.1:8080

# Tor routing
ghostscan -t example.com --all --tor

# Print adaptive next steps
ghostscan -t example.com --workflow

# Resume interrupted scan
ghostscan -t example.com --all --resume ./ghostscan_results/session_*.json

# 20 full examples
bash usage.sh
```

---

## Scoring System

```
score = (impact × 0.6) + (confidence × 0.4)
```

| Finding | Impact | Confidence | Score | Severity |
|---------|--------|-----------|-------|----------|
| AWS key in JS | 10 | 10 | **10.0** | CRITICAL |
| SQLi (sqlmap confirmed) | 10 | 9 | **9.6** | CRITICAL |
| RCE via CVE | 10 | 8 | **9.2** | CRITICAL |
| XSS reflected | 6 | 5 | **5.6** | MEDIUM |
| Missing CSP | 3 | 9 | **5.4** | MEDIUM |
| Server version | 2 | 10 | **4.0** | LOW |

**Context multipliers:**

| Condition | Multiplier | Result |
|-----------|-----------|--------|
| Login panel + SQLi | × 1.50 | CRITICAL |
| API + no auth | × 1.40 | HIGH → CRITICAL |
| DB port exposed externally | × 1.45 | CRITICAL |
| Secret in JS + no WAF | × 1.20 | CRITICAL |
| Payment/checkout path | × 1.50 | PCI scope upgrade |

---

## Correlation Engine

GhostScan automatically detects compound risks:

```
✓ Login panel at /wp-login.php (HTTP 200)
✓ SQL injection in ?search= (boolean-based)
✓ Content-Security-Policy missing
= 🔴 CRITICAL [9.8] SQLi on Auth Endpoint = Auth Bypass + DB Dump
  Attack: admin'-- → bypass auth → dump wp_users → crack hashes
```

```
✓ Redis on port 6379 (open to internet)
✓ No authentication (default config)
= 🔴 CRITICAL [9.6] Database Exposed Externally
  Attack: redis-cli → CONFIG SET → cron RCE
```

---

## Plugin System

Drop a `.py` file into `plugins/` — it loads automatically on the next scan.

```python
from plugins.base import GhostScanPlugin

class MyPlugin(GhostScanPlugin):
    name           = "My Custom Check"
    version        = "1.0.0"
    author         = "Your Name"
    description    = "Checks for something custom"
    requires       = ["web_analysis"]   # runs after web scan
    tags           = ["web", "auth"]
    severity       = "medium"
    stealth        = True               # safe for passive mode
    min_confidence = 0.5                # suppress low-confidence findings
    max_findings   = 20                 # cap to avoid noise
    timeout        = 30                 # auto-killed after 30s

    def run(self, target: str, context: dict) -> list:
        findings = []
        for url in context.get("endpoints", []):
            if "admin" in url:
                f = self.finding(
                    severity         = "high",
                    title            = f"Admin endpoint: {url}",
                    url              = url,
                    confidence       = 0.85,
                    impact           = 7.0,
                    exploitability   = "pre-auth",
                    business_context = "Admin access = full application control",
                    remediation      = "Restrict to VPN/trusted IPs. Enable MFA.",
                )
                if f:  # None = suppressed by min_confidence
                    findings.append(f)
        return findings
```

**Built-in plugins:**
| Plugin | What it detects |
|--------|----------------|
| `xss_custom.py` | XSS-prone parameters, business impact scoring (payment = CRITICAL) |
| `admin_finder.py` | Admin panels, Jenkins, Grafana, H2-console, phpMyAdmin with exploitability |
| `sensitive_files.py` | `.env`, `.git`, SQL dumps, backups, phpinfo — 30+ patterns |

**Plugin safety sandbox:**
- Each plugin runs in its own thread with a timeout kill-switch
- A crash returns `[]` — never breaks the main scan
- Findings capped at `max_findings` per plugin
- Confidence below `min_confidence` suppressed automatically

---

## All Flags

```
Modules:    --all  --recon  --web  --vuln  --workflow
Profile:    --mode stealth/standard/aggressive
Attack:     --sqli  --xss  --brute  --browser  --screenshots
            --parallel  --fast  --udp
            --intensity passive/normal/aggressive
WAF:        --waf-bypass  --waf-profile cloudflare|akamai|aws-waf|f5|imperva|modsecurity|wordfence|sucuri
Scope:      --scope TARGET  --scope-file FILE  --strict-scope  --no-ssrf-protect
Output:     --min-severity critical/high/medium/low/info
            --report markdown/html/pdf/json/both/all
            --output DIR  --resume FILE
Plugins:    --no-plugins
HTTP:       --proxy URL  --tor  --cookies JSON  --headers JSON  --user-agent STRING
Wordlists:  --wordlist-size small/medium/large
            --subdomain-wordlist FILE  --dir-wordlist FILE
Info:       --tools  --wordlists  --version  -v
```

---

## WAF Bypass Profiles

| WAF | sqlmap tamper | Delay |
|-----|--------------|-------|
| CloudFlare | space2comment,randomcase,charencode,between | 0.8–2.5s |
| Akamai | space2comment,charunicodeencode,randomcase,between | 1.0–3.5s |
| AWS-WAF | space2comment,randomcase,between | 0.3–1.2s |
| F5 BIG-IP | charunicodeencode,space2comment,randomcase,multiplespaces | 0.5–2.0s |
| Imperva | space2comment,charencode,randomcase,between,multiplespaces | 1.0–3.0s |
| ModSecurity | space2comment,randomcase,charencode,between,equaltolike | 0.3–1.5s |
| Wordfence | space2comment,randomcase,charencode | 0.5–2.0s |
| Sucuri | space2comment,randomcase | 1.0–3.0s |
| Generic | space2comment,randomcase,charencode | 0.5–2.0s |

---

## Integrated Tools (53)

| Category | Tools |
|----------|-------|
| Recon/OSINT | nmap, masscan, dnsrecon, dnsenum, amass, sublist3r, theHarvester, fierce, whois, dig |
| Web Scanning | nikto, whatweb, wafw00f, gobuster, ffuf, dirb, wfuzz, feroxbuster, wpscan, nuclei |
| Vulnerability | sqlmap, xsstrike, commix, testssl, sslscan, sslyze |
| Online Brute-force | hydra, medusa, ncrack, patator, crackmapexec |
| Offline Cracking | john, hashcat, haiti |
| SMB/Windows | enum4linux, enum4linux-ng, smbclient, smbmap, nbtscan |
| SNMP | snmpwalk, snmp-check, onesixtyone |

---

## Output Structure

```
ghostscan_results/
├── session_20240101_120000.json     ← Full session + intelligence data
├── ghostscan_example.com_*.md       ← Markdown report
├── ghostscan_example.com_*.html     ← Dark-theme HTML report
├── ghostscan_example.com_*.pdf      ← Professional PDF report
└── screenshots/                     ← Page screenshots (--browser --screenshots)
```

See [docs/sample_report.md](docs/sample_report.md) for a full example report.

---

## Project Structure

```
ghostscan/
├── ghostscan.py              # CLI entry point
├── install.sh                # Full installer
├── usage.sh                  # 20 usage examples
├── requirements.txt
├── docs/
│   └── sample_report.md      # Example pentest report
├── modules/
│   ├── scope.py              # Hard scope enforcement + SSRF protection
│   ├── executor.py           # Parallel execution (timeout/retry/isolation)
│   ├── intelligence.py       # Scoring engine + correlation + target ranking
│   ├── normaliser.py         # Unified JSON schema (UUID, confidence, impact)
│   ├── waf_bypass.py         # WAF evasion profiles + payload encoders
│   ├── workflow.py           # Adaptive workflow engine
│   ├── browser.py            # Playwright DOM XSS + screenshots
│   ├── recon.py              # DNS, subdomains, OSINT, port scan
│   ├── web_analysis.py       # Crawl, dir brute, nikto, nuclei, wpscan, JS
│   ├── vuln_detection.py     # Headers, SQLi, XSS, CVE correlation, brute
│   ├── tool_integration.py   # Wrappers for all 53 tools
│   ├── wordlists.py          # SecLists + built-in fallbacks
│   ├── reporting.py          # Markdown, HTML, PDF, JSON reports
│   └── utils.py              # Logging, colours, helpers
└── plugins/
    ├── base.py               # Plugin base class + sandboxed loader
    ├── xss_custom.py         # XSS checker with business impact
    ├── admin_finder.py       # Admin panel finder with exploitability
    └── sensitive_files.py    # Sensitive file detector (30+ patterns)
```

---

## Legal Notice

GhostScan is for **authorized security testing only**. Unauthorized use may violate:
- **US:** 18 U.S.C § 1030 (CFAA)
- **UK:** Computer Misuse Act 1990  
- **EU:** Directive 2013/40/EU

Always obtain written permission before testing any system.

---

## License

[MIT](LICENSE) — © 2024 GhostScan
