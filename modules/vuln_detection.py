#!/usr/bin/env python3
"""
GhostScan - Vulnerability Detection Module v2
Headers, XSS, SQLi (sqlmap), CVE correlation, brute-force, SSL.
Uses SecLists payloads and Kali tools.
"""

import re
import time
import json
import concurrent.futures
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, quote

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from modules.utils import log, log_finding, progress, make_finding, Colors
from modules.wordlists import WordlistManager
from modules.tool_integration import (ToolRunner, SqlmapRunner, HydraRunner,
                                       SSLScanRunner)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "detail": "HSTS not set. Downgrade attacks possible.",
        "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "detail": "No CSP. XSS attacks lack browser-level mitigation.",
        "fix": "Implement a strict Content-Security-Policy."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "detail": "Clickjacking possible.",
        "fix": "X-Frame-Options: DENY"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "detail": "MIME sniffing attacks possible.",
        "fix": "X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "detail": "Referrer header leaks internal URLs.",
        "fix": "Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "detail": "Browser permissions unconstrained.",
        "fix": "Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
}

DANGEROUS_HEADERS = {
    "Server":             "Web server version disclosed.",
    "X-Powered-By":       "Backend technology version disclosed.",
    "X-AspNet-Version":   "ASP.NET version disclosed.",
    "X-AspNetMvc-Version":"ASP.NET MVC version disclosed.",
    "X-Generator":        "CMS/platform disclosed.",
}

# Fallback XSS payloads (when SecLists not available)
BUILTIN_XSS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "';alert(1)//",
    '{{7*7}}',
    '${7*7}',
    '<details open ontoggle=alert(1)>',
    '" onmouseover="alert(1)',
    '<iframe src="javascript:alert(1)">',
]

# Fallback SQLi payloads
BUILTIN_SQLI = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1 OR 1=1",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
    "1' AND SLEEP(5)--",
    "admin'--",
    "' OR 1=1--",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"PostgreSQL.*ERROR", r"Warning.*pg_", r"Npgsql\.",
    r"ORA-\d{5}", r"Oracle error",
    r"Microsoft SQL Server", r"Incorrect syntax near", r"SQLSTATE",
    r"sqlite3.OperationalError",
    r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
]

# CVE knowledge base
CVE_DB = {
    "CVE-2021-44228": {
        "title": "Log4Shell — Apache Log4j2 RCE",
        "severity": "CRITICAL",
        "keywords": ["log4j", "log4j2", "apache log4"],
        "description": "JNDI injection allows unauthenticated RCE via log messages.",
        "fix": "Upgrade Log4j2 to 2.17.1+.",
    },
    "CVE-2021-26855": {
        "title": "ProxyLogon — Microsoft Exchange SSRF → RCE",
        "severity": "CRITICAL",
        "keywords": ["Microsoft Exchange", "OWA", "Exchange Server"],
        "description": "SSRF in Exchange leads to pre-auth RCE.",
        "fix": "Apply Microsoft security updates immediately.",
    },
    "CVE-2022-22965": {
        "title": "Spring4Shell — Spring Framework RCE",
        "severity": "CRITICAL",
        "keywords": ["Spring Framework", "Spring MVC", "Spring Boot"],
        "description": "ClassLoader manipulation leads to RCE.",
        "fix": "Upgrade Spring Framework to 5.3.18+ or 5.2.20+.",
    },
    "CVE-2019-0708": {
        "title": "BlueKeep — Windows RDP Pre-auth RCE",
        "severity": "CRITICAL",
        "keywords": ["rdp", "remote desktop", "windows"],
        "description": "Wormable pre-auth RCE via RDP.",
        "fix": "Apply KB4499175. Disable NLA if not needed.",
    },
    "CVE-2017-0144": {
        "title": "EternalBlue — SMBv1 RCE",
        "severity": "CRITICAL",
        "keywords": ["smb", "samba", "microsoft-ds"],
        "description": "NSA exploit. WannaCry/NotPetya used this.",
        "fix": "Disable SMBv1. Apply MS17-010.",
    },
    "CVE-2021-3156": {
        "title": "Baron Samedit — sudo Heap Overflow LPE",
        "severity": "HIGH",
        "keywords": ["sudo", "sudoedit"],
        "description": "Heap overflow allows local privilege escalation.",
        "fix": "Upgrade sudo to 1.9.5p2+.",
    },
    "CVE-2020-1472": {
        "title": "Zerologon — Netlogon Domain Takeover",
        "severity": "CRITICAL",
        "keywords": ["netlogon", "active directory", "domain controller"],
        "description": "Unauthenticated attacker can become domain admin.",
        "fix": "Apply KB4557222.",
    },
    "CVE-2023-44487": {
        "title": "HTTP/2 Rapid Reset DDoS",
        "severity": "HIGH",
        "keywords": ["nginx", "apache", "http/2"],
        "description": "HTTP/2 rapid reset allows amplified DDoS.",
        "fix": "Update web server and limit stream concurrency.",
    },
    "CVE-2021-41773": {
        "title": "Apache 2.4.49 Path Traversal/RCE",
        "severity": "CRITICAL",
        "keywords": ["Apache/2.4.49", "Apache HTTP Server 2.4.49"],
        "description": "Path traversal in CGI allows RCE.",
        "fix": "Upgrade Apache to 2.4.51+.",
    },
    "CVE-2022-0778": {
        "title": "OpenSSL Infinite Loop DoS",
        "severity": "HIGH",
        "keywords": ["OpenSSL", "openssl"],
        "description": "BN_mod_sqrt() infinite loop causes DoS.",
        "fix": "Upgrade OpenSSL to 1.0.2zd / 1.1.1n / 3.0.2.",
    },
    "CVE-2021-22205": {
        "title": "GitLab CE/EE RCE via ExifTool",
        "severity": "CRITICAL",
        "keywords": ["gitlab", "GitLab"],
        "description": "Unauthenticated RCE via image upload.",
        "fix": "Upgrade GitLab to 13.10.3+.",
    },
    "CVE-2022-27924": {
        "title": "Zimbra CRLF Injection Credential Theft",
        "severity": "HIGH",
        "keywords": ["zimbra", "Zimbra"],
        "description": "Memcache poisoning → plaintext credential theft.",
        "fix": "Patch ZCS 8.8.15 P30 / 9.0.0 P23.",
    },
    "CVE-2023-23397": {
        "title": "Microsoft Outlook Zero-Click NTLM Theft",
        "severity": "CRITICAL",
        "keywords": ["Microsoft Outlook", "Exchange", "SMTP"],
        "description": "Zero-click UNC path → Net-NTLMv2 hash leak.",
        "fix": "Apply March 2023 Outlook patch.",
    },
    "CVE-2023-34362": {
        "title": "MOVEit Transfer SQL Injection",
        "severity": "CRITICAL",
        "keywords": ["MOVEit", "moveit"],
        "description": "SQLi → RCE in MOVEit Transfer.",
        "fix": "Apply MOVEit security patch immediately.",
    },
    "CVE-2024-3400": {
        "title": "PAN-OS GlobalProtect Command Injection",
        "severity": "CRITICAL",
        "keywords": ["PAN-OS", "GlobalProtect", "Palo Alto"],
        "description": "Unauthenticated command injection → root RCE.",
        "fix": "Apply PAN-OS security update.",
    },
}


class VulnDetectionModule:
    def __init__(self, config: dict, prior_web: dict = None, prior_recon: dict = None):
        self.config = config
        self.target = config["target"]
        self.timeout = config.get("timeout", 10)
        self.rate_limit = config.get("rate_limit", 0.1)
        self.threads = config.get("threads", 20)
        self.verbose = config.get("verbose", False)
        self.intensity = config.get("intensity", "normal")
        self.do_xss = config.get("xss", False)
        self.do_sqli = config.get("sqli", False)
        self.do_brute = config.get("brute", False)
        self.do_cve = not config.get("no_cve", False)
        self.prior_web = prior_web or {}
        self.prior_recon = prior_recon or {}
        self.findings = []

        self.runner = ToolRunner(config)
        self.wl = WordlistManager(verbose=self.verbose)
        self.sqlmap_r = SqlmapRunner(self.runner)
        self.hydra_r = HydraRunner(self.runner)
        self.sslscan_r = SSLScanRunner(self.runner)
        self.session = self._build_session() if HAS_REQUESTS else None

        # WAF bypass — auto-detect from prior web results
        self.waf_bypass = None
        waf_info = prior_web.get("waf", {}) if prior_web else {}
        if waf_info.get("detected") or config.get("waf_bypass") or config.get("waf_profile"):
            try:
                from modules.waf_bypass import build_bypass, WafBypass
                if config.get("waf_profile"):
                    self.waf_bypass = WafBypass(config["waf_profile"], self.intensity)
                else:
                    self.waf_bypass = build_bypass(waf_info, self.intensity)
                if self.session and self.waf_bypass:
                    self.waf_bypass.patch_session(self.session)
            except Exception as e:
                log(f"    WAF bypass init error: {e}", Colors.DIM)

    def run(self) -> dict:
        results = {
            "header_audit": {},
            "xss_findings": [],
            "sqli_findings": [],
            "brute_findings": [],
            "cve_findings": [],
            "ssl_findings": [],
            "findings": [],
        }

        base_url = self._get_base_url()

        log("  → Security header audit...", Colors.CYAN)
        results["header_audit"] = self._audit_headers(base_url)
        missing = len(results["header_audit"].get("missing", {}))
        log(f"    {missing} missing security headers", Colors.GREEN)

        if "https" in base_url:
            log("  → SSL/TLS analysis...", Colors.CYAN)
            host = urlparse(base_url).netloc
            results["ssl_findings"] = self.sslscan_r.scan(host)

        if self.do_sqli:
            log("  → SQL injection testing (sqlmap)...", Colors.CYAN)
            results["sqli_findings"] = self._probe_sqli_all(base_url)
            log(f"    {len(results['sqli_findings'])} SQLi findings", Colors.GREEN)

        if self.do_xss:
            log("  → XSS probing...", Colors.CYAN)
            results["xss_findings"] = self._probe_xss_all(base_url)
            log(f"    {len(results['xss_findings'])} potential XSS", Colors.GREEN)

        if self.do_brute:
            log("  → Authentication brute-force...", Colors.CYAN)
            results["brute_findings"] = self._brute_services()
            log(f"    {len(results['brute_findings'])} brute-force findings", Colors.GREEN)

        if self.do_cve:
            log("  → CVE correlation...", Colors.CYAN)
            results["cve_findings"] = self._correlate_cves()
            log(f"    {len(results['cve_findings'])} CVE matches", Colors.GREEN)

        results["findings"] = self.findings
        return results

    # ── HEADER AUDIT ──────────────────────────────────────────────────────────

    def _audit_headers(self, url: str) -> dict:
        result = {"url": url, "missing": {}, "present": {}, "dangerous": {}, "cookies": []}
        if not self.session:
            return result
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            headers = resp.headers

            for hdr, info in SECURITY_HEADERS.items():
                header_lower = hdr.lower()
                found = any(k.lower() == header_lower for k in headers)
                if not found:
                    result["missing"][hdr] = info
                    self.findings.append(make_finding(info["severity"], "Headers",
                        f"Missing: {hdr}", detail=info["detail"], url=url,
                        remediation=info["fix"]))
                    log_finding(info["severity"], f"Missing header: {hdr}", info["detail"])
                else:
                    result["present"][hdr] = headers.get(hdr, "")
                    if hdr == "Content-Security-Policy":
                        self._audit_csp(headers.get(hdr, ""), url)

            for hdr, detail in DANGEROUS_HEADERS.items():
                if any(k.lower() == hdr.lower() for k in headers):
                    val = headers.get(hdr, "")
                    result["dangerous"][hdr] = val
                    self.findings.append(make_finding("LOW", "Headers",
                        f"Info disclosure via {hdr}: {val}", detail=detail, url=url,
                        remediation=f"Remove or sanitise {hdr} header."))
                    log_finding("LOW", f"Info: {hdr}: {val}")

            result["cookies"] = self._audit_cookies(resp, url)
            self._check_cors(resp, url)
        except Exception as e:
            if self.verbose:
                log(f"    Header audit error: {e}", Colors.DIM)
        return result

    def _audit_csp(self, csp: str, url: str):
        checks = [
            ("unsafe-inline", "'unsafe-inline' in script-src — inline JS permitted"),
            ("unsafe-eval",   "'unsafe-eval' — eval() permitted"),
        ]
        if re.search(r"script-src\s+['\"]?\*", csp):
            self.findings.append(make_finding("HIGH", "CSP",
                "Wildcard script-src — CSP is ineffective", url=url))
        for pattern, msg in checks:
            if pattern in csp:
                self.findings.append(make_finding("MEDIUM", "CSP",
                    f"Weak CSP: {msg}", url=url,
                    remediation="Harden CSP to remove unsafe directives."))
                log_finding("MEDIUM", f"Weak CSP: {msg}")

    def _audit_cookies(self, resp, url: str) -> list:
        issues = []
        for cookie in resp.cookies:
            problems = []
            if not cookie.secure:
                problems.append("missing Secure flag")
            name_lower = cookie.name.lower()
            rest = str(getattr(cookie, "_rest", {})).lower()
            if "httponly" not in rest:
                problems.append("missing HttpOnly flag")
            if "samesite" not in rest:
                problems.append("missing SameSite attribute")
            if problems:
                msg = f"Cookie '{cookie.name}': {', '.join(problems)}"
                issues.append(msg)
                self.findings.append(make_finding("MEDIUM", "Cookie", msg, url=url,
                    remediation="Set Secure; HttpOnly; SameSite=Strict on all session cookies."))
                log_finding("MEDIUM", msg)
        return issues

    def _check_cors(self, resp, url: str):
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            self.findings.append(make_finding("HIGH", "CORS",
                "CORS misconfiguration: ACAO=* with Allow-Credentials=true",
                url=url,
                remediation="Never combine wildcard ACAO with Allow-Credentials: true."))
            log_finding("HIGH", "CORS misconfiguration", url)
        elif acao == "*":
            self.findings.append(make_finding("LOW", "CORS",
                "CORS allows any origin (ACAO: *)", url=url))

    # ── SQLI ──────────────────────────────────────────────────────────────────

    def _probe_sqli_all(self, base_url: str) -> list:
        all_findings = []
        targets = self._get_injectable_endpoints()

        # sqlmap (preferred)
        if self.runner.available("sqlmap"):
            log("    ↳ sqlmap detection mode...", Colors.DIM)
            level = {"passive": 1, "normal": 3, "aggressive": 5}.get(self.intensity, 3)
            risk = {"passive": 1, "normal": 2, "aggressive": 3}.get(self.intensity, 2)

            # Get WAF-specific tamper scripts if bypass is configured
            waf_b = getattr(self, 'waf_bypass', None)
            extra_sqlmap_args = []
            if waf_b:
                tamper = waf_b.get_tamper_scripts()
                extra_sqlmap_args = ["--tamper", tamper, "--random-agent",
                                     "--delay", str(round(waf_b.delay_range[0], 1)),
                                     "--headers", "X-Forwarded-For: 127.0.0.1"]
                log(f"    ↳ WAF tamper: {tamper}", Colors.CYAN)

            for url, params in targets[:10]:
                param_str = ",".join(params.keys()) if params else None
                test_url = url + "?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else url
                r = self.sqlmap_r.detect(test_url, params=param_str, level=level, risk=risk,
                                         timeout=180)
                if r.get("vulnerable"):
                    for p in r.get("injectable_params", []):
                        f = make_finding("CRITICAL", "SQLi",
                            f"SQL Injection: {p.get('parameter')} ({p.get('injection_type')})",
                            url=test_url,
                            remediation="Use prepared statements/parameterized queries.")
                        self.findings.append(f)
                        all_findings.append({**p, "url": test_url})
                        log_finding("CRITICAL", f"SQLi: {p.get('parameter')}", test_url)
        else:
            log("    ↳ sqlmap not found — built-in SQLi detection...", Colors.DIM)
            all_findings = self._builtin_sqli(targets)

        # Also test forms
        for form in self.prior_web.get("forms", []):
            if form.get("inputs") and self.runner.available("sqlmap"):
                inputs = {i["name"]: i.get("value", "test") for i in form["inputs"]
                          if i.get("name") and i.get("type") not in ["submit", "hidden", "button"]}
                if inputs and form.get("method") == "POST":
                    post_data = "&".join(f"{k}={v}" for k, v in inputs.items())
                    r = self.sqlmap_r.detect(form["action"], level=2, risk=1, timeout=120)
                    if r.get("vulnerable"):
                        f = make_finding("CRITICAL", "SQLi",
                            f"SQLi in POST form at {form['action']}",
                            url=form["action"],
                            remediation="Use parameterized queries.")
                        self.findings.append(f)
                        all_findings.append({"url": form["action"], "type": "POST form"})

        return all_findings

    def _builtin_sqli(self, targets: list) -> list:
        """Fallback error-based + boolean SQLi without sqlmap."""
        all_findings = []
        payloads = self._load_payloads("sqli") or BUILTIN_SQLI

        for url, params in targets[:5]:
            if not params or not self.session:
                continue
            try:
                baseline = self.session.get(url, params=params,
                                            timeout=self.timeout, verify=False).text
            except Exception:
                continue

            for payload in payloads[:15]:
                try:
                    test = {k: v + payload for k, v in params.items()}
                    resp = self.session.get(url, params=test, timeout=self.timeout, verify=False)
                    for pat in SQLI_ERROR_PATTERNS:
                        m = re.search(pat, resp.text, re.I)
                        if m:
                            f = make_finding("CRITICAL", "SQLi",
                                f"SQL error detected at {url}",
                                evidence=f"Pattern: {m.group(0)[:60]}",
                                url=url,
                                remediation="Use parameterized queries.")
                            self.findings.append(f)
                            all_findings.append({"url": url, "payload": payload[:50]})
                            log_finding("CRITICAL", f"SQLi error at {url}", payload[:40])
                            break
                    time.sleep(self.rate_limit)
                except Exception:
                    pass
        return all_findings

    # ── XSS ───────────────────────────────────────────────────────────────────

    def _probe_xss_all(self, base_url: str) -> list:
        all_findings = []
        targets = self._get_injectable_endpoints()
        payloads = self._load_payloads("xss") or BUILTIN_XSS

        # Limit based on intensity
        max_payloads = {"passive": 5, "normal": 10, "aggressive": len(payloads)}.get(self.intensity, 10)
        payloads = payloads[:max_payloads]

        if not self.session:
            return []

        for url, params in targets[:10]:
            for payload in payloads:
                result = self._test_xss(url, params, payload)
                if result:
                    all_findings.append(result)
                    self.findings.append(make_finding("HIGH", "XSS",
                        f"Reflected XSS at {url}",
                        evidence=f"Payload: {payload[:60]}",
                        url=url,
                        remediation="Encode output. Implement strict CSP."))
                    log_finding("HIGH", f"Reflected XSS at {url}", payload[:50])
                time.sleep(self.rate_limit)

        # Test POST forms
        for form in self.prior_web.get("forms", []):
            if form.get("method") == "POST" and form.get("inputs"):
                inputs = {i["name"]: i.get("value", "test")
                          for i in form["inputs"]
                          if i.get("name") and i.get("type") not in ["submit", "hidden"]}
                if not inputs:
                    continue
                for payload in payloads[:5]:
                    try:
                        test_data = {k: payload for k in inputs}
                        resp = self.session.post(form["action"], data=test_data,
                                                 timeout=self.timeout, verify=False)
                        if payload in resp.text and re.search(r'<script|onerror|onload', resp.text, re.I):
                            all_findings.append({"url": form["action"], "method": "POST", "payload": payload})
                            log_finding("HIGH", f"XSS in POST form", form["action"])
                    except Exception:
                        pass
                    time.sleep(self.rate_limit)

        return all_findings

    def _test_xss(self, url: str, params: dict, payload: str) -> dict:
        try:
            test = {k: payload for k in params}
            resp = self.session.get(url, params=test, timeout=self.timeout, verify=False)
            if payload in resp.text or quote(payload) in resp.text:
                if re.search(r'<script|onerror|onload|javascript:', resp.text, re.I):
                    return {"url": url, "payload": payload, "method": "GET"}
        except Exception:
            pass
        return None

    # ── BRUTE FORCE ───────────────────────────────────────────────────────────

    def _brute_services(self) -> list:
        all_findings = []
        open_ports = {}
        for host_ports in self.prior_recon.get("open_ports", {}).values():
            open_ports.update(host_ports)

        all_ports = set(int(p) for p in open_ports.keys())
        hosts = list(self.prior_recon.get("open_ports", {}).keys())
        if not hosts:
            hosts = [self.target]

        if not self.runner.available("hydra"):
            log("    hydra not installed — skipping brute-force", Colors.YELLOW)
            return []

        wl_users, _ = self.wl.get_or_builtin("usernames", "small")
        wl_pass, _ = self.wl.get_or_builtin("passwords", "small")

        # Write builtins to temp files if needed
        import tempfile, os
        user_file = wl_users if isinstance(wl_users, str) and Path(wl_users).exists() else None
        pass_file = wl_pass if isinstance(wl_pass, str) and Path(wl_pass).exists() else None

        if not user_file:
            tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tf.write("\n".join(wl_users if isinstance(wl_users, list) else self.wl.get_builtin_list("usernames")))
            tf.close()
            user_file = tf.name

        if not pass_file:
            tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tf.write("\n".join(wl_pass if isinstance(wl_pass, list) else self.wl.get_builtin_list("passwords")))
            tf.close()
            pass_file = tf.name

        service_map = {22: "ssh", 21: "ftp", 23: "telnet",
                       3306: "mysql", 5432: "postgres", 1433: "mssql"}

        for host in hosts[:3]:
            for port in all_ports:
                svc = service_map.get(port)
                if svc:
                    log(f"    ↳ Hydra {svc} on {host}:{port}...", Colors.DIM)
                    result = self.hydra_r.attack(
                        host, svc, user_file, pass_file, port=port, threads=4)
                    for cred in result.get("credentials", []):
                        all_findings.append(cred)
                        self.findings.append(make_finding(
                            "CRITICAL", "BruteForce",
                            f"Valid credentials: {cred['username']}:{cred['password']} on {host}:{port} ({svc})",
                            remediation="Change credentials immediately."))

        # HTTP brute-force from form analysis
        for form in self.prior_web.get("forms", [])[:2]:
            inputs = form.get("inputs", [])
            user_field = next((i["name"] for i in inputs
                               if any(kw in i.get("name","").lower()
                                      for kw in ["user","email","login","username"])), None)
            pass_field = next((i["name"] for i in inputs
                               if any(kw in i.get("name","").lower()
                                      for kw in ["pass","pwd","password","secret"])), None)
            if user_field and pass_field and form.get("method") == "POST":
                log(f"    ↳ Hydra HTTP form: {form['action']}", Colors.DIM)
                form_params = f"{user_field}=^USER^&{pass_field}=^PASS^:Invalid"
                result = self.hydra_r.http_form_attack(
                    form["action"], user_file, pass_file, form_params,
                    fail_string="Invalid", threads=8)
                for cred in result.get("credentials", []):
                    all_findings.append(cred)
                    self.findings.append(make_finding(
                        "CRITICAL", "BruteForce",
                        f"HTTP login cracked: {cred['username']}:{cred['password']} at {form['action']}",
                        remediation="Implement account lockout and rate limiting."))

        return all_findings

    # ── CVE CORRELATION ───────────────────────────────────────────────────────

    def _correlate_cves(self) -> list:
        findings = []
        tech = self.prior_web.get("technologies", {})
        fingerprints = []
        for items in tech.values():
            if isinstance(items, list):
                fingerprints.extend(items)

        for host_ports in self.prior_recon.get("open_ports", {}).values():
            for info in host_ports.values():
                svc = f"{info.get('product','')} {info.get('version','')} {info.get('service','')}".strip()
                if svc:
                    fingerprints.append(svc)

        seen = set()
        for fp in fingerprints:
            for cve_id, info in CVE_DB.items():
                if cve_id in seen:
                    continue
                if any(kw.lower() in fp.lower() for kw in info["keywords"]):
                    seen.add(cve_id)
                    findings.append({
                        "cve": cve_id,
                        "title": info["title"],
                        "severity": info["severity"],
                        "matched": fp,
                        "description": info["description"],
                    })
                    self.findings.append(make_finding(
                        info["severity"], "CVE",
                        f"{cve_id}: {info['title']} (matched: {fp[:50]})",
                        detail=info["description"],
                        remediation=info.get("fix", "Apply vendor patches.")))
                    log_finding(info["severity"], f"{cve_id}: {info['title']}", fp[:50])

        return findings

    # ── SSL ───────────────────────────────────────────────────────────────────

    def _check_ssl_http_redirect(self, url: str):
        if not self.session:
            return
        try:
            http_url = url.replace("https://", "http://")
            resp = self.session.get(http_url, timeout=self.timeout,
                                    verify=False, allow_redirects=False)
            if resp.status_code not in [301, 302, 307, 308]:
                self.findings.append(make_finding("MEDIUM", "SSL",
                    "No HTTP → HTTPS redirect", url=http_url,
                    remediation="Redirect all HTTP traffic to HTTPS (301 permanent)."))
                log_finding("MEDIUM", "No HTTP→HTTPS redirect")
        except Exception:
            pass

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _load_payloads(self, category: str) -> list:
        """Load payloads from SecLists if available."""
        payload_files = {
            "xss": [
                "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
                "/usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt",
            ],
            "sqli": [
                "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
                "/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt",
            ],
        }
        for path in payload_files.get(category, []):
            if Path(path).exists():
                try:
                    with open(path) as f:
                        payloads = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                    if self.verbose:
                        log(f"    Loaded {len(payloads)} {category} payloads from SecLists", Colors.DIM)
                    return payloads
                except Exception:
                    pass
        return []

    def _get_injectable_endpoints(self) -> list:
        targets = []
        for url in self.prior_web.get("endpoints", []):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                targets.append((clean, {k: v[0] for k, v in params.items()}))
        for form in self.prior_web.get("forms", []):
            if form.get("method", "GET") == "GET":
                params = {i["name"]: i.get("value", "1")
                          for i in form.get("inputs", [])
                          if i.get("name") and i.get("type") not in ["submit", "button"]}
                if params:
                    targets.append((form["action"], params))
        if not targets:
            base = self._get_base_url()
            targets.append((base, {"id": "1", "q": "test"}))
        return targets[:20]

    def _get_base_url(self) -> str:
        for url in self.prior_web.get("base_urls", []):
            if url.startswith("https://"):
                return url
        for url in self.prior_web.get("base_urls", []):
            return url
        return f"https://{self.target}"

    def _build_session(self):
        if not HAS_REQUESTS:
            return None
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.config.get("user_agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"),
        })
        if self.config.get("headers"):
            session.headers.update(self.config["headers"])
        if self.config.get("cookies"):
            session.cookies.update(self.config["cookies"])
        if self.config.get("proxy"):
            session.proxies.update(self.config["proxy"])
        return session

    def _parse_qs_from_url(self, url: str) -> dict:
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(url)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}
