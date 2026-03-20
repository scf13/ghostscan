#!/usr/bin/env python3
"""
GhostScan - Web Analysis Module v2
Crawling, endpoint discovery, JS analysis, Nikto, WhatWeb, WAF detection,
gobuster/ffuf directory brute-force, WPScan.
"""

import re
import time
import json
import concurrent.futures
from urllib.parse import urljoin, urlparse
from collections import defaultdict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from modules.utils import log, log_finding, progress, make_finding, Colors
from modules.wordlists import WordlistManager
from modules.tool_integration import (ToolRunner, NiktoRunner, WhatWebRunner,
                                       WafW00fRunner, GobusterRunner, FfufRunner,
                                       WpScanRunner, SSLScanRunner, NucleiRunner)

# JS secret patterns
SECRET_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":    r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key":   r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
    "Bearer Token":      r"(?i)bearer\s+[a-zA-Z0-9\-_=]{20,}",
    "Private Key":       r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Password in Code":  r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "JWT Token":         r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token":       r"xox[baprs]-[0-9a-zA-Z-]+",
    "GitHub Token":      r"ghp_[0-9a-zA-Z]{36}",
    "Stripe Live Key":   r"(?:r|s)k_live_[0-9a-zA-Z]{24}",
    "Database DSN":      r"(?i)(mysql|postgres|mongodb|redis)://[^\s'\"]+",
    "SMTP Credentials":  r"(?i)smtp[_-]?(user|pass|password|host)\s*[:=]\s*['\"][^'\"]{3,}['\"]",
    "Firebase URL":      r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
}

INTERESTING_PATHS = [
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.hg/hgrc",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.bak",
    "/config.php", "/config.js", "/config.json", "/config.yml", "/config.yaml",
    "/settings.py", "/settings.php", "/app.config", "/web.config", "/appsettings.json",
    "/wp-config.php", "/wp-login.php", "/wp-admin/", "/wp-json/wp/v2/users",
    "/.htaccess", "/.htpasswd", "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql", "/db.sql",
    "/admin/", "/administrator/", "/manage/", "/dashboard/", "/panel/",
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/swagger-ui.html", "/api-docs",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/actuator/beans", "/actuator/configprops",
    "/graphql", "/graphiql", "/__graphql", "/graphql/playground",
    "/.well-known/security.txt", "/security.txt",
    "/trace", "/debug", "/_debug/",
    "/console", "/h2-console", "/druid/", "/jolokia/",
    "/metrics", "/health", "/status",
    "/jmx-console/", "/web-console/",
    "/solr/", "/jenkins/", "/gitlab/",
    "/phpmyadmin/", "/pma/", "/myadmin/",
    "/adminer.php", "/adminer/",
    "/.DS_Store", "/Thumbs.db",
]


class WebAnalysisModule:
    def __init__(self, config: dict, prior_results: dict = None, waf_bypass_engine=None):
        self.config = config
        self.target = config["target"]
        self.depth = config.get("depth", 3)
        self.threads = config.get("threads", 20)
        self.timeout = config.get("timeout", 10)
        self.rate_limit = config.get("rate_limit", 0.1)
        self.verbose = config.get("verbose", False)
        self.prior = prior_results or {}
        self.findings = []

        self.runner = ToolRunner(config)
        self.wl = WordlistManager(verbose=self.verbose)
        self.nikto = NiktoRunner(self.runner)
        self.whatweb = WhatWebRunner(self.runner)
        self.wafw00f_r = WafW00fRunner(self.runner)
        self.gobuster = GobusterRunner(self.runner)
        self.ffuf_r = FfufRunner(self.runner)
        self.wpscan_r = WpScanRunner(self.runner)
        self.sslscan_r = SSLScanRunner(self.runner)
        self.nuclei_r = NucleiRunner(self.runner)

        self.waf_bypass_engine = waf_bypass_engine
        self.session = self._build_session() if HAS_REQUESTS else None

        # Wire WAF bypass into session and adjust rate limit from profile
        if self.session and waf_bypass_engine:
            waf_bypass_engine.patch_session(self.session)
            lo, hi = waf_bypass_engine.delay_range
            self.rate_limit = max(self.rate_limit, lo * 0.5)
            log(f"  [WAF Bypass] Active ({waf_bypass_engine.waf_name}) — rate {self.rate_limit:.2f}s", Colors.CYAN)

        self.base_urls = self._build_base_urls()
        self.visited = set()
        self.all_endpoints = set()
        self.all_forms = []
        self.all_js_files = set()

    def run(self) -> dict:
        results = {
            "base_urls": self.base_urls,
            "waf": {},
            "technologies": {},
            "endpoints": [],
            "forms": [],
            "js_files": [],
            "js_secrets": [],
            "interesting_paths": [],
            "nikto_findings": [],
            "ssl_findings": [],
            "dir_brute": [],
            "nuclei_findings": [],
            "cms_findings": [],
            "findings": [],
        }

        base = self.base_urls[0] if self.base_urls else f"https://{self.target}"

        # 1. WAF Detection + auto-build bypass
        log("  → WAF detection...", Colors.CYAN)
        results["waf"] = self.wafw00f_r.detect(base)
        waf = results["waf"].get("waf")
        if waf:
            log(f"    WAF detected: {waf}", Colors.YELLOW)
            self.findings.append(make_finding("INFO", "WAF",
                f"WAF detected: {waf}",
                detail="WAF bypass profile auto-activated."))
            # Auto-build bypass from detected WAF if not already provided
            if not self.waf_bypass_engine and self.config.get("waf_bypass", True):
                try:
                    from modules.waf_bypass import build_bypass
                    self.waf_bypass_engine = build_bypass(results["waf"], self.config.get("intensity", "normal"))
                    if self.session and self.waf_bypass_engine:
                        self.waf_bypass_engine.patch_session(self.session)
                        self.rate_limit = max(self.rate_limit, self.waf_bypass_engine.delay_range[0] * 0.5)
                except Exception as e:
                    log(f"    WAF bypass init error: {e}", Colors.DIM)
        else:
            log("    No WAF detected", Colors.GREEN)

        # 2. Technology fingerprinting
        log("  → Technology fingerprinting...", Colors.CYAN)
        results["technologies"] = self._detect_tech(base)

        # 3. Web crawl
        if HAS_REQUESTS and self.session:
            log("  → Web crawl...", Colors.CYAN)
            self._crawl_all()
            log(f"    {len(self.visited)} pages, {len(self.all_endpoints)} endpoints", Colors.GREEN)

        # 4. Directory brute-force
        log("  → Directory brute-force...", Colors.CYAN)
        results["dir_brute"] = self._dir_brute(base)
        log(f"    {len(results['dir_brute'])} paths found", Colors.GREEN)

        # 5. Interesting path probing
        log("  → Probing sensitive paths...", Colors.CYAN)
        results["interesting_paths"] = self._probe_paths(base)
        log(f"    {len(results['interesting_paths'])} accessible sensitive paths", Colors.GREEN)

        # 6. Nikto scan
        log("  → Nikto web scan...", Colors.CYAN)
        nikto_r = self.nikto.scan(base, timeout=self.config.get("nikto_timeout", 300))
        results["nikto_findings"] = nikto_r.get("findings", [])
        log(f"    {len(results['nikto_findings'])} Nikto findings", Colors.GREEN)
        self._process_nikto_findings(results["nikto_findings"], base)

        # 7. SSL scan
        if "https" in base:
            log("  → SSL/TLS analysis...", Colors.CYAN)
            host = urlparse(base).netloc
            results["ssl_findings"] = self.sslscan_r.scan(host)

        # 8. JS secret scanning
        if self.all_js_files:
            log(f"  → JavaScript analysis ({len(self.all_js_files)} files)...", Colors.CYAN)
            results["js_files"] = list(self.all_js_files)
            results["js_secrets"] = self._analyze_js()
            log(f"    {len(results['js_secrets'])} potential secrets in JS", Colors.GREEN)

        # 9. CMS-specific scans
        cms_list = results["technologies"].get("cms", [])
        if any("wordpress" in c.lower() for c in cms_list):
            log("  → WordPress scan (WPScan)...", Colors.CYAN)
            results["cms_findings"] = self._wpscan(base)

        # 10. Nuclei
        if self.runner.available("nuclei"):
            log("  → Nuclei template scan...", Colors.CYAN)
            nuclei_r = self.nuclei_r.scan(base, severity="critical,high,medium",
                                          timeout=self.config.get("nuclei_timeout", 600))
            results["nuclei_findings"] = nuclei_r.get("findings", [])
            log(f"    {len(results['nuclei_findings'])} Nuclei findings", Colors.GREEN)
            self._process_nuclei_findings(results["nuclei_findings"])

        results["endpoints"] = sorted(list(self.all_endpoints))
        results["forms"] = self.all_forms
        results["findings"] = self.findings
        return results

    # ── WAF / TECH ────────────────────────────────────────────────────────────

    def _detect_tech(self, url: str) -> dict:
        tech = defaultdict(list)

        # WhatWeb
        if self.runner.available("whatweb"):
            data = self.whatweb.scan(url)
            for key, val in data.items():
                if key not in ("url", "http_status", "request_config", "plugins"):
                    tech["whatweb"].append(f"{key}: {str(val)[:60]}")
            plugins = data.get("plugins", {})
            for plugin_name in plugins:
                if plugin_name in ("WordPress", "Drupal", "Joomla", "Shopify"):
                    tech["cms"].append(plugin_name)
                elif plugin_name in ("PHP", "ASP.NET", "Ruby-on-Rails", "Django", "Laravel"):
                    tech["backend"].append(plugin_name)
                elif plugin_name in ("Apache", "Nginx", "IIS", "LiteSpeed"):
                    tech["server"].append(plugin_name)
            return dict(tech)

        # Fallback: header + HTML parsing
        if not self.session:
            return {}
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            h = resp.headers
            html = resp.text

            if h.get("Server"): tech["server"].append(h["Server"])
            if h.get("X-Powered-By"): tech["backend"].append(h["X-Powered-By"])
            if h.get("X-Generator"): tech["cms"].append(h["X-Generator"])

            sc = h.get("Set-Cookie", "")
            if "PHPSESSID" in sc: tech["backend"].append("PHP")
            if "JSESSIONID" in sc: tech["backend"].append("Java")
            if "ASP.NET_SessionId" in sc: tech["backend"].append("ASP.NET")

            if "wp-content" in html or "wp-includes" in html: tech["cms"].append("WordPress")
            if "Drupal" in html or "/sites/default/" in html: tech["cms"].append("Drupal")
            if "Joomla" in html: tech["cms"].append("Joomla")
            if "ng-version" in html: tech["frontend"].append("Angular")
            if "__NEXT_DATA__" in html: tech["frontend"].append("Next.js")
            if "data-reactroot" in html: tech["frontend"].append("React")
            if "cdn.shopify.com" in html: tech["cms"].append("Shopify")
            if "cdn.magento.com" in html or "Mage.Cookies" in html: tech["cms"].append("Magento")
        except Exception:
            pass
        return dict(tech)

    # ── DIRECTORY BRUTE-FORCE ─────────────────────────────────────────────────

    def _dir_brute(self, base: str) -> list:
        intensity = self.config.get("intensity", "normal")
        size_map = {"passive": "small", "normal": "medium", "aggressive": "large"}
        wl_size = size_map.get(intensity, "medium")
        wl_path = self.wl.get("web_dirs", wl_size)

        if not wl_path:
            log("    No wordlist found — skipping dir brute", Colors.YELLOW)
            return []

        ext = "php,html,js,txt,json,xml,bak,zip,tar.gz,sql,asp,aspx,jsp"

        if self.runner.available("gobuster"):
            log(f"    ↳ Gobuster ({wl_path.split('/')[-1]})...", Colors.DIM)
            # Apply WAF bypass to gobuster args
            gb_threads = max(5, self.threads // 2) if self.waf_bypass_engine else self.threads
            results = self.gobuster.dir_scan(base, wl_path, extensions=ext,
                                             threads=gb_threads)
        elif self.runner.available("ffuf"):
            log(f"    ↳ FFUF ({wl_path.split('/')[-1]})...", Colors.DIM)
            # Apply WAF bypass: lower threads and add evasion
            ff_threads = max(10, 100 // 3) if self.waf_bypass_engine else 100
            results_raw = self.ffuf_r.fuzz(f"{base}/FUZZ", wl_path, threads=ff_threads)
            results = [{"path": "/" + r.get("input", {}).get("FUZZ", ""),
                        "status": r.get("status", 0),
                        "size": r.get("length", 0)} for r in results_raw]
        elif self.runner.available("dirb"):
            log(f"    ↳ Dirb...", Colors.DIM)
            results = self._run_dirb(base, wl_path, ext)
        else:
            log("    No dir brute tool available (install gobuster or ffuf)", Colors.YELLOW)
            return []

        for r in results:
            full_url = base.rstrip("/") + r.get("path", "")
            if r.get("status") == 200:
                self.all_endpoints.add(full_url)
        return results

    def _run_dirb(self, url: str, wordlist: str, extensions: str) -> list:
        rc, stdout, _ = self.runner.run(["dirb", url, wordlist,
                                          "-X", "." + ",.".join(extensions.split(",")),
                                          "-S", "-r"],
                                         timeout=300)
        results = []
        for line in stdout.splitlines():
            m = re.match(r"^\+\s+(https?://[^\s]+)\s+\(Code:(\d+)\|Size:(\d+)\)", line)
            if m:
                path = "/" + m.group(1).split("/", 3)[-1] if "/" in m.group(1) else m.group(1)
                results.append({"path": path, "status": int(m.group(2)), "size": int(m.group(3))})
        return results

    # ── WEB CRAWL ─────────────────────────────────────────────────────────────

    def _crawl_all(self):
        queue = [(url, 0) for url in self.base_urls]
        while queue:
            batch = [item for item in queue[:self.threads] if item[0] not in self.visited]
            queue = queue[self.threads:]
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self._crawl_page, url, depth): (url, depth)
                           for url, depth in batch}
                for fut in concurrent.futures.as_completed(futures):
                    for new_url, new_depth in fut.result():
                        if new_url not in self.visited and new_depth <= self.depth:
                            queue.append((new_url, new_depth))

    def _crawl_page(self, url: str, depth: int) -> list:
        if url in self.visited:
            return []
        self.visited.add(url)
        self.all_endpoints.add(url)
        new_links = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            # Use WAF bypass throttle if active, else plain sleep
            if self.waf_bypass_engine:
                self.waf_bypass_engine.throttle()
                self.waf_bypass_engine.rotate_ua(self.session)
            else:
                time.sleep(self.rate_limit)
            self._check_response(url, resp)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                return []
            if not HAS_BS4:
                for link in re.findall(r'href=["\']([^"\']+)["\']', resp.text):
                    full = urljoin(url, link)
                    if self._same_domain(url, full):
                        new_links.append((full, depth + 1))
                return new_links
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all(["a", "link"], href=True):
                full = urljoin(url, tag["href"])
                if self._same_domain(url, full) and full not in self.visited:
                    new_links.append((full, depth + 1))
                    self.all_endpoints.add(full)
            for form in soup.find_all("form"):
                self.all_forms.append(self._parse_form(url, form))
            for script in soup.find_all("script", src=True):
                js_url = urljoin(url, script["src"])
                if self._same_domain(url, js_url):
                    self.all_js_files.add(js_url)
            self._extract_api_endpoints(url, resp.text)
        except Exception as e:
            if self.verbose:
                log(f"    Crawl error {url}: {e}", Colors.DIM)
        return new_links

    def _parse_form(self, page_url: str, form) -> dict:
        action = form.get("action", "")
        return {
            "page": page_url,
            "action": urljoin(page_url, action) if action else page_url,
            "method": form.get("method", "GET").upper(),
            "inputs": [{"name": i.get("name", ""), "type": i.get("type", "text"),
                        "value": i.get("value", "")}
                       for i in form.find_all(["input", "textarea", "select"])],
        }

    def _extract_api_endpoints(self, base_url: str, html: str):
        patterns = [
            r'["\'](/api/[^"\'<>\s]{3,})["\']',
            r'["\'](/v\d+/[^"\'<>\s]+)["\']',
            r'fetch\(["\']([^"\']{5,})["\']',
            r'axios\.[a-z]+\(["\']([^"\']{5,})["\']',
            r'url:\s*["\']([^"\']{5,})["\']',
        ]
        for pat in patterns:
            for match in re.findall(pat, html):
                full = urljoin(base_url, match)
                if self._same_domain(base_url, full):
                    self.all_endpoints.add(full)

    def _check_response(self, url: str, resp):
        debug_patterns = ["traceback", "stack trace", "ORA-", "SQLSTATE",
                          "mysql_fetch", "syntax error near", "Call to undefined"]
        for p in debug_patterns:
            if p.lower() in resp.text.lower():
                f = make_finding("MEDIUM", "Web",
                    f"Error disclosure at {url}",
                    detail=f"Pattern: '{p}'", url=url,
                    remediation="Disable verbose errors in production.")
                self.findings.append(f)
                log_finding("MEDIUM", f"Error disclosure at {url}", p)
                break

    # ── PATH PROBING ──────────────────────────────────────────────────────────

    def _probe_paths(self, base: str) -> list:
        found = []

        def probe(path):
            url = base.rstrip("/") + path
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False,
                                        allow_redirects=False)
                time.sleep(self.rate_limit / 2)
                if resp.status_code in [200, 301, 302, 403]:
                    return {"url": url, "status": resp.status_code,
                            "size": len(resp.content), "path": path}
            except Exception:
                pass
            return None

        if not self.session:
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for r in ex.map(probe, INTERESTING_PATHS):
                if r:
                    found.append(r)
                    self._classify_sensitive_path(r)
        return found

    def _classify_sensitive_path(self, r: dict):
        critical = {
            "/.git/HEAD":       ("CRITICAL", "Git repo exposed",     "Source code may be fully downloadable."),
            "/.env":            ("CRITICAL", ".env file exposed",     "Secrets, DB creds, API keys exposed."),
            "/.env.production": ("CRITICAL", ".env.production",       "Production secrets exposed."),
            "/wp-config.php":   ("CRITICAL", "wp-config.php exposed", "WordPress DB credentials accessible."),
            "/dump.sql":        ("CRITICAL", "SQL dump accessible",   "Database content publicly downloadable."),
            "/backup.sql":      ("CRITICAL", "SQL backup accessible", "Database dump publicly accessible."),
            "/actuator/env":    ("CRITICAL", "Spring Actuator /env",  "Environment variables including secrets."),
            "/.htpasswd":       ("HIGH",     ".htpasswd exposed",     "Password hashes accessible."),
            "/phpinfo.php":     ("HIGH",     "phpinfo() exposed",     "Server config and path disclosure."),
            "/backup.zip":      ("HIGH",     "Backup archive accessible", "Possible source code download."),
            "/swagger.json":    ("MEDIUM",   "Swagger/OpenAPI exposed", "Full API surface documented."),
            "/graphql":         ("MEDIUM",   "GraphQL endpoint",      "Test for introspection and enumeration."),
        }
        p = r["path"]
        s = r["status"]
        if p in critical and s == 200:
            sev, title, detail = critical[p]
            f = make_finding(sev, "Web", f"{title} — {r['url']}", detail=detail, url=r["url"],
                             remediation=f"Block access to {p} immediately.")
            self.findings.append(f)
            log_finding(sev, title, r["url"])

    # ── JS ANALYSIS ───────────────────────────────────────────────────────────

    def _analyze_js(self) -> list:
        secrets = []
        total = len(self.all_js_files)
        done = [0]
        for js_url in self.all_js_files:
            done[0] += 1
            progress("    JS scan", done[0], total)
            try:
                resp = self.session.get(js_url, timeout=self.timeout, verify=False)
                time.sleep(self.rate_limit)
                for name, pattern in SECRET_PATTERNS.items():
                    for match in re.findall(pattern, resp.text):
                        entry = {"type": name,
                                 "match": match[:80] + "..." if len(match) > 80 else match,
                                 "url": js_url}
                        secrets.append(entry)
                        f = make_finding("CRITICAL", "Secret",
                            f"{name} found in {js_url}",
                            evidence=entry["match"], url=js_url,
                            remediation="Remove secrets from client-side code.")
                        self.findings.append(f)
                        log_finding("CRITICAL", f"{name} in JS", js_url)
            except Exception:
                pass
        return secrets

    # ── NIKTO / NUCLEI ────────────────────────────────────────────────────────

    def _process_nikto_findings(self, nikto_findings: list, base: str):
        for f in nikto_findings:
            msg = f.get("msg", "")
            severity = "MEDIUM"
            if any(kw in msg.lower() for kw in ["sql injection", "xss", "rce", "shell"]):
                severity = "HIGH"
            elif any(kw in msg.lower() for kw in ["critical", "remote code"]):
                severity = "CRITICAL"
            self.findings.append(make_finding(severity, "Nikto", msg[:120],
                url=base + f.get("url", ""),
                remediation="Review Nikto finding and apply appropriate fix."))

    def _process_nuclei_findings(self, nuclei_findings: list):
        for f in nuclei_findings:
            self.findings.append(make_finding(
                f.get("severity", "MEDIUM"), "Nuclei",
                f"{f.get('name', '')} [{f.get('template_id', '')}]",
                detail=f.get("description", ""),
                url=f.get("url", ""),
                remediation="Review Nuclei template details and apply recommended fix."))

    def _wpscan(self, url: str) -> list:
        wl_users = self.wl.get("usernames", "small")
        wl_pass = self.wl.get("passwords", "small")
        r = self.wpscan_r.scan(url, userlist=wl_users, passlist=wl_pass)
        for f in r.get("findings", []):
            self.findings.append(make_finding(
                f.get("severity", "HIGH"), "WordPress",
                f.get("title", ""), url=url))
        return r.get("findings", [])

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _build_base_urls(self) -> list:
        urls = []
        t = self.target.lstrip("http://").lstrip("https://").rstrip("/")
        for scheme in ["https", "http"]:
            urls.append(f"{scheme}://{t}")
        for sub in self.prior.get("subdomains", [])[:10]:
            sd = sub.get("subdomain", "")
            if sd:
                urls.append(f"https://{sd}")
        return urls

    def _build_session(self):
        if not HAS_REQUESTS:
            return None
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.config.get("user_agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        if self.config.get("headers"):
            session.headers.update(self.config["headers"])
        if self.config.get("cookies"):
            session.cookies.update(self.config["cookies"])
        if self.config.get("proxy"):
            session.proxies.update(self.config["proxy"])
        return session

    def _same_domain(self, base_url: str, url: str) -> bool:
        try:
            base_host = urlparse(base_url).netloc
            url_host = urlparse(url).netloc
            target = self.target.lstrip("www.")
            return target in url_host or url_host == base_host
        except Exception:
            return False
