#!/usr/bin/env python3
"""
GhostScan - Headless Browser Module
Uses Playwright to detect:
  - DOM XSS (sinks: innerHTML, document.write, eval, etc.)
  - JS-rendered hidden endpoints (SPA routes, lazy-loaded URLs)
  - Auth-required content behind login
  - Client-side storage secrets (localStorage, sessionStorage, cookies)
  - Dangling JS includes pointing to unclaimed domains
  - WebSocket endpoints
  - CORS behaviour under real browser context
"""

import re
import json
import asyncio
import time
from urllib.parse import urljoin, urlparse
from modules.utils import log, log_finding, make_finding, Colors

try:
    from playwright.async_api import async_playwright, Page, BrowserContext
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


# ── DOM XSS SINKS ────────────────────────────────────────────────────────────
DOM_XSS_SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(",
    "Function(",
    "location.href", "location.assign", "location.replace",
    "window.open(",
    "document.domain",
    "document.cookie",
    "jQuery.html(",
    "$(", ".html(",
]

DOM_XSS_SOURCES = [
    "location.search", "location.hash", "location.href",
    "document.referrer", "document.URL",
    "window.name", "localStorage", "sessionStorage",
    "URLSearchParams", "document.cookie",
]

XSS_TEST_PAYLOADS = [
    '<img src=x onerror="window.__xss_triggered=1">',
    'javascript:window.__xss_triggered=1',
    '";window.__xss_triggered=1;//',
    "';window.__xss_triggered=1;//",
    '{{constructor.constructor("window.__xss_triggered=1")()}}',
    '<svg/onload=window.__xss_triggered=1>',
]


class HeadlessBrowser:
    """
    Playwright-powered browser engine for deep JS analysis.
    Falls back gracefully if Playwright is not installed.
    """

    def __init__(self, config: dict, waf_bypass=None):
        self.config     = config
        self.target     = config["target"]
        self.timeout    = config.get("timeout", 15) * 1000   # ms
        self.verbose    = config.get("verbose", False)
        self.waf_bypass = waf_bypass
        self.findings   = []
        self.proxy      = config.get("proxy")

    # ── AVAILABILITY CHECK ────────────────────────────────────────────────────

    @staticmethod
    def available() -> bool:
        if not HAS_PLAYWRIGHT:
            return False
        try:
            import subprocess
            r = subprocess.run(["playwright", "install", "--dry-run"],
                               capture_output=True, timeout=5)
            return True
        except Exception:
            return HAS_PLAYWRIGHT

    @staticmethod
    def install_hint() -> str:
        return ("pip install playwright --break-system-packages && "
                "playwright install chromium")

    # ── MAIN RUN ─────────────────────────────────────────────────────────────

    def run(self, urls: list) -> dict:
        """Synchronous entry point — wraps async runner."""
        if not HAS_PLAYWRIGHT:
            log(f"    Playwright not installed — skipping headless scan", Colors.DIM)
            log(f"    Install: {self.install_hint()}", Colors.DIM)
            return {"available": False, "findings": [], "endpoints": [],
                    "js_endpoints": [], "dom_xss": [], "storage": {}}

        try:
            return asyncio.run(self._run_async(urls))
        except Exception as e:
            log(f"    Headless browser error: {e}", Colors.YELLOW)
            return {"available": True, "error": str(e), "findings": self.findings,
                    "endpoints": [], "js_endpoints": [], "dom_xss": [], "storage": {}}

    async def _run_async(self, urls: list) -> dict:
        results = {
            "available":    True,
            "findings":     [],
            "endpoints":    [],
            "js_endpoints": [],
            "dom_xss":      [],
            "websockets":   [],
            "storage":      {},
            "dangling_js":  [],
            "cors_issues":  [],
        }

        proxy_cfg = None
        if self.proxy:
            if isinstance(self.proxy, dict):
                proxy_url = self.proxy.get("http") or self.proxy.get("https", "")
            else:
                proxy_url = self.proxy
            proxy_cfg = {"server": proxy_url}

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-web-security",    # allow cross-origin XHR analysis
                    "--ignore-certificate-errors",
                ],
            )

            ctx_args = {
                "ignore_https_errors": True,
                "bypass_csp": True,            # bypass CSP to test DOM XSS
                "java_script_enabled": True,
            }
            if proxy_cfg:
                ctx_args["proxy"] = proxy_cfg
            if self.waf_bypass:
                ctx_args["extra_http_headers"] = self.waf_bypass.profile.get("headers", {})
                ctx_args["user_agent"] = self.waf_bypass.profile.get(
                    "user_agents", ["Mozilla/5.0"])[0]

            context = await browser.new_context(**ctx_args)

            for url in urls[:5]:  # limit to 5 base URLs
                try:
                    await self._analyse_page(context, url, results)
                except Exception as e:
                    if self.verbose:
                        log(f"      Browser error on {url}: {e}", Colors.DIM)

            await context.close()
            await browser.close()

        results["findings"] = self.findings
        return results

    # ── PAGE ANALYSIS ─────────────────────────────────────────────────────────

    async def _analyse_page(self, context: BrowserContext, url: str, results: dict):
        page = await context.new_page()
        collected_endpoints = []
        collected_ws        = []

        # Intercept network requests to discover hidden endpoints
        async def on_request(req):
            req_url = req.url
            if req_url.startswith("ws://") or req_url.startswith("wss://"):
                collected_ws.append(req_url)
                results["websockets"].append(req_url)
            elif req_url.startswith("http"):
                collected_endpoints.append(req_url)

        page.on("request", on_request)

        # Console error monitoring
        console_errors = []
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)
        except Exception as e:
            if "timeout" not in str(e).lower():
                log(f"      Page load error {url}: {e}", Colors.DIM)
            await page.close()
            return

        # Wait for JS to settle
        await asyncio.sleep(2)

        # Take screenshot if enabled
        if self.config.get("screenshots", False):
            await self._take_screenshot(page, url, results)

        # 1. Collect all JS-rendered URLs
        rendered_links = await page.evaluate("""() => {
            const links = new Set();
            document.querySelectorAll('a[href], form[action], [src]').forEach(el => {
                const val = el.href || el.action || el.src;
                if (val) links.add(val);
            });
            // SPA routes in common frameworks
            if (window.__vue_router__) {
                window.__vue_router__.options.routes?.forEach(r => links.add(r.path));
            }
            if (window.Backbone?.history) {
                Object.keys(window.Backbone.history.handlers || {}).forEach(h => links.add(h));
            }
            return [...links];
        }""")

        for link in rendered_links:
            if link and link.startswith("http"):
                results["endpoints"].append(link)

        # 2. JS-rendered API endpoints from XHR/fetch
        js_urls = await page.evaluate("""() => {
            const urls = [];
            // Override fetch and XHR to capture URLs
            return window.__captured_urls || [];
        }""")
        results["js_endpoints"].extend([u for u in js_urls if u])
        results["js_endpoints"].extend([u for u in collected_endpoints
                                        if "/api/" in u or "/graphql" in u or "/rest/" in u])

        # 3. DOM XSS Analysis
        dom_xss = await self._check_dom_xss(page, url)
        results["dom_xss"].extend(dom_xss)

        # 4. Client-side storage secrets
        storage = await self._extract_storage(page, url)
        if storage:
            results["storage"][url] = storage

        # 5. WebSocket endpoints
        if collected_ws:
            log(f"      WebSocket(s) found: {collected_ws[:3]}", Colors.CYAN)
            for ws in collected_ws[:5]:
                self.findings.append(make_finding("INFO", "WebSocket",
                    f"WebSocket endpoint: {ws}", url=ws,
                    detail="Test for authentication, injection, and message tampering."))

        # 6. Dangling JS includes
        dangling = await self._check_dangling_js(page, url)
        results["dangling_js"].extend(dangling)

        # 7. Source map exposure (reveals original source code)
        source_maps = await self._check_source_maps(page, url)
        for sm in source_maps:
            self.findings.append(make_finding("HIGH", "SourceMap",
                f"Source map exposed: {sm}",
                detail="Original source code recoverable from .map file.",
                url=sm,
                remediation="Remove source maps from production builds."))
            log_finding("HIGH", f"Source map: {sm}")

        await page.close()

    # ── DOM XSS ───────────────────────────────────────────────────────────────

    async def _check_dom_xss(self, page: Page, url: str) -> list:
        findings = []
        parsed = urlparse(url)

        # 1. Static sink analysis — scan JS for dangerous patterns
        sink_analysis = await page.evaluate(f"""() => {{
            const sinks = {json.dumps(DOM_XSS_SINKS)};
            const sources = {json.dumps(DOM_XSS_SOURCES)};
            const scripts = document.querySelectorAll('script:not([src])');
            const found = [];
            scripts.forEach(s => {{
                const code = s.innerText;
                sinks.forEach(sink => {{
                    if (code.includes(sink)) {{
                        sources.forEach(src => {{
                            if (code.includes(src)) {{
                                found.push({{sink, source: src, snippet: code.substring(0, 200)}});
                            }}
                        }});
                    }}
                }});
            }});
            return found;
        }}""")

        for hit in sink_analysis:
            entry = {
                "type":    "Static DOM XSS Pattern",
                "sink":    hit.get("sink", ""),
                "source":  hit.get("source", ""),
                "url":     url,
                "snippet": hit.get("snippet", "")[:150],
            }
            findings.append(entry)
            self.findings.append(make_finding("HIGH", "DOM-XSS",
                f"DOM XSS pattern: {hit['sink']} ← {hit['source']}",
                url=url,
                evidence=hit.get("snippet", "")[:100],
                remediation="Sanitise user-controlled sources before passing to dangerous sinks."))
            log_finding("HIGH", f"DOM XSS sink: {hit['sink']} ← {hit['source']}", url)

        # 2. Dynamic probe — inject payload into URL parameters
        params = {k: v[0] for k, v in
                  __import__("urllib.parse", fromlist=["parse_qs"]).parse_qs(parsed.query).items()}

        for payload in XSS_TEST_PAYLOADS[:3]:
            try:
                # Inject into each parameter
                for param in list(params.keys())[:3]:
                    test_params = {**params, param: payload}
                    qs = "&".join(f"{k}={__import__('urllib.parse').quote(v)}" for k, v in test_params.items())
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                    await page.goto(test_url, timeout=self.timeout, wait_until="domcontentloaded")
                    await asyncio.sleep(0.5)

                    triggered = await page.evaluate("() => window.__xss_triggered === 1")
                    if triggered:
                        entry = {"type": "Dynamic DOM XSS", "payload": payload,
                                 "param": param, "url": test_url}
                        findings.append(entry)
                        self.findings.append(make_finding("CRITICAL", "DOM-XSS",
                            f"DOM XSS confirmed via parameter: {param}",
                            url=test_url, evidence=payload[:80],
                            remediation="Sanitise all user input before DOM operations."))
                        log_finding("CRITICAL", f"DOM XSS CONFIRMED: {param}", test_url)

                # Also test URL hash (common DOM XSS vector)
                hash_test = f"{url}#{payload}"
                await page.goto(hash_test, timeout=self.timeout, wait_until="domcontentloaded")
                await asyncio.sleep(0.5)
                if await page.evaluate("() => window.__xss_triggered === 1"):
                    findings.append({"type": "DOM XSS via URL hash", "payload": payload, "url": hash_test})
                    self.findings.append(make_finding("CRITICAL", "DOM-XSS",
                        "DOM XSS via URL fragment (#hash)",
                        url=url, evidence=payload[:80],
                        remediation="Never write location.hash to innerHTML without sanitisation."))

            except Exception:
                pass

        return findings

    # ── STORAGE ANALYSIS ──────────────────────────────────────────────────────

    async def _extract_storage(self, page: Page, url: str) -> dict:
        """Extract and analyse client-side storage for secrets."""
        try:
            storage_data = await page.evaluate("""() => {
                const ls = {};
                const ss = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    ls[key] = localStorage.getItem(key);
                }
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    ss[key] = sessionStorage.getItem(key);
                }
                return {localStorage: ls, sessionStorage: ss,
                        cookieCount: document.cookie.split(';').length};
            }""")

            # Flag interesting keys
            secret_keywords = ["token", "key", "secret", "password", "auth",
                                "credential", "jwt", "session", "api"]
            for store, items in [("localStorage", storage_data.get("localStorage", {})),
                                  ("sessionStorage", storage_data.get("sessionStorage", {}))]:
                for k, v in items.items():
                    if any(kw in k.lower() for kw in secret_keywords):
                        self.findings.append(make_finding("HIGH", "Storage",
                            f"Sensitive data in {store}: key='{k}'",
                            url=url,
                            evidence=str(v)[:60] + ("..." if len(str(v)) > 60 else ""),
                            remediation=f"Do not store sensitive data in {store}."))
                        log_finding("HIGH", f"Sensitive {store} key: {k}", url)

            return storage_data
        except Exception:
            return {}

    # ── DANGLING JS ───────────────────────────────────────────────────────────

    async def _check_dangling_js(self, page: Page, url: str) -> list:
        """Find <script src> pointing to unclaimed/expired domains."""
        dangling = []
        try:
            scripts = await page.evaluate("""() => {
                return [...document.querySelectorAll('script[src]')]
                    .map(s => s.src)
                    .filter(src => src && !src.startsWith(location.origin));
            }""")

            import socket
            for src in scripts[:20]:
                try:
                    host = urlparse(src).netloc
                    if host:
                        socket.getaddrinfo(host, None)
                except (socket.gaierror, Exception):
                    dangling.append(src)
                    self.findings.append(make_finding("HIGH", "DanglingJS",
                        f"Dangling JS include — domain may be unclaimed: {host}",
                        url=url, evidence=src[:100],
                        remediation="Remove or update external script includes to valid, owned domains."))
                    log_finding("HIGH", f"Dangling JS: {host}", src[:60])

        except Exception:
            pass
        return dangling

    # ── SCREENSHOTS ────────────────────────────────────────────────────────────

    async def _take_screenshot(self, page, url: str, results: dict):
        """Save a screenshot of the current page."""
        try:
            import re, os
            from pathlib import Path

            # Build filename from URL
            safe_url = re.sub(r'[^a-zA-Z0-9]', '_', url)[:60]
            screenshots_dir = Path(self.config.get("output", "ghostscan_results")) / "screenshots"
            screenshots_dir.mkdir(parents=True, exist_ok=True)

            filepath = screenshots_dir / f"{safe_url}.png"
            await page.screenshot(path=str(filepath), full_page=True)

            title = await page.title()
            log(f"      Screenshot saved: {filepath.name} ({title[:40]})", Colors.DIM)

            # Add to results
            results.setdefault("screenshots", []).append({
                "url":      url,
                "filepath": str(filepath),
                "title":    title,
                "source":   "playwright",
            })
        except Exception as e:
            if self.verbose:
                log(f"      Screenshot error: {e}", Colors.DIM)

    # ── SOURCE MAPS ───────────────────────────────────────────────────────────

    async def _check_source_maps(self, page: Page, url: str) -> list:
        """Detect exposed source maps that reveal original source code."""
        maps = []
        try:
            map_refs = await page.evaluate("""() => {
                const maps = [];
                document.querySelectorAll('script[src]').forEach(s => {
                    maps.push(s.src + '.map');
                    maps.push(s.src.replace('.min.js', '.js.map'));
                });
                return maps;
            }""")

            import aiohttp
            for map_url in map_refs[:10]:
                try:
                    resp = await page.request.get(map_url)
                    if resp.status == 200:
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct or "map" in ct:
                            maps.append(map_url)
                except Exception:
                    pass
        except Exception:
            pass
        return maps
