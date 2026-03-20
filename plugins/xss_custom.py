#!/usr/bin/env python3
"""
GhostScan Plugin — Custom XSS Checker v2
Confidence-scored, context-aware, business-impact aware.
"""

from plugins.base import GhostScanPlugin
from urllib.parse import urlparse, parse_qs


class CustomXSSPlugin(GhostScanPlugin):
    name           = "Custom XSS Checker"
    version        = "2.0.0"
    author         = "GhostScan"
    description    = "Context-aware XSS with confidence scoring and business impact"
    requires       = ["web_analysis"]
    tags           = ["web", "xss", "injection"]
    severity       = "high"
    enabled        = True
    stealth        = True
    min_confidence = 0.4
    max_findings   = 30

    HIGH_RISK_PARAMS = {
        "search", "query", "q", "s", "keyword", "term", "find",
        "message", "comment", "body", "text", "content",
        "name", "title", "description", "label",
        "redirect", "url", "next", "return", "goto", "callback",
        "output", "msg", "error", "notice", "alert", "info",
        "username", "user", "email",
    }

    HIGH_VALUE_PATHS = {
        "payment", "checkout", "cart", "billing", "invoice",
        "admin", "dashboard", "account", "profile", "settings",
        "api", "auth", "login", "oauth", "token",
        "report", "analytics", "export",
    }

    def run(self, target: str, context: dict) -> list:
        findings  = []
        endpoints = context.get("endpoints", [])
        forms     = context.get("forms", [])
        mode      = context.get("config", {}).get("mode", "standard")

        # Analyse URL parameters
        for url in endpoints:
            if "?" not in url:
                continue
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            path   = parsed.path.lower()

            for param in params:
                param_lower = param.lower()
                if param_lower not in self.HIGH_RISK_PARAMS:
                    continue

                # Confidence from param name
                if param_lower in ("redirect", "url", "next", "return", "goto", "callback"):
                    confidence, sev = 0.75, "high"
                    detail = f"Redirect/URL parameter `{param}` — open redirect + XSS vector"
                elif param_lower in ("search", "query", "q", "s", "keyword"):
                    confidence, sev = 0.65, "medium"
                    detail = f"Search parameter `{param}` likely reflected in page"
                else:
                    confidence, sev = 0.55, "medium"
                    detail = f"Parameter `{param}` commonly associated with reflected XSS"

                # Business impact boost
                business = ""
                hit_paths = [kw for kw in self.HIGH_VALUE_PATHS if kw in path]
                if hit_paths:
                    business   = f"High-value path ({', '.join(hit_paths)})"
                    confidence = min(0.95, confidence + 0.15)
                    if "payment" in hit_paths or "checkout" in hit_paths:
                        sev      = "critical"
                        business += " — XSS here impacts payment flow (PCI scope)"

                # Exploitability factor (pre-auth = higher impact)
                requires_auth = any(kw in url.lower() for kw in ["token=", "session=", "auth="])
                impact_val    = 8.0 if not requires_auth else 5.0
                expl_note     = "No auth required" if not requires_auth else "Auth required"

                f = self.finding(
                    severity        = sev,
                    title           = f"XSS-prone parameter `{param}` at {parsed.path}",
                    detail          = f"{detail}. {expl_note}.",
                    url             = url,
                    evidence        = f"{url[:100]}",
                    remediation     = (
                        "Encode output with htmlspecialchars(). "
                        "Implement CSP: script-src 'self' 'nonce-{RANDOM}'. "
                        "Validate redirect URLs against an allowlist."
                    ),
                    confidence      = confidence,
                    impact          = impact_val,
                    business_context= business,
                )
                if f:
                    findings.append(f)

        # Analyse forms
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            path   = urlparse(action).path.lower() if action else ""

            risky = [
                i for i in form.get("inputs", [])
                if i.get("type", "text").lower() in ("text", "search", "textarea", "email")
                and i.get("name", "").lower() in self.HIGH_RISK_PARAMS
            ]
            if not risky:
                continue

            confidence = 0.60
            business   = ""
            hit_paths  = [kw for kw in self.HIGH_VALUE_PATHS if kw in path]
            if hit_paths:
                business   = f"High-value form: {', '.join(hit_paths)}"
                confidence = 0.75

            sev   = "high" if method == "POST" else "medium"
            title = (f"POST form may store unsanitised input → Stored XSS"
                     if method == "POST"
                     else f"Form input `{risky[0].get('name','')}` — reflected XSS possible")
            if method == "POST":
                confidence = min(0.90, confidence + 0.10)

            f = self.finding(
                severity        = sev,
                title           = title,
                detail          = f"{len(risky)} risky input(s) at {action}",
                url             = action,
                evidence        = f"Fields: {[i.get('name') for i in risky]}",
                remediation     = "Sanitise all inputs before storage/rendering. Apply CSP.",
                confidence      = confidence,
                impact          = 7.0,
                business_context= business,
            )
            if f:
                findings.append(f)

        # Flag if browser scan would help
        if context.get("js_files") and not context.get("config", {}).get("browser"):
            f = self.finding(
                severity    = "info",
                title       = f"{len(context['js_files'])} JS file(s) not analysed for DOM XSS",
                detail      = "Run with --browser to detect DOM XSS via Playwright.",
                remediation = "ghostscan -t TARGET --web --browser",
                confidence  = 0.9,
                impact      = 3.0,
            )
            if f:
                findings.append(f)

        return [f for f in findings if f]
