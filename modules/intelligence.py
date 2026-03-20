#!/usr/bin/env python3
"""
GhostScan - Intelligence Engine v3
Full scoring pipeline:
  score = (impact × 0.6) + (confidence × 0.4)
  + exploitability factor (auth required = ×0.7)
  + business impact layer (payment, admin, PII = ×1.5)
  + context multipliers (login+SQLi, secret+no_waf, etc.)

All findings carry: uuid, type, confidence, impact, exploitability, business_impact, final_score
"""

import re
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from modules.utils import log, Colors, make_finding


# ── SEVERITY TABLES ───────────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_SCORE = {
    "CRITICAL": 100,
    "HIGH":      75,
    "MEDIUM":    50,
    "LOW":       25,
    "INFO":      10,
}


def calc_score(impact: float, confidence: float,
               exploitability: float = 1.0,
               business_impact: float = 1.0) -> float:
    """
    Full scoring formula:
        base    = (impact × 0.6) + (confidence_scaled × 0.4)
        final   = base × exploitability × business_impact
    Capped at 10.0.

    confidence: 0.0–1.0 (stored as fraction, scaled to 0-10 for formula)

    Examples:
        SQLi (10, 0.90):           base=(10×0.6)+(9.0×0.4)=9.6  → CRITICAL
        XSS  (6,  0.50):           base=(6×0.6)+(5.0×0.4)=5.6   → MEDIUM
        Hdrs (3,  0.90):           base=(3×0.6)+(9.0×0.4)=5.4   → MEDIUM
        Auth-req (8, 0.80, ×0.7):  9.2×0.7=6.44                 → HIGH
        Payment  (10, 0.90, ×1.5): 9.6×1.5=10.0                 → CRITICAL
    """
    # Scale confidence from 0-1 to 0-10 for the formula
    conf_scaled = confidence * 10
    base  = (impact * 0.6) + (conf_scaled * 0.4)
    final = base * exploitability * business_impact
    return round(min(10.0, final), 2)


# Alias for convenience — score(impact, confidence) where confidence is 0-10 scale
def score(impact: float, confidence: float) -> float:
    """Shorthand: score(10, 9) = 9.6 where confidence is 0-10 scale."""
    return round((impact * 0.6) + (confidence * 0.4), 2)


def score_to_severity(s: float) -> str:
    if s >= 9.0: return "CRITICAL"
    if s >= 7.0: return "HIGH"
    if s >= 5.0: return "MEDIUM"
    if s >= 3.0: return "LOW"
    return "INFO"


# ── CONFIDENCE LEVELS (per vulnerability type) ────────────────────────────────
CONFIDENCE_LEVELS = {
    # Confirmed by tool output
    "sqli_confirmed":         0.95,
    "dom_xss_confirmed":      0.95,
    "rce_confirmed":          0.95,
    "default_creds_confirmed":0.98,
    "aws_key_validated":      0.99,
    # Strong indicator
    "env_exposed_200":        0.99,
    "git_head_exposed_200":   0.98,
    "sqli_error_based":       0.90,
    "xss_reflected":          0.60,
    "xss_stored":             0.75,
    "ssrf":                   0.65,
    "lfi":                    0.70,
    "open_redirect":          0.85,
    # Tool-detected
    "nikto_finding":          0.55,
    "nuclei_critical":        0.85,
    "nuclei_high":            0.75,
    "nuclei_medium":          0.60,
    # Header / config issues
    "missing_header":         0.99,   # definitively missing
    "weak_ssl":               0.95,
    "cookie_insecure":        0.95,
    # Port exposure
    "port_open":              0.99,
    # Subdomain / recon
    "zone_transfer":          0.99,
    "subdomain_found":        0.90,
    # Default
    "default":                0.70,
}

# ── EXPLOITABILITY FACTORS ────────────────────────────────────────────────────
EXPLOITABILITY = {
    "no_auth_required":      1.0,    # unauthenticated = fully exploitable
    "auth_required":         0.7,    # needs valid login first
    "admin_auth_required":   0.5,    # needs admin account
    "network_internal_only": 0.6,    # only reachable internally
    "requires_user_action":  0.8,    # e.g. user must click link
    "complex_exploit":       0.75,   # multi-step exploitation
    "known_poc_available":   1.2,    # public PoC = higher risk (capped at 10)
    "wormable":              1.3,    # can self-propagate
}

# ── BUSINESS IMPACT MULTIPLIERS ───────────────────────────────────────────────
BUSINESS_IMPACT = {
    # Endpoint type multipliers
    "payment":      1.5,   # /payment/, /checkout/, /billing/, /card/
    "admin":        1.4,   # /admin/, /dashboard/, /manage/
    "auth":         1.3,   # /login/, /auth/, /sso/, /oauth/
    "api":          1.2,   # /api/, /graphql/, /rest/
    "pii":          1.4,   # /user/, /profile/, /account/, /personal/
    "upload":       1.2,   # file upload endpoints
    "config":       1.3,   # /config/, /settings/, /admin/config
    "backup":       1.3,   # /backup/, /dump/, /.sql
    "health":       0.8,   # /health, /status (lower business impact)
    "static":       0.5,   # static assets (minimal impact)
    "default":      1.0,
}

# ── BASE VULN SCORES (impact, default_confidence) ────────────────────────────
VULN_BASE = {
    "sqli":              (10, 0.90),
    "rce":               (10, 0.85),
    "env_exposed":       (10, 0.99),
    "git_exposed":       (9,  0.98),
    "aws_key":           (10, 0.95),
    "xxe":               (8,  0.70),
    "ssrf":              (8,  0.65),
    "lfi":               (7,  0.70),
    "xss_reflected":     (6,  0.60),
    "xss_stored":        (8,  0.75),
    "xss_dom":           (6,  0.70),
    "open_redirect":     (4,  0.85),
    "csrf":              (5,  0.65),
    "command_injection": (10, 0.75),
    "path_traversal":    (7,  0.75),
    "idor":              (6,  0.65),
    "broken_auth":       (8,  0.55),
    "default_creds":     (9,  0.85),
    "missing_csp":       (3,  0.99),
    "missing_hsts":      (4,  0.99),
    "missing_xfo":       (3,  0.99),
    "exposed_service":   (5,  0.99),
    "smb_exposed":       (7,  0.99),
    "rdp_exposed":       (8,  0.99),
    "redis_unauth":      (9,  0.99),
    "mongodb_exposed":   (8,  0.99),
    "elasticsearch":     (8,  0.99),
    "snmp":              (5,  0.99),
    "wordpress_vuln":    (8,  0.75),
    "cve_critical":      (10, 0.80),
    "cve_high":          (7,  0.80),
    "ssl_weak":          (4,  0.99),
    "cookie_insecure":   (3,  0.99),
    "info_disclosure":   (2,  0.99),
}

# ── CONTEXT MULTIPLIERS ───────────────────────────────────────────────────────
CONTEXT_MULTIPLIERS = {
    "login_no_ratelimit":     1.35,
    "login_sqli":             1.50,
    "admin_no_auth":          1.60,
    "api_no_auth":            1.40,
    "secret_no_waf":          1.20,
    "sqli_no_csp":            1.30,
    "db_exposed_internet":    1.45,
    "smb_signing_disabled":   1.40,
    "critical_cve_confirmed": 1.55,
    "xss_no_csp":             1.25,
    "rdp_no_nla":             1.30,
}

# ── ENDPOINT PRIORITY SCORES ──────────────────────────────────────────────────
ENDPOINT_SCORES = {
    "login": 100, "signin": 100, "auth": 95, "wp-login": 95,
    "admin": 90, "administrator": 90, "dashboard": 85, "panel": 85,
    "phpmyadmin": 92, "adminer": 92, "actuator": 90, ".env": 99,
    ".git": 99, "config": 85, "backup": 90, "dump.sql": 99,
    "wp-config": 99, "api": 75, "graphql": 85, "swagger": 80,
    "upload": 80, "register": 70, "reset": 70, "xmlrpc": 85,
    "static": -50, "assets": -50, "images": -60, "fonts": -70,
}

PORT_RISK = {
    23: 90, 21: 60, 445: 85, 3389: 88, 6379: 95,
    9200: 90, 27017: 90, 5432: 70, 3306: 75, 5900: 85,
    1521: 70, 8080: 35, 8443: 35, 22: 40, 80: 25, 443: 25,
}


@dataclass
class ScoredFinding:
    """Finding with full scoring metadata."""
    id:               str
    title:            str
    severity:         str
    impact:           float
    confidence:       float
    exploitability:   float
    business_impact:  float
    raw_score:        float
    final_score:      float
    category:         str  = ""
    url:              str  = ""
    detail:           str  = ""
    evidence:         str  = ""
    remediation:      str  = ""
    context_boost:    str  = ""
    vuln_type:        str  = ""

    def to_finding(self) -> dict:
        f = make_finding(
            self.severity, self.category, self.title,
            detail=(f"{self.detail} "
                    f"[Score:{self.final_score:.1f} Impact:{self.impact:.0f} "
                    f"Confidence:{self.confidence:.0%} Exploitability:{self.exploitability:.1f}]"),
            url=self.url, evidence=self.evidence, remediation=self.remediation,
        )
        f.update({
            "id":              self.id,
            "impact":          self.impact,
            "confidence":      self.confidence,
            "exploitability":  self.exploitability,
            "business_impact": self.business_impact,
            "raw_score":       self.raw_score,
            "final_score":     self.final_score,
            "context_boost":   self.context_boost,
            "vuln_type":       self.vuln_type,
        })
        return f


@dataclass
class CorrelatedFinding:
    """Compound finding from correlation engine."""
    title:         str
    severity:      str
    score:         float
    components:    List[Dict] = field(default_factory=list)
    description:   str = ""
    attack_path:   str = ""
    remediation:   str = ""
    category:      str = "Correlation"
    url:           str = ""
    multiplier:    float = 1.0
    reason:        str = ""

    def to_finding(self) -> dict:
        f = make_finding(
            self.severity, self.category, self.title,
            detail=f"{self.description} [Correlation score: {self.score:.1f}/10]",
            url=self.url, remediation=self.remediation,
        )
        f.update({
            "id":         str(uuid.uuid4()),
            "score":      self.score,
            "multiplier": self.multiplier,
            "attack_path": self.attack_path,
        })
        return f


@dataclass
class RankedTarget:
    url:      str
    score:    float
    reasons:  List[str] = field(default_factory=list)
    priority: str       = "LOW"
    def __lt__(self, other): return self.score > other.score


class IntelligenceEngine:
    """
    Intelligence engine v3:
    - score = (impact × 0.6) + (confidence × 0.4) × exploitability × business_impact
    - Context-aware severity upgrades
    - Correlation engine with multipliers
    - Smart target ranking
    - Business impact layer
    """

    def __init__(self, config: dict):
        self.config       = config
        self.min_severity = config.get("min_severity", "INFO")
        self._min_score   = SEVERITY_SCORE.get(self.min_severity.upper(), 0)
        self.verbose      = config.get("verbose", False)
        self._target      = config.get("target", "")

    # ── MAIN ENTRY ────────────────────────────────────────────────────────────

    def analyse(self, results: dict) -> dict:
        recon = results.get("recon", {})
        web   = results.get("web", {})
        vuln  = results.get("vuln", {})

        raw          = self._collect(results)
        scored       = self._score_all(raw, web, vuln)
        correlations = self._correlate(recon, web, vuln, raw)
        ranked       = self._rank(web, recon)
        all_findings = self._deduplicate(
            [s.to_finding() for s in scored] +
            [c.to_finding() for c in correlations]
        )
        filtered     = self._filter(all_findings)
        recs         = self._recommendations(recon, web, vuln, correlations)

        results["intelligence"] = {
            "scored_findings":  [self._sdict(s) for s in scored],
            "correlations":     [c.__dict__ for c in correlations],
            "ranked_targets":   [r.__dict__ for r in ranked[:30]],
            "deduped_findings": filtered,
            "recommendations":  recs,
            "stats": {
                "total_raw":      len(raw),
                "scored":         len(scored),
                "correlations":   len(correlations),
                "after_dedup":    len(all_findings),
                "after_filter":   len(filtered),
                "attack_surface": len(ranked),
            },
        }
        return results

    # ── SCORING ENGINE ────────────────────────────────────────────────────────

    def _score_all(self, findings: list, web: dict, vuln: dict) -> List[ScoredFinding]:
        login_paths  = self._login_paths(web)
        has_sqli     = bool(vuln.get("sqli_findings"))
        waf_active   = web.get("waf", {}).get("detected", False)
        missing      = web.get("header_audit", {}).get("missing", {})
        missing_csp  = "Content-Security-Policy" in missing

        scored = []
        for f in findings:
            title  = f.get("title", "").lower()
            cat    = f.get("category", "").lower()
            url    = f.get("url", "").lower()
            sev    = f.get("severity", "INFO").upper()

            vuln_type  = self._classify(title, cat)
            imp, conf  = VULN_BASE.get(vuln_type, (5, CONFIDENCE_LEVELS["default"]))
            exploit    = self._exploitability(url, sev)
            biz        = self._business_impact(url)
            base       = calc_score(imp, conf)
            final      = calc_score(imp, conf, exploit, biz)

            # Context boosts
            boost_reason = ""
            if ("sqli" in vuln_type) and login_paths:
                final = min(10.0, final * CONTEXT_MULTIPLIERS["login_sqli"])
                boost_reason = "SQLi on auth endpoint"
            if ("secret" in cat or "aws" in title) and not waf_active:
                final = min(10.0, final * CONTEXT_MULTIPLIERS["secret_no_waf"])
                boost_reason += " | no WAF protection"
            if "xss" in vuln_type and missing_csp:
                final = min(10.0, final * CONTEXT_MULTIPLIERS["xss_no_csp"])
                boost_reason += " | no CSP"
            if "admin" in url and not any(x in url for x in ["login", "auth"]):
                final = min(10.0, final * CONTEXT_MULTIPLIERS["admin_no_auth"])
                boost_reason += " | admin path"

            final_sev = score_to_severity(final)
            if sev == "CRITICAL":
                final_sev = "CRITICAL"  # never downgrade

            scored.append(ScoredFinding(
                id=str(uuid.uuid4()),
                title=f.get("title", ""),
                severity=final_sev,
                impact=imp,
                confidence=conf,
                exploitability=exploit,
                business_impact=biz,
                raw_score=base,
                final_score=round(final, 2),
                category=f.get("category", ""),
                url=f.get("url", ""),
                detail=f.get("detail", ""),
                evidence=f.get("evidence", ""),
                remediation=f.get("remediation", ""),
                context_boost=boost_reason.strip(" |"),
                vuln_type=vuln_type,
            ))

        return sorted(scored, key=lambda s: s.final_score, reverse=True)

    def _exploitability(self, url: str, severity: str) -> float:
        """Determine exploitability factor from URL and context."""
        # Public API / login = no auth required
        if any(k in url for k in ["/api/", "/login", "/auth", "/public"]):
            return EXPLOITABILITY["no_auth_required"]
        # Admin requires auth
        if any(k in url for k in ["/admin/", "/dashboard/", "/manage/"]):
            return EXPLOITABILITY["auth_required"]
        # Default: no auth assumed
        return EXPLOITABILITY["no_auth_required"]

    def _business_impact(self, url: str) -> float:
        """Determine business impact multiplier from URL."""
        url_l = url.lower()
        for keyword, mult in sorted(BUSINESS_IMPACT.items(), key=lambda x: -x[1]):
            if keyword in url_l:
                return mult
        return BUSINESS_IMPACT["default"]

    def _classify(self, title: str, cat: str) -> str:
        """Map finding text to vuln type key."""
        text = title + cat
        patterns = [
            (["sqli", "sql injection"],          "sqli"),
            (["rce", "remote code execution"],   "rce"),
            (["aws", "access key"],              "aws_key"),
            ([r"\.env", "env file"],             "env_exposed"),
            ([r"\.git", "git repo"],             "git_exposed"),
            (["command injection"],              "command_injection"),
            (["lfi", "local file"],              "lfi"),
            (["ssrf"],                           "ssrf"),
            (["xxe"],                            "xxe"),
            (["xss reflected", "reflected xss"], "xss_reflected"),
            (["xss stored", "stored xss"],       "xss_stored"),
            (["dom xss"],                        "xss_dom"),
            (["open redirect"],                  "open_redirect"),
            (["csrf"],                           "csrf"),
            (["path traversal"],                 "path_traversal"),
            (["idor"],                           "idor"),
            (["default cred", "default pass"],   "default_creds"),
            (["content-security-policy", "csp"], "missing_csp"),
            (["strict-transport", "hsts"],       "missing_hsts"),
            (["x-frame", "clickjack"],           "missing_xfo"),
            (["smb", "samba"],                   "smb_exposed"),
            (["rdp", "remote desktop"],          "rdp_exposed"),
            (["redis"],                          "redis_unauth"),
            (["mongodb", "mongo"],               "mongodb_exposed"),
            (["elasticsearch"],                  "elasticsearch"),
            (["snmp"],                           "snmp"),
            (["wordpress", "wpscan"],            "wordpress_vuln"),
            (["cve-", "log4shell", "bluekeep"],  "cve_critical"),
            (["ssl", "tls", "weak cipher"],      "ssl_weak"),
            (["cookie"],                         "cookie_insecure"),
            (["version", "disclosure", "server header"], "info_disclosure"),
        ]
        for keywords, vtype in patterns:
            if any(re.search(kw, text, re.I) for kw in keywords):
                return vtype
        return "default"

    # ── CORRELATION ENGINE ────────────────────────────────────────────────────

    def _correlate(self, recon: dict, web: dict, vuln: dict,
                   findings: list) -> List[CorrelatedFinding]:
        corrs = []

        open_ports  = {}
        for hp in recon.get("open_ports", {}).values():
            open_ports.update({int(p): info for p, info in hp.items()})
        all_ports   = set(open_ports.keys())
        tech        = web.get("technologies", {})
        endpoints   = set(web.get("endpoints", []))
        js_secrets  = web.get("js_secrets", [])
        waf         = web.get("waf", {})
        missing     = web.get("header_audit", {}).get("missing", {})
        sqli_hits   = vuln.get("sqli_findings", [])
        xss_hits    = vuln.get("xss_findings", [])
        cve_hits    = vuln.get("cve_findings", [])
        login_paths = self._login_paths(web)
        api_paths   = [e for e in endpoints if any(k in e.lower() for k in ["/api/","/v1/","/v2/","/graphql"])]
        waf_active  = waf.get("detected", False)
        missing_csp = "Content-Security-Policy" in missing

        # 1. Login + No Rate Limit
        if login_paths:
            conf = 0.90
            biz  = BUSINESS_IMPACT["auth"]
            s    = calc_score(8, conf, EXPLOITABILITY["no_auth_required"], biz) * CONTEXT_MULTIPLIERS["login_no_ratelimit"]
            corrs.append(CorrelatedFinding(
                title="Login Panel + No Rate-limit → Brute-force Ready",
                severity=score_to_severity(s), score=round(min(10, s), 2),
                components=[{"type":"endpoint","value":p} for p in login_paths[:3]],
                description=f"Login at {login_paths[0]} — no lockout detected. "
                             + ("Missing CSP amplifies credential phishing." if missing_csp else ""),
                attack_path="Enumerate usernames → spray passwords (Hydra) → session access",
                remediation="Implement account lockout, CAPTCHA, rate limiting, and MFA.",
                url=login_paths[0],
                multiplier=CONTEXT_MULTIPLIERS["login_no_ratelimit"],
                reason="Login endpoint + no rate limiting",
            ))

        # 2. Login + SQLi → Auth Bypass
        if login_paths and sqli_hits:
            s = calc_score(10, 0.90, 1.0, BUSINESS_IMPACT["auth"]) * CONTEXT_MULTIPLIERS["login_sqli"]
            corrs.append(CorrelatedFinding(
                title="SQLi on Auth Endpoint → Auth Bypass + Full DB Dump",
                severity="CRITICAL", score=min(10.0, round(s, 2)),
                description=f"SQLi confirmed in {len(sqli_hits)} parameter(s) at auth endpoint. "
                             f"Auth bypass payload: admin'--",
                attack_path="SQLi auth bypass → admin access → --dump DB → crack hashes → RCE via plugin upload",
                remediation="Parameterised queries. Validate all inputs. Separate auth from data queries.",
                multiplier=CONTEXT_MULTIPLIERS["login_sqli"],
                reason="SQLi + authentication endpoint",
            ))

        # 3. API + No Auth
        if api_paths:
            swagger = any("swagger" in e.lower() or "openapi" in e.lower() for e in endpoints)
            biz     = BUSINESS_IMPACT["api"]
            s       = calc_score(8, 0.80, 1.0, biz) * CONTEXT_MULTIPLIERS["api_no_auth"]
            if swagger: s = min(10.0, s * 1.15)
            corrs.append(CorrelatedFinding(
                title=f"Unauthenticated API ({len(api_paths)} endpoints)"
                       + (" + Swagger Exposed" if swagger else ""),
                severity=score_to_severity(s), score=round(min(10, s), 2),
                components=[{"type":"endpoint","value":p} for p in api_paths[:5]],
                description=f"{len(api_paths)} API endpoints reachable without auth. "
                             + ("Swagger spec exposes full surface." if swagger else ""),
                attack_path="Read API spec → test unauthenticated endpoints → IDOR → data exfil",
                remediation="Enforce auth on all routes. Rate-limit API. Restrict spec access.",
                url=api_paths[0], multiplier=CONTEXT_MULTIPLIERS["api_no_auth"],
                reason="API endpoints + no authentication",
            ))

        # 4. Secrets in JS
        if js_secrets:
            biz = BUSINESS_IMPACT["config"]
            s   = calc_score(10, 0.95, 1.0, biz) * (1.0 if waf_active else CONTEXT_MULTIPLIERS["secret_no_waf"])
            corrs.append(CorrelatedFinding(
                title=f"{len(js_secrets)} Secret(s) Hardcoded in JavaScript",
                severity="CRITICAL", score=round(min(10.0, s), 2),
                components=[{"type":"secret","value":x.get("type","")} for x in js_secrets[:5]],
                description=f"Types: {', '.join(x.get('type','') for x in js_secrets[:3])}. "
                             + ("No WAF — directly accessible." if not waf_active else ""),
                attack_path="Download JS → grep for keys → direct cloud/API access",
                remediation="Remove all secrets from client-side code. Rotate exposed keys NOW.",
                url=js_secrets[0].get("url",""),
                multiplier=1.0 if waf_active else CONTEXT_MULTIPLIERS["secret_no_waf"],
            ))

        # 5. Database ports exposed
        db_ports = {p: i for p, i in open_ports.items() if p in (3306,5432,1433,27017,6379,9200)}
        for port, info in db_ports.items():
            svc = info.get("service","db")
            ver = f"{info.get('product','')} {info.get('version','')}".strip()
            imp = 9 if port in (6379,9200,27017) else 7
            s   = calc_score(imp, 0.99) * CONTEXT_MULTIPLIERS["db_exposed_internet"]
            corrs.append(CorrelatedFinding(
                title=f"Database Exposed — {svc.upper()} {ver} on :{port}",
                severity="CRITICAL" if s >= 9 else "HIGH", score=round(min(10, s), 2),
                description=f"{svc} accessible from network. "
                             + ("No auth by default." if port in (6379,27017,9200) else "Brute-force viable."),
                attack_path=f"Connect → authenticate (empty creds) → data dump / RCE",
                remediation=f"Firewall port {port}. Enable authentication.",
                multiplier=CONTEXT_MULTIPLIERS["db_exposed_internet"],
            ))

        # 6. SMB exposed ± signing disabled
        if 445 in all_ports or 139 in all_ports:
            signing_disabled = "disabled" in str(open_ports.get(445,{}).get("scripts",{})
                                                  .get("smb2-security-mode","")).lower()
            mult = CONTEXT_MULTIPLIERS["smb_signing_disabled"] if signing_disabled else 1.0
            s    = calc_score(7 if signing_disabled else 6, 0.99) * mult
            corrs.append(CorrelatedFinding(
                title="SMB Exposed" + (" — Signing Disabled (NTLM Relay)" if signing_disabled else ""),
                severity="CRITICAL" if signing_disabled else "HIGH",
                score=round(min(10, s), 2),
                description="SMB reachable from network. "
                             + ("Signing disabled — NTLM relay attack is trivial." if signing_disabled else ""),
                attack_path="Responder → capture Net-NTLMv2 → relay to SMB (no cracking needed)",
                remediation="Enforce SMB signing via GPO. Restrict SMB to internal networks.",
                multiplier=mult,
            ))

        # 7. XSS + no CSP
        if xss_hits and missing_csp:
            s = calc_score(6, 0.65) * CONTEXT_MULTIPLIERS["xss_no_csp"]
            corrs.append(CorrelatedFinding(
                title=f"XSS ({len(xss_hits)} location(s)) + No Content-Security-Policy",
                severity=score_to_severity(s), score=round(s, 2),
                description="XSS confirmed without CSP — cookies and credentials fully exposed.",
                attack_path="XSS payload → steal session cookies → account takeover",
                remediation="Fix injection points. Add strict CSP with nonces.",
                multiplier=CONTEXT_MULTIPLIERS["xss_no_csp"],
            ))

        # 8. CVE matches with exploitability boost
        for cve in cve_hits:
            sev  = cve.get("severity","HIGH")
            mult = CONTEXT_MULTIPLIERS["critical_cve_confirmed"] if sev == "CRITICAL" else 1.2
            imp  = 10 if sev == "CRITICAL" else 7
            s    = calc_score(imp, 0.80) * mult
            # Check for public PoC (boost exploitability)
            if sev == "CRITICAL":
                s = min(10.0, s * EXPLOITABILITY["known_poc_available"])
            corrs.append(CorrelatedFinding(
                title=f"Exploitable Version: {cve.get('title','')}",
                severity=sev, score=round(min(10, s), 2),
                description=f"CVE: {cve.get('cve','')} — matched on: {cve.get('matched','')}",
                attack_path="searchsploit / GitHub PoC → exploit → system access",
                remediation=f"Apply patch for {cve.get('cve','')}. Check NVD for details.",
                category="CVE", multiplier=mult,
                reason="Public PoC likely available for CRITICAL CVEs",
            ))

        return sorted(corrs, key=lambda c: c.score, reverse=True)

    # ── TARGET RANKING ────────────────────────────────────────────────────────

    def _rank(self, web: dict, recon: dict) -> List[RankedTarget]:
        ranked = []
        seen   = set()
        base_urls = web.get("base_urls", [f"https://{self._target}"])
        base = base_urls[0].rstrip("/") if base_urls else ""

        for url in set(web.get("endpoints", [])):
            if url in seen: continue
            seen.add(url)
            s, reasons = self._endpoint_score(url)
            if s < 0: continue
            ranked.append(RankedTarget(url=url, score=s, reasons=reasons[:4],
                priority="CRITICAL" if s>=95 else "HIGH" if s>=70 else "MEDIUM" if s>=40 else "LOW"))

        for d in web.get("dir_brute", []):
            url = base + d.get("path","")
            if url in seen: continue
            seen.add(url)
            s, reasons = self._endpoint_score(url)
            if d.get("status") == 200: s += 20; reasons.append("HTTP 200")
            if s < 0: continue
            ranked.append(RankedTarget(url=url, score=s, reasons=reasons[:4],
                priority="CRITICAL" if s>=95 else "HIGH" if s>=70 else "MEDIUM" if s>=40 else "LOW"))

        for host, host_ports in recon.get("open_ports", {}).items():
            for port, info in host_ports.items():
                p = int(port)
                r = PORT_RISK.get(p, 20)
                ranked.append(RankedTarget(url=f"{host}:{p}", score=r,
                    reasons=[info.get("service",""), f"port {p}"],
                    priority="CRITICAL" if r>=85 else "HIGH" if r>=65 else "MEDIUM"))

        ranked.sort()
        return ranked

    def _endpoint_score(self, url: str):
        sc = 0; reasons = []
        ul = url.lower()
        for kw, pts in ENDPOINT_SCORES.items():
            if kw in ul:
                sc += pts
                if pts > 0: reasons.append(kw)
        return sc, reasons

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _collect(self, results: dict) -> list:
        all_f = []; seen = set()
        for section in ["recon","web","vuln"]:
            for f in results.get(section, {}).get("findings", []):
                key = f"{f.get('severity')}{f.get('title')}{f.get('url')}"
                if key not in seen:
                    seen.add(key); all_f.append(f)
        return all_f

    def _login_paths(self, web: dict) -> list:
        kws = ["login","signin","wp-login","auth","dashboard","sign-in"]
        found = []
        for ep in web.get("endpoints", []):
            if any(k in ep.lower() for k in kws): found.append(ep)
        for d in web.get("dir_brute", []):
            p = d.get("path","")
            if any(k in p.lower() for k in kws) and d.get("status") in (200,302):
                found.append(f"https://{self._target}{p}")
        return found[:5]

    def _deduplicate(self, findings: list) -> list:
        best: Dict[str, dict] = {}
        for f in findings:
            key = re.sub(r'\s+', ' ',
                f"{f.get('category','')}{f.get('title','')}{f.get('url','')}".lower().strip())
            ex = best.get(key)
            if not ex or (SEVERITY_SCORE.get(f.get("severity","INFO").upper(), 0) >
                          SEVERITY_SCORE.get(ex.get("severity","INFO").upper(), 0)):
                best[key] = f
        return list(best.values())

    def _filter(self, findings: list) -> list:
        return [f for f in findings
                if SEVERITY_SCORE.get(f.get("severity","INFO").upper(), 0) >= self._min_score]

    def _recommendations(self, recon: dict, web: dict, vuln: dict,
                          correlations: list) -> list:
        recs  = []
        ports = set()
        for hp in recon.get("open_ports", {}).values():
            ports.update(int(p) for p in hp.keys())
        tech    = web.get("technologies", {})
        secrets = web.get("js_secrets", [])
        sqli    = vuln.get("sqli_findings", [])
        xss     = vuln.get("xss_findings", [])
        cves    = vuln.get("cve_findings", [])
        base    = f"https://{self._target}"

        if secrets:
            recs.append({"priority":1,"severity":"CRITICAL",
                "action":"IMMEDIATE — Rotate ALL exposed secrets found in JavaScript",
                "command":"aws iam delete-access-key --access-key-id <KEY_ID>"})
        if sqli:
            recs.append({"priority":2,"severity":"CRITICAL",
                "action":"Exploit confirmed SQLi — extract DB schema and credentials",
                "command":f"sqlmap -u '{base}?id=1' --level=5 --risk=3 --batch --dbs --dump"})
        for cve in cves:
            if cve.get("severity") == "CRITICAL":
                recs.append({"priority":3,"severity":"CRITICAL",
                    "action":f"Exploit PoC: {cve.get('title','')}",
                    "command":f"searchsploit {cve.get('cve','')} && nuclei -u {base} -tags {cve.get('cve','').lower()}"})
        if 6379 in ports:
            recs.append({"priority":4,"severity":"CRITICAL",
                "action":"Test Redis unauthenticated → RCE via cron",
                "command":f"redis-cli -h {self._target} ping && redis-cli -h {self._target} info server"})
        if any("wordpress" in c.lower() for c in tech.get("cms",[])):
            recs.append({"priority":5,"severity":"HIGH",
                "action":"WordPress deep scan — vulnerable plugins + brute-force",
                "command":f"wpscan --url {base} --enumerate vp,vt,u,cb,dbe --plugins-detection aggressive"})
        if xss:
            recs.append({"priority":6,"severity":"HIGH",
                "action":"Escalate XSS to blind/stored via XSS Hunter",
                "command":f"xsstrike -u '{base}?q=test' --crawl --fuzzer --blind"})
        if 445 in ports:
            recs.append({"priority":7,"severity":"HIGH",
                "action":"SMB full enumeration — null sessions, users, password policy",
                "command":f"enum4linux-ng -A {self._target} && crackmapexec smb {self._target} --shares --users"})
        recs.sort(key=lambda r: r["priority"])
        return recs

    def _sdict(self, s: ScoredFinding) -> dict:
        return {"id": s.id, "title": s.title, "severity": s.severity,
                "impact": s.impact, "confidence": s.confidence,
                "exploitability": s.exploitability, "business_impact": s.business_impact,
                "raw_score": s.raw_score, "final_score": s.final_score,
                "context_boost": s.context_boost, "vuln_type": s.vuln_type,
                "url": s.url, "category": s.category}

    # ── PRINTERS ──────────────────────────────────────────────────────────────

    def print_ranked_targets(self, results: dict):
        ranked = results.get("intelligence", {}).get("ranked_targets", [])
        if not ranked: return
        log("\n  ┌─ Attack Surface Ranking ──────────────────────────", Colors.BOLD_CYAN)
        log("  │  Scored: impact × confidence × exploitability × business_impact", Colors.DIM)
        colors = {"CRITICAL": Colors.BOLD_RED, "HIGH": Colors.RED,
                  "MEDIUM": Colors.YELLOW, "LOW": Colors.DIM}
        for i, t in enumerate(ranked[:15], 1):
            col = colors.get(t.get("priority","LOW"), Colors.DIM)
            log(f"  │  {i:>2}. {col}[{t['priority']}]{Colors.RESET} {t['url'][:65]}", Colors.RESET)
            why = ", ".join(t.get("reasons",[])[:3])
            if why: log(f"  │      {Colors.DIM}↳ score={t['score']} | {why}{Colors.RESET}", Colors.DIM)
        log("  └───────────────────────────────────────────────────", Colors.BOLD_CYAN)

    def print_recommendations(self, results: dict):
        recs = results.get("intelligence", {}).get("recommendations", [])
        if not recs: return
        log("\n  ┌─ Prioritised Next Steps ───────────────────────────", Colors.BOLD_CYAN)
        colors = {"CRITICAL": Colors.BOLD_RED, "HIGH": Colors.RED, "MEDIUM": Colors.YELLOW}
        for r in recs[:8]:
            col = colors.get(r.get("severity","MEDIUM"), Colors.DIM)
            log(f"  │  {col}[{r['severity']}]{Colors.RESET} {r['action']}", Colors.RESET)
            if r.get("command"):
                log(f"  │      {Colors.DIM}$ {r['command'][:88]}{Colors.RESET}", Colors.DIM)
        log("  └───────────────────────────────────────────────────", Colors.BOLD_CYAN)

    def print_score_table(self, results: dict):
        scored = results.get("intelligence", {}).get("scored_findings", [])
        if not scored: return
        log("\n  ┌─ Scored Findings ── score=(imp×0.6)+(conf×0.4)×exploit×biz ─", Colors.BOLD_CYAN)
        log("  │  Finding                                  Imp  Conf   Expl  Score", Colors.DIM)
        log("  │  " + "─"*60, Colors.DIM)
        colors = {"CRITICAL":Colors.BOLD_RED,"HIGH":Colors.RED,"MEDIUM":Colors.YELLOW,"LOW":Colors.DIM}
        for s in scored[:12]:
            col   = colors.get(s.get("severity","INFO"), Colors.DIM)
            title = s.get("title","")[:40].ljust(40)
            imp   = f"{s.get('impact',0):.0f}".rjust(3)
            conf  = f"{s.get('confidence',0):.0%}".rjust(5)
            expl  = f"×{s.get('exploitability',1):.1f}".rjust(5)
            sc    = f"{s.get('final_score',0):.1f}".rjust(5)
            boost = f"  ↑{s.get('context_boost','')[:20]}" if s.get("context_boost") else ""
            log(f"  │  {col}{title}{Colors.RESET} {imp}  {conf} {expl}  {col}{sc}{Colors.RESET}{Colors.DIM}{boost}{Colors.RESET}", Colors.RESET)
        log("  └───────────────────────────────────────────────────", Colors.BOLD_CYAN)
