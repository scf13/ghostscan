#!/usr/bin/env python3
"""
GhostScan Plugin — Admin Panel Finder v2
Identifies privileged endpoints with business context and exploitability scoring.
"""

from plugins.base import GhostScanPlugin
from urllib.parse import urlparse


class AdminFinderPlugin(GhostScanPlugin):
    name           = "Admin Panel Finder"
    version        = "2.0.0"
    author         = "GhostScan"
    description    = "Finds admin, CI/CD, and management interfaces with exploitability scoring"
    requires       = ["web_analysis"]
    tags           = ["web", "auth", "admin", "recon"]
    severity       = "high"
    enabled        = True
    stealth        = True
    min_confidence = 0.5
    max_findings   = 20

    # (keyword, severity, confidence, description, business_context)
    ADMIN_SIGNATURES = [
        # Database admin
        ("phpmyadmin",    "critical", 0.95, "phpMyAdmin — direct DB access",
         "Full database administration without application controls"),
        ("adminer",       "critical", 0.95, "Adminer — DB management panel",
         "Direct database access; single-file PHP = often overlooked"),
        ("pma",           "high",     0.80, "phpMyAdmin shortpath",
         "Possible phpMyAdmin instance"),
        # Application admin
        ("wp-admin",      "high",     0.95, "WordPress admin panel",
         "CMS control panel — theme/plugin upload = RCE vector"),
        ("wp-login",      "high",     0.90, "WordPress login",
         "Brute-force target — xmlrpc.php may also be active"),
        ("administrator", "high",     0.85, "CMS administrator panel",
         "Privileged application access"),
        ("admin",         "high",     0.75, "Generic admin panel",
         "Privileged access — test default credentials"),
        ("dashboard",     "medium",   0.65, "Dashboard interface",
         "Aggregate view — may expose sensitive metrics"),
        # DevOps / CI-CD
        ("jenkins",       "critical", 0.92, "Jenkins CI/CD",
         "Script console = direct OS command execution"),
        ("gitlab",        "high",     0.88, "GitLab instance",
         "Source code + secrets + CI pipelines"),
        ("portainer",     "critical", 0.90, "Portainer Docker UI",
         "Container management = host escape possible"),
        ("rancher",       "critical", 0.90, "Rancher Kubernetes UI",
         "K8s cluster access = full infrastructure"),
        ("grafana",       "high",     0.85, "Grafana dashboard",
         "Metrics + default admin:admin — may have plugin RCE"),
        ("kibana",        "high",     0.85, "Kibana (Elasticsearch UI)",
         "Log data + Timelion RCE in older versions"),
        # Framework consoles
        ("h2-console",    "critical", 0.95, "H2 database console",
         "JDBC H2 console = direct DB + Java RCE possible"),
        ("actuator",      "critical", 0.92, "Spring Boot Actuator",
         "/env exposes secrets, /restart = DoS, /heapdump = memory"),
        ("jolokia",       "critical", 0.90, "Jolokia JMX bridge",
         "JMX over HTTP = MBean RCE vector"),
        ("jmx-console",   "critical", 0.90, "JBoss JMX console",
         "Direct JMX = OS command execution"),
        ("web-console",   "high",     0.82, "Application web console",
         "Script execution console"),
        # Setup pages
        ("install",       "high",     0.85, "Installation page",
         "May allow re-initialisation or credential reset"),
        ("setup",         "high",     0.82, "Setup wizard",
         "Post-install setup left exposed"),
        ("upgrade",       "medium",   0.70, "Upgrade/migration script",
         "DB migration scripts should not be web-accessible"),
    ]

    def run(self, target: str, context: dict) -> list:
        findings  = []
        endpoints = context.get("endpoints", [])
        dir_brute = context.get("dir_brute", [])
        tech      = context.get("technologies", {})
        findings_seen = set()

        # Collect all known paths
        all_paths = []
        for url in endpoints:
            path = urlparse(url).path
            all_paths.append((path, url, 200))
        for d in dir_brute:
            path = d.get("path", "")
            url  = f"https://{target}{path}"
            all_paths.append((path, url, d.get("status", 0)))

        for path, url, status in all_paths:
            path_low = path.lower()
            for keyword, sev, conf, desc, biz in self.ADMIN_SIGNATURES:
                if keyword not in path_low:
                    continue
                if url in findings_seen:
                    continue
                findings_seen.add(url)

                # Boost confidence if HTTP 200 (directly accessible)
                final_conf = conf
                if status == 200:
                    final_conf = min(0.99, conf + 0.10)
                    sev_final  = "critical" if sev in ("high", "critical") else sev
                elif status == 403:
                    sev_final = sev
                    desc = f"{desc} (403 — try bypass techniques)"
                else:
                    sev_final = sev

                # Exploitability: auth bypass candidates
                bypass_hint = ""
                if status == 403:
                    bypass_hint = " | Try: X-Forwarded-For: 127.0.0.1, path normalisation, double-slash"
                if status == 200 and "auth" not in path_low and "login" not in path_low:
                    bypass_hint = " | No auth gate detected on this path"

                f = self.finding(
                    severity        = sev_final,
                    title           = f"{desc}: {path}",
                    detail          = f"HTTP {status} | {desc}.{bypass_hint}",
                    url             = url,
                    evidence        = f"GET {path} → {status}",
                    remediation     = (
                        "Restrict to trusted IPs/VPN via firewall or web server config. "
                        "Enable strong authentication + MFA. "
                        "Remove or disable if not required."
                    ),
                    confidence      = final_conf,
                    impact          = 9.5 if sev_final == "critical" else 7.0,
                    business_context= biz,
                )
                if f:
                    findings.append(f)
                break  # one finding per path

        # CMS-specific hints not yet found
        cms = [c.lower() for c in tech.get("cms", [])]
        if "wordpress" in cms:
            wp_paths = {"/wp-admin/", "/wp-login.php", "/xmlrpc.php"}
            existing = {urlparse(url).path for url, _, _ in all_paths}
            for wp in wp_paths:
                if wp not in existing:
                    f = self.finding(
                        severity    = "info",
                        title       = f"WordPress path not yet tested: {wp}",
                        detail      = "Verify manually or run with --intensity aggressive",
                        url         = f"https://{target}{wp}",
                        remediation = "Test with: curl -I https://{target}" + wp,
                        confidence  = 0.7,
                        impact      = 5.0,
                    )
                    if f:
                        findings.append(f)

        return [f for f in findings if f]
