#!/usr/bin/env python3
"""
GhostScan Plugin — Sensitive File Detector v2
Confidence-scored with exploitability, business impact, and file-type context.
"""

from plugins.base import GhostScanPlugin
from urllib.parse import urlparse


class SensitiveFilePlugin(GhostScanPlugin):
    name           = "Sensitive File Detector"
    version        = "2.0.0"
    author         = "GhostScan"
    description    = "Detects backup files, configs, secrets, and source exposure with scoring"
    requires       = ["web_analysis"]
    tags           = ["web", "files", "disclosure", "recon"]
    severity       = "high"
    enabled        = True
    stealth        = True
    min_confidence = 0.4
    max_findings   = 40

    # (pattern, severity, confidence, impact, description, remediation)
    FILE_PATTERNS = [
        # ── Credentials / secrets ─────────────────────────────────────────────
        (".env",          "critical", 0.95, 10.0,
         "Environment file — database creds, API keys, secrets",
         "Deny access in web server config. Use: location ~ /\\. { deny all; }"),
        (".env.local",    "critical", 0.95, 10.0,
         "Local env file — often contains real production secrets",
         "Remove .env files from web root entirely"),
        (".env.production","critical",0.97, 10.0,
         "Production environment file",
         "Never store .env files in web-accessible directories"),
        (".env.staging",  "high",    0.90,  8.0,
         "Staging environment file — may share production credentials",
         "Remove and rotate any exposed credentials"),
        ("wp-config.php", "critical", 0.97, 10.0,
         "WordPress config — database host, name, username, password, secret keys",
         "Move wp-config.php one directory above web root"),
        ("config.php",    "high",    0.80,  8.0,
         "PHP config — may contain database credentials or API keys",
         "Move config files outside web root"),
        ("settings.py",   "high",    0.78,  8.0,
         "Django settings — SECRET_KEY, DB config, DEBUG flag",
         "Use environment variables for secrets. Set DEBUG=False in production"),
        ("database.yml",  "high",    0.82,  8.0,
         "Rails database config — credentials in plaintext",
         "Move outside web root. Use environment variables"),
        ("secrets.yml",   "critical", 0.90, 9.0,
         "Rails secrets file",
         "Add to .gitignore. Move outside web root"),
        ("application.yml","high",   0.75,  7.5,
         "Spring application config — may contain DB/cloud credentials",
         "Use Spring vault or environment variables for secrets"),
        (".htpasswd",     "high",    0.90,  7.0,
         "Apache password file — password hashes accessible",
         "Move .htpasswd outside web root"),

        # ── Source code exposure ─────────────────────────────────────────────
        (".git/HEAD",     "critical", 0.99, 9.5,
         "Git repository exposed — full source code downloadable",
         "Block /.git/ in web server. Run: git rm -r --cached .git"),
        (".git/config",   "critical", 0.98, 9.5,
         "Git config file — remote URL, credentials may be embedded",
         "Block /.git/ completely. Check for hardcoded credentials"),
        (".svn/entries",  "high",    0.90,  8.5,
         "SVN repository exposed",
         "Block /.svn/ in web server config"),
        (".hg/hgrc",      "high",    0.88,  8.0,
         "Mercurial repository exposed",
         "Block /.hg/ in web server config"),

        # ── Database / backup ─────────────────────────────────────────────────
        ("dump.sql",      "critical", 0.95, 10.0,
         "SQL dump — full database content publicly accessible",
         "Remove immediately. Restrict backup directory access"),
        ("backup.sql",    "critical", 0.93, 10.0,
         "SQL backup file",
         "Store backups outside web root"),
        ("db.sql",        "critical", 0.92, 10.0,
         "Database SQL file",
         "Move to secure, non-web-accessible storage"),
        (".sql",          "high",    0.75,  8.0,
         "SQL file — potential database dump",
         "Verify content and remove from web root"),
        (".tar.gz",       "high",    0.70,  7.0,
         "Compressed archive — may contain source code or sensitive data",
         "Remove archives from web root. Store backups securely"),
        (".zip",          "high",    0.68,  7.0,
         "ZIP archive — potential source code or backup",
         "Remove from web root"),
        (".bak",          "medium",  0.72,  5.0,
         "Backup file — may contain unmodified version with credentials",
         "Remove backup files from production"),
        (".old",          "medium",  0.68,  4.5,
         "Old version of file",
         "Remove old/backup files from production"),

        # ── Debug / info pages ────────────────────────────────────────────────
        ("phpinfo.php",   "high",    0.92,  6.5,
         "PHP info page — server config, PHP version, loaded modules",
         "Delete phpinfo.php from production"),
        ("info.php",      "high",    0.88,  6.5,
         "PHP info page",
         "Delete from production immediately"),
        ("test.php",      "medium",  0.75,  4.0,
         "Test PHP file left in production",
         "Remove test files from production deployments"),
        ("debug.php",     "high",    0.82,  6.0,
         "Debug PHP file — may expose stack traces and config",
         "Remove debug scripts from production"),
        (".DS_Store",     "low",     0.90,  2.0,
         "macOS .DS_Store — reveals directory structure",
         "Add to .gitignore. Block in web server"),

        # ── Config / server ───────────────────────────────────────────────────
        ("web.config",    "high",    0.78,  7.0,
         "IIS web.config — connection strings, app settings",
         "Ensure web.config is not readable via HTTP"),
        ("server-status", "medium",  0.85,  4.0,
         "Apache server-status — live request data, client IPs",
         "Restrict with: <Location /server-status> Require ip 127.0.0.1 </Location>"),
        ("server-info",   "medium",  0.82,  3.5,
         "Apache server-info — loaded modules, config directives",
         "Restrict to localhost only"),

        # ── API specs ─────────────────────────────────────────────────────────
        ("swagger.json",  "medium",  0.90,  4.5,
         "Swagger/OpenAPI spec — full API surface documented",
         "Restrict spec access in production"),
        ("openapi.json",  "medium",  0.88,  4.5,
         "OpenAPI spec",
         "Restrict to internal/dev environments"),

        # ── Logs ──────────────────────────────────────────────────────────────
        ("access.log",    "high",    0.75,  6.0,
         "Web access log — user paths, parameters, IPs",
         "Store logs outside web root"),
        ("error.log",     "high",    0.78,  6.0,
         "Error log — stack traces, internal paths, SQL queries",
         "Move logs outside web root"),
    ]

    def run(self, target: str, context: dict) -> list:
        findings = []
        seen     = set()

        # Collect all known paths
        all_paths = []
        for d in context.get("dir_brute", []):
            all_paths.append((d.get("path",""), d.get("status",0), d.get("size",0)))
        for ep in context.get("endpoints", []):
            path = urlparse(ep).path
            all_paths.append((path, 200, 0))
        for ip in context.get("interesting_paths", []):
            all_paths.append((ip.get("path",""), ip.get("status",0), ip.get("size",0)))

        for path, status, size in all_paths:
            path_low = path.lower()
            if path in seen:
                continue

            for pattern, sev, conf, impact_v, desc, remed in self.FILE_PATTERNS:
                if pattern.lower() not in path_low:
                    continue

                seen.add(path)
                url = f"https://{target}{path}"

                # Boost confidence and severity if file is directly accessible
                final_conf = conf
                final_sev  = sev
                if status == 200:
                    final_conf = min(0.99, conf + 0.08)
                    if sev == "medium":
                        final_sev = "high"
                    elif sev == "high":
                        final_sev = "critical"
                elif status in (301, 302):
                    final_conf = conf * 0.85  # redirect — less certain
                elif status == 403:
                    desc = f"{desc} (403 Forbidden — may be bypassable)"

                # Business context from path
                business = ""
                if size > 100_000:
                    business = f"Large file ({size//1000}KB) — likely contains substantial data"
                if "production" in path_low or "prod" in path_low:
                    business = "Production file — credentials likely valid for live systems"
                    final_sev = "critical"
                    final_conf = min(0.99, final_conf + 0.05)

                f = self.finding(
                    severity        = final_sev,
                    title           = f"Sensitive file accessible: {path}",
                    detail          = f"{desc} | HTTP {status} | {size} bytes",
                    url             = url,
                    evidence        = f"GET {path} → HTTP {status}",
                    remediation     = remed,
                    confidence      = final_conf,
                    impact          = impact_v,
                    business_context= business,
                )
                if f:
                    findings.append(f)
                break  # one finding per path

        # Backup file naming patterns not caught above
        backup_patterns = (".bak", ".old", ".orig", "~", ".save", ".swp", ".backup")
        for path, status, size in all_paths:
            if any(path.endswith(ext) for ext in backup_patterns) and path not in seen:
                seen.add(path)
                f = self.finding(
                    severity        = "medium",
                    title           = f"Backup/temp file found: {path}",
                    detail          = f"HTTP {status} | {size} bytes | Backup files may contain credentials or source code",
                    url             = f"https://{target}{path}",
                    evidence        = f"GET {path} → {status}",
                    remediation     = "Remove all backup and temporary files from production servers.",
                    confidence      = 0.72,
                    impact          = 5.0,
                )
                if f:
                    findings.append(f)

        return [f for f in findings if f]
