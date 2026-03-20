#!/usr/bin/env python3
"""
GhostScan - Wordlist Manager v2
Discovers and indexes SecLists + Kali built-in wordlists.
Covers ALL categories including wordpress, fuzzing, parameters, vhosts.
Auto-generates missing wordlists from built-in data if files not found.
"""

import os
import subprocess
from pathlib import Path

# ── FULL WORDLIST DATABASE ────────────────────────────────────────────────────
WORDLIST_DB = {

    # ── SUBDOMAINS ───────────────────────────────────────────────────────────
    "subdomains": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
        "/usr/share/seclists/Discovery/DNS/namelist.txt",
        "/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt",
        "/usr/share/seclists/Discovery/DNS/combined_subdomains.txt",
        "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt",
        "/usr/share/wordlists/dnsmap.txt",
        "/usr/share/amass/wordlists/subdomains.lst",
    ],

    # ── WEB DIRECTORIES ──────────────────────────────────────────────────────
    "web_dirs": [
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt",
        "/usr/share/seclists/Discovery/Web-Content/combined_directories.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirb/big.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt",
        "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
    ],

    # ── WEB FILES ────────────────────────────────────────────────────────────
    "web_files": [
        "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
        "/usr/share/wordlists/dirb/extensions_common.txt",
    ],

    # ── API ENDPOINTS ─────────────────────────────────────────────────────────
    "api": [
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt",
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "/usr/share/seclists/Discovery/Web-Content/swagger.txt",
        "/usr/share/seclists/Discovery/Web-Content/graphql.txt",
    ],

    # ── PASSWORDS ─────────────────────────────────────────────────────────────
    "passwords": [
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/best110.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
        "/usr/share/seclists/Passwords/darkweb2017-top10000.txt",
        "/usr/share/seclists/Passwords/darkweb2017-top100.txt",
        "/usr/share/seclists/Passwords/rockyou-75.txt",
        "/usr/share/seclists/Passwords/rockyou-50.txt",
        "/usr/share/seclists/Passwords/rockyou-25.txt",
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt",
        "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt",
        "/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-50.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-25.txt",
    ],

    # ── USERNAMES ─────────────────────────────────────────────────────────────
    "usernames": [
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/seclists/Usernames/Names/names.txt",
        "/usr/share/seclists/Usernames/Names/female-names.txt",
        "/usr/share/seclists/Usernames/Names/male-names.txt",
        "/usr/share/seclists/Usernames/cirt-default-usernames.txt",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
    ],

    # ── CREDENTIALS (default creds per service) ───────────────────────────────
    "credentials": [
        "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv",
        "/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
        "/usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
        "/usr/share/seclists/Passwords/Default-Credentials/http-betterdefaultpasslist.txt",
        "/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt",
        "/usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt",
        "/usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt",
        "/usr/share/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt",
    ],

    # ── FUZZING / PAYLOADS ────────────────────────────────────────────────────
    "fuzzing": [
        "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
        "/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt",
        "/usr/share/seclists/Fuzzing/SQLi/MySQL.fuzz.txt",
        "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
        "/usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt",
        "/usr/share/seclists/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt",
        "/usr/share/seclists/Fuzzing/XSS/XSS-RSNAKE.txt",
        "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt",
        "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
        "/usr/share/seclists/Fuzzing/SSRF.txt",
        "/usr/share/seclists/Fuzzing/template-engines-special-vars.txt",
        "/usr/share/seclists/Fuzzing/special-chars.txt",
        "/usr/share/seclists/Fuzzing/command-injection-commix.txt",
        "/usr/share/seclists/Fuzzing/XXE-Fuzzing.txt",
    ],

    # ── PARAMETERS ────────────────────────────────────────────────────────────
    "parameters": [
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "/usr/share/seclists/Discovery/Web-Content/Logins/http-default-logins.txt",
        "/usr/share/seclists/Discovery/Web-Content/CGIs.txt",
        "/usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt",
    ],

    # ── VHOSTS ────────────────────────────────────────────────────────────────
    "vhosts": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/Web-Content/vhosts.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    ],

    # ── WORDPRESS ─────────────────────────────────────────────────────────────
    "wordpress": [
        "/usr/share/seclists/Discovery/Web-Content/CMS/WordPress/wp-plugins.fuzz.txt",
        "/usr/share/seclists/Discovery/Web-Content/CMS/WordPress/wp-themes.fuzz.txt",
        "/usr/share/seclists/Discovery/Web-Content/CMS/WordPress/wordpress-plugins.txt",
        "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "/usr/share/wordlists/wfuzz/webservices/ws-dirs.txt",
    ],

    # ── SNMP COMMUNITIES ──────────────────────────────────────────────────────
    "snmp": [
        "/usr/share/seclists/Discovery/SNMP/snmp.txt",
        "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
        "/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt",
        "/usr/share/wordlists/metasploit/snmp_default_pass.txt",
    ],

    # ── HASHCAT RULES ─────────────────────────────────────────────────────────
    "hashcat_rules": [
        "/usr/share/hashcat/rules/best64.rule",
        "/usr/share/hashcat/rules/rockyou-30000.rule",
        "/usr/share/hashcat/rules/d3ad0ne.rule",
        "/usr/share/hashcat/rules/dive.rule",
        "/usr/share/hashcat/rules/generated.rule",
        "/usr/share/hashcat/rules/Incisive-leetspeak.rule",
        "/usr/share/hashcat/rules/InsidePro-HashManager.rule",
        "/usr/share/hashcat/rules/InsidePro-PasswordsPro.rule",
        "/usr/share/hashcat/rules/leetspeak.rule",
        "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
        "/usr/share/hashcat/rules/oscommerce.rule",
        "/usr/share/hashcat/rules/PasswordPro.rule",
        "/usr/share/hashcat/rules/specific.rule",
        "/usr/share/hashcat/rules/T0XlC.rule",
        "/usr/share/hashcat/rules/T0XlC-insert_00-99_1950-2050_toprules_0_F.rule",
        "/usr/share/hashcat/rules/toggles1.rule",
        "/usr/share/hashcat/rules/unix-ninja-leetspeak.rule",
    ],
}

# ── BUILT-IN FALLBACK WORDLISTS ───────────────────────────────────────────────
# Used when SecLists files are not found — tool still works without SecLists

BUILTIN_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "portal", "ns", "host",
    "support", "dev", "web", "admin", "api", "cdn", "app", "staging",
    "beta", "old", "static", "img", "images", "media", "assets", "status",
    "docs", "help", "wiki", "login", "sso", "auth", "id", "intranet",
    "internal", "corp", "lb", "mysql", "db", "database", "backup",
    "monitor", "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "exchange", "owa", "autodiscover", "autoconfig", "cpanel", "whm",
    "mx", "mx1", "mx2", "imap", "pop", "pop3", "smtp2", "vps",
    "test", "demo", "sandbox", "qa", "uat", "preprod", "preview",
    "mobile", "wap", "api2", "api3", "v1", "v2", "graphql", "rest",
    "dashboard", "manage", "panel", "console", "control", "admin2",
    "cloud", "storage", "cdn2", "assets2", "files", "downloads",
]

BUILTIN_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "password1", "1234567890", "qwerty", "abc123", "111111", "iloveyou",
    "admin", "letmein", "monkey", "1234", "dragon", "master", "123123",
    "qwerty123", "princess", "welcome", "login", "passw0rd", "pass",
    "root", "toor", "test", "guest", "default", "changeme", "secret",
    "p@ssword", "p@ss123", "Admin1234", "Password123!", "Summer2024!",
    "Winter2024!", "Spring2024!", "company123", "company2024",
    "admin123", "admin@123", "root123", "test123", "pass123",
    "password123", "Password1", "P@ssword1", "Passw0rd!", "qwerty123!",
]

BUILTIN_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "info",
    "adm", "mysql", "web", "www", "email", "ftp", "oracle", "support",
    "manager", "postmaster", "hostmaster", "webmaster", "security",
    "backup", "operator", "sysadmin", "sysop", "abuse", "noc", "daemon",
    "apache", "nginx", "ubuntu", "debian", "kali", "pi", "service",
    "postgres", "mssql", "sqlserver", "tomcat", "jboss", "jenkins",
    "dev", "developer", "deploy", "git", "svn", "ansible", "puppet",
]

BUILTIN_WORDPRESS_PLUGINS = [
    "wp-content/plugins/akismet", "wp-content/plugins/jetpack",
    "wp-content/plugins/contact-form-7", "wp-content/plugins/woocommerce",
    "wp-content/plugins/yoast-seo", "wp-content/plugins/wordfence",
    "wp-content/plugins/elementor", "wp-content/plugins/wpforms-lite",
    "wp-content/plugins/classic-editor", "wp-content/plugins/really-simple-ssl",
    "wp-content/plugins/wp-super-cache", "wp-content/plugins/all-in-one-seo-pack",
    "wp-content/plugins/updraftplus", "wp-content/plugins/mailchimp-for-wp",
    "wp-content/plugins/duplicate-post", "wp-content/plugins/wp-migrate-db",
    "wp-content/plugins/timber-library", "wp-content/plugins/advanced-custom-fields",
    "wp-content/plugins/w3-total-cache", "wp-content/plugins/wp-file-manager",
]

BUILTIN_XSS_PAYLOADS = [
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
    '<body onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<script>alert(document.domain)</script>',
    '<!--<script>alert(1)</script>-->',
]

BUILTIN_SQLI_PAYLOADS = [
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
    "1; DROP TABLE users--",
    "' OR 'x'='x",
    "1' AND '1'='1",
    "' OR 1=1#",
    "1 UNION SELECT NULL,NULL,NULL--",
]

BUILTIN_LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../etc/shadow",
    "../../etc/hosts",
    "../../proc/self/environ",
    "../../var/log/apache2/access.log",
    "../../var/log/nginx/access.log",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "....//....//etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
]

BUILTIN_SNMP_COMMUNITIES = [
    "public", "private", "community", "manager", "admin",
    "snmp", "snmpd", "cisco", "default", "internal",
    "monitor", "write", "read", "secret", "password",
    "test", "guest", "backup", "network", "switch",
]

BUILTIN_PARAMETERS = [
    "id", "page", "search", "query", "q", "s", "url", "path",
    "file", "dir", "name", "user", "username", "email", "pass",
    "password", "token", "key", "api_key", "apikey", "auth",
    "redirect", "return", "next", "goto", "target", "dest",
    "action", "cmd", "exec", "command", "code", "lang", "locale",
    "callback", "jsonp", "format", "type", "cat", "category",
    "view", "template", "theme", "style", "debug", "test",
    "mode", "sort", "order", "limit", "offset", "start",
]

BUILTIN_VHOSTS = [
    "dev", "staging", "test", "admin", "api", "internal",
    "intranet", "portal", "dashboard", "app", "beta", "demo",
    "preview", "sandbox", "qa", "uat", "preprod", "old",
    "new", "v2", "mobile", "m", "secure", "mail", "smtp",
    "ftp", "vpn", "remote", "git", "gitlab", "jenkins",
    "monitor", "logs", "db", "database", "backup", "cdn",
]


class WordlistManager:
    def __init__(self, verbose: bool = False):
        self.verbose  = verbose
        self._cache   = {}
        self._tmpdir  = Path("/tmp/ghostscan_wordlists")

    # ── MAIN GET ──────────────────────────────────────────────────────────────

    def get(self, category: str, size: str = "medium") -> str:
        """
        Return path to the best available wordlist for the category.
        size: 'small' | 'medium' | 'large'
        Returns a file path string or None.
        """
        cache_key = f"{category}:{size}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        candidates = WORDLIST_DB.get(category, [])

        size_keywords = {
            "small":  ["small", "shortlist", "top-1000", "-75", "-25", "100",
                       "top-usernames", "quick", "best110"],
            "medium": ["medium", "top-100000", "20000", "common", "10000",
                       "best1050", "darkweb2017"],
            "large":  ["large", "big", "110000", "1000000", "xato", "combined",
                       "Jhaddix", "all"],
        }

        # Size-preferred first
        for path in candidates:
            if any(kw in path.lower() for kw in size_keywords.get(size, [])):
                if Path(path).exists():
                    self._cache[cache_key] = path
                    return path

        # Any available
        for path in candidates:
            if Path(path).exists():
                self._cache[cache_key] = path
                return path

        # Generate from built-in if missing
        generated = self._generate_builtin(category)
        if generated:
            self._cache[cache_key] = generated
            return generated

        self._cache[cache_key] = None
        return None

    def get_all_available(self, category: str) -> list:
        return [p for p in WORDLIST_DB.get(category, []) if Path(p).exists()]

    def get_builtin_list(self, category: str) -> list:
        mapping = {
            "subdomains":  BUILTIN_SUBDOMAINS,
            "passwords":   BUILTIN_PASSWORDS,
            "usernames":   BUILTIN_USERNAMES,
            "wordpress":   BUILTIN_WORDPRESS_PLUGINS,
            "fuzzing":     BUILTIN_XSS_PAYLOADS + BUILTIN_SQLI_PAYLOADS,
            "parameters":  BUILTIN_PARAMETERS,
            "vhosts":      BUILTIN_VHOSTS,
            "snmp":        BUILTIN_SNMP_COMMUNITIES,
            "xss":         BUILTIN_XSS_PAYLOADS,
            "sqli":        BUILTIN_SQLI_PAYLOADS,
            "lfi":         BUILTIN_LFI_PAYLOADS,
        }
        return mapping.get(category, [])

    def get_or_builtin(self, category: str, size: str = "medium"):
        """Return (path, 'file') or (list, 'builtin')."""
        path = self.get(category, size)
        if path:
            return path, "file"
        return self.get_builtin_list(category), "builtin"

    def get_xss_payloads(self) -> str:
        """Return path to XSS payload file (generate if needed)."""
        for p in [
            "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
            "/usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt",
            "/usr/share/seclists/Fuzzing/XSS/XSS-RSNAKE.txt",
        ]:
            if Path(p).exists():
                return p
        return self._generate_builtin("xss")

    def get_sqli_payloads(self) -> str:
        """Return path to SQLi payload file (generate if needed)."""
        for p in [
            "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
            "/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt",
        ]:
            if Path(p).exists():
                return p
        return self._generate_builtin("sqli")

    def get_lfi_payloads(self) -> str:
        """Return path to LFI payload file (generate if needed)."""
        for p in [
            "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
            "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
        ]:
            if Path(p).exists():
                return p
        return self._generate_builtin("lfi")

    def get_hashcat_rule(self, name: str = "best64") -> str:
        """Return path to a hashcat rule file."""
        for p in WORDLIST_DB.get("hashcat_rules", []):
            if name in p and Path(p).exists():
                return p
        # Return best64 as fallback
        best = "/usr/share/hashcat/rules/best64.rule"
        return best if Path(best).exists() else None

    # ── INVENTORY ─────────────────────────────────────────────────────────────

    def inventory(self) -> dict:
        report = {}
        for category, paths in WORDLIST_DB.items():
            available = [p for p in paths if Path(p).exists()]
            report[category] = {
                "available": len(available),
                "total":     len(paths),
                "paths":     available,
                "has_builtin": bool(self.get_builtin_list(category)),
            }
        return report

    def seclists_installed(self) -> bool:
        return Path("/usr/share/seclists").exists()

    def rockyou_path(self) -> str:
        plain = "/usr/share/wordlists/rockyou.txt"
        gz    = "/usr/share/wordlists/rockyou.txt.gz"
        if Path(plain).exists():
            return plain
        if Path(gz).exists():
            return gz
        return None

    def count_words(self, path: str) -> int:
        try:
            with open(path) as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    # ── AUTO-GENERATE MISSING WORDLISTS ───────────────────────────────────────

    def _generate_builtin(self, category: str) -> str:
        """
        Write built-in wordlist to a temp file and return path.
        Used as fallback when SecLists files are not found.
        """
        words = self.get_builtin_list(category)
        if not words:
            return None

        self._tmpdir.mkdir(parents=True, exist_ok=True)
        path = self._tmpdir / f"{category}_builtin.txt"

        if not path.exists():
            try:
                with open(path, "w") as f:
                    f.write("\n".join(words) + "\n")
                if self.verbose:
                    from modules.utils import log, Colors
                    log(f"    Generated built-in {category} wordlist: {path} ({len(words)} entries)", Colors.DIM)
            except Exception:
                return None

        return str(path)

    # ── FIX MISSING WORDLISTS ─────────────────────────────────────────────────

    def fix_missing(self, verbose: bool = True) -> dict:
        """
        Check all categories and generate built-in fallbacks for missing ones.
        Returns dict of what was fixed.
        """
        fixed = {}
        inv = self.inventory()
        for category, data in inv.items():
            if data["available"] == 0 and data["has_builtin"]:
                path = self._generate_builtin(category)
                if path:
                    fixed[category] = path
                    if verbose:
                        from modules.utils import log, Colors
                        log(f"  ✓ Generated fallback wordlist: {category} → {path}", Colors.GREEN)
        return fixed

    def print_fix_instructions(self):
        """Print apt commands to fix all missing wordlists."""
        from modules.utils import log, Colors
        inv = self.inventory()
        missing_cats = [c for c, d in inv.items() if d["available"] == 0]
        if not missing_cats:
            log("  All wordlist categories covered.", Colors.GREEN)
            return

        log("\n  Missing wordlist categories: " + ", ".join(missing_cats), Colors.YELLOW)
        log("\n  Fix with:", Colors.BOLD_CYAN)
        log("    sudo apt install -y seclists wordlists", Colors.CYAN)
        log("    # Or full SecLists from GitHub:", Colors.DIM)
        log("    sudo git clone --depth=1 https://github.com/danielmiessler/SecLists /usr/share/seclists", Colors.DIM)
        log("\n  WordPress wordlists specifically:", Colors.BOLD_CYAN)
        log("    sudo apt install -y seclists", Colors.CYAN)
        log("    ls /usr/share/seclists/Discovery/Web-Content/CMS/WordPress/", Colors.DIM)
        log("\n  Note: GhostScan will use built-in fallback lists in the meantime.", Colors.GREEN)
