#!/usr/bin/env python3
"""
GhostScan - Hard Scope Enforcement
Every tool call, URL fetch, and domain check passes through this gate first.
Raises ScopeViolation if target is outside declared scope.
Supports: single IP, CIDR, domain, wildcard domain, scope files.
"""

import ipaddress
import socket
import re
from pathlib import Path
from urllib.parse import urlparse
from modules.utils import log, Colors


class ScopeViolation(Exception):
    """Raised when a target is outside defined scope."""
    pass


# RFC 1918 + reserved ranges - always blocked for SSRF protection
_ALWAYS_BLOCKED = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # link-local / AWS metadata
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("224.0.0.0/4"),     # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),     # reserved
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
]


class ScopeEnforcer:
    """
    Hard scope gate. Wrap every tool call with:
        enforcer.check(target)   → raises ScopeViolation or returns True
        enforcer.check_url(url)  → same but parses URL first
        enforcer.wrap_cmd(cmd)   → validates first arg of tool cmd list

    Scope sources (in priority order):
        1. --scope-file FILE    (one entry per line)
        2. --scope CIDR/domain  (repeatable flag)
        3. Primary -t TARGET    (auto-added)
    """

    def __init__(self, primary: str, extra_scope: list = None,
                 scope_file: str = None, strict: bool = True,
                 ssrf_protect: bool = True):
        self.strict = strict
        self.ssrf_protect = ssrf_protect
        self.primary = primary.strip()
        self._allowed_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._allowed_domains: set[str] = set()
        self._allowed_wildcards: list[str] = []
        self._denied_nets: list[ipaddress.IPv4Network] = []
        self._denied_domains: set[str] = set()
        self._violations: list[str] = []
        self._checked: int = 0

        # Detect if primary target is internal (allow private ranges)
        self._primary_is_internal = self._detect_internal(primary)
        if self._primary_is_internal:
            # internal target — private ranges are IN scope
            self.ssrf_protect = False

        self._add_to_scope(primary)
        for t in (extra_scope or []):
            self._add_to_scope(t)
        if scope_file:
            self._load_scope_file(scope_file)

    # ── PUBLIC ────────────────────────────────────────────────────────────────

    def check(self, target: str, raise_on_fail: bool = True) -> bool:
        """Main gate. Call before every external interaction."""
        self._checked += 1
        host = self._extract_host(target)
        if not host:
            return True  # empty / local path — pass

        # 1. Denied list
        if self._is_denied(host):
            return self._fail(target, "explicitly denied", raise_on_fail)

        # 2. SSRF protection (private ranges when primary is public)
        if self.ssrf_protect and self._is_always_blocked(host):
            return self._fail(target,
                "private/reserved address (SSRF protection — use --no-ssrf-protect for internal targets)",
                raise_on_fail)

        # 3. Allowed list
        if self._is_allowed(host):
            return True

        # 4. Strict mode — block anything not explicitly allowed
        if self.strict:
            return self._fail(target, "not in declared scope", raise_on_fail)

        # 5. Non-strict — warn and allow
        log(f"    ⚠ Out-of-scope (non-strict mode): {target}", Colors.YELLOW)
        return True

    def check_url(self, url: str, raise_on_fail: bool = True) -> bool:
        """Parse URL host and check scope."""
        host = self._extract_host(url)
        return self.check(host or url, raise_on_fail)

    def wrap_cmd(self, cmd: list) -> list:
        """
        Validate a tool command before execution.
        Scans cmd list for IPs/domains and blocks out-of-scope targets.
        Returns cmd unchanged if in-scope, raises ScopeViolation otherwise.
        """
        for arg in cmd:
            # Only check args that look like hosts/IPs/URLs
            if re.match(r'^(https?://|[\w\-\.]+\.[a-z]{2,}|[\d\.]+)$', arg):
                self.check(arg)
        return cmd

    def add_scope(self, target: str):
        """Dynamically expand scope (e.g. after discovering subdomains)."""
        self._add_to_scope(target)

    def deny(self, target: str):
        """Explicitly deny a target even if within main scope."""
        host = self._extract_host(target)
        try:
            net = ipaddress.ip_network(host, strict=False)
            self._denied_nets.append(net)
        except ValueError:
            self._denied_domains.add(host.lower())

    def is_in_scope(self, target: str) -> bool:
        """Non-raising check."""
        return self.check(target, raise_on_fail=False)

    def filter_targets(self, targets: list) -> list:
        """Filter a list of targets/URLs to only in-scope ones."""
        return [t for t in targets if self.is_in_scope(t)]

    @property
    def violations(self) -> list:
        return self._violations

    @property
    def stats(self) -> dict:
        return {
            "checks": self._checked,
            "violations": len(self._violations),
            "allowed_nets": [str(n) for n in self._allowed_nets],
            "allowed_domains": sorted(self._allowed_domains),
            "wildcards": self._allowed_wildcards,
            "ssrf_protect": self.ssrf_protect,
            "strict": self.strict,
        }

    def print_scope(self):
        log("\n  ┌─ Scope Configuration ─────────────────────────", Colors.BOLD_CYAN)
        log(f"  │  Strict mode:    {'ON (out-of-scope blocked)' if self.strict else 'OFF (warn only)'}", Colors.CYAN)
        log(f"  │  SSRF protect:   {'ON' if self.ssrf_protect else 'OFF (internal target)'}", Colors.CYAN)
        if self._allowed_nets:
            log(f"  │  IP ranges:      {', '.join(str(n) for n in self._allowed_nets)}", Colors.GREEN)
        if self._allowed_domains:
            log(f"  │  Domains:        {', '.join(sorted(self._allowed_domains)[:8])}", Colors.GREEN)
        if self._allowed_wildcards:
            log(f"  │  Wildcards:      *.{', *.'.join(self._allowed_wildcards)}", Colors.GREEN)
        if self._denied_domains or self._denied_nets:
            all_denied = list(self._denied_domains) + [str(n) for n in self._denied_nets]
            log(f"  │  Denied:         {', '.join(all_denied)}", Colors.YELLOW)
        log("  └───────────────────────────────────────────────", Colors.BOLD_CYAN)

    # ── PRIVATE ───────────────────────────────────────────────────────────────

    def _add_to_scope(self, target: str):
        if not target:
            return
        clean = target.strip().lower()

        # CIDR
        try:
            net = ipaddress.ip_network(clean, strict=False)
            self._allowed_nets.append(net)
            return
        except ValueError:
            pass

        # Single IP
        try:
            addr = ipaddress.ip_address(clean)
            self._allowed_nets.append(ipaddress.ip_network(f"{addr}/32", strict=False))
            return
        except ValueError:
            pass

        # Wildcard  *.example.com
        if clean.startswith("*."):
            base = clean[2:]
            self._allowed_wildcards.append(base)
            self._allowed_domains.add(base)
            return

        # URL — extract host
        if "://" in clean:
            host = urlparse(clean).netloc.split(":")[0]
            clean = host

        # Plain domain — add root + www variant
        clean = clean.rstrip("/")
        if clean:
            self._allowed_domains.add(clean)
            if clean.startswith("www."):
                self._allowed_domains.add(clean[4:])
            else:
                self._allowed_domains.add(f"www.{clean}")

    def _load_scope_file(self, path: str):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if line.startswith("!"):   # ! prefix = deny
                            self.deny(line[1:])
                        else:
                            self._add_to_scope(line)
            log(f"  Scope file loaded: {path}", Colors.GREEN)
        except Exception as e:
            log(f"  Scope file error: {e}", Colors.YELLOW)

    def _is_allowed(self, host: str) -> bool:
        # Resolve to IP if needed and check nets
        ip = self._resolve(host)
        if ip:
            for net in self._allowed_nets:
                try:
                    if ip in net:
                        return True
                except TypeError:
                    pass

        # Check exact domain match
        hl = host.lower()
        if hl in self._allowed_domains:
            return True

        # Check wildcard  — e.g. dev.example.com matches *.example.com
        for wc in self._allowed_wildcards:
            if hl.endswith(f".{wc}") or hl == wc:
                return True

        # Check if it's a subdomain of an allowed domain
        for dom in self._allowed_domains:
            if hl == dom or hl.endswith(f".{dom}"):
                return True

        return False

    def _is_denied(self, host: str) -> bool:
        ip = self._resolve(host)
        if ip:
            for net in self._denied_nets:
                try:
                    if ip in net:
                        return True
                except TypeError:
                    pass
        return host.lower() in self._denied_domains

    def _is_always_blocked(self, host: str) -> bool:
        ip = self._resolve(host)
        if not ip:
            # Try hostname-based SSRF patterns
            ssrf_keywords = ["localhost", "metadata", "169.254", "internal", "intranet"]
            return any(k in host.lower() for k in ssrf_keywords)
        for net in _ALWAYS_BLOCKED:
            try:
                if ip in net:
                    return True
            except TypeError:
                pass
        return False

    def _resolve(self, host: str):
        """Try to resolve host to IP. Returns ip_address object or None."""
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            pass
        try:
            resolved = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
            return ipaddress.ip_address(resolved)
        except Exception:
            return None

    def _extract_host(self, target: str) -> str:
        if not target:
            return ""
        target = target.strip()
        if "://" in target:
            return urlparse(target).netloc.split(":")[0]
        if target.startswith("/"):
            return ""  # relative path
        return target.split(":")[0].split("/")[0]  # strip port / path

    def _detect_internal(self, target: str) -> bool:
        """True if primary target is an RFC1918 IP or .local/.internal domain."""
        host = self._extract_host(target)
        ip = self._resolve(host)
        if ip:
            for net in _ALWAYS_BLOCKED:
                try:
                    if ip in net:
                        return True
                except TypeError:
                    pass
        if host.endswith((".local", ".internal", ".corp", ".lan", ".home")):
            return True
        return False

    def _fail(self, target: str, reason: str, raise_on_fail: bool) -> bool:
        msg = f"SCOPE VIOLATION: {target} — {reason}"
        self._violations.append(msg)
        log(f"  🚫 {msg}", Colors.BOLD_RED)
        if raise_on_fail:
            raise ScopeViolation(msg)
        return False
