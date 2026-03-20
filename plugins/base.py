#!/usr/bin/env python3
"""
GhostScan - Plugin System v2
Full metadata, dependency management, safety sandbox, marketplace-ready.
Drop any .py file into plugins/ and it auto-loads.
"""

import os
import sys
import time
import threading
import importlib.util
from pathlib import Path
from typing import List, Dict, Optional, Any
from modules.utils import log, make_finding, Colors


class GhostScanPlugin:
    """
    Base class for all GhostScan plugins.

    Required metadata (set as class variables):
        name            — Display name
        version         — Semver string (e.g. "1.0.0")
        author          — Plugin author
        description     — One-line description
        requires        — Phases that must complete first:
                          ["recon", "web_analysis", "vuln_detection"]
        tags            — Category tags for filtering
        severity        — Default severity for produced findings
        enabled         — Set False to skip without deleting file
        stealth         — True = safe for passive/stealth mode
        min_confidence  — Suppress findings below this threshold (0.0–1.0)
        max_findings    — Cap findings to avoid noise
        timeout         — Max seconds plugin may run (safety kill)

    Context dict keys passed to run():
        endpoints, forms, technologies, open_ports, subdomains,
        dir_brute, js_secrets, waf, header_audit, sqli_findings,
        xss_findings, cve_findings, findings, config, mode
    """

    # ── Metadata ──────────────────────────────────────────────────────────────
    name:           str   = "BasePlugin"
    version:        str   = "1.0.0"
    author:         str   = "GhostScan"
    description:    str   = "Base plugin — override in subclass"
    requires:       list  = []
    tags:           list  = []
    severity:       str   = "medium"
    enabled:        bool  = True
    stealth:        bool  = True
    min_confidence: float = 0.5
    max_findings:   int   = 50
    timeout:        int   = 60

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self, target: str, context: dict) -> list:
        """
        Main plugin logic. Return a list of finding dicts via self.finding().
        Never raises — sandbox catches all exceptions.
        """
        return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def finding(self,
                severity:         str,
                title:            str,
                detail:           str   = "",
                url:              str   = "",
                evidence:         str   = "",
                remediation:      str   = "",
                confidence:       float = 0.8,
                impact:           float = 5.0,
                exploitability:   str   = "unknown",
                business_context: str   = "") -> Optional[dict]:
        """
        Create a standardised finding dict.
        Returns None if confidence < min_confidence (suppressed).
        """
        if confidence < self.min_confidence:
            return None

        # Normalise severity to uppercase
        severity = severity.upper()
        valid = {"CRITICAL","HIGH","MEDIUM","LOW","INFO"}
        if severity not in valid:
            severity = "INFO"

        conf_label = (
            "Confirmed"   if confidence >= 0.9  else
            "Likely"      if confidence >= 0.7  else
            "Possible"    if confidence >= 0.5  else
            "Speculative"
        )

        detail_full = detail
        if business_context:
            detail_full += f" | Business impact: {business_context}"
        detail_full += f" | Confidence: {conf_label} ({confidence:.0%})"

        f = make_finding(
            severity, f"Plugin:{self.name}", title,
            detail=detail_full, url=url,
            evidence=evidence, remediation=remediation,
        )
        f["_confidence"]      = round(float(confidence), 2)
        f["_impact"]          = round(float(impact), 1)
        f["_exploitability"]  = str(exploitability)
        f["_plugin"]          = self.name
        f["_plugin_ver"]      = self.version
        f["_business"]        = business_context
        return f

    def meta(self) -> dict:
        """Return full plugin metadata dict (for listing and marketplace)."""
        return {
            "name":           self.name,
            "version":        self.version,
            "author":         self.author,
            "description":    self.description,
            "requires":       list(self.requires),
            "tags":           list(self.tags),
            "severity":       self.severity,
            "enabled":        self.enabled,
            "stealth":        self.stealth,
            "min_confidence": self.min_confidence,
            "max_findings":   self.max_findings,
            "timeout":        self.timeout,
        }

    def log(self, msg: str, level: str = "info"):
        """Plugin-scoped logging."""
        colors = {
            "info":    Colors.DIM,
            "warn":    Colors.YELLOW,
            "error":   Colors.RED,
            "success": Colors.GREEN,
            "find":    Colors.BOLD_RED,
        }
        log(f"    [{self.name}] {msg}", colors.get(level, Colors.DIM))

    def __repr__(self) -> str:
        return f"<Plugin:{self.name} v{self.version} by {self.author} tags={self.tags}>"


# ── Plugin Loader ─────────────────────────────────────────────────────────────

class PluginLoader:
    """
    Discovers, validates, sandboxes, and runs plugins from plugins/ directory.

    Safety features:
    - Per-plugin timeout (threading kill switch)
    - Exception sandbox (crash = empty result, not broken scan)
    - Finding cap per plugin (max_findings)
    - Dependency checking (requires field)
    - Tag and stealth filtering
    - Performance metrics per plugin
    """

    def __init__(self, plugin_dir: str = None):
        if plugin_dir is None:
            plugin_dir = Path(__file__).parent
        self.plugin_dir   = Path(plugin_dir)
        self._plugins:    List[GhostScanPlugin] = []
        self._errors:     Dict[str, str]        = {}
        self._metrics:    Dict[str, dict]       = {}

    # ── Loading ───────────────────────────────────────────────────────────────

    def load_all(self,
                 tags:             list = None,
                 stealth_only:     bool = False,
                 completed_phases: list = None) -> List[GhostScanPlugin]:
        """
        Discover and load all valid, enabled plugins.
        Returns list of instantiated plugin objects.
        """
        self._plugins = []
        self._errors  = {}
        completed     = set(completed_phases or ["recon", "web_analysis", "vuln_detection"])

        if not self.plugin_dir.exists():
            return []

        for py_file in sorted(self.plugin_dir.glob("*.py")):
            if py_file.name.startswith("_") or py_file.name == "base.py":
                continue
            try:
                instances = self._load_file(py_file)
            except Exception as e:
                self._errors[py_file.name] = str(e)
                log(f"    ↳ Plugin load error ({py_file.name}): {str(e)[:70]}", Colors.YELLOW)
                continue

            for plugin in instances:
                if not plugin.enabled:
                    continue
                if stealth_only and not plugin.stealth:
                    continue
                if tags and not any(t in plugin.tags for t in tags):
                    continue
                missing = [r for r in plugin.requires if r not in completed]
                if missing:
                    log(f"    ↳ Skipping {plugin.name}: missing phases {missing}", Colors.DIM)
                    continue
                self._plugins.append(plugin)
                log(f"    ↳ ✓ {plugin.name} v{plugin.version} [{plugin.author}]"
                    f" tags=[{', '.join(plugin.tags)}]", Colors.DIM)

        return self._plugins

    # ── Running ───────────────────────────────────────────────────────────────

    def run_all(self, target: str, context: dict) -> list:
        """
        Run all loaded plugins in sandboxed threads.
        One crash/timeout never affects other plugins.
        """
        all_findings = []

        for plugin in self._plugins:
            t0       = time.time()
            findings = self._run_sandboxed(plugin, target, context)
            elapsed  = round(time.time() - t0, 2)

            # Cap findings per plugin
            if len(findings) > plugin.max_findings:
                findings = findings[:plugin.max_findings]

            # Filter None (suppressed by confidence)
            findings = [f for f in findings if f is not None]

            self._metrics[plugin.name] = {
                "elapsed":  elapsed,
                "findings": len(findings),
                "status":   self._metrics.get(plugin.name, {}).get("status", "ok"),
            }

            if findings:
                log(f"    [{plugin.name}] {Colors.GREEN}{len(findings)} finding(s){Colors.RESET} in {elapsed}s",
                    Colors.RESET)
            else:
                log(f"    [{plugin.name}] 0 findings ({elapsed}s)", Colors.DIM)

            all_findings.extend(findings)

        return all_findings

    def _run_sandboxed(self, plugin: GhostScanPlugin,
                       target: str, context: dict) -> list:
        """Run plugin in thread with timeout + exception isolation."""
        result_holder    = []
        exception_holder = []

        def _worker():
            try:
                result_holder.extend(plugin.run(target, context) or [])
            except Exception as e:
                exception_holder.append(str(e))

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=plugin.timeout)

        if t.is_alive():
            log(f"    [{plugin.name}] Timed out after {plugin.timeout}s", Colors.YELLOW)
            self._metrics[plugin.name] = {"status": "timeout", "elapsed": plugin.timeout, "findings": 0}
            return []

        if exception_holder:
            log(f"    [{plugin.name}] Error: {exception_holder[0][:80]}", Colors.YELLOW)
            self._metrics[plugin.name] = {"status": "error", "error": exception_holder[0], "findings": 0}
            return []

        return result_holder

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _load_file(self, py_file: Path) -> List[GhostScanPlugin]:
        spec   = importlib.util.spec_from_file_location(f"gs_plugin_{py_file.stem}", py_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return [
            getattr(module, name)()
            for name in dir(module)
            if (isinstance(getattr(module, name), type) and
                issubclass(getattr(module, name), GhostScanPlugin) and
                getattr(module, name) is not GhostScanPlugin)
        ]

    def summary(self) -> str:
        lines = [f"  Plugins loaded: {len(self._plugins)}"]
        for p in self._plugins:
            m = self._metrics.get(p.name, {})
            lines.append(f"    {'✓' if m.get('status','ok')=='ok' else '!'} "
                         f"{p.name} v{p.version} — {m.get('findings',0)} findings, {m.get('elapsed',0):.1f}s")
        if self._errors:
            lines.append(f"  Load errors: {len(self._errors)}")
            for name, err in self._errors.items():
                lines.append(f"    ✗ {name}: {err[:70]}")
        return "\n".join(lines)

    @property
    def loaded(self)  -> List[GhostScanPlugin]: return self._plugins
    @property
    def errors(self)  -> Dict[str, str]:         return self._errors
    @property
    def metrics(self) -> Dict[str, dict]:        return self._metrics
