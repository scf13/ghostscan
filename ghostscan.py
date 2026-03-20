#!/usr/bin/env python3
"""
GhostScan v3.0 — Elite Penetration Testing Framework for Kali Linux

WHAT'S NEW IN v3:
  ✓ Hard scope enforcement (blocks out-of-scope targets + SSRF)
  ✓ Safe parallel executor (timeout/retry/failure isolation per tool)
  ✓ Intelligence engine (correlation + smart target ranking)
  ✓ Adaptive workflow (dynamic next steps based on findings)
  ✓ WAF bypass engine (profile-based evasion for CloudFlare, Akamai, F5, etc.)
  ✓ Headless browser (Playwright DOM XSS, hidden endpoints, storage analysis)
  ✓ Parallel recon (nmap + amass + sublist3r + theHarvester simultaneously)
  ✓ --min-severity filter (suppress noise, show only what matters)

AUTHORIZED USE ONLY — 18 U.S.C § 1030 / Computer Misuse Act applies.
"""

import argparse
import sys
import os
import json
import time
import signal
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import banner, log, Colors, SEVERITY_COLORS
from modules.wordlists import WordlistManager
from modules.tool_integration import ToolRunner
from modules.scope import ScopeEnforcer, ScopeViolation
from modules.executor import SafeExecutor
from modules.intelligence import IntelligenceEngine
from modules.workflow import WorkflowEngine


def parse_args():
    parser = argparse.ArgumentParser(
        prog="ghostscan",
        description="GhostScan v3.0 — Elite Pentest Framework for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
═══════════════════════════════════════════════════
  USAGE EXAMPLES
═══════════════════════════════════════════════════
  Full scan, PDF report, aggressive mode:
    ghostscan -t example.com --all --intensity aggressive --report pdf

  Parallel recon only (fast, simultaneous tools):
    ghostscan -t example.com --recon --parallel

  Web scan through Burp Suite + WAF bypass:
    ghostscan -t example.com --web --proxy http://127.0.0.1:8080 --waf-bypass

  Injection testing with scope enforcement:
    ghostscan -t example.com --vuln --sqli --xss --scope example.com --strict-scope

  Headless browser DOM XSS scan:
    ghostscan -t example.com --web --browser

  Show only HIGH+ findings:
    ghostscan -t example.com --all --min-severity high

  Tor routing (requires tor service running):
    ghostscan -t example.com --all --tor

  Show installed tools:
    ghostscan -t example.com --tools

  Full pentest workflow guide:
    ghostscan -t example.com --workflow

  Resume from saved session:
    ghostscan -t example.com --all --resume ./ghostscan_results/session_*.json

═══════════════════════════════════════════════════
  DISCLAIMER: Authorized use only.
═══════════════════════════════════════════════════
""",
    )

    # ── TARGET ───────────────────────────────────────────────────────────────
    parser.add_argument("-t", "--target", required=True,
                        help="Domain, IP, or CIDR (e.g. 192.168.1.0/24)")

    # ── PROFILE / MODE ───────────────────────────────────────────────────────
    parser.add_argument("--mode",
        choices=["stealth", "standard", "aggressive"],
        default=None,
        help=(
            "Scan profile — shortcut for multiple flags:\n"
            "  stealth:    Passive recon only. No bruteforce, no active probing. Slow rate.\n"
            "  standard:   Balanced scan. All modules. Normal rate. (default behaviour)\n"
            "  aggressive: Everything enabled. Max threads. Large wordlists. All injections."
        ))

    # ── MODULES ──────────────────────────────────────────────────────────────
    mods = parser.add_argument_group("Module Selection")
    mods.add_argument("--all",      action="store_true", help="Run all modules")
    mods.add_argument("--recon",    action="store_true", help="DNS, subdomains, OSINT, port scan")
    mods.add_argument("--web",      action="store_true", help="Web crawl, dir brute, nikto, nuclei, wpscan")
    mods.add_argument("--vuln",     action="store_true", help="Headers, XSS, SQLi, CVE correlation")
    mods.add_argument("--workflow", action="store_true", help="Print adaptive pentest workflow and exit")

    # ── ATTACK OPTIONS ────────────────────────────────────────────────────────
    atk = parser.add_argument_group("Attack Options")
    atk.add_argument("--xss",   action="store_true", help="XSS probing (SecLists payloads)")
    atk.add_argument("--sqli",  action="store_true", help="SQLi via sqlmap")
    atk.add_argument("--brute", action="store_true", help="Online brute-force via Hydra")
    atk.add_argument("--udp",   action="store_true", help="UDP port scan")
    atk.add_argument("--fast",  action="store_true", help="masscan full-range discovery first")
    atk.add_argument("--browser", action="store_true",
                     help="Headless browser (Playwright) for DOM XSS + hidden endpoints")
    atk.add_argument("--stealth",  action="store_true",
                     help="Stealth mode — passive recon only, no brute-force, no fuzzing, low rate")
    atk.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")
    atk.add_argument("--no-cve",        action="store_true", help="Skip CVE correlation")
    atk.add_argument("--plugins",  action="store_true", default=True,
                     help="Run community plugins from plugins/ directory (default: on)")
    atk.add_argument("--no-plugins", action="store_true",
                     help="Disable plugin system")
    atk.add_argument("--screenshots", action="store_true",
                     help="Save screenshots of discovered pages (requires --browser)")

    # ── SCOPE ─────────────────────────────────────────────────────────────────
    scope = parser.add_argument_group("Scope Enforcement")
    scope.add_argument("--scope", action="append", metavar="TARGET",
                       help="Add target to scope (repeatable). e.g. --scope *.example.com --scope 10.0.0.0/8")
    scope.add_argument("--scope-file", metavar="FILE",
                       help="Load scope from file (one entry per line, ! prefix = deny)")
    scope.add_argument("--strict-scope", action="store_true",
                       help="Block all out-of-scope requests (default: warn only)")
    scope.add_argument("--no-ssrf-protect", action="store_true",
                       help="Disable SSRF protection (use for internal/pentest lab targets)")

    # ── EVASION ──────────────────────────────────────────────────────────────
    evade = parser.add_argument_group("WAF Evasion")
    evade.add_argument("--waf-bypass", action="store_true",
                       help="Enable WAF evasion (auto-detects WAF and loads bypass profile)")
    evade.add_argument("--waf-profile",
                       choices=["cloudflare", "akamai", "aws-waf", "f5", "imperva",
                                "modsecurity", "wordfence", "sucuri", "generic"],
                       help="Force a specific WAF bypass profile")

    # ── PARALLEL ─────────────────────────────────────────────────────────────
    perf = parser.add_argument_group("Performance")
    perf.add_argument("--parallel",  action="store_true",
                      help="Run recon tools simultaneously (nmap+amass+sublist3r at once)")
    perf.add_argument("--intensity", choices=["passive", "normal", "aggressive"],
                      default="normal",
                      help="Scan intensity (default: normal)")
    perf.add_argument("--ports",     default="21,22,23,25,53,80,110,111,135,139,143,443,445,"
                                              "993,995,1433,1521,3306,3389,5432,5900,6379,"
                                              "8080,8443,8888,9090,9200,27017",
                      help="Ports to scan (comma-sep or range)")
    perf.add_argument("--port-scan-type", choices=["connect","syn","udp"], default="connect")
    perf.add_argument("--depth",    type=int, default=3, help="Web crawl depth")
    perf.add_argument("--threads",  type=int, default=20, help="Thread count")
    perf.add_argument("--timeout",  type=int, default=10, help="Request timeout (s)")
    perf.add_argument("--rate-limit", type=float, default=0.1, help="Delay between requests (s)")
    perf.add_argument("--tool-timeout", type=int, default=300, help="External tool timeout (s)")

    # ── OUTPUT ────────────────────────────────────────────────────────────────
    out = parser.add_argument_group("Output & Filtering")
    out.add_argument("--min-severity",
                     choices=["critical", "high", "medium", "low", "info"],
                     default="info",
                     help="Minimum severity to display/report (default: info = show all)")
    out.add_argument("--report",
                     choices=["markdown", "html", "pdf", "json", "both", "all"],
                     default="both")
    out.add_argument("--output",  default="ghostscan_results", help="Output directory")
    out.add_argument("--resume",  help="Resume from a saved session JSON file")
    out.add_argument("-v", "--verbose", action="store_true")

    # ── WORDLISTS ────────────────────────────────────────────────────────────
    wl = parser.add_argument_group("Wordlists")
    wl.add_argument("--wordlist-size", choices=["small","medium","large"], default="medium")
    wl.add_argument("--subdomain-wordlist")
    wl.add_argument("--dir-wordlist")
    wl.add_argument("--password-wordlist")
    wl.add_argument("--username-wordlist")

    # ── HTTP ─────────────────────────────────────────────────────────────────
    http = parser.add_argument_group("HTTP")
    http.add_argument("--proxy")
    http.add_argument("--tor",     action="store_true")
    http.add_argument("--cookies", type=json.loads)
    http.add_argument("--headers", type=json.loads)
    http.add_argument("--user-agent",
                      default="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0")

    # ── INFO ──────────────────────────────────────────────────────────────────
    info = parser.add_argument_group("Info")
    info.add_argument("--tools",     action="store_true", help="Show tool inventory")
    info.add_argument("--wordlists", action="store_true", help="Show wordlist inventory")
    info.add_argument("--version",   action="store_true")

    return parser.parse_args()


# ── BUILD CONFIG ──────────────────────────────────────────────────────────────

def build_config(args) -> dict:
    config = {
        "target":          args.target,
        "verbose":         args.verbose,
        "intensity":       args.intensity,
        "ports":           args.ports,
        "port_scan_type":  args.port_scan_type,
        "depth":           args.depth,
        "threads":         args.threads,
        "timeout":         args.timeout,
        "rate_limit":      args.rate_limit,
        "tool_timeout":    args.tool_timeout,
        "xss":             args.xss,
        "sqli":            args.sqli,
        "brute":           args.brute,
        "no_cve":          args.no_cve,
        "no_subdomains":   args.no_subdomains,
        "udp_scan":        args.udp,
        "stealth":         args.stealth,
        "plugins_enabled": not args.no_plugins,
        "screenshots":     args.screenshots,
        "mode":            args.mode or "standard",
        "fast_scan":       args.fast,
        "parallel":        args.parallel,
        "waf_bypass":      args.waf_bypass,
        "waf_profile":     args.waf_profile,
        "browser":         args.browser,
        "wordlist_size":   args.wordlist_size,
        "user_agent":      args.user_agent,
        "output":          args.output,
        "report":          args.report,
        "min_severity":    args.min_severity.upper(),
        "nikto_timeout":   600,
        "nuclei_timeout":  600,
    }

    # ── Mode profile shortcuts ────────────────────────────────────────────────
    if args.mode == "stealth":
        args.stealth    = True
        args.intensity  = "passive"
    elif args.mode == "standard":
        # Standard is default — no overrides needed
        if not args.all and not any([args.recon, args.web, args.vuln]):
            args.all = True
    elif args.mode == "aggressive":
        args.all        = True
        args.intensity  = "aggressive"
        args.sqli       = True
        args.xss        = True
        args.brute      = True
        args.fast       = True
        args.parallel   = True
        args.waf_bypass = True
        config["wordlist_size"]   = "large"
        config["threads"]         = 50
        config["depth"]           = 5
        log("  🔥 AGGRESSIVE MODE — all modules, injections, brute-force, large wordlists", Colors.BOLD_RED)

    # Stealth mode overrides
    if args.stealth or args.mode == "stealth":
        config["intensity"]     = "passive"
        config["rate_limit"]    = 2.0       # 2s between requests
        config["threads"]       = 5         # very low threads
        config["xss"]           = False     # no active probing
        config["sqli"]          = False
        config["brute"]         = False
        config["no_subdomains"] = False     # keep passive recon
        config["fast_scan"]     = False
        log("  ⚡ STEALTH MODE — passive recon only, rate-limited, no injection probing", Colors.YELLOW)

    if args.tor:
        config["proxy"] = {"http": "socks5h://127.0.0.1:9050",
                           "https": "socks5h://127.0.0.1:9050"}
        config["tor"] = True
        log("  Tor routing enabled via socks5h://127.0.0.1:9050", Colors.YELLOW)
    elif args.proxy:
        config["proxy"] = {"http": args.proxy, "https": args.proxy}

    if args.cookies: config["cookies"] = args.cookies
    if args.headers: config["headers"] = args.headers

    for attr in ["subdomain_wordlist","dir_wordlist","password_wordlist","username_wordlist"]:
        val = getattr(args, attr, None)
        if val: config[f"custom_{attr}"] = val

    return config


# ── SCOPE SETUP ───────────────────────────────────────────────────────────────

def build_scope(args, config: dict) -> ScopeEnforcer:
    extra = args.scope or []
    enforcer = ScopeEnforcer(
        primary=args.target,
        extra_scope=extra,
        scope_file=args.scope_file if hasattr(args, "scope_file") else None,
        strict=args.strict_scope if hasattr(args, "strict_scope") else False,
        ssrf_protect=not (args.no_ssrf_protect if hasattr(args, "no_ssrf_protect") else False),
    )
    enforcer.print_scope()
    return enforcer


# ── INFO PRINTERS ─────────────────────────────────────────────────────────────

def print_tool_inventory(runner: ToolRunner):
    inv = runner.tool_inventory()
    installed = [t for t, v in inv.items() if v]
    missing   = [t for t, v in inv.items() if not v]
    log("", Colors.RESET)
    log("═"*60, Colors.BOLD_CYAN)
    log("  TOOL INVENTORY", Colors.BOLD_CYAN)
    log("═"*60, Colors.BOLD_CYAN)
    log(f"  Installed: {len(installed)}/{len(inv)}", Colors.GREEN)
    categories = {
        "Recon / OSINT":      ["nmap","dnsrecon","dnsenum","sublist3r","amass","theHarvester","masscan","fierce","whois","dig"],
        "Web Scanning":       ["nikto","whatweb","wafw00f","gobuster","ffuf","dirb","wfuzz","feroxbuster","wpscan","nuclei"],
        "Vulnerability":      ["sqlmap","xssstrike","commix","testssl","sslscan","sslyze"],
        "Online Brute-force": ["hydra","medusa","ncrack","patator","crackmapexec"],
        "Offline Cracking":   ["john","hashcat","haiti"],
        "Network/Services":   ["enum4linux","smbclient","smbmap","nbtscan","snmpwalk","onesixtyone"],
    }
    for cat, tools in categories.items():
        log(f"\n  {cat}", Colors.BOLD_YELLOW)
        for t in tools:
            ok = inv.get(t, False)
            path = runner.which(t) or "" if ok else ""
            sym  = "✓" if ok else "✗"
            col  = Colors.GREEN if ok else Colors.DIM
            log(f"    {col}{sym}  {t:<20}{Colors.DIM}{path[:40]}{Colors.RESET}", Colors.RESET)
    if missing:
        log("\n  Install missing tools:", Colors.BOLD_YELLOW)
        apt_pkgs = ["nmap","gobuster","ffuf","nikto","sqlmap","hydra","john","hashcat",
                    "seclists","wordlists","dnsrecon","amass","sublist3r","theharvester",
                    "whatweb","wafw00f","sslscan","enum4linux","smbclient","nuclei","wpscan"]
        log(f"    sudo apt install -y {' '.join(apt_pkgs[:8])}", Colors.CYAN)
        log(f"    sudo apt install -y {' '.join(apt_pkgs[8:])}", Colors.CYAN)
        log("    # Headless browser: pip install playwright && playwright install chromium", Colors.CYAN)


def print_wordlist_inventory():
    wl = WordlistManager()
    log("", Colors.RESET)
    log("═"*60, Colors.BOLD_CYAN)
    log("  WORDLIST INVENTORY", Colors.BOLD_CYAN)
    log("═"*60, Colors.BOLD_CYAN)
    seclists = Path("/usr/share/seclists").exists()
    wlists   = Path("/usr/share/wordlists").exists()
    log(f"\n  SecLists:  {'✓ installed' if seclists else '✗ not found → sudo apt install seclists'}", Colors.GREEN if seclists else Colors.YELLOW)
    log(f"  wordlists: {'✓ installed' if wlists else '✗ not found → sudo apt install wordlists'}", Colors.GREEN if wlists else Colors.YELLOW)
    inv = wl.inventory()
    for cat, data in inv.items():
        col = Colors.GREEN if data["available"] > 0 else Colors.DIM
        log(f"  {cat:<20} {col}{data['available']}/{data['total']} available{Colors.RESET}", Colors.RESET)
    rr = wl.rockyou_path()
    log(f"\n  rockyou.txt: {'✓ ' + rr if rr else '✗ not found'}", Colors.GREEN if rr else Colors.DIM)


# ── SCAN ORCHESTRATION ────────────────────────────────────────────────────────

def run_modules(config: dict, args, scope: ScopeEnforcer,
                executor: SafeExecutor, prior: dict = None) -> tuple:
    all_results  = prior or {}
    total_findings = 0

    # ── RECON (parallel if --parallel) ────────────────────────────────────────
    if args.all or args.recon:
        log("\n", Colors.RESET)
        log("━"*62, Colors.BOLD_CYAN)
        log("  [1/3] RECONNAISSANCE", Colors.BOLD_CYAN)
        log("━"*62, Colors.BOLD_CYAN)
        t0 = time.time()

        if config.get("parallel"):
            log("  ⚡ Parallel mode — running all recon tools simultaneously...", Colors.CYAN)
            # Run nmap + amass + sublist3r + theHarvester at the same time
            raw_parallel = executor.run_recon_parallel(config["target"], config)
            # Still run the full ReconModule to process+normalise results
            from modules.recon import ReconModule
            recon_mod = ReconModule(config)
            recon_mod._parallel_results = raw_parallel  # pass in pre-run results
            all_results["recon"] = recon_mod.run()
        else:
            from modules.recon import ReconModule
            recon_mod = ReconModule(config)
            all_results["recon"] = recon_mod.run()

        elapsed = time.time() - t0
        n = len(all_results["recon"].get("findings", []))
        total_findings += n
        log(f"\n  ✓ Recon done in {elapsed:.1f}s — {n} findings", Colors.GREEN)

    # ── WEB ───────────────────────────────────────────────────────────────────
    if args.all or args.web:
        log("\n", Colors.RESET)
        log("━"*62, Colors.BOLD_CYAN)
        log("  [2/3] WEB ANALYSIS", Colors.BOLD_CYAN)
        log("━"*62, Colors.BOLD_CYAN)
        t0 = time.time()

        # Build WAF bypass if requested
        waf_bypass = None
        if config.get("waf_bypass") or config.get("waf_profile"):
            from modules.waf_bypass import WafBypass, build_bypass
            if config.get("waf_profile"):
                waf_bypass = WafBypass(config["waf_profile"], config["intensity"])
            # actual WAF is detected in web_analysis; bypass applied to session

        from modules.web_analysis import WebAnalysisModule
        web_mod = WebAnalysisModule(config,
                                    prior_results=all_results.get("recon", {}),
                                    waf_bypass_engine=waf_bypass)
        all_results["web"] = web_mod.run()
        elapsed = time.time() - t0
        n = len(all_results["web"].get("findings", []))
        total_findings += n
        log(f"\n  ✓ Web analysis done in {elapsed:.1f}s — {n} findings", Colors.GREEN)

        # Headless browser pass
        if config.get("browser"):
            from modules.browser import HeadlessBrowser
            log("  → Headless browser (Playwright) DOM XSS scan...", Colors.CYAN)
            if HeadlessBrowser.available():
                hb = HeadlessBrowser(config, waf_bypass=waf_bypass)
                base_urls = all_results["web"].get("base_urls", [f"https://{config['target']}"])
                browser_results = hb.run(base_urls[:5])
                all_results["web"]["browser"] = browser_results
                # Merge browser findings into web findings
                all_results["web"]["findings"] += browser_results.get("findings", [])
                dom_xss = browser_results.get("dom_xss", [])
                if dom_xss:
                    log(f"    {len(dom_xss)} DOM XSS pattern(s) found by headless browser", Colors.BOLD_RED)
            else:
                log(f"    Playwright not installed.", Colors.YELLOW)
                log(f"    Install: {HeadlessBrowser.install_hint()}", Colors.DIM)

    # ── VULN ──────────────────────────────────────────────────────────────────
    if args.all or args.vuln:
        log("\n", Colors.RESET)
        log("━"*62, Colors.BOLD_CYAN)
        log("  [3/3] VULNERABILITY ANALYSIS", Colors.BOLD_CYAN)
        log("━"*62, Colors.BOLD_CYAN)
        t0 = time.time()
        from modules.vuln_detection import VulnDetectionModule
        vuln_mod = VulnDetectionModule(config,
                                       prior_web=all_results.get("web", {}),
                                       prior_recon=all_results.get("recon", {}))
        all_results["vuln"] = vuln_mod.run()
        elapsed = time.time() - t0
        n = len(all_results["vuln"].get("findings", []))
        total_findings += n
        log(f"\n  ✓ Vulnerability analysis done in {elapsed:.1f}s — {n} findings", Colors.GREEN)

    return all_results, total_findings


# ── PLUGIN RUNNER ────────────────────────────────────────────────────────────

def run_plugins(config: dict, all_results: dict) -> dict:
    """Load and run all enabled plugins from the plugins/ directory."""
    import sys, os
    from pathlib import Path

    plugin_dir = Path(os.path.dirname(os.path.abspath(__file__))) / "plugins"

    # Add project root to sys.path so plugins can import modules.*
    project_root = str(Path(os.path.dirname(os.path.abspath(__file__))))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    if not plugin_dir.exists():
        return all_results

    try:
        from plugins.base import PluginLoader
    except ImportError:
        return all_results

    log("\n", Colors.RESET)
    log("━"*62, Colors.BOLD_CYAN)
    log("  PLUGINS", Colors.BOLD_CYAN)
    log("━"*62, Colors.BOLD_CYAN)

    loader = PluginLoader(str(plugin_dir))
    stealth = config.get("stealth", False)
    mode      = config.get("mode", "standard") or "standard"
    completed = []
    if all_results.get("recon"):    completed.append("recon")
    if all_results.get("web"):      completed.append("web_analysis")
    if all_results.get("vuln"):     completed.append("vuln_detection")
    plugins   = loader.load_all(mode=mode, completed=completed)

    if not plugins:
        log("  No plugins found in plugins/ directory", Colors.DIM)
        return all_results

    log(f"  {len(plugins)} plugin(s) loaded", Colors.GREEN)

    # Build context for plugins
    context = {
        **all_results.get("web", {}),
        **all_results.get("recon", {}),
        **all_results.get("vuln", {}),
        "config": config,
    }

    plugin_findings = loader.run_all(config["target"], context)

    if plugin_findings:
        log(f"  Plugins found {len(plugin_findings)} additional finding(s)", Colors.GREEN)
        # Merge into web findings
        all_results.setdefault("web", {}).setdefault("findings", [])
        all_results["web"]["findings"].extend(plugin_findings)

    return all_results


# ── INTELLIGENCE POST-PROCESSING ─────────────────────────────────────────────

def run_intelligence(config: dict, all_results: dict) -> dict:
    if not all_results:
        return all_results
    log("\n", Colors.RESET)
    log("━"*62, Colors.BOLD_CYAN)
    log("  INTELLIGENCE ENGINE — Correlating Findings...", Colors.BOLD_CYAN)
    log("━"*62, Colors.BOLD_CYAN)
    intel = IntelligenceEngine(config)
    all_results = intel.analyse(all_results)
    stats = all_results.get("intelligence", {}).get("stats", {})
    log(f"  Correlations:   {stats.get('correlations', 0)}", Colors.GREEN)
    log(f"  Ranked targets: {stats.get('attack_surface', 0)}", Colors.GREEN)
    log(f"  After dedup:    {stats.get('after_dedup', 0)} → filtered: {stats.get('after_filter', 0)}", Colors.GREEN)
    return all_results


# ── SUMMARY PRINTER ───────────────────────────────────────────────────────────

def print_summary(config: dict, all_results: dict):
    from modules.intelligence import SEVERITY_SCORE
    min_score = SEVERITY_SCORE.get(config.get("min_severity","INFO").upper(), 0)

    # Prefer intelligence-filtered findings
    intel = all_results.get("intelligence", {})
    findings = intel.get("deduped_findings") or _collect_raw_findings(all_results)

    # Apply min_severity filter
    findings = [f for f in findings
                if SEVERITY_SCORE.get(f.get("severity","INFO").upper(), 0) >= min_score]

    counts = {}
    for f in findings:
        s = f.get("severity","INFO").upper()
        counts[s] = counts.get(s, 0) + 1

    log("\n", Colors.RESET)
    log("═"*62, Colors.BOLD_CYAN)
    log("  SCAN SUMMARY", Colors.BOLD_CYAN)
    log("═"*62, Colors.BOLD_CYAN)

    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        c = counts.get(sev, 0)
        if c:
            col = SEVERITY_COLORS.get(sev, Colors.WHITE)
            log(f"  {col}{sev:<10}{Colors.RESET}  {c}", Colors.RESET)

    log("─"*62, Colors.DIM)
    log(f"  Total (after filter): {len(findings)}", Colors.BOLD)

    if config.get("min_severity","INFO").upper() != "INFO":
        log(f"  (Showing {config['min_severity'].upper()}+ only — use --min-severity info to see all)", Colors.DIM)

    # Top findings
    from modules.reporting import SEVERITY_ORDER
    top = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))[:8]
    if top:
        log("\n  Top Findings:", Colors.BOLD_YELLOW)
        for f in top:
            sev = f.get("severity","INFO")
            col = SEVERITY_COLORS.get(sev, Colors.WHITE)
            title = f.get("title","")[:58]
            log(f"  {col}[{sev}]{Colors.RESET} {title}", Colors.RESET)

    # Correlations
    corrs = intel.get("correlations", [])
    if corrs:
        log(f"\n  Correlations ({len(corrs)} compound risks):", Colors.BOLD_YELLOW)
        for c in sorted(corrs, key=lambda x: x.get("score",0), reverse=True)[:5]:
            sev = c.get("severity","HIGH")
            col = SEVERITY_COLORS.get(sev, Colors.WHITE)
            log(f"  {col}[{sev}]{Colors.RESET} {c.get('title','')[:58]}", Colors.RESET)
            if c.get("attack_path"):
                log(f"    {Colors.DIM}→ {c['attack_path'][:70]}{Colors.RESET}", Colors.DIM)

    log("", Colors.RESET)


# ── ADAPTIVE NEXT STEPS ───────────────────────────────────────────────────────

def print_next_steps(config: dict, all_results: dict):
    engine = WorkflowEngine(config)
    # Merge all relevant findings for the workflow engine
    merged = {
        **all_results.get("recon", {}),
        **all_results.get("web", {}),
        **all_results.get("vuln", {}),
    }
    # Also pass intelligence ranked targets
    intel = all_results.get("intelligence", {})
    if intel.get("ranked_targets"):
        merged["ranked_targets"] = intel["ranked_targets"]

    engine.print_adaptive_steps(merged)

    # Intelligence ranked targets
    if intel.get("ranked_targets"):
        intel_engine = IntelligenceEngine(config)
        intel_engine.print_ranked_targets(all_results)
        intel_engine.print_recommendations(all_results)


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _collect_raw_findings(results: dict) -> list:
    all_f = []
    seen  = set()
    for section in ["recon","web","vuln"]:
        for f in results.get(section, {}).get("findings", []):
            key = f"{f.get('severity')}{f.get('title')}{f.get('url')}"
            if key not in seen:
                seen.add(key)
                all_f.append(f)
    return all_f


def load_session(path: str) -> dict:
    try:
        with open(path) as f:
            data = json.load(f)
        log(f"  Session loaded: {path}", Colors.GREEN)
        return data.get("results", {})
    except Exception as e:
        log(f"  Session load failed: {e}", Colors.YELLOW)
        return {}


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if args.version:
        print("GhostScan v3.0 — Elite Pentest Framework for Kali Linux")
        sys.exit(0)

    banner()

    config  = build_config(args)
    runner  = ToolRunner(config)

    # ── INFO MODES ───────────────────────────────────────────────────────────
    if args.tools:
        print_tool_inventory(runner)
        sys.exit(0)

    if args.wordlists:
        print_wordlist_inventory()
        sys.exit(0)

    if args.workflow:
        engine = WorkflowEngine(config)
        engine.print_workflow()
        sys.exit(0)

    # ── VALIDATION ───────────────────────────────────────────────────────────
    if not any([args.all, args.recon, args.web, args.vuln]):
        log("No modules selected. Use --all, --recon, --web, --vuln, or --workflow.", Colors.YELLOW)
        log("Run: ghostscan --help", Colors.DIM)
        sys.exit(1)

    # ── SCOPE ────────────────────────────────────────────────────────────────
    scope    = build_scope(args, config)
    executor = SafeExecutor(config, scope)

    # Scope-check the primary target before doing anything
    try:
        scope.check(args.target)
    except ScopeViolation as e:
        log(f"\n  SCOPE ERROR: {e}", Colors.BOLD_RED)
        log("  Add --scope to widen scope, or fix --target.", Colors.YELLOW)
        sys.exit(1)

    # ── HEADER ───────────────────────────────────────────────────────────────
    log("  ⚠  AUTHORIZED SECURITY TESTING ONLY", Colors.BOLD_YELLOW)
    log(f"  Target:     {args.target}", Colors.CYAN)
    log(f"  Intensity:  {args.intensity}  │  Threads: {args.threads}  │  Severity filter: {args.min_severity.upper()}+", Colors.DIM)
    log(f"  Parallel:   {'YES' if config.get('parallel') else 'no'}"
        f"  │  WAF bypass: {'YES' if config.get('waf_bypass') else 'no'}"
        f"  │  Browser: {'YES' if config.get('browser') else 'no'}", Colors.DIM)
    if config.get("tor"):
        log("  Routing via Tor", Colors.YELLOW)

    # ── INTERRUPT HANDLER ────────────────────────────────────────────────────
    interrupted = [False]
    def _sig(sig, frame):
        log("\n  Interrupted — saving partial results...", Colors.YELLOW)
        interrupted[0] = True
        executor.cancel_all()
    signal.signal(signal.SIGINT, _sig)

    # ── RESUME ───────────────────────────────────────────────────────────────
    prior = {}
    if args.resume:
        prior = load_session(args.resume)

    # ── RUN ──────────────────────────────────────────────────────────────────
    start = time.time()
    all_results = {}
    total       = 0

    try:
        all_results, total = run_modules(config, args, scope, executor, prior)
    except KeyboardInterrupt:
        log("\n  Interrupted.", Colors.YELLOW)
        all_results = prior
    except Exception as e:
        log(f"\n  Fatal error: {e}", Colors.BOLD_RED)
        if args.verbose:
            import traceback; traceback.print_exc()
        all_results = prior

    elapsed = time.time() - start

    # ── PLUGINS ──────────────────────────────────────────────────────────────
    if all_results and config.get("plugins_enabled", True):
        all_results = run_plugins(config, all_results)

    # ── INTELLIGENCE ─────────────────────────────────────────────────────────
    if all_results:
        all_results = run_intelligence(config, all_results)

    # ── SUMMARY + NEXT STEPS ─────────────────────────────────────────────────
    print_summary(config, all_results)
    print_next_steps(config, all_results)
    # Print scoring table
    if all_results.get("intelligence"):
        from modules.intelligence import IntelligenceEngine
        ie = IntelligenceEngine(config)
        ie.print_score_table(all_results)
    log(f"  Total scan time: {elapsed:.1f}s", Colors.DIM)

    # ── SCOPE VIOLATIONS ─────────────────────────────────────────────────────
    if scope.violations:
        log(f"\n  ⚠  {len(scope.violations)} scope violation(s) blocked:", Colors.YELLOW)
        for v in scope.violations[:5]:
            log(f"    {v}", Colors.DIM)

    # ── REPORT ───────────────────────────────────────────────────────────────
    if all_results:
        log("\n", Colors.RESET)
        log("━"*62, Colors.BOLD_CYAN)
        log("  GENERATING REPORTS", Colors.BOLD_CYAN)
        log("━"*62, Colors.BOLD_CYAN)
        from modules.reporting import ReportingModule
        reporter = ReportingModule(config, all_results)
        paths = reporter.generate(args.report)
        log("\n  Output files:", Colors.BOLD_GREEN)
        for fmt, path in paths.items():
            log(f"    {fmt:<10} {path}", Colors.CYAN)
    else:
        log("  No results to report.", Colors.YELLOW)

    log("", Colors.RESET)
    log("  Run --workflow for the full step-by-step reference.", Colors.DIM)
    log("", Colors.RESET)


if __name__ == "__main__":
    main()
