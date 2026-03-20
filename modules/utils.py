#!/usr/bin/env python3
"""Shared utilities for GhostScan modules."""

import sys
import time
from datetime import datetime


class Colors:
    RESET       = "\033[0m"
    RED         = "\033[91m"
    GREEN       = "\033[92m"
    YELLOW      = "\033[93m"
    BLUE        = "\033[94m"
    MAGENTA     = "\033[95m"
    CYAN        = "\033[96m"
    WHITE       = "\033[97m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"
    BOLD_CYAN   = "\033[1;96m"
    BOLD_RED    = "\033[1;91m"
    BOLD_GREEN  = "\033[1;92m"
    BOLD_YELLOW = "\033[1;93m"


SEVERITY_COLORS = {
    "CRITICAL": Colors.BOLD_RED,
    "HIGH":     Colors.RED,
    "MEDIUM":   Colors.YELLOW,
    "LOW":      Colors.CYAN,
    "INFO":     Colors.DIM,
}


def log(msg, color=Colors.RESET, end="\n"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.DIM}[{ts}]{Colors.RESET} {color}{msg}{Colors.RESET}", end=end)
    sys.stdout.flush()


def log_finding(severity, title, detail="", color=None):
    c = color or SEVERITY_COLORS.get(severity.upper(), Colors.WHITE)
    prefix = {
        "CRITICAL": "!!!",
        "HIGH":     "[!]",
        "MEDIUM":   "[~]",
        "LOW":      "[*]",
        "INFO":     "[-]",
    }.get(severity.upper(), "[?]")
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.DIM}[{ts}]{Colors.RESET} {c}{prefix} [{severity.upper()}] {title}{Colors.RESET}")
    if detail:
        print(f"         {Colors.DIM}{detail}{Colors.RESET}")
    sys.stdout.flush()


def banner():
    art = f"""
{Colors.BOLD_CYAN}
  ██████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓  ██████  ▄████▄   ▄▄▄       ███▄    █
▒██    ▒ ▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █
░ ▓██▄   ▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
  ▒   ██▒░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░   ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
▒██████▒▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒
░ ░▒  ░ ░ ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░    ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
░  ░  ░   ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░      ░  ░  ░  ░          ░   ▒      ░   ░ ░
      ░   ░  ░  ░    ░ ░        ░                  ░  ░ ░             ░  ░         ░
                                                      ░
{Colors.RESET}{Colors.DIM}  Modular Recon & Vuln Detection Framework | Kali Linux
  Use responsibly on systems you own or have explicit permission to test.
{Colors.RESET}"""
    print(art)


def progress(label, current, total, width=40):
    pct = current / total if total else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r{Colors.CYAN}{label}{Colors.RESET} [{Colors.GREEN}{bar}{Colors.RESET}] "
          f"{Colors.BOLD}{current}/{total}{Colors.RESET} ({pct*100:.0f}%)",
          end="", flush=True)
    if current >= total:
        print()


def make_finding(severity, category, title, detail="", url="", evidence="", remediation=""):
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "url": url,
        "evidence": evidence,
        "remediation": remediation,
        "timestamp": datetime.now().isoformat(),
    }
