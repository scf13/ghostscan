#!/usr/bin/env python3
"""
GhostScan - Tool Integration Layer
Wraps all Kali Linux pre-installed security tools with subprocess management.
Gracefully skips unavailable tools and falls back to built-in implementations.
"""

import subprocess
import shutil
import os
import re
import json
import time
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List, Dict

from modules.utils import log, log_finding, Colors, make_finding


# ── TOOL REGISTRY ──────────────────────────────────────────────────────────────
# Maps logical name → binary name(s) to search for
TOOL_REGISTRY = {
    # Recon / OSINT
    "nmap":          ["nmap"],
    "dnsrecon":      ["dnsrecon"],
    "dnsenum":       ["dnsenum"],
    "sublist3r":     ["sublist3r"],
    "amass":         ["amass"],
    "theHarvester":  ["theHarvester", "theharvester"],
    "fierce":        ["fierce"],
    "host":          ["host"],
    "dig":           ["dig"],
    "whois":         ["whois"],

    # Web Analysis
    "nikto":         ["nikto"],
    "whatweb":       ["whatweb"],
    "wafw00f":       ["wafw00f"],
    "gobuster":      ["gobuster"],
    "ffuf":          ["ffuf"],
    "dirb":          ["dirb"],
    "wfuzz":         ["wfuzz"],
    "dirsearch":     ["dirsearch"],
    "feroxbuster":   ["feroxbuster"],
    "wpscan":        ["wpscan"],
    "joomscan":      ["joomscan"],

    # Vuln / Web Attack (detection mode)
    "sqlmap":        ["sqlmap"],
    "nuclei":        ["nuclei"],
    "xssstrike":     ["xsstrike", "XSStrike"],
    "commix":        ["commix"],
    "testssl":       ["testssl", "testssl.sh"],
    "sslscan":       ["sslscan"],
    "sslyze":        ["sslyze"],

    # Network
    "masscan":       ["masscan"],
    "netcat":        ["nc", "ncat", "netcat"],
    "curl":          ["curl"],
    "wget":          ["wget"],

    # Brute-force (online)
    "hydra":         ["hydra"],
    "medusa":        ["medusa"],
    "ncrack":        ["ncrack"],
    "patator":       ["patator"],

    # Brute-force (offline)
    "john":          ["john"],
    "hashcat":       ["hashcat"],
    "haiti":         ["haiti"],

    # SMB / Network services
    "enum4linux":    ["enum4linux", "enum4linux-ng"],
    "smbclient":     ["smbclient"],
    "smbmap":        ["smbmap"],
    "rpcclient":     ["rpcclient"],
    "nbtscan":       ["nbtscan"],
    "crackmapexec":  ["crackmapexec", "cme"],
    "impacket":      ["impacket-secretsdump", "secretsdump.py"],

    # SNMP
    "snmpwalk":      ["snmpwalk"],
    "snmpcheck":     ["snmp-check"],
    "onesixtyone":   ["onesixtyone"],

    # Misc
    "python3":       ["python3"],
    "jq":            ["jq"],
    "unzip":         ["unzip"],
    "gunzip":        ["gunzip"],
}


class ToolRunner:
    """
    Subprocess wrapper for Kali tools.
    - Checks tool availability at init
    - Runs with timeout + streaming output
    - Returns structured results
    """

    def __init__(self, config: dict):
        self.config = config
        self.verbose = config.get("verbose", False)
        self.timeout_default = config.get("tool_timeout", 300)
        self._avail_cache = {}
        self._which_cache = {}

    def available(self, tool: str) -> bool:
        """Check if a tool is installed and executable."""
        if tool in self._avail_cache:
            return self._avail_cache[tool]

        binaries = TOOL_REGISTRY.get(tool, [tool])
        for binary in binaries:
            path = shutil.which(binary)
            if path:
                self._avail_cache[tool] = True
                self._which_cache[tool] = path
                return True

        self._avail_cache[tool] = False
        return False

    def which(self, tool: str) -> Optional[str]:
        """Return full path to tool binary."""
        if not self.available(tool):
            return None
        return self._which_cache.get(tool)

    def run(self, cmd: List[str], timeout: int = None,
            cwd: str = None, env: dict = None,
            live_output: bool = False) -> Tuple[int, str, str]:
        """
        Run a command and return (returncode, stdout, stderr).
        live_output=True prints lines as they arrive.
        """
        timeout = timeout or self.timeout_default
        combined_env = os.environ.copy()
        if env:
            combined_env.update(env)

        if self.verbose:
            log(f"    $ {' '.join(cmd)}", Colors.DIM)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=combined_env,
            )

            stdout_lines = []
            stderr_lines = []

            if live_output:
                import select
                while True:
                    reads = [proc.stdout.fileno(), proc.stderr.fileno()]
                    ret = select.select(reads, [], [], 1.0)
                    for fd in ret[0]:
                        if fd == proc.stdout.fileno():
                            line = proc.stdout.readline()
                            if line:
                                stdout_lines.append(line)
                                if self.verbose:
                                    print(f"    {Colors.DIM}{line.rstrip()}{Colors.RESET}")
                        if fd == proc.stderr.fileno():
                            line = proc.stderr.readline()
                            if line:
                                stderr_lines.append(line)
                    if proc.poll() is not None:
                        # Drain
                        for line in proc.stdout:
                            stdout_lines.append(line)
                        for line in proc.stderr:
                            stderr_lines.append(line)
                        break
                stdout = "".join(stdout_lines)
                stderr = "".join(stderr_lines)
            else:
                stdout, stderr = proc.communicate(timeout=timeout)

            return proc.returncode, stdout, stderr

        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            log(f"    Tool timeout after {timeout}s: {cmd[0]}", Colors.YELLOW)
            return -1, "", f"TIMEOUT after {timeout}s"
        except FileNotFoundError:
            return -2, "", f"Binary not found: {cmd[0]}"
        except Exception as e:
            return -3, "", str(e)

    def tool_inventory(self) -> Dict[str, bool]:
        """Return availability status of all registered tools."""
        return {tool: self.available(tool) for tool in TOOL_REGISTRY}


# ── INDIVIDUAL TOOL WRAPPERS ───────────────────────────────────────────────────

class NmapRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def full_scan(self, target: str, ports: str, scan_type: str = "connect",
                  timeout: int = 600) -> dict:
        """Full nmap scan with service detection, OS detection, NSE scripts."""
        if not self.r.available("nmap"):
            return {"error": "nmap not installed (sudo apt install nmap)"}

        scan_flags = {
            "syn":     ["-sS"],
            "connect": ["-sT"],
            "udp":     ["-sU"],
        }.get(scan_type, ["-sT"])

        cmd = (["nmap"] + scan_flags +
               ["-sV", "--version-intensity", "5",
                "-sC",           # default NSE scripts
                "--script", "banner,http-title,ssl-cert,ssh-hostkey,"
                             "smtp-commands,ftp-anon,smb-os-discovery,"
                             "snmp-info,http-methods,http-server-header",
                "-O",            # OS detection
                "--open",        # only open ports
                "-p", ports,
                "-oX", "-",      # XML output to stdout
                "--host-timeout", "120s",
                "-T4",           # timing
                target])

        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        return self._parse_xml(stdout, rc, stderr)

    def quick_scan(self, target: str) -> dict:
        """Fast scan of top 1000 ports."""
        if not self.r.available("nmap"):
            return {"error": "nmap not installed"}
        cmd = ["nmap", "-sT", "-sV", "--open", "-T4",
               "--top-ports", "1000", "-oX", "-", target]
        rc, stdout, stderr = self.r.run(cmd, timeout=180)
        return self._parse_xml(stdout, rc, stderr)

    def udp_scan(self, target: str, ports: str = "53,67,68,69,111,123,135,137,138,161,162,500,514,520") -> dict:
        """UDP scan for common services."""
        if not self.r.available("nmap"):
            return {"error": "nmap not installed"}
        cmd = ["nmap", "-sU", "--open", "-T4", "-p", ports, "-oX", "-", target]
        rc, stdout, stderr = self.r.run(cmd, timeout=300)
        return self._parse_xml(stdout, rc, stderr)

    def vuln_scan(self, target: str, ports: str) -> dict:
        """nmap vuln NSE scripts."""
        if not self.r.available("nmap"):
            return {"error": "nmap not installed"}
        cmd = ["nmap", "-sT", "-sV", "--script", "vuln",
               "-p", ports, "-oX", "-", target]
        rc, stdout, stderr = self.r.run(cmd, timeout=600)
        return self._parse_xml(stdout, rc, stderr)

    def _parse_xml(self, xml_out: str, rc: int, stderr: str) -> dict:
        """Parse nmap XML output into a clean dict."""
        result = {"hosts": {}, "raw_rc": rc, "error": ""}
        if rc < 0:
            result["error"] = stderr
            return result
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_out)
            for host in root.findall("host"):
                addr_el = host.find("address[@addrtype='ipv4']")
                if addr_el is None:
                    addr_el = host.find("address")
                if addr_el is None:
                    continue
                ip = addr_el.get("addr", "unknown")
                ports_found = {}
                for port_el in host.findall(".//port"):
                    state = port_el.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    portid = int(port_el.get("portid", 0))
                    proto = port_el.get("protocol", "tcp")
                    svc = port_el.find("service")
                    scripts = {}
                    for sc in port_el.findall("script"):
                        scripts[sc.get("id", "")] = sc.get("output", "")
                    ports_found[portid] = {
                        "protocol": proto,
                        "state": "open",
                        "service": svc.get("name", "") if svc is not None else "",
                        "product": svc.get("product", "") if svc is not None else "",
                        "version": svc.get("version", "") if svc is not None else "",
                        "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                        "cpe": svc.get("cpe", "") if svc is not None else "",
                        "scripts": scripts,
                    }
                result["hosts"][ip] = ports_found
        except Exception as e:
            result["error"] = f"XML parse error: {e}"
            # Fall back to grep-style parsing
            result["hosts"] = self._parse_greppable(xml_out)
        return result

    def _parse_greppable(self, output: str) -> dict:
        hosts = {}
        for line in output.splitlines():
            m = re.search(r"(\d+)/open/(\w+)//([^/]*)/", line)
            if m:
                hosts.setdefault("unknown", {})[int(m.group(1))] = {
                    "protocol": m.group(2),
                    "state": "open",
                    "service": m.group(3),
                    "product": "", "version": "", "scripts": {},
                }
        return hosts


class GobusterRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def dir_scan(self, url: str, wordlist: str, extensions: str = "php,html,js,txt,json,xml,bak,zip,gz,tar",
                 threads: int = 50, timeout: int = 300) -> list:
        if not self.r.available("gobuster"):
            return []
        cmd = ["gobuster", "dir",
               "-u", url,
               "-w", wordlist,
               "-t", str(threads),
               "-x", extensions,
               "--no-error",
               "-q",
               "--timeout", "10s",
               "-k",   # skip TLS verification
               ]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        return self._parse_output(stdout)

    def dns_enum(self, domain: str, wordlist: str, threads: int = 50) -> list:
        if not self.r.available("gobuster"):
            return []
        cmd = ["gobuster", "dns",
               "-d", domain,
               "-w", wordlist,
               "-t", str(threads),
               "--no-error",
               "-q"]
        rc, stdout, stderr = self.r.run(cmd, timeout=300)
        results = []
        for line in stdout.splitlines():
            if "Found:" in line:
                parts = line.split()
                if len(parts) >= 2:
                    results.append({"subdomain": parts[-1], "source": "gobuster"})
        return results

    def vhost_enum(self, url: str, domain: str, wordlist: str) -> list:
        if not self.r.available("gobuster"):
            return []
        cmd = ["gobuster", "vhost",
               "-u", url,
               "--domain", domain,
               "-w", wordlist,
               "--no-error", "-q", "-k"]
        rc, stdout, stderr = self.r.run(cmd, timeout=300)
        results = []
        for line in stdout.splitlines():
            if "Found:" in line:
                results.append(line.split("Found:")[-1].strip())
        return results

    def _parse_output(self, output: str) -> list:
        results = []
        for line in output.splitlines():
            # Gobuster format: /path   (Status: 200) [Size: 1234]
            m = re.match(r"^(/[^\s]*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line.strip())
            if m:
                results.append({
                    "path": m.group(1),
                    "status": int(m.group(2)),
                    "size": int(m.group(3)),
                })
            elif line.startswith("/"):
                results.append({"path": line.split()[0], "status": 0, "size": 0})
        return results


class FfufRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def fuzz(self, url: str, wordlist: str, fuzz_keyword: str = "FUZZ",
             filters: str = "", threads: int = 100, timeout: int = 300) -> list:
        """General fuzzing with FFUF."""
        if not self.r.available("ffuf"):
            return []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        cmd = ["ffuf",
               "-u", url if fuzz_keyword in url else f"{url}/{fuzz_keyword}",
               "-w", f"{wordlist}:{fuzz_keyword}",
               "-t", str(threads),
               "-timeout", "10",
               "-of", "json",
               "-o", out_file,
               "-s",  # silent
               "-k",  # insecure TLS
               "-mc", "200,201,204,301,302,307,401,403,405,500",
               ]
        if filters:
            cmd += ["-fc", filters]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        return self._parse_json_output(out_file)

    def param_fuzz(self, url: str, wordlist: str, method: str = "GET") -> list:
        """Fuzz GET/POST parameters."""
        if not self.r.available("ffuf"):
            return []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        if method == "GET":
            target_url = f"{url}?FUZZ=value"
        else:
            target_url = url
        cmd = ["ffuf",
               "-u", target_url,
               "-w", wordlist,
               "-t", "50", "-timeout", "10",
               "-of", "json", "-o", out_file,
               "-s", "-k",
               "-mc", "200,201,204,301,302,307,401,403",
               ]
        if method == "POST":
            cmd += ["-X", "POST", "-d", "FUZZ=value",
                    "-H", "Content-Type: application/x-www-form-urlencoded"]
        rc, stdout, stderr = self.r.run(cmd, timeout=180)
        return self._parse_json_output(out_file)

    def _parse_json_output(self, json_file: str) -> list:
        results = []
        try:
            with open(json_file) as f:
                data = json.load(f)
            for entry in data.get("results", []):
                results.append({
                    "url": entry.get("url", ""),
                    "status": entry.get("status", 0),
                    "length": entry.get("length", 0),
                    "words": entry.get("words", 0),
                    "input": entry.get("input", {}),
                })
        except Exception:
            pass
        try:
            os.unlink(json_file)
        except Exception:
            pass
        return results


class NiktoRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def scan(self, url: str, timeout: int = 300) -> dict:
        if not self.r.available("nikto"):
            return {"error": "nikto not installed (sudo apt install nikto)", "findings": []}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            out_file = f.name
        cmd = ["nikto",
               "-h", url,
               "-o", out_file,
               "-Format", "json",
               "-nointeractive",
               "-maxtime", f"{timeout}s",
               "-timeout", "10",
               "-C", "all",    # Check all CGI dirs
               ]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout + 30)
        findings = self._parse_output(out_file, stdout)
        try:
            os.unlink(out_file)
        except Exception:
            pass
        return {"findings": findings, "raw_rc": rc}

    def _parse_output(self, json_file: str, fallback_stdout: str) -> list:
        findings = []
        try:
            with open(json_file) as f:
                data = json.load(f)
            for vuln in data.get("vulnerabilities", []):
                findings.append({
                    "id": vuln.get("id", ""),
                    "method": vuln.get("method", ""),
                    "url": vuln.get("url", ""),
                    "msg": vuln.get("msg", ""),
                    "references": vuln.get("references", ""),
                })
            return findings
        except Exception:
            pass
        # Parse text output as fallback
        for line in fallback_stdout.splitlines():
            if "+ " in line and ":" in line:
                findings.append({"msg": line.strip(), "url": "", "id": "", "method": ""})
        return findings


class WhatWebRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def scan(self, url: str) -> dict:
        if not self.r.available("whatweb"):
            return {}
        cmd = ["whatweb", "--color=never", "--log-json=-", url]
        rc, stdout, stderr = self.r.run(cmd, timeout=60)
        try:
            data = json.loads(stdout)
            if isinstance(data, list) and data:
                return data[0]
        except Exception:
            pass
        return {"raw": stdout[:500]}


class WafW00fRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def detect(self, url: str) -> dict:
        if not self.r.available("wafw00f"):
            return {"waf": None, "detected": False}
        cmd = ["wafw00f", "-a", "-o", "-", "-f", "json", url]
        rc, stdout, stderr = self.r.run(cmd, timeout=60)
        try:
            data = json.loads(stdout)
            if data:
                return {"waf": data[0].get("waf", None),
                        "manufacturer": data[0].get("manufacturer", ""),
                        "detected": data[0].get("detected", False)}
        except Exception:
            pass
        # Text fallback
        if "is behind" in stdout.lower():
            m = re.search(r"is behind ([^\n]+)", stdout, re.I)
            if m:
                return {"waf": m.group(1).strip(), "detected": True}
        return {"waf": None, "detected": False, "raw": stdout[:200]}


class SqlmapRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def detect(self, url: str, params: str = None,
               level: int = 1, risk: int = 1,
               timeout: int = 300) -> dict:
        """
        Run sqlmap in detection-only mode (no --dump, no --os-shell).
        Returns list of injectable parameters found.
        """
        if not self.r.available("sqlmap"):
            return {"error": "sqlmap not installed (sudo apt install sqlmap)", "findings": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = ["sqlmap",
                   "-u", url,
                   "--level", str(level),
                   "--risk", str(risk),
                   "--batch",          # non-interactive
                   "--timeout", "10",
                   "--retries", "1",
                   "--output-dir", tmpdir,
                   "--forms",          # also test forms
                   "--random-agent",
                   "--technique", "BEUSTQ",  # all techniques
                   "--no-logging",
                   ]
            if params:
                cmd += ["-p", params]

            rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
            return self._parse_output(stdout, stderr)

    def _parse_output(self, stdout: str, stderr: str) -> dict:
        findings = []
        injectable_params = []

        for line in stdout.splitlines():
            if "is vulnerable" in line.lower() or "parameter" in line.lower() and "injectable" in line.lower():
                findings.append(line.strip())
            if re.search(r"Parameter:\s+(.+)\s+\(", line):
                m = re.search(r"Parameter:\s+(.+?)\s+\((.+?)\)", line)
                if m:
                    injectable_params.append({
                        "parameter": m.group(1).strip(),
                        "injection_type": m.group(2).strip(),
                    })

        has_vuln = bool(injectable_params) or any(
            kw in stdout.lower() for kw in
            ["is vulnerable", "sqlmap identified", "injection point(s)"]
        )

        return {
            "vulnerable": has_vuln,
            "injectable_params": injectable_params,
            "findings": findings,
            "raw_excerpt": stdout[-1500:] if stdout else "",
        }


class HydraRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def attack(self, target: str, service: str, userlist: str,
               passlist: str, port: int = None, extra_args: list = None,
               threads: int = 16, timeout: int = 300) -> dict:
        """
        Online brute-force via Hydra.
        Supported services: ssh, ftp, http-get, http-post-form, smb,
                            rdp, telnet, smtp, pop3, imap, mysql, postgres,
                            mssql, vnc, ldap
        """
        if not self.r.available("hydra"):
            return {"error": "hydra not installed (sudo apt install hydra)", "credentials": []}

        cmd = ["hydra",
               "-L", userlist,
               "-P", passlist,
               "-t", str(threads),
               "-f",           # stop after first success
               "-q",
               ]
        if port:
            cmd += ["-s", str(port)]
        if extra_args:
            cmd += extra_args
        cmd += [target, service]

        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        return self._parse_output(stdout, service)

    def http_form_attack(self, url: str, userlist: str, passlist: str,
                         form_params: str, fail_string: str,
                         threads: int = 16, timeout: int = 300) -> dict:
        """Brute-force HTTP POST login form."""
        if not self.r.available("hydra"):
            return {"error": "hydra not installed", "credentials": []}
        from urllib.parse import urlparse
        parsed = urlparse(url)
        target = parsed.netloc
        path = parsed.path or "/"
        service = f"https-post-form" if parsed.scheme == "https" else "http-post-form"
        form_spec = f"{path}:{form_params}:{fail_string}"
        cmd = ["hydra",
               "-L", userlist, "-P", passlist,
               "-t", str(threads), "-f", "-q",
               target, service, "-m", form_spec]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        return self._parse_output(stdout, service)

    def _parse_output(self, stdout: str, service: str) -> dict:
        credentials = []
        for line in stdout.splitlines():
            if "[" in line and "] login:" in line.lower():
                m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line, re.I)
                if m:
                    credentials.append({
                        "username": m.group(1),
                        "password": m.group(2),
                        "service": service,
                    })
                    log_finding("CRITICAL", f"Credential found: {m.group(1)}:{m.group(2)}", service)
        return {"credentials": credentials, "raw_excerpt": stdout[-500:]}


class JohnRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def crack(self, hash_file: str, wordlist: str = None,
              format_hint: str = None, rules: str = "best64",
              timeout: int = 600) -> dict:
        """Offline password cracking with John the Ripper."""
        if not self.r.available("john"):
            return {"error": "john not installed (sudo apt install john)", "cracked": []}
        cmd = ["john", hash_file]
        if wordlist:
            cmd += [f"--wordlist={wordlist}"]
        if format_hint:
            cmd += [f"--format={format_hint}"]
        if rules and wordlist:
            cmd += [f"--rules={rules}"]

        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        # Show results
        show_cmd = ["john", "--show", hash_file]
        if format_hint:
            show_cmd.append(f"--format={format_hint}")
        rc2, show_out, _ = self.r.run(show_cmd, timeout=30)
        return self._parse_output(show_out)

    def identify(self, hash_value: str) -> str:
        """Use haiti or john to identify hash type."""
        if self.r.available("haiti"):
            cmd = ["haiti", hash_value]
            rc, stdout, _ = self.r.run(cmd, timeout=10)
            return stdout.strip()
        # Fallback: length-based guess
        length = len(hash_value.strip())
        guesses = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256",
                   96: "sha384", 128: "sha512"}
        return guesses.get(length, "unknown")

    def _parse_output(self, show_output: str) -> dict:
        cracked = []
        for line in show_output.splitlines():
            if ":" in line and not line.startswith("0 "):
                parts = line.split(":")
                if len(parts) >= 2:
                    cracked.append({"hash": parts[0], "password": parts[1]})
        return {"cracked": cracked, "raw": show_output}


class HashcatRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def crack(self, hash_file: str, hash_mode: int, wordlist: str,
              rules: str = None, timeout: int = 600) -> dict:
        """GPU-accelerated offline cracking with hashcat."""
        if not self.r.available("hashcat"):
            return {"error": "hashcat not installed (sudo apt install hashcat)", "cracked": []}
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            pot_file = f.name
        cmd = ["hashcat",
               "-m", str(hash_mode),
               "-a", "0",       # dictionary attack
               hash_file,
               wordlist,
               "--outfile", pot_file,
               "--outfile-format", "2",  # hash:plain
               "--quiet",
               "--force",       # ignore hardware warnings
               "--status",
               ]
        if rules:
            cmd += ["-r", rules]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        cracked = []
        try:
            with open(pot_file) as f:
                for line in f:
                    if ":" in line:
                        parts = line.strip().split(":")
                        cracked.append({"hash": parts[0], "password": ":".join(parts[1:])})
        except Exception:
            pass
        try:
            os.unlink(pot_file)
        except Exception:
            pass
        return {"cracked": cracked, "raw_rc": rc}


class Enum4LinuxRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def enumerate(self, target: str, timeout: int = 180) -> dict:
        """Full SMB/Windows enumeration via enum4linux-ng."""
        tool = "enum4linux"
        if not self.r.available(tool):
            return {"error": "enum4linux not installed (sudo apt install enum4linux)", "data": {}}
        # Prefer enum4linux-ng if available
        binary = self.r.which(tool)
        cmd = [binary, "-A", "-oJ", "-", target]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        try:
            return {"data": json.loads(stdout), "raw_rc": rc}
        except Exception:
            return {"data": {"raw_output": stdout[:2000]}, "raw_rc": rc}


class DNSReconRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def full_recon(self, domain: str, timeout: int = 180) -> dict:
        if not self.r.available("dnsrecon"):
            return {"error": "dnsrecon not installed (sudo apt install dnsrecon)", "records": []}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        cmd = ["dnsrecon", "-d", domain, "-t", "std,brt,axfr,rvl,snoop",
               "-j", out_file]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        records = []
        try:
            with open(out_file) as f:
                data = json.load(f)
            records = data if isinstance(data, list) else data.get("records", [])
        except Exception:
            pass
        try:
            os.unlink(out_file)
        except Exception:
            pass
        return {"records": records, "raw_rc": rc}


class TheHarvesterRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def harvest(self, domain: str, sources: str = "bing,certspotter,crtsh,dnsdumpster,hackertarget",
                timeout: int = 120) -> dict:
        if not self.r.available("theHarvester"):
            return {"error": "theHarvester not installed (sudo apt install theharvester)",
                    "emails": [], "hosts": []}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        cmd = ["theHarvester", "-d", domain, "-b", sources,
               "-f", out_file.replace(".json", "")]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        result = {"emails": [], "hosts": [], "ips": []}
        try:
            with open(out_file) as f:
                data = json.load(f)
            result["emails"] = data.get("emails", [])
            result["hosts"] = data.get("hosts", [])
            result["ips"] = data.get("interesting_urls", [])
        except Exception:
            # Parse stdout
            for line in stdout.splitlines():
                if "@" in line and "." in line:
                    result["emails"].append(line.strip())
                elif re.match(r"[\w\.-]+\.[a-z]{2,}", line.strip()):
                    result["hosts"].append(line.strip())
        try:
            os.unlink(out_file)
        except Exception:
            pass
        return result


class WpScanRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def scan(self, url: str, userlist: str = None, passlist: str = None,
             timeout: int = 300) -> dict:
        if not self.r.available("wpscan"):
            return {"error": "wpscan not installed (sudo apt install wpscan)", "findings": []}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        cmd = ["wpscan",
               "--url", url,
               "--no-update",
               "--format", "json",
               "--output", out_file,
               "--enumerate", "p,t,u,vp,vt",  # plugins, themes, users, vuln-plugins, vuln-themes
               "--plugins-detection", "mixed",
               ]
        if userlist and passlist:
            cmd += ["--usernames", userlist, "--passwords", passlist,
                    "--password-attack", "wp-login"]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        result = {"findings": [], "plugins": [], "themes": [], "users": []}
        try:
            with open(out_file) as f:
                data = json.load(f)
            for vuln in data.get("vulnerabilities", []):
                result["findings"].append({
                    "title": vuln.get("title", ""),
                    "cve": vuln.get("references", {}).get("cve", []),
                    "severity": "HIGH",
                })
            result["plugins"] = list(data.get("plugins", {}).keys())
            result["themes"] = list(data.get("themes", {}).keys())
            result["users"] = [u.get("username", "") for u in data.get("users", {}).values()]
        except Exception:
            result["raw"] = stdout[:1000]
        try:
            os.unlink(out_file)
        except Exception:
            pass
        return result


class SSLScanRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def scan(self, host: str, port: int = 443, timeout: int = 60) -> dict:
        if not self.r.available("sslscan"):
            return self._testssl_fallback(host, port, timeout)
        cmd = ["sslscan", "--no-colour", "--show-certificate",
               "--xml=-", f"{host}:{port}"]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        return self._parse_sslscan(stdout)

    def _testssl_fallback(self, host: str, port: int, timeout: int) -> dict:
        if not self.r.available("testssl"):
            return {"error": "Neither sslscan nor testssl.sh installed"}
        binary = self.r.which("testssl")
        cmd = [binary, "--jsonfile-pretty", "-", f"{host}:{port}"]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        return {"raw": stdout[:2000], "tool": "testssl"}

    def _parse_sslscan(self, xml_out: str) -> dict:
        result = {"protocols": [], "weak_ciphers": [], "cert_info": {}, "issues": []}
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_out)
            # Protocols
            for proto in root.findall(".//protocol"):
                if proto.get("enabled") == "1":
                    result["protocols"].append(proto.get("type", "") + " " + proto.get("version", ""))
            # Weak protocols
            for name, label in [("ssl2", "SSLv2"), ("ssl3", "SSLv3"), ("tls10", "TLSv1.0"), ("tls11", "TLSv1.1")]:
                el = root.find(f".//protocol[@type='{name.replace('tls','tls').replace('ssl','ssl')}']")
                if el is not None and el.get("enabled") == "1":
                    result["issues"].append(f"Weak protocol enabled: {label}")
        except Exception as e:
            result["error"] = str(e)
        return result


class MasscanRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def scan(self, target: str, ports: str = "0-65535", rate: int = 1000,
             timeout: int = 180) -> dict:
        """
        Fast port scan with masscan.
        Requires root for raw sockets — automatically uses sudo if needed.
        Falls back to list format if JSON parse fails.
        """
        if not self.r.available("masscan"):
            return {"error": "masscan not installed (sudo apt install masscan)", "ports": []}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            out_file = f.name

        # Detect if we need sudo (masscan needs root for raw sockets)
        is_root = (os.geteuid() == 0)

        cmd = []
        if not is_root:
            cmd = ["sudo", "-n"]  # -n = non-interactive, fails if password needed

        cmd += [
            "masscan", target,
            f"-p{ports}",
            f"--rate={rate}",      # Conservative default rate to avoid dropping packets
            "--wait", "5",          # Wait 5s after scan for late replies
            "--open-only",          # Only show open ports
            "-oJ", out_file,
        ]

        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)

        # If sudo failed without password, retry without sudo (some systems allow it)
        if rc != 0 and "sudo" in cmd and ("password" in stderr.lower() or rc == 1):
            cmd_no_sudo = [c for c in cmd if c not in ("sudo", "-n")]
            rc, stdout, stderr = self.r.run(cmd_no_sudo, timeout=timeout)

        ports_found = []
        try:
            with open(out_file) as f:
                raw = f.read().strip()

            if raw:
                # masscan JSON quirk: ends with trailing comma, not valid JSON array
                # Fix: strip trailing comma and wrap in array
                raw = raw.rstrip().rstrip(",")
                if not raw.startswith("["):
                    raw = "[" + raw + "]"
                raw = re.sub(r",\s*\]", "]", raw)  # remove trailing comma before ]

                data = json.loads(raw)
                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    ip = entry.get("ip", target)
                    for port_info in entry.get("ports", []):
                        if isinstance(port_info, dict):
                            ports_found.append({
                                "ip":    ip,
                                "port":  int(port_info.get("port", 0)),
                                "proto": port_info.get("proto", "tcp"),
                                "state": port_info.get("status", "open"),
                            })
        except (json.JSONDecodeError, Exception):
            # Fallback: parse greppable output from stdout
            ports_found = self._parse_greppable(stdout, target)

        try:
            os.unlink(out_file)
        except Exception:
            pass

        if rc not in (0, 1) and not ports_found:
            err = stderr[:200] if stderr else "masscan failed — may need root: sudo ghostscan ..."
            return {"error": err, "ports": [], "raw_rc": rc}

        return {"ports": ports_found, "raw_rc": rc}

    def _parse_greppable(self, output: str, target: str) -> list:
        """Parse masscan text output as fallback."""
        ports = []
        for line in output.splitlines():
            # Format: Discovered open port 80/tcp on 1.2.3.4
            m = re.search(r"port\s+(\d+)/(\w+)\s+on\s+([\d\.]+)", line)
            if m:
                ports.append({
                    "ip":    m.group(3),
                    "port":  int(m.group(1)),
                    "proto": m.group(2),
                    "state": "open",
                })
        return ports


class NucleiRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def scan(self, url: str, severity: str = "critical,high,medium",
             timeout: int = 600) -> dict:
        """Run Nuclei templates against target."""
        if not self.r.available("nuclei"):
            return {"error": "nuclei not installed (sudo apt install nuclei)", "findings": []}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        cmd = ["nuclei",
               "-u", url,
               "-severity", severity,
               "-json-export", out_file,
               "-silent",
               "-no-color",
               "-timeout", "10",
               "-bulk-size", "25",
               "-c", "25",
               "-rl", "50",      # rate limit
               "-retries", "1",
               ]
        rc, stdout, stderr = self.r.run(cmd, timeout=timeout)
        findings = []
        try:
            with open(out_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            findings.append({
                                "template_id": entry.get("template-id", ""),
                                "name": entry.get("info", {}).get("name", ""),
                                "severity": entry.get("info", {}).get("severity", "").upper(),
                                "url": entry.get("matched-at", ""),
                                "description": entry.get("info", {}).get("description", ""),
                                "reference": entry.get("info", {}).get("reference", []),
                            })
                        except Exception:
                            pass
        except Exception:
            pass
        try:
            os.unlink(out_file)
        except Exception:
            pass
        return {"findings": findings, "raw_rc": rc}


class SNMPRunner:
    def __init__(self, runner: ToolRunner):
        self.r = runner

    def walk(self, target: str, community: str = "public",
             oid: str = "1.3.6.1.2.1") -> dict:
        if not self.r.available("snmpwalk"):
            return {"error": "snmpwalk not installed"}
        cmd = ["snmpwalk", "-v2c", "-c", community, target, oid]
        rc, stdout, stderr = self.r.run(cmd, timeout=60)
        return {"output": stdout[:3000], "rc": rc}

    def brute_communities(self, target: str,
                          wordlist: str = "/usr/share/wordlists/snmpcommunities.txt") -> list:
        if not self.r.available("onesixtyone"):
            return []
        if not Path(wordlist).exists():
            communities = ["public", "private", "community", "manager", "admin",
                           "snmp", "snmpd", "cisco", "default", "internal"]
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(communities))
                wordlist = f.name
        cmd = ["onesixtyone", "-c", wordlist, target]
        rc, stdout, stderr = self.r.run(cmd, timeout=60)
        found = []
        for line in stdout.splitlines():
            m = re.search(r"\[(.+?)\]", line)
            if m:
                found.append(m.group(1))
        return found
