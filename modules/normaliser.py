#!/usr/bin/env python3
"""
GhostScan - JSON Normalisation Layer v2
Unified schema for all tool outputs.
Every finding, port, endpoint, credential uses the same structure.
Enables: cross-tool correlation, deduplication, dashboards, APIs.

Standard finding schema:
{
    "id":           "uuid4",
    "type":         "vulnerability",
    "name":         "SQL Injection",
    "severity":     "critical",
    "confidence":   0.9,
    "impact":       10,
    "score":        9.6,
    "exploitability": "pre-auth",
    "source":       "sqlmap",
    "url":          "https://...",
    "evidence":     "...",
    "remediation":  "...",
    "cve":          "CVE-2021-XXXX",
    "timestamp":    "2024-01-01T12:00:00"
}
"""

import uuid
from datetime import datetime
from typing import Optional, Any


def _ts() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _id() -> str:
    return str(uuid.uuid4())


# ── CORE SCHEMAS ──────────────────────────────────────────────────────────────

def finding(severity: str,
            name: str,
            category: str       = "",
            detail: str         = "",
            url: str            = "",
            evidence: str       = "",
            remediation: str    = "",
            confidence: float   = 0.8,
            impact: float       = 5.0,
            exploitability: str = "unknown",
            source: str         = "ghostscan",
            cve: str            = "",
            score: float        = 0.0,
            business_context: str = "",
            tags: list          = None) -> dict:
    """
    Unified vulnerability/finding record.

    exploitability: "pre-auth" | "post-auth" | "physical" | "unknown"
    confidence:     0.0 (speculative) → 1.0 (confirmed)
    impact:         0.0 (none) → 10.0 (full compromise)
    score:          computed if not provided: impact*0.6 + confidence*10*0.4
    """
    valid_sev = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    sev_clean = severity.upper()
    if sev_clean not in valid_sev:
        sev_clean = "INFO"

    if not score:
        score = round((impact * 0.6) + (confidence * 10 * 0.4), 2)

    return {
        "id":               _id(),
        "type":             "vulnerability",
        "name":             str(name),
        "category":         str(category),
        "severity":         sev_clean,
        "confidence":       round(float(confidence), 2),
        "impact":           round(float(impact), 1),
        "score":            round(float(score), 2),
        "exploitability":   str(exploitability),
        "source":           str(source),
        "url":              str(url),
        "detail":           str(detail),
        "evidence":         str(evidence),
        "remediation":      str(remediation),
        "cve":              str(cve),
        "business_context": str(business_context),
        "tags":             tags or [],
        "timestamp":        _ts(),
    }


def port(host: str,
         port_num: int,
         proto: str         = "tcp",
         state: str         = "open",
         service: str       = "",
         product: str       = "",
         version: str       = "",
         banner: str        = "",
         cpe: str           = "",
         source: str        = "") -> dict:
    """Unified open port record."""
    return {
        "id":       _id(),
        "type":     "open_port",
        "host":     str(host),
        "port":     int(port_num),
        "proto":    str(proto).lower(),
        "state":    str(state).lower(),
        "service":  str(service).lower(),
        "product":  str(product),
        "version":  str(version),
        "banner":   str(banner)[:300],
        "cpe":      str(cpe),
        "source":   str(source),
        "timestamp": _ts(),
    }


def subdomain(name: str,
              ips: list       = None,
              source: str     = "",
              wildcard: bool  = False,
              cdn: bool       = False) -> dict:
    """Unified subdomain record."""
    return {
        "id":        _id(),
        "type":      "subdomain",
        "subdomain": str(name).lower().strip("."),
        "ips":       [str(ip) for ip in (ips or [])],
        "source":    str(source),
        "wildcard":  bool(wildcard),
        "cdn":       bool(cdn),
        "timestamp": _ts(),
    }


def endpoint(url: str,
             status: int       = 0,
             size: int         = 0,
             method: str       = "GET",
             content_type: str = "",
             title: str        = "",
             source: str       = "",
             forms: int        = 0,
             js_files: int     = 0) -> dict:
    """Unified web endpoint record."""
    return {
        "id":           _id(),
        "type":         "endpoint",
        "url":          str(url),
        "status":       int(status) if status else 0,
        "size":         int(size) if size else 0,
        "method":       str(method).upper(),
        "content_type": str(content_type),
        "title":        str(title),
        "forms":        int(forms),
        "js_files":     int(js_files),
        "source":       str(source),
        "timestamp":    _ts(),
    }


def credential(username: str,
               password: str,
               service: str,
               host: str    = "",
               port_num: int = 0,
               source: str  = "hydra",
               hash_type: str = "") -> dict:
    """Unified credential record."""
    return {
        "id":        _id(),
        "type":      "credential",
        "username":  str(username),
        "password":  str(password),
        "service":   str(service),
        "host":      str(host),
        "port":      int(port_num) if port_num else 0,
        "hash_type": str(hash_type),
        "source":    str(source),
        "timestamp": _ts(),
    }


def dns_record(rtype: str,
               name: str,
               value: str,
               ttl: int    = 0,
               source: str = "") -> dict:
    """Unified DNS record."""
    return {
        "id":        _id(),
        "type":      "dns_record",
        "rtype":     str(rtype).upper(),
        "name":      str(name).lower().strip("."),
        "value":     str(value),
        "ttl":       int(ttl),
        "source":    str(source),
        "timestamp": _ts(),
    }


def screenshot(url: str,
               filepath: str,
               title: str   = "",
               source: str  = "playwright",
               width: int   = 0,
               height: int  = 0) -> dict:
    """Unified screenshot record."""
    return {
        "id":        _id(),
        "type":      "screenshot",
        "url":       str(url),
        "filepath":  str(filepath),
        "title":     str(title),
        "source":    str(source),
        "width":     int(width),
        "height":    int(height),
        "timestamp": _ts(),
    }


def service(host: str,
            service_name: str,
            port_num: int,
            banner: str  = "",
            version: str = "",
            source: str  = "") -> dict:
    """Unified service record (higher-level than raw port)."""
    return {
        "id":       _id(),
        "type":     "service",
        "host":     str(host),
        "service":  str(service_name).lower(),
        "port":     int(port_num),
        "banner":   str(banner)[:500],
        "version":  str(version),
        "source":   str(source),
        "timestamp": _ts(),
    }


# ── CONVERTERS ────────────────────────────────────────────────────────────────

def from_nmap_port(host: str, port_data: dict) -> dict:
    return port(
        host     = host,
        port_num = port_data.get("port", 0),
        proto    = port_data.get("protocol", "tcp"),
        state    = port_data.get("state", "open"),
        service  = port_data.get("service", ""),
        product  = port_data.get("product", ""),
        version  = port_data.get("version", ""),
        cpe      = port_data.get("cpe", ""),
        source   = "nmap",
    )


def from_masscan(entry: dict) -> dict:
    return port(
        host     = entry.get("ip", ""),
        port_num = entry.get("port", 0),
        proto    = entry.get("proto", "tcp"),
        state    = entry.get("state", "open"),
        source   = "masscan",
    )


def from_gobuster(base_url: str, result: dict) -> dict:
    path = result.get("path", "")
    return endpoint(
        url    = base_url.rstrip("/") + path,
        status = result.get("status", 0),
        size   = result.get("size", 0),
        source = "gobuster",
    )


def from_nikto(finding_data: dict, base_url: str) -> dict:
    msg = finding_data.get("msg", "")
    sev = "HIGH" if any(kw in msg.lower() for kw in ["rce","injection","shell"]) else "MEDIUM"
    return finding(
        severity = sev,
        name     = msg[:120],
        category = "Nikto",
        url      = base_url + finding_data.get("url", ""),
        source   = "nikto",
        confidence = 0.7,
    )


def from_nuclei(finding_data: dict) -> dict:
    return finding(
        severity  = finding_data.get("severity", "MEDIUM").upper(),
        name      = f"{finding_data.get('name','')} [{finding_data.get('template_id','')}]",
        category  = "Nuclei",
        detail    = finding_data.get("description", ""),
        url       = finding_data.get("url", ""),
        source    = "nuclei",
        cve       = finding_data.get("template_id","") if "CVE" in finding_data.get("template_id","").upper() else "",
        confidence = 0.85,
    )


def from_sqlmap(result: dict, url: str) -> list:
    results = []
    for p in result.get("injectable_params", []):
        results.append(finding(
            severity      = "CRITICAL",
            name          = f"SQL Injection: {p.get('parameter')} ({p.get('injection_type')})",
            category      = "SQLi",
            url           = url,
            remediation   = "Use prepared statements/parameterised queries.",
            source        = "sqlmap",
            confidence    = 0.95,
            impact        = 10.0,
            exploitability = "pre-auth",
            score         = 9.6,
        ))
    return results


def from_hydra(cred: dict) -> dict:
    return credential(
        username = cred.get("username", ""),
        password = cred.get("password", ""),
        service  = cred.get("service", ""),
        source   = "hydra",
    )


# ── BATCH NORMALISATION ───────────────────────────────────────────────────────

def normalise_all_ports(open_ports: dict) -> list:
    records = []
    for host, ports in open_ports.items():
        for p, info in ports.items():
            records.append(port(
                host     = host,
                port_num = int(p),
                proto    = info.get("protocol", "tcp"),
                state    = info.get("state", "open"),
                service  = info.get("service", ""),
                product  = info.get("product", ""),
                version  = info.get("version", ""),
                source   = "scan",
            ))
    return records


def normalise_results(all_results: dict) -> dict:
    """Convert full scan results into a clean, unified JSON schema."""
    recon = all_results.get("recon", {})
    web   = all_results.get("web", {})

    all_findings = []
    seen_ids     = set()
    for section in ("recon", "web", "vuln"):
        for f in all_results.get(section, {}).get("findings", []):
            key = f"{f.get('severity')}{f.get('title')}{f.get('url')}"
            if key not in seen_ids:
                seen_ids.add(key)
                all_findings.append(finding(
                    severity       = f.get("severity", "INFO"),
                    name           = f.get("title", ""),
                    category       = f.get("category", ""),
                    detail         = f.get("detail", ""),
                    url            = f.get("url", ""),
                    evidence       = f.get("evidence", ""),
                    remediation    = f.get("remediation", ""),
                    source         = f.get("source", "ghostscan"),
                    cve            = f.get("cve", ""),
                    confidence     = f.get("_confidence", 0.8),
                    impact         = f.get("_impact", 5.0),
                ))

    return {
        "meta": {
            "schema":    "ghostscan-v3",
            "version":   "3.0",
            "target":    recon.get("target", ""),
            "timestamp": _ts(),
        },
        "summary": {
            sev: sum(1 for f in all_findings if f.get("severity") == sev)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
        "findings":    all_findings,
        "ports":       normalise_all_ports(recon.get("open_ports", {})),
        "subdomains": [
            subdomain(s.get("subdomain",""), s.get("ips",[]), s.get("source",""))
            for s in recon.get("subdomains", [])
        ],
        "endpoints": [
            endpoint(url, source="crawl")
            for url in web.get("endpoints", [])
        ],
        "dns_records": [
            dns_record(rtype, recon.get("target",""), val)
            for rtype, vals in recon.get("dns_records", {}).items()
            for val in vals
        ],
        "technologies": web.get("technologies", {}),
        "js_secrets":   web.get("js_secrets", []),
        "waf":          web.get("waf", {}),
        "screenshots":  web.get("screenshots", []),
    }


# ── LEGACY COMPAT (old name) ──────────────────────────────────────────────────
# Keep old function names working for existing code

def normalise_finding(*args, **kwargs):  return finding(*args, **kwargs)
def normalise_port(*args, **kwargs):     return port(*args, **kwargs)
def normalise_endpoint(*args, **kwargs): return endpoint(*args, **kwargs)
