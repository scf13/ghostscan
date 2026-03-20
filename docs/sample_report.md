# GhostScan Security Assessment Report

---

| Field | Value |
|-------|-------|
| **Target** | `example.com` |
| **Date** | 2026-03-20 |
| **Framework** | GhostScan v3.0 |
| **Risk Level** | 🔴 **HIGH** |
| **Total Findings** | 14 |
| **Duration** | 12m 34s |

---

## Executive Summary

GhostScan conducted a full-scope automated security assessment against `example.com` and its associated infrastructure. The scan identified **3 critical**, **4 high**, **4 medium**, and **3 low** severity findings.

The most significant risks include a hardcoded AWS Access Key exposed in client-side JavaScript, a `.env` file accessible without authentication containing database credentials, and SQL injection in the search parameter. These findings collectively represent a path to full application and database compromise with no prior authentication required.

**Immediate action is required on CRITICAL findings before continued operation.**

---

## Attack Surface Summary

| Category | Value |
|----------|-------|
| Subdomains discovered | 12 |
| Open TCP ports | 22, 80, 443, 8080 |
| Technologies detected | PHP 8.1, Apache 2.4.49, MySQL 8.0, WordPress 6.4 |
| WAF detected | None |
| SSL/TLS | TLSv1.2 + TLSv1.3 |
| Endpoints crawled | 847 |
| Forms found | 14 |
| JS files analysed | 23 |
| Brute-force wordlist | raft-large-directories (221,558 entries) |

---

## Correlation Engine Results

> These are compound risks automatically detected by GhostScan's intelligence engine.

### 🔴 [CRITICAL] Login Panel + No Rate Limiting = Brute-force Ready
- **Login endpoint:** `https://example.com/wp-login.php` (HTTP 200)
- **Evidence:** 50 rapid login attempts completed with no lockout, no CAPTCHA
- **Attack path:** Enumerate valid usernames via `?author=1` → spray with `rockyou.txt`
- **Score:** 96/100

### 🔴 [CRITICAL] Hardcoded Secret + No WAF = Direct Cloud Access
- **AWS Key in JS:** `app.min.js` → `AKIA4EXAMPLE1234ABCD`
- **Evidence:** Key validated via `aws sts get-caller-identity` → Account ID: `123456789012`
- **Attack path:** Download JS → extract key → `aws s3 ls` → full S3 bucket access
- **Score:** 99/100

### 🔴 [CRITICAL] SQLi + Missing CSP = Credential Dump + Session Theft
- **SQLi parameter:** `?search=` (boolean-based blind)
- **Missing header:** `Content-Security-Policy`
- **Attack path:** SQLi → dump `wp_users` table → crack hashes → admin login → RCE via plugin upload
- **Score:** 97/100

---

## Key Findings

### 🔴 [CRITICAL] AWS Access Key Exposed in JavaScript

| Field | Detail |
|-------|--------|
| **URL** | `https://example.com/assets/js/app.min.js` |
| **Type** | Hardcoded AWS Access Key |
| **Evidence** | `AKIA4EXAMPLE1234ABCD` (line 847) |
| **Impact** | Full AWS account access — S3 buckets, EC2, IAM, RDS |
| **CVSS** | 9.8 (Critical) |
| **Score** | 99/100 |

**Evidence:**
```javascript
// app.min.js line 847
const AWS_ACCESS_KEY="AKIA4EXAMPLE1234ABCD";
const AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const S3_BUCKET="production-user-uploads";
```

**Recommendation:**
Remove all secrets from client-side code immediately. Use server-side environment variables. Rotate the exposed key now — assume it has already been harvested by automated scanners. Implement a secrets scanner (e.g. `truffleHog`, `gitleaks`) in your CI/CD pipeline.

---

### 🔴 [CRITICAL] .env File Publicly Accessible

| Field | Detail |
|-------|--------|
| **URL** | `https://example.com/.env` |
| **Status** | HTTP 200 |
| **Size** | 1,247 bytes |
| **Impact** | Full database credential disclosure, API key exposure |
| **CVSS** | 9.1 (Critical) |
| **Score** | 98/100 |

**Evidence:**
```
APP_ENV=production
APP_KEY=base64:SomeBase64EncodedKeyHere==
DB_HOST=127.0.0.1
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD=Sup3rS3cur3P@ss!
STRIPE_SECRET=sk_live_EXAMPLE123456
MAIL_PASSWORD=gmail_app_password_here
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY
```

**Recommendation:**
Block access to `.env` files via web server configuration immediately:

```nginx
# Nginx
location ~ /\. { deny all; }

# Apache (.htaccess)
<Files ".env">
    Order allow,deny
    Deny from all
</Files>
```

---

### 🔴 [CRITICAL] SQL Injection — Search Parameter

| Field | Detail |
|-------|--------|
| **URL** | `https://example.com/search?q=test` |
| **Parameter** | `q` |
| **Type** | Boolean-based blind SQLi |
| **Backend** | MySQL 8.0.32 |
| **Impact** | Full database extraction, potential RCE via `INTO OUTFILE` |
| **CVSS** | 9.8 (Critical) |
| **Score** | 97/100 |

**Evidence:**
```
Request:  GET /search?q=test' AND 1=1-- HTTP/1.1
Response: 200 OK — 14,832 bytes (normal results)

Request:  GET /search?q=test' AND 1=2-- HTTP/1.1
Response: 200 OK — 2,341 bytes (empty results)
```
Boolean difference confirms injectable parameter.

**sqlmap verification:**
```bash
sqlmap -u 'https://example.com/search?q=test' --level=3 --risk=2 --batch --dbs
# [*] Available databases: information_schema, production_db, wordpress
```

**Recommendation:**
Replace all raw SQL queries with prepared statements / parameterised queries:
```php
// Vulnerable
$query = "SELECT * FROM posts WHERE title LIKE '%" . $_GET['q'] . "%'";

// Fixed
$stmt = $pdo->prepare("SELECT * FROM posts WHERE title LIKE ?");
$stmt->execute(["%{$_GET['q']}%"]);
```

---

### 🔴 [HIGH] WordPress 6.4 — Vulnerable Plugin Detected

| Field | Detail |
|-------|--------|
| **Plugin** | `wp-file-manager` v6.0 |
| **CVE** | CVE-2020-25213 |
| **Impact** | Unauthenticated Remote Code Execution |
| **CVSS** | 9.8 (Critical) — detected as HIGH due to version uncertainty |
| **Score** | 88/100 |

**Evidence:**
```
GET /wp-content/plugins/wp-file-manager/readme.txt HTTP/1.1
→ Stable tag: 6.0
```

**Recommendation:**
Update `wp-file-manager` to the latest version immediately. Consider removing if not required. Run:
```bash
wpscan --url https://example.com --enumerate vp --plugins-detection aggressive
```

---

### 🟠 [HIGH] RDP Exposed on Port 3389

| Field | Detail |
|-------|--------|
| **Host** | `192.168.1.10` |
| **Port** | 3389/tcp |
| **Service** | Microsoft Terminal Services |
| **Impact** | BlueKeep (CVE-2019-0708) risk, brute-force surface |
| **Score** | 85/100 |

**Recommendation:**
Restrict RDP to VPN only. Enable Network Level Authentication (NLA). Apply all Windows security patches. Consider moving to a VPN + jump host architecture.

---

### 🟠 [HIGH] SMB Exposed — Signing Disabled

| Field | Detail |
|-------|--------|
| **Host** | `192.168.1.10` |
| **Port** | 445/tcp |
| **Issue** | SMB signing disabled |
| **Impact** | NTLM relay attacks possible — potential domain compromise |
| **Score** | 82/100 |

**Attack path:** Responder → capture Net-NTLMv2 hash → relay to SMB → authenticated access without cracking

**Recommendation:**
Enable SMB signing via Group Policy:
`Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Microsoft network server: Digitally sign communications (always) → Enabled`

---

### 🟠 [MEDIUM] Missing Security Headers (6 of 6 Missing)

| Header | Risk |
|--------|------|
| `Strict-Transport-Security` | Downgrade/MITM attacks |
| `Content-Security-Policy` | XSS amplification |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME sniffing |
| `Referrer-Policy` | Internal URL leakage |
| `Permissions-Policy` | Browser feature abuse |

**Recommendation — add to Apache/Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{RANDOM}'";
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()";
```

---

### 🟠 [MEDIUM] Session Cookie — Missing Secure Flags

| Cookie | Missing Flags |
|--------|--------------|
| `PHPSESSID` | `Secure`, `HttpOnly`, `SameSite` |
| `wordpress_logged_in_*` | `Secure`, `SameSite` |

**Recommendation:**
```php
session_set_cookie_params([
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
```

---

### 🟠 [MEDIUM] Swagger/OpenAPI Specification Exposed

| Field | Detail |
|-------|--------|
| **URL** | `https://example.com/api/swagger.json` |
| **Impact** | Full API surface documented publicly — simplifies targeted attacks |
| **Endpoints exposed** | 47 API routes including `/api/v1/admin/users` |

---

### 🟡 [LOW] Server Version Disclosure

| Header | Value |
|--------|-------|
| `Server` | `Apache/2.4.49 (Ubuntu)` |
| `X-Powered-By` | `PHP/8.1.2` |

Apache 2.4.49 is affected by **CVE-2021-41773** (path traversal / RCE). Immediately patch to 2.4.51+.

```nginx
# Hide server version
ServerTokens Prod
ServerSignature Off
```

---

### 🟡 [LOW] TLSv1.0 and TLSv1.1 Enabled

**Recommendation:** Disable legacy TLS protocols:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
```

---

### 🟡 [LOW] Directory Listing Enabled

| URL | Status |
|-----|--------|
| `https://example.com/uploads/` | 200 — full listing |
| `https://example.com/backups/` | 200 — full listing |

---

## Open Ports

| Port | Service | Version | Risk |
|------|---------|---------|------|
| 22 | SSH | OpenSSH 8.2 | MEDIUM — test auth methods |
| 80 | HTTP | Apache 2.4.49 | HIGH — see CVE-2021-41773 |
| 443 | HTTPS | Apache 2.4.49 | HIGH — see CVE-2021-41773 |
| 3389 | RDP | MS Terminal Services | HIGH — restrict to VPN |
| 8080 | HTTP | Tomcat 9.0.50 | MEDIUM — admin panel at /manager |

---

## Subdomains Discovered (12)

| Subdomain | IPs | Notes |
|-----------|-----|-------|
| `dev.example.com` | 192.168.1.20 | Staging — identical codebase, less hardened |
| `admin.example.com` | 192.168.1.10 | Admin panel — HTTP Basic Auth |
| `api.example.com` | 192.168.1.11 | REST API — no rate limiting |
| `mail.example.com` | 192.168.1.5 | Roundcube webmail |
| `vpn.example.com` | 192.168.1.1 | OpenVPN — test default creds |
| `staging.example.com` | 192.168.1.20 | Old WordPress, unpatched |
| `jenkins.example.com` | 192.168.1.30 | CI/CD — anonymous read access |
| `gitlab.example.com` | 192.168.1.31 | Source code — registration open |
| `db.example.com` | — | DNS resolves — port 3306 open externally |
| `backup.example.com` | — | HTTP 403 — directory listing attempts |
| `monitor.example.com` | 192.168.1.40 | Grafana — default admin:admin |
| `cdn.example.com` | CDN | Static assets |

---

## Adaptive Next Steps

> Generated by GhostScan intelligence engine based on scan findings.

1. **[CRITICAL] Rotate AWS key immediately** — assume already harvested
   ```bash
   aws iam delete-access-key --access-key-id AKIA4EXAMPLE1234ABCD
   ```

2. **[CRITICAL] Exploit SQLi to assess data exposure**
   ```bash
   sqlmap -u 'https://example.com/search?q=test' --level=5 --risk=3 --batch --dbs --dump
   ```

3. **[CRITICAL] Test WordPress plugin CVE-2020-25213**
   ```bash
   searchsploit wp-file-manager 6.0
   nuclei -u https://example.com -tags CVE-2020-25213
   ```

4. **[HIGH] Brute-force WordPress login (no rate limit confirmed)**
   ```bash
   wpscan --url https://example.com --passwords /usr/share/wordlists/rockyou.txt --usernames admin,editor
   ```

5. **[HIGH] Test Jenkins for anonymous access → RCE**
   ```bash
   curl -sk https://jenkins.example.com/api/json | jq .
   # If accessible → script console → RCE
   ```

6. **[HIGH] Test Grafana default credentials**
   ```bash
   curl -sk https://monitor.example.com/api/org -u admin:admin | jq .
   ```

---

## Remediation Priority

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 🔴 P1 — Immediate | Rotate exposed AWS key | Low | Critical |
| 🔴 P1 — Immediate | Remove/restrict `.env` file | Low | Critical |
| 🔴 P1 — Immediate | Fix SQL injection | Medium | Critical |
| 🔴 P2 — This week | Update wp-file-manager plugin | Low | Critical |
| 🟠 P2 — This week | Add all security headers | Low | High |
| 🟠 P2 — This week | Restrict RDP to VPN | Low | High |
| 🟠 P3 — This month | Enable SMB signing | Low | High |
| 🟡 P3 — This month | Disable TLSv1.0/1.1 | Low | Medium |
| 🟡 P4 — Backlog | Fix cookie flags | Low | Medium |
| 🟡 P4 — Backlog | Disable directory listing | Low | Low |

---

## Tool Chain Used

```
nmap 7.94          → Port discovery, service detection, NSE scripts
gobuster 3.6        → Directory brute-force (raft-large-directories)
nikto 2.1.6         → Web vulnerability scanning
sqlmap 1.7.8        → SQL injection detection
wpscan 3.8.24       → WordPress enumeration
nuclei 2.9.15       → CVE template scanning
wafw00f 2.2.0       → WAF detection
whatweb 0.5.5       → Technology fingerprinting
sslscan 2.0.15      → SSL/TLS analysis
sublist3r 1.1       → Subdomain enumeration
theHarvester 4.4.3  → OSINT email/host harvesting
dnsrecon 1.1.4      → DNS enumeration
```

---

*Report generated by GhostScan v3.0 — For authorized security testing only.*
*Classification: CONFIDENTIAL — Do not distribute without authorization.*
