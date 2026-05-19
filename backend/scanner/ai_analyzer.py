import json
from anthropic import Anthropic

client = Anthropic()

SYSTEM = """You are an expert penetration tester on Kali Linux performing a real security assessment.
You MUST find and report ALL vulnerabilities including CRITICAL and HIGH severity issues.
Be aggressive in your analysis - do not downgrade severity.
Return ONLY a valid JSON array. No markdown, no explanation."""

OWASP_2025 = """
OWASP Top 10 2025 - use these exact codes:
A01:2025 - Broken Access Control
A02:2025 - Security Misconfiguration  
A03:2025 - Software Supply Chain Failures
A04:2025 - Cryptographic Failures
A05:2025 - Injection
A06:2025 - Insecure Design
A07:2025 - Authentication Failures
A08:2025 - Data Integrity Failures
A09:2025 - Security Logging & Alerting Failures
A10:2025 - Mishandling of Exceptional Conditions
"""

def analyze(probe_data):
    try:
        http = probe_data.get("http", {})
        dns  = probe_data.get("dns", {})
        ports = probe_data.get("ports", {})
        nikto = probe_data.get("nikto", {})
        tech  = probe_data.get("technologies", {})
        tls   = http.get("tls", {})

        prompt = f"""You are performing a real penetration test. Analyze ALL of this scan data carefully.

{OWASP_2025}

TARGET: {probe_data.get("target_url")}
HOSTNAME: {probe_data.get("hostname")}

=== HTTP PROBE RESULTS ===
Status Code: {http.get("status_code")}
Final URL: {http.get("final_url")}
Redirect Chain: {http.get("redirect_chain", [])}

Missing Security Headers: {http.get("missing_security_headers", [])}
Info Disclosure Headers: {http.get("info_disclosure_headers", {})}
Cookies: {http.get("cookies", [])}

=== TLS/SSL RESULTS ===
Protocol: {tls.get("protocol", "Unknown")}
Cipher: {tls.get("cipher_suite", "Unknown")}
Days Until Expiry: {tls.get("days_until_expiry", "Unknown")}
TLS Error: {tls.get("error", "None")}

=== DNS RESULTS ===
A Records: {dns.get("a_records", [])}
SPF Record: {dns.get("spf", "MISSING")}
DMARC Record: {dns.get("dmarc", "MISSING")}
DNSSEC: {dns.get("dnssec", False)}
DNS Errors: {dns.get("errors", [])}

=== NMAP PORT SCAN ===
Open Ports: {json.dumps(ports.get("open_ports", []), default=str)}
Risky Ports: {json.dumps(ports.get("risky_ports", []), default=str)}
Service Versions: {ports.get("service_versions", [])}
OS Guess: {ports.get("os_guess", "Unknown")}
Nmap Errors: {ports.get("errors", [])}

=== NIKTO WEB SCAN ===
Total Issues Found: {nikto.get("total_issues", 0)}
Nikto Findings: {json.dumps(nikto.get("findings", []), default=str)}
Nikto Errors: {nikto.get("errors", [])}

=== TECHNOLOGY FINGERPRINT ===
Technologies Detected: {tech.get("technologies", [])}

=== YOUR TASK ===
Analyze ALL the above data and generate a comprehensive list of security findings.

CRITICAL RULES:
1. If Nikto found issues - each one should become a finding (CRITICAL or HIGH severity)
2. If risky ports are open (MySQL 3306, Redis 6379, MongoDB 27017, etc) - mark as CRITICAL
3. If TLS 1.0 or TLS 1.1 is enabled - mark as HIGH
4. If no HTTPS / plain HTTP only - mark as HIGH  
5. If server version disclosed (Apache/2.4.x, IIS/8.5, etc) - mark as MEDIUM
6. If cookies missing Secure+HttpOnly+SameSite - mark as MEDIUM per cookie
7. If SPF missing - MEDIUM, if DMARC missing - MEDIUM
8. If no security headers - MEDIUM each
9. Look for SQL injection indicators in Nikto findings - mark as CRITICAL
10. Look for file inclusion, XSS, RCE indicators - mark as CRITICAL
11. If using outdated software versions - mark as HIGH with CVE if known

Return a JSON array where each finding has:
{{
  "severity": "critical|high|medium|low|info",
  "category": "one of: Injection|TLS|Headers|Cookies|DNS|Ports|Auth|Config|Nikto|Supply Chain|Error Handling",
  "title": "Clear specific title",
  "description": "2-3 sentences explaining the real risk and impact",
  "evidence": "Exact proof from the scan data above",
  "cve": "CVE-XXXX-XXXXX if applicable or null",
  "cwe": "CWE-XXX",
  "owasp": "AXX:2025 - Category Name",
  "recommendation": "Specific actionable fix with example"
}}

Generate AT LEAST 8-15 findings. Order by severity: critical first, then high, medium, low, info.
Be specific - use the actual data from the scan. Reference real port numbers, header names, service versions.
"""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4000,
            system=SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text.strip()
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("["):
                    text = part
                    break
        text = text.strip()
        if not text.startswith("["):
            start = text.find("[")
            if start != -1:
                text = text[start:]
        return json.loads(text)

    except Exception as e:
        return _fallback_analyze(probe_data, str(e))


def _fallback_analyze(probe_data, error_msg):
    findings = []
    http  = probe_data.get("http", {})
    dns   = probe_data.get("dns", {})
    ports = probe_data.get("ports", {})
    nikto = probe_data.get("nikto", {})
    tls   = http.get("tls", {})

    # Nikto findings → Critical/High
    for f in nikto.get("findings", []):
        msg = f.get("msg", "").lower()
        sev = "high"
        if any(x in msg for x in ["sql", "injection", "rce", "exec", "shell", "upload", "traversal"]):
            sev = "critical"
        findings.append({
            "severity": sev,
            "category": "Nikto",
            "title": "Nikto: " + f.get("msg", "")[:60],
            "description": "Nikto web scanner detected: " + f.get("msg", ""),
            "evidence": f.get("url", "") + " - " + f.get("msg", ""),
            "cve": None,
            "cwe": "CWE-16",
            "owasp": "A05:2025 - Injection" if sev == "critical" else "A02:2025 - Security Misconfiguration",
            "recommendation": "Investigate and remediate the issue found by Nikto immediately.",
        })

    # Risky open ports → Critical
    for p in ports.get("risky_ports", []):
        findings.append({
            "severity": "critical" if p["port"] in [3306, 27017, 6379, 5432, 2375] else "high",
            "category": "Ports",
            "title": "Risky Port Exposed: " + str(p["port"]) + " (" + p["label"] + ")",
            "description": p["label"] + " on port " + str(p["port"]) + " is publicly accessible. This allows direct database/service attacks.",
            "evidence": "nmap found port " + str(p["port"]) + "/tcp open - " + p["label"],
            "cve": None,
            "cwe": "CWE-284",
            "owasp": "A01:2025 - Broken Access Control",
            "recommendation": "Immediately restrict port " + str(p["port"]) + " with firewall rules. Only allow trusted IPs.",
        })

    # TLS issues → High
    protocol = tls.get("protocol", "")
    if protocol in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
        findings.append({
            "severity": "high",
            "category": "TLS",
            "title": "Weak TLS Protocol: " + protocol,
            "description": protocol + " is deprecated and vulnerable to POODLE and BEAST attacks.",
            "evidence": "TLS handshake negotiated: " + protocol,
            "cve": "CVE-2014-3566",
            "cwe": "CWE-326",
            "owasp": "A04:2025 - Cryptographic Failures",
            "recommendation": "Disable " + protocol + ". Only allow TLS 1.2 and TLS 1.3.",
        })

    # Cert expiry
    days = tls.get("days_until_expiry")
    if days is not None and days < 30:
        findings.append({
            "severity": "high" if days < 7 else "medium",
            "category": "TLS",
            "title": "SSL Certificate Expires in " + str(days) + " Days",
            "description": "Certificate is about to expire causing service disruption.",
            "evidence": "Certificate expiry: " + str(days) + " days remaining",
            "cve": None,
            "cwe": "CWE-298",
            "owasp": "A04:2025 - Cryptographic Failures",
            "recommendation": "Renew SSL certificate immediately.",
        })

    # Missing security headers → Medium
    for h in http.get("missing_security_headers", []):
        findings.append({
            "severity": "medium",
            "category": "Headers",
            "title": "Missing Security Header: " + h,
            "description": "The " + h + " header is absent. This weakens browser security protections.",
            "evidence": "HTTP response missing header: " + h,
            "cve": None,
            "cwe": "CWE-693",
            "owasp": "A02:2025 - Security Misconfiguration",
            "recommendation": "Add " + h + " header to all HTTP responses.",
        })

    # Info disclosure → Medium
    for h, v in http.get("info_disclosure_headers", {}).items():
        findings.append({
            "severity": "medium",
            "category": "Config",
            "title": "Server Info Disclosure: " + h,
            "description": "The " + h + " header reveals technology stack details to attackers.",
            "evidence": h + ": " + v,
            "cve": None,
            "cwe": "CWE-200",
            "owasp": "A02:2025 - Security Misconfiguration",
            "recommendation": "Remove or obscure the " + h + " header in server config.",
        })

    # Cookie issues → Medium
    for cookie in http.get("cookies", []):
        if not cookie.get("httponly"):
            findings.append({
                "severity": "medium",
                "category": "Cookies",
                "title": "Cookie Missing HttpOnly Flag",
                "description": "Session cookie accessible via JavaScript enabling XSS-based session hijacking.",
                "evidence": cookie.get("raw", "")[:120],
                "cve": None,
                "cwe": "CWE-1004",
                "owasp": "A07:2025 - Authentication Failures",
                "recommendation": "Set HttpOnly flag on all session cookies.",
            })
        if not cookie.get("secure"):
            findings.append({
                "severity": "medium",
                "category": "Cookies",
                "title": "Cookie Missing Secure Flag",
                "description": "Cookie transmitted over unencrypted HTTP allowing interception.",
                "evidence": cookie.get("raw", "")[:120],
                "cve": None,
                "cwe": "CWE-614",
                "owasp": "A07:2025 - Authentication Failures",
                "recommendation": "Set Secure flag on all cookies.",
            })

    # DNS issues → Medium
    if not dns.get("spf"):
        findings.append({
            "severity": "medium",
            "category": "DNS",
            "title": "Missing SPF Record",
            "description": "No SPF record allows attackers to send spoofed emails from this domain.",
            "evidence": "DNS TXT query returned no v=spf1 record",
            "cve": None,
            "cwe": "CWE-290",
            "owasp": "A05:2025 - Injection",
            "recommendation": "Add TXT record: v=spf1 include:your-mail-provider.com ~all",
        })

    if not dns.get("dmarc"):
        findings.append({
            "severity": "medium",
            "category": "DNS",
            "title": "Missing DMARC Record",
            "description": "No DMARC policy allows phishing emails to pass authentication checks.",
            "evidence": "No v=DMARC1 record found on _dmarc." + probe_data.get("hostname",""),
            "cve": None,
            "cwe": "CWE-290",
            "owasp": "A05:2025 - Injection",
            "recommendation": "Add: v=DMARC1; p=quarantine; rua=mailto:security@yourdomain.com",
        })

    if not findings:
        findings.append({
            "severity": "info",
            "category": "Config",
            "title": "Scan Complete - AI Analysis Unavailable",
            "description": "Rule-based fallback: " + error_msg[:100],
            "evidence": "API error occurred",
            "cve": None,
            "cwe": None,
            "owasp": "N/A",
            "recommendation": "Check API key and credits at console.anthropic.com",
        })

    return sorted(findings, key=lambda x: ["critical","high","medium","low","info"].index(x["severity"]))
