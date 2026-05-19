import subprocess
import requests
import re
import json


CPANEL_PORTS = {
    2082: "cPanel HTTP",
    2083: "cPanel HTTPS",
    2086: "WHM HTTP",
    2087: "WHM HTTPS",
    2095: "Webmail HTTP",
    2096: "Webmail HTTPS",
}

CPANEL_PATHS = [
    "/cpanel",
    "/whm",
    "/webmail",
    "/cgi-sys/defaultwebpage.cgi",
    "/cgi-sys/suspendedpage.cgi",
    "/:2082",
    "/:2083",
]


def probe_cpanel(hostname, open_ports=None):
    result = {
        "hostname":        hostname,
        "cpanel_detected": False,
        "whm_detected":    False,
        "webmail_detected":False,
        "version":         None,
        "exposed_ports":   [],
        "exposed_paths":   [],
        "technologies":    [],
        "searchsploit":    [],
        "findings":        [],
        "errors":          [],
    }

    # Check exposed cPanel ports from nmap results
    if open_ports:
        for port_info in open_ports:
            port = port_info.get("port")
            if port in CPANEL_PORTS:
                label = CPANEL_PORTS[port]
                result["exposed_ports"].append({
                    "port":    port,
                    "label":   label,
                    "service": port_info.get("service", ""),
                    "version": port_info.get("version", ""),
                })
                if "cPanel" in label:
                    result["cpanel_detected"] = True
                if "WHM" in label:
                    result["whm_detected"] = True
                if "Webmail" in label:
                    result["webmail_detected"] = True

    # HTTP fingerprinting for cPanel
    for scheme in ["https", "http"]:
        for port in [2083, 2082, 443, 80]:
            try:
                url = f"{scheme}://{hostname}:{port}"
                resp = requests.get(
                    url, timeout=5, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=True,
                )
                body = resp.text.lower()
                headers = {k.lower(): v for k, v in resp.headers.items()}

                # Detect cPanel
                if any(x in body for x in [
                    "cpanel", "whm", "webmail",
                    "cpsess", "cpcontacts", "x-cpanel"
                ]):
                    result["cpanel_detected"] = True
                    result["technologies"].append("cPanel detected")

                    # Try to extract version
                    version_match = re.search(
                        r"cpanel[\s/]+(\d+\.\d+\.\d+)", body
                    )
                    if version_match:
                        result["version"] = version_match.group(1)

                # Detect WHM
                if any(x in body for x in ["whm", "web host manager"]):
                    result["whm_detected"] = True
                    result["technologies"].append("WHM detected")

                # Check response headers
                if "x-cpanel-version" in headers:
                    result["version"] = headers["x-cpanel-version"]
                    result["cpanel_detected"] = True

                if result["cpanel_detected"]:
                    result["exposed_paths"].append(url)
                    break

            except Exception:
                continue
        if result["cpanel_detected"]:
            break

    # Check common cPanel paths on port 80/443
    for path in CPANEL_PATHS:
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{hostname}{path}"
                resp = requests.get(
                    url, timeout=4, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=True,
                )
                if resp.status_code in [200, 301, 302, 403]:
                    body = resp.text.lower()
                    if any(x in body for x in ["cpanel", "whm", "webmail", "cpsess"]):
                        result["cpanel_detected"] = True
                        if url not in result["exposed_paths"]:
                            result["exposed_paths"].append(url)
            except Exception:
                continue

    # Searchsploit for cPanel
    if result["cpanel_detected"]:
        query = "cPanel " + result["version"] if result["version"] else "cPanel WHM"
        result["searchsploit"] = _run_searchsploit(query)

        # Also search for WHM
        whm_results = _run_searchsploit("WHM")
        result["searchsploit"].extend(whm_results[:3])

    # Generate findings
    result["findings"] = _generate_findings(result)

    return result


def _run_searchsploit(query):
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True, text=True, timeout=15
        )
        if not proc.stdout.strip():
            return []
        data = json.loads(proc.stdout)
        results = []
        for item in data.get("RESULTS_EXPLOIT", [])[:5]:
            results.append({
                "title":    item.get("Title", ""),
                "edb_id":   item.get("EDB-ID", ""),
                "type":     item.get("Type", ""),
                "platform": item.get("Platform", ""),
                "date":     item.get("Date", ""),
                "url": "https://www.exploit-db.com/exploits/" + str(item.get("EDB-ID", "")),
            })
        return results
    except Exception:
        return []


def _generate_findings(result):
    findings = []

    if not result["cpanel_detected"] and not result["whm_detected"]:
        return findings

    # Exposed cPanel admin ports — Critical
    for port_info in result["exposed_ports"]:
        port  = port_info["port"]
        label = port_info["label"]
        findings.append({
            "severity":       "critical",
            "category":       "cPanel/WHM",
            "title":          f"Exposed {label} Admin Panel on Port {port}",
            "description":    (
                f"{label} is publicly accessible on port {port}. "
                "This exposes the hosting control panel to brute force attacks, "
                "credential stuffing, and exploitation of known cPanel vulnerabilities."
            ),
            "evidence":       f"Port {port}/tcp open — {label} accessible",
            "cve":            None,
            "cwe":            "CWE-284",
            "owasp":          "A01:2025 - Broken Access Control",
            "recommendation": (
                f"Restrict port {port} to trusted IP addresses only using firewall rules. "
                "Enable two-factor authentication on cPanel/WHM. "
                "Keep cPanel updated to the latest version."
            ),
        })

    # WHM exposed — Critical
    if result["whm_detected"]:
        findings.append({
            "severity":       "critical",
            "category":       "cPanel/WHM",
            "title":          "WHM (Web Host Manager) Admin Interface Exposed",
            "description":    (
                "WHM root-level hosting admin interface is publicly accessible. "
                "WHM has full server control including root access. "
                "Exposure to the internet is extremely dangerous."
            ),
            "evidence":       "WHM interface detected at: " + ", ".join(result["exposed_paths"][:2]),
            "cve":            "CVE-2021-38583",
            "cwe":            "CWE-284",
            "owasp":          "A01:2025 - Broken Access Control",
            "recommendation": (
                "Immediately restrict WHM access to admin IPs only. "
                "Enable WHM IP restrictions in Security Center. "
                "Enable two-factor authentication."
            ),
        })

    # cPanel version outdated — High
    if result["version"]:
        findings.append({
            "severity":       "high",
            "category":       "cPanel/WHM",
            "title":          f"cPanel Version {result['version']} Detected",
            "description":    (
                f"cPanel version {result['version']} is exposed. "
                "Older cPanel versions have multiple known CVEs including "
                "XSS, CSRF, privilege escalation, and remote code execution."
            ),
            "evidence":       f"X-cPanel-Version: {result['version']} or body fingerprint",
            "cve":            "CVE-2023-29489",
            "cwe":            "CWE-200",
            "owasp":          "A06:2025 - Insecure Design",
            "recommendation": (
                "Update cPanel to the latest stable version immediately. "
                "Enable automatic updates in WHM > Update Preferences."
            ),
        })

    # cPanel paths exposed — High
    if result["exposed_paths"]:
        findings.append({
            "severity":       "high",
            "category":       "cPanel/WHM",
            "title":          "cPanel Login Pages Publicly Accessible",
            "description":    (
                "cPanel and/or WHM login interfaces are reachable from the internet. "
                "This exposes the server to brute force and credential stuffing attacks "
                "targeting hosting account credentials."
            ),
            "evidence":       "Accessible URLs: " + " | ".join(result["exposed_paths"][:3]),
            "cve":            None,
            "cwe":            "CWE-307",
            "owasp":          "A07:2025 - Authentication Failures",
            "recommendation": (
                "Use cPanel's IP Blocker and firewall to restrict access. "
                "Enable brute force protection in cPHulk. "
                "Require 2FA for all cPanel accounts."
            ),
        })

    # Searchsploit findings — Critical if exploits found
    if result["searchsploit"]:
        exploit_list = ", ".join(
            e["title"][:50] for e in result["searchsploit"][:3]
        )
        findings.append({
            "severity":       "critical",
            "category":       "cPanel/WHM",
            "title":          f"Known Exploits Found for cPanel/WHM ({len(result['searchsploit'])} exploits)",
            "description":    (
                f"Searchsploit found {len(result['searchsploit'])} public exploits "
                "for this cPanel/WHM installation. Attackers can use these to "
                "compromise the server, steal data, or gain root access."
            ),
            "evidence":       f"Exploit-DB matches: {exploit_list}",
            "cve":            result["searchsploit"][0].get("edb_id", ""),
            "cwe":            "CWE-1035",
            "owasp":          "A03:2025 - Software Supply Chain Failures",
            "recommendation": (
                "Update cPanel immediately. Review each exploit and apply patches. "
                "Monitor cPanel security advisories at https://docs.cpanel.net/security/"
            ),
            "searchsploit":   result["searchsploit"],
        })

    return findings
