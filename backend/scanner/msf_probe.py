import subprocess
import json
import re


def search_msf(query):
    try:
        cmd = "search " + query + "; exit"
        proc = subprocess.run(
            ["msfconsole", "-q", "-x", cmd],
            capture_output=True, text=True, timeout=60
        )
        output = proc.stdout
        results = []
        for line in output.splitlines():
            line = line.strip()
            if any(t in line for t in ["exploit/", "auxiliary/", "post/"]):
                parts = line.split()
                if len(parts) >= 2:
                    results.append({
                        "fullname":    parts[0],
                        "type":        parts[0].split("/")[0],
                        "rank":        parts[1] if len(parts) > 1 else "",
                        "description": " ".join(parts[2:])[:150],
                    })
        return results[:5]
    except subprocess.TimeoutExpired:
        return [{"error": "msfconsole timed out"}]
    except FileNotFoundError:
        return [{"error": "msfconsole not found"}]
    except Exception as e:
        return [{"error": str(e)}]


def enrich_with_msf(findings, tech_exploits):
    queried = set()

    for f in findings:
        cve = f.get("cve")
        if cve and cve not in queried:
            queried.add(cve)
            modules = search_msf(cve)
            if modules and "error" not in modules[0]:
                f["msf_modules"] = modules

    tech_msf = {}
    for tech in list(tech_exploits.keys())[:4]:
        clean = re.sub(r"[\[\]]", " ", tech).strip()
        product = re.split(r"\s+\d", clean)[0].strip()
        if product and product not in queried:
            queried.add(product)
            modules = search_msf(product)
            if modules and "error" not in modules[0]:
                tech_msf[tech] = modules

    return findings, tech_msf
