import subprocess
import json
import re


def search_exploits(query):
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
                "path":     item.get("Path", ""),
                "url":      "https://www.exploit-db.com/exploits/" + str(item.get("EDB-ID", "")),
            })
        return results
    except FileNotFoundError:
        return [{"error": "searchsploit not found"}]
    except json.JSONDecodeError:
        return []
    except Exception as e:
        return [{"error": str(e)}]


def enrich_with_searchsploit(findings, technologies):
    queried = set()

    # Search per CVE in findings
    for f in findings:
        cve = f.get("cve")
        if cve and cve not in queried:
            queried.add(cve)
            exploits = search_exploits(cve)
            if exploits and "error" not in exploits[0]:
                f["searchsploit"] = exploits

    # Search for versioned technologies from nmap/whatweb
    tech_list = technologies.get("technologies", [])
    tech_exploits = {}

    # Also search common tech patterns directly
    search_terms = []

    # Extract from whatweb technologies
    for tech in tech_list[:8]:
        clean = re.sub(r"[\[\]]", " ", tech).strip()
        if re.search(r"\d+\.\d+", clean):
            product = re.split(r"\s+\d", clean)[0].strip()
            if product and len(product) > 2:
                search_terms.append((tech, product))

    for orig_tech, term in search_terms[:6]:
        if term not in queried:
            queried.add(term)
            exploits = search_exploits(term)
            if exploits and "error" not in exploits[0]:
                tech_exploits[orig_tech] = exploits

    return findings, tech_exploits


def search_from_ports(open_ports):
    port_exploits = {}
    queried = set()
    for port_info in open_ports:
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        service = port_info.get("service", "")
        if product and version:
            query = product + " " + version
        elif product:
            query = product
        elif service:
            query = service
        else:
            continue
        query = query.strip()
        if query and query not in queried and len(query) > 3:
            queried.add(query)
            exploits = search_exploits(query)
            if exploits and "error" not in exploits[0]:
                port_key = str(port_info.get("port","")) + "/" + port_info.get("protocol","tcp")
                port_exploits[port_key + " " + query] = exploits
    return port_exploits
