import dns.resolver

def probe_dns(hostname):
    result = {
        "hostname": hostname,
        "a_records": [],
        "mx_records": [],
        "txt_records": [],
        "spf": None,
        "dmarc": None,
        "dnssec": False,
        "errors": [],
    }
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        ans = resolver.resolve(hostname, "A")
        result["a_records"] = [r.to_text() for r in ans]
    except Exception as e:
        result["errors"].append(str(e))
    try:
        ans = resolver.resolve(hostname, "TXT")
        txts = [r.to_text().strip('"') for r in ans]
        result["txt_records"] = txts
        spf = [t for t in txts if t.startswith("v=spf1")]
        result["spf"] = spf[0] if spf else None
    except Exception as e:
        result["errors"].append(str(e))
    try:
        ans = resolver.resolve("_dmarc." + hostname, "TXT")
        txts = [r.to_text().strip('"') for r in ans]
        dmarc = [t for t in txts if t.startswith("v=DMARC1")]
        result["dmarc"] = dmarc[0] if dmarc else None
    except Exception:
        pass
    return result
