import nmap
import subprocess

def probe_ports(hostname):
    result = {
        "hostname": hostname,
        "open_ports": [],
        "os_guess": None,
        "service_versions": [],
        "risky_ports": [],
        "errors": [],
    }
    RISKY = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        27017: "MongoDB", 8080: "HTTP-alt",
    }
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=hostname, arguments="-sV -T4 --top-ports 100")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port, data in nm[host][proto].items():
                    if data["state"] == "open":
                        entry = {
                            "port": port,
                            "protocol": proto,
                            "service": data.get("name", ""),
                            "version": data.get("version", ""),
                            "product": data.get("product", ""),
                        }
                        result["open_ports"].append(entry)
                        if port in RISKY:
                            result["risky_ports"].append({
                                "port": port,
                                "label": RISKY[port],
                            })
    except Exception as e:
        result["errors"].append(str(e))
    return result

def run_whatweb(url):
    try:
        proc = subprocess.run(
            ["whatweb", "--color=never", "-a", "1", url],
            capture_output=True, text=True, timeout=20
        )
        output = proc.stdout.strip()
        techs = []
        for line in output.splitlines():
            if "[" in line:
                parts = line.split("]", 1)
                if len(parts) > 1:
                    for item in parts[-1].strip().split(","):
                        item = item.strip()
                        if item:
                            techs.append(item)
        return {"raw": output[:1000], "technologies": techs}
    except Exception as e:
        return {"error": str(e), "technologies": []}
