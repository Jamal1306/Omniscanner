import subprocess
import json
import tempfile
import os

def run_nikto(url):
    result = {"url": url, "findings": [], "total_issues": 0, "errors": []}
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
        subprocess.run(
            ["nikto", "-h", url, "-Format", "json", "-output", tmp_path,
             "-nointeractive", "-maxtime", "60s"],
            capture_output=True, text=True, timeout=90,
        )
        if tmp_path and os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            with open(tmp_path) as f:
                raw = json.load(f)
            for v in raw.get("vulnerabilities", [])[:20]:
                result["findings"].append({
                    "id": v.get("id", ""),
                    "method": v.get("method", "GET"),
                    "url": v.get("url", ""),
                    "msg": v.get("msg", ""),
                })
        result["total_issues"] = len(result["findings"])
    except subprocess.TimeoutExpired:
        result["errors"].append("Nikto timed out")
    except FileNotFoundError:
        result["errors"].append("Nikto not found")
    except Exception as e:
        result["errors"].append(str(e))
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    return result
