import httpx, ssl, socket
from datetime import datetime, timezone
from urllib.parse import urlparse

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]
INFO_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

def probe_http(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    result = {
        "url": url,
        "hostname": hostname,
        "final_url": None,
        "status_code": None,
        "headers": {},
        "missing_security_headers": [],
        "info_disclosure_headers": {},
        "cookies": [],
        "redirect_chain": [],
        "tls": {},
        "errors": [],
    }
    try:
        with httpx.Client(follow_redirects=True, timeout=10, verify=False) as client:
            response = client.get(url)
            result["status_code"] = response.status_code
            result["final_url"] = str(response.url)
            result["headers"] = dict(response.headers)
            result["redirect_chain"] = [str(r.url) for r in response.history]
            present = {h.lower() for h in response.headers}
            result["missing_security_headers"] = [
                h for h in SECURITY_HEADERS if h not in present
            ]
            for h in INFO_HEADERS:
                if h in response.headers:
                    result["info_disclosure_headers"][h] = response.headers[h]
            for k, v in response.headers.multi_items():
                if k.lower() == "set-cookie":
                    flags = v.lower()
                    result["cookies"].append({
                        "raw": v[:200],
                        "httponly": "httponly" in flags,
                        "secure": "secure" in flags,
                        "samesite": "samesite" in flags,
                    })
    except Exception as e:
        result["errors"].append(str(e))
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=8),
            server_hostname=hostname,
        ) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            not_after = cert.get("notAfter")
            days = None
            if not_after:
                try:
                    exp = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                except Exception:
                    pass
            result["tls"] = {
                "protocol": ssock.version(),
                "cipher_suite": cipher[0] if cipher else None,
                "days_until_expiry": days,
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
            }
    except Exception as e:
        result["tls"]["error"] = str(e)
    return result
