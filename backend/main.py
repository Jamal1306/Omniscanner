import os
import asyncio
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response
from pydantic import BaseModel
from urllib.parse import urlparse

from scanner.http_probe         import probe_http
from scanner.dns_probe          import probe_dns
from scanner.nmap_probe         import probe_ports, run_whatweb
from scanner.nikto_probe        import run_nikto
from scanner.ai_analyzer        import analyze
from scanner.searchsploit_probe import enrich_with_searchsploit, search_from_ports
from scanner.msf_probe          import enrich_with_msf
from scanner.cpanel_probe       import probe_cpanel
from database import init_db, save_scan, get_all_scans, get_scan_by_id, delete_scan
from report   import generate_pdf

app = FastAPI(title="OmniScanner — Kali Edition")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    await init_db()


class ScanRequest(BaseModel):
    url: str


@app.post("/scan")
async def scan(req: ScanRequest):
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed   = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")

    loop = asyncio.get_event_loop()

    (http_data, dns_data, nmap_data,
     whatweb_data, nikto_data) = await asyncio.gather(
        loop.run_in_executor(None, probe_http,   url),
        loop.run_in_executor(None, probe_dns,    hostname),
        loop.run_in_executor(None, probe_ports,  hostname),
        loop.run_in_executor(None, run_whatweb,  url),
        loop.run_in_executor(None, run_nikto,    url),
    )

    # cPanel/WHM detection
    cpanel_data = await loop.run_in_executor(
        None, probe_cpanel, hostname, nmap_data.get("open_ports", [])
    )

    probe_data = {
        "target_url":   url,
        "hostname":     hostname,
        "http":         http_data,
        "dns":          dns_data,
        "ports":        nmap_data,
        "technologies": whatweb_data,
        "nikto":        nikto_data,
        "cpanel":       cpanel_data,
    }

    # AI analysis
    findings = analyze(probe_data)

    # Merge cPanel findings (rule-based, no AI needed)
    if cpanel_data.get("findings"):
        findings = cpanel_data["findings"] + findings

    # Searchsploit — CVEs + technologies + ports
    findings, tech_exploits = await loop.run_in_executor(
        None, enrich_with_searchsploit, findings, whatweb_data
    )

    # Searchsploit from open ports (Apache 2.2.6, Tomcat etc)
    open_ports = nmap_data.get("open_ports", [])
    port_exploits = await loop.run_in_executor(
        None, search_from_ports, open_ports
    )
    tech_exploits.update(port_exploits)

    # Metasploit
    findings, tech_msf = await loop.run_in_executor(
        None, enrich_with_msf, findings, tech_exploits
    )

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        summary[sev] = summary.get(sev, 0) + 1

    scan_id = await save_scan(url, hostname, summary, findings, probe_data)

    return {
        "id":            scan_id,
        "url":           url,
        "hostname":      hostname,
        "http":          http_data,
        "dns":           dns_data,
        "ports":         nmap_data,
        "technologies":  whatweb_data,
        "nikto":         nikto_data,
        "findings":      findings,
        "tech_exploits": tech_exploits,
        "tech_msf":      tech_msf,
        "cpanel":        cpanel_data,
        "summary":       summary,
    }


@app.get("/history")
async def history():
    return await get_all_scans()


@app.get("/history/{scan_id}")
async def get_scan(scan_id: int):
    s = await get_scan_by_id(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return s


@app.delete("/history/{scan_id}")
async def delete(scan_id: int):
    if not await delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}


@app.get("/report/{scan_id}")
async def download_report(scan_id: int):
    s = await get_scan_by_id(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf_bytes = generate_pdf(s)
    filename  = "vuln-report-" + s["hostname"] + "-" + str(scan_id) + ".pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=" + filename},
    )


@app.get("/health")
async def health():
    return {"status": "ok", "scanner": "vuln-scanner-kali"}


app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")
