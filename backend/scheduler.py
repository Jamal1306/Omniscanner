from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
import asyncio
import logging

log = logging.getLogger("scheduler")

scheduler = AsyncIOScheduler()


async def run_scheduled_scans():
    """Called every minute — checks for due schedules and runs them."""
    from database import get_due_schedules, update_schedule_after_run, save_scan
    from scanner.http_probe  import probe_http
    from scanner.dns_probe   import probe_dns
    from scanner.nmap_probe  import probe_ports, run_whatweb
    from scanner.nikto_probe import run_nikto
    from scanner.searchsploit_probe import enrich_findings_with_exploits
    from scanner.msf_probe   import enrich_findings_with_msf
    from scanner.ai_analyzer import analyze
    from urllib.parse import urlparse

    due = await get_due_schedules()
    if not due:
        return

    for schedule in due:
        url      = schedule["url"]
        sched_id = schedule["id"]
        log.info(f"Running scheduled scan for {url}")

        try:
            parsed   = urlparse(url)
            hostname = parsed.hostname

            loop = asyncio.get_event_loop()
            (http_data, dns_data, nmap_data,
             whatweb_data, nikto_data) = await asyncio.gather(
                loop.run_in_executor(None, probe_http,  url),
                loop.run_in_executor(None, probe_dns,   hostname),
                loop.run_in_executor(None, probe_ports, hostname),
                loop.run_in_executor(None, run_whatweb, url),
                loop.run_in_executor(None, run_nikto,   url),
            )

            probe_data = {
                "target_url":   url,
                "hostname":     hostname,
                "http":         http_data,
                "dns":          dns_data,
                "ports":        nmap_data,
                "technologies": whatweb_data,
                "nikto":        nikto_data,
            }

            findings = analyze(probe_data)
            findings, tech_exploits = enrich_findings_with_exploits(
                findings, whatweb_data
            )
            findings, tech_msf = enrich_findings_with_msf(findings, tech_exploits)

            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                sev = f.get("severity", "info").lower()
                summary[sev] = summary.get(sev, 0) + 1

            scan_id = await save_scan(url, hostname, summary, findings, probe_data)
            await update_schedule_after_run(sched_id, scan_id)
            log.info(f"Scheduled scan complete: {url} → scan #{scan_id}")

        except Exception as e:
            log.error(f"Scheduled scan failed for {url}: {e}")


def start_scheduler():
    scheduler.add_job(
        run_scheduled_scans,
        trigger=IntervalTrigger(minutes=1),
        id="scheduled_scans",
        replace_existing=True,
    )
    scheduler.start()
    log.info("Scheduler started — checking for due scans every minute")


def stop_scheduler():
    scheduler.shutdown(wait=False)
