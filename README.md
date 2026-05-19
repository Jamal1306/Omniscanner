# OmniScanner

> Kali Linux vulnerability scanner — OWASP Top 10 2025 — AI powered

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![Kali](https://img.shields.io/badge/Kali-Linux-557C94) ![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202025-red) ![Docker](https://img.shields.io/badge/Docker-ready-2496ED)

## Features

- Real HTTP/TLS probing
- nmap port scanning
- Nikto web vulnerability scanning
- WhatWeb technology fingerprinting
- DNS analysis (SPF, DMARC, DNSSEC)
- cPanel/WHM detection and exploit lookup
- AI-powered analysis (Anthropic Claude)
- OWASP Top 10 2025 mapping on every finding
- Searchsploit CVE lookup
- Metasploit module references
- Scan history with SQLite
- PDF report export
- Dashboard with charts
- Dark theme UI with OmniScanner branding
- Docker containerization

## OWASP Top 10 2025

| Code | Category |
|------|----------|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Data Integrity Failures |
| A09:2025 | Security Logging & Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

## Tech Stack

- **Backend:** Python, FastAPI, uvicorn
- **AI:** Anthropic Claude (claude-sonnet-4-6)
- **Security Tools:** nmap, Nikto, WhatWeb, sslscan, searchsploit, Metasploit
- **Frontend:** HTML, CSS, Vanilla JS, Chart.js
- **Database:** SQLite via aiosqlite

## Quick Start

### Option 1 — Docker (one command)

    git clone https://github.com/Jamal1306/omniscanner.git
    cd omniscanner
    echo 'ANTHROPIC_API_KEY=your_key_here' > .env
    ./start.sh

Open http://localhost:8000

### Option 2 — Direct on Kali

    git clone https://github.com/Jamal1306/omniscanner.git
    cd omniscanner/backend
    sudo pip install -r requirements.txt --break-system-packages
    echo 'ANTHROPIC_API_KEY=your_key_here' > .env
    sudo python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

## Project Structure

    omniscanner/
    backend/
        main.py
        database.py
        report.py
        requirements.txt
        Dockerfile
        scanner/
            http_probe.py
            dns_probe.py
            nmap_probe.py
            nikto_probe.py
            cpanel_probe.py
            searchsploit_probe.py
            msf_probe.py
            ai_analyzer.py
    frontend/
        index.html
        style.css
        app.js
        logo.svg
    docker-compose.yml
    start.sh
    stop.sh

## Safe Test Targets

Only scan systems you own or have explicit permission to test.

- http://testphp.vulnweb.com
- http://zero.webappsecurity.com
- http://scanme.nmap.org
- http://demo.cpanel.net

## Legal Disclaimer

Only scan systems you own or have written permission to test.
Unauthorized scanning is illegal.

## License

MIT License
