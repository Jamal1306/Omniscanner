#!/bin/bash
set -e

echo ""
echo "  OmniScanner - Kali Linux Edition"
echo "  OWASP Top 10 2025"
echo "  ================================"
echo ""

if [ ! -f ".env" ]; then
    echo "  ERROR: .env not found!"
    echo "  Run: echo 'ANTHROPIC_API_KEY=your_key' > .env"
    exit 1
fi

echo "  Starting OmniScanner..."
docker-compose up --build -d
echo ""
echo "  Running at: http://localhost:8000"
echo "  Logs:  docker-compose logs -f"
echo "  Stop:  ./stop.sh"
echo ""
