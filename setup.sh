#!/bin/bash

# OWASP Juice Shop - Red/Blue Team Exercise Setup Script
# This script sets up the complete training environment

set -e

echo "
╔═══════════════════════════════════════════════════════════╗
║  OWASP JUICE SHOP - RED/BLUE TEAM TRAINING SETUP          ║
╚═══════════════════════════════════════════════════════════╝
"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
echo -e "${BLUE}[*] Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}[-] Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

if ! command -v docker compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}[-] Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Docker and Docker Compose found${NC}"

# Create required directories
echo -e "${BLUE}[*] Creating required directories...${NC}"
mkdir -p logs/nginx
mkdir -p blue-team/config
mkdir -p red-team/scripts
mkdir -p red-team/exercises
mkdir -p red-team/answers

echo -e "${GREEN}[+] Directories created${NC}"

# Check Elasticsearch memory requirement
echo -e "${BLUE}[*] Checking system configuration...${NC}"
CURRENT_MAP_COUNT=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo "0")
if [ "$CURRENT_MAP_COUNT" -lt 262144 ]; then
    echo -e "${BLUE}[*] Increasing vm.max_map_count for Elasticsearch...${NC}"
    sudo sysctl -w vm.max_map_count=262144 || echo "Warning: Could not set vm.max_map_count"
fi

# Select mode
echo ""
echo "Select training mode:"
echo "  1) Full Environment (Red Team + Blue Team monitoring)"
echo "  2) Red Team Only (Juice Shop + Attack Box)"
echo "  3) Blue Team Only (Juice Shop + ELK Stack)"
echo ""
read -p "Enter selection [1-3]: " MODE

case $MODE in
    1)
        echo -e "${BLUE}[*] Starting full environment...${NC}"
        docker compose up -d
        ;;
    2)
        echo -e "${BLUE}[*] Starting Red Team environment...${NC}"
        docker compose up -d juice-shop kali-attack
        ;;
    3)
        echo -e "${BLUE}[*] Starting Blue Team environment...${NC}"
        docker compose up -d juice-shop elasticsearch kibana filebeat nginx-proxy
        ;;
    *)
        echo -e "${RED}[-] Invalid selection. Starting full environment...${NC}"
        docker compose up -d
        ;;
esac

# Wait for services to start
echo -e "${BLUE}[*] Waiting for services to start (this may take 1-2 minutes)...${NC}"
sleep 30

# Check service status
echo -e "${BLUE}[*] Checking service status...${NC}"
docker compose ps

# Test endpoints
echo ""
echo -e "${BLUE}[*] Testing endpoints...${NC}"

# Test Juice Shop
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200"; then
    echo -e "${GREEN}[+] Juice Shop: http://localhost:3000 - OK${NC}"
else
    echo -e "${RED}[-] Juice Shop: Not responding yet (may still be starting)${NC}"
fi

# Test Kibana (if started)
if docker ps | grep -q kibana; then
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:5601 | grep -q "200\|302"; then
        echo -e "${GREEN}[+] Kibana: http://localhost:5601 - OK${NC}"
    else
        echo -e "${BLUE}[*] Kibana: Still starting (wait 1-2 minutes)${NC}"
    fi
fi

# Test Nginx Proxy (if started)
if docker ps | grep -q nginx-proxy; then
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 | grep -q "200"; then
        echo -e "${GREEN}[+] Nginx Proxy: http://localhost:8080 - OK${NC}"
    else
        echo -e "${BLUE}[*] Nginx Proxy: Still starting${NC}"
    fi
fi

# Print access information
echo ""
echo "═══════════════════════════════════════════════════════════"
echo -e "${GREEN}SETUP COMPLETE!${NC}"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "ACCESS POINTS:"
echo "  • Juice Shop:     http://localhost:3000"
echo "  • Proxied Access: http://localhost:8080 (logged)"
echo "  • Kibana:         http://localhost:5601"
echo ""
echo "RED TEAM:"
echo "  • Access attack box: docker exec -it kali-attack bash"
echo "  • Exercises: red-team/exercises/"
echo "  • Answers: red-team/answers/"
echo ""
echo "BLUE TEAM:"
echo "  • Open Kibana: http://localhost:5601"
echo "  • Exercises: blue-team/exercises/"
echo "  • Answers: blue-team/answers/"
echo ""
echo "COMMANDS:"
echo "  • Stop environment:  docker compose down"
echo "  • View logs:         docker compose logs -f"
echo "  • Reset environment: docker compose down -v && docker compose up -d"
echo ""
echo "═══════════════════════════════════════════════════════════"
