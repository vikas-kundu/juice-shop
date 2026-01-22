# OWASP Juice Shop - Purple Team Exercise Setup

## Overview

This repository contains a complete dockerized environment for conducting **Purple Team** security exercises using OWASP Juice Shop as the target application. Red Team and Blue Team work simultaneously on coordinated exercises.

**Duration:** 2 hours (3 exercises x 40 minutes)

## Prerequisites

### System Requirements
- **OS:** Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **RAM:** Minimum 8GB (16GB recommended)
- **Disk Space:** At least 10GB free
- **CPU:** 4+ cores recommended

### Required Software
- Docker Engine 20.10+
- Docker Compose 2.0+
- Git
- Web browser (Firefox or Chrome recommended)

## Installation

### Step 1: Clone or Navigate to Repository

```bash
cd /root/juice_shop
```

### Step 2: Create Required Directories

```bash
mkdir -p logs/nginx
mkdir -p blue-team/config
mkdir -p red-team
```

### Step 3: Start the Full Environment

#### Option A: Full Environment (Both Teams)
```bash
docker-compose up -d
```

#### Option B: Juice Shop Only (Minimal Setup)
```bash
docker-compose up -d juice-shop
```

#### Option C: Blue Team Only (With Monitoring)
```bash
docker-compose up -d juice-shop elasticsearch kibana filebeat nginx-proxy
```

### Step 4: Verify Installation

Wait 2-3 minutes for all services to start, then verify:

```bash
# Check all containers are running
docker-compose ps

# Test Juice Shop
curl http://localhost:8000

# Test Kibana (Blue Team)
curl http://localhost:5601

# Test Nginx Proxy
curl http://localhost:8080
```

## Service Endpoints

| Service | URL | Purpose |
|---------|-----|---------|
| Juice Shop | http://localhost:8000 | Vulnerable application (direct) |
| Juice Shop (via Proxy) | http://localhost:8080 | Vulnerable application (logged) |
| Kibana | http://localhost:5601 | Log analysis & dashboards |
| Elasticsearch | http://localhost:9200 | Search engine backend |

## Quick Start Guide

### For Red Team (Attackers)
1. Use your own Kali Linux or security testing environment
2. Target URL: `http://<VPS_IP>:8000` (direct) or `http://<VPS_IP>:8080` (proxied/logged)
3. Navigate to `exercises/` folder
4. Each exercise has Red Team and Blue Team sections - follow your section

### For Blue Team (Defenders)
1. SSH into the VPS or access Kibana: http://<VPS_IP>:5601
2. Navigate to `exercises/` folder
3. Each exercise has Red Team and Blue Team sections - follow your section
4. Monitor logs via command line: `tail -f ./logs/nginx/access.log`

### Exercise Flow
1. **Both teams read** the same exercise file together
2. **Red Team** follows the 🔴 Red Team Instructions
3. **Blue Team** follows the 🔵 Blue Team Instructions
4. **Debrief together** using the 🟣 Debrief Questions

## Stopping the Environment

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

## Troubleshooting

### Elasticsearch fails to start
```bash
# Increase virtual memory limit
sudo sysctl -w vm.max_map_count=262144

# Make it permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Port conflicts
Edit `docker-compose.yml` and change the host ports (left side of colon).

### Container fails to build
```bash
# Rebuild without cache
docker-compose build --no-cache
docker-compose up -d
```

### View container logs
```bash
docker-compose logs -f [service-name]
```

## Reset for New Session

```bash
# Complete reset
docker-compose down -v
docker-compose up -d

# Reset only Juice Shop (preserves logs)
docker-compose restart juice-shop
```

## Additional Resources

- [OWASP Juice Shop Official Documentation](https://pwning.owasp-juice.shop/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Juice Shop GitHub Repository](https://github.com/juice-shop/juice-shop)
