# OWASP Juice Shop - Red Team & Blue Team Exercise Setup

## Overview

This repository contains a complete dockerized environment for conducting Red Team (offensive) and Blue Team (defensive) security exercises using OWASP Juice Shop as the target application.

**Duration:** 2 hours per team (can be run simultaneously for Purple Team exercises)

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

#### Option B: Red Team Only (Minimal Setup)
```bash
docker-compose up -d juice-shop kali-attack
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
curl http://localhost:3000

# Test Kibana (Blue Team)
curl http://localhost:5601

# Test Nginx Proxy
curl http://localhost:8080
```

## Service Endpoints

| Service | URL | Purpose |
|---------|-----|---------|
| Juice Shop | http://localhost:3000 | Vulnerable application (direct) |
| Juice Shop (via Proxy) | http://localhost:8080 | Vulnerable application (logged) |
| Kibana | http://localhost:5601 | Log analysis & dashboards |
| Elasticsearch | http://localhost:9200 | Search engine backend |

## Quick Start Guide

### For Red Team
1. Access the attack box: `docker exec -it kali-attack /bin/bash`
2. Target URL: `http://juice-shop:3000` (internal) or `http://localhost:3000` (external)
3. Navigate to `red-team/exercises/` and start with Exercise 01

### For Blue Team
1. Access Kibana: http://localhost:5601
2. Navigate to `blue-team/exercises/` and start with Exercise 01
3. Monitor attacks via logs and dashboards

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
