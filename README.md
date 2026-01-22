# OWASP Juice Shop - Red Team & Blue Team Exercises

[![OWASP Juice Shop](https://img.shields.io/badge/OWASP-Juice%20Shop-orange)](https://owasp.org/www-project-juice-shop/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 Overview

This repository provides a complete dockerized environment for hands-on security training using OWASP Juice Shop. It includes structured exercises for both **Red Team** (offensive security) and **Blue Team** (defensive security) practitioners.

**Total Training Time:** 2 hours per team (can be run simultaneously for Purple Team exercises)

## 📁 Repository Structure

```
juice_shop/
├── docker-compose.yml          # Main Docker orchestration
├── installation.md             # Detailed setup instructions
├── README.md                   # This file
│
├── exercises/                  # Purple Team Exercises (Simultaneous)
│   ├── exercise-01-sql-injection.md    # SQL Injection Attack & Defense
│   ├── exercise-02-brute-force.md      # Brute Force & Rate Limiting
│   ├── exercise-03-xss-waf.md          # XSS Attack & WAF Rules
│   └── answers/
│       ├── exercise-01-answers.md
│       ├── exercise-02-answers.md
│       └── exercise-03-answers.md
│
├── red-team/                   # Red Team Reference & Scripts
│   ├── exercises/              # Additional exercises (optional)
│   ├── answers/                # Solutions and commands
│   └── scripts/                # Attack automation tools
│       ├── attack_toolkit.py
│       └── jwt_tool.py
│
├── blue-team/                  # Blue Team Reference & Scripts
│   ├── config/                 # Monitoring configurations
│   │   ├── filebeat.yml
│   │   └── nginx.conf
│   ├── exercises/              # Additional exercises (optional)
│   ├── answers/                # Solutions and commands
│   └── scripts/                # Detection tools
│       └── log_analyzer.py
│
└── logs/                       # Log storage (created at runtime)
    └── nginx/
```

## 🚀 Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum
- 10GB free disk space

### Installation

```bash
# 1. Navigate to the repository
cd /root/juice_shop

# 2. Create required directories
mkdir -p logs/nginx

# 3. Start the environment
docker-compose up -d

# 4. Verify all services are running
docker-compose ps
```

### Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| Juice Shop (Direct) | http://localhost:8000 | Direct access (no logging) |
| **Juice Shop (Proxied)** | http://localhost:8080 | **Use this for exercises** (logged) |
| Kibana | http://localhost:5601 | Log analysis dashboard |

> **Important for Exercises:** Red Team should attack port **8080** so Blue Team can see the attacks in logs!

## 🟣 Purple Team Exercises (Main Track)

**Duration:** 2 hours total (3 exercises x 40 minutes each)  
**Skill Level:** Beginner  
**Mode:** Red Team and Blue Team work simultaneously

### Exercise Overview

| # | Exercise | Time | Red Team Activity | Blue Team Activity |
|---|----------|------|-------------------|-------------------|
| 1 | **SQL Injection** | 40 min | SQL injection attacks | Detect & block attacker |
| 2 | **Brute Force** | 40 min | Password cracking | Rate limiting & lockout |
| 3 | **XSS & WAF** | 40 min | XSS payload injection | WAF rules & blocking |

### How It Works

1. **Both teams start together** - Read the exercise instructions
2. **Red Team attacks** - Perform the offensive techniques
3. **Blue Team monitors** - Detect attacks in real-time
4. **Blue Team responds** - Block attackers and create rules
5. **Debrief together** - Discuss what worked and what didn't

### Getting Started

1. Navigate to `exercises/` folder
2. Start with `exercise-01-sql-injection.md`
3. Each exercise has sections for both teams
4. Answers are in `exercises/answers/`

---

## 🔴 Red Team (Attackers)

### Setup
- Use your own Kali Linux or security testing environment
- **Target:** `http://<VPS_IP>:8080` (proxied - Blue Team sees your attacks)
- Alternative: `http://<VPS_IP>:8000` (direct - no logging)

### Objectives
- Exploit vulnerabilities in OWASP Juice Shop
- Document successful attack techniques
- Try to bypass Blue Team's defenses

### Tools Needed
- curl, Burp Suite, or browser
- Password wordlists
- Python for scripting

---

## 🔵 Blue Team (Defenders)

### Setup (SSH Access to Blue Team Server)

Blue Team has SSH access to a dedicated monitoring server with access to all logs:

```bash
# SSH to Blue Team server
ssh blueteam@<VPS_IP> -p 2222
# Password: defend123
```

### SSH Access Credentials

| Field | Value |
|-------|-------|
| **Host** | `<VPS_IP>` |
| **Port** | `2222` |
| **Username** | `blueteam` |
| **Password** | `defend123` |

### Available Helper Scripts

Once connected via SSH, use these commands:

```bash
# See all available commands
~/scripts/help.sh

# Real-time log monitoring
~/scripts/monitor.sh

# Detect SQL injection attempts
~/scripts/detect-sqli.sh

# Detect brute force attacks
~/scripts/detect-bruteforce.sh

# Detect XSS attempts
~/scripts/detect-xss.sh

# Show attacker IPs
~/scripts/show-attackers.sh

# View latest logs
~/scripts/tail-logs.sh
```

### Key Log Analysis Commands

```bash
# Real-time monitoring
tail -f /var/log/nginx/access.log

# Search for specific patterns
grep -iE "PATTERN" /var/log/nginx/access.log

# Find attacker IPs
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn
```

### Additional Access (Optional)

| Method | Access | Description |
|--------|--------|-------------|
| **SSH** | `ssh blueteam@<VPS_IP> -p 2222` | Primary log access |
| **Kibana** | Browser to `http://<VPS_IP>:5601` | Visual log analysis dashboard |

### Objectives
- Detect attacks in real-time via SSH log access
- Identify attacker IPs
- Document and report attackers for blocking
- Create incident reports

### Tools Provided
- SSH server with log access
- Helper detection scripts
- ELK Stack (Elasticsearch, Kibana, Filebeat)
- Nginx reverse proxy with detailed logging

## 📊 Covered Vulnerabilities (OWASP Top 10)

| OWASP Category | Exercise | Attack | Defense |
|----------------|----------|--------|---------|
| A03 Injection (SQL) | Exercise 1 | SQL injection bypass | Log analysis, IP blocking |
| A07 Auth Failures | Exercise 2 | Brute force, credential stuffing | Rate limiting, lockout |
| A03 Injection (XSS) | Exercise 3 | Cross-site scripting | WAF rules, CSP headers |

## 🛠️ Included Tools

### Red Team (Use Your Own Kali)
Recommended tools to have installed:
- Nmap, Nikto, Gobuster
- SQLMap, Burp Suite, OWASP ZAP
- Hydra, John, Hashcat
- Python with requests, jwt libraries

### Blue Team Stack
- Elasticsearch + Kibana (SIEM)
- Filebeat (log collection)
- Nginx (reverse proxy with logging)
- Python analysis scripts

## 📝 Assessment & Reporting

Both tracks include:
- Success criteria for each exercise
- Note-taking templates
- Final report templates
- Lessons learned frameworks

## 🔄 Reset Environment

```bash
# Complete reset (removes all data)
docker-compose down -v
docker-compose up -d

# Reset only Juice Shop
docker-compose restart juice-shop
```

## ⚠️ Disclaimer

This environment is for **educational purposes only**. The exercises teach both offensive and defensive security techniques. Never use these techniques against systems without explicit authorization.

## 📚 Additional Resources

- [OWASP Juice Shop Documentation](https://pwning.owasp-juice.shop/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Juice Shop GitHub](https://github.com/juice-shop/juice-shop)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## 📄 License

This project is provided for educational purposes. OWASP Juice Shop is licensed under the MIT License.
