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
├── red-team/                   # Offensive Security Exercises
│   ├── Dockerfile              # Kali-based attack container
│   ├── exercises/              # 6 structured exercises
│   │   ├── exercise-01-reconnaissance.md
│   │   ├── exercise-02-sql-injection.md
│   │   ├── exercise-03-xss.md
│   │   ├── exercise-04-broken-auth.md
│   │   ├── exercise-05-access-control.md
│   │   └── exercise-06-api-exploitation.md
│   ├── answers/                # Solutions and commands
│   │   └── exercise-0X-answers.md
│   └── scripts/                # Attack automation tools
│       ├── attack_toolkit.py
│       └── jwt_tool.py
│
├── blue-team/                  # Defensive Security Exercises
│   ├── config/                 # Monitoring configurations
│   │   ├── filebeat.yml
│   │   └── nginx.conf
│   ├── exercises/              # 6 structured exercises
│   │   ├── exercise-01-setup.md
│   │   ├── exercise-02-attack-detection.md
│   │   ├── exercise-03-xss-detection.md
│   │   ├── exercise-04-auth-detection.md
│   │   ├── exercise-05-access-monitoring.md
│   │   └── exercise-06-incident-response.md
│   ├── answers/                # Solutions and commands
│   │   └── exercise-0X-answers.md
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
| Juice Shop | http://localhost:3000 | Target application |
| Juice Shop (Proxied) | http://localhost:8080 | Logged traffic |
| Kibana | http://localhost:5601 | Log analysis |
| Attack Box | `docker exec -it kali-attack bash` | Red Team terminal |

## 🔴 Red Team Track

**Duration:** 2 hours  
**Skill Level:** Beginner to Intermediate

### Exercise Overview

| # | Exercise | Time | Topics |
|---|----------|------|--------|
| 1 | Reconnaissance | 15 min | Fingerprinting, Directory Enumeration |
| 2 | SQL Injection | 20 min | Auth Bypass, Data Extraction, SQLMap |
| 3 | XSS | 20 min | Reflected, Stored, DOM-based XSS |
| 4 | Broken Auth | 20 min | Password Cracking, JWT, Reset Bypass |
| 5 | Access Control | 20 min | IDOR, Privilege Escalation |
| 6 | API Exploitation | 25 min | Mass Assignment, Business Logic |

### Getting Started

```bash
# Access the attack container
docker exec -it kali-attack bash

# Navigate to exercises
cd /workspace/exercises

# Start with exercise 1
cat exercise-01-reconnaissance.md
```

## 🔵 Blue Team Track

**Duration:** 2 hours  
**Skill Level:** Beginner to Intermediate

### Exercise Overview

| # | Exercise | Time | Topics |
|---|----------|------|--------|
| 1 | Environment Setup | 15 min | Kibana, Log Collection |
| 2 | SQL Injection Detection | 20 min | Pattern Recognition, Alerts |
| 3 | XSS Detection | 20 min | Attack Signatures, Headers |
| 4 | Auth Attack Detection | 20 min | Brute Force, Credential Stuffing |
| 5 | Access Control Monitoring | 20 min | IDOR, Privilege Escalation |
| 6 | Incident Response | 25 min | Forensics, Reporting |

### Getting Started

1. Access Kibana: http://localhost:5601
2. Navigate to `blue-team/exercises/`
3. Start with `exercise-01-setup.md`

## 🟣 Purple Team Mode

Run both teams simultaneously for realistic attack/defense scenarios:

1. Start Red Team in attack container
2. Blue Team monitors via Kibana/logs
3. Real-time detection and response practice
4. Debrief together at the end

## 📊 Covered Vulnerabilities (OWASP Top 10)

| OWASP Category | Red Team Exercise | Blue Team Exercise |
|----------------|-------------------|-------------------|
| A01 Broken Access Control | Ex 5 | Ex 5 |
| A02 Cryptographic Failures | Ex 4 | Ex 4 |
| A03 Injection (SQLi/XSS) | Ex 2, 3 | Ex 2, 3 |
| A04 Insecure Design | Ex 6 | Ex 6 |
| A07 Auth Failures | Ex 4 | Ex 4 |

## 🛠️ Included Tools

### Red Team Container
- Nmap, Nikto, Gobuster
- SQLMap, Burp Suite, OWASP ZAP
- Hydra, John, Hashcat
- Python with security libraries

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
