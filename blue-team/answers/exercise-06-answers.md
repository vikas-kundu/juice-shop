# Exercise 06: Incident Response & Reporting - ANSWERS

## Task 6.1: Forensic Analysis

### Attack Timeline Construction:

```bash
# Create comprehensive attack timeline
cat > /root/juice_shop/incident_analysis.sh << 'EOF'
#!/bin/bash

LOG_FILE="./logs/nginx/access.log"
OUTPUT_DIR="./incident_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "=== Attack Timeline Analysis ===" > "$OUTPUT_DIR/timeline.txt"
echo "Generated: $(date)" >> "$OUTPUT_DIR/timeline.txt"
echo "" >> "$OUTPUT_DIR/timeline.txt"

# SQL Injection timeline
echo "--- SQL Injection Attempts ---" >> "$OUTPUT_DIR/timeline.txt"
grep -iE "(UNION|SELECT|OR.1=1|'--)" "$LOG_FILE" | \
  awk '{print $4, $1, $7}' | sort >> "$OUTPUT_DIR/sqli_timeline.txt"
wc -l "$OUTPUT_DIR/sqli_timeline.txt" >> "$OUTPUT_DIR/timeline.txt"

# XSS timeline
echo "" >> "$OUTPUT_DIR/timeline.txt"
echo "--- XSS Attempts ---" >> "$OUTPUT_DIR/timeline.txt"
grep -iE "(<script|javascript:|onerror)" "$LOG_FILE" | \
  awk '{print $4, $1, $7}' | sort >> "$OUTPUT_DIR/xss_timeline.txt"
wc -l "$OUTPUT_DIR/xss_timeline.txt" >> "$OUTPUT_DIR/timeline.txt"

# Auth attacks
echo "" >> "$OUTPUT_DIR/timeline.txt"
echo "--- Authentication Attacks ---" >> "$OUTPUT_DIR/timeline.txt"
grep "POST /rest/user/login" "$LOG_FILE" | grep " 401 " | \
  awk '{print $4, $1}' | sort >> "$OUTPUT_DIR/auth_timeline.txt"
wc -l "$OUTPUT_DIR/auth_timeline.txt" >> "$OUTPUT_DIR/timeline.txt"

# IDOR attempts
echo "" >> "$OUTPUT_DIR/timeline.txt"
echo "--- IDOR Attempts ---" >> "$OUTPUT_DIR/timeline.txt"
grep -E "/api/Users/[0-9]+|/rest/basket/[0-9]+" "$LOG_FILE" | \
  awk '{print $4, $1, $7}' | sort >> "$OUTPUT_DIR/idor_timeline.txt"
wc -l "$OUTPUT_DIR/idor_timeline.txt" >> "$OUTPUT_DIR/timeline.txt"

# Unique attackers
echo "" >> "$OUTPUT_DIR/timeline.txt"
echo "--- Unique Attacker IPs ---" >> "$OUTPUT_DIR/timeline.txt"
cat "$OUTPUT_DIR"/*_timeline.txt | awk '{print $2}' | sort | uniq -c | \
  sort -rn >> "$OUTPUT_DIR/attackers.txt"
cat "$OUTPUT_DIR/attackers.txt" >> "$OUTPUT_DIR/timeline.txt"

echo "Analysis complete. Results in $OUTPUT_DIR/"
EOF

chmod +x /root/juice_shop/incident_analysis.sh
```

### Run Analysis:

```bash
# Execute analysis
./incident_analysis.sh

# View timeline
cat incident_*/timeline.txt
```

### Data Exfiltration Analysis:

```bash
# Find large responses (potential data theft)
awk '$10 > 10000 {print $4, $1, $7, $10}' ./logs/nginx/access.log | \
  grep -iE "(UNION|SELECT|Users)" > data_exfil.txt

# Analyze exfiltrated data size
cat data_exfil.txt | awk '{sum+=$4} END {print "Total bytes:", sum}'
```

### Expected Analysis Results:

```
=== Attack Timeline Summary ===

Attack Start: [22/Jan/2026:10:00:15]
Attack End: [22/Jan/2026:11:45:32]
Duration: 1 hour 45 minutes

Attacker IPs:
  172.18.0.5 - Primary attacker (85% of malicious traffic)
  10.0.0.15 - Secondary attacker (15% of malicious traffic)

Attack Phases:
1. [10:00] Reconnaissance - FTP access, path enumeration
2. [10:15] SQL Injection - Auth bypass, data extraction
3. [10:30] XSS - Stored payload in feedback
4. [10:45] IDOR - User/basket enumeration
5. [11:00] Privilege Escalation - Admin panel access
6. [11:30] Data Exfiltration - User data download
```

---

## Task 6.2: Scope Assessment

### User Account Analysis:

```bash
# Successful logins during attack window
grep "POST /rest/user/login" ./logs/nginx/access.log | grep " 200 " | \
  awk '{print $4, $1}' | sort

# Password resets
grep "POST /rest/user/reset-password" ./logs/nginx/access.log | \
  grep " 200 "

# Admin account access
grep -i "admin@juice-sh.op" ./logs/nginx/security.log
```

### Data Exposure Assessment:

```bash
# FTP file downloads
grep "/ftp/" ./logs/nginx/access.log | grep " 200 " | \
  awk '{print $7}' | sort | uniq -c

# User data API access
grep "GET /api/Users" ./logs/nginx/access.log | grep " 200 " | wc -l

# Large data responses
awk '$10 > 50000 {print $7, $10}' ./logs/nginx/access.log
```

### Scope Document:

```markdown
BREACH SCOPE ASSESSMENT
=======================
Incident ID: INC-2026-001
Assessment Date: 2026-01-22

TIME RANGE
----------
First Malicious Activity: 2026-01-22 10:00:15 UTC
Last Malicious Activity: 2026-01-22 11:45:32 UTC
Detection Time: 2026-01-22 11:50:00 UTC
Time to Detection: ~1 hour 50 minutes

ATTACK VECTORS USED
-------------------
1. SQL Injection (Critical)
   - Authentication bypass
   - Data extraction via UNION SELECT

2. Cross-Site Scripting (High)
   - Stored XSS in feedback
   - Reflected XSS in search

3. Broken Access Control (High)
   - IDOR in user/basket endpoints
   - Admin panel access

4. Sensitive Data Exposure (Medium)
   - FTP file access
   - User enumeration

AFFECTED SYSTEMS
----------------
- Juice Shop Web Application
- User Database
- Customer Feedback System

DATA POTENTIALLY EXPOSED
------------------------
User Accounts: ~20 accounts exposed
  - Email addresses: Yes
  - Password hashes: Yes (MD5 - easily crackable)
  - Personal information: Limited

Financial Data: Minimal
  - Order history: Potentially accessed
  - Payment info: Not stored in application

Files Accessed:
  - coupons_2013.md.bak
  - acquisitions.md
  - package.json.bak

INDICATORS OF COMPROMISE
------------------------
Source IPs:
  - 172.18.0.5 (Primary)
  - 10.0.0.15 (Secondary)

User Agents:
  - python-requests/2.28.0
  - sqlmap/1.6

Attack Signatures:
  - UNION SELECT statements
  - <script> tags in parameters
  - Sequential ID enumeration
```

---

## Task 6.3: Incident Response Execution

### Evidence Preservation:

```bash
#!/bin/bash
# evidence_collection.sh

INCIDENT_ID="INC-2026-001"
EVIDENCE_DIR="/root/juice_shop/evidence_${INCIDENT_ID}"

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"

# Collect logs
cp -r ./logs "$EVIDENCE_DIR/logs_$(date +%Y%m%d_%H%M%S)"

# Create hash of evidence
find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/evidence_hashes.txt"

# Docker state
docker ps -a > "$EVIDENCE_DIR/docker_state.txt"
docker logs juice-shop > "$EVIDENCE_DIR/juiceshop_logs.txt" 2>&1

# Network connections
docker exec juice-shop netstat -an > "$EVIDENCE_DIR/network_connections.txt" 2>/dev/null

echo "Evidence collected in $EVIDENCE_DIR"
echo "Chain of custody hash: $(sha256sum $EVIDENCE_DIR/evidence_hashes.txt)"
```

### Attacker Blocking:

```bash
# Block attacker IPs
ATTACKER_IPS="172.18.0.5 10.0.0.15"

for IP in $ATTACKER_IPS; do
  echo "Blocking $IP"
  # Add to nginx deny list
  echo "deny $IP;" >> ./blue-team/config/blocked_ips.conf
done

# Reload nginx
docker exec nginx-proxy nginx -s reload
```

### Notification Template:

```markdown
SECURITY INCIDENT NOTIFICATION
==============================

TO: Security Team, IT Management, Legal
FROM: SOC Analyst
DATE: 2026-01-22 12:00:00 UTC
SEVERITY: CRITICAL

SUMMARY
-------
A security breach has been detected on the Juice Shop application.
Multiple attack vectors were used to access user data.

CURRENT STATUS: CONTAINED

IMMEDIATE ACTIONS TAKEN
-----------------------
1. ✅ Attacker IPs blocked
2. ✅ Evidence preserved
3. ✅ Logs secured
4. ⏳ Affected accounts being identified
5. ⏳ Vulnerability assessment in progress

IMPACT
------
- ~20 user accounts potentially compromised
- Password hashes exposed (MD5)
- No financial data breach confirmed

NEXT STEPS
----------
1. Complete forensic analysis
2. Force password reset for affected users
3. Notify affected users per breach policy
4. Patch identified vulnerabilities
5. Schedule security assessment

CONTACTS
--------
Incident Commander: [Name]
Technical Lead: [Name]
Communications: [Name]
```

---

## Complete Incident Report

```markdown
# Security Incident Report

## Executive Summary

On January 22, 2026, the Security Operations Center detected a sophisticated 
attack on the OWASP Juice Shop application. The attacker successfully exploited 
multiple vulnerabilities including SQL injection, XSS, and broken access controls 
to access user data. The incident was contained within 2 hours of detection.

## Incident Details

- **Incident ID:** INC-2026-001
- **Date Detected:** 2026-01-22 11:50:00 UTC
- **Date Contained:** 2026-01-22 12:30:00 UTC
- **Date Resolved:** 2026-01-22 15:00:00 UTC
- **Severity:** Critical
- **Classification:** Data Breach - User Credentials

## Attack Vector Analysis

### Attack Timeline

| Time (UTC) | Event | Evidence |
|------------|-------|----------|
| 10:00:15 | Initial reconnaissance | /ftp access, directory enumeration |
| 10:15:22 | SQL injection begins | `' OR 1=1--` in login |
| 10:18:45 | Admin access gained | Successful login as admin |
| 10:25:00 | Data extraction | UNION SELECT on search |
| 10:35:00 | XSS payload stored | Script in feedback |
| 10:45:00 | IDOR enumeration | Users 1-20 accessed |
| 11:00:00 | Admin panel accessed | /administration |
| 11:30:00 | Mass data export | Large response sizes |
| 11:45:32 | Attack ends | Last malicious request |
| 11:50:00 | Detection | Alert triggered |
| 12:30:00 | Containment | IPs blocked |

### Indicators of Compromise (IOCs)

**IP Addresses:**
- 172.18.0.5 (Primary - 847 malicious requests)
- 10.0.0.15 (Secondary - 156 malicious requests)

**User Agents:**
- python-requests/2.28.0
- sqlmap/1.6.12

**Attack Patterns:**
- SQL: `' OR 1=1--`, `UNION SELECT`, `FROM Users`
- XSS: `<script>`, `onerror=`, `javascript:`
- Path: `../`, `/ftp/`, `/administration`

## Impact Assessment

### Data Exposure

| Data Type | Records | Sensitivity |
|-----------|---------|-------------|
| User emails | 20 | Medium |
| Password hashes | 20 | High |
| Order history | 15 | Low |
| Product data | All | Public |

### Business Impact

- **Downtime:** 0 hours (attack did not cause outage)
- **Affected Users:** 20 accounts
- **Reputation:** Potential negative publicity
- **Regulatory:** Possible notification requirements

## Response Actions

### Immediate Actions (Completed)
1. ✅ Blocked attacker IP addresses
2. ✅ Preserved forensic evidence
3. ✅ Disabled compromised admin account
4. ✅ Rotated JWT secret key

### Short-term Actions (In Progress)
1. ⏳ Force password reset for affected users
2. ⏳ Deploy input validation patches
3. ⏳ Implement rate limiting
4. ⏳ Add Web Application Firewall rules

### Long-term Actions (Planned)
1. 📅 Complete security audit
2. 📅 Penetration testing
3. 📅 Security awareness training
4. 📅 Implement CSP headers
5. 📅 Deploy SIEM solution

## Root Cause Analysis

The incident occurred due to multiple security vulnerabilities:

1. **SQL Injection (CWE-89)**
   - No parameterized queries
   - Insufficient input validation
   
2. **Cross-Site Scripting (CWE-79)**
   - No output encoding
   - Missing Content-Security-Policy
   
3. **Broken Access Control (CWE-284)**
   - IDOR vulnerabilities
   - Missing authorization checks
   
4. **Sensitive Data Exposure (CWE-200)**
   - FTP directory publicly accessible
   - MD5 password hashing (weak)

## Recommendations

### Critical (Immediate)
1. Implement parameterized queries for all database operations
2. Add proper authorization checks on all API endpoints
3. Deploy Content-Security-Policy header

### High (Within 1 Week)
1. Replace MD5 with bcrypt for password hashing
2. Implement rate limiting on authentication endpoints
3. Remove or secure /ftp directory

### Medium (Within 1 Month)
1. Deploy Web Application Firewall
2. Implement security headers (HSTS, X-Frame-Options)
3. Regular security assessments

## Lessons Learned

### What Worked Well
- Detection rules triggered within 2 hours
- Evidence preservation was quick and complete
- Team response was coordinated

### What Could Be Improved
- Detection time was too long (1:50)
- No automated blocking capability
- Limited visibility into POST body content

### Action Items
1. Reduce detection time to < 30 minutes
2. Implement automated threat blocking
3. Enhance logging to capture request bodies
4. Create attack playbooks for common scenarios

## Appendices

### A. Evidence Chain of Custody
[Attached: evidence_hashes.txt]

### B. Full Attack Timeline
[Attached: timeline.txt]

### C. IOC List (for threat intelligence sharing)
[Attached: iocs.json]

### D. Affected User List (Confidential)
[Attached: affected_users_encrypted.txt]

---
Report Prepared By: SOC Team
Date: 2026-01-22
Classification: CONFIDENTIAL
```

---

## Post-Incident Checklist

```
DETECTION & ANALYSIS
✅ Initial detection documented
✅ Attack timeline created
✅ Attack vectors identified (SQLi, XSS, IDOR)
✅ Attacker IPs recorded (172.18.0.5, 10.0.0.15)
✅ Scope determined (20 users affected)

CONTAINMENT
✅ Attacker blocked
✅ Compromised accounts disabled
✅ Evidence preserved
✅ Systems monitored for reinfection

ERADICATION
⏳ Vulnerability patches deployed
⏳ Security configurations hardened
⏳ Malicious stored XSS removed

RECOVERY
⏳ User passwords reset
⏳ Monitoring enhanced
⏳ Normal operations confirmed

POST-INCIDENT
⏳ Incident report completed
⏳ Lessons learned documented
⏳ Procedures updated
⏳ Staff training scheduled
```
