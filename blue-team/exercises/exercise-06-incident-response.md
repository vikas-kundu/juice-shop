# Blue Team Exercise 06: Incident Response & Reporting

**Difficulty:** ⭐⭐⭐ Advanced  
**Time:** 25 minutes  
**Focus:** Incident Response, Forensics, Reporting, Remediation

## Objective

Practice complete incident response workflow from detection through remediation and reporting.

## Prerequisites

- Completed all previous exercises
- All detection rules in place
- Understanding of incident response process

---

## Scenario

You've detected multiple attacks on the Juice Shop application over the past 2 hours. Your task is to:
1. Perform forensic analysis
2. Determine the scope of the breach
3. Execute incident response procedures
4. Write an incident report

---

## Tasks

### Task 6.1: Forensic Analysis (10 minutes)

Perform comprehensive log analysis:

**Attack Timeline Construction:**
```bash
# Create attack timeline
grep -E "(UNION|SELECT|<script>|onerror|\.\.\/|/admin)" ./logs/nginx/access.log | \
  sort -k4 | head -50 > attack_timeline.txt

# Identify unique attackers
cat attack_timeline.txt | awk '{print $1}' | sort | uniq -c | sort -rn
```

**Data Exfiltration Analysis:**
```bash
# Find successful SQL injection (large responses)
awk '$10 > 10000 {print $1, $4, $7, $10}' ./logs/nginx/access.log | \
  grep -E "(UNION|SELECT)"

# Check for unusual outbound connections (if logging enabled)
grep -E "(external|http://)" ./logs/nginx/access.log
```

**Questions to Answer:**
1. When did the attack begin?
2. How many attackers were involved?
3. What data was potentially compromised?
4. Which attack vectors were used?

---

### Task 6.2: Scope Assessment (7 minutes)

Determine the breach scope:

**User Account Analysis:**
```bash
# Identify compromised accounts
grep "POST /rest/user/login" ./logs/nginx/access.log | grep " 200 " | \
  tail -20

# Check for password resets
grep "POST /rest/user/reset-password" ./logs/nginx/access.log
```

**Data Exposure Analysis:**
```bash
# Check FTP access
grep "/ftp/" ./logs/nginx/access.log | grep " 200 "

# Check user data access
grep "/api/Users" ./logs/nginx/access.log | grep " 200 "
```

**Create Scope Document:**
```
BREACH SCOPE ASSESSMENT
=======================
Time Range: [Start] - [End]
Attack Vectors: [List]
Affected Systems: [List]
Data Potentially Exposed:
  - User accounts: [Count]
  - Financial data: [Yes/No]
  - Personal information: [Yes/No]
```

---

### Task 6.3: Incident Response Execution (8 minutes)

Execute incident response procedures:

**Immediate Actions:**

1. **Contain the Threat**
```bash
# Block attacker IPs (example - adjust for your firewall)
# iptables -A INPUT -s <attacker_ip> -j DROP

# List IPs to block
cat attack_timeline.txt | awk '{print $1}' | sort | uniq
```

2. **Preserve Evidence**
```bash
# Create forensic copies
mkdir -p /root/juice_shop/incident_$(date +%Y%m%d)
cp -r ./logs /root/juice_shop/incident_$(date +%Y%m%d)/
cp attack_timeline.txt /root/juice_shop/incident_$(date +%Y%m%d)/
```

3. **Notify Stakeholders**
```
INCIDENT NOTIFICATION
=====================
Severity: [Critical/High/Medium/Low]
Status: [Active/Contained/Resolved]
Summary: [Brief description]
Impact: [Affected systems/users]
Actions Taken: [List]
Next Steps: [List]
```

---

## Incident Response Checklist

### Detection & Analysis
- [ ] Initial detection documented
- [ ] Attack timeline created
- [ ] Attack vectors identified
- [ ] Attacker IPs/signatures recorded
- [ ] Scope determined

### Containment
- [ ] Attacker blocked
- [ ] Compromised accounts disabled
- [ ] Affected systems isolated
- [ ] Evidence preserved

### Eradication
- [ ] Vulnerability patched
- [ ] Backdoors removed
- [ ] Malicious code cleaned
- [ ] Systems hardened

### Recovery
- [ ] Systems restored
- [ ] User passwords reset
- [ ] Monitoring enhanced
- [ ] Normal operations resumed

### Post-Incident
- [ ] Incident report written
- [ ] Lessons learned documented
- [ ] Procedures updated
- [ ] Staff training scheduled

---

## Incident Report Template

```markdown
# Security Incident Report

## Executive Summary
Brief overview of the incident for leadership.

## Incident Details
- **Incident ID:** INC-2024-001
- **Date Detected:** YYYY-MM-DD HH:MM
- **Date Contained:** YYYY-MM-DD HH:MM
- **Date Resolved:** YYYY-MM-DD HH:MM
- **Severity:** Critical/High/Medium/Low
- **Classification:** Data Breach / Unauthorized Access / DoS / etc.

## Attack Vector Analysis
Detailed description of how the attack was conducted.

### Attack Timeline
| Time | Event | Evidence |
|------|-------|----------|
| HH:MM | Reconnaissance | Access to /ftp |
| HH:MM | SQL Injection | UNION SELECT in logs |
| HH:MM | Data Exfiltration | Large response sizes |

### Indicators of Compromise (IOCs)
- IP Addresses: 
- User Agents:
- Attack Patterns:

## Impact Assessment
### Data Exposure
- User credentials: X accounts
- Personal information: X records
- Financial data: Yes/No

### Business Impact
- Downtime: X hours
- Affected users: X
- Estimated cost: $X

## Response Actions
### Immediate Actions
1. Blocked attacker IP
2. Disabled compromised accounts
3. Preserved evidence

### Short-term Actions
1. Patched vulnerable endpoints
2. Reset all user passwords
3. Enhanced monitoring

### Long-term Actions
1. Security audit
2. Penetration testing
3. Security awareness training

## Root Cause Analysis
The incident occurred due to:
1. Lack of input validation (SQL injection)
2. Missing security headers (XSS)
3. Weak access controls (IDOR)

## Recommendations
1. Implement parameterized queries
2. Deploy Web Application Firewall
3. Implement Content-Security-Policy
4. Add rate limiting
5. Regular security assessments

## Lessons Learned
1. Detection capabilities were effective
2. Response time was X minutes
3. Communication could be improved
4. Need automated blocking

## Appendices
- Full attack timeline
- Log excerpts
- IOC list
- Evidence chain of custody
```

---

## Success Criteria

- [ ] Complete attack timeline created
- [ ] Breach scope fully assessed
- [ ] Incident response procedures executed
- [ ] Comprehensive incident report written
- [ ] Lessons learned documented

---

## Post-Exercise Debrief

After completing all exercises, discuss:

1. **What worked well?**
   - Detection capabilities
   - Response time
   - Team coordination

2. **What could be improved?**
   - Detection gaps
   - Response procedures
   - Tool limitations

3. **Action Items:**
   - Implement missing controls
   - Update detection rules
   - Schedule training

---

**Congratulations!** You've completed the Blue Team exercises!
