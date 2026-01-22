# Blue Team Exercise 04: Authentication Attack Detection

**Difficulty:** ⭐⭐ Intermediate  
**Time:** 20 minutes  
**Focus:** Brute Force Detection, Account Takeover, Credential Stuffing

## Objective

Learn to detect authentication-based attacks including brute force, credential stuffing, and session hijacking.

## Prerequisites

- Completed previous exercises
- Access to authentication logs
- Understanding of JWT tokens

---

## Tasks

### Task 4.1: Detect Brute Force Attacks (7 minutes)

Identify brute force login attempts:

**Indicators:**
- Multiple failed logins from same IP
- Sequential requests to /rest/user/login
- High volume of 401/403 responses

**Kibana Queries:**
```
url.path:"/rest/user/login" AND http.response.status_code:401
url.path:*login* AND http.response.status_code:(401 OR 403)
```

**Command Line Analysis:**
```bash
# Count login failures by IP
grep "POST /rest/user/login" ./logs/nginx/access.log | grep " 401 " | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Login attempts over time
grep "/rest/user/login" ./logs/nginx/access.log | \
  awk '{print $4}' | cut -d: -f1-3 | uniq -c
```

**Detection Threshold:**
- More than 10 failed logins in 5 minutes = Brute Force Alert

---

### Task 4.2: Identify Credential Stuffing (7 minutes)

Detect credential stuffing patterns:

**Indicators:**
- Multiple different usernames from same IP
- Known breached password patterns
- Automated user-agent strings

**Analysis:**
```bash
# Find login attempts with email in body
grep "POST /rest/user/login" ./logs/nginx/security.log | \
  grep -oE '"email":"[^"]*"' | sort | uniq -c | sort -rn

# Check for automated user agents
grep "/rest/user/login" ./logs/nginx/access.log | \
  grep -E "(curl|python|script|bot)" | head -20
```

**Kibana Query:**
```
url.path:"/rest/user/login" AND 
user_agent.original:(*curl* OR *python* OR *script* OR *bot*)
```

---

### Task 4.3: Session Hijacking Detection (6 minutes)

Identify potential session takeover:

**Indicators:**
- Same token used from different IPs
- Impossible travel (same user, different locations, short time)
- Session used after password change

**JWT Token Analysis:**
```bash
# Extract authorization headers
grep "Authorization: Bearer" ./logs/nginx/security.log | \
  awk '{print $1, $NF}' | sort -k2 | uniq -c

# Look for token reuse from different IPs
# (requires parsing Bearer tokens)
```

**Kibana Analysis:**
1. Group by authorization token
2. Check for multiple source IPs per token
3. Alert if token used from > 2 IPs

---

## Detection Rules

### Brute Force Detection Rule

```json
{
  "rule_name": "Brute Force Login",
  "condition": "count(failed_logins) > 10 within 5 minutes where source_ip = same",
  "severity": "high",
  "action": "alert + temporary_block"
}
```

### Credential Stuffing Detection Rule

```json
{
  "rule_name": "Credential Stuffing",
  "condition": "count(distinct_usernames) > 20 from same IP within 10 minutes",
  "severity": "critical",
  "action": "alert + permanent_block"
}
```

### Session Anomaly Detection Rule

```json
{
  "rule_name": "Session Anomaly",
  "condition": "same_session_token from different_IP within 5 minutes",
  "severity": "critical",
  "action": "alert + invalidate_session"
}
```

---

## Password Spray Detection

Detect password spraying (one password, many users):

```bash
# Same password tried against multiple accounts
# Look for patterns where failure time is consistent
grep "POST /rest/user/login" ./logs/nginx/access.log | \
  awk '{print $4, $1}' | sort | uniq -c | \
  awk '$1 > 5 {print}'
```

**Kibana Query:**
```
url.path:"/rest/user/login" AND http.response.status_code:401
| stats count by source.ip, @timestamp per minute
| where count > 5
```

---

## Challenge: Advanced Detection

1. Can you detect password reset abuse?
2. How would you identify a successful account takeover?
3. Can you correlate SQL injection auth bypass with login events?

---

## Account Takeover Indicators

| Indicator | Description | Action |
|-----------|-------------|--------|
| Password changed after SQL injection | Auth bypass followed by password reset | High alert |
| Multiple failed then success | Successful brute force | Block + force reset |
| Login from new country | Unusual location | Verify with user |
| Session from Tor/VPN after login | Privacy tool usage post-auth | Risk scoring |

---

## Success Criteria

- [ ] Identified brute force attack patterns
- [ ] Detected credential stuffing indicators
- [ ] Created authentication monitoring rules
- [ ] Understand session hijacking detection

---

## Incident Response for Auth Attacks

**Brute Force:**
1. [ ] Block source IP
2. [ ] Lock targeted account temporarily
3. [ ] Alert account owner
4. [ ] Review for successful compromise

**Account Takeover:**
1. [ ] Immediately disable account
2. [ ] Invalidate all sessions
3. [ ] Reset credentials
4. [ ] Contact account owner
5. [ ] Forensic investigation

---

## Notes

```
Brute Force Attempts:
- Source IPs:
- Targeted Accounts:
- Success/Failure Ratio:

Credential Stuffing:
- Source IPs:
- Number of Accounts Tested:
- User-Agents Used:

Session Anomalies:
- Tokens with Multiple IPs:
- Impossible Travel Detected:

Rules Created:
1. 
2. 
```

---

**Next Exercise:** [Exercise 05 - Access Control Monitoring](./exercise-05-access-monitoring.md)
