# Exercise 04: Authentication Attack Detection - ANSWERS

## Task 4.1: Brute Force Detection

### Kibana Queries:

```kql
# Failed login attempts
url.path:"/rest/user/login" AND http.response.status_code:401

# Failed logins by source IP
url.path:"/rest/user/login" AND http.response.status_code:401 | stats count by source.ip
```

### Command Line Detection:

```bash
# Count failed logins by IP
grep "POST /rest/user/login" ./logs/nginx/access.log | grep " 401 " | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Brute force detection (>10 failures from same IP)
grep "POST /rest/user/login" ./logs/nginx/access.log | grep " 401 " | \
  awk '{print $1}' | sort | uniq -c | awk '$1 > 10 {print "BRUTE FORCE:", $2, "attempts:", $1}'

# Failed login timeline
grep "POST /rest/user/login" ./logs/nginx/access.log | grep " 401 " | \
  awk '{print $4}' | cut -d: -f1-3 | uniq -c
```

### Expected Brute Force Pattern:

```
Source IP: 172.18.0.5
Failed Attempts: 150+
Time Window: 5 minutes
Target: /rest/user/login
User-Agent: python-requests/2.28.0 (automated)

Timeline:
  50 [22/Jan/2026:10:15]
  45 [22/Jan/2026:10:16]
  55 [22/Jan/2026:10:17]
```

### Detection Threshold:

```yaml
rule:
  name: Brute Force Login
  condition:
    - endpoint: /rest/user/login
    - response_code: 401
    - count: > 10
    - window: 5 minutes
    - group_by: source.ip
  severity: high
  action: alert
```

---

## Task 4.2: Credential Stuffing Detection

### Command Line Analysis:

```bash
# Find unique usernames attempted from same IP
grep "POST /rest/user/login" ./logs/nginx/security.log | \
  grep -oE '"email":"[^"]*"' | sort | uniq -c | sort -rn

# Check for automated user-agents
grep "/rest/user/login" ./logs/nginx/access.log | \
  grep -iE "(curl|python|script|httpclient|bot)" | wc -l

# Attempts with different emails from same IP
# (requires body logging)
cat ./logs/nginx/security.log | \
  grep "POST /rest/user/login" | \
  awk -F'body=' '{print $1, $2}' | \
  awk '{print $1}' | sort | uniq -c | sort -rn
```

### Credential Stuffing Indicators:

| Indicator | Normal | Credential Stuffing |
|-----------|--------|---------------------|
| Emails per IP per hour | 1-3 | 50+ different |
| Failed/Success ratio | 10-20% | 95%+ failures |
| User-Agent consistency | Varies | Same automated tool |
| Time between attempts | Seconds+ | Milliseconds |
| Geographic pattern | Consistent | VPN/Tor nodes |

### Detection Script:

```python
#!/usr/bin/env python3
"""Credential Stuffing Detector"""

import re
import sys
from collections import defaultdict
from datetime import datetime

def parse_log(log_file):
    ip_emails = defaultdict(set)
    ip_attempts = defaultdict(int)
    
    with open(log_file) as f:
        for line in f:
            if "POST /rest/user/login" not in line:
                continue
            
            parts = line.split()
            ip = parts[0]
            ip_attempts[ip] += 1
            
            # Extract email from body if logged
            email_match = re.search(r'"email":"([^"]*)"', line)
            if email_match:
                ip_emails[ip].add(email_match.group(1))
    
    print("=== Credential Stuffing Analysis ===\n")
    for ip, emails in sorted(ip_emails.items(), key=lambda x: -len(x[1])):
        if len(emails) > 5:  # Threshold
            print(f"ALERT: {ip}")
            print(f"  Unique emails tried: {len(emails)}")
            print(f"  Total attempts: {ip_attempts[ip]}")
            print(f"  Sample emails: {list(emails)[:5]}")
            print()

if __name__ == "__main__":
    parse_log(sys.argv[1] if len(sys.argv) > 1 else "./logs/nginx/security.log")
```

---

## Task 4.3: Session Hijacking Detection

### Session Analysis:

```bash
# Extract authorization headers with source IPs
grep "Authorization: Bearer" ./logs/nginx/security.log | \
  awk -F'Authorization: Bearer ' '{print $1, $2}' | \
  awk '{print $1, $NF}' | \
  sort -k2 | uniq

# Find same token from different IPs
# (simplified - in practice, use proper parsing)
```

### Impossible Travel Detection Logic:

```python
#!/usr/bin/env python3
"""Session Anomaly Detector"""

from collections import defaultdict
import re

def detect_session_anomalies(log_file):
    token_ips = defaultdict(set)
    token_times = defaultdict(list)
    
    with open(log_file) as f:
        for line in f:
            # Extract token
            token_match = re.search(r'Bearer\s+(\S+)', line)
            if not token_match:
                continue
            
            token = token_match.group(1)[:50]  # First 50 chars
            ip = line.split()[0]
            
            token_ips[token].add(ip)
    
    print("=== Session Anomaly Detection ===\n")
    for token, ips in token_ips.items():
        if len(ips) > 1:
            print(f"ALERT: Token used from multiple IPs")
            print(f"  Token: {token}...")
            print(f"  IPs: {ips}")
            print()

if __name__ == "__main__":
    detect_session_anomalies("./logs/nginx/security.log")
```

---

## Detection Rules

### Brute Force Alert:

```json
{
  "name": "Brute Force Login Detection",
  "type": "threshold",
  "query": "url.path:\"/rest/user/login\" AND http.response.status_code:401",
  "threshold": 10,
  "window": "5m",
  "group_by": "source.ip",
  "severity": "high",
  "actions": [
    {"type": "alert", "channel": "security-team"},
    {"type": "block", "duration": "30m"}
  ]
}
```

### Credential Stuffing Alert:

```json
{
  "name": "Credential Stuffing Detection",
  "type": "cardinality",
  "query": "url.path:\"/rest/user/login\"",
  "field": "body.email",
  "threshold": 20,
  "window": "10m",
  "group_by": "source.ip",
  "severity": "critical",
  "actions": [
    {"type": "alert", "channel": "security-team"},
    {"type": "block", "duration": "24h"}
  ]
}
```

### Session Hijacking Alert:

```json
{
  "name": "Session Token Anomaly",
  "type": "cardinality",
  "query": "http.request.header.authorization:*Bearer*",
  "field": "source.ip",
  "cardinality_on": "authorization_token",
  "threshold": 2,
  "window": "5m",
  "severity": "critical",
  "actions": [
    {"type": "alert"},
    {"type": "invalidate_session"}
  ]
}
```

---

## Summary

```
Brute Force Attempts:
- Source IPs: 172.18.0.5, 10.0.0.15
- Targeted Accounts: admin@juice-sh.op
- Success/Failure Ratio: 1:150
- User-Agent: python-requests (automated)

Credential Stuffing:
- Source IPs: 172.18.0.5
- Number of Accounts Tested: 250+
- User-Agents Used: python-requests, curl
- Pattern: Sequential email attempts

Session Anomalies:
- Tokens with Multiple IPs: 2 detected
- Impossible Travel Detected: 1 case

Rules Created:
1. Brute force: >10 failures in 5 min → block
2. Credential stuffing: >20 unique emails in 10 min → block
3. Session anomaly: Same token from 2+ IPs → alert
```

---

## Response Actions

### Automated Blocking:

```bash
# Block IP using iptables
iptables -A INPUT -s 172.18.0.5 -j DROP

# Or add to nginx deny list
echo "deny 172.18.0.5;" >> /etc/nginx/blocked_ips.conf
nginx -s reload
```

### Account Protection:

```bash
# In application: temporarily lock account
# After 10 failed attempts, require CAPTCHA
# After 20 failed attempts, lock for 30 minutes
```
