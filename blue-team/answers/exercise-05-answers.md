# Exercise 05: Access Control Monitoring - ANSWERS

## Task 5.1: IDOR Detection

### Kibana Queries:

```kql
# User resource access
url.path:/\/api\/Users\/[0-9]+/

# Basket access patterns
url.path:/\/rest\/basket\/[0-9]+/

# Multiple IDs from same source
url.path:*Users* | stats dc(url.path) by source.ip | where count > 5
```

### Command Line Detection:

```bash
# Detect ID enumeration
grep -E "/api/Users/[0-9]+" ./logs/nginx/access.log | \
  awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -20

# Extract accessed IDs per source IP
grep -E "/api/Users/[0-9]+" ./logs/nginx/access.log | \
  awk '{print $1}' | sort | uniq -c | \
  awk '$1 > 5 {print "IDOR ALERT:", $2, "accessed", $1, "user IDs"}'

# Find basket enumeration
grep -E "/rest/basket/[0-9]+" ./logs/nginx/access.log | \
  awk '{ip=$1; match($7, /basket\/([0-9]+)/, arr); print ip, arr[1]}' | \
  sort | uniq | awk '{count[$1]++} END {for(ip in count) if(count[ip]>3) print "IDOR:", ip, count[ip], "baskets"}'

# Sequential ID access detection
grep -oE "/api/Users/[0-9]+" ./logs/nginx/access.log | \
  cut -d/ -f4 | sort -n | uniq -c
```

### IDOR Detection Script:

```python
#!/usr/bin/env python3
"""IDOR Attack Detector"""

import re
import sys
from collections import defaultdict

RESOURCE_PATTERNS = [
    (r'/api/Users/(\d+)', 'Users'),
    (r'/rest/basket/(\d+)', 'Baskets'),
    (r'/api/Feedbacks/(\d+)', 'Feedbacks'),
    (r'/api/Complaints/(\d+)', 'Complaints'),
    (r'/rest/track-order/(\S+)', 'Orders'),
]

def detect_idor(log_file):
    ip_resources = defaultdict(lambda: defaultdict(set))
    
    with open(log_file) as f:
        for line in f:
            ip = line.split()[0]
            request = line.split('"')[1] if '"' in line else ''
            
            for pattern, resource_type in RESOURCE_PATTERNS:
                match = re.search(pattern, request)
                if match:
                    resource_id = match.group(1)
                    ip_resources[ip][resource_type].add(resource_id)
    
    print("=== IDOR Detection Results ===\n")
    for ip, resources in ip_resources.items():
        for resource_type, ids in resources.items():
            if len(ids) > 3:  # Threshold
                print(f"ALERT: Potential IDOR from {ip}")
                print(f"  Resource: {resource_type}")
                print(f"  IDs accessed: {len(ids)}")
                print(f"  Sample IDs: {sorted(list(ids))[:10]}")
                print()

if __name__ == "__main__":
    detect_idor(sys.argv[1] if len(sys.argv) > 1 else "./logs/nginx/access.log")
```

### Expected IDOR Pattern:

```
Source IP: 172.18.0.5
Resource: /api/Users
IDs Accessed: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
Pattern: Sequential enumeration
Time Window: 30 seconds

Source IP: 172.18.0.5
Resource: /rest/basket
IDs Accessed: 1, 2, 3, 4, 5
Pattern: Non-authorized basket access
```

---

## Task 5.2: Privilege Escalation Monitoring

### Admin Endpoint Monitoring:

```bash
# Administration panel access
grep -E "/administration|/admin" ./logs/nginx/access.log

# User listing (admin only)
grep "GET /api/Users " ./logs/nginx/access.log | \
  grep " 200 "  # Successful access

# Feedback deletion (admin only)
grep "DELETE /api/Feedbacks" ./logs/nginx/access.log

# Security questions access
grep "/api/SecurityQuestions" ./logs/nginx/access.log
```

### Kibana Queries:

```kql
# Admin panel access
url.path:*administration*

# Successful admin API calls
url.path:"/api/Users" AND http.request.method:GET AND http.response.status_code:200

# Delete operations
http.request.method:DELETE
```

### Privilege Escalation Detection:

```python
#!/usr/bin/env python3
"""Privilege Escalation Detector"""

import re

ADMIN_ENDPOINTS = [
    '/administration',
    '/admin',
    '/api/Users$',  # List all users
    '/api/SecurityQuestions',
    '/api/SecurityAnswers',
    '/rest/admin',
]

def detect_priv_esc(log_file):
    with open(log_file) as f:
        for line in f:
            request = line.split('"')[1] if '"' in line else ''
            
            for endpoint in ADMIN_ENDPOINTS:
                if re.search(endpoint, request):
                    # Check for success
                    if ' 200 ' in line:
                        ip = line.split()[0]
                        print(f"ADMIN ACCESS: {ip} -> {request}")

if __name__ == "__main__":
    detect_priv_esc("./logs/nginx/access.log")
```

---

## Task 5.3: Path Traversal Detection

### Command Line Detection:

```bash
# Basic path traversal patterns
grep -E "(\.\./|%2e%2e|%252e)" ./logs/nginx/access.log

# FTP directory access
grep "/ftp/" ./logs/nginx/access.log

# Null byte injection
grep -E "%00|%2500" ./logs/nginx/access.log

# Double encoding detection
grep -E "%25[0-9a-fA-F]{2}" ./logs/nginx/access.log
```

### Kibana Queries:

```kql
# Path traversal
url.path:*../*

# URL encoded traversal
url.path:*%2e%2e* OR url.query:*%2e%2e*

# FTP access
url.path:/ftp/*

# Null byte
url.path:*%00* OR url.query:*%00*
```

### Path Traversal Detection Script:

```python
#!/usr/bin/env python3
"""Path Traversal Detector"""

import re
from urllib.parse import unquote

TRAVERSAL_PATTERNS = [
    r'\.\.',
    r'%2e%2e',
    r'%252e%252e',
    r'\.\.%2f',
    r'%2e%2e%2f',
    r'\.\.%5c',
    r'%00',
    r'%2500',
]

def detect_traversal(log_file):
    with open(log_file) as f:
        for line in f:
            decoded = unquote(unquote(line))
            
            for pattern in TRAVERSAL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE) or '..' in decoded:
                    ip = line.split()[0]
                    request = line.split('"')[1] if '"' in line else ''
                    status = re.search(r'\s(\d{3})\s', line)
                    status = status.group(1) if status else 'unknown'
                    
                    print(f"PATH TRAVERSAL: {ip}")
                    print(f"  Request: {request[:80]}")
                    print(f"  Status: {status}")
                    print(f"  Pattern: {pattern}")
                    print()
                    break

if __name__ == "__main__":
    detect_traversal("./logs/nginx/access.log")
```

---

## Detection Rules Summary

### IDOR Detection:

```yaml
name: IDOR_Enumeration
description: Detect resource enumeration attacks
query: |
  url.path matches /\/(api|rest)\/\w+\/\d+/
group_by: source.ip
threshold: 
  distinct_ids: 5
  window: 2m
severity: high
action: alert
```

### Admin Access Monitoring:

```yaml
name: Unauthorized_Admin_Access
description: Monitor admin endpoint access
query: |
  url.path in ["/administration", "/api/Users", "/admin"]
  AND http.response.status_code:200
severity: critical
action: alert_immediate
```

### Path Traversal:

```yaml
name: Path_Traversal_Attempt
description: Detect directory traversal
query: |
  url.path matches /\.\./ OR
  url.path matches /%2e%2e/ OR
  url.query matches /%00/
severity: high
action: alert + block
```

---

## Summary

```
IDOR Attempts:
- Endpoints: /api/Users, /rest/basket
- Resource IDs Accessed: Users 1-20, Baskets 1-10
- Source IPs: 172.18.0.5
- Success Rate: 90% (access control missing)

Admin Access Attempts:
- Endpoints: /administration, /api/Users
- Authenticated/Unauthenticated: Both
- Success/Failure: Most successful (broken auth)

Path Traversal:
- Payloads Used: ../, %2e%2e, %2500
- Files Targeted: /etc/passwd, /ftp/../
- Success/Failure: Some successful

Rules Created:
1. IDOR: >5 different IDs from same IP in 2 min
2. Admin: Any access to admin endpoints → alert
3. Traversal: Any ../ pattern → block
```

---

## Recommended Mitigations

1. **Implement proper authorization checks**
   - Verify user owns resource before access
   - Role-based access control for admin functions

2. **Input validation**
   - Sanitize path components
   - Reject null bytes and traversal patterns

3. **Monitoring enhancements**
   - Log authorization context (user ID)
   - Alert on any traversal pattern
   - Monitor admin endpoint access volume
