# Red Team Exercise 04: Broken Authentication & Session Management

**Difficulty:** ⭐⭐ Intermediate  
**Time:** 20 minutes  
**OWASP Category:** A07:2021 - Identification and Authentication Failures

## Objective

Exploit authentication and session management vulnerabilities to gain unauthorized access to user accounts.

## Prerequisites

- Completed previous exercises
- Understanding of JWT tokens
- Burp Suite or similar proxy tool

---

## Tasks

### Task 4.1: Password Cracking (5 minutes)

Crack the password hashes obtained from SQL injection:
1. Take the MD5 hashes from Exercise 02
2. Use hashcat or john to crack them
3. Log in with the cracked credentials

**Hints:**
- Hashes are MD5 (mode 0 in hashcat)
- Try common wordlists like rockyou.txt
- Some passwords are very simple

---

### Task 4.2: JWT Token Manipulation (10 minutes)

Exploit weaknesses in JWT implementation:
1. Register a new user and obtain a JWT token
2. Decode the JWT and analyze its structure
3. Attempt to forge a token to gain admin access

**JWT Attack Vectors:**
- None algorithm attack
- Weak secret key
- Algorithm confusion

**Hints:**
- Use jwt.io to decode tokens
- Check if the algorithm can be changed to 'none'
- Try common secret keys

---

### Task 4.3: Password Reset Exploitation (5 minutes)

Exploit the password reset mechanism:
1. Find the forgot password functionality
2. Analyze how security questions work
3. Reset another user's password using gathered intel

**Hints:**
- Admin's security question might have a guessable answer
- Look for information disclosure in other parts of the app
- Try common pet names

---

## Tools & Commands

### Hash Cracking with Hashcat
```bash
# MD5 cracking
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### Hash Cracking with John
```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### JWT Manipulation with Python
```python
import jwt

# Decode without verification
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
decoded = jwt.decode(token, options={"verify_signature": False})
print(decoded)

# Forge with none algorithm
forged = jwt.encode({"id": 1, "email": "admin@juice-sh.op"}, "", algorithm="none")
```

---

## Challenge: Advanced Authentication Attacks

1. Can you brute force the admin password?
2. Can you perform a session fixation attack?
3. Can you exploit any race conditions in authentication?
4. Can you bypass 2FA if implemented?

---

## Success Criteria

- [ ] Cracked at least 2 user passwords
- [ ] Successfully manipulated JWT token
- [ ] Reset password for another user
- [ ] Documented all exploitation techniques

---

## Notes

Document your findings:

```
Cracked Passwords:
1. User: _____ Password: _____
2. User: _____ Password: _____

JWT Vulnerabilities:
- Algorithm: 
- Secret Key (if found): 
- Forged Token: 

Password Reset Bypass:
- User targeted: 
- Security question: 
- Answer found: 
```

---

**Next Exercise:** [Exercise 05 - Broken Access Control](./exercise-05-access-control.md)
