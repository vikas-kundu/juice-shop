# Red Team Exercise 02: SQL Injection Attacks

**Difficulty:** ⭐⭐ Intermediate  
**Time:** 20 minutes  
**OWASP Category:** A03:2021 - Injection

## Objective

Exploit SQL injection vulnerabilities in the Juice Shop application to bypass authentication and extract sensitive data.

## Prerequisites

- Completed Exercise 01 (Reconnaissance)
- Basic understanding of SQL syntax
- Access to the Kali attack box

---

## Tasks

### Task 2.1: Authentication Bypass (5 minutes)

Bypass the login authentication to access the administrator account:
1. Navigate to the login page
2. Use SQL injection to log in as the admin user
3. Document the admin's email address and any interesting information

**Target:** `http://juice-shop:3000/#/login`

**Hints:**
- Think about how the login query might be structured
- Classic SQL injection payloads work here
- The admin email might be visible in the scoreboard

---

### Task 2.2: Blind SQL Injection - Data Extraction (10 minutes)

Extract sensitive data from the database using the search functionality:
1. Find the search endpoint
2. Confirm it's vulnerable to SQL injection
3. Extract the password hash for at least one user

**Target:** Search functionality in the application

**Hints:**
- Use UNION-based injection
- Determine the number of columns first
- SQLite is the database backend
- Common tables: `Users`, `Products`

---

### Task 2.3: Automated SQL Injection with SQLMap (5 minutes)

Use SQLMap to automate the exploitation:
1. Capture a vulnerable request
2. Use SQLMap to enumerate databases
3. Extract the Users table

**Hints:**
- Save a request to a file for SQLMap
- Use `-p` to specify the vulnerable parameter
- Use `--tables` and `--dump` options

---

## Challenge: Advanced Exploitation

1. Can you extract all user password hashes?
2. Can you crack any of the extracted hashes?
3. Can you modify data in the database using SQL injection?

---

## Common SQL Injection Payloads

```sql
-- Authentication Bypass
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
admin'/*

-- UNION Based
' UNION SELECT 1,2,3,4,5,6,7,8,9--
' UNION SELECT null,null,null--

-- SQLite Specific
' UNION SELECT sql FROM sqlite_master--
' UNION SELECT name FROM sqlite_master WHERE type='table'--
```

---

## Success Criteria

- [ ] Successfully logged in as admin via SQL injection
- [ ] Extracted at least one password hash
- [ ] Used SQLMap to automate exploitation
- [ ] Documented all vulnerable endpoints

---

## Notes

Document your findings:

```
Vulnerable Endpoints:
1. 
2. 

Successful Payloads:
1. 
2. 

Extracted Data:
- Admin Email: 
- Password Hashes: 

```

---

**Next Exercise:** [Exercise 03 - Cross-Site Scripting (XSS)](./exercise-03-xss.md)
