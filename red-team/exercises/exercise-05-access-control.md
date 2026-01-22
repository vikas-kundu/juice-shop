# Red Team Exercise 05: Broken Access Control

**Difficulty:** ⭐⭐ Intermediate  
**Time:** 20 minutes  
**OWASP Category:** A01:2021 - Broken Access Control

## Objective

Exploit access control vulnerabilities to access unauthorized resources and perform privilege escalation.

## Prerequisites

- Completed previous exercises
- Valid user account (can be the admin account)
- Burp Suite or browser dev tools

---

## Tasks

### Task 5.1: Horizontal Privilege Escalation (7 minutes)

Access another user's data without authorization:
1. Log in as a regular user
2. Find endpoints that expose user-specific data
3. Access another user's basket, orders, or profile

**Target Endpoints:**
- `/api/Baskets/{id}`
- `/api/Users/{id}`
- `/rest/user/whoami`

**Hints:**
- Manipulate IDs in API requests
- Check for IDOR (Insecure Direct Object Reference)
- Look at your own requests and modify identifiers

---

### Task 5.2: Vertical Privilege Escalation (7 minutes)

Gain administrative privileges:
1. Find admin-only functionality
2. Access the administration panel
3. Perform admin-only actions

**Target:**
- Admin section
- User management
- Feedback deletion

**Hints:**
- Check for hidden routes in JavaScript
- Look for `/administration` or similar paths
- Modify role in user data if possible

---

### Task 5.3: Sensitive Data Exposure (6 minutes)

Access sensitive files and data that should be restricted:
1. Find and download confidential documents
2. Access backup files
3. Retrieve source code or configuration files

**Hints:**
- Check `/ftp` directory
- Look for common backup extensions
- Try path traversal techniques
- Check for exposed `.git` folders

---

## Common Access Control Tests

```bash
# IDOR Testing - Change IDs
GET /api/Users/1
GET /api/Users/2
GET /api/Baskets/1
GET /api/Baskets/2

# Forced Browsing
GET /administration
GET /admin
GET /api/admin

# HTTP Method Tampering
GET /api/Users/1 -> 403
PUT /api/Users/1 -> 200?
DELETE /api/Users/1 -> 200?

# Path Traversal
GET /ftp/../../etc/passwd
GET /assets/../../etc/passwd
```

---

## Path Traversal Payloads

```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
....//....//....//etc/passwd
..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

---

## Challenge: Advanced Access Control

1. Can you access all users' data via API enumeration?
2. Can you delete other users' feedback?
3. Can you access the coupon codes?
4. Can you download the entire database backup?

---

## Success Criteria

- [ ] Accessed another user's basket
- [ ] Accessed the administration panel
- [ ] Downloaded at least one confidential file
- [ ] Documented all access control flaws

---

## Notes

Document your findings:

```
IDOR Vulnerabilities:
1. Endpoint: 
   - Accessed User ID: 

2. Endpoint: 
   - Accessed Data: 

Admin Access:
- URL: 
- Method: 

Sensitive Files Found:
1. 
2. 
3. 

Path Traversal Success:
- Payload: 
- File Accessed: 
```

---

**Next Exercise:** [Exercise 06 - API Exploitation](./exercise-06-api-exploitation.md)
