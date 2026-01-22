# Red Team Exercise 01: Reconnaissance & Information Gathering

**Difficulty:** ⭐ Beginner  
**Time:** 15 minutes  
**OWASP Category:** A01:2021 - Broken Access Control

## Objective

Perform initial reconnaissance on the Juice Shop application to discover attack surfaces, hidden endpoints, and gather information for further exploitation.

## Prerequisites

- Access to the Kali attack box or your local machine
- Target URL: `http://juice-shop:3000` (from container) or `http://localhost:3000` (from host)

---

## Tasks

### Task 1.1: Application Fingerprinting (5 minutes)

Identify the following information about the target:
1. What web framework/technology is the application built with?
2. What is the server technology?
3. Are there any exposed version numbers?

**Hints:**
- Check HTTP response headers
- Look at JavaScript files
- Examine the page source

---

### Task 1.2: Directory Enumeration (5 minutes)

Find hidden directories and files that may expose sensitive information:
1. Find at least 3 hidden or interesting endpoints
2. Locate the API documentation (if any)
3. Find any configuration or backup files

**Hints:**
- Use tools like `gobuster` or `dirb`
- Check for common paths like `/api`, `/admin`, `/swagger`
- Look for `.bak`, `.old`, `.git` files

---

### Task 1.3: JavaScript Analysis (5 minutes)

Analyze the client-side JavaScript to find:
1. Hardcoded secrets or API keys
2. Hidden routes or functionality
3. Authentication mechanisms

**Hints:**
- Look at `main.js` or bundled JavaScript files
- Search for keywords like `admin`, `secret`, `password`, `api`
- Use browser developer tools

---

## Challenge Questions

1. What is the email format used for accounts in the application?
2. Can you find any admin user information?
3. What security headers are missing from the application?

---

## Success Criteria

- [ ] Identified the technology stack
- [ ] Found at least 3 hidden endpoints
- [ ] Discovered at least 1 potential vulnerability or misconfiguration
- [ ] Documented all findings for use in future exercises

---

## Notes

Document your findings here:

```
Technology Stack:
- Frontend: 
- Backend: 
- Database: 

Hidden Endpoints Found:
1. 
2. 
3. 

Potential Vulnerabilities:
1. 
2. 
```

---

**Next Exercise:** [Exercise 02 - SQL Injection](./exercise-02-sql-injection.md)
