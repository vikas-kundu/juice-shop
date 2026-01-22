# Exercise 01: Reconnaissance - ANSWERS

## Task 1.1: Application Fingerprinting

### Commands to Run:

```bash
# Check HTTP headers
curl -I http://localhost:8000

# Detailed header analysis
curl -v http://localhost:8000 2>&1 | grep -E "^< "

# Check for technology indicators
curl -s http://localhost:8000 | grep -E "(angular|react|vue|express)"
```

### Answers:

1. **Web Framework/Technology:** 
   - Frontend: Angular (visible in HTML and JavaScript)
   - Backend: Node.js with Express.js
   - Look for `ng-` attributes and Angular-specific patterns

2. **Server Technology:**
   - Express.js (visible in `X-Powered-By: Express` header)
   - To see: `curl -I http://localhost:8000 | grep "X-Powered-By"`

3. **Exposed Version Numbers:**
   - Check `/package.json` or `/main.js` for version info
   - Application version visible in UI (bottom of page)

---

## Task 1.2: Directory Enumeration

### Commands to Run:

```bash
# Using gobuster
gobuster dir -u http://localhost:8000 -w /usr/share/wordlists/dirb/common.txt

# Using dirb
dirb http://localhost:8000 /usr/share/wordlists/dirb/common.txt

# Manual checks
curl -s http://localhost:8000/api
curl -s http://localhost:8000/ftp
curl -s http://localhost:8000/api-docs
curl -s http://localhost:8000/swagger.json
curl -s http://localhost:8000/robots.txt
```

### Hidden Endpoints Found:

1. **`/ftp`** - Directory listing with downloadable files
   - Contains backup files and confidential documents
   - Access: `http://localhost:8000/ftp`

2. **`/api-docs`** - Swagger API documentation
   - Full API specification
   - Access: `http://localhost:8000/api-docs`

3. **`/rest/admin/application-version`** - Version disclosure
   - Exposes exact application version

4. **`/encryptionkeys`** - Exposed encryption keys (path traversal needed)

5. **`/api/Users`** - User enumeration endpoint

6. **`/administration`** - Admin panel (requires auth)

7. **`/#/score-board`** - Hidden scoreboard showing all challenges

---

## Task 1.3: JavaScript Analysis

### Commands to Run:

```bash
# Download and analyze main JavaScript
curl -s http://localhost:8000/main.js | head -5000 > main_analysis.js

# Search for interesting strings
curl -s http://localhost:8000/main.js | grep -oE '"[^"]*admin[^"]*"'
curl -s http://localhost:8000/main.js | grep -oE '"[^"]*password[^"]*"'
curl -s http://localhost:8000/main.js | grep -oE '"[^"]*secret[^"]*"'
curl -s http://localhost:8000/main.js | grep -oE '/api/[^"]*'

# Find routes
curl -s http://localhost:8000/main.js | grep -oE 'path:"[^"]*"'
```

### Findings:

1. **Hidden Routes Found:**
   - `/#/administration` - Admin panel
   - `/#/score-board` - Challenge scoreboard
   - `/#/accounting` - Accounting section
   - `/#/privacy-security/data-export` - Data export functionality

2. **Hardcoded Information:**
   - Admin email: `admin@juice-sh.op`
   - Default accounts visible in code

3. **Authentication Mechanism:**
   - JWT tokens used for authentication
   - Token stored in localStorage/sessionStorage

---

## Challenge Questions - Answers:

1. **Email Format:** `username@juice-sh.op`

2. **Admin User Information:**
   - Email: `admin@juice-sh.op`
   - Found in JavaScript analysis and scoreboard

3. **Missing Security Headers:**
   ```bash
   curl -I http://localhost:8000
   ```
   Missing headers:
   - `Content-Security-Policy`
   - `X-Content-Type-Options` 
   - `X-Frame-Options`
   - `Strict-Transport-Security`

---

## Complete Reconnaissance Summary:

```
Technology Stack:
- Frontend: Angular 15.x
- Backend: Node.js with Express.js
- Database: SQLite

Hidden Endpoints Found:
1. /ftp - File storage with sensitive files
2. /api-docs - Full API documentation
3. /#/score-board - Hidden scoreboard
4. /administration - Admin panel
5. /api/Users - User enumeration

Potential Vulnerabilities:
1. Information disclosure via /ftp
2. Missing security headers
3. Exposed API documentation
4. Version disclosure
5. Hidden admin functionality
```
