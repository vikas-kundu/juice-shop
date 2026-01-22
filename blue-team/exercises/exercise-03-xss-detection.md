# Blue Team Exercise 03: XSS Attack Detection

**Difficulty:** ⭐⭐ Intermediate  
**Time:** 20 minutes  
**Focus:** XSS Detection, Content Analysis, Security Headers

## Objective

Learn to detect Cross-Site Scripting (XSS) attacks in logs and understand protective measures.

## Prerequisites

- Completed previous exercises
- Access to application logs
- Understanding of XSS attack types

---

## Tasks

### Task 3.1: Identify XSS Patterns in Logs (7 minutes)

Search for XSS attack indicators:

**Common XSS Patterns to Detect:**
```html
<script>
</script>
javascript:
onerror=
onload=
onclick=
<img src=x
<svg onload
<iframe
alert(
document.cookie
```

**Kibana Queries:**
```
url.query:*<script>*
url.query:*javascript:*
url.query:*onerror*
url.query:*document.cookie*
message:*XSS*
```

**Command Line Analysis:**
```bash
# Find XSS patterns
grep -iE "(<script|javascript:|onerror|onload|<iframe|<svg)" ./logs/nginx/access.log

# URL decode and search
cat ./logs/nginx/access.log | python3 -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))" | grep -i "<script>"
```

---

### Task 3.2: Categorize XSS Attack Types (7 minutes)

Identify different types of XSS attempts:

**1. Reflected XSS:**
- Look for XSS payloads in URL parameters
- Query: `url.query:*<script>* AND http.response.status_code:200`

**2. Stored XSS:**
- Look for XSS payloads in POST bodies (feedback, comments)
- Check for successful form submissions with script tags

**3. DOM-Based XSS:**
- Look for payloads in URL fragments (#)
- Query: `url.path:*search* AND url.query:*<*`

**Analysis Questions:**
1. Which type of XSS is most common in your logs?
2. What endpoints are targeted for stored XSS?
3. Are the attacks automated or manual?

---

### Task 3.3: Evaluate Security Headers (6 minutes)

Check for protective security headers:

```bash
# Check response headers
curl -I http://localhost:8080

# Expected security headers:
# X-Content-Type-Options: nosniff
# X-Frame-Options: SAMEORIGIN
# X-XSS-Protection: 1; mode=block
# Content-Security-Policy: ...
```

**Missing Header Impact:**

| Header | Missing Impact |
|--------|----------------|
| Content-Security-Policy | XSS execution possible |
| X-XSS-Protection | Browser XSS filter disabled |
| X-Content-Type-Options | MIME sniffing attacks |
| X-Frame-Options | Clickjacking possible |

---

## XSS Detection Signatures

### Encoded Patterns to Watch

| Encoding | Pattern | Decoded |
|----------|---------|---------|
| URL | %3Cscript%3E | `<script>` |
| HTML | &#60;script&#62; | `<script>` |
| Unicode | \u003cscript\u003e | `<script>` |
| Double URL | %253Cscript%253E | `<script>` |

### Detection Regex
```regex
(<|%3C|&lt;|&#60;|\\u003c)(script|img|svg|iframe|body|input)
(javascript|vbscript|data)(\s)*:
on(error|load|click|mouse|focus|blur)(\s)*=
```

---

## Challenge: Advanced XSS Detection

1. Can you detect encoded XSS payloads?
2. How would you detect a successful stored XSS?
3. What indicators show XSS being used for session theft?

---

## Cookie Theft Detection

Look for indicators of successful cookie stealing:

```
# Outbound requests with cookies
url.path:*cookie*
message:*external* AND message:*cookie*

# Suspicious redirects
http.response.status_code:302 AND http.response.headers.location:*external*
```

---

## Success Criteria

- [ ] Identified XSS patterns in logs
- [ ] Categorized attack types (reflected, stored, DOM)
- [ ] Evaluated security header configuration
- [ ] Created XSS detection rules

---

## Incident Response for XSS

When XSS is detected:

1. **Immediate:**
   - [ ] Document attack details
   - [ ] Check if payload was stored

2. **Short-term:**
   - [ ] Review affected pages
   - [ ] Check for session theft indicators
   - [ ] Implement input validation

3. **Long-term:**
   - [ ] Deploy Content-Security-Policy
   - [ ] Implement output encoding
   - [ ] Security awareness training

---

## Notes

```
XSS Attempts Found:
- Reflected: 
- Stored: 
- DOM-Based: 

Vulnerable Endpoints:
1. 
2. 

Security Headers Status:
- CSP: [Present/Missing]
- X-XSS-Protection: [Present/Missing]
- X-Frame-Options: [Present/Missing]

Detection Rules Created:
1. 
2. 
```

---

**Next Exercise:** [Exercise 04 - Authentication Attack Detection](./exercise-04-auth-detection.md)
