# Exercise 03: XSS Detection - ANSWERS

## Task 3.1: XSS Pattern Identification

### Kibana Queries:

```kql
# Script tags
url.query:*<script>* OR url.query:*%3Cscript%3E*

# Event handlers
url.query:*onerror* OR url.query:*onload* OR url.query:*onclick*

# JavaScript protocol
url.query:*javascript:* OR url.query:*javascript%3A*

# Common XSS vectors
url.query:*<iframe* OR url.query:*<svg* OR url.query:*<img*
```

### Command Line Detection:

```bash
# Basic XSS detection
grep -iE "(<script|%3Cscript|javascript:|onerror=|onload=|<iframe|<svg)" ./logs/nginx/access.log

# URL decode and search
cat ./logs/nginx/access.log | while read line; do
  echo "$line" | python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))"
done | grep -i "<script>"

# Count XSS attempts
grep -ciE "(<script|javascript:|onerror)" ./logs/nginx/access.log

# Find XSS by source IP
grep -iE "(<script|onerror)" ./logs/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn
```

### Expected XSS Patterns in Logs:

```
# URL-encoded XSS
GET /rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E

# IMG tag based
GET /#/track-result?id=<img%20src=x%20onerror=alert(1)>

# JavaScript protocol
GET /#/search?q=javascript:alert(document.cookie)

# SVG-based
GET /api/Products/1?q=<svg%20onload=alert(1)>
```

---

## Task 3.2: XSS Attack Type Categorization

### Reflected XSS Detection:

```bash
# Find reflected XSS in search/track
grep -iE "search\?q=.*(<|%3C|javascript:)" ./logs/nginx/access.log
grep -iE "track-result\?id=.*(<|%3C)" ./logs/nginx/access.log
```

**Sample Findings:**
```
172.18.0.5 - GET /#/track-result?id=<iframe%20src="javascript:alert('XSS')"> 200
172.18.0.5 - GET /rest/products/search?q=<img%20src=x%20onerror=alert(1)> 200
```

### Stored XSS Detection:

```bash
# Check POST requests to feedback/reviews
grep "POST /api/Feedbacks" ./logs/nginx/security.log | grep -i "<script>"
grep "POST /api/Products/.*/reviews" ./logs/nginx/security.log | grep -i "onerror"
```

**Look for in request body:**
```json
{"comment": "<iframe src='javascript:alert(1)'>", "rating": 5}
{"review": "<img src=x onerror=alert(document.cookie)>"}
```

### DOM-Based XSS Detection:

```bash
# DOM XSS typically in URL fragments (harder to log)
# Check for patterns in hash-based URLs
grep -E "/#/.*<" ./logs/nginx/access.log
```

---

## Task 3.3: Security Headers Analysis

### Check Response Headers:

```bash
# Inspect headers from proxied traffic
curl -I http://localhost:8080

# Expected output (with our nginx config):
# X-Content-Type-Options: nosniff
# X-Frame-Options: SAMEORIGIN
# X-XSS-Protection: 1; mode=block

# Check direct Juice Shop headers
curl -I http://localhost:8000
```

### Security Header Assessment:

| Header | Status | Recommendation |
|--------|--------|----------------|
| Content-Security-Policy | ❌ Missing | Add strict CSP |
| X-Content-Type-Options | ✅ Present | Already configured |
| X-Frame-Options | ✅ Present | Already configured |
| X-XSS-Protection | ✅ Present | Already configured |
| Strict-Transport-Security | ❌ Missing | Add for HTTPS |

### Recommended CSP:

```
Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self' 'unsafe-inline' 'unsafe-eval'; 
  style-src 'self' 'unsafe-inline'; 
  img-src 'self' data:; 
  connect-src 'self';
  frame-ancestors 'none';
```

---

## Detection Regex Patterns

### Comprehensive XSS Detection:

```regex
# URL-encoded tags
(%3C|<)\s*(script|img|svg|iframe|body|input|div|form|a|link|style)

# Event handlers
on(error|load|click|mouseover|focus|blur|change|submit|keyup|keydown)\s*=

# JavaScript protocol
(javascript|vbscript|data)\s*:

# Encoded variations
%3C|%3E|&#60;|&#62;|&lt;|&gt;|\\u003c|\\u003e
```

### Python Detection Script:

```python
#!/usr/bin/env python3
"""XSS Detection Script"""

import re
import sys
from urllib.parse import unquote
from collections import defaultdict

XSS_PATTERNS = [
    r'<\s*script',
    r'<\s*img[^>]+onerror',
    r'<\s*svg[^>]+onload',
    r'<\s*iframe',
    r'javascript\s*:',
    r'on(error|load|click|mouseover)\s*=',
    r'document\.(cookie|location|write)',
    r'alert\s*\(',
    r'eval\s*\(',
]

def detect_xss(log_line):
    # URL decode
    decoded = unquote(unquote(log_line))
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, decoded, re.IGNORECASE):
            return pattern
    return None

def analyze_logs(log_file):
    findings = defaultdict(list)
    
    with open(log_file) as f:
        for line in f:
            pattern = detect_xss(line)
            if pattern:
                ip = line.split()[0]
                findings[pattern].append((ip, line.strip()[:100]))
    
    print("=== XSS Detection Results ===\n")
    for pattern, hits in sorted(findings.items(), key=lambda x: -len(x[1])):
        print(f"Pattern: {pattern}")
        print(f"Count: {len(hits)}")
        print(f"Sample: {hits[0][1]}\n")

if __name__ == "__main__":
    analyze_logs(sys.argv[1] if len(sys.argv) > 1 else "./logs/nginx/access.log")
```

---

## Summary

```
XSS Attempts Found:
- Reflected: 25 attempts
- Stored: 8 attempts (in feedback)
- DOM-Based: 12 attempts

Vulnerable Endpoints:
1. /#/track-result?id= (Reflected)
2. /rest/products/search?q= (Reflected)
3. /api/Feedbacks (Stored)

Security Headers Status:
- CSP: Missing - CRITICAL
- X-XSS-Protection: Present
- X-Frame-Options: Present

Detection Rules Created:
1. Script tag detection: <script OR %3Cscript
2. Event handler detection: onerror= OR onload=
3. JavaScript protocol: javascript:

Cookie Theft Indicators:
- Requests containing document.cookie
- Outbound requests to external domains
- Large response sizes after XSS injection
```

---

## Recommended Mitigations

1. **Deploy Content-Security-Policy**
   - Prevents inline script execution
   - Blocks unauthorized script sources

2. **Implement Output Encoding**
   - HTML entity encoding for user content
   - Context-aware encoding

3. **Input Validation**
   - Whitelist allowed characters
   - Reject known XSS patterns

4. **HTTPOnly Cookies**
   - Prevent JavaScript cookie access
   - Already should be default
