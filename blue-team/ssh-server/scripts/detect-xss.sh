#!/bin/bash
# Detect XSS attempts
echo "=== XSS Detection ==="
echo ""
grep -iE "(<script|javascript:|onerror|onload|onclick|<img|<svg|alert\(|document\.)" /var/log/nginx/access.log 2>/dev/null | tail -20
echo ""
echo "Total XSS attempts: $(grep -ciE "(<script|javascript:|onerror|onload)" /var/log/nginx/access.log 2>/dev/null || echo 0)"
