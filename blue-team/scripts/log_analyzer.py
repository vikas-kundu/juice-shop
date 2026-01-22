#!/usr/bin/env python3
"""
Blue Team Log Analyzer
Comprehensive attack detection and reporting
"""

import re
import sys
import json
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote

class AttackDetector:
    def __init__(self):
        self.findings = defaultdict(list)
        self.stats = defaultdict(int)
        
        # Detection patterns
        self.sqli_patterns = [
            r"UNION\s+SELECT",
            r"OR\s+\d+=\d+",
            r"'--",
            r"%27--",
            r"SELECT\s+.*\s+FROM",
        ]
        
        self.xss_patterns = [
            r"<\s*script",
            r"javascript\s*:",
            r"on(error|load|click)\s*=",
            r"<\s*iframe",
            r"<\s*svg",
        ]
        
        self.traversal_patterns = [
            r"\.\./",
            r"%2e%2e",
            r"%252e",
        ]
        
        self.idor_patterns = [
            r"/api/Users/\d+",
            r"/rest/basket/\d+",
            r"/api/Feedbacks/\d+",
        ]
    
    def decode_url(self, text):
        """Double URL decode"""
        try:
            return unquote(unquote(text))
        except:
            return text
    
    def extract_info(self, line):
        """Extract key fields from log line"""
        parts = line.split()
        if len(parts) < 10:
            return None
        
        return {
            'ip': parts[0],
            'timestamp': parts[3].strip('['),
            'request': ' '.join(parts[5:8]),
            'status': parts[8] if len(parts) > 8 else '',
            'size': parts[9] if len(parts) > 9 else '',
            'raw': line
        }
    
    def check_patterns(self, text, patterns):
        """Check if any pattern matches"""
        decoded = self.decode_url(text)
        for pattern in patterns:
            if re.search(pattern, decoded, re.IGNORECASE):
                return pattern
        return None
    
    def analyze_line(self, line):
        """Analyze single log line for attacks"""
        info = self.extract_info(line)
        if not info:
            return
        
        # Check SQL Injection
        if pattern := self.check_patterns(info['request'], self.sqli_patterns):
            self.findings['sqli'].append({
                'ip': info['ip'],
                'timestamp': info['timestamp'],
                'pattern': pattern,
                'request': info['request'][:100]
            })
            self.stats['sqli'] += 1
        
        # Check XSS
        if pattern := self.check_patterns(info['request'], self.xss_patterns):
            self.findings['xss'].append({
                'ip': info['ip'],
                'timestamp': info['timestamp'],
                'pattern': pattern,
                'request': info['request'][:100]
            })
            self.stats['xss'] += 1
        
        # Check Path Traversal
        if pattern := self.check_patterns(info['request'], self.traversal_patterns):
            self.findings['traversal'].append({
                'ip': info['ip'],
                'timestamp': info['timestamp'],
                'pattern': pattern,
                'request': info['request'][:100]
            })
            self.stats['traversal'] += 1
        
        # Check IDOR
        if pattern := self.check_patterns(info['request'], self.idor_patterns):
            self.findings['idor'].append({
                'ip': info['ip'],
                'timestamp': info['timestamp'],
                'pattern': pattern,
                'request': info['request'][:100]
            })
            self.stats['idor'] += 1
        
        # Check brute force (401 on login)
        if '/rest/user/login' in info['request'] and info['status'] == '401':
            self.findings['bruteforce'].append({
                'ip': info['ip'],
                'timestamp': info['timestamp']
            })
            self.stats['bruteforce'] += 1
    
    def analyze_file(self, log_file):
        """Analyze entire log file"""
        with open(log_file) as f:
            for line in f:
                self.analyze_line(line)
    
    def get_attacker_stats(self):
        """Get statistics per attacker IP"""
        ip_stats = defaultdict(lambda: defaultdict(int))
        
        for attack_type, findings in self.findings.items():
            for finding in findings:
                ip_stats[finding['ip']][attack_type] += 1
        
        return dict(ip_stats)
    
    def generate_report(self):
        """Generate analysis report"""
        report = []
        report.append("=" * 60)
        report.append("BLUE TEAM LOG ANALYSIS REPORT")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("=" * 60)
        
        # Summary
        report.append("\n## SUMMARY\n")
        for attack_type, count in self.stats.items():
            report.append(f"- {attack_type.upper()}: {count} attempts")
        
        # Attacker Analysis
        report.append("\n## TOP ATTACKERS\n")
        ip_stats = self.get_attacker_stats()
        for ip, attacks in sorted(ip_stats.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]:
            total = sum(attacks.values())
            report.append(f"IP: {ip} - Total: {total} attacks")
            for attack_type, count in attacks.items():
                report.append(f"  - {attack_type}: {count}")
        
        # Detailed Findings
        report.append("\n## DETAILED FINDINGS\n")
        for attack_type, findings in self.findings.items():
            if findings:
                report.append(f"\n### {attack_type.upper()} ({len(findings)} attempts)\n")
                for finding in findings[:5]:  # First 5 examples
                    report.append(f"- [{finding.get('timestamp', 'N/A')}] {finding['ip']}")
                    if 'request' in finding:
                        report.append(f"  Request: {finding['request'][:80]}...")
        
        return '\n'.join(report)


def main():
    print("""
    ╔═══════════════════════════════════════════╗
    ║     BLUE TEAM LOG ANALYZER                ║
    ║     Attack Detection & Reporting          ║
    ╚═══════════════════════════════════════════╝
    """)
    
    log_file = sys.argv[1] if len(sys.argv) > 1 else "./logs/nginx/access.log"
    
    print(f"[*] Analyzing: {log_file}")
    
    detector = AttackDetector()
    
    try:
        detector.analyze_file(log_file)
        report = detector.generate_report()
        print(report)
        
        # Save report
        with open('attack_analysis_report.txt', 'w') as f:
            f.write(report)
        print(f"\n[+] Report saved to: attack_analysis_report.txt")
        
        # Save JSON findings
        with open('attack_findings.json', 'w') as f:
            json.dump(dict(detector.findings), f, indent=2)
        print(f"[+] Findings saved to: attack_findings.json")
        
    except FileNotFoundError:
        print(f"[-] Log file not found: {log_file}")
        print("    Make sure to run from the juice_shop directory")
        sys.exit(1)


if __name__ == "__main__":
    main()
