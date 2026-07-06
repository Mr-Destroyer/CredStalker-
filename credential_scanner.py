#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║         CREDENTIAL & SENSITIVE DATA SCANNER                   ║
║  Crawls websites and finds exposed credentials, API keys, etc.║
╚═══════════════════════════════════════════════════════════════╝

Author: Mr-Destroyer
GitHub: github.com/Mr-Destroyer
YouTube: @Study_Hard69
Instagram: @zimthegoat
Facebook: zimthegoat
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from collections import defaultdict
import json
import sys
from typing import Set, Dict, List, Tuple

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings()

class CredentialScanner:
    def __init__(self, base_url: str, max_depth: int = 3, verbose: bool = False):
        self.base_url = base_url
        self.max_depth = max_depth
        self.verbose = verbose
        self.visited_urls = set()
        self.domain = urlparse(base_url).netloc
        self.findings = defaultdict(list)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Regex patterns for detecting sensitive data
        self.patterns = {
            'api_key': [
                r'(?i)(api[_-]?key|apikey|api_token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?',
                r'(?i)(api[_-]?key)["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)["\']?',
            ],
            'password': [
                r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s,}]{6,})["\']?',
                r'(?i)(pass)["\']?\s*[:=]\s*["\']?([^"\'\s,}]{6,})["\']?',
                r'(?i)\.value\s*==\s*["\']([^"\']{6,})["\']',  # Catch hardcoded value checks
            ],
            'username': [
                r'(?i)(username|user|login|uname)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.@]{3,})["\']?',
                r'(?i)(admin|root|user)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_]{3,})["\']?',
                r'(?i)\.value\s*==\s*["\']([a-zA-Z0-9_\-\.@]{3,})["\']',  # Catch hardcoded value checks
            ],
            'bearer_token': [
                r'(?i)(bearer|token|auth)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_.]{20,})["\']?',
            ],
            'database_url': [
                r'(?i)(database[_-]?url|db[_-]?url|mongo[_-]?uri|sql[_-]?url)["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)["\']?',
            ],
            'private_key': [
                r'-----BEGIN[A-Z\s]+PRIVATE KEY-----[^-]+-----END[A-Z\s]+PRIVATE KEY-----',
            ],
            'aws_key': [
                r'AKIA[0-9A-Z]{16}',
            ],
            'email': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            ],
            'credit_card': [
                r'\b\d{4}[_\-\s]?\d{4}[_\-\s]?\d{4}[_\-\s]?\d{4}\b',
            ],
            'webhook_url': [
                r'(?i)(webhook|hook)[_-]?url["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)["\']?',
            ],
            'obfuscated_string': [
                r'(?i)(RevereString|reverse|atob|btoa|decode|encode)\s*\(\s*["\']([^"\']+)["\']\s*\)',
            ],
        }

    def scan(self):
        """Start scanning from base URL"""
        print(f"\n{'='*60}")
        print(f"🔍 Starting scan on: {self.base_url}")
        print(f"{'='*60}\n")
        
        self._crawl_url(self.base_url, depth=0)
        self._print_results()

    def _crawl_url(self, url: str, depth: int):
        """Recursively crawl URLs and extract sensitive data"""
        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        
        if self.verbose:
            print(f"[*] Crawling ({depth}): {url}")
        
        try:
            response = self.session.get(url, timeout=5, verify=False)
            if response.status_code != 200:
                return

            # Scan the content
            self._analyze_content(response.text, url)

            # Extract links if not at max depth
            if depth < self.max_depth:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(url, href)
                    
                    # Only crawl same domain
                    if urlparse(absolute_url).netloc == self.domain:
                        self._crawl_url(absolute_url, depth + 1)

        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[!] Error accessing {url}: {str(e)}")

    def _analyze_content(self, content: str, url: str):
        """Analyze content for sensitive data patterns"""
        
        # Extract and analyze JavaScript
        js_patterns = re.findall(r'<script[^>]*>([^<]*)</script>', content, re.IGNORECASE | re.DOTALL)
        for js_code in js_patterns:
            self._check_patterns(js_code, url, 'JavaScript')

        # Analyze HTML comments
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        for comment in comments:
            self._check_patterns(comment, url, 'HTML Comment')

        # Analyze meta tags and attributes
        self._check_patterns(content, url, 'HTML')

    def _check_patterns(self, text: str, url: str, source: str):
        """Check text against all patterns"""
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    finding = {
                        'url': url,
                        'type': pattern_type,
                        'match': match.group(0),
                        'source': source,
                    }
                    self.findings[pattern_type].append(finding)
                    if self.verbose:
                        print(f"[+] Found {pattern_type} in {source}: {match.group(0)[:50]}")

    def _print_results(self):
        """Print formatted results"""
        if not self.findings:
            print("\n✅ No sensitive data found!\n")
            return

        print(f"\n{'='*60}")
        print(f"🚨 FINDINGS SUMMARY")
        print(f"{'='*60}\n")

        total_findings = 0
        for finding_type, findings in self.findings.items():
            if findings:
                print(f"\n📌 {finding_type.upper()} ({len(findings)} found):")
                print(f"   {'-'*56}")
                
                for i, finding in enumerate(findings, 1):
                    total_findings += 1
                    print(f"\n   [{i}] URL: {finding['url']}")
                    print(f"       Source: {finding['source']}")
                    print(f"       Match: {finding['match'][:100]}")

        print(f"\n{'='*60}")
        print(f"📊 Total findings: {total_findings}")
        print(f"{'='*60}\n")

    def export_json(self, filename: str = "findings.json"):
        """Export findings to JSON"""
        with open(filename, 'w') as f:
            json.dump(dict(self.findings), f, indent=2)
        print(f"  Results exported to {filename}")


def print_banner():
    """Print scanner banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          🔍  CREDENTIAL & SENSITIVE DATA SCANNER  🔍             ║
║                                                                  ║
║  Author: Mr-Destroyer                                            ║
║  GitHub: github.com/Mr-Destroyer                                 ║
║  YouTube: @Study_Hard69                                          ║
║  Instagram: @zimthegoat                                          ║
║  Facebook: zimthegoat                                            ║
║                                                                  ║
║  Finds: API Keys | Passwords | Tokens | Private Keys            ║
║         Database URLs | Credit Cards | Emails | Webhooks        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    if len(sys.argv) < 2:
        print_banner()
        print("Usage: python credential_scanner.py <url> [--depth <max_depth>] [--verbose] [--export <filename>]")
        print("\nExamples:")
        print("  python credential_scanner.py http://example.com")
        print("  python credential_scanner.py http://example.com --depth 5 --verbose")
        print("  python credential_scanner.py http://example.com --export findings.json")
        sys.exit(1)

    url = sys.argv[1]
    max_depth = 3
    verbose = False
    export_file = None

    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--depth' and i + 1 < len(sys.argv):
            max_depth = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--verbose':
            verbose = True
            i += 1
        elif sys.argv[i] == '--export' and i + 1 < len(sys.argv):
            export_file = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    print_banner()
    scanner = CredentialScanner(url, max_depth=max_depth, verbose=verbose)
    scanner.scan()

    if export_file:
        scanner.export_json(export_file)


if __name__ == '__main__':
    main()
