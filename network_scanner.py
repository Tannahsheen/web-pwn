import subprocess
import re
import requests
import json
import csv
from urllib.parse import urljoin, urlparse
from requests.auth import HTTPBasicAuth
import time
import os
import sys
from datetime import datetime
import argparse
import ipaddress
import socket

class NetworkScanner:
    def __init__(self, input_file, output_dir="scan_results", take_screenshots=False, debug=False, ports=None):
        self.input_file = input_file
        self.output_dir = output_dir
        self.take_screenshots = take_screenshots
        self.debug = debug
        self.results = []
        self.session = requests.Session()
        self.session.timeout = 10
        
        # Default ports to scan if not specified
        self.ports = ports if ports else [80, 443, 8080, 8443, 8000, 8888]
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
# Default credentials database
self.default_creds = {
    "BUFFALO": [
        {"username": "admin", "password": "password"},
        {"username": "root", "password": ""},
        {"username": "admin", "password": "admin"}
    ],
    "Fortigate": [
        {"username": "admin", "password": ""},
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"}
    ],
    "IIS Windows": [
        {"username": "administrator", "password": "password"},
        {"username": "admin", "password": "admin"},
        {"username": "iisadmin", "password": "password"}
    ],
    "Apache": [
        {"username": "admin", "password": "admin"},
        {"username": "root", "password": "password"},
        {"username": "apache", "password": "apache"}
    ],
    "nginx": [
        {"username": "admin", "password": "admin"},
        {"username": "nginx", "password": "nginx"}
    ],
    "Tomcat": [
        {"username": "tomcat", "password": "tomcat"},
        {"username": "admin", "password": "admin"},
        {"username": "manager", "password": "manager"}
    ],
    "pfSense": [
        {"username": "admin", "password": "pfsense"},
        {"username": "admin", "password": "admin"}
    ],
    "Ubiquiti": [
        {"username": "ubnt", "password": "ubnt"},
        {"username": "admin", "password": "admin"}
    ],
    "Netgear": [
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "1234"}
    ],
    "Linksys": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "", "password": "admin"}
    ],
    "D-Link": [
        {"username": "admin", "password": ""},
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"}
    ],
    "TP-Link": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"}
    ],
    "Cisco": [
        {"username": "admin", "password": "admin"},
        {"username": "cisco", "password": "cisco"},
        {"username": "admin", "password": "password"}
    ],
    "Juniper": [
        {"username": "root", "password": "Juniper"},
        {"username": "admin", "password": "admin"}
    ],
    "Polycom": [
        {"username": "Polycom", "password": "456"}
    ],
    "Zyxel": [
        {"username": "admin", "password": "1234"},
        {"username": "admin", "password": "admin"}
    ],
    "MikroTik": [
        {"username": "admin", "password": ""}
    ],
    "QNAP": [
        {"username": "admin", "password": "admin"}
    ],
    "Dell iDRAC": [
        {"username": "root", "password": "calvin"}
    ],
    "HP iLO": [
        {"username": "Administrator", "password": "admin"},
        {"username": "Administrator", "password": "password"}
    ],
    "Supermicro": [
        {"username": "ADMIN", "password": "ADMIN"}
    ],
    "MongoDB": [
        {"username": "admin", "password": "admin"},
        {"username": "root", "password": ""}
    ],
    "MySQL": [
        {"username": "root", "password": ""},
        {"username": "root", "password": "root"},
        {"username": "admin", "password": "admin"}
    ],
    "WordPress": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"}
    ],
    "Joomla": [
        {"username": "admin", "password": "admin"}
    ],
    "Drupal": [
        {"username": "admin", "password": "admin"}
    ],
    "SNMP": [
        {"community": "public"},
        {"community": "private"}
    ],
    "default": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": ""},
        {"username": "root", "password": "root"},
        {"username": "root", "password": "password"},
        {"username": "root", "password": ""},
        {"username": "administrator", "password": "password"},
        {"username": "user", "password": "user"}
    ]
}


    def log_debug(self, message):
        """Log debug messages if debug mode is enabled"""
        if self.debug:
            print(f"[DEBUG] {message}")

    def expand_targets(self):
        """Expand IP ranges and CIDR notation in the input file"""
        expanded_targets = []
        
        try:
            with open(self.input_file, "r") as infile:
                for line in infile:
                    target = line.strip()
                    if not target or target.startswith("#"):
                        continue
                    
                    try:
                        # Check if it's a CIDR notation
                        if "/" in target:
                            network = ipaddress.ip_network(target, strict=False)
                            for ip in network.hosts():
                                expanded_targets.append(str(ip))
                            self.log_debug(f"Expanded CIDR {target} to {len(list(network.hosts()))} IPs")
                        # Check if it's a range like 192.168.1.1-10
                        elif "-" in target and target.count(".") == 3:
                            base, range_end = target.rsplit(".", 1)[0], target.rsplit(".", 1)[1]
                            if "-" in range_end:
                                start, end = range_end.split("-")
                                for i in range(int(start), int(end) + 1):
                                    expanded_targets.append(f"{base}.{i}")
                                self.log_debug(f"Expanded range {target} to {int(end) - int(start) + 1} IPs")
                        else:
                            # It's a single IP
                            expanded_targets.append(target)
                    except Exception as e:
                        print(f"[!] Error processing target {target}: {e}")
                        # Just add it as is
                        expanded_targets.append(target)
        
        except FileNotFoundError:
            print(f"[!] Error: Input file {self.input_file} not found")
            return []
        
        print(f"[+] Expanded targets to {len(expanded_targets)} IPs")
        return expanded_targets

    def check_web_service(self, ip, port):
        """Check if a web service is running on the specified IP and port"""
        url = f"http://{ip}:{port}"
        try:
            response = self.session.get(url, timeout=5, allow_redirects=True)
            self.log_debug(f"Found web service at {url} - Status: {response.status_code}")
            return url, response
        except requests.exceptions.RequestException:
            pass
        
        # Try HTTPS
        url = f"https://{ip}:{port}"
        try:
            response = self.session.get(url, timeout=5, verify=False, allow_redirects=True)
            self.log_debug(f"Found web service at {url} - Status: {response.status_code}")
            return url, response
        except requests.exceptions.RequestException:
            return None, None

    def direct_web_scan(self):
        """Directly scan for web services without using WhatWeb"""
        print("[+] Starting direct web service scan...")
        
        # Suppress only the InsecureRequestWarning from urllib3
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        targets = self.expand_targets()
        services = []
        
        for ip in targets:
            print(f"[*] Scanning IP: {ip}")
            
            for port in self.ports:
                url, response = self.check_web_service(ip, port)
                if url and response:
                    print(f"[+] Found web service: {url}")
                    
                    # Extract title
                    title = "Unknown"
                    server = "Unknown"
                    
                    try:
                        # Try to extract title
                        title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL)
                        if title_match:
                            title = title_match.group(1).strip()
                        
                        # Get server header
                        server = response.headers.get('Server', 'Unknown')
                    except:
                        pass
                    
                    service_info = {
                        'ip': ip,
                        'port': port,
                        'url': url,
                        'title': title,
                        'server': server,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'device_type': self.identify_device_type(title, server),
                        'credentials_tested': [],
                        'successful_logins': []
                    }
                    
                    services.append(service_info)
                    print(f"[*] Found: {ip}:{port} - {title} ({server})")
        
        return services

    def run_whatweb_scan(self):
        """Run WhatWeb scan on all IPs/subnets in input file"""
        print(f"[+] Starting WhatWeb scan from {self.input_file}")
        
        # Check if WhatWeb is installed
        try:
            subprocess.run(["whatweb", "--version"], capture_output=True, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            print("[!] WhatWeb not found or not working. Make sure it's installed.")
            print("[!] Falling back to direct web scanning...")
            return None
        
        whatweb_output = os.path.join(self.output_dir, "whatweb_output.txt")
        
        try:
            with open(self.input_file, "r") as infile, open(whatweb_output, "w") as outfile:
                for ip in infile:
                    ip = ip.strip()
                    if ip and not ip.startswith("#"):
                        print(f"[*] Scanning: {ip}")
                        try:
                            # Use more aggressive options for better detection
                            result = subprocess.run(
                                ["whatweb", "--color=never", "-a", "3", ip], 
                                capture_output=True, 
                                text=True, 
                                timeout=60
                            )
                            outfile.write(result.stdout + "\n")
                            
                            # Debug output
                            if self.debug:
                                print(f"[DEBUG] WhatWeb output for {ip}:")
                                print(result.stdout)
                        except subprocess.TimeoutExpired:
                            print(f"[!] Timeout scanning {ip}")
                        except Exception as e:
                            print(f"[!] Error scanning {ip}: {e}")
                        
                        time.sleep(1)  # Rate limiting
            
            print(f"[+] WhatWeb output saved to {whatweb_output}")
            return whatweb_output
            
        except FileNotFoundError:
            print(f"[!] Error: Input file {self.input_file} not found")
            return None

    def parse_whatweb_output(self, whatweb_file):
        """Parse WhatWeb output and extract service information"""
        print("[+] Parsing WhatWeb output...")
        
        services = []
        
        try:
            with open(whatweb_file, "r") as file:
                content = file.read()
                
                # Debug the raw content
                if self.debug:
                    print("[DEBUG] Raw WhatWeb output:")
                    print(content[:500])  # Print first 500 chars
                
                # Split by lines and process each line
                lines = content.split("\n")
                for line in lines:
                    if not line.strip():
                        continue
                    
                    # Remove ANSI escape sequences
                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                    
                    # Debug the cleaned line
                    self.log_debug(f"Processing line: {clean_line[:100]}...")
                    
                    # Extract URL - try different patterns
                    url_match = re.search(r"(https?://[^\s]+)", clean_line)
                    if not url_match:
                        self.log_debug(f"No URL found in line: {clean_line[:50]}...")
                        continue
                    
                    url = url_match.group(1).rstrip(',')
                    self.log_debug(f"Found URL: {url}")
                    
                    try:
                        parsed_url = urlparse(url)
                        ip = parsed_url.hostname
                        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
                        
                        # Extract Title
                        title = "Unknown"
                        title_match = re.search(r"Title\[(.*?)\]", clean_line)
                        if title_match:
                            title = title_match.group(1).strip()
                        
                        # Extract HTTPServer if no title
                        server = "Unknown"
                        server_match = re.search(r"HTTPServer\[(.*?)\]", clean_line)
                        if server_match:
                            server = server_match.group(1).strip()
                        
                        # Extract other interesting fields
                        country = ""
                        country_match = re.search(r"Country\[(.*?)\]", clean_line)
                        if country_match:
                            country = country_match.group(1)
                        
                        service_info = {
                            'ip': ip,
                            'port': port,
                            'url': url,
                            'title': title,
                            'server': server,
                            'country': country,
                            'raw_output': clean_line.strip(),
                            'device_type': self.identify_device_type(title, server),
                            'credentials_tested': [],
                            'successful_logins': []
                        }
                        
                        services.append(service_info)
                        print(f"[*] Found: {ip}:{port} - {title} ({server})")
                    except Exception as e:
                        print(f"[!] Error parsing URL {url}: {e}")
        
        except FileNotFoundError:
            print(f"[!] Error: WhatWeb output file not found")
            return []
        
        return services

    def identify_device_type(self, title, server=""):
        """Identify device type based on title/server info"""
        # Combine title and server for better detection
        combined_text = (title + " " + server).lower()
        
        device_mappings = {
            'buffalo': 'BUFFALO',
            'fortigate': 'Fortigate',
            'fortinet': 'Fortigate',
            'iis': 'IIS Windows',
            'microsoft-iis': 'IIS Windows',
            'apache': 'Apache',
            'nginx': 'nginx',
            'tomcat': 'Tomcat',
            'pfsense': 'pfSense',
            'ubiquiti': 'Ubiquiti',
            'unifi': 'Ubiquiti',
            'netgear': 'Netgear',
            'linksys': 'Linksys',
            'd-link': 'D-Link',
            'tp-link': 'TP-Link',
            'cisco': 'Cisco'
        }
        
        for keyword, device_type in device_mappings.items():
            if keyword in combined_text:
                return device_type
        
        return 'Unknown'

    def test_http_basic_auth(self, url, username, password):
        """Test HTTP Basic Authentication"""
        try:
            # First, try without credentials to get baseline
            response_no_auth = self.session.get(url, timeout=10, verify=False)
        
            # Then try with credentials
            response_with_auth = self.session.get(url, auth=HTTPBasicAuth(username, password), timeout=10, verify=False)
        
            # If we get a 401 with credentials, auth definitely failed
            if response_with_auth.status_code == 401:
                return False
        
            # If we get a 200 without auth and 200 with auth, and the content is the same,
            # then auth probably isn't required or didn't work
            if (response_no_auth.status_code == 200 and 
                response_with_auth.status_code == 200 and 
                len(response_no_auth.text) > 0 and
                response_no_auth.text == response_with_auth.text):
                return False
        
            # If we got 401 without auth but 200 with auth, that's a real success
            if response_no_auth.status_code == 401 and response_with_auth.status_code == 200:
                return True
        
            # If we got 403 without auth but 200 with auth, that's also success
            if response_no_auth.status_code == 403 and response_with_auth.status_code == 200:
                return True
        
            # Check for authentication-related headers or content changes
            if response_with_auth.status_code == 200:
                # Look for signs that we're actually authenticated
                auth_indicators = [
                    'logout', 'dashboard', 'admin panel', 'configuration',
                    'settings', 'management', 'control panel'
                ]
            
                # Check if the authenticated response has different content
                if any(indicator in response_with_auth.text.lower() for indicator in auth_indicators):
                    # Make sure these indicators weren't in the non-auth response
                    if not any(indicator in response_no_auth.text.lower() for indicator in auth_indicators):
                        return True
        
            return False
        
        except Exception as e:
            self.log_debug(f"HTTP Basic Auth test failed for {url}: {e}")
            return False

    def test_form_login(self, url, username, password):
        """Test form-based login with better detection"""
        try:
            # Get the main page first to establish baseline
            main_response = self.session.get(url, timeout=10, verify=False)
            if main_response.status_code != 200:
                return False
        
            # Look for login forms in the main page
            login_form_indicators = [
                'type="password"', 'name="password"', 'id="password"',
                'login', 'signin', 'authenticate'
            ]
        
            has_login_form = any(indicator in main_response.text.lower() for indicator in login_form_indicators)
        
            # If no login form detected on main page, try common login URLs
            login_urls = [
                urljoin(url, '/login'),
                urljoin(url, '/admin'),
                urljoin(url, '/admin/login'),
                urljoin(url, '/login.php'),
                urljoin(url, '/admin.php'),
                urljoin(url, '/index.php')
            ]
        
            # If main page has login form, test it first
            if has_login_form:
                login_urls.insert(0, url)
        
            for login_url in login_urls:
                try:
                    # Get the login page
                    login_page_response = self.session.get(login_url, timeout=10, verify=False)
                    if login_page_response.status_code != 200:
                        continue
                
                    # Check if this page actually has a login form
                    if not any(indicator in login_page_response.text.lower() for indicator in login_form_indicators):
                        continue
                
                    # Common form field names
                    login_data_variants = [
                        {'username': username, 'password': password},
                        {'user': username, 'pass': password},
                        {'login': username, 'password': password},
                        {'email': username, 'password': password},
                        {'admin_user': username, 'admin_pass': password},
                        {'name': username, 'password': password}
                    ]
                
                    for login_data in login_data_variants:
                        try:
                            # Attempt login
                            response = self.session.post(
                                login_url, 
                                data=login_data, 
                                timeout=10, 
                                allow_redirects=True, 
                                verify=False
                            )
                        
                            # Check for successful login indicators
                            success_indicators = [
                                'dashboard', 'welcome', 'logout', 'admin panel', 
                                'configuration', 'settings', 'management', 'control panel',
                                'home', 'main menu'
                            ]
                        
                            failure_indicators = [
                                'invalid', 'error', 'failed', 'incorrect', 'denied',
                                'wrong', 'authentication failed', 'login failed',
                                'bad credentials', 'access denied'
                            ]
                        
                            response_text = response.text.lower()
                        
                            # Strong failure indicators
                            if any(indicator in response_text for indicator in failure_indicators):
                                continue
                        
                            # Check for success indicators
                            if any(indicator in response_text for indicator in success_indicators):
                                # Make sure we're not just seeing the same login page
                                if not any(indicator in login_page_response.text.lower() for indicator in login_form_indicators):
                                    return True
                        
                            # Check for redirect to different page (potential success)
                            if response.url != login_url:
                                # Make sure we didn't just get redirected back to login
                                final_response_text = response.text.lower()
                                if not any(indicator in final_response_text for indicator in login_form_indicators):
                                    if any(indicator in final_response_text for indicator in success_indicators):
                                        return True
                        
                            # Check if the response is significantly different from the login page
                            if (len(response.text) > 0 and 
                                len(login_page_response.text) > 0 and
                                abs(len(response.text) - len(login_page_response.text)) > 500):
                                # Content changed significantly, might be success
                                if not any(indicator in response_text for indicator in failure_indicators):
                                    return True
                                
                        except Exception as e:
                            self.log_debug(f"Form login attempt failed: {e}")
                            continue
                        
                except Exception as e:
                    self.log_debug(f"Error testing login URL {login_url}: {e}")
                    continue
        
            return False
        
        except Exception as e:
            self.log_debug(f"Form login test failed for {url}: {e}")
            return False

    def test_credentials(self, service):
        """Test default credentials for a service"""
        device_type = service['device_type']
        print(f"[*] Testing credentials for {service['ip']}:{service['port']} ({device_type})")
        
        # Only use device-specific credentials if we identified the device type
        # Otherwise use the default list, but never both
        if device_type != 'Unknown' and device_type in self.default_creds:
            creds_to_test = self.default_creds[device_type]
            print(f"    [*] Using {device_type}-specific credentials ({len(creds_to_test)} combinations)")
        else:
            creds_to_test = self.default_creds['default']
            print(f"    [*] Using generic default credentials ({len(creds_to_test)} combinations)")
        
        successful_logins = []
        
        for i, cred in enumerate(creds_to_test, 1):
            username = cred['username']
            password = cred['password']
        
            print(f"    [{i}/{len(creds_to_test)}] Trying {username}:{password}")
            service['credentials_tested'].append(f"{username}:{password}")
        
            # Test HTTP Basic Auth first
            if self.test_http_basic_auth(service['url'], username, password):
                print(f"    [+] SUCCESS: HTTP Basic Auth - {username}:{password}")
                successful_logins.append({
                    'method': 'HTTP Basic Auth',
                    'username': username,
                    'password': password
                })
                # Don't continue testing other methods for this credential
                continue
        
            # Test form-based login
            if self.test_form_login(service['url'], username, password):
                print(f"    [+] SUCCESS: Form Login - {username}:{password}")
                successful_logins.append({
                    'method': 'Form Login',
                    'username': username,
                    'password': password
                })
                # Don't continue testing other methods for this credential
                continue
        
            print(f"    [-] Failed: {username}:{password}")
            time.sleep(2)  # Rate limiting between attempts
        
        service['successful_logins'] = successful_logins
        
        if successful_logins:
            print(f"[+] Found {len(successful_logins)} successful login(s) for {service['ip']}")
        else:
            print(f"[-] No successful logins found for {service['ip']}")

    def take_screenshot(self, service):
        """Take screenshot of web interface (requires playwright)"""
        if not self.take_screenshots:
            return
        
        try:
            from playwright.sync_api import sync_playwright
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                
                screenshot_path = os.path.join(
                    self.output_dir, 
                    f"screenshot_{service['ip']}_{service['port']}.png"
                )
                
                page.goto(service['url'], timeout=30000)
                page.screenshot(path=screenshot_path)
                browser.close()
                
                service['screenshot'] = screenshot_path
                print(f"[+] Screenshot saved: {screenshot_path}")
                
        except ImportError:
            print("[!] Playwright not installed. Install with: pip install playwright")
        except Exception as e:
            print(f"[!] Screenshot failed for {service['url']}: {e}")

    def generate_report(self):
        """Generate detailed report of findings"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON Report
        json_report = os.path.join(self.output_dir, f"scan_report_{timestamp}.json")
        with open(json_report, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # CSV Report
        csv_report = os.path.join(self.output_dir, f"scan_report_{timestamp}.csv")
        with open(csv_report, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Port', 'URL', 'Title', 'Server', 'Device Type', 'Successful Logins', 'Credentials Tested'])
            
            for service in self.results:
                successful = '; '.join([f"{login['username']}:{login['password']} ({login['method']})" 
                                     for login in service['successful_logins']])
                tested = '; '.join(service['credentials_tested'])
                
                writer.writerow([
                    service['ip'],
                    service['port'],
                    service['url'],
                    service['title'],
                    service.get('server', 'Unknown'),
                    service['device_type'],
                    successful,
                    tested
                ])
        
        # Summary Report
        summary_report = os.path.join(self.output_dir, f"summary_{timestamp}.txt")
        with open(summary_report, 'w') as f:
            f.write("=== NETWORK SCAN SUMMARY ===\n\n")
            f.write(f"Scan completed: {datetime.now()}\n")
            f.write(f"Total services found: {len(self.results)}\n")
            
            successful_services = [s for s in self.results if s['successful_logins']]
            f.write(f"Services with successful logins: {len(successful_services)}\n\n")
            
            if successful_services:
                f.write("=== SUCCESSFUL LOGINS ===\n")
                for service in successful_services:
                    f.write(f"\n{service['ip']}:{service['port']} - {service['title']}\n")
                    for login in service['successful_logins']:
                        f.write(f"  ✓ {login['username']}:{login['password']} ({login['method']})\n")
        
        print(f"\n[+] Reports generated:")
        print(f"    JSON: {json_report}")
        print(f"    CSV: {csv_report}")
        print(f"    Summary: {summary_report}")

    def run_scan(self):
        """Main scanning function"""
        print("[+] Starting network scan...")
        
        # Step 1: Try WhatWeb scan first
        whatweb_file = self.run_whatweb_scan()
        
        # Step 2: Parse results or fall back to direct scanning
        if whatweb_file:
            self.results = self.parse_whatweb_output(whatweb_file)
            
            # If WhatWeb didn't find anything, fall back to direct scanning
            if not self.results:
                print("[!] WhatWeb didn't find any services. Falling back to direct scanning...")
                self.results = self.direct_web_scan()
        else:
            # WhatWeb not available or failed, use direct scanning
            self.results = self.direct_web_scan()
        
        if not self.results:
            print("[!] No services found. Try adjusting scan parameters or check target availability.")
            return
        
        print(f"[+] Found {len(self.results)} web services")
        
        # Step 3: Test credentials for each service
        for service in self.results:
            self.test_credentials(service)
            
            # Take screenshot if requested
            if self.take_screenshots:
                self.take_screenshot(service)
        
        # Step 4: Generate reports
        self.generate_report()
        
        # Print summary
        successful_services = [s for s in self.results if s['successful_logins']]
        print(f"\n[+] Scan complete!")
        print(f"[+] Total services: {len(self.results)}")
        print(f"[+] Successful logins: {len(successful_services)}")
        
        if successful_services:
            print("\n=== SUCCESSFUL LOGINS ===")
            for service in successful_services:
                print(f"{service['ip']}:{service['port']} - {service['title']}")
                for login in service['successful_logins']:
                    print(f"  ✓ {login['username']}:{login['password']} ({login['method']})")

def main():
    parser = argparse.ArgumentParser(description='Network Web Interface Scanner with Default Credential Testing')
    parser.add_argument('input_file', help='File containing IPs or subnets to scan')
    parser.add_argument('-o', '--output', default='scan_results', help='Output directory (default: scan_results)')
    parser.add_argument('-s', '--screenshots', action='store_true', help='Take screenshots (requires playwright)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    parser.add_argument('-p', '--ports', type=str, default='80,443,8080,8443,8000,8888', 
                        help='Comma-separated list of ports to scan (default: 80,443,8080,8443,8000,8888)')
    
    args = parser.parse_args()
    
    # Parse ports
    ports = [int(p) for p in args.ports.split(',')]
    
    scanner = NetworkScanner(args.input_file, args.output, args.screenshots, args.debug, ports)
    scanner.run_scan()

if __name__ == "__main__":
    main()
