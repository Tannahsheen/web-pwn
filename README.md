# Network Web Interface Scanner

A Python tool that scans networks for web interfaces, identifies services, and tests default credentials.

## Features

- Scans networks for web interfaces using WhatWeb or direct HTTP/HTTPS probing
- Automatically detects device types (routers, firewalls, web servers, etc.)
- Tests common default credentials
- Optional screenshot capture
- Generates detailed reports (JSON, CSV, summary)
- Supports IP ranges, CIDR notation, and individual IPs

## Installation

1. Install Python dependencies:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

2. Install WhatWeb (optional but recommended):
\`\`\`bash
# Ubuntu/Debian
sudo apt-get install whatweb

# Or install from source
git clone https://github.com/urbanadventurer/WhatWeb.git
\`\`\`

3. For screenshots (optional):
\`\`\`bash
pip install playwright
playwright install chromium
\`\`\`

## Usage

Basic scan:
\`\`\`bash
python network_scanner.py targets.txt
\`\`\`

With screenshots:
\`\`\`bash
python network_scanner.py targets.txt --screenshots
\`\`\`

Custom output directory:
\`\`\`bash
python network_scanner.py targets.txt -o my_scan_results
\`\`\`

Debug mode:
\`\`\`bash
python network_scanner.py targets.txt --debug
\`\`\`

Custom ports:
\`\`\`bash
python network_scanner.py targets.txt --ports 80,443,8080,8443,9090
\`\`\`

## Input File Format

Create a text file with one IP, IP range, or subnet per line:
\`\`\`
192.168.1.1
192.168.1.0/24
10.0.0.1-10
172.16.1.0/24
example.com
\`\`\`

## How It Works

1. The tool first tries to use WhatWeb for service identification
2. If WhatWeb fails or finds no services, it falls back to direct HTTP/HTTPS probing
3. For each discovered web service, it identifies the device type
4. It tests appropriate default credentials based on the device type
5. It generates comprehensive reports of the findings

## Output

The tool generates:
- JSON report with detailed findings
- CSV report for spreadsheet analysis
- Summary text report
- Screenshots (if enabled)

## Supported Devices

The tool includes default credentials for:
- Buffalo routers
- Fortigate firewalls
- IIS servers
- Apache/nginx
- Tomcat
- pfSense
- Ubiquiti devices
- Netgear/Linksys/D-Link/TP-Link routers
- Cisco devices
- And many more...

## Legal Notice

This tool is for authorized security testing only. Only use on networks you own or have explicit permission to test.
