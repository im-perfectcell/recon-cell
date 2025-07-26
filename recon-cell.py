#!/usr/bin/env python3
#
# Recon Cell - Advanced Reconnaissance Framework v1.2
#
import subprocess
import os
import sys
import argparse
import ipaddress
import json
import re
import time
import requests
import concurrent.futures
from datetime import datetime
import shutil
import shlex
import xml.etree.ElementTree as ET
import csv

# --- Configuration ---
__version__ = "1.2"
DEFAULT_PORTS = "80,443,8080,8443,8000,8008,8088,8888,3000,5000,9000"
GITHUB_RAW_URL = "https://github.com/im-perfectcell/recon-cell/main/recon-cell.py"
OUTPUT_DIR = "recon_results"
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8088, 8888, 3000, 5000, 9000}
TIMEOUT = 5
SSL_VERIFY = False

# --- Helper Functions ---
def print_banner():
    print("="*60)
    print(f"  RECON CELL v{__version__} - Advanced Reconnaissance Framework")
    print("="*60)
    print(f"[*] Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def sanitize_domain(domain):
    """Sanitize domain input by removing dangerous characters"""
    return re.sub(r'[^a-zA-Z0-9.\-]', '', domain)

def validate_cidr(cidr):
    """Validate CIDR range with size warning"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > 1000:
            print(f"[WARNING] Large CIDR range: {cidr} ({network.num_addresses} hosts)")
            confirm = input("Continue? (y/n): ").lower()
            if confirm != 'y':
                print("Scan aborted")
                sys.exit(0)
        return cidr
    except ValueError:
        print(f"[ERROR] Invalid CIDR: {cidr}")
        sys.exit(1)

def parse_ports(ports_str):
    """Parse and validate port specifications efficiently"""
    ports = set()
    for part in ports_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
            ports.add(port)
    return ports

def check_tool(tool):
    """Check if a tool is installed with installation guidance"""
    if not shutil.which(tool):
        print(f"[ERROR] {tool} not found.")
        install_commands = {
            'nmap': "sudo apt-get install nmap",
            'masscan': "sudo apt-get install masscan",
            'sublist3r': "pip install sublist3r",
            'amass': "sudo snap install amass",
            'nuclei': "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        }
        if tool in install_commands:
            print(f"Install with: '{install_commands[tool]}'")
        sys.exit(1)
    print(f"[OK] {tool} is installed")

def write_targets(targets, filename):
    """Write targets to a file"""
    with open(filename, 'w') as f:
        for target in targets:
            f.write(f"{target}\n")

def parse_nmap_xml(xml_file):
    """Parse Nmap XML output for open ports and services"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        services = {}
        for host in root.findall('host'):
            address_elem = host.find('address[@addrtype="ipv4"]')
            if address_elem is None:
                continue
            ip = address_elem.get('addr')
            hostnames = [hn.get('name') for hn in host.findall('hostnames/hostname')]
            port_data = []
            for port in host.findall('ports/port'):
                port_id = int(port.get('portid'))
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                if state == 'open':
                    service_info = {'protocol': protocol, 'state': state}
                    service_elem = port.find('service')
                    if service_elem is not None:
                        for attr in ['name', 'product', 'version', 'extrainfo']:
                            if service_elem.get(attr):
                                service_info[attr] = service_elem.get(attr)
                    port_data.append((port_id, service_info))
            services[ip] = {'hostnames': hostnames, 'ports': port_data}
        return services
    except Exception as e:
        print(f"[!] XML parsing error: {str(e)}")
        return {}

# --- GitHub Auto-Update ---
def update_script():
    """Update script from GitHub repository"""
    print(f"[*] Checking for updates on GitHub...")
    
    try:
        # Fetch latest version
        response = requests.get(GITHUB_RAW_URL, timeout=10, verify=SSL_VERIFY)
        response.raise_for_status()
        new_content = response.text
        
        # Extract version from new script
        version_match = re.search(r'__version__\s*=\s*"([\d.]+)"', new_content)
        if not version_match:
            print("[!] Could not determine version from GitHub script")
            return False
            
        new_version = version_match.group(1)
        
        # Compare versions
        if tuple(map(int, new_version.split('.'))) <= tuple(map(int, __version__.split('.'))):
            print(f"[*] Already running latest version ({__version__})")
            return True
        
        # Create backup
        backup_path = f"{__file__}.bak"
        shutil.copyfile(__file__, backup_path)
        print(f"[+] Created backup: {backup_path}")
        
        # Write new version
        with open(__file__, 'w') as f:
            f.write(new_content)
        
        # Set executable permissions
        os.chmod(__file__, 0o755)
        
        print(f"[+] Updated successfully to version {new_version}!")
        print("[*] Please rerun the script to use the new version")
        return True
        
    except requests.RequestException as e:
        print(f"[!] Update failed: {str(e)}")
        return False
    except Exception as e:
        print(f"[!] Update error: {str(e)}")
        return False

# --- Core Functions ---
def run_command(cmd, tool_name):
    """Execute a command safely with comprehensive error handling"""
    try:
        result = subprocess.run(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=600
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] {tool_name} failed: {e.stderr.strip()}")
        return None
    except subprocess.TimeoutExpired:
        print(f"[!] {tool_name} timed out after 10 minutes")
        return None
    except Exception as e:
        print(f"[!] Unexpected error with {tool_name}: {str(e)}")
        return None

def enum_subdomains(target, output_dir, tools, threads, timeout=30):
    """Enumerate subdomains using multiple tools in parallel"""
    out_file = os.path.join(output_dir, f"{target}_subdomains.txt")
    results = set()
    print(f"[*] Enumerating subdomains for {target}...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        tool_futures = []
        for tool in tools:
            if tool == 'sublist3r':
                cmd = f"sublist3r -d {target} -t {timeout} -o {out_file}"
            elif tool == 'amass':
                cmd = f"amass enum -timeout {timeout} -d {target} -o {out_file}.amass"
            elif tool == 'subfinder':
                cmd = f"subfinder -timeout {timeout} -d {target} -o {out_file}.subfinder"
            tool_futures.append(executor.submit(run_command, cmd, tool))
        
        concurrent.futures.wait(tool_futures)
    
    for tool in tools:
        tool_file = f"{out_file}.{tool}" if tool != 'sublist3r' else out_file
        if os.path.exists(tool_file):
            try:
                with open(tool_file) as f:
                    results.update(line.strip() for line in f if line.strip())
            except Exception as e:
                print(f"[!] Error reading {tool_file}: {str(e)}")
    
    if results:
        with open(out_file, 'w') as f:
            for d in sorted(results):
                f.write(d + "\n")
        print(f"[+] Found {len(results)} subdomains for {target}")
        return list(results)
    else:
        print(f"[!] No subdomains found for {target}")
        return []

def run_port_scan(targets, ports, config):
    """Perform comprehensive port scanning with Masscan and Nmap"""
    use_masscan = config.get('use_masscan', False)
    threads = config['threads']
    target_file = os.path.join(OUTPUT_DIR, "targets.txt")
    write_targets(targets, target_file)
    port_str = ",".join(map(str, ports))
    
    # Adjust timing based on target count
    if len(targets) > 100:
        nmap_timing = '-T4'
        masscan_rate = 5000
    else:
        nmap_timing = '-T3'
        masscan_rate = 1000
        
    masscan_results = {}
    if use_masscan:
        masscan_out = target_file + ".masscan"
        cmd = f"masscan -iL {target_file} -p {port_str} --rate={masscan_rate} -oL {masscan_out}"
        if run_command(cmd, "Masscan") and os.path.exists(masscan_out):
            with open(masscan_out) as f:
                for line in f:
                    if line.startswith('open tcp'):
                        parts = line.split()
                        ip, port = parts[3], int(parts[2])
                        masscan_results.setdefault(ip, []).append(port)
    
    nmap_out = target_file + ".nmap"
    version_intensity = "-sV --version-intensity 5" if config['mode'] in ['aggressive', 'normal'] else ""
    nmap_cmd = f"nmap {nmap_timing} {version_intensity} -sS -p {port_str} --open -iL {target_file} -oX {nmap_out}.xml"
    run_command(nmap_cmd, "Nmap")
    
    nmap_results = parse_nmap_xml(f"{nmap_out}.xml")
    
    # Merge Masscan and Nmap results
    for ip, ports in masscan_results.items():
        if ip not in nmap_results:
            nmap_results[ip] = {'hostnames': [], 'ports': []}
        for port in ports:
            if not any(p[0] == port for p in nmap_results[ip]['ports']):
                nmap_results[ip]['ports'].append((port, {'protocol': 'tcp', 'state': 'open', 'name': 'unknown'}))
    
    return nmap_results

def identify_tech(response):
    """Identify web technologies from response headers"""
    tech = []
    headers = response.headers
    
    # Server identification
    server = headers.get('Server', '')
    if server: 
        tech.append(f"Server: {server}")
        if 'Apache' in server: tech.append('Apache')
        if 'nginx' in server: tech.append('Nginx')
        if 'IIS' in server: tech.append('IIS')
    
    # Framework detection
    powered_by = headers.get('X-Powered-By', '')
    if powered_by: 
        tech.append(f"PoweredBy: {powered_by}")
        if 'PHP' in powered_by: tech.append('PHP')
        if 'ASP.NET' in powered_by: tech.append('ASP.NET')
    
    # Application detection
    if headers.get('X-Drupal-Cache'): tech.append('Drupal')
    if headers.get('X-Generator') == 'WordPress': tech.append('WordPress')
    if 'wp-' in response.url: tech.append('WordPress (URL pattern)')
    if 'django' in headers.get('Set-Cookie', ''): tech.append('Django')
    
    # Security headers
    security_headers = [
        'Content-Security-Policy', 'Strict-Transport-Security',
        'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection'
    ]
    for header in security_headers:
        if header in headers:
            tech.append(f"Security: {header}")
    
    return list(set(tech))  # Deduplicate

def check_web_service_sync(host_port, custom_headers=None, rate_limit_delay=0):
    """Synchronous web service check with rate limiting"""
    if rate_limit_delay > 0:
        time.sleep(rate_limit_delay)
        
    host, port = host_port
    schemes = ['https'] if port == 443 else ['http'] if port == 80 else ['http', 'https']
    headers = {'User-Agent': 'ReconCell/1.2'}
    if custom_headers:
        headers.update(custom_headers)
    
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
        try:
            # First try HEAD request
            response = requests.head(
                url,
                headers=headers,
                allow_redirects=True,
                verify=SSL_VERIFY,
                timeout=TIMEOUT
            )
            
            # Fallback to GET if needed
            if response.status_code >= 400:
                response = requests.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    verify=SSL_VERIFY,
                    timeout=TIMEOUT
                )
            
            if response.status_code < 400:
                tech = identify_tech(response)
                print(f"[+] Valid service at {url} (Status {response.status_code})")
                return {
                    'url': url,
                    'final_url': response.url,
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'tech': tech
                }
        except requests.RequestException as e:
            print(f"[~] Connection error to {url}: {str(e)}")
    
    return None

def check_web_services_sync(targets, custom_headers, rate_limit, threads):
    """Check web services synchronously with rate limiting"""
    services = {}
    total = len(targets)
    rate_limit_delay = 1.0 / rate_limit if rate_limit > 0 else 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {}
        for i, target in enumerate(targets):
            # Calculate delay to maintain rate limit
            delay = i * rate_limit_delay if rate_limit > 0 else 0
            future = executor.submit(
                check_web_service_sync, 
                target, 
                custom_headers,
                delay
            )
            future_to_target[future] = target
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_target), 1):
            target = future_to_target[future]
            result = future.result()
            if result:
                host, port = target
                service_key = f"{host}:{port}"
                services[service_key] = result
                
            if i % 10 == 0 or i == total:
                print(f"[*] Checked {i}/{total} web services")
    
    return services

def capture_screenshot(url, output_dir):
    """Capture website screenshot using Selenium"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("user-agent=ReconCell/1.2")
        
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(3)  # Allow page to load
        
        # Create safe filename
        safe_url = re.sub(r'[^a-zA-Z0-9]', '_', url)[:100]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_file = os.path.join(output_dir, f"screenshot_{safe_url}_{timestamp}.png")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(screenshot_file), exist_ok=True)
        
        driver.save_screenshot(screenshot_file)
        driver.quit()
        return screenshot_file
    except ImportError:
        print("[!] Selenium not installed. Screenshots disabled.")
        return None
    except Exception as e:
        print(f"[!] Screenshot failed for {url}: {str(e)}")
        return None

# --- Scan Functions ---
def run_domain_scan(domains, config, custom_headers=None, rate_limit=0):
    """Scan domains and their subdomains for services"""
    all_targets = []
    for domain in domains:
        subdomains = enum_subdomains(
            domain, 
            OUTPUT_DIR, 
            config['enum_tools'], 
            config['threads'],
            timeout=config.get('timeout', 30)
        )
        all_targets.extend([domain] + subdomains)
    
    print(f"[*] Scanning {len(all_targets)} targets for open ports")
    scan_results = run_port_scan(all_targets, config['ports'], config)
    
    # Prepare targets for web service checks
    web_targets = []
    non_web_services = {}
    for host, data in scan_results.items():
        for port, service in data['ports']:
            if port in WEB_PORTS:
                web_targets.append((host, port))
            else:
                service_key = f"{host}:{port}"
                non_web_services[service_key] = service
    
    # Check web services
    print(f"[*] Checking {len(web_targets)} web services (Rate limit: {rate_limit}/sec)")
    services = check_web_services_sync(
        web_targets,
        custom_headers,
        rate_limit,
        min(config['threads'] * 2, 50)  # Max 50 threads
    )
    
    # Capture screenshots
    if config.get('capture_screenshots'):
        print("[*] Capturing screenshots")
        for service_key, service in services.items():
            screenshot = capture_screenshot(service['url'], OUTPUT_DIR)
            if screenshot:
                service['screenshot'] = screenshot
    
    # Organize results by domain
    results = {}
    for domain in domains:
        domain_results = {}
        for host, data in scan_results.items():
            if host == domain or host.endswith('.' + domain):
                domain_results[host] = {
                    'hostnames': data['hostnames'],
                    'ports': data['ports'],
                    'services': {k: v for k, v in services.items() if k.startswith(host + ':')},
                    'non_web_services': {k: v for k, v in non_web_services.items() if k.startswith(host + ':')}
                }
        results[domain] = domain_results
    
    summary = {
        'total_subdomains': len(all_targets) - len(domains),
        'hosts_with_open_ports': len(scan_results),
        'active_services': len(services),
        'non_web_services': len(non_web_services)
    }
    return results, summary

def run_cidr_scan(cidr, config, custom_headers=None, rate_limit=0):
    """Scan a CIDR range for services"""
    net = ipaddress.ip_network(cidr)
    targets = [str(ip) for ip in net.hosts()]
    
    if len(targets) > 1000:
        print(f"[WARNING] Scanning {len(targets)} hosts. This may take a while.")
        confirm = input("Proceed? (y/n): ").lower()
        if confirm != 'y':
            print("Scan aborted")
            sys.exit(0)
    
    print(f"[*] Scanning {len(targets)} hosts in {cidr}")
    scan_results = run_port_scan(targets, config['ports'], config)
    
    # Prepare targets for web service checks
    web_targets = []
    non_web_services = {}
    for ip, data in scan_results.items():
        for port, service in data['ports']:
            if port in WEB_PORTS:
                web_targets.append((ip, port))
            else:
                service_key = f"{ip}:{port}"
                non_web_services[service_key] = service
    
    # Check web services
    print(f"[*] Checking {len(web_targets)} web services (Rate limit: {rate_limit}/sec)")
    services = check_web_services_sync(
        web_targets,
        custom_headers,
        rate_limit,
        min(config['threads'] * 2, 50)  # Max 50 threads
    )
    
    # Capture screenshots
    if config.get('capture_screenshots'):
        print("[*] Capturing screenshots")
        for service_key, service in services.items():
            screenshot = capture_screenshot(service['url'], OUTPUT_DIR)
            if screenshot:
                service['screenshot'] = screenshot
    
    # Organize results
    results = {'cidr': cidr, 'hosts': {}}
    for ip, data in scan_results.items():
        results['hosts'][ip] = {
            'hostnames': data['hostnames'],
            'ports': data['ports'],
            'services': {k: v for k, v in services.items() if k.startswith(ip + ':')},
            'non_web_services': {k: v for k, v in non_web_services.items() if k.startswith(ip + ':')}
        }
    
    summary = {
        'host_count': len(targets),
        'hosts_with_open_ports': len(scan_results),
        'active_services': len(services),
        'non_web_services': len(non_web_services)
    }
    return results, summary

def run_vuln_scan(urls, output_dir, templates_path=None):
    """Run Nuclei vulnerability scan on discovered web services"""
    if not urls:
        print("[!] No URLs for vulnerability scanning")
        return None
    
    targets_file = os.path.join(output_dir, "vuln_targets.txt")
    write_targets(urls, targets_file)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    vuln_file = os.path.join(output_dir, f"vuln_report_{timestamp}.txt")
    
    templates = templates_path or "~/nuclei-templates/"
    cmd = f"nuclei -l {targets_file} -t {templates} -o {vuln_file}"
    
    if run_command(cmd, "Nuclei"):
        return vuln_file
    return None

def export_to_csv(results, filename):
    """Export results to CSV format"""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Type', 'Target', 'Port', 'Status', 'Service', 'URL', 'Tech']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        if 'cidr' in results:
            # CIDR scan results
            for ip, host_data in results['hosts'].items():
                # Web services
                for service_key, service in host_data.get('services', {}).items():
                    _, port = service_key.split(':')
                    writer.writerow({
                        'Type': 'Web',
                        'Target': ip,
                        'Port': port,
                        'Status': service.get('status', ''),
                        'Service': service.get('headers', {}).get('Server', ''),
                        'URL': service.get('url', ''),
                        'Tech': ', '.join(service.get('tech', []))
                    })
                
                # Non-web services
                for service_key, service in host_data.get('non_web_services', {}).items():
                    _, port = service_key.split(':')
                    writer.writerow({
                        'Type': 'Non-Web',
                        'Target': ip,
                        'Port': port,
                        'Status': '',
                        'Service': service.get('name', ''),
                        'URL': '',
                        'Tech': ''
                    })
        else:
            # Domain scan results
            for domain, domain_data in results.items():
                for host, host_data in domain_data.items():
                    # Web services
                    for service_key, service in host_data.get('services', {}).items():
                        _, port = service_key.split(':')
                        writer.writerow({
                            'Type': 'Web',
                            'Target': host,
                            'Port': port,
                            'Status': service.get('status', ''),
                            'Service': service.get('headers', {}).get('Server', ''),
                            'URL': service.get('url', ''),
                            'Tech': ', '.join(service.get('tech', []))
                        })
                    
                    # Non-web services
                    for service_key, service in host_data.get('non_web_services', {}).items():
                        _, port = service_key.split(':')
                        writer.writerow({
                            'Type': 'Non-Web',
                            'Target': host,
                            'Port': port,
                            'Status': '',
                            'Service': service.get('name', ''),
                            'URL': '',
                            'Tech': ''
                        })
    
    print(f"[+] CSV report exported: {filename}")
    return filename

# --- Main Entry Point ---
def main():
    start_time = datetime.now()
    parser = argparse.ArgumentParser(description=f"Recon Cell v{__version__}")
    parser.add_argument('-d', '--domains', help="Comma-separated domain list or file")
    parser.add_argument('-c', '--cidr', help="CIDR range to scan")
    parser.add_argument('-p', '--ports', default=DEFAULT_PORTS, help="Ports to scan")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads")
    parser.add_argument('--rate-limit', type=int, default=10, help="Max requests per second for HTTP checks")
    parser.add_argument('--masscan', action='store_true', help="Use Masscan")
    parser.add_argument('--tools', default='sublist3r,amass', help="Subdomain enumeration tools")
    parser.add_argument('--headers', help="Custom HTTP headers as JSON")
    parser.add_argument('--mode', choices=['stealth', 'normal', 'aggressive'], default='normal', help="Scan mode")
    parser.add_argument('--screenshots', action='store_true', help="Capture screenshots of web services")
    parser.add_argument('--vuln-scan', action='store_true', help="Run vulnerability scan with Nuclei")
    parser.add_argument('--nuclei-templates', help="Path to custom Nuclei templates")
    parser.add_argument('--ssl-verify', action='store_true', help="Enable SSL certificate verification")
    parser.add_argument('--csv', action='store_true', help="Export results to CSV")
    parser.add_argument('--update', action='store_true', help="Update script from GitHub")
    parser.add_argument('--version', action='store_true', help="Show version")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"Recon Cell v{__version__}")
        sys.exit(0)
        
    # Handle update request first
    if args.update:
        if update_script():
            sys.exit(0)
        else:
            sys.exit(1)
    
    if not (args.domains or args.cidr):
        print("[ERROR] Specify either domains or CIDR range")
        sys.exit(1)
    
    # Configuration
    try:
        ports = parse_ports(args.ports)
        config = {
            'ports': ports,
            'threads': args.threads,
            'use_masscan': args.masscan,
            'enum_tools': args.tools.split(','),
            'mode': args.mode,
            'capture_screenshots': args.screenshots,
            'run_vuln_scan': args.vuln_scan,
            'timeout': 30  # Subdomain enumeration timeout
        }
    except ValueError as e:
        print(f"[ERROR] {str(e)}")
        sys.exit(1)
    
    global SSL_VERIFY
    SSL_VERIFY = args.ssl_verify
    if not SSL_VERIFY:
        print("[WARNING] SSL certificate verification is disabled. Use --ssl-verify to enable.")
    
    custom_headers = json.loads(args.headers) if args.headers else None
    
    # Tool checks
    required_tools = {'nmap'}.union(set(config['enum_tools']))
    if config['use_masscan']:
        required_tools.add('masscan')
    if config['run_vuln_scan']:
        required_tools.add('nuclei')
    
    for tool in required_tools:
        check_tool(tool)
    
    # Screenshot dependencies
    if config['capture_screenshots']:
        if importlib.util.find_spec("selenium") is None:
            print("[!] Selenium not installed. Screenshots disabled.")
            config['capture_screenshots'] = False
        elif not shutil.which("chromedriver"):
            print("[!] ChromeDriver not found. Screenshots disabled.")
            config['capture_screenshots'] = False
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print_banner()
    
    # Execute scan
    if args.domains:
        # Check if domains is a file
        if os.path.isfile(args.domains):
            with open(args.domains) as f:
                domains = [sanitize_domain(line.strip()) for line in f if line.strip()]
        else:
            domains = [sanitize_domain(d) for d in args.domains.split(',')]
        
        results, summary = run_domain_scan(
            domains, 
            config, 
            custom_headers, 
            args.rate_limit
        )
        scan_type = "domain"
    elif args.cidr:
        cidr = validate_cidr(args.cidr)
        results, summary = run_cidr_scan(
            cidr, 
            config, 
            custom_headers, 
            args.rate_limit
        )
        scan_type = "cidr"
    
    # Vulnerability scanning
    vuln_report = None
    if config['run_vuln_scan']:
        # Collect all web URLs
        web_urls = []
        if scan_type == "domain":
            for domain_data in results.values():
                for host_data in domain_data.values():
                    for service in host_data.get('services', {}).values():
                        web_urls.append(service['url'])
        elif scan_type == "cidr":
            for host_data in results['hosts'].values():
                for service in host_data.get('services', {}).values():
                    web_urls.append(service['url'])
        
        if web_urls:
            print(f"[*] Running vulnerability scan on {len(web_urls)} URLs")
            vuln_report = run_vuln_scan(web_urls, OUTPUT_DIR, args.nuclei_templates)
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(OUTPUT_DIR, f"{scan_type}_results_{timestamp}.json")
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[*] Results saved to {out_file}")
    
    # Export to CSV if requested
    if args.csv:
        csv_file = os.path.join(OUTPUT_DIR, f"{scan_type}_results_{timestamp}.csv")
        export_to_csv(results, csv_file)
    
    # Print summary
    if summary:
        duration = datetime.now() - start_time
        print("\n===== Scan Summary =====")
        print(f"Execution time: {duration}")
        
        if scan_type == "domain":
            print(f"Domains: {', '.join(domains)}")
            print(f"Total subdomains: {summary['total_subdomains']}")
        elif scan_type == "cidr":
            print(f"CIDR: {cidr}")
            print(f"Hosts scanned: {summary['host_count']}")
        
        print(f"Hosts with open ports: {summary['hosts_with_open_ports']}")
        print(f"Active web services: {summary['active_services']}")
        print(f"Non-web services: {summary['non_web_services']}")
        
        if vuln_report:
            print(f"Vulnerability report: {vuln_report}")
        
        print("========================")

if __name__ == "__main__":
    main()
