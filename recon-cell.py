#!/usr/bin/env python3
#
# Recon Cell - Elite Reconnaissance Framework v2.1
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
import socket
import logging
from logging.handlers import RotatingFileHandler
import asyncio
import aiohttp
import dns.resolver
import yaml
import importlib.util
from urllib.parse import urljoin
import random

# --- Configuration ---
__version__ = "2.1"
DEFAULT_PORTS = "80,443,8080,8443"
GITHUB_RAW_URL = "https://raw.githubusercontent.com/im-perfectcell/recon-cell/main/recon-cell.py"
OUTPUT_DIR = "recon_results"
WEB_PORTS = {80, 443, 8080, 8443}
TIMEOUT = 5
SSL_VERIFY = True
CONFIG_PATH = os.path.expanduser("~/.recon-cell.yaml")
DEBUG = False

# --- Logging Setup ---
def setup_logging(debug=False):
    """Configure logging with file rotation and console output"""
    global DEBUG
    DEBUG = debug
    
    logger = logging.getLogger('recon-cell')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    # File handler
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fh = RotatingFileHandler(
        os.path.join(OUTPUT_DIR, 'recon-cell.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    return logger

logger = setup_logging()

# --- Configuration Management ---
def load_config():
    """Load configuration from YAML file"""
    default_config = {
        'ports': DEFAULT_PORTS,
        'threads': 10,
        'rate_limit': 10,
        'mode': 'normal',
        'dns_timeout': 5,
        'dns_retries': 3
    }
    
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                user_config = yaml.safe_load(f)
                # Merge configs
                for key, value in user_config.items():
                    if isinstance(value, dict) and key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
            logger.info("Loaded configuration from %s", CONFIG_PATH)
        except Exception as e:
            logger.error("Error loading config: %s", str(e))
    
    return default_config

# --- Helper Functions ---
def print_banner():
    print("="*60)
    print(f"  RECON CELL v{__version__} - Elite Reconnaissance Framework")
    print("="*60)
    print(f"[*] Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("Scan started")

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
                logger.info("User aborted scan due to large CIDR range")
                sys.exit(0)
        return cidr
    except ValueError:
        logger.error("Invalid CIDR: %s", cidr)
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
        logger.error("%s not found", tool)
        install_commands = {
            'nmap': "sudo apt-get install nmap",
            'masscan': "sudo apt-get install masscan",
            'sublist3r': "pip install sublist3r",
            'amass': "sudo snap install amass",
            'nuclei': "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        }
        if tool in install_commands:
            logger.info("Install with: '%s'", install_commands[tool])
        sys.exit(1)
    logger.debug("%s is installed", tool)

def write_targets(targets, filename):
    """Write targets to a file"""
    with open(filename, 'w') as f:
        for target in targets:
            f.write(f"{target}\n")
    logger.debug("Wrote targets to %s", filename)

def parse_nmap_xml(xml_file):
    """Parse Nmap XML output for open ports and services"""
    try:
        logger.debug("Parsing Nmap XML: %s", xml_file)
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
        logger.debug("Parsed %d hosts from Nmap XML", len(services))
        return services
    except Exception as e:
        logger.exception("XML parsing error: %s", str(e))
        return {}

def resolve_domain(domain, config):
    """Resolve domain to IP address with retries"""
    for attempt in range(config['dns_retries']):
        try:
            result = dns.resolver.resolve(domain, 'A')
            if result:
                return str(result[0])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass
        except Exception as e:
            logger.debug("DNS resolution error: %s", str(e))
        
        logger.debug("DNS resolution failed for %s (attempt %d/%d)", 
                    domain, attempt+1, config['dns_retries'])
        time.sleep(0.5)
    
    logger.warning("DNS resolution failed for %s after %d attempts", 
                  domain, config['dns_retries'])
    return None

def host_alive(host):
    """Check if host is alive using ICMP ping"""
    try:
        param = '-n' if sys.platform.lower().startswith('win') else '-c'
        command = ['ping', param, '1', '-W', '2', host]
        return subprocess.call(command, stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False

# --- GitHub Auto-Update ---
def update_script():
    """Update script from GitHub repository"""
    logger.info("Checking for updates on GitHub...")
    
    try:
        # Fetch latest version
        response = requests.get(GITHUB_RAW_URL, timeout=10, verify=SSL_VERIFY)
        response.raise_for_status()
        new_content = response.text
        
        # Extract version from new script
        version_match = re.search(r'__version__\s*=\s*"([\d.]+)"', new_content)
        if not version_match:
            logger.error("Could not determine version from GitHub script")
            return False
            
        new_version = version_match.group(1)
        
        # Compare versions
        if tuple(map(int, new_version.split('.'))) <= tuple(map(int, __version__.split('.'))):
            logger.info("Already running latest version (%s)", __version__)
            return True
        
        # Create backup
        backup_path = f"{__file__}.bak"
        shutil.copyfile(__file__, backup_path)
        logger.info("Created backup: %s", backup_path)
        
        # Write new version
        with open(__file__, 'w') as f:
            f.write(new_content)
        
        # Set executable permissions
        os.chmod(__file__, 0o755)
        
        logger.info("Updated successfully to version %s!", new_version)
        print(f"[+] Updated to v{new_version}! Please rerun the script.")
        return True
        
    except requests.RequestException as e:
        logger.error("Update failed: %s", str(e))
        return False
    except Exception as e:
        logger.exception("Update error: %s", str(e))
        return False

# --- Core Functions ---
def run_command(cmd, tool_name):
    """Execute a command safely with comprehensive error handling"""
    logger.debug("Running command: %s", cmd)
    try:
        result = subprocess.run(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=600
        )
        if DEBUG:
            logger.debug("%s output:\n%s", tool_name, result.stdout[:1000])
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error("%s failed: %s", tool_name, e.stderr.strip())
        return None
    except subprocess.TimeoutExpired:
        logger.error("%s timed out after 10 minutes", tool_name)
        return None
    except Exception as e:
        logger.exception("Unexpected error with %s: %s", tool_name, str(e))
        return None

def enum_subdomains(target, output_dir, tools, threads, timeout=30):
    """Enumerate subdomains using multiple tools in parallel"""
    out_file = os.path.join(output_dir, f"{target}_subdomains.txt")
    results = set()
    logger.info("Enumerating subdomains for %s...", target)
    
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
                logger.error("Error reading %s: %s", tool_file, str(e))
    
    if results:
        with open(out_file, 'w') as f:
            for d in sorted(results):
                f.write(d + "\n")
        logger.info("Found %d subdomains for %s", len(results), target)
        return list(results)
    else:
        logger.warning("No subdomains found for %s", target)
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
            logger.debug("Masscan found %d open ports", len(masscan_results))
    
    nmap_out = target_file + ".nmap"
    version_intensity = "-sV --version-intensity 5" if config['mode'] in ['aggressive', 'normal'] else ""
    nmap_cmd = f"nmap {nmap_timing} -Pn {version_intensity} -sS -p {port_str} --open -iL {target_file} -oX {nmap_out}.xml"
    run_command(nmap_cmd, "Nmap")
    
    nmap_file = f"{nmap_out}.xml"
    if not os.path.exists(nmap_file):
        logger.error("Nmap failed to create XML output")
        return {}
    
    nmap_results = parse_nmap_xml(nmap_file)
    
    # Merge Masscan and Nmap results
    for ip, ports in masscan_results.items():
        if ip not in nmap_results:
            nmap_results[ip] = {'hostnames': [], 'ports': []}
        for port in ports:
            if not any(p[0] == port for p in nmap_results[ip]['ports']):
                nmap_results[ip]['ports'].append((port, {'protocol': 'tcp', 'state': 'open', 'name': 'unknown'}))
    
    logger.info("Port scan completed for %d targets", len(targets))
    return nmap_results

def identify_tech(response, url):
    """Identify web technologies from response headers"""
    tech = []
    headers = response
    
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
    if 'wp-' in url: tech.append('WordPress (URL pattern)')
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

async def check_web_service(session, host_port, custom_headers=None):
    """Asynchronous web service check"""
    host, port = host_port
    schemes = ['https'] if port == 443 else ['http'] if port == 80 else ['http', 'https']
    headers = {'User-Agent': f'ReconCell/{__version__}'}
    if custom_headers:
        headers.update(custom_headers)
    
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
        try:
            # First try HEAD request
            async with session.head(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as resp:
                # If HEAD not allowed, try GET
                if resp.status >= 400:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as get_resp:
                        resp = get_resp
                
                if resp.status < 400:
                    tech = identify_tech(resp.headers, str(resp.url))
                    logger.info("Valid service at %s (Status %d)", url, resp.status)
                    return {
                        'url': url,
                        'final_url': str(resp.url),
                        'status': resp.status,
                        'headers': dict(resp.headers),
                        'tech': tech
                    }
        except aiohttp.ClientError as e:
            logger.debug("Connection error to %s: %s", url, str(e))
        except asyncio.TimeoutError:
            logger.debug("Timeout connecting to %s", url)
    
    return None

async def check_web_services(targets, custom_headers, rate_limit, max_workers):
    """Check web services asynchronously with rate limiting"""
    services = {}
    connector = aiohttp.TCPConnector(limit_per_host=5, ssl=SSL_VERIFY)
    async with aiohttp.ClientSession(connector=connector) as session:
        semaphore = asyncio.Semaphore(max_workers)
        
        async def worker(target):
            async with semaphore:
                # Rate limiting
                await asyncio.sleep(1/rate_limit if rate_limit > 0 else 0)
                result = await check_web_service(session, target, custom_headers)
                return target, result
        
        tasks = [worker(target) for target in targets]
        for future in asyncio.as_completed(tasks):
            target, result = await future
            if result:
                host, port = target
                service_key = f"{host}:{port}"
                services[service_key] = result
    
    logger.info("Completed web service checks for %d targets", len(targets))
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
        options.add_argument(f"user-agent=ReconCell/{__version__}")
        
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(3)  # Allow page to load
        
        # Create safe filename
        safe_url = re.sub(r'[^\w\-]', '_', url)[:100]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_file = os.path.join(output_dir, f"screenshots/screenshot_{safe_url}_{timestamp}.png")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(screenshot_file), exist_ok=True)
        
        driver.save_screenshot(screenshot_file)
        driver.quit()
        logger.info("Captured screenshot for %s", url)
        return screenshot_file
    except ImportError:
        logger.error("Selenium not installed. Screenshots disabled.")
        return None
    except Exception as e:
        logger.error("Screenshot failed for %s: %s", url, str(e))
        return None

# --- Scan Functions ---
async def run_domain_scan(domains, config, custom_headers=None, rate_limit=0):
    """Scan domains and their subdomains for services"""
    all_targets = []
    resolved_targets = []
    
    for domain in domains:
        # DNS resolution check
        ip = resolve_domain(domain, config)
        if not ip:
            logger.warning("Skipping %s - DNS resolution failed", domain)
            continue
        
        if config.get('skip_subdomains'):
            logger.info("Skipping subdomain enumeration for %s", domain)
            all_targets.append(domain)
        else:
            subdomains = enum_subdomains(
                domain, 
                OUTPUT_DIR, 
                config['enum_tools'], 
                config['threads'],
                timeout=config.get('timeout', 30)
            )
            all_targets.extend([domain] + subdomains)
    
    # Resolve all targets and filter alive hosts
    for target in all_targets:
        ip = resolve_domain(target, config)
        if ip:
            if host_alive(ip) or config.get('force_scan', False):
                resolved_targets.append(target)
            else:
                logger.warning("Host %s (%s) is not responding to ping", target, ip)
        else:
            logger.warning("DNS resolution failed for %s", target)
    
    if not resolved_targets:
        logger.error("No resolvable targets found")
        return {}, {}
    
    logger.info("Scanning %d targets for open ports", len(resolved_targets))
    scan_results = run_port_scan(resolved_targets, config['ports'], config)
    
    if not scan_results:
        logger.error("No open ports found on any targets")
        return {}, {}
    
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
    
    logger.info("Found %d web services to check", len(web_targets))
    
    # Check web services
    services = {}
    if web_targets:
        services = await check_web_services(
            web_targets,
            custom_headers,
            rate_limit,
            min(config['threads'] * 2, 50)  # Max 50 threads
        )
    
    # Capture screenshots
    if config.get('capture_screenshots'):
        logger.info("Capturing screenshots for %d services", len(services))
        screenshot_dir = os.path.join(OUTPUT_DIR, "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)
        for service_key, service in services.items():
            screenshot = capture_screenshot(service['url'], screenshot_dir)
            if screenshot:
                service['screenshot'] = os.path.basename(screenshot)
    
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

async def run_cidr_scan(cidr, config, custom_headers=None, rate_limit=0):
    """Scan a CIDR range for services"""
    net = ipaddress.ip_network(cidr)
    targets = [str(ip) for ip in net.hosts()]
    
    if len(targets) > 1000:
        logger.warning("Scanning %d hosts in %s", len(targets), cidr)
        confirm = input("Proceed? (y/n): ").lower()
        if confirm != 'y':
            logger.info("Scan aborted by user")
            sys.exit(0)
    
    logger.info("Scanning %d hosts in %s", len(targets), cidr)
    scan_results = run_port_scan(targets, config['ports'], config)
    
    if not scan_results:
        logger.error("No open ports found on any hosts")
        return {}, {}
    
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
    
    logger.info("Found %d web services to check", len(web_targets))
    
    # Check web services
    services = {}
    if web_targets:
        services = await check_web_services(
            web_targets,
            custom_headers,
            rate_limit,
            min(config['threads'] * 2, 50)  # Max 50 threads
        )
    
    # Capture screenshots
    if config.get('capture_screenshots'):
        logger.info("Capturing screenshots for %d services", len(services))
        screenshot_dir = os.path.join(OUTPUT_DIR, "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)
        for service_key, service in services.items():
            screenshot = capture_screenshot(service['url'], screenshot_dir)
            if screenshot:
                service['screenshot'] = os.path.basename(screenshot)
    
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
        logger.error("No URLs for vulnerability scanning")
        return None
    
    targets_file = os.path.join(output_dir, "vuln_targets.txt")
    write_targets(urls, targets_file)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    vuln_file = os.path.join(output_dir, f"vuln_report_{timestamp}.txt")
    
    templates = templates_path or "~/nuclei-templates/"
    cmd = f"nuclei -l {targets_file} -t {templates} -o {vuln_file}"
    
    if run_command(cmd, "Nuclei"):
        logger.info("Vulnerability scan completed: %s", vuln_file)
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
    
    logger.info("CSV report exported: %s", filename)
    return filename

# --- Main Entry Point ---
async def async_main():
    start_time = datetime.now()
    parser = argparse.ArgumentParser(description=f"Recon Cell v{__version__}")
    parser.add_argument('-d', '--domains', help="Comma-separated domain list or file")
    parser.add_argument('-c', '--cidr', help="CIDR range to scan")
    parser.add_argument('-p', '--ports', help="Ports to scan")
    parser.add_argument('-t', '--threads', type=int, help="Number of threads")
    parser.add_argument('--rate-limit', type=int, help="Max requests per second for HTTP checks")
    parser.add_argument('--masscan', action='store_true', help="Use Masscan")
    parser.add_argument('--tools', help="Subdomain enumeration tools")
    parser.add_argument('--headers', help="Custom HTTP headers as JSON")
    parser.add_argument('--mode', choices=['stealth', 'normal', 'aggressive'], help="Scan mode")
    parser.add_argument('--screenshots', action='store_true', help="Capture screenshots of web services")
    parser.add_argument('--vuln-scan', action='store_true', help="Run vulnerability scan with Nuclei")
    parser.add_argument('--nuclei-templates', help="Path to custom Nuclei templates")
    parser.add_argument('--ssl-verify', action='store_true', help="Enable SSL certificate verification")
    parser.add_argument('--csv', action='store_true', help="Export results to CSV")
    parser.add_argument('--update', action='store_true', help="Update script from GitHub")
    parser.add_argument('--version', action='store_true', help="Show version")
    parser.add_argument('--no-subdomains', action='store_true', help="Skip subdomain enumeration")
    parser.add_argument('--force', action='store_true', help="Scan hosts even if they don't respond to ping")
    parser.add_argument('--debug', action='store_true', help="Enable debug output")
    
    args = parser.parse_args()
    
    # Setup logging based on debug flag
    global logger
    logger = setup_logging(args.debug)
    
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
        logger.error("Specify either domains or CIDR range")
        sys.exit(1)
    
    # Load configuration
    config = load_config()
    
    # Apply CLI overrides to config
    if args.ports: config['ports'] = args.ports
    if args.threads: config['threads'] = args.threads
    if args.rate_limit: config['rate_limit'] = args.rate_limit
    if args.mode: config['mode'] = args.mode
    if args.tools: config['enum_tools'] = args.tools.split(',')
    config['use_masscan'] = args.masscan
    config['capture_screenshots'] = args.screenshots
    config['run_vuln_scan'] = args.vuln_scan
    config['skip_subdomains'] = args.no_subdomains
    config['force_scan'] = args.force
    
    if args.ssl_verify:
        global SSL_VERIFY
        SSL_VERIFY = True
    
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
            logger.error("Selenium not installed. Screenshots disabled.")
            config['capture_screenshots'] = False
        elif not shutil.which("chromedriver"):
            logger.error("ChromeDriver not found. Screenshots disabled.")
            config['capture_screenshots'] = False
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print_banner()
    
    # Execute scan
    results = {}
    summary = {}
    scan_type = ""
    
    if args.domains:
        # Check if domains is a file
        if os.path.isfile(args.domains):
            with open(args.domains) as f:
                domains = [sanitize_domain(line.strip()) for line in f if line.strip()]
        else:
            domains = [sanitize_domain(d) for d in args.domains.split(',')]
        
        results, summary = await run_domain_scan(
            domains, 
            config, 
            custom_headers, 
            config['rate_limit']
        )
        scan_type = "domain"
    elif args.cidr:
        cidr = validate_cidr(args.cidr)
        results, summary = await run_cidr_scan(
            cidr, 
            config, 
            custom_headers, 
            config['rate_limit']
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
            logger.info("Running vulnerability scan on %d URLs", len(web_urls))
            vuln_report = run_vuln_scan(web_urls, OUTPUT_DIR, args.nuclei_templates)
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(OUTPUT_DIR, f"{scan_type}_results_{timestamp}.json")
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info("Results saved to %s", out_file)
    
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

def main():
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
