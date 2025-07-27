#!/usr/bin/env python3
"""
Recon-Cell  - Elite Reconnaissance Framework (Enhanced)
Version: 2.3- (Security Hardened)
"""

import argparse
import asyncio
import concurrent.futures
import csv
import importlib.util
import ipaddress
import json
import logging
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Set, Tuple, Union, Optional, Any
from urllib.parse import urljoin

import aiohttp
import dns.resolver
import requests
import yaml
import xml.etree.ElementTree as ET

# --- Configuration ---
__version__ = "2.3-"
DEFAULT_PORTS = "80,443,8080,8443"
OUTPUT_DIR = "recon_results"
WEB_PORTS = {80, 443, 8080, 8443}
TIMEOUT = 5
SSL_VERIFY = True
CONFIG_PATH = os.path.expanduser("~/.recon-cell.yaml")
DEBUG = False
MAX_CIDR_HOSTS = 100000  # Maximum allowed hosts in CIDR range

# --- OpSec Configs (Optional) ---
HTTP_PROXY = os.environ.get("HTTP_PROXY")  # e.g., "socks5h://127.0.0.1:9050"
USER_AGENT_LIST = [
    "ReconCell/2.3",
    "Mozilla/5.0 (compatible; ReconCell/2.3-; +https://github.com/im-perfectcell/recon-cell)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
]

# --- Logging Setup ---
def setup_logging(debug: bool = False) -> logging.Logger:
    """Configure logging with file rotation and console output"""
    global DEBUG
    DEBUG = debug

    logger = logging.getLogger('recon-cell')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Remove existing handlers to avoid duplicate logs
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(ch)

    # File handler
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fh = RotatingFileHandler(
        os.path.join(OUTPUT_DIR, 'recon-cell.log'),
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(fh)

    return logger

logger = setup_logging()

# --- Configuration Management ---
def load_config() -> dict:
    """Load and validate configuration from YAML file"""
    default_config = {
        'ports': DEFAULT_PORTS,
        'threads': 10,
        'rate_limit': 10,
        'mode': 'normal',
        'dns_timeout': 5,
        'dns_retries': 3,
        'enum_tools': ['sublist3r'],
        'use_masscan': False,
        'capture_screenshots': False,
        'skip_subdomains': False,
        'force_scan': False,
        'run_vuln_scan': False,
    }
    
    # Valid configuration keys
    valid_keys = set(default_config.keys())
    
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                user_config = yaml.safe_load(f) or {}
                for key, value in user_config.items():
                    if key in valid_keys:
                        default_config[key] = value
                    else:
                        logger.warning(f"Ignoring invalid config key: {key}")
            logger.info("Loaded configuration from %s", CONFIG_PATH)
        except (yaml.YAMLError, OSError) as e:
            logger.error("Error loading config: %s", str(e))
    return default_config

# --- Helper Functions ---
def print_banner() -> None:
    """Print application banner"""
    print("="*60)
    print(f"  Recon-Cell  v{__version__} - Elite Reconnaissance Framework")
    print("="*60)
    print(f"[*] Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("Scan started")

def sanitize_domain(domain: str) -> str:
    """Sanitize domain input by removing dangerous characters"""
    return re.sub(r'[^a-zA-Z0-9.\-]', '', domain)

def validate_cidr(cidr: str) -> str:
    """Validate CIDR range with size warning"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > MAX_CIDR_HOSTS:
            logger.error(f"CIDR too large: {cidr} ({network.num_addresses} hosts)")
            sys.exit(1)
        if network.num_addresses > 1000:
            logger.warning(f"Large CIDR range: {cidr} ({network.num_addresses} hosts)")
            confirm = input("Continue? (y/n): ").lower()
            if confirm != 'y':
                logger.info("User aborted scan due to large CIDR range")
                sys.exit(0)
        return cidr
    except ValueError as e:
        logger.error("Invalid CIDR: %s - %s", cidr, str(e))
        sys.exit(1)

def parse_ports(ports_str: str) -> Set[int]:
    """Parse and validate port specifications safely"""
    ports = set()
    for part in ports_str.split(','):
        try:
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
        except ValueError as e:
            logger.error("Port parsing error: %s", str(e))
            sys.exit(1)
    return ports

def check_tool(tool: str) -> None:
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

def write_targets(targets: List[str], filename: str) -> None:
    """Write targets to a file safely"""
    try:
        with open(filename, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
        logger.debug("Wrote targets to %s", filename)
    except OSError as e:
        logger.error("Error writing targets: %s", str(e))

def parse_nmap_xml(xml_file: str) -> Dict[str, dict]:
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
    except (ET.ParseError, OSError) as e:
        logger.exception("XML parsing error: %s", str(e))
        return {}

def resolve_domain(domain: str, config: dict) -> Optional[str]:
    """Resolve domain to IP address with retries"""
    for attempt in range(config['dns_retries']):
        try:
            result = dns.resolver.resolve(domain, 'A', lifetime=config['dns_timeout'])
            if result:
                return str(result[0])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass
        except dns.resolver.NoNameservers as e:
            logger.debug("DNS resolution error (NoNameservers): %s", str(e))
        except dns.resolver.LifetimeTimeout as e:
            logger.debug("DNS resolution timeout: %s", str(e))
        except Exception as e:
            logger.debug("DNS resolution error: %s", str(e))
        
        logger.debug("DNS resolution failed for %s (attempt %d/%d)",
                     domain, attempt + 1, config['dns_retries'])
        time.sleep(0.5)
    
    logger.warning("DNS resolution failed for %s after %d attempts",
                   domain, config['dns_retries'])
    return None

def host_alive(host: str) -> bool:
    """Check if host is alive using ICMP ping safely"""
    try:
        param = '-n' if sys.platform.lower().startswith('win') else '-c'
        command = ['ping', param, '1', '-W', '2', host]
        return subprocess.call(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ) == 0
    except (OSError, subprocess.SubprocessError):
        return False

# --- Command Execution Abstraction ---
def run_command(cmd: Union[str, List[str]], tool_name: str) -> Optional[str]:
    """Execute a command safely with comprehensive error handling"""
    try:
        # Handle both string and list commands
        if isinstance(cmd, str):
            cmd_list = shlex.split(cmd)
        else:
            cmd_list = cmd
            
        logger.debug("Running command: %s", ' '.join(cmd_list))
        
        result = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=600
        )
        if DEBUG and result.stdout:
            logger.debug("%s output:\n%s", tool_name, result.stdout[:1000])
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error("%s failed: %s", tool_name, e.stderr.strip())
        return None
    except subprocess.TimeoutExpired:
        logger.error("%s timed out after 10 minutes", tool_name)
        return None
    except (OSError, ValueError) as e:
        logger.error("Command execution error: %s", str(e))
        return None

# --- Subdomain Enumeration ---
def enum_subdomains(target: str, output_dir: str, tools: List[str]], 
                   threads: int, timeout: int = 30) -> List[str]:
    """Enumerate subdomains using multiple tools safely"""
    out_file = os.path.join(output_dir, f"{target}_subdomains.txt")
    results = set()
    logger.info("Enumerating subdomains for %s...", target)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        tool_futures = []
        for tool in tools:
            if tool == 'sublist3r':
                cmd = ["sublist3r", "-d", target, "-t", str(timeout), "-o", out_file]
            elif tool == 'amass':
                cmd = ["amass", "enum", "-timeout", str(timeout), "-d", target, 
                       "-o", f"{out_file}.amass"]
            elif tool == 'subfinder':
                cmd = ["subfinder", "-timeout", str(timeout), "-d", target, 
                       "-o", f"{out_file}.subfinder"]
            else:
                continue
            tool_futures.append(executor.submit(run_command, cmd, tool))

        concurrent.futures.wait(tool_futures)

    for tool in tools:
        tool_file = f"{out_file}.{tool}" if tool != 'sublist3r' else out_file
        if os.path.exists(tool_file):
            try:
                with open(tool_file) as f:
                    results.update(line.strip() for line in f if line.strip())
            except OSError as e:
                logger.error("Error reading %s: %s", tool_file, str(e))

    if results:
        with open(out_file, 'w') as f:
            for d in sorted(results):
                f.write(f"{d}\n")
        logger.info("Found %d subdomains for %s", len(results), target)
        return list(results)
    else:
        logger.warning("No subdomains found for %s", target)
        return []

# --- Port Scanning ---
def run_port_scan(targets: List[str], ports: Set[int], config: dict) -> Dict[str, dict]:
    """Perform comprehensive port scanning safely"""
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
        cmd = [
            "masscan", "-iL", target_file, "-p", port_str, 
            f"--rate={masscan_rate}", "-oL", masscan_out
        ]
        if run_command(cmd, "Masscan") and os.path.exists(masscan_out):
            try:
                with open(masscan_out) as f:
                    for line in f:
                        if line.startswith('open tcp'):
                            parts = line.split()
                            ip, port = parts[3], int(parts[2])
                            masscan_results.setdefault(ip, []).append(port)
                logger.debug("Masscan found %d open ports", len(masscan_results))
            except OSError as e:
                logger.error("Error reading Masscan output: %s", str(e))

    nmap_out = target_file + ".nmap"
    version_intensity = "-sV --version-intensity 5" if config['mode'] in ['aggressive', 'normal'] else ""
    nmap_cmd = [
        "nmap", nmap_timing, "-Pn", 
        *shlex.split(version_intensity), 
        "-sS", "-p", port_str, "--open", 
        "-iL", target_file, "-oX", f"{nmap_out}.xml"
    ]
    run_command(nmap_cmd, "Nmap")

    nmap_file = f"{nmap_out}.xml"
    if not os.path.exists(nmap_file):
        logger.error("Nmap failed to create XML output")
        return {}

    nmap_results = parse_nmap_xml(nmap_file)

    # Merge Masscan and Nmap results
    for ip, ports_list in masscan_results.items():
        if ip not in nmap_results:
            nmap_results[ip] = {'hostnames': [], 'ports': []}
        for port in ports_list:
            if not any(p[0] == port for p in nmap_results[ip]['ports']):
                nmap_results[ip]['ports'].append(
                    (port, {'protocol': 'tcp', 'state': 'open', 'name': 'unknown'})
                )

    logger.info("Port scan completed for %d targets", len(targets))
    return nmap_results

# --- Technology Detection ---
def identify_tech(headers: Dict[str, str], url: str) -> List[str]:
    """Identify web technologies from response headers and URL"""
    tech = []
    server = headers.get('Server', '')
    if server:
        tech.append(f"Server: {server}")
        if 'Apache' in server: tech.append('Apache')
        if 'nginx' in server: tech.append('Nginx')
        if 'IIS' in server: tech.append('IIS')
    powered_by = headers.get('X-Powered-By', '')
    if powered_by:
        tech.append(f"PoweredBy: {powered_by}")
        if 'PHP' in powered_by: tech.append('PHP')
        if 'ASP.NET' in powered_by: tech.append('ASP.NET')
    if headers.get('X-Drupal-Cache'): tech.append('Drupal')
    if headers.get('X-Generator') == 'WordPress': tech.append('WordPress')
    if 'wp-' in url: tech.append('WordPress (URL pattern)')
    if 'django' in headers.get('Set-Cookie', ''): tech.append('Django')
    # Security headers
    for header in ['Content-Security-Policy', 'Strict-Transport-Security',
                   'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']:
        if header in headers:
            tech.append(f"Security: {header}")
    return list(set(tech))

# --- HTTP/Web Service Probing ---
async def check_web_service(session: aiohttp.ClientSession, 
                           host_port: Tuple[str, int], 
                           custom_headers: Optional[Dict[str, str]] = None) -> Optional[dict]:
    """Asynchronous web service check with optional proxy and OpSec features"""
    host, port = host_port
    schemes = ['https'] if port == 443 else ['http'] if port == 80 else ['http', 'https']
    headers = {'User-Agent': random.choice(USER_AGENT_LIST)}
    if custom_headers:
        headers.update(custom_headers)

    for scheme in schemes:
        url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
        try:
            async with session.head(
                url, 
                headers=headers, 
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                allow_redirects=True,
                ssl=SSL_VERIFY
            ) as resp:
                if resp.status >= 400:
                    async with session.get(
                        url, 
                        headers=headers, 
                        timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                        allow_redirects=True,
                        ssl=SSL_VERIFY
                    ) as get_resp:
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
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug("Connection error to %s: %s", url, str(e))
        except Exception as e:
            logger.debug("General error connecting to %s: %s", url, str(e))
    return None

async def check_web_services(targets: List[Tuple[str, int]], 
                            custom_headers: Optional[Dict[str, str]], 
                            rate_limit: int, 
                            max_workers: int) -> Dict[str, dict]:
    """Check web services asynchronously with rate limiting"""
    services = {}
    connector_args = dict(limit_per_host=5, ssl=SSL_VERIFY)
    if HTTP_PROXY:
        connector_args['proxy'] = HTTP_PROXY
    
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(**connector_args)
    ) as session:
        semaphore = asyncio.Semaphore(max_workers)
        limiter = asyncio.Semaphore(rate_limit) if rate_limit > 0 else None

        async def worker(target):
            async with semaphore:
                # Rate limiting
                if limiter:
                    async with limiter:
                        await asyncio.sleep(1/rate_limit if rate_limit > 0 else 0)
                        result = await check_web_service(session, target, custom_headers)
                else:
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

# --- Screenshot Capture ---
def capture_screenshot(url: str, output_dir: str) -> Optional[str]:
    """Capture website screenshot using Selenium safely"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        options.add_argument(f"user-agent={random.choice(USER_AGENT_LIST)}")

        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(3)
        safe_url = re.sub(r'[^\w\-]', '_', url)[:100]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_dir = os.path.join(output_dir, "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)
        screenshot_file = os.path.join(screenshot_dir, f"screenshot_{safe_url}_{timestamp}.png")
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

# --- Vulnerability Scanning ---
def run_vuln_scan(urls: List[str], output_dir: str, 
                 templates_path: Optional[str] = None) -> Optional[str]:
    """Run Nuclei vulnerability scan safely"""
    if not urls:
        logger.error("No URLs for vulnerability scanning")
        return None
        
    targets_file = os.path.join(output_dir, "vuln_targets.txt")
    write_targets(urls, targets_file)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    vuln_file = os.path.join(output_dir, f"vuln_report_{timestamp}.txt")
    templates = templates_path or "~/nuclei-templates/"
    
    cmd = ["nuclei", "-l", targets_file, "-t", templates, "-o", vuln_file]
    if run_command(cmd, "Nuclei"):
        logger.info("Vulnerability scan completed: %s", vuln_file)
        return vuln_file
    return None

# --- Export to CSV ---
def export_to_csv(results: Dict[str, Any], filename: str) -> str:
    """Export results to CSV format safely"""
    try:
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['Type', 'Target', 'Port', 'Status', 'Service', 'URL', 'Tech', 'Error']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            if 'cidr' in results:
                for ip, host_data in results['hosts'].items():
                    for service_key, service in host_data.get('services', {}).items():
                        _, port = service_key.split(':')
                        writer.writerow({
                            'Type': 'Web',
                            'Target': ip,
                            'Port': port,
                            'Status': service.get('status', ''),
                            'Service': service.get('headers', {}).get('Server', ''),
                            'URL': service.get('url', ''),
                            'Tech': ', '.join(service.get('tech', [])),
                            'Error': service.get('error', '')
                        })
                    for service_key, service in host_data.get('non_web_services', {}).items():
                        _, port = service_key.split(':')
                        writer.writerow({
                            'Type': 'Non-Web',
                            'Target': ip,
                            'Port': port,
                            'Status': '',
                            'Service': service.get('name', ''),
                            'URL': '',
                            'Tech': '',
                            'Error': service.get('error', '')
                        })
            else:
                for domain, domain_data in results.items():
                    for host, host_data in domain_data.items():
                        for service_key, service in host_data.get('services', {}).items():
                            _, port = service_key.split(':')
                            writer.writerow({
                                'Type': 'Web',
                                'Target': host,
                                'Port': port,
                                'Status': service.get('status', ''),
                                'Service': service.get('headers', {}).get('Server', ''),
                                'URL': service.get('url', ''),
                                'Tech': ', '.join(service.get('tech', [])),
                                'Error': service.get('error', '')
                            })
                        for service_key, service in host_data.get('non_web_services', {}).items():
                            _, port = service_key.split(':')
                            writer.writerow({
                                'Type': 'Non-Web',
                                'Target': host,
                                'Port': port,
                                'Status': '',
                                'Service': service.get('name', ''),
                                'URL': '',
                                'Tech': '',
                                'Error': service.get('error', '')
                            })
        logger.info("CSV report exported: %s", filename)
        return filename
    except (OSError, csv.Error) as e:
        logger.error("CSV export failed: %s", str(e))
        return ""

# --- Main Async Scan Logic ---
async def scan_targets(
    domains: Optional[List[str]] = None, 
    cidr: Optional[str] = None, 
    config: Optional[dict] = None, 
    custom_headers: Optional[Dict[str, str]] = None, 
    rate_limit: int = 0
) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """
    Scan domains or a CIDR range for services.
    Returns (results_dict, summary_dict, scan_type)
    """
    if config is None:
        config = {}
    
    all_targets = []
    resolved_targets = []
    scan_type = ""
    cidr_hosts = []
    
    if domains:
        scan_type = "domain"
        for domain in domains:
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
        for target in all_targets:
            ip = resolve_domain(target, config)
            if ip:
                if host_alive(ip) or config.get('force_scan', False):
                    resolved_targets.append(target)
                else:
                    logger.warning("Host %s (%s) is not responding to ping", target, ip)
            else:
                logger.warning("DNS resolution failed for %s", target)
    elif cidr:
        scan_type = "cidr"
        net = ipaddress.ip_network(cidr)
        cidr_hosts = [str(ip) for ip in net.hosts()]
        if len(cidr_hosts) > 1000:
            logger.warning("Scanning %d hosts in %s", len(cidr_hosts), cidr)
            confirm = input("Proceed? (y/n): ").lower()
            if confirm != 'y':
                logger.info("Scan aborted by user")
                sys.exit(0)
        resolved_targets = cidr_hosts

    if not resolved_targets:
        logger.error("No resolvable targets found")
        return {}, {}, scan_type

    logger.info("Scanning %d targets for open ports", len(resolved_targets))
    scan_results = run_port_scan(resolved_targets, config['ports'], config)
    if not scan_results:
        logger.error("No open ports found on any targets")
        return {}, {}, scan_type

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
    services = {}
    if web_targets:
        services = await check_web_services(
            web_targets,
            custom_headers,
            rate_limit,
            min(config['threads'] * 2, 50)
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
    results = {}
    if scan_type == "domain":
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
    elif scan_type == "cidr":
        results = {'cidr': cidr, 'hosts': {}}
        for ip, data in scan_results.items():
            results['hosts'][ip] = {
                'hostnames': data['hostnames'],
                'ports': data['ports'],
                'services': {k: v for k, v in services.items() if k.startswith(ip + ':')},
                'non_web_services': {k: v for k, v in non_web_services.items() if k.startswith(ip + ':')}
            }

    summary = {
        'total_subdomains': len(all_targets) - len(domains) if scan_type == "domain" else 0,
        'host_count': len(cidr_hosts) if scan_type == "cidr" else len(resolved_targets),
        'hosts_with_open_ports': len(scan_results),
        'active_services': len(services),
        'non_web_services': len(non_web_services)
    }
    return results, summary, scan_type

# --- Main Entry Point ---
async def async_main() -> None:
    """Asynchronous main function for scan execution"""
    start_time = datetime.now()
    parser = argparse.ArgumentParser(description=f"Recon-Cell  v{__version__}")
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
    parser.add_argument('--version', action='store_true', help="Show version")
    parser.add_argument('--no-subdomains', action='store_true', help="Skip subdomain enumeration")
    parser.add_argument('--force', action='store_true', help="Scan hosts even if they don't respond to ping")
    parser.add_argument('--debug', action='store_true', help="Enable debug output")

    args = parser.parse_args()

    # Setup logging based on debug flag
    global logger
    logger = setup_logging(args.debug)

    if args.version:
        print(f"Recon-Cell  v{__version__}")
        sys.exit(0)

    if not (args.domains or args.cidr):
        logger.error("Specify either domains or CIDR range")
        sys.exit(1)

    # Load configuration
    config = load_config()

    # Apply CLI overrides to config
    if args.ports:
        config['ports'] = args.ports
    if args.threads:
        config['threads'] = args.threads
    if args.rate_limit:
        config['rate_limit'] = args.rate_limit
    if args.mode:
        config['mode'] = args.mode
    if args.tools:
        config['enum_tools'] = args.tools.split(',')
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

    # Determine domains/cidr
    domains = []
    if args.domains:
        if os.path.isfile(args.domains):
            with open(args.domains) as f:
                domains = [sanitize_domain(line.strip()) for line in f if line.strip()]
        else:
            domains = [sanitize_domain(d) for d in args.domains.split(',')]

    results, summary, scan_type = await scan_targets(
        domains=domains if args.domains else None,
        cidr=args.cidr if args.cidr else None,
        config=config,
        custom_headers=custom_headers,
        rate_limit=config['rate_limit']
    )

    # Vulnerability scanning
    vuln_report = None
    if config['run_vuln_scan']:
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
    try:
        with open(out_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", out_file)
    except (OSError, json.JSONDecodeError) as e:
        logger.error("Error saving results: %s", str(e))

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
            print(f"CIDR: {args.cidr}")
            print(f"Hosts scanned: {summary['host_count']}")
        print(f"Hosts with open ports: {summary['hosts_with_open_ports']}")
        print(f"Active web services: {summary['active_services']}")
        print(f"Non-web services: {summary['non_web_services']}")
        if vuln_report:
            print(f"Vulnerability report: {vuln_report}")
        print("========================")

def main() -> None:
    """Main entry point for the application"""
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
