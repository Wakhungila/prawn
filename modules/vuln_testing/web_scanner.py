#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Vulnerability Scanner Module for PIN0CCHI0

This module performs comprehensive web vulnerability scanning using various
techniques and tools to identify common web vulnerabilities.
"""

import os
import json
import re
import time
import logging
from urllib.parse import urljoin, urlparse

from core.base_module import VulnTestingModule
from core.utils import make_request, run_command, ensure_dir_exists

# Configure logger
logger = logging.getLogger('pin0cchi0.vuln_testing.web_scanner')

class WebVulnerabilityScanner(VulnTestingModule):
    """Web Vulnerability Scanner module for PIN0CCHI0."""
    
    def __init__(self):
        """Initialize the Web Vulnerability Scanner module."""
        super().__init__()
        self.name = "Web Vulnerability Scanner"
        self.description = "Scans web applications for common vulnerabilities"
        self.category = "vuln_testing"
        self.author = "PIN0CCHI0 Team"
        self.version = "0.1.0"
        self.references = [
            "https://owasp.org/www-project-top-ten/",
            "https://portswigger.net/web-security"
        ]
        
        # Initialize results storage
        self.vulnerabilities = []
        self.scan_results = {}
        self.tool_outputs = {}
        
    def run(self, target, config=None):
        """Run the web vulnerability scanner on the target.
        
        Args:
            target (str): The target URL to scan
            config (dict): Configuration options for the scan
            
        Returns:
            dict: Scan results and identified vulnerabilities
        """
        logger.info(f"Starting web vulnerability scan on {target}")
        
        if config is None:
            config = {}
        
        # Ensure target is properly formatted
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Create results directory
        timestamp = int(time.time())
        results_dir = os.path.join(os.getcwd(), 'results', 'vuln_testing', f"web_scan_{timestamp}")
        ensure_dir_exists(results_dir)
        
        # Run different scanning techniques
        self._run_passive_analysis(target, config)
        self._run_active_scanning(target, config, results_dir)
        self._run_tool_scans(target, config, results_dir)
        
        # Consolidate and deduplicate results
        self._consolidate_results()
        
        # Save results to file
        results_file = os.path.join(results_dir, 'web_vulnerabilities.json')
        with open(results_file, 'w') as f:
            json.dump({
                'target': target,
                'timestamp': timestamp,
                'vulnerabilities': self.vulnerabilities,
                'scan_summary': {
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'critical': len([v for v in self.vulnerabilities if v.get('severity') == 'critical']),
                    'high': len([v for v in self.vulnerabilities if v.get('severity') == 'high']),
                    'medium': len([v for v in self.vulnerabilities if v.get('severity') == 'medium']),
                    'low': len([v for v in self.vulnerabilities if v.get('severity') == 'low']),
                    'info': len([v for v in self.vulnerabilities if v.get('severity') == 'info'])
                }
            }, f, indent=2)
        
        logger.info(f"Web vulnerability scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        logger.info(f"Results saved to {results_file}")
        
        return {
            'vulnerabilities': self.vulnerabilities,
            'results_file': results_file
        }
    
    def _run_passive_analysis(self, target, config):
        """Perform passive analysis of the target.
        
        This includes analyzing HTTP headers, cookies, and response content
        without actively testing for vulnerabilities.
        """
        logger.info(f"Performing passive analysis on {target}")
        
        # Get the main page
        response = make_request(target)
        
        if not response['success']:
            logger.warning(f"Failed to retrieve main page for passive analysis: {response.get('error', 'Unknown error')}")
            return
        
        # Analyze HTTP headers
        self._analyze_http_headers(response['headers'], target)
        
        # Analyze cookies
        self._analyze_cookies(response['headers'], target)
        
        # Analyze HTML content
        self._analyze_html_content(response['text'], target)
        
        logger.info("Passive analysis completed")
    
    def _analyze_http_headers(self, headers, target):
        """Analyze HTTP headers for security issues."""
        logger.info("Analyzing HTTP headers for security issues")
        
        # Check for missing security headers
        security_headers: Dict[str, Dict[str, str]] = {
            'Strict-Transport-Security': {
                'missing': "Missing HTTP Strict Transport Security (HSTS) header",
                'severity': "medium",
                'description': "HSTS header is missing, which helps protect against protocol downgrade attacks and cookie hijacking."
            },
            'Content-Security-Policy': {
                'missing': "Missing Content Security Policy (CSP) header",
                'severity': "medium",
                'description': "CSP header is missing, which helps mitigate XSS and data injection attacks."
            },
            'X-Content-Type-Options': {
                'missing': "Missing X-Content-Type-Options header",
                'severity': "low",
                'description': "X-Content-Type-Options header is missing, which prevents MIME type sniffing."
            },
            'X-Frame-Options': {
                'missing': "Missing X-Frame-Options header",
                'severity': "low",
                'description': "X-Frame-Options header is missing, which helps prevent clickjacking attacks."
            },
            'X-XSS-Protection': {
                'missing': "Missing X-XSS-Protection header",
                'severity': "low",
                'description': "X-XSS-Protection header is missing, which enables browser's built-in XSS protection."
            },
            'Referrer-Policy': {
                'missing': "Missing Referrer-Policy header",
                'severity': "info",
                'description': "Referrer-Policy header is missing, which controls how much referrer information is included with requests."
            },
            'Feature-Policy': {
                'missing': "Missing Feature-Policy/Permissions-Policy header",
                'severity': "info",
                'description': "Feature-Policy/Permissions-Policy header is missing, which allows control over browser features."
            },
            'Cache-Control': {
                'missing': "Missing Cache-Control header",
                'severity': "info",
                'description': "Cache-Control header is missing, which helps control browser and proxy caching behavior."
            }
        }
        
        # Convert headers to lowercase for case-insensitive comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, info in security_headers.items(): # type: ignore
            if header.lower() not in headers_lower:
                vuln = {
                    'name': info['missing'],
                    'severity': info['severity'],
                    'description': info['description'],
                    'location': target,
                    'evidence': f"Header '{header}' not found in response",
                    'type': 'missing_security_header',
                    'remediation': f"Add the {header} header to server responses"
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"Found vulnerability: {info['missing']}")
        
        # Check for insecure cookie attributes
        if 'set-cookie' in headers_lower:
            cookies = headers_lower['set-cookie'] # type: ignore
            if 'httponly' not in cookies.lower():
                vuln = {
                    'name': "Cookie without HttpOnly flag",
                    'severity': "medium",
                    'description': "Cookies are set without the HttpOnly flag, which helps mitigate the risk of client-side script accessing the cookie.",
                    'location': target,
                    'evidence': cookies,
                    'type': 'insecure_cookie',
                    'remediation': "Set the HttpOnly flag on all cookies containing sensitive data"
                }
                self.vulnerabilities.append(vuln)
                logger.info("Found vulnerability: Cookie without HttpOnly flag")
            
            if 'secure' not in cookies.lower() and target.startswith('https'):
                vuln = {
                    'name': "Cookie without Secure flag",
                    'severity': "medium",
                    'description': "Cookies are set without the Secure flag, which ensures cookies are only sent over HTTPS connections.",
                    'location': target,
                    'evidence': cookies,
                    'type': 'insecure_cookie',
                    'remediation': "Set the Secure flag on all cookies containing sensitive data"
                }
                self.vulnerabilities.append(vuln)
                logger.info("Found vulnerability: Cookie without Secure flag")
        
        # Check for information disclosure in headers
        sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
        for header in sensitive_headers:
            if header in headers_lower:
                vuln = {
                    'name': f"Information disclosure in {header.upper()} header",
                    'severity': "low",
                    'description': f"The {header.upper()} header reveals information about the technology stack being used.",
                    'location': target,
                    'evidence': f"{header.upper()}: {headers_lower[header]}",
                    'type': 'information_disclosure',
                    'remediation': f"Configure the server to not send the {header.upper()} header"
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"Found vulnerability: Information disclosure in {header.upper()} header")
    
    def _analyze_cookies(self, headers, target):
        """Analyze cookies for security issues."""
        logger.info("Analyzing cookies for security issues")
        
        # Check for cookies in headers
        if 'set-cookie' not in {k.lower(): v for k, v in headers.items()}: # type: ignore
            return
        
        cookies = headers.get('Set-Cookie') or headers.get('set-cookie')
        if not cookies:
            return
        
        # Check for SameSite attribute
        if 'samesite' not in cookies.lower():
            vuln = {
                'name': "Cookie without SameSite attribute",
                'severity': "low",
                'description': "Cookies are set without the SameSite attribute, which helps mitigate CSRF attacks.",
                'location': target,
                'evidence': cookies,
                'type': 'insecure_cookie',
                'remediation': "Set the SameSite attribute on all cookies"
            }
            self.vulnerabilities.append(vuln)
            logger.info("Found vulnerability: Cookie without SameSite attribute")
    
    def _analyze_html_content(self, html, target):
        """Analyze HTML content for security issues."""
        logger.info("Analyzing HTML content for security issues")
        
        # Check for forms without CSRF protection
        form_pattern = re.compile(r'<form[^>]*>.*?</form>', re.DOTALL | re.IGNORECASE) # type: ignore
        csrf_pattern = re.compile(r'csrf|token|nonce', re.IGNORECASE)
        
        forms = form_pattern.findall(html)
        for form in forms:
            if not csrf_pattern.search(form):
                vuln = {
                    'name': "Form without CSRF protection",
                    'severity': "medium",
                    'description': "A form was found without apparent CSRF protection, which could allow attackers to submit unauthorized requests.",
                    'location': target,
                    'evidence': form[:200] + '...' if len(form) > 200 else form,
                    'type': 'csrf',
                    'remediation': "Implement CSRF tokens for all forms"
                }
                self.vulnerabilities.append(vuln)
                logger.info("Found vulnerability: Form without CSRF protection")
        
        # Check for mixed content
        if target.startswith('https'):
            mixed_content_pattern = re.compile(r'src=["\']http://[^"\'>]*["\']', re.IGNORECASE) # type: ignore
            mixed_content = mixed_content_pattern.findall(html)
            
            if mixed_content:
                vuln = {
                    'name': "Mixed content",
                    'severity': "medium",
                    'description': "The page includes resources over HTTP when served over HTTPS, which can be intercepted and modified.",
                    'location': target,
                    'evidence': mixed_content[0],
                    'type': 'mixed_content',
                    'remediation': "Ensure all resources are loaded over HTTPS"
                }
                self.vulnerabilities.append(vuln)
                logger.info("Found vulnerability: Mixed content")
    
    def _run_active_scanning(self, target, config, results_dir):
        """Perform active scanning for vulnerabilities.
        
        This includes testing for XSS, SQLi, CSRF, etc. by sending
        potentially malicious payloads.
        """
        logger.info(f"Performing active scanning on {target}")
        
        # Get configuration options
        active_config = config.get('web_scanner', {}).get('active_scanning', {})
        enable_xss = active_config.get('xss', True)
        enable_sqli = active_config.get('sqli', True)
        enable_lfi = active_config.get('lfi', True)
        enable_rce = active_config.get('rce', False)  # Disabled by default as it can be dangerous
        
        # First, crawl the site to find endpoints
        endpoints = self._discover_endpoints(target)
        
        # Test each endpoint
        for endpoint in endpoints:
            if enable_xss:
                self._test_xss(endpoint, target)
            
            if enable_sqli:
                self._test_sqli(endpoint, target)
            
            if enable_lfi:
                self._test_lfi(endpoint, target)
            
            if enable_rce:
                self._test_rce(endpoint, target)
        
        logger.info("Active scanning completed")
    
    def _discover_endpoints(self, target):
        """Discover endpoints on the target for testing."""
        logger.info(f"Discovering endpoints on {target}")
        
        # Get the main page
        response = make_request(target) # type: ignore
        
        if not response['success']:
            logger.warning(f"Failed to retrieve main page for endpoint discovery: {response.get('error', 'Unknown error')}")
            return []
        
        html = response['text']
        
        # Find all links
        link_pattern = re.compile(r'href=["\']([^"\'#>]+)["\']', re.IGNORECASE)
        links = link_pattern.findall(html)
        
        # Find all forms
        form_pattern = re.compile(r'<form[^>]*action=["\']([^"\'#>]*)["\'][^>]*>', re.IGNORECASE)
        forms = form_pattern.findall(html)
        
        # Combine and normalize endpoints
        endpoints = []
        
        for link in links:
            # Handle relative URLs
            if not link.startswith(('http://', 'https://', '//')): 
                link = urljoin(target, link)
            elif link.startswith('//'):
                link = 'https:' + link if target.startswith('https') else 'http:' + link
            
            # Only include endpoints from the same domain
            if urlparse(link).netloc == urlparse(target).netloc:
                endpoints.append({'url': link, 'type': 'link'})
        
        for form in forms:
            # Handle empty action (submits to current page)
            if not form:
                form = urlparse(target).path or '/'
            
            # Handle relative URLs
            if not form.startswith(('http://', 'https://', '//')): 
                form = urljoin(target, form)
            elif form.startswith('//'):
                form = 'https:' + form if target.startswith('https') else 'http:' + form
            
            # Only include endpoints from the same domain
            if urlparse(form).netloc == urlparse(target).netloc:
                endpoints.append({'url': form, 'type': 'form'})
        
        # Deduplicate endpoints
        unique_endpoints = []
        seen_urls = set()
        
        for endpoint in endpoints:
            if endpoint['url'] not in seen_urls:
                seen_urls.add(endpoint['url'])
                unique_endpoints.append(endpoint)
        
        logger.info(f"Discovered {len(unique_endpoints)} unique endpoints")
        return unique_endpoints
    
    def _test_xss(self, endpoint, target):
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        url = endpoint['url']
        logger.info(f"Testing for XSS on {url}")
        
        # XSS test payloads
        xss_payloads: List[str] = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '\'"><img src=x onerror=alert(1)>',
            '<body onload=alert(1)>',
            '" onmouseover=alert(1) "',
            '\'onmouseover=alert(1)//'
        ]
        
        # Parse URL to get parameters
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        
        # If URL has query parameters, test each parameter
        if query:
            params = query.split('&')
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    
                    for payload in xss_payloads:
                        # Replace parameter value with payload
                        test_query = query.replace(f"{param_name}=", f"{param_name}={payload}")
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{test_query}"
                        
                        # Send request with payload
                        response = make_request(test_url)
                        
                        if response['success']:
                            # Check if payload is reflected in the response
                            if payload in response['text']:
                                vuln = {
                                    'name': "Reflected Cross-Site Scripting (XSS)",
                                    'severity': "high",
                                    'description': "A reflected XSS vulnerability was found, which could allow attackers to execute arbitrary JavaScript in users' browsers.",
                                    'location': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': f"Payload '{payload}' was reflected in the response",
                                    'type': 'xss',
                                    'remediation': "Implement proper input validation and output encoding"
                                }
                                self.vulnerabilities.append(vuln)
                                logger.info(f"Found XSS vulnerability in parameter {param_name} on {url}")
                                
                                # No need to test more payloads for this parameter
                                break
        
        # For forms, we would need to parse the form and submit it with payloads
        # This is a simplified version and would need to be expanded for real testing
        if endpoint['type'] == 'form':
            # Get the form
            response = make_request(url)
            
            if response['success']:
                html = response['text']
                
                # Find the form
                form_pattern = re.compile(r'<form[^>]*action=["\']([^"\'#>]*)["\'][^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
                form_matches = form_pattern.findall(html)
                
                for _, form_content in form_matches:
                    # Find input fields
                    input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                    inputs = input_pattern.findall(form_content)
                    
                    # Test each input field with XSS payloads
                    for input_name in inputs:
                        for payload in xss_payloads:
                            # This is a simplified approach and would need to be expanded
                            # In a real implementation, we would need to handle different form methods,
                            # maintain other form fields, etc.
                            test_url = f"{url}?{input_name}={payload}"
                            
                            # Send request with payload
                            response = make_request(test_url)
                            
                            if response['success']:
                                # Check if payload is reflected in the response
                                if payload in response['text']:
                                    vuln = {
                                        'name': "Reflected Cross-Site Scripting (XSS) in form",
                                        'severity': "high",
                                        'description': "A reflected XSS vulnerability was found in a form field, which could allow attackers to execute arbitrary JavaScript in users' browsers.",
                                        'location': url,
                                        'parameter': input_name,
                                        'payload': payload,
                                        'evidence': f"Payload '{payload}' was reflected in the response",
                                        'type': 'xss',
                                        'remediation': "Implement proper input validation and output encoding"
                                    }
                                    self.vulnerabilities.append(vuln)
                                    logger.info(f"Found XSS vulnerability in form field {input_name} on {url}")
                                    
                                    # No need to test more payloads for this input
                                    break
    
    def _test_sqli(self, endpoint, target):
        """Test for SQL Injection vulnerabilities."""
        url = endpoint['url']
        logger.info(f"Testing for SQL Injection on {url}")
        
        # SQL Injection test payloads
        sqli_payloads: List[str] = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1' --",
            "1\" OR \"1\"=\"1\" --",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR '1'='1' /*",
            "\" OR \"1\"=\"1\" /*",
            "') OR ('1'='1",
            "\"') OR (\"1\"=\"1"
        ]
        
        # Error patterns that might indicate SQL Injection
        error_patterns: List[str] = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "Oracle error",
            "Microsoft SQL Server",
            "PostgreSQL",
            "SQLite",
            "syntax error",
            "unclosed quotation mark",
            "unterminated string",
            "ODBC Driver"
        ]
        
        # Parse URL to get parameters
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        
        # If URL has query parameters, test each parameter
        if query:
            params = query.split('&')
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    
                    for payload in sqli_payloads:
                        # Replace parameter value with payload
                        test_query = query.replace(f"{param_name}=", f"{param_name}={payload}")
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{test_query}"
                        
                        # Send request with payload
                        response = make_request(test_url)
                        
                        if response['success']:
                            # Check for error messages that might indicate SQL Injection
                            for pattern in error_patterns:
                                if pattern.lower() in response['text'].lower():
                                    vuln = {
                                        'name': "SQL Injection",
                                        'severity': "high",
                                        'description': "A SQL Injection vulnerability was found, which could allow attackers to manipulate database queries.",
                                        'location': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'evidence': f"Error pattern '{pattern}' found in response",
                                        'type': 'sqli',
                                        'remediation': "Use parameterized queries or prepared statements"
                                    }
                                    self.vulnerabilities.append(vuln)
                                    logger.info(f"Found SQL Injection vulnerability in parameter {param_name} on {url}")
                                    
                                    # No need to test more payloads for this parameter
                                    break
                            
                            # Also check for successful injection by comparing with normal response
                            normal_url = url
                            normal_response = make_request(normal_url)
                            
                            if response['success'] and normal_response['success']:
                                # If response is significantly different, it might indicate successful injection
                                if len(response['text']) > len(normal_response['text']) * 1.5 or len(response['text']) < len(normal_response['text']) * 0.5:
                                    vuln = {
                                        'name': "Potential SQL Injection",
                                        'severity': "high",
                                        'description': "A potential SQL Injection vulnerability was found based on response size difference.",
                                        'location': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'evidence': f"Response size changed significantly with payload",
                                        'type': 'sqli',
                                        'remediation': "Use parameterized queries or prepared statements"
                                    }
                                    self.vulnerabilities.append(vuln)
                                    logger.info(f"Found potential SQL Injection vulnerability in parameter {param_name} on {url}")
                                    
                                    # No need to test more payloads for this parameter
                                    break
    
    def _test_lfi(self, endpoint, target):
        """Test for Local File Inclusion vulnerabilities."""
        url = endpoint['url']
        logger.info(f"Testing for Local File Inclusion on {url}")
        
        # LFI test payloads
        lfi_payloads: List[str] = [
            "../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "../../../../../../../etc/passwd%00",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini%00",
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "file:///etc/passwd",
            "file://C:\\windows\\win.ini"
        ]
        
        # Patterns that might indicate successful LFI
        lfi_patterns: List[str] = [
            "root:x:",  # Linux /etc/passwd
            "\[extensions\]",  # Windows win.ini
            "for 16-bit app support",  # Windows win.ini
            "\[fonts\]",  # Windows win.ini
            "\[files\]",  # Windows win.ini
            "\[mci extensions\]"  # Windows win.ini
        ]
        
        # Parse URL to get parameters
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        
        # If URL has query parameters, test each parameter
        if query:
            params = query.split('&')
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    
                    for payload in lfi_payloads:
                        # Replace parameter value with payload
                        test_query = query.replace(f"{param_name}=", f"{param_name}={payload}")
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{test_query}"
                        
                        # Send request with payload
                        response = make_request(test_url)
                        
                        if response['success']:
                            # Check for patterns that might indicate successful LFI
                            for pattern in lfi_patterns:
                                if pattern in response['text']:
                                    vuln = {
                                        'name': "Local File Inclusion (LFI)",
                                        'severity': "high",
                                        'description': "A Local File Inclusion vulnerability was found, which could allow attackers to read files on the server.",
                                        'location': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'evidence': f"Pattern '{pattern}' found in response",
                                        'type': 'lfi',
                                        'remediation': "Validate and sanitize file paths, use whitelists for included files"
                                    }
                                    self.vulnerabilities.append(vuln)
                                    logger.info(f"Found LFI vulnerability in parameter {param_name} on {url}")
                                    
                                    # No need to test more payloads for this parameter
                                    break
    
    def _test_rce(self, endpoint, target):
        """Test for Remote Code Execution vulnerabilities."""
        url = endpoint['url']
        logger.info(f"Testing for Remote Code Execution on {url}")
        
        # RCE test payloads (non-destructive)
        rce_payloads: List[str] = [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            ";whoami",
            "|whoami",
            "`whoami`",
            "$(whoami)",
            ";echo PIN0CCHI0_RCE_TEST",
            "|echo PIN0CCHI0_RCE_TEST",
            "`echo PIN0CCHI0_RCE_TEST`",
            "$(echo PIN0CCHI0_RCE_TEST)"
        ]
        
        # Patterns that might indicate successful RCE
        rce_patterns: List[str] = [
            "uid=",  # Output of id command
            "gid=",  # Output of id command
            "PIN0CCHI0_RCE_TEST"  # Our test string
        ]
        
        # Parse URL to get parameters
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        
        # If URL has query parameters, test each parameter
        if query:
            params = query.split('&')
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    
                    for payload in rce_payloads:
                        # Replace parameter value with payload
                        test_query = query.replace(f"{param_name}=", f"{param_name}={payload}")
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{test_query}"
                        
                        # Send request with payload
                        response = make_request(test_url)
                        
                        if response['success']:
                            # Check for patterns that might indicate successful RCE
                            for pattern in rce_patterns:
                                if pattern in response['text']:
                                    vuln = {
                                        'name': "Remote Code Execution (RCE)",
                                        'severity': "critical",
                                        'description': "A Remote Code Execution vulnerability was found, which could allow attackers to execute arbitrary commands on the server.",
                                        'location': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'evidence': f"Pattern '{pattern}' found in response",
                                        'type': 'rce',
                                        'remediation': "Avoid using shell commands with user input, use safer alternatives, implement proper input validation"
                                    }
                                    self.vulnerabilities.append(vuln)
                                    logger.info(f"Found RCE vulnerability in parameter {param_name} on {url}")
                                    
                                    # No need to test more payloads for this parameter
                                    break
    
    def _run_tool_scans(self, target, config, results_dir):
        """Run external security tools for vulnerability scanning."""
        logger.info(f"Running external security tools on {target}")
        
        # Get configuration options
        tools_config = config.get('web_scanner', {}).get('tools', {})
        enable_nikto = tools_config.get('nikto', True)
        enable_zap = tools_config.get('zap', False)  # Disabled by default as it requires setup
        enable_sqlmap = tools_config.get('sqlmap', False)  # Disabled by default as it can be intensive
        
        # Run Nikto
        if enable_nikto:
            self._run_nikto(target, results_dir)
        
        # Run ZAP
        if enable_zap:
            self._run_zap(target, results_dir)
        
        # Run SQLMap
        if enable_sqlmap:
            self._run_sqlmap(target, results_dir)
        
        logger.info("External tool scans completed")
    
    def _run_nikto(self, target, results_dir):
        """Run Nikto web scanner."""
        logger.info(f"Running Nikto on {target}")
        
        # Prepare output file
        output_file = os.path.join(results_dir, 'nikto_results.json')
        
        # Run Nikto command
        cmd = f"nikto -h {target} -Format json -output {output_file}"
        result = run_command(cmd)
        
        if result['success']:
            logger.info(f"Nikto scan completed successfully. Results saved to {output_file}")
            
            # Parse Nikto results
            try:
                with open(output_file, 'r') as f:
                    nikto_results = json.load(f)
                
                # Process Nikto vulnerabilities
                if 'vulnerabilities' in nikto_results:
                    for vuln in nikto_results['vulnerabilities']:
                        severity = 'medium'  # Default severity
                        
                        # Try to determine severity based on description
                        desc = vuln.get('description', '').lower()
                        if any(word in desc for word in ['critical', 'remote code', 'rce', 'sql injection']):
                            severity = 'critical'
                        elif any(word in desc for word in ['high', 'xss', 'csrf', 'directory traversal']):
                            severity = 'high'
                        elif any(word in desc for word in ['medium', 'information disclosure']):
                            severity = 'medium'
                        elif any(word in desc for word in ['low', 'warning']):
                            severity = 'low'
                        
                        # Add to vulnerabilities list
                        self.vulnerabilities.append({
                            'name': vuln.get('title', 'Nikto Finding'),
                            'severity': severity,
                            'description': vuln.get('description', ''),
                            'location': vuln.get('url', target),
                            'evidence': vuln.get('message', ''),
                            'type': 'nikto_finding',
                            'remediation': vuln.get('solution', 'Review and fix the identified issue')
                        })
                
                # Save raw results
                self.tool_outputs['nikto'] = nikto_results
                
            except Exception as e:
                logger.error(f"Failed to parse Nikto results: {e}")
        else:
            logger.error(f"Nikto scan failed: {result.get('error', 'Unknown error')}")
    
    def _run_zap(self, target, results_dir):
        """Run OWASP ZAP scanner."""
        logger.info(f"Running OWASP ZAP on {target}")
        
        # This is a simplified implementation
        # In a real implementation, we would need to handle ZAP API or daemon mode
        
        # Prepare output file
        output_file = os.path.join(results_dir, 'zap_results.json')
        
        # Run ZAP command (example, would need to be adjusted for actual environment)
        cmd = f"zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' -o '-config api.addrs.addr.name=.*' -o '-config api.addrs.addr.regex=true' {target} --output-format json > {output_file}"
        result = run_command(cmd)
        
        if result['success']:
            logger.info(f"ZAP scan completed successfully. Results saved to {output_file}")
            
            # Parse ZAP results
            try:
                with open(output_file, 'r') as f:
                    zap_results = json.load(f)
                
                # Process ZAP alerts
                if 'alerts' in zap_results:
                    for alert in zap_results['alerts']:
                        # Map ZAP risk levels to our severity levels
                        risk_to_severity = {
                            'High': 'high',
                            'Medium': 'medium',
                            'Low': 'low',
                            'Informational': 'info'
                        }
                        
                        severity = risk_to_severity.get(alert.get('risk', 'Medium'), 'medium')
                        
                        # Add to vulnerabilities list
                        self.vulnerabilities.append({
                            'name': alert.get('name', 'ZAP Finding'),
                            'severity': severity,
                            'description': alert.get('description', ''),
                            'location': alert.get('url', target),
                            'evidence': alert.get('evidence', ''),
                            'type': 'zap_finding',
                            'remediation': alert.get('solution', 'Review and fix the identified issue')
                        })
                
                # Save raw results
                self.tool_outputs['zap'] = zap_results
                
            except Exception as e:
                logger.error(f"Failed to parse ZAP results: {e}")
        else:
            logger.error(f"ZAP scan failed: {result.get('error', 'Unknown error')}")
    
    def _run_sqlmap(self, target, results_dir):
        """Run SQLMap for SQL injection testing."""
        logger.info(f"Running SQLMap on {target}")
        
        # Prepare output file
        output_file = os.path.join(results_dir, 'sqlmap_results.json')
        
        # Run SQLMap command
        cmd = f"sqlmap -u {target} --batch --forms --crawl=3 --level=1 --risk=1 -o --output-dir={results_dir} --dump-format=JSON"
        result = run_command(cmd)
        
        if result['success']:
            logger.info(f"SQLMap scan completed successfully. Results saved to {results_dir}")
            
            # Parse SQLMap results (simplified, would need to be adjusted for actual output format)
            try:
                # SQLMap creates multiple files, we would need to find and parse them
                # This is a simplified approach
                sqlmap_files = [f for f in os.listdir(results_dir) if f.startswith('sqlmap')]
                
                for sqlmap_file in sqlmap_files:
                    file_path = os.path.join(results_dir, sqlmap_file)
                    
                    if os.path.isfile(file_path) and file_path.endswith('.json'):
                        with open(file_path, 'r') as f:
                            sqlmap_results = json.load(f)
                        
                        # Process SQLMap findings
                        if 'data' in sqlmap_results:
                            for url, data in sqlmap_results['data'].items():
                                if 'injectable' in data and data['injectable']:
                                    # Add to vulnerabilities list
                                    self.vulnerabilities.append({
                                        'name': "SQL Injection",
                                        'severity': "high",
                                        'description': "SQLMap found a SQL Injection vulnerability.",
                                        'location': url,
                                        'evidence': f"SQLMap found injectable parameter: {data.get('parameter', '')}",
                                        'type': 'sqli',
                                        'remediation': "Use parameterized queries or prepared statements"
                                    })
                
                # Save raw results (simplified)
                self.tool_outputs['sqlmap'] = {'files': sqlmap_files}
                
            except Exception as e:
                logger.error(f"Failed to parse SQLMap results: {e}")
        else:
            logger.error(f"SQLMap scan failed: {result.get('error', 'Unknown error')}")
    
    def _consolidate_results(self):
        """Consolidate and deduplicate vulnerability findings."""
        logger.info("Consolidating vulnerability findings")
        
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