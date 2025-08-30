#!/usr/bin/env python3

from typing import Dict, List, Optional, Set
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, quote
from core.base_module import VulnerabilityTestingModule
from core.utils import make_http_request, generate_random_string

class OpenRedirectScanner(VulnerabilityTestingModule):
    """Open Redirect vulnerability scanner module for PIN0CCHI0."""

    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "open_redirect_scanner"
        self.description = "Tests for Open Redirect vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
            "https://cwe.mitre.org/data/definitions/601.html"
        ]
        self.vulnerabilities = []
        self.visited_urls: Set[str] = set()
        
        # Test domains for redirect attempts
        self.test_domains = [
            'evil.com',
            'attacker.com',
            'malicious.net',
            'pin0cchi0.test'
        ]
        
        # Payload patterns for different redirect implementations
        self.redirect_payloads = [
            # Basic redirects
            '{domain}',
            'https://{domain}',
            'http://{domain}',
            '//{domain}',
            
            # Encoded payloads
            '%2f%2f{domain}',
            'https%3A%2F%2F{domain}',
            
            # Double encoded payloads
            '%252f%252f{domain}',
            'https%253A%252F%252F{domain}',
            
            # Path traversal
            '/../redirect/{domain}',
            '/..%2fredirect/{domain}',
            
            # Common redirect parameter values
            'https://legitimate-site.com@{domain}',
            'https://legitimate-site.com.{domain}',
            
            # Data URL scheme
            'data:text/html,<script>window.location=\'http://{domain}\';</script>',
            
            # JavaScript protocol
            'javascript:window.location.href=\'http://{domain}\''
        ]

    def _extract_redirect_parameters(self, url: str, response: requests.Response) -> List[Dict]:
        """Extract potential redirect parameters from the response.

        Args:
            url: Target URL
            response: HTTP response object

        Returns:
            List of dictionaries containing redirect parameter information
        """
        redirect_params = []
        try:
            # Common redirect parameter names
            redirect_keywords = [
                'redirect', 'redir', 'next', 'url', 'target', 'dest', 'destination',
                'return', 'return_url', 'return_to', 'goto', 'link', 'forward',
                'forward_url', 'path', 'continue', 'window', 'to', 'out', 'view',
                'dir', 'show', 'navigation', 'open', 'domain'
            ]

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract form inputs
            for form in soup.find_all('form'):
                form_action = urljoin(url, form.get('action', ''))
                form_method = form.get('method', 'GET').upper()

                for input_field in form.find_all('input'):
                    input_name = input_field.get('name', '').lower()
                    if any(keyword in input_name for keyword in redirect_keywords):
                        redirect_params.append({
                            'type': 'form',
                            'method': form_method,
                            'action': form_action,
                            'name': input_field.get('name', ''),
                            'value': input_field.get('value', '')
                        })

            # Extract URL parameters
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for param, values in query_params.items():
                if any(keyword in param.lower() for keyword in redirect_keywords):
                    redirect_params.append({
                        'type': 'url',
                        'method': 'GET',
                        'action': url,
                        'name': param,
                        'value': values[0] if values else ''
                    })

        except Exception as e:
            self.logger.error(f"Error extracting redirect parameters: {str(e)}")

        return redirect_params

    def _test_redirect_parameter(self, param_info: Dict) -> Optional[Dict]:
        """Test a single redirect parameter for vulnerabilities.

        Args:
            param_info: Dictionary containing redirect parameter information

        Returns:
            Dictionary containing vulnerability details if found, None otherwise
        """
        try:
            for test_domain in self.test_domains:
                for payload_template in self.redirect_payloads:
                    payload = payload_template.format(domain=test_domain)

                    if param_info['type'] == 'url':
                        # Test URL parameters
                        parsed = urlparse(param_info['action'])
                        query_params = parse_qs(parsed.query)
                        query_params[param_info['name']] = [payload]
                        new_query = '&'.join(
                            f"{k}={v[0]}" for k, v in query_params.items()
                        )
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                        response = make_http_request(
                            test_url,
                            allow_redirects=False
                        )

                        if response:
                            # Check for redirect indicators
                            location = response.headers.get('location', '')
                            if response.status_code in [301, 302, 303, 307, 308]:
                                if test_domain in location.lower():
                                    return {
                                        "type": "Open Redirect",
                                        "url": test_url,
                                        "parameter": param_info['name'],
                                        "payload": payload,
                                        "redirect_url": location,
                                        "severity": "Medium",
                                        "description": "Parameter allows unvalidated redirects",
                                        "mitigation": "Implement strict URL validation and whitelist allowed domains"
                                    }

                    elif param_info['type'] == 'form':
                        # Test form inputs
                        data = {param_info['name']: payload}
                        response = make_http_request(
                            param_info['action'],
                            method=param_info['method'],
                            data=data,
                            allow_redirects=False
                        )

                        if response:
                            # Check for redirect indicators
                            location = response.headers.get('location', '')
                            if response.status_code in [301, 302, 303, 307, 308]:
                                if test_domain in location.lower():
                                    return {
                                        "type": "Open Redirect",
                                        "url": param_info['action'],
                                        "parameter": param_info['name'],
                                        "payload": payload,
                                        "redirect_url": location,
                                        "severity": "Medium",
                                        "description": "Form parameter allows unvalidated redirects",
                                        "mitigation": "Implement strict URL validation and whitelist allowed domains"
                                    }

        except Exception as e:
            self.logger.error(f"Error testing redirect parameter: {str(e)}")

        return None

    def _analyze_javascript_redirects(self, url: str, response: requests.Response) -> List[Dict]:
        """Analyze JavaScript code for potential client-side redirect vulnerabilities.

        Args:
            url: Target URL
            response: HTTP response object

        Returns:
            List of dictionaries containing vulnerability details
        """
        findings = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Common JavaScript redirect patterns
            redirect_patterns = [
                r'window\.location(?:\.href)?\s*=\s*[\'"](.*?)[\'"]',
                r'document\.location(?:\.href)?\s*=\s*[\'"](.*?)[\'"]',
                r'window\.navigate\([\'"](.*?)[\'"]\)',
                r'window\.open\([\'"](.*?)[\'"]\)',
                r'self\.location(?:\.href)?\s*=\s*[\'"](.*?)[\'"]',
                r'top\.location(?:\.href)?\s*=\s*[\'"](.*?)[\'"]'
            ]

            # Check inline scripts
            for script in soup.find_all('script'):
                script_content = script.string
                if script_content:
                    for pattern in redirect_patterns:
                        matches = re.findall(pattern, script_content)
                        for redirect_url in matches:
                            if any(param in redirect_url.lower() for param in ['location.hash', 'location.search', 'location.href']):
                                findings.append({
                                    "type": "Client-Side Open Redirect",
                                    "url": url,
                                    "code_snippet": script_content.strip(),
                                    "redirect_pattern": pattern,
                                    "severity": "Medium",
                                    "description": "Client-side JavaScript contains potentially unsafe redirect logic",
                                    "mitigation": "Implement proper URL validation before redirecting"
                                })

            # Check external JavaScript files
            for script in soup.find_all('script', src=True):
                script_url = urljoin(url, script['src'])
                if urlparse(script_url).netloc == urlparse(url).netloc:
                    script_response = make_http_request(script_url)
                    if script_response:
                        for pattern in redirect_patterns:
                            matches = re.findall(pattern, script_response.text)
                            for redirect_url in matches:
                                if any(param in redirect_url.lower() for param in ['location.hash', 'location.search', 'location.href']):
                                    findings.append({
                                        "type": "Client-Side Open Redirect",
                                        "url": script_url,
                                        "redirect_pattern": pattern,
                                        "severity": "Medium",
                                        "description": "External JavaScript contains potentially unsafe redirect logic",
                                        "mitigation": "Implement proper URL validation before redirecting"
                                    })

        except Exception as e:
            self.logger.error(f"Error analyzing JavaScript redirects: {str(e)}")

        return findings

    def run(self, target: str) -> bool:
        """Run the Open Redirect scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting Open Redirect scan on {target}")

        try:
            # Make initial request
            response = make_http_request(target)
            if not response:
                self.logger.error(f"Could not connect to target {target}")
                return False

            # Extract and test redirect parameters
            redirect_params = self._extract_redirect_parameters(target, response)
            for param in redirect_params:
                vuln = self._test_redirect_parameter(param)
                if vuln:
                    self.vulnerabilities.append(vuln)

            # Analyze JavaScript redirects
            js_vulns = self._analyze_javascript_redirects(target, response)
            self.vulnerabilities.extend(js_vulns)

            self.logger.info(
                f"Open Redirect scan completed. Found {len(self.vulnerabilities)} vulnerabilities."
            )
            return True

        except Exception as e:
            self.logger.error(f"Error during Open Redirect scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the Open Redirect scanner module."""
        self.logger.info("Cleaning up Open Redirect scanner module...")
        return True