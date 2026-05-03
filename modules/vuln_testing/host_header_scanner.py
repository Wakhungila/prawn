#!/usr/bin/env python3

from typing import Dict, List, Optional, Set
import requests
import re
from urllib.parse import urljoin, urlparse
from core.base_module import VulnTestingModule
from core.utils import make_http_request, generate_random_string

class HostHeaderScanner(VulnTestingModule):
    """Host Header Injection vulnerability scanner module for PIN0CCHI0."""

    def __init__(self):
        super().__init__(name="host_header_scanner", description="Tests for Host Header Injection vulnerabilities")
        self.description = "Tests for Host Header Injection vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://portswigger.net/web-security/host-header",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"
        ]
        self.vulnerabilities = []
        
        # Test domains for injection attempts
        self.test_domains = [
            'evil.com',
            'attacker.com',
            'malicious.net',
            'pin0cchi0.test'
        ]
        
        # Headers to test for injection
        self.test_headers = {
            'Host': '{domain}',
            'X-Forwarded-Host': '{domain}',
            'X-Host': '{domain}',
            'X-Forwarded-Server': '{domain}',
            'X-HTTP-Host-Override': '{domain}',
            'Forwarded': 'host={domain}'
        }
        
        # Patterns to detect in responses
        self.detection_patterns = {
            'absolute_links': r'https?://{domain}[^\s"\'<>]+',
            'relative_links': r'href=["\']/[^\s"\'<>]+',
            'email_domains': r'[a-zA-Z0-9._%+-]+@{domain}',
            'password_reset': r'reset[^\s]*token',
            'sensitive_paths': r'(?:admin|config|setup|install)'
        }

    def _test_host_header(self, url: str, test_domain: str) -> Optional[Dict]:
        """Test for Host header manipulation vulnerabilities.

        Args:
            url: Target URL
            test_domain: Domain to use in injection attempts

        Returns:
            Dictionary containing vulnerability details if found, None otherwise
        """
        try:
            parsed_url = urlparse(url)
            original_host = parsed_url.netloc
            
            # Test basic Host header override
            headers = {'Host': test_domain}
            response = make_http_request(url, headers=headers, allow_redirects=False)
            
            if response:
                # Check for reflected test domain
                if test_domain in response.get('text', ''):
                    return {
                        "type": "Host Header Injection",
                        "url": url,
                        "header": "Host",
                        "payload": test_domain,
                        "severity": "High",
                        "description": "Host header value is reflected in response",
                        "mitigation": "Validate and sanitize Host header values"
                    }
                
                # Check for redirect to injected domain
                location = response.get('headers', {}).get('location', '')
                if test_domain in location:
                    return {
                        "type": "Host Header Injection",
                        "url": url,
                        "header": "Host",
                        "payload": test_domain,
                        "redirect_url": location,
                        "severity": "High",
                        "description": "Host header manipulation leads to redirect",
                        "mitigation": "Implement strict Host header validation"
                    }

        except Exception as e:
            self.logger.error(f"Error testing Host header: {str(e)}")

        return None

    def _test_proxy_headers(self, url: str, test_domain: str) -> List[Dict]:
        """Test for proxy header injection vulnerabilities.

        Args:
            url: Target URL
            test_domain: Domain to use in injection attempts

        Returns:
            List of dictionaries containing vulnerability details
        """
        findings = []
        try:
            for header_name, header_template in self.test_headers.items():
                if header_name == 'Host':
                    continue  # Skip Host header as it's tested separately
                    
                header_value = header_template.format(domain=test_domain)
                headers = {header_name: header_value}
                
                # Test with and without original Host header
                for include_host in [True, False]:
                    if include_host:
                        headers['Host'] = urlparse(url).netloc
                    
                    response = make_http_request(
                        url,
                        headers=headers,
                        allow_redirects=False
                    )
                    
                    if response:
                        # Check for reflected test domain
                        if test_domain in response.text:
                            findings.append({
                                "type": "Proxy Header Injection",
                                "url": url,
                                "header": header_name,
                                "payload": header_value,
                                "severity": "High",
                                "description": f"{header_name} value is reflected in response",
                                "mitigation": "Validate and sanitize proxy header values"
                            })
                        
                        # Check for redirect to injected domain
                        location = response.headers.get('location', '')
                        if test_domain in location:
                            findings.append({
                                "type": "Proxy Header Injection",
                                "url": url,
                                "header": header_name,
                                "payload": header_value,
                                "redirect_url": location,
                                "severity": "High",
                                "description": f"{header_name} manipulation leads to redirect",
                                "mitigation": "Implement strict proxy header validation"
                            })

        except Exception as e:
            self.logger.error(f"Error testing proxy headers: {str(e)}")

        return findings

    def _test_cache_poisoning(self, url: str, test_domain: str) -> Optional[Dict]:
        """Test for web cache poisoning via Host header.

        Args:
            url: Target URL
            test_domain: Domain to use in injection attempts

        Returns:
            Dictionary containing vulnerability details if found, None otherwise
        """
        try:
            # Generate unique cache buster
            cache_buster = generate_random_string(8)
            test_url = f"{url}?cb={cache_buster}"
            
            # First request with malicious Host header
            headers = {'Host': test_domain}
            response1 = make_http_request(test_url, headers=headers)
            
            if response1:
                # Second request without malicious header
                response2 = make_http_request(test_url)
                
                if response2 and test_domain in response2.text:
                    return {
                        "type": "Web Cache Poisoning",
                        "url": test_url,
                        "header": "Host",
                        "payload": test_domain,
                        "severity": "High",
                        "description": "Host header manipulation leads to cache poisoning",
                        "mitigation": "Implement proper cache key calculation and validation"
                    }

        except Exception as e:
            self.logger.error(f"Error testing cache poisoning: {str(e)}")

        return None

    def _test_password_reset(self, url: str, test_domain: str) -> Optional[Dict]:
        """Test for password reset poisoning via Host header.

        Args:
            url: Target URL
            test_domain: Domain to use in injection attempts

        Returns:
            Dictionary containing vulnerability details if found, None otherwise
        """
        try:
            # Common password reset endpoints
            reset_paths = [
                '/reset-password',
                '/forgot-password',
                '/password/reset',
                '/account/reset',
                '/users/password'
            ]
            
            for path in reset_paths:
                reset_url = urljoin(url, path)
                headers = {'Host': test_domain}
                
                response = make_http_request(reset_url, headers=headers)
                if response and response.status_code != 404:
                    # Check for password reset functionality
                    if any(pattern in response.text.lower() for pattern in [
                        'reset', 'password', 'email', 'token'
                    ]):
                        return {
                            "type": "Password Reset Poisoning",
                            "url": reset_url,
                            "header": "Host",
                            "payload": test_domain,
                            "severity": "High",
                            "description": "Host header manipulation may affect password reset functionality",
                            "mitigation": "Validate Host header in password reset process"
                        }

        except Exception as e:
            self.logger.error(f"Error testing password reset: {str(e)}")

        return None

    def run(self, target: str) -> bool:
        """Run the Host Header Injection scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting Host Header Injection scan on {target}")

        try:
            for test_domain in self.test_domains:
                # Test basic Host header injection
                vuln = self._test_host_header(target, test_domain)
                if vuln:
                    self.vulnerabilities.append(vuln)

                # Test proxy header injection
                proxy_vulns = self._test_proxy_headers(target, test_domain)
                self.vulnerabilities.extend(proxy_vulns)

                # Test for cache poisoning
                cache_vuln = self._test_cache_poisoning(target, test_domain)
                if cache_vuln:
                    self.vulnerabilities.append(cache_vuln)

                # Test password reset functionality
                reset_vuln = self._test_password_reset(target, test_domain)
                if reset_vuln:
                    self.vulnerabilities.append(reset_vuln)

            self.logger.info(
                f"Host Header Injection scan completed. Found {len(self.vulnerabilities)} vulnerabilities."
            )
            return True

        except Exception as e:
            self.logger.error(f"Error during Host Header Injection scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the Host Header Injection scanner module."""
        self.logger.info("Cleaning up Host Header Injection scanner module...")
        return True