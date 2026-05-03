#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
import requests
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode
from core.base_module import VulnerabilityTestingModule
from core.utils import make_http_request, generate_random_string

class IDORScanner(VulnerabilityTestingModule):
    """Insecure Direct Object References (IDOR) vulnerability scanner module for PIN0CCHI0."""

    def __init__(self):
        super().__init__(config)
        self.name = "idor_scanner"
        self.description = "Tests for Insecure Direct Object References (IDOR) vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://portswigger.net/web-security/access-control/idor"
        ]
        self.vulnerabilities = []
        self.session = requests.Session()
        self.authenticated = False
        self.test_users = self._generate_test_users()

    def _generate_test_users(self) -> List[Dict]:
        """Generate test user credentials for IDOR testing.

        Returns:
            List of dictionaries containing test user credentials
        """
        return [
            {
                'username': 'test_user1',
                'password': 'password123',
                'id': '1001'
            },
            {
                'username': 'test_user2',
                'password': 'password123',
                'id': '1002'
            }
        ]

    def _detect_id_parameters(self, url: str, response: requests.Response) -> List[Dict]:
        """Detect parameters that might be object references.

        Args:
            url: Target URL
            response: HTTP response object

        Returns:
            List of dictionaries containing parameter information
        """
        id_params = []

        # Common ID parameter patterns
        id_patterns = [
            r'(?i)(?:^|[^a-z])(?:id|uid|user_?id|account_?id|order_?id|item_?id|file_?id|doc_?id|record_?id)(?:$|[^a-z])',
            r'\d{4,}',  # Numeric sequences that might be IDs
            r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'  # UUID pattern
        ]

        # Check URL parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        path_segments = parsed_url.path.split('/')

        # Check query parameters
        for param, values in query_params.items():
            for pattern in id_patterns:
                if re.search(pattern, param):
                    id_params.append({
                        'location': 'query',
                        'name': param,
                        'value': values[0]
                    })

        # Check path segments
        for segment in path_segments:
            for pattern in id_patterns:
                if re.search(pattern, segment):
                    id_params.append({
                        'location': 'path',
                        'name': 'path_segment',
                        'value': segment
                    })

        # Check response body for potential object references
        if 'application/json' in response.headers.get('Content-Type', '').lower():
            try:
                json_data = response.json()
                self._scan_json_for_ids(json_data, id_params)
            except:
                pass

        return id_params

    def _scan_json_for_ids(self, data: Dict, id_params: List[Dict], prefix: str = ''):
        """Recursively scan JSON data for potential object references.

        Args:
            data: JSON data to scan
            id_params: List to store found parameters
            prefix: Current key prefix for nested objects
        """
        if isinstance(data, dict):
            for key, value in data.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    self._scan_json_for_ids(value, id_params, new_prefix)
                elif isinstance(value, (str, int)) and any(key.lower().endswith('id') for key in [new_prefix]):
                    id_params.append({
                        'location': 'json',
                        'name': new_prefix,
                        'value': str(value)
                    })
        elif isinstance(data, list):
            for item in data:
                self._scan_json_for_ids(item, id_params, prefix)

    def _test_idor(self, url: str, param: Dict, original_response: requests.Response) -> Optional[Dict]:
        """Test a parameter for IDOR vulnerability.

        Args:
            url: Target URL
            param: Parameter information dictionary
            original_response: Original HTTP response

        Returns:
            Dict containing vulnerability details if found, None otherwise
        """
        try:
            original_value = param['value']
            test_values = self._generate_test_values(original_value)

            for test_value in test_values:
                test_url = self._modify_url(url, param, test_value)
                response = make_http_request(test_url, method="GET")

                if response and response.status_code == 200:
                    # Compare responses
                    if self._compare_responses(original_response, response):
                        continue

                    # Check for sensitive data patterns
                    if self._contains_sensitive_data(response.text):
                        return {
                            "type": "Insecure Direct Object Reference (IDOR)",
                            "url": url,
                            "parameter": param['name'],
                            "original_value": original_value,
                            "test_value": test_value,
                            "evidence": "Access to unauthorized resource possible",
                            "severity": "High",
                            "description": "Application allows access to resources through direct object references without proper authorization",
                            "mitigation": "Implement proper access controls and use indirect object references"
                        }

        except Exception as e:
            self.logger.error(f"Error testing IDOR: {str(e)}")

        return None

    def _generate_test_values(self, original_value: str) -> List[str]:
        """Generate test values for IDOR testing.

        Args:
            original_value: Original parameter value

        Returns:
            List of test values
        """
        test_values = []

        try:
            # If numeric, try adjacent values
            if original_value.isdigit():
                num_val = int(original_value)
                test_values.extend([str(num_val - 1), str(num_val + 1)])

            # If UUID, try other UUIDs
            uuid_pattern = r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
            if re.match(uuid_pattern, original_value):
                test_values.extend([user['id'] for user in self.test_users])

            # Try common user IDs
            test_values.extend(['1', '2', '3', 'admin', 'administrator'])

        except Exception as e:
            self.logger.error(f"Error generating test values: {str(e)}")

        return test_values

    def _modify_url(self, url: str, param: Dict, new_value: str) -> str:
        """Modify URL with new parameter value.

        Args:
            url: Original URL
            param: Parameter information dictionary
            new_value: New value to set

        Returns:
            Modified URL
        """
        parsed_url = urlparse(url)
        
        if param['location'] == 'query':
            query_params = parse_qs(parsed_url.query)
            query_params[param['name']] = [new_value]
            new_query = '&'.join(f"{k}={v[0]}" for k, v in query_params.items())
            return url.replace(parsed_url.query, new_query)

        elif param['location'] == 'path':
            path_segments = parsed_url.path.split('/')
            for i, segment in enumerate(path_segments):
                if segment == param['value']:
                    path_segments[i] = new_value
                    break
            new_path = '/'.join(path_segments)
            return url.replace(parsed_url.path, new_path)

        return url

    def _compare_responses(self, response1: requests.Response, response2: requests.Response) -> bool:
        """Compare two responses to determine if they're essentially the same.

        Args:
            response1: First HTTP response
            response2: Second HTTP response

        Returns:
            bool: True if responses are similar, False otherwise
        """
        # Compare content length
        if abs(len(response1.text) - len(response2.text)) < 10:
            return True

        # Compare response structure if JSON
        if 'application/json' in response1.headers.get('Content-Type', '').lower():
            try:
                json1 = response1.json()
                json2 = response2.json()
                return self._compare_json_structure(json1, json2)
            except:
                pass

        return False

    def _compare_json_structure(self, json1: Dict, json2: Dict) -> bool:
        """Compare structure of two JSON objects.

        Args:
            json1: First JSON object
            json2: Second JSON object

        Returns:
            bool: True if structures are similar, False otherwise
        """
        if isinstance(json1, dict) and isinstance(json2, dict):
            return set(json1.keys()) == set(json2.keys())
        elif isinstance(json1, list) and isinstance(json2, list):
            return len(json1) == len(json2)
        return False

    def _contains_sensitive_data(self, content: str) -> bool:
        """Check if response contains sensitive data patterns.

        Args:
            content: Response content to check

        Returns:
            bool: True if sensitive data found, False otherwise
        """
        sensitive_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{16}\b',  # Credit card
            r'password|secret|token|key',  # Sensitive keywords
            r'admin|root|superuser'  # Privileged user indicators
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in sensitive_patterns)

    def run(self, target: str) -> bool:
        """Run the IDOR scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting IDOR scan on {target}")

        try:
            # First, make a request to the target
            response = make_http_request(target, method="GET")
            if not response:
                self.logger.error(f"Could not connect to target {target}")
                return False

            # Detect potential object reference parameters
            id_params = self._detect_id_parameters(target, response)
            self.logger.info(f"Found {len(id_params)} potential object reference parameters")

            # Test each parameter for IDOR
            for param in id_params:
                result = self._test_idor(target, param, response)
                if result:
                    self.vulnerabilities.append(result)

            self.logger.info(f"IDOR scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
            return True

        except Exception as e:
            self.logger.error(f"Error during IDOR scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the IDOR scanner module."""
        self.logger.info("Cleaning up IDOR scanner module...")
        return True