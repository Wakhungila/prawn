#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test cases for the IDOR Scanner module.
"""

import unittest
from unittest.mock import patch, MagicMock

from modules.vuln_testing.idor_scanner import IDORScanner


class TestIDORScanner(unittest.TestCase):
    """Test cases for the IDOR Scanner module."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = IDORScanner() # No config needed in constructor now
        self.scanner.config = {'target': 'http://example.com'} # Set config after init

    def test_initialization(self):
        """Test that the scanner initializes correctly."""
        self.assertEqual(self.scanner.name, "idor_scanner")
        self.assertEqual(self.scanner.description, "Tests for Insecure Direct Object References (IDOR) vulnerabilities")
        self.assertIsInstance(self.scanner.test_users, list)
        self.assertTrue(len(self.scanner.test_users) > 0)

    @patch('modules.vuln_testing.idor_scanner.make_http_request')
    def test_detect_idor_numeric_id(self, mock_make_request):
        """Test detection of IDOR vulnerability with numeric ID."""
        # Mock responses for different user IDs
        def side_effect(url, method="GET", **kwargs):
            response = MagicMock()
            if 'user_id=1' in url:
                response.text = '<html><body><h1>Admin User</h1><div class="user-data">admin@example.com</div></body></html>'
                response.status_code = 200
            elif 'user_id=2' in url:
                response.text = '<html><body><h1>Regular User</h1><div class="user-data">user@example.com</div></body></html>'
                response.status_code = 200
            else:
                response.text = '<html><body><h1>Access Denied</h1></body></html>'
                response.status_code = 403
            return response
        
        mock_make_request.side_effect = side_effect
        
        # Run the scan
        target_url = 'http://example.com/profile?user_id=2'
        self.scanner.run(target_url)
        
        # Check that vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 1)
        self.assertEqual(self.scanner.vulnerabilities[0]['type'], 'Insecure Direct Object Reference (IDOR)')
        self.assertEqual(self.scanner.vulnerabilities[0]['severity'], 'High')
        self.assertEqual(self.scanner.vulnerabilities[0]['parameter'], 'user_id')

    @patch('modules.vuln_testing.idor_scanner.make_http_request')
    def test_detect_idor_uuid(self, mock_make_request):
        """Test detection of IDOR vulnerability with UUID."""
        # Mock responses for different user UUIDs
        def side_effect(url, method="GET", **kwargs):
            response = MagicMock()
            if 'user=a1b2c3d4-e5f6-7890-abcd-ef1234567890' in url:
                response.text = '<html><body><h1>Admin User</h1><div class="user-data">admin@example.com</div></body></html>'
                response.status_code = 200
                response.headers = {'Content-Type': 'text/html'}
            elif 'user=11111111-2222-3333-4444-555555555555' in url:
                response.text = '<html><body><h1>Regular User</h1><div class="user-data">user@example.com</div></body></html>'
                response.status_code = 200
                response.headers = {'Content-Type': 'text/html'}
            else:
                response.text = '<html><body><h1>Access Denied</h1></body></html>'
                response.status_code = 403
                response.headers = {'Content-Type': 'text/html'}
            return response
        
        mock_make_request.side_effect = side_effect
        
        # Run the scan
        target_url = 'http://example.com/profile?user=11111111-2222-3333-4444-555555555555'
        self.scanner.run(target_url)
        
        # Check that vulnerability was detected
        self.assertTrue(len(self.scanner.vulnerabilities) > 0)
        found_uuid_vuln = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['parameter'] == 'user':
                found_uuid_vuln = True
                self.assertEqual(vuln['type'], 'Insecure Direct Object Reference (IDOR)')
                self.assertEqual(vuln['severity'], 'High')
        self.assertTrue(found_uuid_vuln)

    @patch('modules.vuln_testing.idor_scanner.make_http_request')
    def test_detect_idor_in_path(self, mock_make_request):
        """Test detection of IDOR vulnerability in URL path."""
        # Mock responses for different user IDs in path
        def side_effect(url, method="GET", **kwargs):
            response = MagicMock()
            if '/users/1/' in url:
                response.text = '<html><body><h1>Admin User</h1><div class="user-data">admin@example.com</div></body></html>'
                response.status_code = 200
                response.headers = {'Content-Type': 'text/html'}
            elif '/users/2/' in url:
                response.text = '<html><body><h1>Regular User</h1><div class="user-data">user@example.com</div></body></html>'
                response.status_code = 200
                response.headers = {'Content-Type': 'text/html'}
            else:
                response.text = '<html><body><h1>Access Denied</h1></body></html>'
                response.status_code = 403
                response.headers = {'Content-Type': 'text/html'}
            return response
        
        mock_make_request.side_effect = side_effect
        
        # Run the scan
        target_url = 'http://example.com/users/2/profile'
        self.scanner.run(target_url)
        
        # Check that vulnerability was detected
        self.assertTrue(len(self.scanner.vulnerabilities) > 0)
        found_path_vuln = False
        for vuln in self.scanner.vulnerabilities:
            if 'path_segment' in vuln['parameter']:
                found_path_vuln = True
                self.assertEqual(vuln['type'], 'Insecure Direct Object Reference (IDOR)')
                self.assertEqual(vuln['severity'], 'High')
        self.assertTrue(found_path_vuln)

    @patch('modules.vuln_testing.idor_scanner.make_http_request')
    def test_no_idor_vulnerability(self, mock_make_request):
        """Test that no vulnerability is reported when IDOR is not present."""
        # Mock responses with proper access control
        def side_effect(url, method="GET", **kwargs):
            response = MagicMock()
            if 'user_id=2' in url:
                response.text = '<html><body><h1>Regular User</h1><div class="user-data">user@example.com</div></body></html>'
                response.status_code = 200
                response.headers = {'Content-Type': 'text/html'}
            elif 'user_id=1' in url:
                response.text = '<html><body><h1>Access Denied</h1></body></html>'
                response.status_code = 403
                response.headers = {'Content-Type': 'text/html'}
            else:
                response.text = '<html><body><h1>Access Denied</h1></body></html>'
                response.status_code = 403
                response.headers = {'Content-Type': 'text/html'}
            return response
        
        mock_make_request.side_effect = side_effect
        
        # Clear previous vulnerabilities
        self.scanner.vulnerabilities = []
        
        # Run the scan
        target_url = 'http://example.com/profile?user_id=2'
        self.scanner.run(target_url)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 0)

    @patch('modules.vuln_testing.idor_scanner.make_http_request')
    def test_error_response(self, mock_make_request):
        """Test handling of error responses during scanning."""
        # Mock error response
        mock_response = MagicMock()
        mock_response.text = "<html><body>Internal Server Error</body></html>"
        mock_response.status_code = 500
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_make_request.return_value = mock_response
        
        # Clear previous vulnerabilities
        self.scanner.vulnerabilities = []
        
        # Run the scan
        target_url = 'http://example.com/profile?user_id=2'
        self.scanner.run(target_url)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 0)

    def test_detect_id_parameters(self):
        """Test detection of ID parameters in URLs."""
        # Create a mock response
        mock_response = MagicMock()
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.headers = {'Content-Type': 'text/html'}
        
        # Test URL with query parameters
        url = 'http://example.com/profile?user_id=123&action=view'
        params = self.scanner._detect_id_parameters(url, mock_response)
        
        # Check that user_id was detected as an ID parameter
        found_user_id = False
        for param in params:
            if param['name'] == 'user_id' and param['location'] == 'query':
                found_user_id = True
                self.assertEqual(param['value'], '123')
        self.assertTrue(found_user_id)

    def test_modify_url(self):
        """Test URL modification for parameter testing."""
        # Test modifying query parameter
        url = 'http://example.com/profile?user_id=123&action=view'
        param = {'location': 'query', 'name': 'user_id', 'value': '123'}
        new_url = self.scanner._modify_url(url, param, '456')
        self.assertIn('user_id=456', new_url)
        self.assertIn('action=view', new_url)
        
        # Test modifying path segment
        url = 'http://example.com/users/123/profile'
        param = {'location': 'path', 'name': 'path_segment', 'value': '123'}
        new_url = self.scanner._modify_url(url, param, '456')
        self.assertIn('/users/456/profile', new_url)

    def test_compare_responses(self):
        """Test comparison of responses to determine if they're different resources."""
        # Create two different responses
        response1 = MagicMock()
        response1.text = "<html><body><h1>User 1</h1><div>Data for user 1</div></body></html>"
        response1.headers = {'Content-Type': 'text/html'}
        
        response2 = MagicMock()
        response2.text = "<html><body><h1>User 2</h1><div>Data for user 2</div></body></html>"
        response2.headers = {'Content-Type': 'text/html'}
        
        # Test comparison
        self.assertFalse(self.scanner._compare_responses(response1, response2))
        
        # Test with similar responses
        response3 = MagicMock()
        response3.text = "<html><body><h1>User 1</h1><div>Data for user 1</div></body></html>"
        response3.headers = {'Content-Type': 'text/html'}
        
        self.assertTrue(self.scanner._compare_responses(response1, response3))

    def test_contains_sensitive_data(self):
        """Test detection of sensitive data in responses."""
        # Test with sensitive data
        content_with_email = "<html><body><div>user@example.com</div></body></html>"
        self.assertTrue(self.scanner._contains_sensitive_data(content_with_email))
        
        content_with_ssn = "<html><body><div>123-45-6789</div></body></html>"
        self.assertTrue(self.scanner._contains_sensitive_data(content_with_ssn))
        
        # Test without sensitive data
        content_without_sensitive = "<html><body><div>Regular content</div></body></html>"
        self.assertFalse(self.scanner._contains_sensitive_data(content_without_sensitive))


if __name__ == '__main__':
    unittest.main()