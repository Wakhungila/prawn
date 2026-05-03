import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.vuln_testing.csrf_scanner import CSRFScanner

class TestCSRFScanner(unittest.TestCase):
    
    def setUp(self):
        # Create the scanner with the mock configuration
        self.scanner = CSRFScanner() # No config needed in constructor now
        self.scanner.config = {'output_dir': './test_results'} # Set config after init
        self.scanner.target = "http://example.com" # Set a default target for tests
        
    @patch('modules.vuln_testing.csrf_scanner.make_request')
    def test_detect_missing_csrf_token(self, mock_make_request):
        # Setup mock response with form missing CSRF token
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body><form action="/update" method="POST"><input type="text" name="username"><input type="submit"></form></body></html>',
            'elapsed': 0.5
        }
        mock_make_request.return_value = mock_response
        
        # Test the scan_endpoint method
        url = 'http://example.com/profile'
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url)
        
        # Check that a vulnerability was detected
        self.assertGreater(len(self.scanner.vulnerabilities), 0)
        found = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['url'] == url and vuln['type'] == 'Missing CSRF Token':
                found = True
                break
        self.assertTrue(found)
    
    @patch('modules.vuln_testing.csrf_scanner.make_request')
    def test_detect_csrf_token_not_validated(self, mock_make_request):
        # Setup mock responses for CSRF token validation test
        form_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body><form action="/update" method="POST"><input type="hidden" name="csrf_token" value="abc123"><input type="text" name="username"><input type="submit"></form></body></html>',
            'elapsed': 0.5
        }
        
        # Response when submitting with invalid token (should reject but doesn't)
        submit_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>Profile updated successfully</body></html>',
            'elapsed': 0.5
        }
        
        # Configure mock to return different responses
        mock_make_request.side_effect = [form_response, submit_response]
        
        # Test the scan_endpoint method
        url = 'http://example.com/profile'
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url)
        
        # Check that a vulnerability was detected
        self.assertGreater(len(self.scanner.vulnerabilities), 0)
        found = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['url'] == url and vuln['type'] == 'CSRF Token Not Validated':
                found = True
                break
        self.assertTrue(found)
    
    @patch('modules.vuln_testing.csrf_scanner.make_request')
    def test_no_csrf_vulnerability_with_token(self, mock_make_request):
        # Setup mock response with form that has CSRF token
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body><form action="/update" method="POST"><input type="hidden" name="csrf_token" value="abc123"><input type="text" name="username"><input type="submit"></form></body></html>',
            'elapsed': 0.5
        }
        
        # Response when submitting with invalid token (correctly rejects)
        submit_response = {
            'success': True,
            'status_code': 403,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>Invalid CSRF token</body></html>',
            'elapsed': 0.5
        }
        
        # Configure mock to return different responses
        mock_make_request.side_effect = [mock_response, submit_response]
        
        # Test the scan_endpoint method
        url = 'http://example.com/secure-profile'
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 0)

if __name__ == '__main__':
    unittest.main()