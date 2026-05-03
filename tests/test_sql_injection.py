import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.vuln_testing.sql_injection import SQLInjectionScanner

class TestSQLInjectionScanner(unittest.TestCase):
    
    def setUp(self):
        # Create the scanner with the mock configuration
        self.scanner = SQLInjectionScanner() # Corrected class name
        self.scanner.config = {'output_dir': './test_results'} # Set config after init
        self.scanner.target = "http://example.com" # Set a default target for tests
        
    @patch('modules.vuln_testing.sql_injection.make_request')
    def test_detect_error_based_sqli(self, mock_make_request):
        # Setup mock response with SQL error
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': 'Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version',
            'elapsed': 0.5
        }
        mock_make_request.return_value = mock_response
        
        # Test the scan_endpoint method
        url = 'http://example.com/users'
        params = {'id': '1'}
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url, params)
        
        # Check that a vulnerability was detected
        self.assertGreater(len(self.scanner.vulnerabilities), 0)
        found = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['url'] == url and vuln['type'] == 'Error-based SQL Injection':
                found = True
                break
        self.assertTrue(found)
    
    @patch('modules.vuln_testing.sql_injection.make_request')
    def test_detect_time_based_sqli(self, mock_make_request):
        # Setup mock responses for time-based injection
        normal_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>Results for user 1</body></html>',
            'elapsed': 0.5
        }
        
        delayed_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>Results for user 1</body></html>',
            'elapsed': 5.5  # Significant delay indicating time-based injection
        }
        
        # Configure mock to return different responses
        mock_make_request.side_effect = [normal_response, delayed_response]
        
        # Test the scan_endpoint method
        url = 'http://example.com/users'
        params = {'id': '1'}
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url, params)
        
        # Check that a vulnerability was detected
        self.assertGreater(len(self.scanner.vulnerabilities), 0)
        found = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['url'] == url and vuln['type'] == 'Time-based SQL Injection':
                found = True
                break
        self.assertTrue(found)
    
    @patch('modules.vuln_testing.sql_injection.make_request')
    def test_detect_boolean_based_sqli(self, mock_make_request):
        # Setup mock responses for boolean-based injection
        true_condition_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>Results found</body></html>',
            'elapsed': 0.5
        }
        
        false_condition_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>No results found</body></html>',
            'elapsed': 0.5
        }
        
        # Configure mock to return different responses
        mock_make_request.side_effect = [true_condition_response, false_condition_response]
        
        # Test the scan_endpoint method
        url = 'http://example.com/users'
        params = {'id': '1'}
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url, params)
        
        # Check that a vulnerability was detected
        self.assertGreater(len(self.scanner.vulnerabilities), 0)
        found = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['url'] == url and vuln['type'] == 'Boolean-based SQL Injection':
                found = True
                break
        self.assertTrue(found)
    
    @patch('modules.vuln_testing.sql_injection.make_request')
    def test_no_sqli_vulnerability(self, mock_make_request):
        # Setup mock response with no SQL injection vulnerability
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>Results for user 1</body></html>',
            'elapsed': 0.5
        }
        mock_make_request.return_value = mock_response
        
        # Test the scan_endpoint method
        url = 'http://example.com/secure'
        params = {'id': '1'}
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url, params)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 0)

if __name__ == '__main__':
    unittest.main()