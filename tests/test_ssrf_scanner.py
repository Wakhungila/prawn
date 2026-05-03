import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.vuln_testing.ssrf_scanner import SSRFScanner

class TestSSRFScanner(unittest.TestCase):
    
    def setUp(self):
        # Create the scanner with the mock configuration
        self.scanner = SSRFScanner() # No config needed in constructor now
        self.scanner.config = {'output_dir': './test_results'} # Set config after init
        self.scanner.target = "http://example.com" # Set a default target for tests
        
    @patch('modules.vuln_testing.ssrf_scanner.make_request')
    def test_check_ssrf_indicators(self, mock_make_request):
        # Setup mock response
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'text': '{"instance-id":"i-12345", "hostname":"test"}',
            'elapsed': 0.5
        }
        
        # Test the _check_ssrf_indicators method
        url = 'http://example.com/test'
        param = 'url'
        payload = 'http://169.254.169.254/latest/meta-data/'
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner._check_ssrf_indicators(mock_response, url, param, payload)
        
        # Check that a vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 1)
        self.assertEqual(self.scanner.vulnerabilities[0]['url'], url)
        self.assertEqual(self.scanner.vulnerabilities[0]['parameter'], param)
        self.assertEqual(self.scanner.vulnerabilities[0]['payload'], payload)
    
    @patch('modules.vuln_testing.ssrf_scanner.make_request')
    def test_test_url_parameters(self, mock_make_request):
        # Setup mock response
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>Test</body></html>',
            'elapsed': 0.1
        }
        
        # Configure the mock to return our response
        mock_make_request.return_value = mock_response
        
        # Test URL with parameters
        url = 'http://example.com/test?url=http://example.org'
        
        # Mock the check_ssrf_indicators method
        self.scanner._check_ssrf_indicators = MagicMock()
        
        # Call the method
        self.scanner._test_url_parameters(url, ['http://127.0.0.1'])
        
        # Check that make_request was called
        mock_make_request.assert_called()
        
        # Check that _check_ssrf_indicators was called
        self.scanner._check_ssrf_indicators.assert_called()
    
    @patch('modules.vuln_testing.ssrf_scanner.make_request')
    def test_test_form(self, mock_make_request):
        # Setup mock response
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>Test</body></html>',
            'elapsed': 0.1
        }
        
        # Configure the mock to return our response
        mock_make_request.return_value = mock_response
        
        # Test form endpoint
        endpoint = {
            'url': 'http://example.com/test',
            'method': 'POST',
            'inputs': ['url', 'submit']
        }
        
        # Mock the check_ssrf_indicators method
        self.scanner._check_ssrf_indicators = MagicMock()
        
        # Call the method
        self.scanner._test_form(endpoint, ['http://127.0.0.1'])
        
        # Check that make_request was called
        mock_make_request.assert_called()
        
        # Check that _check_ssrf_indicators was called
        self.scanner._check_ssrf_indicators.assert_called()
    
    def test_determine_severity(self):
        # Test high severity
        indicators = ['Pattern match: root:x:0:0:root:/root:/bin/bash']
        payload = 'http://example.com'
        severity = self.scanner._determine_severity(indicators, payload)
        self.assertEqual(severity, 'High')
        
        # Test medium severity
        indicators = ['Pattern match: HTTP/1.1 200 OK']
        payload = 'http://127.0.0.1'
        severity = self.scanner._determine_severity(indicators, payload)
        self.assertEqual(severity, 'Medium')
        
        # Test low severity
        indicators = ['Long response time (3s) with cloud metadata payload']
        payload = 'http://example.com'
        severity = self.scanner._determine_severity(indicators, payload)
        self.assertEqual(severity, 'Low')

if __name__ == '__main__':
    unittest.main()