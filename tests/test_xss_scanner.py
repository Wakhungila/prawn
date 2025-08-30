import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.vuln_testing.xss_scanner import XSSScanner

class TestXSSScanner(unittest.TestCase):
    
    def setUp(self):
        # Create a mock configuration
        self.config = {
            'output_dir': './test_results',
            'callbacks': {
                'domain': 'example.com'
            }
        }
        
        # Create the scanner with the mock configuration
        self.scanner = XSSScanner()
        self.scanner.config = self.config
        
    @patch('modules.vuln_testing.xss_scanner.make_request')
    def test_detect_reflected_xss(self, mock_make_request):
        # Setup mock response with XSS payload reflected in the response
        payload = '<script>alert("PIN0CCHI0")</script>'
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': f'<html><body>User input: {payload}</body></html>',
            'elapsed': 0.5
        }
        mock_make_request.return_value = mock_response
        
        # Test the scan_endpoint method
        url = 'http://example.com/search'
        params = {'q': 'test'}
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url, params)
        
        # Check that a vulnerability was detected
        self.assertGreater(len(self.scanner.vulnerabilities), 0)
        found = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['url'] == url and vuln['type'] == 'Reflected XSS':
                found = True
                break
        self.assertTrue(found)
    
    @patch('modules.vuln_testing.xss_scanner.make_request')
    def test_detect_dom_xss(self, mock_make_request):
        # Setup mock response with DOM XSS vulnerability
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body><script>document.write(location.hash.substring(1));</script></body></html>',
            'elapsed': 0.5
        }
        mock_make_request.return_value = mock_response
        
        # Test the scan_endpoint method
        url = 'http://example.com/page'
        params = {}
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url, params)
        
        # Check that a vulnerability was detected
        self.assertGreater(len(self.scanner.vulnerabilities), 0)
        found = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['url'] == url and vuln['type'] == 'DOM-based XSS':
                found = True
                break
        self.assertTrue(found)
    
    @patch('modules.vuln_testing.xss_scanner.make_request')
    def test_no_xss_vulnerability(self, mock_make_request):
        # Setup mock response with no XSS vulnerability
        mock_response = {
            'success': True,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'text': '<html><body>User input: &lt;script&gt;alert("PIN0CCHI0")&lt;/script&gt;</body></html>',
            'elapsed': 0.5
        }
        mock_make_request.return_value = mock_response
        
        # Test the scan_endpoint method
        url = 'http://example.com/secure'
        params = {'q': 'test'}
        
        # Mock the vulnerabilities list
        self.scanner.vulnerabilities = []
        
        # Call the method
        self.scanner.scan_endpoint(url, params)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 0)

if __name__ == '__main__':
    unittest.main()