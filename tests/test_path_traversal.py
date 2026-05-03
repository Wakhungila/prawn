#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test cases for the Path Traversal Scanner module.
"""

import unittest
from unittest.mock import patch, MagicMock

from modules.vuln_testing.path_traversal import PathTraversalScanner


class TestPathTraversalScanner(unittest.TestCase):
    """Test cases for the Path Traversal Scanner module."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = PathTraversalScanner()
        self.test_config = {
            'target': 'http://example.com'
        }
        self.scanner.config = self.test_config

    def test_initialization(self):
        """Test that the scanner initializes correctly."""
        self.assertEqual(self.scanner.name, "Path Traversal Scanner")
        self.assertEqual(self.scanner.category, "vuln_testing")
        self.assertIsInstance(self.scanner.unix_payloads, list)
        self.assertIsInstance(self.scanner.windows_payloads, list)
        self.assertTrue(len(self.scanner.unix_payloads) > 0)
        self.assertTrue(len(self.scanner.windows_payloads) > 0)

    @patch('modules.vuln_testing.path_traversal.make_request')
    def test_detect_path_traversal_unix(self, mock_make_request):
        """Test detection of path traversal vulnerability on Unix-like systems."""
        # Mock response with path traversal vulnerability
        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_make_request.return_value = mock_response
        
        # Clear previous vulnerabilities
        self.scanner.vulnerabilities = []
        
        # Run the scan
        target_url = 'http://example.com/file.php?path=file'
        self.scanner._test_parameter(target_url, 'path', 'file')
        
        # Check that vulnerability was detected
        self.assertTrue(len(self.scanner.vulnerabilities) > 0)
        found_vuln = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['type'] == 'Path Traversal' and vuln['severity'] == 'High':
                found_vuln = True
                break
        self.assertTrue(found_vuln)

    @patch('modules.vuln_testing.path_traversal.make_request')
    def test_detect_path_traversal_windows(self, mock_make_request):
        """Test detection of path traversal vulnerability on Windows systems."""
        # Mock response with path traversal vulnerability
        mock_response = MagicMock()
        mock_response.text = "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS"
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_make_request.return_value = mock_response
        
        # Clear previous vulnerabilities
        self.scanner.vulnerabilities = []
        
        # Run the scan
        target_url = 'http://example.com/file.php?file=document'
        self.scanner._test_parameter(target_url, 'file', 'document')
        
        # Check that vulnerability was detected
        self.assertTrue(len(self.scanner.vulnerabilities) > 0)
        found_vuln = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['type'] == 'Path Traversal' and vuln['severity'] == 'High':
                found_vuln = True
                break
        self.assertTrue(found_vuln)

    @patch('modules.vuln_testing.path_traversal.make_request')
    def test_detect_path_traversal_encoded(self, mock_make_request):
        """Test detection of path traversal with URL encoded payloads."""
        # Mock response with path traversal vulnerability
        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" # type: ignore
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_make_request.return_value = mock_response
        
        # Clear previous vulnerabilities
        self.scanner.vulnerabilities = []
        
        # Run the scan with encoded parameter
        target_url = 'http://example.com/file.php?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        self.scanner._extract_parameters(target_url)
        
        # Check that vulnerability was detected
        self.assertTrue(len(self.scanner.vulnerabilities) > 0)
        found_vuln = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['type'] == 'Path Traversal' and vuln['severity'] == 'High':
                found_vuln = True
                break
        self.assertTrue(found_vuln)

    @patch('modules.vuln_testing.path_traversal.make_request')
    def test_no_path_traversal(self, mock_make_request):
        """Test that no vulnerability is reported when path traversal is not present."""
        # Mock response without path traversal vulnerability
        mock_response = MagicMock()
        mock_response = MagicMock() # type: ignore
        mock_response.text = "<html><body>Normal page content</body></html>"
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_make_request.return_value = mock_response
        
        # Clear previous vulnerabilities
        self.scanner.vulnerabilities = []
        
        # Run the scan
        target_url = 'http://example.com/file.php?file=document'
        self.scanner._test_parameter(target_url, 'file', 'document')
        
        # Check that no vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 0)
        
    @patch('modules.vuln_testing.path_traversal.make_request')
    def test_error_response(self, mock_make_request):
        """Test handling of error responses."""
        # Mock error response
        mock_response = MagicMock()
        mock_response = MagicMock() # type: ignore
        mock_response.status_code = 500
        mock_make_request.return_value = mock_response
        
        # Clear previous vulnerabilities
        self.scanner.vulnerabilities = []
        
        # Run the scan
        target_url = 'http://example.com/file.php?file=document'
        self.scanner._test_parameter(target_url, 'file', 'document')
        
        # Check that no vulnerability was detected
        self.assertEqual(len(self.scanner.vulnerabilities), 0)
        
    def test_extract_parameters(self):
        """Test extraction of parameters from URLs."""
        # Test URL with parameters
        url = 'http://example.com/file.php?file=document&id=123&path=images'
        params = self.scanner._extract_parameters(url)
        
        # Check that parameters were extracted correctly
        self.assertIn('file', params)
        self.assertIn('id', params)
        self.assertIn('path', params)
        self.assertEqual(params['file'], 'document')
        self.assertEqual(params['id'], '123')
        self.assertEqual(params['path'], 'images')
        
    def test_is_file_parameter(self):
        """Test detection of file-related parameters."""
        # Test file-related parameters
        self.assertTrue(self.scanner._is_file_parameter('file'))
        self.assertTrue(self.scanner._is_file_parameter('path'))
        self.assertTrue(self.scanner._is_file_parameter('document'))
        self.assertTrue(self.scanner._is_file_parameter('filename'))
        
        # Test non-file-related parameters
        self.assertFalse(self.scanner._is_file_parameter('id'))
        self.assertFalse(self.scanner._is_file_parameter('user'))
        self.assertFalse(self.scanner._is_file_parameter('page'))
        
    def test_run(self):
        """Test the main run method."""
        with patch('modules.vuln_testing.path_traversal.make_request') as mock_make_request:
            # Mock initial response
            mock_response = MagicMock()
            mock_response = MagicMock() # type: ignore
            mock_response.text = "<html><body>Test page</body></html>"
            mock_response.status_code = 200
            mock_response.headers = {'Content-Type': 'text/html'}
            mock_make_request.return_value = mock_response
            
            # Clear previous vulnerabilities
            self.scanner.vulnerabilities = []
            
            # Run the scanner
            self.scanner.run()
            
            # Verify that make_request was called at least once
            mock_make_request.assert_called()
        



    @patch('modules.vuln_testing.path_traversal.make_request')
    def test_null_byte_injection(self, mock_make_request):
        """Test detection of path traversal with null byte injection."""
        # Mock response with path traversal vulnerability
        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" # type: ignore
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_make_request.return_value = mock_response
        
        # Clear previous vulnerabilities
        self.scanner.vulnerabilities = []
        
        # Run the scan with null byte injection
        target_url = 'http://example.com/file.php?path=image.jpg%00'
        self.scanner._test_parameter(target_url, 'path', 'image.jpg%00')
        
        # Check that vulnerability was detected
        self.assertTrue(len(self.scanner.vulnerabilities) > 0)
        found_vuln = False
        for vuln in self.scanner.vulnerabilities:
            if vuln['type'] == 'Path Traversal' and vuln['severity'] == 'High':
                found_vuln = True
                break
        self.assertTrue(found_vuln)

    def test_extract_parameters(self):
        """Test extraction of parameters from URLs."""
        # Test URL with query parameters
        url = 'http://example.com/page.php?file=image.jpg&id=123&action=view'
        params = self.scanner._extract_parameters(url)
        self.assertEqual(len(params), 3)
        self.assertIn('file', params)
        self.assertIn('id', params)
        self.assertIn('action', params)
        self.assertEqual(params['file'], 'image.jpg')
        self.assertEqual(params['id'], '123')
        self.assertEqual(params['action'], 'view')
        
        # Test URL without query parameters
        url = 'http://example.com/page.php'
        params = self.scanner._extract_parameters(url)
        self.assertEqual(len(params), 0)

    def test_generate_payloads(self):
        """Test generation of path traversal payloads."""
        # Test Unix payloads
        unix_payloads = self.scanner.unix_payloads
        self.assertTrue(len(unix_payloads) > 0)
        self.assertTrue(any('../' in p for p in unix_payloads))
        self.assertTrue(any('/etc/passwd' in p for p in unix_payloads))
        
        # Test Windows payloads
        windows_payloads = self.scanner.windows_payloads
        self.assertTrue(len(windows_payloads) > 0)
        self.assertTrue(any('..\\' in p for p in windows_payloads))
        self.assertTrue(any('boot.ini' in p for p in windows_payloads))


if __name__ == '__main__':
    unittest.main()