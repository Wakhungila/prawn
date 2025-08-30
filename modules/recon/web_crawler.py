#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Web Crawler Module

This module crawls web applications to discover endpoints, parameters, and potential vulnerabilities.
"""

import os
import re
import json
import logging
from urllib.parse import urljoin, urlparse
from datetime import datetime

from core.base_module import ReconModule
from core.utils import make_request, save_json, ensure_directory, normalize_url

logger = logging.getLogger('PIN0CCHI0.Recon.WebCrawler')

class WebCrawlerModule(ReconModule):
    """Module for web crawling."""
    
    def __init__(self):
        super().__init__(
            name="Web Crawler",
            description="Crawls web applications to discover endpoints and parameters"
        )
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.parameters = set()
        self.js_files = set()
        self.api_endpoints = set()
    
    def run(self, target=None, output_dir=None, config=None, max_depth=3, max_urls=100, **kwargs):
        """
        Run web crawling on the target.
        
        Args:
            target (str): Target URL
            output_dir (str): Directory to save results
            config (dict): Module configuration
            max_depth (int): Maximum crawl depth
            max_urls (int): Maximum URLs to crawl
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for web crawling")
            return {'success': False, 'error': 'No target specified'}
        
        # Normalize target URL
        target = normalize_url(target)
        
        logger.info(f"Starting web crawling on {target}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'web_crawl', timestamp)
        ensure_directory(output_dir)
        
        # Start crawling
        self._crawl(target, max_depth, max_urls)
        
        # Save results
        results = {
            'target': target,
            'discovered_urls': list(sorted(self.discovered_urls)),
            'forms': self.forms,
            'parameters': list(sorted(self.parameters)),
            'js_files': list(sorted(self.js_files)),
            'api_endpoints': list(sorted(self.api_endpoints))
        }
        
        results_file = os.path.join(output_dir, 'web_crawl_results.json')
        save_json(results, results_file)
        
        logger.info(f"Web crawling completed for {target}. Discovered {len(self.discovered_urls)} URLs.")
        
        # Add result
        result = {
            'title': f"Web Crawl for {target}",
            'severity': 'Info',
            'description': f"Discovered {len(self.discovered_urls)} URLs, {len(self.forms)} forms, {len(self.parameters)} parameters, {len(self.js_files)} JS files, and {len(self.api_endpoints)} API endpoints",
            'discovered_urls': list(sorted(self.discovered_urls)),
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'discovered_urls': list(sorted(self.discovered_urls)),
            'forms_count': len(self.forms),
            'parameters_count': len(self.parameters),
            'js_files_count': len(self.js_files),
            'api_endpoints_count': len(self.api_endpoints),
            'output_file': results_file
        }
    
    def _crawl(self, url, max_depth, max_urls, current_depth=0):
        """Recursively crawl the website."""
        if current_depth > max_depth or len(self.visited_urls) >= max_urls or url in self.visited_urls:
            return
        
        logger.debug(f"Crawling: {url} (depth: {current_depth})")
        
        self.visited_urls.add(url)
        self.discovered_urls.add(url)
        
        # Make request
        response = make_request(url)
        
        if not response['success']:
            logger.warning(f"Failed to fetch {url}: {response.get('error', 'Unknown error')}")
            return
        
        # Extract links
        links = self._extract_links(url, response['text'])
        
        # Extract forms
        forms = self._extract_forms(url, response['text'])
        self.forms.extend(forms)
        
        # Extract parameters
        params = self._extract_parameters(url, response['text'])
        self.parameters.update(params)
        
        # Extract JavaScript files
        js_files = self._extract_js_files(url, response['text'])
        self.js_files.update(js_files)
        
        # Extract API endpoints
        api_endpoints = self._extract_api_endpoints(url, response['text'])
        self.api_endpoints.update(api_endpoints)
        
        # Continue crawling
        for link in links:
            if link not in self.visited_urls and len(self.visited_urls) < max_urls:
                self._crawl(link, max_depth, max_urls, current_depth + 1)
    
    def _extract_links(self, base_url, html):
        """Extract links from HTML content."""
        links = set()
        base_domain = urlparse(base_url).netloc
        
        # Find href attributes
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']')
        for match in href_pattern.finditer(html):
            link = match.group(1)
            absolute_url = urljoin(base_url, link)
            
            # Only include links from the same domain
            if urlparse(absolute_url).netloc == base_domain:
                links.add(absolute_url)
        
        return links
    
    def _extract_forms(self, base_url, html):
        """Extract forms from HTML content."""
        forms = []
        
        # Find forms
        form_pattern = re.compile(r'<form[^>]*>([\s\S]*?)</form>')
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            
            # Extract form action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
            action = action_match.group(1) if action_match else ''
            absolute_action = urljoin(base_url, action) if action else base_url
            
            # Extract form method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Extract form inputs
            inputs = []
            input_pattern = re.compile(r'<input[^>]*>')
            for input_match in input_pattern.finditer(form_html):
                input_html = input_match.group(0)
                
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html)
                name = name_match.group(1) if name_match else ''
                
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html)
                input_type = type_match.group(1) if type_match else 'text'
                
                if name:
                    inputs.append({
                        'name': name,
                        'type': input_type
                    })
            
            forms.append({
                'action': absolute_action,
                'method': method,
                'inputs': inputs
            })
        
        return forms
    
    def _extract_parameters(self, base_url, html):
        """Extract URL parameters from HTML content."""
        parameters = set()
        
        # Find URL parameters in href attributes
        href_pattern = re.compile(r'href=["\']([^"\']*)\?([^"\']*)["\'\s]')
        for match in href_pattern.finditer(html):
            params_str = match.group(2)
            params = params_str.split('&')
            
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    parameters.add(param_name)
        
        # Find URL parameters in form actions
        action_pattern = re.compile(r'action=["\']([^"\']*)\?([^"\']*)["\'\s]')
        for match in action_pattern.finditer(html):
            params_str = match.group(2)
            params = params_str.split('&')
            
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    parameters.add(param_name)
        
        return parameters
    
    def _extract_js_files(self, base_url, html):
        """Extract JavaScript files from HTML content."""
        js_files = set()
        
        # Find script src attributes
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>')
        for match in script_pattern.finditer(html):
            js_file = match.group(1)
            absolute_url = urljoin(base_url, js_file)
            js_files.add(absolute_url)
        
        return js_files
    
    def _extract_api_endpoints(self, base_url, html):
        """Extract potential API endpoints from HTML and JavaScript content."""
        api_endpoints = set()
        
        # Common API endpoint patterns
        api_patterns = [
            r'["\'](/api/[^"\')]+)["\'\)]',
            r'["\'](/v\d+/[^"\')]+)["\'\)]',
            r'["\'](/rest/[^"\')]+)["\'\)]',
            r'["\'](/graphql[^"\')]*)["\']',
            r'["\'](/\w+/\w+\.json)["\']'
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, html):
                endpoint = match.group(1)
                absolute_url = urljoin(base_url, endpoint)
                api_endpoints.add(absolute_url)
        
        return api_endpoints