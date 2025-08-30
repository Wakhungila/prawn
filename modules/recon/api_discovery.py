#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 API Discovery Module

This module discovers API endpoints, documentation, and specifications
using various techniques including crawling, fuzzing, and analyzing JavaScript files.
"""

import os
import json
import logging
from datetime import datetime
import re
from urllib.parse import urljoin, urlparse

from core.base_module import ReconModule
from core.utils import run_command, make_request, save_json, ensure_directory, normalize_url

logger = logging.getLogger('PIN0CCHI0.Recon.APIDiscovery')

class APIDiscoveryModule(ReconModule):
    """Module for discovering API endpoints and documentation."""
    
    def __init__(self):
        super().__init__(
            name="API Discovery",
            description="Discovers API endpoints, documentation, and specifications"
        )
        self.api_endpoints = []
        self.api_docs = []
        self.swagger_specs = []
        self.graphql_endpoints = []
    
    def run(self, target=None, output_dir=None, config=None, **kwargs):
        """
        Run API discovery on the target.
        
        Args:
            target (str): Target URL
            output_dir (str): Directory to save results
            config (dict): Module configuration
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for API discovery")
            return {'success': False, 'error': 'No target specified'}
        
        # Normalize target URL
        target = normalize_url(target)
        
        logger.info(f"Starting API discovery on {target}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'api_discovery', timestamp)
        ensure_directory(output_dir)
        
        # Run API discovery methods
        self._discover_common_api_paths(target)
        self._discover_swagger_docs(target)
        self._discover_graphql_endpoints(target)
        self._analyze_javascript_files(target)
        self._fuzz_api_endpoints(target, config or {})
        
        # Save results
        results = {
            'target': target,
            'api_endpoints': self.api_endpoints,
            'api_docs': self.api_docs,
            'swagger_specs': self.swagger_specs,
            'graphql_endpoints': self.graphql_endpoints
        }
        
        results_file = os.path.join(output_dir, 'api_discovery_results.json')
        save_json(results, results_file)
        
        logger.info(f"API discovery completed for {target}")
        
        # Add result
        result = {
            'title': f"API Discovery for {target}",
            'severity': 'Info',
            'description': f"Discovered {len(self.api_endpoints)} API endpoints, {len(self.api_docs)} API documentation resources, {len(self.swagger_specs)} Swagger/OpenAPI specifications, and {len(self.graphql_endpoints)} GraphQL endpoints",
            'api_endpoints': self.api_endpoints,
            'api_docs': self.api_docs,
            'swagger_specs': self.swagger_specs,
            'graphql_endpoints': self.graphql_endpoints,
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'api_endpoints_count': len(self.api_endpoints),
            'api_docs_count': len(self.api_docs),
            'swagger_specs_count': len(self.swagger_specs),
            'graphql_endpoints_count': len(self.graphql_endpoints),
            'output_file': results_file
        }
    
    def _discover_common_api_paths(self, target):
        """Discover common API paths."""
        logger.info(f"Checking common API paths for {target}")
        
        common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2', '/json',
            '/api/rest', '/api/json', '/v1', '/v2', '/v3',
            '/service', '/services', '/api-docs', '/api/docs',
            '/api/swagger', '/api/openapi', '/api/spec', '/api/specification',
            '/api/schema', '/api/endpoint', '/api/endpoints', '/api/methods',
            '/api/resources', '/api/info', '/api/status', '/api/health',
            '/api/ping', '/api/test', '/api/version', '/api/config',
            '/api/settings', '/api/public', '/api/private', '/api/internal',
            '/api/external', '/api/open', '/api/closed', '/api/auth',
            '/api/login', '/api/logout', '/api/register', '/api/user', '/api/users',
            '/api/admin', '/api/data', '/api/search', '/api/query', '/api/upload',
            '/api/download', '/api/file', '/api/files', '/api/image', '/api/images',
            '/api/media', '/api/video', '/api/videos', '/api/audio', '/api/audios',
            '/api/document', '/api/documents', '/api/product', '/api/products',
            '/api/category', '/api/categories', '/api/tag', '/api/tags',
            '/api/comment', '/api/comments', '/api/post', '/api/posts',
            '/api/article', '/api/articles', '/api/news', '/api/event', '/api/events',
            '/api/notification', '/api/notifications', '/api/message', '/api/messages',
            '/api/chat', '/api/email', '/api/emails', '/api/sms', '/api/push',
            '/api/subscription', '/api/subscriptions', '/api/payment', '/api/payments',
            '/api/order', '/api/orders', '/api/cart', '/api/checkout', '/api/shipping',
            '/api/billing', '/api/invoice', '/api/invoices', '/api/transaction', '/api/transactions',
            '/api/report', '/api/reports', '/api/stats', '/api/statistics', '/api/analytics',
            '/api/log', '/api/logs', '/api/error', '/api/errors', '/api/debug', '/api/cache',
            '/api/session', '/api/sessions', '/api/cookie', '/api/cookies', '/api/token', '/api/tokens',
            '/api/key', '/api/keys', '/api/secret', '/api/secrets', '/api/configs', '/api/setting', '/api/settings',
            '/api/preference', '/api/preferences', '/api/profile', '/api/profiles', '/api/account', '/api/accounts',
            '/api/group', '/api/groups', '/api/role', '/api/roles', '/api/permission', '/api/permissions',
            '/api/privilege', '/api/privileges', '/api/access', '/api/webhook', '/api/webhooks', '/api/callback', '/api/callbacks',
            '/api/job', '/api/jobs', '/api/task', '/api/tasks', '/api/queue', '/api/queues', '/api/worker', '/api/workers',
            '/api/process', '/api/processes', '/api/thread', '/api/threads', '/api/schedule', '/api/schedules', '/api/cron',
            '/api/backup', '/api/backups', '/api/restore', '/api/import', '/api/export', '/api/sync', '/api/synchronize'
        ]
        
        for path in common_api_paths:
            url = urljoin(target, path)
            response = make_request(url)
            
            if response['success'] and response['status_code'] < 400:
                logger.info(f"Found API path: {url} (Status: {response['status_code']})")
                
                # Add to API endpoints
                endpoint_info = {
                    'url': url,
                    'method': 'GET',
                    'status_code': response['status_code'],
                    'content_type': response['headers'].get('Content-Type', ''),
                    'response_size': len(response['text']) if 'text' in response else 0,
                    'discovery_method': 'Common Path Check'
                }
                
                self.api_endpoints.append(endpoint_info)
        
        logger.info(f"Checked {len(common_api_paths)} common API paths, found {len(self.api_endpoints)} endpoints")
    
    def _discover_swagger_docs(self, target):
        """Discover Swagger/OpenAPI documentation."""
        logger.info(f"Looking for Swagger/OpenAPI documentation for {target}")
        
        swagger_paths = [
            '/swagger/v1/swagger.json', '/swagger/v2/swagger.json', '/swagger/swagger.json',
            '/api/swagger.json', '/api-docs/swagger.json', '/api/v1/swagger.json', '/api/v2/swagger.json', '/api/v3/swagger.json',
            '/api/swagger/swagger.json', '/api/swagger/index.html', '/swagger-ui.html', '/swagger/index.html', '/swagger-ui/index.html',
            '/swagger', '/swagger-ui', '/api-docs', '/api/docs', '/docs/api', '/api/swagger-ui.html', '/api/api-docs', '/api/swagger-ui',
            '/api/documentation', '/api/spec', '/api/specs', '/api/schema', '/api/schemas', '/openapi.json', '/openapi.yaml',
            '/v1/openapi.json', '/v2/openapi.json', '/v3/openapi.json', '/api/openapi.json', '/api/v1/openapi.json', '/api/v2/openapi.json', '/api/v3/openapi.json',
            '/api/openapi.yaml', '/api/v1/openapi.yaml', '/api/v2/openapi.yaml', '/api/v3/openapi.yaml', '/docs', '/documentation', '/redoc', '/redoc.html', '/api/redoc', '/api/redoc.html'
        ]
        
        for path in swagger_paths:
            url = urljoin(target, path)
            response = make_request(url)
            
            if response['success'] and response['status_code'] < 400:
                logger.info(f"Found API documentation: {url} (Status: {response['status_code']})")
                
                # Check if it's a Swagger/OpenAPI specification
                is_swagger = False
                content_type = response['headers'].get('Content-Type', '')
                
                if 'application/json' in content_type:
                    try:
                        data = json.loads(response['text'])
                        
                        # Check for OpenAPI/Swagger indicators
                        if 'swagger' in data or 'openapi' in data:
                            is_swagger = True
                            
                            # Extract API endpoints from Swagger spec
                            if 'paths' in data:
                                for path, methods in data['paths'].items():
                                    for method, details in methods.items():
                                        if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                                            full_path = urljoin(target, path)
                                            
                                            endpoint_info = {
                                                'url': full_path,
                                                'method': method.upper(),
                                                'description': details.get('summary', details.get('description', '')),
                                                'parameters': details.get('parameters', []),
                                                'responses': details.get('responses', {}),
                                                'discovery_method': 'Swagger Specification'
                                            }
                                            
                                            self.api_endpoints.append(endpoint_info)
                            
                            # Add to Swagger specs
                            spec_info = {
                                'url': url,
                                'version': data.get('swagger', data.get('openapi', '')),
                                'title': data.get('info', {}).get('title', ''),
                                'description': data.get('info', {}).get('description', ''),
                                'endpoints_count': len(data.get('paths', {}))
                            }
                            
                            self.swagger_specs.append(spec_info)
                    except Exception as e:
                        logger.debug(f"Failed to parse JSON from {url}: {e}")
                
                # Add to API docs
                doc_info = {
                    'url': url,
                    'title': 'API Documentation',
                    'type': 'Swagger/OpenAPI' if is_swagger else 'Unknown',
                    'content_type': content_type
                }
                
                self.api_docs.append(doc_info)
        
        logger.info(f"Checked {len(swagger_paths)} documentation paths, found {len(self.api_docs)} API docs and {len(self.swagger_specs)} Swagger/OpenAPI specifications")
    
    def _discover_graphql_endpoints(self, target):
        """Discover GraphQL endpoints."""
        logger.info(f"Looking for GraphQL endpoints for {target}")
        
        graphql_paths = [
            '/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql', '/v3/graphql',
            '/api/v1/graphql', '/api/v2/graphql', '/api/v3/graphql', '/query', '/api/query',
            '/graphiql', '/api/graphiql', '/explorer', '/api/explorer', '/playground', '/api/playground', '/gql', '/api/gql'
        ]
        
        for path in graphql_paths:
            url = urljoin(target, path)
            
            # Try GET request first
            response = make_request(url)
            
            if response['success'] and response['status_code'] < 400:
                logger.info(f"Found potential GraphQL endpoint (GET): {url} (Status: {response['status_code']})")
                
                # Add to GraphQL endpoints
                endpoint_info = {
                    'url': url,
                    'method': 'GET',
                    'status_code': response['status_code'],
                    'content_type': response['headers'].get('Content-Type', ''),
                    'discovery_method': 'Common Path Check'
                }
                
                self.graphql_endpoints.append(endpoint_info)
            
            # Try POST request with introspection query
            introspection_query = {
                'query': '''
                query {
                    __schema {
                        queryType { name }
                        types { name kind }
                    }
                }
                '''
            }
            
            post_headers = {'Content-Type': 'application/json'}
            post_response = make_request(url, method='POST', headers=post_headers, data=json.dumps(introspection_query))
            
            if post_response['success'] and post_response['status_code'] < 400:
                try:
                    data = json.loads(post_response['text'])
                    
                    # Check if it's a valid GraphQL response
                    if 'data' in data and '__schema' in data['data']:
                        logger.info(f"Confirmed GraphQL endpoint (POST): {url} (Status: {post_response['status_code']})")
                        
                        # Add to GraphQL endpoints if not already added
                        endpoint_info = {
                            'url': url,
                            'method': 'POST',
                            'status_code': post_response['status_code'],
                            'content_type': post_response['headers'].get('Content-Type', ''),
                            'schema_info': data['data']['__schema'],
                            'discovery_method': 'Introspection Query'
                        }
                        
                        # Check if this URL is already in the list
                        if not any(e['url'] == url and e['method'] == 'POST' for e in self.graphql_endpoints):
                            self.graphql_endpoints.append(endpoint_info)
                except Exception as e:
                    logger.debug(f"Failed to parse JSON from {url}: {e}")
        
        logger.info(f"Checked {len(graphql_paths)} GraphQL paths, found {len(self.graphql_endpoints)} GraphQL endpoints")
    
    def _analyze_javascript_files(self, target):
        """Analyze JavaScript files for API endpoints."""
        logger.info(f"Analyzing JavaScript files for API endpoints for {target}")
        
        # First, get the main page
        response = make_request(target)
        
        if not response['success']:
            logger.warning(f"Failed to retrieve main page for {target}: {response.get('error', 'Unknown error')}")
            return
        
        html = response['text']
        
        # Extract JavaScript file URLs
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*></script>')
        js_urls = []
        
        for match in script_pattern.finditer(html):
            js_url = match.group(1)
            
            # Handle relative URLs
            if not js_url.startswith(('http://', 'https://', '//')): 
                js_url = urljoin(target, js_url)
            elif js_url.startswith('//'):
                js_url = 'https:' + js_url if target.startswith('https') else 'http:' + js_url
            
            js_urls.append(js_url)
        
        logger.info(f"Found {len(js_urls)} JavaScript files to analyze")
        
        # Patterns to look for in JavaScript files
        api_patterns = [
            # Fetch API
            r"fetch\(['\"]((?:/|https?://)[^'\"]+)['\"](\)|,)",
            # Axios
            r"axios\.(?:get|post|put|delete|patch)\(['\"]((?:/|https?://)[^'\"]+)['\"](\)|,)",
            # jQuery AJAX
            r"\$\.(?:ajax|get|post)\(\{\s*url:\s*['\"]((?:/|https?://)[^'\"]+)['\"](\)|,)",
            # XMLHttpRequest
            r"open\(['\"](GET|POST|PUT|DELETE|PATCH)['\"](\s*,\s*)['\"]((?:/|https?://)[^'\"]+)['\"](\)|,)",
            # API endpoints
            r"['\"](/api/[^'\"]+)['\"](\)|,|\s|\})",
            r"['\"](https?://[^'\"]+/api/[^'\"]+)['\"](\)|,|\s|\})",
            # GraphQL
            r"['\"](/graphql[^'\"]*)['\"](\)|,|\s|\})",
            r"['\"](https?://[^'\"]+/graphql[^'\"]*)['\"](\)|,|\s|\})",
            # Common API patterns
            r"['\"](/v\d+/[^'\"]+)['\"](\)|,|\s|\})",
            r"['\"](https?://[^'\"]+/v\d+/[^'\"]+)['\"](\)|,|\s|\})"
        ]
        
        # Analyze each JavaScript file
        for js_url in js_urls:
            js_response = make_request(js_url)
            
            if not js_response['success']:
                logger.debug(f"Failed to retrieve JavaScript file {js_url}: {js_response.get('error', 'Unknown error')}")
                continue
            
            js_content = js_response['text']
            
            # Look for API endpoints
            for pattern in api_patterns:
                for match in re.finditer(pattern, js_content):
                    # Extract the URL
                    endpoint = None
                    
                    if 'open' in pattern:
                        # Handle XMLHttpRequest pattern
                        endpoint = match.group(3)
                    else:
                        # Handle other patterns
                        endpoint = match.group(1)
                    
                    if endpoint:
                        # Handle relative URLs
                        if not endpoint.startswith(('http://', 'https://', '//')): 
                            full_endpoint = urljoin(target, endpoint)
                        elif endpoint.startswith('//'):
                            full_endpoint = 'https:' + endpoint if target.startswith('https') else 'http:' + endpoint
                        else:
                            full_endpoint = endpoint
                        
                        # Determine method
                        method = 'GET'  # Default
                        if 'post' in pattern.lower():
                            method = 'POST'
                        elif 'put' in pattern.lower():
                            method = 'PUT'
                        elif 'delete' in pattern.lower():
                            method = 'DELETE'
                        elif 'patch' in pattern.lower():
                            method = 'PATCH'
                        elif 'open' in pattern.lower():
                            method = match.group(1)
                        
                        # Add to API endpoints if not already added
                        endpoint_info = {
                            'url': full_endpoint,
                            'method': method,
                            'source_file': js_url,
                            'discovery_method': 'JavaScript Analysis'
                        }
                        
                        # Check if this URL is already in the list
                        if not any(e['url'] == full_endpoint and e['method'] == method for e in self.api_endpoints):
                            logger.info(f"Found API endpoint in JavaScript: {method} {full_endpoint}")
                            self.api_endpoints.append(endpoint_info)
                            
                            # Check if it's a GraphQL endpoint
                            if 'graphql' in full_endpoint.lower():
                                if not any(e['url'] == full_endpoint for e in self.graphql_endpoints):
                                    graphql_info = {
                                        'url': full_endpoint,
                                        'method': method,
                                        'source_file': js_url,
                                        'discovery_method': 'JavaScript Analysis'
                                    }
                                    self.graphql_endpoints.append(graphql_info)
        
        logger.info(f"JavaScript analysis found {len(self.api_endpoints)} API endpoints")
    
    def _fuzz_api_endpoints(self, target, config):
        """Fuzz API endpoints using common patterns."""
        logger.info(f"Fuzzing API endpoints for {target}")
        
        # Get configuration
        fuzz_config = config.get('api_discovery', {}).get('fuzzing', {})
        fuzz_enabled = fuzz_config.get('enabled', False)
        
        if not fuzz_enabled:
            logger.info("API endpoint fuzzing is disabled in configuration")
            return
        
        # Get discovered API endpoints as base paths
        base_paths = set()
        
        for endpoint in self.api_endpoints:
            url = endpoint['url']
            parsed = urlparse(url)
            path = parsed.path
            
            # Extract base path (e.g., /api/v1)
            path_parts = path.split('/')
            if len(path_parts) >= 3:
                base_path = '/'.join(path_parts[:3])
                base_paths.add(base_path)
        
        # Add default base paths if none discovered
        if not base_paths:
            base_paths = {'/api', '/api/v1', '/api/v2', '/v1', '/v2'}
        
        logger.info(f"Using {len(base_paths)} base paths for API fuzzing")
        
        # Common API endpoint patterns to fuzz (representative subset)
        endpoint_patterns = [
            '/users', '/user/{id}', '/auth/login', '/auth/logout', '/auth/register', '/auth/token', '/auth/refresh',
            '/products', '/product/{id}', '/orders', '/order/{id}', '/items', '/item/{id}', '/search', '/status', '/health',
            '/version', '/config', '/settings', '/profile', '/me', '/admin', '/docs', '/schema', '/swagger', '/openapi',
            '/metrics', '/stats', '/logs', '/events', '/notifications', '/messages', '/files', '/upload', '/download',
            '/export', '/import', '/backup', '/restore', '/sync', '/webhooks', '/callback', '/categories', '/tags',
            '/comments', '/reviews', '/ratings', '/favorites', '/cart', '/checkout', '/payment', '/invoice', '/subscription',
            '/plan', '/pricing', '/discount', '/coupon', '/promotion', '/shipping', '/tracking', '/locations', '/addresses',
            '/contacts', '/support', '/feedback', '/report', '/analytics', '/dashboard', '/account', '/preferences',
            '/permissions', '/roles', '/groups', '/teams', '/organizations', '/projects', '/tasks', '/issues', '/tickets',
            '/devices', '/sensors', '/data', '/stream', '/feed', '/activity', '/history', '/audit', '/monitor', '/alert',
            '/notification', '/email', '/sms', '/push', '/media', '/images', '/videos', '/audio', '/documents'
        ]
        
        # HTTP methods to try
        http_methods = ['GET', 'POST', 'PUT', 'DELETE']
        
        # Fuzz each base path with each endpoint pattern
        for base_path in base_paths:
            for endpoint in endpoint_patterns:
                full_path = base_path + endpoint
                url = urljoin(target, full_path)
                
                # Replace {id} with a test value
                if '{id}' in url:
                    url = url.replace('{id}', '1')
                
                # Try each HTTP method
                for method in http_methods:
                    if method == 'GET':
                        response = make_request(url, method=method)
                    else:
                        # For non-GET methods, send a simple JSON payload
                        payload = {'test': 'data'}
                        headers = {'Content-Type': 'application/json'}
                        response = make_request(url, method=method, headers=headers, data=json.dumps(payload))
                    
                    if response['success'] and response['status_code'] < 400:
                        logger.info(f"Found API endpoint through fuzzing: {method} {url} (Status: {response['status_code']})")
                        
                        # Add to API endpoints
                        endpoint_info = {
                            'url': url,
                            'method': method,
                            'status_code': response['status_code'],
                            'content_type': response['headers'].get('Content-Type', ''),
                            'response_size': len(response['text']) if 'text' in response else 0,
                            'discovery_method': 'Fuzzing'
                        }
                        
                        self.api_endpoints.append(endpoint_info)
        
        logger.info(f"API fuzzing completed, found {len(self.api_endpoints)} total API endpoints")
