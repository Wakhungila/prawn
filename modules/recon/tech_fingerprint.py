#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Technology Fingerprinting Module

This module identifies technologies, frameworks, and software used by web applications
using tools like Wappalyzer, Whatweb, and custom fingerprinting techniques.
"""

import os
import json
import logging
from datetime import datetime
import re

from core.base_module import ReconModule
from core.utils import run_command, make_request, save_json, ensure_directory, normalize_url

logger = logging.getLogger('PIN0CCHI0.Recon.TechFingerprint')

class TechFingerprintModule(ReconModule):
    """Module for technology fingerprinting."""
    
    def __init__(self):
        super().__init__(
            name="Technology Fingerprinting",
            description="Identifies technologies, frameworks, and software used by web applications"
        )
        self.technologies = {}
        self.server_info = {}
        self.cms_info = {}
        self.javascript_libraries = []
        self.headers = {}
    
    def run(self, target=None, output_dir=None, config=None, **kwargs):
        """
        Run technology fingerprinting on the target.
        
        Args:
            target (str): Target URL
            output_dir (str): Directory to save results
            config (dict): Module configuration
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for technology fingerprinting")
            return {'success': False, 'error': 'No target specified'}
        
        # Normalize target URL
        target = normalize_url(target)
        
        logger.info(f"Starting technology fingerprinting on {target}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'tech_fingerprint', timestamp)
        ensure_directory(output_dir)
        
        # Run fingerprinting tools
        self._run_whatweb(target, output_dir)
        self._run_wappalyzer(target, output_dir)
        self._analyze_headers(target)
        self._detect_javascript_libraries(target)
        self._detect_cms(target)
        
        # Save results
        results = {
            'target': target,
            'technologies': self.technologies,
            'server_info': self.server_info,
            'cms_info': self.cms_info,
            'javascript_libraries': self.javascript_libraries,
            'headers': self.headers
        }
        
        results_file = os.path.join(output_dir, 'tech_fingerprint_results.json')
        save_json(results, results_file)
        
        logger.info(f"Technology fingerprinting completed for {target}")
        
        # Add result
        result = {
            'title': f"Technology Fingerprint for {target}",
            'severity': 'Info',
            'description': f"Identified {len(self.technologies)} technologies, {len(self.javascript_libraries)} JavaScript libraries, and server information",
            'technologies': self.technologies,
            'server_info': self.server_info,
            'cms_info': self.cms_info,
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'technologies_count': len(self.technologies),
            'javascript_libraries_count': len(self.javascript_libraries),
            'cms_detected': bool(self.cms_info),
            'output_file': results_file
        }
    
    def _run_whatweb(self, target, output_dir):
        """Run WhatWeb tool."""
        logger.info(f"Running WhatWeb on {target}")
        
        whatweb_output = os.path.join(output_dir, 'whatweb_output.json')
        
        cmd = f"whatweb --log-json={whatweb_output} -a 3 {target}"
        result = run_command(cmd)
        
        if result['success'] and os.path.exists(whatweb_output):
            try:
                with open(whatweb_output, 'r') as f:
                    data = json.load(f)
                
                for entry in data:
                    plugins = entry.get('plugins', {})
                    
                    # Extract server information
                    if 'HTTPServer' in plugins:
                        server = plugins['HTTPServer'].get('string', [])
                        if server:
                            self.server_info['server'] = server[0] if isinstance(server, list) else server
                    
                    # Extract technologies
                    for plugin_name, plugin_data in plugins.items():
                        if plugin_name not in ['HTTPServer', 'Title', 'IP', 'Country', 'Email', 'HTML']:
                            version = None
                            if 'version' in plugin_data:
                                version = plugin_data['version'][0] if isinstance(plugin_data['version'], list) else plugin_data['version']
                            
                            self.technologies[plugin_name] = {
                                'name': plugin_name,
                                'version': version,
                                'confidence': 'High',
                                'source': 'WhatWeb'
                            }
                
                logger.info(f"WhatWeb identified {len(self.technologies)} technologies")
            except Exception as e:
                logger.error(f"Failed to parse WhatWeb output: {e}")
        else:
            logger.warning(f"WhatWeb failed or produced no output: {result.get('error', 'Unknown error')}")
    
    def _run_wappalyzer(self, target, output_dir):
        """Run Wappalyzer CLI tool."""
        logger.info(f"Running Wappalyzer on {target}")
        
        wappalyzer_output = os.path.join(output_dir, 'wappalyzer_output.json')
        
        cmd = f"wappalyzer {target} -o {wappalyzer_output}"
        result = run_command(cmd)
        
        if result['success'] and os.path.exists(wappalyzer_output):
            try:
                with open(wappalyzer_output, 'r') as f:
                    data = json.load(f)
                
                technologies = data.get('technologies', [])
                
                for tech in technologies:
                    name = tech.get('name')
                    if name:
                        self.technologies[name] = {
                            'name': name,
                            'version': tech.get('version'),
                            'confidence': tech.get('confidence', 'Medium'),
                            'categories': [cat.get('name') for cat in tech.get('categories', [])],
                            'source': 'Wappalyzer'
                        }
                
                logger.info(f"Wappalyzer identified {len(technologies)} technologies")
            except Exception as e:
                logger.error(f"Failed to parse Wappalyzer output: {e}")
        else:
            logger.warning(f"Wappalyzer failed or produced no output: {result.get('error', 'Unknown error')}")
            
            # Fallback to custom fingerprinting if Wappalyzer fails
            self._custom_fingerprinting(target)
    
    def _analyze_headers(self, target):
        """Analyze HTTP headers for technology information."""
        logger.info(f"Analyzing HTTP headers for {target}")
        
        response = make_request(target, method='HEAD')
        
        if response['success']:
            headers = response['headers']
            self.headers = headers
            
            # Extract server information
            if 'Server' in headers and not self.server_info.get('server'):
                self.server_info['server'] = headers['Server']
            
            # Extract X-Powered-By information
            if 'X-Powered-By' in headers:
                self.server_info['powered_by'] = headers['X-Powered-By']
                
                # Add as technology
                tech_name = headers['X-Powered-By'].split('/')[0].strip()
                if tech_name and tech_name not in self.technologies:
                    version = None
                    if '/' in headers['X-Powered-By']:
                        version = headers['X-Powered-By'].split('/')[1].strip()
                    
                    self.technologies[tech_name] = {
                        'name': tech_name,
                        'version': version,
                        'confidence': 'High',
                        'source': 'HTTP Headers'
                    }
            
            # Check for specific headers that indicate technologies
            header_tech_mapping = {
                'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC',
                'X-Drupal-Cache': 'Drupal',
                'X-Generator': 'CMS',
                'X-Powered-CMS': 'CMS',
                'X-Varnish': 'Varnish',
                'X-Magento-Cache-Debug': 'Magento',
                'X-Shopify-Stage': 'Shopify',
                'X-WP-Total': 'WordPress',
                'X-Litespeed-Cache': 'LiteSpeed',
                'X-Pingback': 'WordPress'
            }
            
            for header, tech in header_tech_mapping.items():
                if header in headers and tech not in self.technologies:
                    version = None
                    if header in ['X-AspNet-Version', 'X-AspNetMvc-Version']:
                        version = headers[header]
                    
                    self.technologies[tech] = {
                        'name': tech,
                        'version': version,
                        'confidence': 'High',
                        'source': 'HTTP Headers'
                    }
            
            logger.info(f"Analyzed HTTP headers for {target}")
        else:
            logger.warning(f"Failed to retrieve HTTP headers for {target}: {response.get('error', 'Unknown error')}")
    
    def _detect_javascript_libraries(self, target):
        """Detect JavaScript libraries used by the target."""
        logger.info(f"Detecting JavaScript libraries for {target}")
        
        response = make_request(target)
        
        if response['success']:
            html = response['text']
            
            # Look for script tags with src attributes
            script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*></script>')
            for match in script_pattern.finditer(html):
                script_src = match.group(1)
                
                # Check for common JS libraries
                js_libraries = {
                    'jquery': r'jquery[.-]\d+\.\d+\.\d+',
                    'bootstrap': r'bootstrap[.-]\d+\.\d+\.\d+',
                    'react': r'react[.-]\d+\.\d+\.\d+',
                    'angular': r'angular[.-]\d+\.\d+\.\d+',
                    'vue': r'vue[.-]\d+\.\d+\.\d+',
                    'lodash': r'lodash[.-]\d+\.\d+\.\d+',
                    'moment': r'moment[.-]\d+\.\d+\.\d+',
                    'underscore': r'underscore[.-]\d+\.\d+\.\d+',
                    'backbone': r'backbone[.-]\d+\.\d+\.\d+',
                    'd3': r'd3[.-]\d+\.\d+\.\d+'
                }
                
                for lib_name, pattern in js_libraries.items():
                    if re.search(pattern, script_src, re.IGNORECASE) or lib_name in script_src.lower():
                        # Extract version if available
                        version_match = re.search(r'[.-](\d+\.\d+\.\d+)', script_src)
                        version = version_match.group(1) if version_match else None
                        
                        lib_info = {
                            'name': lib_name,
                            'version': version,
                            'url': script_src
                        }
                        
                        if lib_info not in self.javascript_libraries:
                            self.javascript_libraries.append(lib_info)
                        
                        # Add to technologies
                        if lib_name not in self.technologies:
                            self.technologies[lib_name] = {
                                'name': lib_name,
                                'version': version,
                                'confidence': 'High',
                                'source': 'Script Tags'
                            }
            
            # Look for inline library declarations
            inline_libraries = {
                'jQuery': r'jQuery\s*=|\$\s*=\s*jQuery',
                'React': r'React\s*=|ReactDOM',
                'Angular': r'angular\s*=|angular\.module',
                'Vue': r'Vue\s*=|new\s+Vue',
                'Lodash': r'_\s*=|lodash\s*=',
                'Underscore': r'_\s*=|underscore\s*=',
                'Backbone': r'Backbone\s*=',
                'D3': r'd3\s*='
            }
            
            for lib_name, pattern in inline_libraries.items():
                if re.search(pattern, html):
                    lib_info = {
                        'name': lib_name,
                        'version': None,
                        'detection': 'Inline declaration'
                    }
                    
                    if lib_info not in self.javascript_libraries:
                        self.javascript_libraries.append(lib_info)
                    
                    # Add to technologies
                    if lib_name not in self.technologies:
                        self.technologies[lib_name] = {
                            'name': lib_name,
                            'version': None,
                            'confidence': 'Medium',
                            'source': 'Inline Code'
                        }
            
            logger.info(f"Detected {len(self.javascript_libraries)} JavaScript libraries for {target}")
        else:
            logger.warning(f"Failed to retrieve HTML content for {target}: {response.get('error', 'Unknown error')}")
    
    def _detect_cms(self, target):
        """Detect Content Management System (CMS) used by the target."""
        logger.info(f"Detecting CMS for {target}")
        
        response = make_request(target)
        
        if response['success']:
            html = response['text']
            
            # Check for common CMS signatures
            cms_signatures = {
                'WordPress': [
                    r'wp-content',
                    r'wp-includes',
                    r'<meta name="generator" content="WordPress',
                    r'<link[^>]*wp-content',
                    r'<script[^>]*wp-includes'
                ],
                'Drupal': [
                    r'Drupal.settings',
                    r'<meta name="Generator" content="Drupal',
                    r'sites/all/themes',
                    r'sites/all/modules'
                ],
                'Joomla': [
                    r'<meta name="generator" content="Joomla',
                    r'/templates/system/',
                    r'/media/system/js/'
                ],
                'Magento': [
                    r'Mage.Cookies',
                    r'var BLANK_URL',
                    r'skin/frontend/',
                    r'<script[^>]*magento'
                ],
                'Shopify': [
                    r'cdn.shopify.com',
                    r'Shopify.theme',
                    r'shopify-payment-button'
                ],
                'Wix': [
                    r'X-Wix-',
                    r'wix-dropdown',
                    r'wixSiteProperties',
                    r'wix-image'
                ],
                'Squarespace': [
                    r'static\d+\.squarespace\.com',
                    r'squarespace\.com/universal',
                    r'<meta name="generator" content="Squarespace"'
                ],
                'Ghost': [
                    r'<meta name="generator" content="Ghost',
                    r'ghost-url',
                    r'ghost-script'
                ],
                'TYPO3': [
                    r'<meta name="generator" content="TYPO3',
                    r'typo3temp/',
                    r'typo3conf/'
                ],
                'PrestaShop': [
                    r'<meta name="generator" content="PrestaShop',
                    r'prestashop-',
                    r'/themes/[^/]+/assets/'
                ]
            }
            
            for cms_name, patterns in cms_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, html, re.IGNORECASE):
                        # Extract version if available
                        version = None
                        version_pattern = re.compile(f'<meta name="generator" content="{cms_name}\s+([\d\.]+)', re.IGNORECASE)
                        version_match = version_pattern.search(html)
                        if version_match:
                            version = version_match.group(1)
                        
                        self.cms_info = {
                            'name': cms_name,
                            'version': version,
                            'confidence': 'High'
                        }
                        
                        # Add to technologies
                        if cms_name not in self.technologies:
                            self.technologies[cms_name] = {
                                'name': cms_name,
                                'version': version,
                                'confidence': 'High',
                                'source': 'CMS Detection',
                                'category': 'CMS'
                            }
                        
                        logger.info(f"Detected CMS: {cms_name} {version if version else ''}")
                        return
            
            logger.info(f"No CMS detected for {target}")
        else:
            logger.warning(f"Failed to retrieve HTML content for {target}: {response.get('error', 'Unknown error')}")
    
    def _custom_fingerprinting(self, target):
        """Custom fingerprinting when standard tools fail."""
        logger.info(f"Running custom fingerprinting on {target}")
        
        response = make_request(target)
        
        if response['success']:
            html = response['text']
            
            # Check for common technology signatures in HTML
            tech_signatures = {
                'jQuery': r'jquery[.-]\d+\.\d+\.\d+|jQuery\(|\$\(document\)',
                'Bootstrap': r'bootstrap[.-]\d+\.\d+\.\d+|class="container"|class="navbar',
                'React': r'react[.-]\d+\.\d+\.\d+|ReactDOM|createElement\(',
                'Angular': r'angular[.-]\d+\.\d+\.\d+|ng-app|ng-controller',
                'Vue.js': r'vue[.-]\d+\.\d+\.\d+|v-bind|v-model|v-if',
                'Font Awesome': r'font-awesome[.-]\d+\.\d+\.\d+|fa-|<i class="fa',
                'Google Analytics': r'google-analytics\.com|gtag\(|ga\(',
                'Google Tag Manager': r'googletagmanager\.com|gtm\.js',
                'Google Fonts': r'fonts\.googleapis\.com',
                'Cloudflare': r'cloudflare\.com|__cf',
                'Modernizr': r'modernizr[.-]\d+\.\d+\.\d+',
                'PHP': r'<\?php|X-Powered-By: PHP',
                'ASP.NET': r'\.aspx|__VIEWSTATE|__EVENTVALIDATION',
                'Laravel': r'laravel_session|\\Illuminate\\',
                'Django': r'csrfmiddlewaretoken|django',
                'Ruby on Rails': r'rails-ujs|csrf-token|data-method="delete"',
                'Express.js': r'express:sess',
                'Nginx': r'nginx/\d+\.\d+\.\d+',
                'Apache': r'apache/\d+\.\d+\.\d+',
                'IIS': r'IIS/\d+\.\d+',
                'Tomcat': r'tomcat/\d+\.\d+\.\d+',
                'Webpack': r'webpack/\d+\.\d+\.\d+|__webpack_require__',
                'Babel': r'babel-polyfill|transform-runtime',
                'TypeScript': r'__extends|__assign|__awaiter',
                'Lodash': r'lodash[.-]\d+\.\d+\.\d+|_\.map|_\.each',
                'Moment.js': r'moment[.-]\d+\.\d+\.\d+|moment\(\)',
                'Axios': r'axios[.-]\d+\.\d+\.\d+|axios\.get|axios\.post',
                'Redux': r'redux[.-]\d+\.\d+\.\d+|createStore|combineReducers',
                'GraphQL': r'graphql|ApolloClient|gql`',
                'Webpack': r'webpack[.-]\d+\.\d+\.\d+|__webpack_require__',
                'Tailwind CSS': r'tailwindcss|class="[^"]*text-\w+[^"]*"',
                'Material-UI': r'material-ui|MuiButton|MuiAppBar',
                'Ant Design': r'ant-design|antd|ant-btn|ant-input',
                'Bulma': r'bulma[.-]\d+\.\d+\.\d+|is-primary|is-info|is-success',
                'Foundation': r'foundation[.-]\d+\.\d+\.\d+|row|column|callout',
                'Semantic UI': r'semantic-ui|ui segment|ui button|ui form',
                'Materialize CSS': r'materialize[.-]\d+\.\d+\.\d+|materialize\.min\.css'
            }
            
            for tech_name, pattern in tech_signatures.items():
                if re.search(pattern, html, re.IGNORECASE) or re.search(pattern, str(response['headers']), re.IGNORECASE):
                    # Extract version if available
                    version_match = re.search(r'[.-](\d+\.\d+\.\d+)', html)
                    version = version_match.group(1) if version_match else None
                    
                    if tech_name not in self.technologies:
                        self.technologies[tech_name] = {
                            'name': tech_name,
                            'version': version,
                            'confidence': 'Medium',
                            'source': 'Custom Fingerprinting'
                        }
            
            logger.info(f"Custom fingerprinting identified {len(self.technologies)} technologies")
        else:
            logger.warning(f"Failed to retrieve HTML content for {target}: {response.get('error', 'Unknown error')}")