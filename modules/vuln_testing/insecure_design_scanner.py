#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Insecure Design Scanner Module for PIN0CCHI0

This module detects insecure design patterns in web applications.
It focuses on identifying architectural and design flaws that can lead to security vulnerabilities.
"""

import re
import json
import logging
from urllib.parse import urlparse, parse_qs

from core.utils import make_request
from core.base_module import VulnTestingModule

# Configure logger
logger = logging.getLogger('pin0cchi0.vuln_testing.insecure_design')

class InsecureDesignScanner(VulnTestingModule):
    """Scanner for detecting insecure design patterns."""
    
    def __init__(self):
        """Initialize the Insecure Design Scanner module."""
        super().__init__()
        self.name = "Insecure Design Scanner"
        self.description = "Detects insecure design patterns in web applications"
        self.category = "vuln_testing"
        self.author = "PIN0CCHI0 Team"
        self.version = "0.1.0"
        self.references = [
            "https://owasp.org/Top10/A04_2021-Insecure_Design/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html"
        ]
        
        # Initialize patterns to detect
        self.insecure_patterns = {
            "predictable_ids": {
                "pattern": r"id=[0-9]+",
                "description": "Sequential or predictable resource IDs"
            },
            "debug_info": {
                "pattern": r"(stack trace|debug|exception|error:).{0,50}(at|in) [\w\.\\/:]+\.[a-zA-Z]+:[0-9]+",
                "description": "Debug information or stack traces exposed"
            },
            "insecure_direct_object_reference": {
                "pattern": r"(file|path|filepath|doc|document|load)=([\w\.\-/\\]+)",
                "description": "Potential insecure direct object references"
            },
            "missing_access_control": {
                "pattern": r"(admin|dashboard|manage|config|settings|setup)",
                "description": "Potentially sensitive endpoints without proper access control"
            },
            "hardcoded_credentials": {
                "pattern": r'''(api_?key|token|secret|password|credential)s?['"]?\s*[:=]\s*['"]?[\w\-]+['"]?''',
                "description": "Hardcoded credentials or secrets"
            },
            "mass_assignment": {
                "pattern": r"(user_?id|role|admin|is_?admin|group|permission)s?",
                "description": "Parameters that might be vulnerable to mass assignment"
            },
            "unsafe_redirects": {
                "pattern": r"(redirect|url|link|goto|return_?to|next)=",
                "description": "Potentially unsafe redirect parameters"
            },
            "rate_limit_absence": {
                "pattern": r"(login|register|signup|reset|forgot|password|otp|2fa|verify)",
                "description": "Authentication endpoints that might lack rate limiting"
            },
            "security_misconfiguration": {
                "pattern": r"(phpinfo|test|debug|dev|development)",
                "description": "Development or debug endpoints exposed in production"
            },
            "business_logic_flaws": {
                "pattern": r"(price|quantity|discount|coupon|total|amount|payment|checkout)",
                "description": "Parameters that might be manipulated in business logic"
            }
        }
        
    def run(self, target=None, output_dir=None, config=None, **kwargs):
        """Run the insecure design scanner."""
        if config is None:
            config = self.config or {}
        
        target = target or config.get('target')
        if not target:
            logger.error("No target specified")
            return {"status": "error", "message": "No target specified"}
        
        logger.info(f"Starting insecure design scan on {target}")
        
        # Results container
        results = {
            "status": "completed",
            "vulnerabilities": []
        }
        
        # Analyze the target
        self.analyze_target(target, results)
        
        # Check for additional design issues
        self._check_authentication_design(target, results)
        self.check_authorization_design(target, results)
        self.check_business_logic(target, results)
        self.check_api_design(target, results)
        
        logger.info(f"Completed insecure design scan on {target}")
        logger.info(f"Found {len(results['vulnerabilities'])} potential insecure design issues")
        
        return results
    
    def analyze_target(self, target, results):
        """Analyze the target for insecure design patterns."""
        # Make a request to the target
        response = make_request(target)
        if not response:
            logger.error(f"Failed to connect to {target}")
            return
        
        # Check response for insecure patterns
        self.check_response_patterns(target, response, results)
        
        # Extract and analyze links
        links = self.extract_links(response)
        for link in links:
            if self.should_analyze_link(target, link):
                link_response = make_request(link)
                if link_response:
                    self.check_response_patterns(link, link_response, results)
    
    def check_response_patterns(self, url, response, results):
        """Check response content for insecure design patterns."""
        # Check URL parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param_name in query_params:
            for pattern_name, pattern_info in self.insecure_patterns.items():
                if re.search(pattern_info["pattern"], param_name, re.IGNORECASE):
                    self.add_vulnerability(results, {
                        "type": "Insecure Design - Parameter",
                        "subtype": pattern_name,
                        "url": url,
                        "parameter": param_name,
                        "evidence": f"Parameter name matches pattern: {pattern_name}",
                        "description": pattern_info["description"],
                        "severity": "Medium"
                    })
        
        # Check response content
        content = response.text if hasattr(response, 'text') else str(response)
        
        for pattern_name, pattern_info in self.insecure_patterns.items():
            matches = re.finditer(pattern_info["pattern"], content, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                self.add_vulnerability(results, {
                    "type": "Insecure Design - Content",
                    "subtype": pattern_name,
                    "url": url,
                    "evidence": f"Content matches pattern: {matched_text}",
                    "description": pattern_info["description"],
                    "severity": "Medium"
                })
        
        # Check response headers
        if hasattr(response, 'headers'):
            for header_name, header_value in response.headers.items():
                if header_name.lower() in ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']:
                    self.add_vulnerability(results, {
                        "type": "Insecure Design - Information Disclosure",
                        "url": url,
                        "evidence": f"Header {header_name}: {header_value}",
                        "description": "Server information disclosure through headers",
                        "severity": "Low"
                    })
    
    def _check_authentication_design(self, target, results):
        """Check for authentication design issues."""
        # Check for login page
        login_paths = ["/login", "/signin", "/auth", "/user/login"]
        
        for path in login_paths:
            login_url = self.join_url(target, path)
            response = make_request(login_url)
            
            if response and response.status_code == 200:
                # Check for lack of CAPTCHA or rate limiting headers
                if not any(h.lower() in [h.lower() for h in response.headers] for h in ['x-rate-limit', 'retry-after']):
                    self.add_vulnerability(results, {
                        "type": "Insecure Design - Authentication",
                        "url": login_url,
                        "evidence": "No rate limiting headers detected",
                        "description": "Authentication endpoint without apparent rate limiting",
                        "severity": "Medium",
                        "remediation": "Implement rate limiting for authentication endpoints to prevent brute force attacks"
                    })
                
                # Check for password reset functionality
                reset_paths = ["/reset", "/forgot", "/password/reset", "/password/forgot"]
                for reset_path in reset_paths:
                    reset_url = self.join_url(target, reset_path)
                    reset_response = make_request(reset_url)
                    
                    if reset_response and reset_response.status_code == 200:
                        # Check for potential username enumeration
                        self.add_vulnerability(results, {
                            "type": "Insecure Design - Authentication",
                            "url": reset_url,
                            "evidence": "Password reset functionality found",
                            "description": "Password reset functionality might be vulnerable to username enumeration",
                            "severity": "Low",
                            "remediation": "Ensure password reset doesn't reveal whether an account exists"
                        })
    
    def check_authorization_design(self, target, results):
        """Check for authorization design issues."""
        # Check for admin or dashboard pages
        admin_paths = ["/admin", "/dashboard", "/manage", "/console", "/panel"]
        
        for path in admin_paths:
            admin_url = self.join_url(target, path)
            response = make_request(admin_url)
            
            if response:
                # If we can access it without authentication
                if response.status_code == 200:
                    self.add_vulnerability(results, {
                        "type": "Insecure Design - Authorization",
                        "url": admin_url,
                        "evidence": f"Admin page accessible: {response.status_code}",
                        "description": "Administrative interface potentially accessible without proper authorization",
                        "severity": "High",
                        "remediation": "Implement proper access controls for administrative interfaces"
                    })
                # If we get a redirect to login (302) rather than 401/403
                elif response.status_code == 302:
                    self.add_vulnerability(results, {
                        "type": "Insecure Design - Authorization",
                        "url": admin_url,
                        "evidence": f"Admin page redirects: {response.status_code}",
                        "description": "Administrative interface uses redirect instead of proper authorization denial",
                        "severity": "Low",
                        "remediation": "Use proper HTTP status codes (401/403) for authorization failures"
                    })
    
    def check_business_logic(self, target, results):
        """Check for business logic design issues."""
        # Check for cart/checkout functionality
        cart_paths = ["/cart", "/checkout", "/basket", "/order"]
        
        for path in cart_paths:
            cart_url = self.join_url(target, path)
            response = make_request(cart_url)
            
            if response and response.status_code == 200:
                # Look for price or quantity parameters
                content = response.text
                # Look for input fields that suggest price/quantity manipulation
                if re.search(r"<input[^>]*name=\s*['\"](price|amount|total|quantity)['\"][^>]*value=\s*['\"][\d\.]+", content, re.IGNORECASE):
                    self.add_vulnerability(results, {
                        "type": "Insecure Design - Business Logic",
                        "url": cart_url,
                        "evidence": "Price/quantity parameters found in form inputs",
                        "description": "Checkout process might be vulnerable to parameter manipulation",
                        "severity": "Medium",
                        "remediation": "Store prices server-side and validate all calculations"
                    })
    
    def check_api_design(self, target, results):
        """Check for API design issues."""
        # Check for API endpoints
        api_paths = ["/api", "/api/v1", "/api/v2", "/rest", "/graphql"]
        
        for path in api_paths:
            api_url = self.join_url(target, path)
            response = make_request(api_url)
            
            if response:
                # Check for API documentation exposure
                if response.status_code == 200:
                    content = response.text
                    if re.search(r"(swagger|api.?doc|openapi|raml|documentation)", content, re.IGNORECASE):
                        self.add_vulnerability(results, {
                            "type": "Insecure Design - API",
                            "url": api_url,
                            "evidence": "API documentation exposed",
                            "description": "API documentation publicly accessible",
                            "severity": "Low",
                            "remediation": "Restrict access to API documentation in production"
                        })
                    
                    # Check for potential mass assignment
                    if 'application/json' in response.headers.get('Content-Type', ''):
                        try:
                            json_data = json.loads(content)
                            if isinstance(json_data, dict) and any(k in json_data for k in ['id', 'user_id', 'role', 'admin']):
                                self.add_vulnerability(results, {
                                    "type": "Insecure Design - API",
                                    "url": api_url,
                                    "evidence": "Sensitive fields in API response",
                                    "description": "API might be vulnerable to mass assignment",
                                    "severity": "Medium",
                                    "remediation": "Implement allowlisting for API parameters and responses"
                                })
                        except json.JSONDecodeError:
                            pass
    
    def extract_links(self, response):
        """Extract links from response."""
        links = []
        if hasattr(response, 'text'):
            # Extract href links
            href_links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
            links.extend(href_links)
            
            # Extract src links
            src_links = re.findall(r'src=["\']([^"\']+)["\']', response.text)
            links.extend(src_links)
            
            # Extract form action links
            action_links = re.findall(r'action=["\']([^"\']+)["\']', response.text)
            links.extend(action_links)
        
        return links
    
    def should_analyze_link(self, base_url, link):
        """Determine if a link should be analyzed."""
        # Skip external links
        if link.startswith('http'):
            base_domain = urlparse(base_url).netloc
            link_domain = urlparse(link).netloc
            if base_domain != link_domain:
                return False
        
        # Skip non-web links
        if link.startswith('mailto:') or link.startswith('tel:') or link.startswith('#'):
            return False
        
        # Skip common static file extensions
        if re.search(r'\.(css|js|jpg|jpeg|png|gif|svg|ico|woff|ttf|eot)$', link, re.IGNORECASE):
            return False
        
        return True
    
    def join_url(self, base, path):
        """Join base URL with path."""
        if base.endswith('/') and path.startswith('/'):
            return base + path[1:]
        elif not base.endswith('/') and not path.startswith('/'):
            return base + '/' + path
        else:
            return base + path
    
    def get_timestamp(self):
        """Return ISO-8601 UTC timestamp."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'

    def add_vulnerability(self, results, vuln):
        """Add a vulnerability to results if it's not a duplicate."""
        # Check for duplicates
        for existing_vuln in results["vulnerabilities"]:
            if (existing_vuln["type"] == vuln["type"] and 
                existing_vuln["url"] == vuln["url"] and 
                existing_vuln.get("evidence") == vuln.get("evidence")):
                return
        
        # Add timestamp
        vuln["timestamp"] = self.get_timestamp()
        
        # Add to results
        results["vulnerabilities"].append(vuln)
        
        # Log the finding
        logger.warning(f"Found {vuln['type']} at {vuln['url']}: {vuln.get('description')}")