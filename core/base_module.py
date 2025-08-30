#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Base Module

This module defines the base class that all PIN0CCHI0 modules should inherit from.
"""

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger('PIN0CCHI0.BaseModule')

class BaseModule(ABC):
    """Base class for all PIN0CCHI0 modules."""
    
    def __init__(self, name=None, description=None):
        """
        Initialize the base module.
        
        Args:
            name (str): Module name
            description (str): Module description
        """
        self.name = name or self.__class__.__name__
        self.description = description or "No description provided"
        self.results = []
        self.logger = logging.getLogger(f'PIN0CCHI0.{self.name}')
    
    @abstractmethod
    def run(self, **kwargs):
        """Run the module. Must be implemented by subclasses."""
        pass
    
    def add_result(self, result):
        """
        Add a result to the module's results.
        
        Args:
            result (dict): Result data
        """
        self.results.append(result)
        self.logger.info(f"Added result: {result.get('title', 'Untitled')}")
    
    def get_results(self):
        """Get all results from the module."""
        return self.results
    
    def clear_results(self):
        """Clear all results from the module."""
        self.results = []
        self.logger.debug("Cleared all results")
    
    def validate_result(self, result):
        """
        Validate a result to ensure it has all required fields.
        
        Args:
            result (dict): Result to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        required_fields = ['title', 'severity']
        
        for field in required_fields:
            if field not in result:
                self.logger.warning(f"Result missing required field: {field}")
                return False
        
        return True


class ReconModule(BaseModule):
    """Base class for reconnaissance modules."""
    
    def __init__(self, name=None, description=None):
        super().__init__(name, description)
        self.category = 'recon'


class VulnTestingModule(BaseModule):
    """Base class for vulnerability testing modules."""
    
    def __init__(self, name=None, description=None):
        super().__init__(name, description)
        self.category = 'vuln_testing'

# Compatibility alias for legacy import names
VulnerabilityTestingModule = VulnTestingModule


class ExploitationModule(BaseModule):
    """Base class for exploitation modules."""
    
    def __init__(self, name=None, description=None):
        super().__init__(name, description)
        self.category = 'exploitation'


class ReportingModule(BaseModule):
    """Base class for reporting modules."""
    
    def __init__(self, name=None, description=None):
        super().__init__(name, description)
        self.category = 'reporting'