#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Module Manager

This module handles the loading, management, and execution of PIN0CCHI0 modules.
"""

import os
import sys
import inspect
import importlib.util
import logging

logger = logging.getLogger('PIN0CCHI0.ModuleManager')

class ModuleManager:
    """Module manager for PIN0CCHI0."""
    
    def __init__(self, config_manager=None, modules_dir=None):
        """
        Initialize the module manager.
        
        Args:
            config_manager: Optional configuration manager reference
            modules_dir (str): Directory containing modules
        """
        self.config_manager = config_manager
        self.modules_dir = modules_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'modules')
        self.modules = {
            'recon': {},
            'vuln_testing': {},
            'exploitation': {},
            'reporting': {}
        }
    
    def discover_modules(self):
        """Discover available modules in the modules directory."""
        logger.info("Discovering modules...")
        
        for category in self.modules.keys():
            category_path = os.path.join(self.modules_dir, category)
            
            if not os.path.exists(category_path) or not os.path.isdir(category_path):
                logger.warning(f"Module category directory not found: {category_path}")
                continue
            
            logger.debug(f"Scanning for modules in {category_path}")
            
            # Get all Python files in the category directory
            for filename in os.listdir(category_path):
                if filename.endswith('.py') and not filename.startswith('__'):
                    module_name = filename[:-3]  # Remove .py extension
                    module_path = os.path.join(category_path, filename)
                    
                    logger.debug(f"Found module: {module_name} at {module_path}")
                    
                    # Add module to the list
                    self.modules[category][module_name] = {
                        'name': module_name,
                        'path': module_path,
                        'loaded': False,
                        'instance': None
                    }
        
        return self.modules
    
    def load_module(self, category, module_name):
        """Load a specific module."""
        if category not in self.modules or module_name not in self.modules[category]:
            logger.error(f"Module not found: {category}/{module_name}")
            return None
        
        module_info = self.modules[category][module_name]
        
        if module_info['loaded'] and module_info['instance']:
            return module_info['instance']
        
        try:
            # Load module dynamically
            spec = importlib.util.spec_from_file_location(
                f"pin0cchi0.modules.{category}.{module_name}",
                module_info['path']
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find the main class in the module by looking for subclasses of BaseModule
            from core.base_module import BaseModule as _Base
            candidates = []
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Only consider classes defined in this module
                if obj.__module__ != module.__name__:
                    continue
                try:
                    if issubclass(obj, _Base) and obj is not _Base:
                        candidates.append(obj)
                except Exception:
                    continue

            main_class = None
            if candidates:
                # Prefer names that contain the module_name (sans underscores) or end with 'Module'/'Scanner'
                key = module_name.replace('_', '').lower()
                def _score(cls):
                    n = cls.__name__.lower()
                    s = 0
                    if n.endswith('module') or n.endswith('scanner'):
                        s += 2
                    if key and key in n:
                        s += 3
                    # Small tie-breaker: longer names slightly preferred
                    s += len(n) * 0.001
                    return s
                candidates.sort(key=_score, reverse=True)
                main_class = candidates[0]
            
            if main_class is None:
                logger.error(f"Could not find main class in module: {category}/{module_name}")
                return None
            
            # Create an instance of the module
            instance = main_class()
            
            # Update module info
            self.modules[category][module_name]['loaded'] = True
            self.modules[category][module_name]['instance'] = instance
            
            logger.info(f"Module loaded: {category}/{module_name}")
            
            return instance
        
        except Exception as e:
            logger.error(f"Error loading module {category}/{module_name}: {e}")
            return None
    
    def load_all_modules(self):
        """Load all discovered modules."""
        logger.info("Loading all modules...")
        
        for category in self.modules:
            for module_name in self.modules[category]:
                self.load_module(category, module_name)
    
    def get_module(self, category, module_name):
        """Get a module instance, loading it if necessary."""
        if category not in self.modules or module_name not in self.modules[category]:
            logger.error(f"Module not found: {category}/{module_name}")
            return None
        
        module_info = self.modules[category][module_name]
        
        if not module_info['loaded'] or not module_info['instance']:
            return self.load_module(category, module_name)
        
        return module_info['instance']
    
    def get_all_modules(self, category=None):
        """Get all modules in a category or all categories."""
        if category:
            if category not in self.modules:
                logger.error(f"Category not found: {category}")
                return {}
            return self.modules[category]
        
        return self.modules
    
    def execute_module(self, category, module_name, **kwargs):
        """Execute a specific module with the given parameters."""
        instance = self.get_module(category, module_name)
        
        if not instance:
            logger.error(f"Failed to execute module {category}/{module_name}: Module not loaded")
            return None
        
        try:
            logger.info(f"Executing module: {category}/{module_name}")
            result = instance.run(**kwargs)
            return result
        except Exception as e:
            logger.error(f"Error executing module {category}/{module_name}: {e}")
            return None

    def get_modules(self):
        """Return a flattened list of discovered module metadata, for progress reporting."""
        flat = []
        for cat, mods in self.modules.items():
            for name, meta in mods.items():
                item = {'category': cat, 'name': name}
                for k, v in meta.items():
                    if k not in ('loaded', 'instance'):
                        item[k] = v
                flat.append(item)
        return flat