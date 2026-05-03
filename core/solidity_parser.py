import os
import re
import logging
from typing import List, Dict

logger = logging.getLogger("PRAWN.SolidityParser")

class SolidityInterfaceParser:
    """
    Specialized parser to extract function signatures from Solidity interfaces.
    Used to build concrete Echidna harnesses from abstract audit findings.
    """
    def __init__(self):
        # Captures interface or contract blocks
        self.block_regex = re.compile(r'(?:interface|contract|library)\s+(\w+)\s*\{(.*?)\}', re.DOTALL)
        
        # Improved function regex to handle overloading and return types
        self.function_regex = re.compile(r'function\s+(\w+\s*\([^)]*\))\s*(?:external|public|internal|private)?\s*(?:pure|view|payable)?\s*(?:returns\s*\([^)]*\))?;', re.MULTILINE)
        
        # Captures state variables and their visibility
        self.variable_regex = re.compile(r'\b(\w+(?:\[\])?)\s+(public|internal|private)\s+(?:constant\s+|immutable\s+)?(\w+)\s*(?:;|=)', re.MULTILINE)

    def extract_metadata(self, file_path: str) -> Dict[str, Dict[str, List[str]]]:
        """
        Parses a solidity file to return functions and state variables per block.
        """
        if not os.path.exists(file_path):
            return {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Failed to read file for parsing: {e}")
            return {}

        results = {}
        for block_match in self.block_regex.finditer(content):
            name = block_match.group(1)
            body = block_match.group(2)
            
            block_data = {
                "functions": [],
                "variables": []
            }
            
            # Extract Functions (handles overloading)
            for func_match in self.function_regex.finditer(body):
                block_data["functions"].append(func_match.group(0).strip())
            
            # Extract Variables and Visibility
            for var_match in self.variable_regex.finditer(body):
                block_data["variables"].append(f"{var_match.group(2)} {var_match.group(1)} {var_match.group(3)}")
            
            if block_data["functions"] or block_data["variables"]:
                results[name] = block_data

        return results

    def extract_signatures(self, file_path: str) -> Dict[str, List[str]]:
        """Legacy wrapper for backward compatibility."""
        meta = self.extract_metadata(file_path)
        return {name: data["functions"] for name, data in meta.items()}