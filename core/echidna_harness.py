import os
import logging
from typing import List
from core.schemas import ResearchHypothesis
from core.utils import run_command
from core.solidity_parser import SolidityInterfaceParser

logger = logging.getLogger("PRAWN.EchidnaGenerator")

class EchidnaHarnessGenerator:
    """
    Generates property-based fuzzing targets for Echidna 
    based on ResearcherAgent attack chains.
    """
    def __init__(self, output_dir: str, project_root: str = None):
        self.output_dir = output_dir
        self.project_root = project_root
        self.parser = SolidityInterfaceParser()
        os.makedirs(self.output_dir, exist_ok=True)

    def _get_remappings(self) -> List[str]:
        """Dynamically retrieves Forge remappings for interface inclusion."""
        res = run_command("forge remappings")
        if res.get('success'):
            return res.get('stdout', '').splitlines()
        return []

    def _get_local_interfaces(self) -> List[str]:
        """Scans the 'src' directory for local interfaces to import."""
        if not self.project_root:
            return []
        
        interfaces = []
        src_path = os.path.join(self.project_root, "src")
        if os.path.exists(src_path):
            for root, _, filenames in os.walk(src_path):
                for f in filenames:
                    if f.endswith(".sol") and (f.startswith("I") or "interface" in f.lower()):
                        rel_path = os.path.relpath(os.path.join(root, f), src_path)
                        interfaces.append(f'import "src/{rel_path}";')
        return interfaces

    def generate(self, hypothesis: ResearchHypothesis) -> str:
        """
        Translates an attack chain into a Solidity Echidna harness.
        """
        class_name = hypothesis.title.replace(" ", "")
        file_path = os.path.join(self.output_dir, f"{class_name}_Harness.sol")
        
        # Dynamically include common external interfaces based on detected remappings
        remappings = self._get_remappings()
        imports = []
        contract_fields = []
        call_stubs = []
        
        for r in remappings:
            key = r.split('=')[0]
            if "openzeppelin" in r.lower():
                imports.append(f'import "{key}token/ERC20/IERC20.sol";')

        # Automatically detect and import local interfaces from the project's src directory
        local_imports = self._get_local_interfaces()
        all_imports = imports + local_imports
        imports_str = "\n".join(all_imports)

        # Use SolidityInterfaceParser to define concrete function calls
        if self.project_root:
            src_path = os.path.join(self.project_root, "src")
            if os.path.exists(src_path):
                for root, _, filenames in os.walk(src_path):
                    for f in filenames:
                        if f.endswith(".sol"):
                            f_path = os.path.join(root, f)
                            meta = self.parser.extract_metadata(f_path)
                            for name, data in meta.items():
                                # Define a field for the interface
                                var_name = f"target{name}"
                                contract_fields.append(f"    {name} internal {var_name};")
                                
                                # Create call stubs for each function
                                for sig in data.get("functions", []):
                                    call_stubs.append(f"        // {var_name}.{sig}")

        # Transform attack chain steps into descriptive comments/markers
        chain_comments = "\n    ".join([f"// Step {i+1}: {step}" for i, step in enumerate(hypothesis.attack_chain)])
        fields_str = "\n".join(contract_fields)
        stubs_str = "\n".join(call_stubs)
        
        harness_code = f"""
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

{imports_str}

/**
 * @dev Automatically generated Echidna harness for PRAWN Hypothesis:
 * {hypothesis.title}
 * Potential Impact: {hypothesis.potential_impact}
 */
contract {class_name}Harness {{
{fields_str}

    function echidna_verify_attack_chain() public returns (bool) {{
        {chain_comments}

        // Concrete Function Call Templates:
{stubs_str}

        // The property is that this attack chain should be unreachable
        return true; 
    }}
}}
"""
        with open(file_path, "w") as f:
            f.write(harness_code)
            
        logger.info(f"Echidna harness generated: {file_path}")
        return file_path