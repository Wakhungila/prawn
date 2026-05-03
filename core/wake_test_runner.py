import os
import logging
from typing import Dict, Any
from core.utils import run_command

logger = logging.getLogger("PRAWN.WakeTestRunner")

class WakeTestRunner:
    """
    Automated runner for Wake-based reproduction tests.
    Executes generated tests and captures results for strategic reporting.
    """
    def __init__(self, target_path: str):
        self.target_path = target_path

    async def execute_reproduction_tests(self) -> Dict[str, Any]:
        """
        Executes all tests in the project's test directory using Wake.
        """
        test_dir = os.path.join(self.target_path, "tests")
        if not os.path.isdir(test_dir):
            return {"success": False, "error": "Test directory not found"}

        logger.info(f"🚀 WakeTestRunner initiating execution in {test_dir}...")
        
        # Execute wake test within the target project context
        # We use a timeout to prevent infinite loops in faulty test cases
        result = run_command(f"wake test", timeout=300)
        
        summary = {
            "success": result.get("success", False),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "returncode": result.get("returncode", -1)
        }
        
        logger.info(f"Wake execution finished with status: {'Success' if summary['success'] else 'Failure'}")
        return summary