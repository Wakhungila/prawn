import os
import logging
import subprocess
from typing import List, Dict

logger = logging.getLogger("PRAWN.GitDiff")

class GitDiffModule:
    """
    Extracts changed files and lines to enable 'delta-audit' mode.
    Focuses the CodeAuditorAgent only on the attack surface introduced by new changes.
    """
    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def get_changed_files(self, revision_range: str) -> List[str]:
        """Returns a list of files changed in the specified git range (e.g., v1.0..HEAD)."""
        try:
            cmd = f"git -C {self.repo_path} diff --name-only {revision_range}"
            result = subprocess.check_output(cmd, shell=True).decode().splitlines()
            return [os.path.join(self.repo_path, f) for f in result]
        except Exception as e:
            logger.error(f"Failed to extract git changed files: {e}")
            return []

    def get_diff_context(self, file_path: str, revision_range: str) -> str:
        """Extracts the actual diff content for a specific file."""
        try:
            # Relative path for git
            rel_path = os.path.relpath(file_path, self.repo_path)
            cmd = f"git -C {self.repo_path} diff -U0 {revision_range} -- {rel_path}"
            return subprocess.check_output(cmd, shell=True).decode()
        except Exception:
            return ""