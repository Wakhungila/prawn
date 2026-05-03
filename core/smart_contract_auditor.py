import logging
from typing import List
from core.schemas import Finding, Severity, FindingType

logger = logging.getLogger('PRAWN.Web3Auditor')

class SmartContractAuditor:
    """
    Dedicated auditor for EVM (Solidity) and SVM (Anchor/Rust).
    """
    def __init__(self, config):
        self.config = config

    async def audit_file(self, content: str, filename: str) -> List[Finding]:
        """Perform multi-language static + contextual analysis."""
        findings = []
        
        if filename.endswith('.sol'):
            findings.extend(self._audit_solidity(content, filename))
        elif filename.endswith('.rs'):
            findings.extend(self._audit_anchor(content, filename))
            
        return findings

    def _audit_solidity(self, content: str, path: str) -> List[Finding]:
        vulns = []
        # High-level patterns for the Judge to validate
        if "call{value:" in content and ".sender" in content:
             vulns.append(Finding(
                id=f"WEB3-SOL-{path}-01",
                type=FindingType.REENTRANCY,
                severity=Severity.HIGH,
                target=path,
                description="Potential reentrancy vector detected in external call.",
                evidence="Unprotected low-level call found.",
                remediation="Use ReentrancyGuard and ensure state is updated before the call."
            ))
        return vulns

    def _audit_anchor(self, content: str, path: str) -> List[Finding]:
        vulns = []
        if "AccountInfo" in content and "owner" not in content.lower():
            vulns.append(Finding(
                id=f"WEB3-SVM-{path}-01",
                type=FindingType.ACCOUNT_CONFUSION,
                severity=Severity.CRITICAL,
                target=path,
                description="SVM Account ownership check missing.",
                evidence="AccountInfo used without ownership validation.",
                remediation="Verify account ownership using Anchor's #[account] macros."
            ))
        return vulns