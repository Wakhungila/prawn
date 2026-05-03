from typing import List
import logging

logger = logging.getLogger("PRAWN.BytecodeAnalyzer")

try:
    import prawn_core
except ImportError:
    logger.warning("Native prawn-core not compiled. Falling back to slow Python analysis. Run 'maturin develop'.")
    prawn_core = None

class BytecodeAnalyzer:
    """
    Advanced EVM Bytecode Analyzer.
    Identifies dangerous logic patterns like reentrancy using opcode sequence analysis.
    """

    # Opcode Hex constants
    CALL = 'f1'
    CALLCODE = 'f2'
    SLOAD = '54'
    DELEGATECALL = 'f4'
    STATICCALL = 'fa'
    SSTORE = '55'

    def analyze(self, bytecode_hex: str) -> List[str]:
        """Analyzes hex bytecode for specific vulnerability patterns."""
        findings = []
        code = bytecode_hex.lower().replace('0x', '')

        # Try Native Rust implementation first for blazing speed
        if prawn_core:
            if prawn_core.detect_reentrancy_native(bytecode_hex):
                findings.append("Potential Reentrancy: Sequence [CALL -> SSTORE] detected in bytecode (Native Analysis).")
            return findings

        # 1. State-After-Call Reentrancy Sequence
        # Heuristic: Detects if a storage update (SSTORE) follows an external call in a potential execution flow.
        if self._detect_reentrancy_pattern(code):
            findings.append("Potential Reentrancy: Sequence [CALL -> SSTORE] detected in bytecode.")

        if self._detect_uninitialized_storage_pointer(code):
            findings.append("Potential Uninitialized Storage Pointer: Access to slot 0 detected.")

        return findings

    def check_cross_contract_collision(self, proxy_bytecode: str, impl_bytecode: str) -> List[str]:
        """Analyzes two bytecodes to find overlapping storage slot writes."""
        collisions = []
        
        def get_slots(bcode):
            # Heuristic: find PUSH instructions immediately preceding SSTORE
            slots = set()
            ops = [bcode[i:i+2] for i in range(0, len(bcode), 2)]
            for i, op in enumerate(ops):
                if op == self.SSTORE and i > 0:
                    # Look back for PUSH opcodes (60-7f)
                    if ops[i-1].startswith('6'):
                        slots.add(ops[i-1])
            return slots

        p_slots = get_slots(proxy_bytecode.lower().replace('0x', ''))
        i_slots = get_slots(impl_bytecode.lower().replace('0x', ''))
        
        overlap = p_slots.intersection(i_slots)
        if overlap:
            collisions.append(f"Storage Collision Detected: Both contracts write to slots: {list(overlap)}")
        
        return collisions

    def _detect_uninitialized_storage_pointer(self, code: str) -> bool:
        """Heuristic: look for PUSH 0 followed by SSTORE in non-standard contexts."""
        return "600055" in code or "600054" in code

    def _detect_reentrancy_pattern(self, code: str) -> bool:
        """
        Heuristic sequence checker.
        Looks for state-changing CALLs followed by SSTORE (55) within a sliding window.
        """
        # Convert hex string to a list of opcodes (pairs of chars)
        opcodes = [code[i:i+2] for i in range(0, len(code), 2)]
        
        for i, op in enumerate(opcodes):
            if op in [self.CALL, self.DELEGATECALL, self.CALLCODE]:
                # Check for storage write in the subsequent 256 opcodes
                window = opcodes[i+1 : i+257]
                if self.SSTORE in window:
                    return True
        return False