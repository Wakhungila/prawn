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

        # Try Native Rust implementation first for blazing speed
        if prawn_core:
            try:
                # Native reentrancy check (CFG-aware)
                if prawn_core.detect_reentrancy_native(bytecode_hex):
                    findings.append("Potential Reentrancy: Sequence [CALL -> SSTORE] detected via native CFG analysis.")
                
                # Native uninitialized storage check
                uninit_slots = prawn_core.detect_uninitialized_storage_native(bytecode_hex)
                if uninit_slots:
                    findings.append(f"Potential Uninitialized Storage Pointer: Critical access to slots {uninit_slots} detected (Native).")
                
                # Native cross-function reentrancy check
                if prawn_core.detect_cross_function_reentrancy_native(bytecode_hex):
                    findings.append("High Risk: Potential Cross-Function Reentrancy detected via state-flow analysis (Native).")
                
                # If we have native results, we return early to avoid redundant/noisy heuristic checks
                if findings:
                    return findings
            except Exception as e:
                logger.error(f"Native bytecode analysis failed, falling back to heuristics: {e}")

        # --- Fallback Heuristics (Python) ---
        code = bytecode_hex.lower().replace('0x', '')
        
        # 1. State-After-Call Reentrancy Sequence
        if self._detect_reentrancy_pattern(code):
            findings.append("Potential Reentrancy: Sequence [CALL -> SSTORE] detected (Heuristic).")

        if self._detect_uninitialized_storage_pointer(code):
            findings.append("Potential Uninitialized Storage Pointer: Access to slot 0 detected (Heuristic).")

        if self._detect_cross_function_reentrancy_risk(code):
            findings.append("High Risk: Potential Cross-Function Reentrancy (Heuristic).")

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

        if prawn_core:
            try:
                # Convert hex-string slots from heuristic to integers for Rust
                p_ids = [int(s, 16) for s in p_slots if len(s) <= 16]
                i_ids = [int(s, 16) for s in i_slots if len(s) <= 16]
                
                # Use the native set-intersection collision detector
                overlap = prawn_core.detect_storage_collisions_native(p_ids, i_ids)
                if overlap:
                    return [f"Storage Collision Detected (Native): Both contracts write to slots: {overlap}"]
            except Exception as e:
                logger.error(f"Native collision check failed: {e}")
        
        overlap = p_slots.intersection(i_slots)
        if overlap:
            collisions.append(f"Storage Collision Detected: Both contracts write to slots: {list(overlap)}")
        
        return collisions

    def _detect_uninitialized_storage_pointer(self, code: str) -> bool:
        """Heuristic: look for PUSH 0 followed by SSTORE in non-standard contexts."""
        return "600055" in code or "600054" in code

    def _detect_cross_function_reentrancy_risk(self, code: str) -> bool:
        """
        Heuristic for cross-function reentrancy.
        Looks for a pattern where a storage slot is written (SSTORE), followed by a 
        potential state-changing call, followed by another SSTORE later in the bytecode.
        """
        opcodes = [code[i:i+2] for i in range(0, len(code), 2)]
        call_indices = [i for i, op in enumerate(opcodes) if op in [self.CALL, self.DELEGATECALL]]
        
        for idx in call_indices:
            # Check if there's an SSTORE before AND after the call in a broad window
            pre_window = opcodes[max(0, idx-128) : idx]
            post_window = opcodes[idx+1 : min(len(opcodes), idx+129)]
            if self.SSTORE in pre_window and self.SSTORE in post_window:
                return True
        return False

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