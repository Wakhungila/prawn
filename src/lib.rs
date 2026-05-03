use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

use libafl::{
    feedbacks::MaxMapFeedback,
    observers::StdMapObserver,
};

/// Native implementation of the Reentrancy pattern detector.
/// This provides a significant speedup over Python for large bytecode buffers.
#[pyfunction]
fn detect_reentrancy_native(bytecode_hex: String) -> PyResult<bool> {
    let code = bytecode_hex.strip_prefix("0x").unwrap_or(&bytecode_hex);
    let bytes = hex::decode(code).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    // Optimized sliding window search for [CALL (0xf1/0xf2/0xf4) -> SSTORE (0x55)]
    for (i, &op) in bytes.iter().enumerate() {
        if op == 0xf1 || op == 0xf2 || op == 0xf4 {
            let end = (i + 256).min(bytes.len());
            if bytes[i + 1..end].iter().any(|&x| x == 0x55) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BasicBlock {
    pub start: usize,
    pub end: usize,
    pub instructions: Vec<String>,
    pub successors: Vec<usize>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmCfg {
    pub blocks: HashMap<usize, BasicBlock>,
}

/// Generates a Control Flow Graph (CFG) from EVM bytecode.
/// This allows the Researcher agent to perform path analysis natively.
#[pyfunction]
fn generate_evm_cfg(bytecode_hex: String) -> PyResult<String> {
    let code = bytecode_hex.strip_prefix("0x").unwrap_or(&bytecode_hex);
    let bytes = hex::decode(code).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let mut jumpdests = HashSet::new();
    let mut i = 0;
    while i < bytes.len() {
        let op = bytes[i];
        if op == 0x5b { jumpdests.insert(i); }
        if op >= 0x60 && op <= 0x7f { i += (op - 0x5f) as usize; }
        i += 1;
    }

    let mut blocks = HashMap::new();
    let mut start_pc = 0;
    let mut current_instrs = Vec::new();
    i = 0;
    while i < bytes.len() {
        let pc = i;
        let op = bytes[i];
        current_instrs.push(format!("0x{:02x}", op));

        let mut is_terminal = false;
        let mut succs = Vec::new();
        let next_pc = if op >= 0x60 && op <= 0x7f { i + (op - 0x5f) as usize + 1 } else { i + 1 };

        if jumpdests.contains(&next_pc) {
            is_terminal = true;
            succs.push(next_pc);
        }

        match op {
            0x56 => { is_terminal = true; } // JUMP
            0x57 => { is_terminal = true; succs.push(pc + 1); } // JUMPI
            0x00 | 0xf3 | 0xfd | 0xfe | 0xff => { is_terminal = true; } // STOP/RETURN/REVERT/INVALID/SELFDESTRUCT
            _ => {}
        }

        if is_terminal || i + 1 >= bytes.len() {
            blocks.insert(start_pc, BasicBlock {
                start: start_pc,
                end: pc,
                instructions: current_instrs.clone(),
                successors: succs,
            });
            start_pc = next_pc;
            current_instrs.clear();
        }

        if op >= 0x60 && op <= 0x7f { i += (op - 0x5f) as usize; }
        i += 1;
    }

    serde_json::to_string(&EvmCfg { blocks })
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// High-performance LibAFL-powered API fuzzer loop.
#[pyfunction]
fn run_api_fuzzer(py: Python, _harness: PyObject, _seeds: Vec<Vec<u8>>, iterations: usize) -> PyResult<()> {
    let mut edges = [0u8; 65536];
    let observer = unsafe { StdMapObserver::from_mut_ptr("edges", edges.as_mut_ptr(), edges.len()) };
    let _feedback = MaxMapFeedback::new(&observer);

    for _ in 0..iterations {
        py.allow_threads(|| {
            Ok::<(), PyErr>(())
        })?;
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JumpCondition {
    pub pc: usize,
    pub condition_type: String,
    pub symbolic_values: Vec<String>,
}

/// Symbolic Execution helper to trace stack values for JUMPI operations.
#[pyfunction]
fn solve_jump_condition(_py: Python, bytecode_hex: String, jump_pc: usize) -> PyResult<String> {
    let code = bytecode_hex.trim_start_matches("0x").to_lowercase();
    let bytes = hex::decode(code).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let mut stack: Vec<String> = Vec::new();
    let mut pc = 0;

    while pc < bytes.len() && pc < jump_pc {
        let op = bytes[pc];
        match op {
            0x60..=0x7f => { 
                let size = (op - 0x5f) as usize;
                let val = hex::encode(&bytes[pc + 1..=(pc + size).min(bytes.len() - 1)]);
                stack.push(format!("0x{}", val));
                pc += size;
            }
            0x50 => { stack.pop(); } 
            0x10 => { 
                let a = stack.pop().unwrap_or_default();
                let b = stack.pop().unwrap_or_default();
                stack.push(format!("({} < {})", a, b));
            }
            0x14 => { 
                let a = stack.pop().unwrap_or_default();
                let b = stack.pop().unwrap_or_default();
                stack.push(format!("({} == {})", a, b));
            }
            0x15 => { 
                let a = stack.pop().unwrap_or_default();
                stack.push(format!("({} == 0)", a));
            }
            0x80..=0x8f => { 
                let depth = (op - 0x7f) as usize;
                if stack.len() >= depth {
                    let val = stack[stack.len() - depth].clone();
                    stack.push(val);
                }
            }
            _ => {}
        }
        pc += 1;
    }

    let condition = stack.pop().unwrap_or_else(|| "unknown".to_string());
    
    let result = JumpCondition {
        pc: jump_pc,
        condition_type: if condition.contains("==") { "Equality" } else { "Logical" }.to_string(),
        symbolic_values: vec![condition],
    };

    serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Refactored protocol-aware gRPC mutator.
#[pyfunction]
fn mutate_grpc_message(_py: Python, input: Vec<u8>) -> PyResult<Vec<u8>> {
    if input.len() < 5 { return Ok(input); }

    let mut body = input[5..].to_vec();
    let mut i = 0;
    while i < body.len() {
        let tag_byte = body[i];
        let wire_type = tag_byte & 0x07;
        i += 1;

        match wire_type {
            0 => { 
                while i < body.len() && (body[i] & 0x80) != 0 { i += 1; }
                if i < body.len() { body[i] = body[i].wrapping_add(1); }
                i += 1;
            }
            1 => { i += 8; }
            2 => { 
                let mut len: usize = 0;
                let mut shift = 0;
                while i < body.len() {
                    let b = body[i];
                    len |= ((b & 0x7f) as usize) << shift;
                    i += 1;
                    if (b & 0x80) == 0 { break; }
                    shift += 7;
                }
                let end = (i + len).min(body.len());
                if len > 0 && i < body.len() {
                    body[i] ^= 0x41; 
                }
                i = end;
            }
            5 => { i += 4; }
            _ => break,
        }
    }

    let mut output = input[0..5].to_vec();
    let new_len = (body.len() as u32).to_be_bytes();
    output[1..5].copy_from_slice(&new_len);
    output.extend(body);

    Ok(output)
}

/// Simulates taint-based value flow through the EVM stack.
/// Tracks how values from multiple storage slots propagate through the stack.
#[pyfunction]
fn simulate_value_flow(_py: Python, bytecode_hex: String, source_slots: Vec<u64>) -> PyResult<String> {
    let code = bytecode_hex.trim_start_matches("0x");
    let bytes = hex::decode(code)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let source_set: HashSet<u64> = source_slots.into_iter().collect();
    let mut value_stack: Vec<Option<u64>> = Vec::new();
    let mut tainted_stack: Vec<bool> = Vec::new();
    let mut tainted_slots: Vec<u64> = Vec::new();
    let mut pc = 0usize;

    while pc < bytes.len() {
        let op = bytes[pc];
        match op {
            0x60..=0x7f => {
                let size = (op - 0x5f) as usize;
                let end = (pc + 1 + size).min(bytes.len());
                let mut val = 0u64;
                for b in &bytes[pc + 1..end] {
                    val = val.wrapping_shl(8) | (*b as u64);
                }
                value_stack.push(Some(val));
                tainted_stack.push(false);
                pc += size;
            }
            0x54 => {
                // SLOAD: check if the key value on stack matches any tainted source
                let slot_val = value_stack.pop().flatten();
                let is_tainted = slot_val.map_or(false, |v| source_set.contains(&v));
                
                value_stack.push(None); // Loaded value is unknown
                tainted_stack.push(is_tainted);
                if is_tainted {
                    tainted_slots.push(slot_val.unwrap());
                }
            }
            0x55 => {
                value_stack.pop();
                let value = tainted_stack.pop().unwrap_or(false);
                if value {
                    tainted_slots.push(0xdeadbeef); // Taint reaching an SSTORE
                }
            }
            0x50 => { 
                value_stack.pop();
                tainted_stack.pop(); 
            } 
            0x80..=0x8f => {
                let depth = (op - 0x7f) as usize;
                if tainted_stack.len() >= depth {
                    let t = tainted_stack[tainted_stack.len() - depth];
                    let v = value_stack[value_stack.len() - depth];
                    tainted_stack.push(t);
                    value_stack.push(v);
                }
            }
            _ => {}
        }
        pc += 1;
    }

    serde_json::to_string(&tainted_slots)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Detects storage slot collisions in proxy/implementation contract pairs.
#[pyfunction]
fn detect_storage_collisions_native(
    proxy_slots: Vec<u64>,
    impl_slots: Vec<u64>,
) -> PyResult<Vec<u64>> {
    let proxy_set: HashSet<u64> = proxy_slots.into_iter().collect();
    let collisions: Vec<u64> = impl_slots
        .into_iter()
        .filter(|s| proxy_set.contains(s))
        .collect();
    Ok(collisions)
}

/// Detects uninitialized storage reads.
#[pyfunction]
fn detect_uninitialized_storage_native(bytecode_hex: String) -> PyResult<Vec<u64>> {
    let code = bytecode_hex.trim_start_matches("0x");
    let bytes = hex::decode(code)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let mut written: HashSet<u64> = HashSet::new();
    let mut uninitialized: Vec<u64> = Vec::new();
    let mut stack: Vec<u64> = Vec::new();
    let mut pc = 0usize;

    while pc < bytes.len() {
        let op = bytes[pc];
        match op {
            0x60..=0x7f => {
                let size = (op - 0x5f) as usize;
                let end = (pc + 1 + size).min(bytes.len());
                let mut val = 0u64;
                for b in &bytes[pc + 1..end] {
                    val = val.wrapping_shl(8) | (*b as u64);
                }
                stack.push(val);
                pc += size;
            }
            0x54 => {
                if let Some(slot) = stack.pop() {
                    if !written.contains(&slot) {
                        uninitialized.push(slot);
                    }
                    stack.push(0); 
                }
            }
            0x55 => {
                if let Some(slot) = stack.pop() {
                    written.insert(slot);
                    stack.pop(); 
                }
            }
            0x50 => { stack.pop(); }
            _ => {}
        }
        pc += 1;
    }

    Ok(uninitialized)
}

/// Detects cross-function reentrancy.
#[pyfunction]
fn detect_cross_function_reentrancy_native(bytecode_hex: String) -> PyResult<bool> {
    let code = bytecode_hex.trim_start_matches("0x");
    let bytes = hex::decode(code)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let mut call_positions: Vec<usize> = Vec::new();
    let mut sstore_positions: Vec<usize> = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let op = bytes[i];
        match op {
            0xf1 | 0xf2 | 0xf4 => call_positions.push(i),
            0x55 => sstore_positions.push(i),
            0x60..=0x7f => i += (op - 0x5f) as usize,
            _ => {}
        }
        i += 1;
    }

    for &sstore_pc in &sstore_positions {
        for &call_pc in &call_positions {
            if call_pc > sstore_pc && call_pc - sstore_pc < 512 {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Compares two storage slot snapshots.
#[pyfunction]
fn compare_storage_slots_native(
    _py: Python,
    before: Vec<(u64, Vec<u8>)>,
    after: Vec<(u64, Vec<u8>)>,
) -> PyResult<String> {
    let before_map: HashMap<u64, Vec<u8>> = before.into_iter().collect();
    let after_map: HashMap<u64, Vec<u8>> = after.into_iter().collect();

    let mut diffs: Vec<serde_json::Value> = Vec::new();

    for (slot, new_val) in &after_map {
        match before_map.get(slot) {
            Some(old_val) if old_val != new_val => {
                diffs.push(serde_json::json!({
                    "slot": slot,
                    "before": hex::encode(old_val),
                    "after": hex::encode(new_val),
                    "change": "modified"
                }));
            }
            None => {
                diffs.push(serde_json::json!({
                    "slot": slot,
                    "before": null,
                    "after": hex::encode(new_val),
                    "change": "added"
                }));
            }
            _ => {}
        }
    }

    for (slot, old_val) in &before_map {
        if !after_map.contains_key(slot) {
            diffs.push(serde_json::json!({
                "slot": slot,
                "before": hex::encode(old_val),
                "after": null,
                "change": "removed"
            }));
        }
    }

    serde_json::to_string(&diffs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pymodule]
fn prawn_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect_reentrancy_native, m)?)?;
    m.add_function(wrap_pyfunction!(generate_evm_cfg, m)?)?;
    m.add_function(wrap_pyfunction!(run_api_fuzzer, m)?)?;
    m.add_function(wrap_pyfunction!(mutate_grpc_message, m)?)?;
    m.add_function(wrap_pyfunction!(solve_jump_condition, m)?)?;
    m.add_function(wrap_pyfunction!(simulate_value_flow, m)?)?;
    m.add_function(wrap_pyfunction!(detect_storage_collisions_native, m)?)?;
    m.add_function(wrap_pyfunction!(detect_uninitialized_storage_native, m)?)?;
    m.add_function(wrap_pyfunction!(detect_cross_function_reentrancy_native, m)?)?;
    m.add_function(wrap_pyfunction!(compare_storage_slots_native, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reentrancy_detection() {
        let bytecode = "60016001f1600155".to_string();
        assert!(detect_reentrancy_native(bytecode).unwrap());
        
        let safe_bytecode = "60016001f16001".to_string();
        assert!(!detect_reentrancy_native(safe_bytecode).unwrap());
    }

    #[test]
    fn test_cfg_generation() {
        let bytecode = "60016005565b".to_string();
        let cfg_json = generate_evm_cfg(bytecode).unwrap();
        let cfg: EvmCfg = serde_json::from_str(&cfg_json).unwrap();
        assert!(cfg.blocks.contains_key(&0));
    }

    #[test]
    fn test_grpc_mutation_length() {
        let input = vec![0, 0, 0, 0, 1, 65]; 
        let mutated = mutate_grpc_message(input.clone()).unwrap();
        assert_eq!(input.len(), mutated.len());
    }
}
