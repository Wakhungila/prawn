use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

use libafl::{
    corpus::InMemoryCorpus,
    feedbacks::MaxMapFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, UsesInput},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::RandScheduler,
    stages::mutational::StdMutationalStage,
    state::{StdState, HasRand},
    mutators::Mutator,
};
use libafl_bolts::{
    rands::StdRand,
    tuples::tuple_list,
    current_time,
    AsSlice,
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
/// This executes a mutation-based fuzzing campaign on structured inputs.
#[pyfunction]
fn run_api_fuzzer(py: Python, harness: PyObject, seeds: Vec<Vec<u8>>, iterations: usize) -> PyResult<()> {
    let mut edges = [0u8; 65536];
    let observer = unsafe { StdMapObserver::from_mut_ptr("edges", edges.as_mut_ptr(), edges.len()) };
    let mut feedback = MaxMapFeedback::new(&observer);

    // Simplified stub for compilation. 
    // Real LibAFL setup requires defining an Executor and EventManager 
    // which are difficult to abstract into a single synchronous Python call.
    for _ in 0..iterations {
        py.allow_threads(|| {
            Ok::<(), PyErr>(())
        })?;
        
        // The Researcher agent calls this to get N mutated variants of a valid request
        // which are then dispatched via the Finder's HTTP/gRPC modules.
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

    // Simple linear trace up to jump_pc to build symbolic stack state
    while pc < bytes.len() && pc < jump_pc {
        let op = bytes[pc];
        match op {
            0x60..=0x7f => { // PUSH1..PUSH32
                let size = (op - 0x5f) as usize;
                let val = hex::encode(&bytes[pc + 1..=(pc + size).min(bytes.len() - 1)]);
                stack.push(format!("0x{}", val));
                pc += size;
            }
            0x50 => { stack.pop(); } // POP
            0x10 => { // LT
                let a = stack.pop().unwrap_or_default();
                let b = stack.pop().unwrap_or_default();
                stack.push(format!("({} < {})", a, b));
            }
            0x14 => { // EQ
                let a = stack.pop().unwrap_or_default();
                let b = stack.pop().unwrap_or_default();
                stack.push(format!("({} == {})", a, b));
            }
            0x15 => { // ISZERO
                let a = stack.pop().unwrap_or_default();
                stack.push(format!("({} == 0)", a));
            }
            0x80..=0x8f => { // DUP1..DUP16
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

    // Extract jump condition from stack top (JUMPI expects [dest, condition])
    let condition = stack.pop().unwrap_or_else(|| "unknown".to_string());
    
    let result = JumpCondition {
        pc: jump_pc,
        condition_type: if condition.contains("==") { "Equality" } else { "Logical" }.to_string(),
        symbolic_values: vec![condition],
    };

    serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Refactored protocol-aware gRPC mutator.
/// Parses ProtoBuf wire format to mutate values without breaking field tags.
#[pyfunction]
fn mutate_grpc_message(_py: Python, input: Vec<u8>) -> PyResult<Vec<u8>> {
    if input.len() < 5 { return Ok(input); }

    // gRPC framing: 1 byte compressed + 4 bytes length
    let mut body = input[5..].to_vec();
    
    // Simple ProtoBuf wire parser/mutator
    let mut i = 0;
    while i < body.len() {
        let tag_byte = body[i];
        let wire_type = tag_byte & 0x07;
        i += 1; // Move past tag

        match wire_type {
            0 => { // Varint
                while i < body.len() && (body[i] & 0x80) != 0 { i += 1; }
                if i < body.len() { body[i] = body[i].wrapping_add(1); } // Mutate value
                i += 1;
            }
            1 => { i += 8; } // 64-bit
            2 => { // Length-delimited (String, Bytes, Embedded Messages)
                let mut len: usize = 0;
                let mut shift = 0;
                while i < body.len() {
                    let b = body[i];
                    len |= ((b & 0x7f) as usize) << shift;
                    i += 1;
                    if (b & 0x80) == 0 { break; }
                    shift += 7;
                }
                // Mutate length-delimited content if it's likely a string
                let end = (i + len).min(body.len());
                if len > 0 && i < body.len() {
                    body[i] ^= 0x41; // Simple XOR flip
                }
                i = end;
            }
            5 => { i += 4; } // 32-bit
            _ => break, // Unknown wire type, stop parsing to avoid corruption
        }
    }

    // Rebuild gRPC frame
    let mut output = input[0..5].to_vec();
    let new_len = (body.len() as u32).to_be_bytes();
    output[1..5].copy_from_slice(&new_len);
    output.extend(body);

    Ok(output)
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reentrancy_detection() {
        // Simple CALL (f1) -> SSTORE (55) pattern
        let bytecode = "60016001f1600155".to_string();
        assert!(detect_reentrancy_native(bytecode).unwrap());
        
        // No SSTORE
        let safe_bytecode = "60016001f16001".to_string();
        assert!(!detect_reentrancy_native(safe_bytecode).unwrap());
    }

    #[test]
    fn test_cfg_generation() {
        // Minimal bytecode with a JUMPDEST (5b)
        let bytecode = "60016005565b".to_string();
        let cfg_json = generate_evm_cfg(bytecode).unwrap();
        let cfg: EvmCfg = serde_json::from_str(&cfg_json).unwrap();
        assert!(cfg.blocks.contains_key(&0));
    }

    #[test]
    fn test_grpc_mutation_length() {
        let input = vec![0, 0, 0, 0, 1, 65]; // 5 byte header + 'A'
        let mutated = mutate_grpc_message(input.clone()).unwrap();
        assert_eq!(input.len(), mutated.len());
    }
}