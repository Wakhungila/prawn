# PRAWN 🦐 – Powerful Research Agent for Web & Web3

PRAWN is a production-grade, multi-agent autonomous security researcher designed for modern Web2/Web3 ecosystems. It transitions beyond simple scanning into deep logic analysis, 0-day hypothesis generation, and contextual source code auditing.

### 🔱 The Multi-Agent System (MAS)
PRAWN operates via a coordinated sequential agent loop, optimized for **8GB RAM** local environments (Ollama):

- **Finder 🔍**: High-speed discovery and anomaly detection across APIs and Smart Contracts.
- **Judge ⚖️**: Validates anomalies, filters noise, and assigns deterministic severity scores.
- **Researcher 🧪**: The "0-day mode" agent. Combines findings to hypothesize novel attack chains.
- **Code Auditor 📄**: Deep contextual static analysis of Solidity, Rust, Go, and Python.
- **Senator 🏛️**: The strategic layer. Finalizes reporting and decides if further recursion is required.

### 🦀 Native Core (Rust)
PRAWN utilizes a hybrid Rust/Python architecture for elite performance:
- **Fuzzing Engine**: Powered by LibAFL for blazing-fast instrumentation.
- **EVM/SVM Runner**: Native execution using `revm` for deterministic state transitions.
- **Sandbox**: Memory-safe execution of AI-generated harnesses.
- **Analysis**: High-speed bit-level bytecode analysis.

### 🚀 Installation

```bash
# Clone and Install
git clone https://github.com/Wakhungila/PRAWN.git && cd PRAWN
pip install -r requirements.txt

# Build the Rust Core
pip install maturin
maturin develop

# Pull the PRAWN researcher model
ollama create prawn-researcher -f Modelfile
```

### 🛠 Usage Examples

#### 1. Autonomous Web + Web3 Audit
```bash
python prawn-cli.py research https://vulnerable-defi-dapp.com --web3-enabled
```

#### 2. Deep Source Code Review (EVM/SVM)
```bash
python prawn-cli.py audit ./contracts/LendingProtocol.sol
```

#### 3. 0-Day Research Mode
```bash
python prawn-cli.py research https://api.target.com --0day
```

### 🧠 Architecture
```mermaid
graph TD
    T[Target] --> F[Finder Agent]
    F -->|Anomalies| J[Judge Agent]
    J -->|Findings| R[Researcher Agent]
    R -->|Hypotheses| S[Senator Agent]
    S -->|Final Report| U[User]
    
    subgraph Local Intelligence (8GB Optimized)
    F
    J
    R
    S
    end
    
    subgraph Memory
    DB[(SQLite/Learning)]
    end

    subgraph Native Performance Layer (Rust)
    CORE[prawn-core]
    end

    F <--> CORE
    CORE <--> DB
    
    J <--> DB
    R <--> DB
```

### 💻 8GB RAM Laptop Optimization
PRAWN is designed to run on resource-constrained devices:
1. **Sequential Processing**: Agents do not run in parallel, preventing RAM spikes.
2. **Small-Quantized Models**: Defaults to `qwen2.5-coder:3b` or `phi4:mini`.
3. **Pydantic Filtering**: We only pass relevant context to the LLM to minimize token count.

---
*Developed by top-tier researchers for top-tier research. Use responsibly.*
