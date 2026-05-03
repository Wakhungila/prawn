#!/bin/bash
# PRAWN 🦐 - Unified Tool Setup Script
# Installs external security dependencies for Debian/Ubuntu-based systems

set -e

GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}[*] Installing system dependencies...${NC}"
sudo apt-get update && sudo apt-get install -y \
    git curl wget python3-pip build-essential libpcap-dev \
    golang-go jq libusb-1.0-0-dev libssl-dev

# Ensure Go and Local bins are in PATH
mkdir -p "$HOME/go/bin"
export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin

echo -e "${GREEN}[*] Installing ProjectDiscovery Suite (Recon)...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo -e "${GREEN}[*] Installing Discovery & Fuzzing Tools (Go)...${NC}"
go install github.com/ffuf/ffuf/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/qsreplace@latest

echo -e "${GREEN}[*] Installing Python Security Tools...${NC}"
pip install arjun dirsearch wfuzz trufflehog eth-wake --break-system-packages

echo -e "${GREEN}[*] Installing Web3 Research Suite...${NC}"
# Foundry (forge/cast)
if ! command -v forge &> /dev/null; then
    curl -L https://foundry.paradigm.xyz | bash
    source "$HOME/.bashrc"
    export PATH="$PATH:$HOME/.foundry/bin"
    $HOME/.foundry/bin/foundryup
fi

# Medusa (High-performance fuzzer)
go install github.com/crytic/medusa@latest

# Echidna (Binary download for stability)
E_VER="2.2.3"
wget "https://github.com/crytic/echidna/releases/download/v${E_VER}/echidna-${E_VER}-Ubuntu-22.04.tar.gz"
tar -xvf echidna-${E_VER}-Ubuntu-22.04.tar.gz
sudo mv echidna /usr/local/bin/ && rm echidna-*.tar.gz

echo -e "${GREEN}[+] Setup complete. Restart your terminal to refresh PATH.${NC}"