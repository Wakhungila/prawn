#!/bin/bash

# PRAWN 🦐 Dependency Checker
# Validates Python environment and Go binaries

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "Checking PRAWN Dependencies...\n"

check_python_pkg() {
    python3 -c "import $1" &> /dev/null
    if [ $? -eq 0 ]; then
        echo -e "[${GREEN}OK${NC}] Python Package: $1"
    else
        echo -e "[${RED}MISSING${NC}] Python Package: $1 (Run: pip install $1)"
    fi
}

check_binary() {
    if command -v $1 &> /dev/null; then
        echo -e "[${GREEN}OK${NC}] Binary: $1"
    else
        echo -e "[${RED}MISSING${NC}] Binary: $1"
    fi
}

echo "--- Python Packages ---"
check_python_pkg "httpx"
check_python_pkg "pydantic"
check_python_pkg "rich"
check_python_pkg "requests"
check_python_pkg "bs4"
check_python_pkg "yaml"

echo -e "\n--- Go Recon Tools ---"
check_binary "httpx"
check_binary "naabu"
check_binary "katana"
check_binary "nuclei"
check_binary "subfinder"

echo -e "\n--- Web3 Fuzzing Tools ---"
check_binary "forge"
check_binary "echidna"
check_binary "wake"
check_binary "medusa"

echo -e "\nDependency check complete."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    echo "Note: If you are on Windows/WSL, ensure Go binaries are in your \$PATH."
fi