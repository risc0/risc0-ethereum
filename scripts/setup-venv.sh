#!/bin/bash
"""
Setup Python virtual environment for release automation scripts.
"""

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

echo "Setting up Python virtual environment for release scripts..."

# Create virtual environment if it doesn't exist
if [[ ! -d "$VENV_DIR" ]]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Install dependencies
echo "Installing Python dependencies..."
pip install -r "$SCRIPT_DIR/requirements.txt"

echo "Setup complete!"
echo ""
echo "To use the scripts:"
echo "1. Activate the environment: source scripts/venv/bin/activate"
echo "2. Run scripts normally: python3 scripts/bump-cargo-versions.py ..."
echo "3. Or use the wrapper scripts that auto-activate the environment"